// Package rm is the client-side T2 reward models (16 §L6): RM-A and RM-B, each a supervised llama-server child, scoring task text + final diff after TaskClose and spooling one signed RmScore{locus: CLIENT_SIDE} each; nothing else leaves the machine.
package rm

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/identity"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/procattr"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/redact"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/supervise"
)

const (
	ChildName = "mark1-rm"
	// scoreTimeout bounds one model's inference: scoring is post-close background work off the gate path, so a 4096-token CPU pass must finish, not abstain.
	scoreTimeout   = 180 * time.Second
	renderTimeout  = 30 * time.Second
	queueDepth     = 64
	backlogDepth   = 32
	AbstainBacklog = "rm_backlog"
	ctxTokens      = MaxSeqLen + 256
	logitBias      = 100.0
	stopGrace      = 5 * time.Second
	retryAfter     = 10 * time.Minute
	defaultPoll    = 15 * time.Second
	// WeightsBudget caps the GGUF bytes resident at once across both slots (Q8_0 qwen2.5-coder-1.5b + granite-4.0-1b ≈ 3.4 GB); a slot that would pass it is not served.
	WeightsBudget = 4 << 30
)

type Config struct {
	StateDir  string
	Log       *slog.Logger
	Catalog   []Manifest // nil ⇒ the embedded catalog
	BaseURL   string     // "" ⇒ DefaultBaseURL
	Binary    string     // "" ⇒ supervise.FindRM
	Consented func() bool
	// Intent and Diff are the RM's only inputs (16 "Independence rules"): the task's opening prompt and its diff from the HEAD it opened at; no anchor, judge or trajectory source exists here.
	Intent  func(session, task [16]byte) (string, bool)
	Diff    func(ctx context.Context, session, task [16]byte) []byte
	Scanner *redact.Scanner // redacts the diff before the model sees it; nil ⇒ abstain, never an unredacted diff
	Admit   func(context.Context, *m1pv1.Event) error
	HTTP    *http.Client
	Poll    time.Duration
	// WeightsBudget, Backlog, Backoff and Breaker override the defaults (test seam).
	WeightsBudget int64
	Backlog       int
	Backoff       supervise.Backoff
	Breaker       supervise.Breaker
}

type closed struct{ session, task [16]byte }

// job is a closed task rendered at close time, so a backed-up queue never scores a later worktree's diff.
type job struct {
	c closed
	r Rendered
}

// slot is one served model (RM-A or RM-B) and its own supervised child; the Run goroutine owns stop/done/next, phase/detail sit under Plane.mu.
type slot struct {
	m      Manifest
	hash   []byte
	port   atomic.Int64
	key    atomic.Pointer[string]
	live   atomic.Bool
	failed atomic.Bool
	stop   context.CancelFunc
	done   chan struct{}
	next   time.Time
	phase  string
	detail string
}

type Plane struct {
	cfg     Config
	log     *slog.Logger
	closes  chan closed
	slots   []*slot
	skipped []ModelStatus

	qmu     sync.Mutex
	backlog []job
	wake    chan struct{}
	dropped atomic.Int64

	mu     sync.Mutex
	signer identity.DeviceKey
}

func New(cfg Config) (*Plane, error) {
	if cfg.StateDir == "" || cfg.Consented == nil || cfg.Intent == nil || cfg.Diff == nil || cfg.Admit == nil {
		return nil, errors.New("rm: StateDir, Consented, Intent, Diff and Admit required")
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	if cfg.Catalog == nil {
		cfg.Catalog = Catalog()
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = DefaultBaseURL
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: time.Hour, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	if cfg.Poll <= 0 {
		cfg.Poll = defaultPoll
	}
	if cfg.WeightsBudget <= 0 {
		cfg.WeightsBudget = WeightsBudget
	}
	if cfg.Backlog <= 0 {
		cfg.Backlog = backlogDepth
	}
	p := &Plane{cfg: cfg, log: cfg.Log, closes: make(chan closed, queueDepth), wake: make(chan struct{}, 1)}
	var used int64
	for _, m := range Active(cfg.Catalog) {
		if used+m.SizeBytes > cfg.WeightsBudget {
			p.skipped = append(p.skipped, ModelStatus{ModelID: m.ModelID(), State: "not_served", SizeBytes: m.SizeBytes,
				Detail: fmt.Sprintf("%.1f GB would pass the %.1f GB weights budget", float64(used+m.SizeBytes)/1e9, float64(cfg.WeightsBudget)/1e9)})
			continue
		}
		used += m.SizeBytes
		p.slots = append(p.slots, &slot{m: m, phase: "starting"})
	}
	return p, nil
}

func (p *Plane) SetSigner(k identity.DeviceKey) {
	p.mu.Lock()
	p.signer = k
	p.mu.Unlock()
}

// Observe is the admitter tap: a TaskClose queues the task for one score per slot; never blocks capture. A MERGED_FORWARD close is skipped: its successor carries the work.
func (p *Plane) Observe(ev *m1pv1.Event) {
	tc := ev.GetTaskClose()
	if tc == nil || tc.GetResolution() == m1pv1.Resolution_RESOLUTION_MERGED_FORWARD || len(ev.GetTaskId()) != 16 || len(ev.GetSessionId()) != 16 {
		return
	}
	var c closed
	copy(c.task[:], ev.GetTaskId())
	copy(c.session[:], ev.GetSessionId())
	select {
	case p.closes <- c:
	default:
		p.log.Warn("rm: score queue full; task not scored", "task", hex.EncodeToString(c.task[:]))
	}
}

// Run owns one child per served slot and the scoring loop until ctx ends (`mark1 off` cancels the session ctx, which kills the children).
func (p *Plane) Run(ctx context.Context) {
	scored, rendered := make(chan struct{}), make(chan struct{})
	go func() { defer close(scored); p.scoreLoop(ctx) }()
	go func() { defer close(rendered); p.renderLoop(ctx) }()
	t := time.NewTicker(p.cfg.Poll)
	defer t.Stop()
	for {
		if !p.cfg.Consented() {
			for _, s := range p.slots {
				p.halt(s)
				s.failed.Store(false)
				s.next = time.Time{}
				p.setPhase(s, "starting", "")
			}
			p.status("off", "", "reward model is off on this device")
		} else {
			for _, s := range p.slots {
				if s.done == nil && !s.failed.Load() && !time.Now().Before(s.next) {
					p.start(ctx, s)
				}
			}
			p.report()
		}
		select {
		case <-ctx.Done():
			for _, s := range p.slots {
				p.halt(s)
			}
			<-scored
			<-rendered
			return
		case <-t.C:
		}
	}
}

func (p *Plane) halt(s *slot) {
	if s.stop != nil {
		s.stop()
		<-s.done
		s.stop, s.done = nil, nil
	}
	s.live.Store(false)
	s.port.Store(0)
}

func (p *Plane) setPhase(s *slot, phase, detail string) {
	p.mu.Lock()
	s.phase, s.detail = phase, detail
	p.mu.Unlock()
}

var severity = map[string]int{"ready": 0, "starting": 1, "verifying": 2, "downloading": 3, "no_runtime": 4, "download_failed": 5, "failed": 6, "refused": 7}

// report folds the slots into the one status row: the worst served model's state, and every model's own state and detail.
func (p *Plane) report() {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := Status{State: "no_model"}
	var ids, parts []string
	if len(p.slots) == 0 {
		parts = append(parts, "no reward model is published for this build")
	} else {
		st.State = "ready"
	}
	for _, s := range p.slots {
		if severity[s.phase] > severity[st.State] {
			st.State = s.phase
		}
		ids = append(ids, s.m.ModelID())
		st.Models = append(st.Models, ModelStatus{ModelID: s.m.ModelID(), State: s.phase, Detail: s.detail, SizeBytes: s.m.SizeBytes})
	}
	st.Models = append(st.Models, p.skipped...)
	for _, m := range st.Models {
		part := m.ModelID + " " + m.State
		if m.Detail != "" {
			part += ": " + m.Detail
		}
		parts = append(parts, part)
	}
	st.ModelID, st.Detail, st.Backlog = strings.Join(ids, ","), strings.Join(parts, "; "), p.dropped.Load()
	p.writeStatus(st)
}

func (p *Plane) start(ctx context.Context, s *slot) {
	bin := p.cfg.Binary
	if bin == "" {
		var err error
		if bin, err = supervise.FindRM(); err != nil {
			p.setPhase(s, "no_runtime", err.Error())
			return
		}
	}
	if _, err := os.Stat(ModelPath(p.cfg.StateDir, s.m)); err != nil {
		p.setPhase(s, "downloading", fmt.Sprintf("fetching %.0f MB once from %s", float64(s.m.SizeBytes)/1e6, p.cfg.BaseURL))
	} else {
		p.setPhase(s, "verifying", "checking the model against its pinned sha256")
	}
	p.report()
	dctx, dcancel := context.WithCancel(ctx)
	go func() { p.untilRevoked(dctx); dcancel() }()
	gguf, err := ensureModel(dctx, p.cfg.HTTP, p.cfg.BaseURL, p.cfg.StateDir, s.m)
	aborted := dctx.Err() != nil
	dcancel()
	if err != nil {
		if !aborted {
			s.next = time.Now().Add(retryAfter)
			p.setPhase(s, "download_failed", err.Error())
		}
		return
	}
	runtimeID, err := RuntimeID(ctx, bin)
	if err != nil {
		s.next = time.Now().Add(retryAfter)
		p.setPhase(s, "no_runtime", err.Error())
		return
	}
	if s.hash, err = ExecutionHash(gguf, runtimeID); err != nil || hex.EncodeToString(s.hash) != s.m.ExecutionHash {
		s.failed.Store(true)
		p.setPhase(s, "refused", fmt.Sprintf("execution hash %x on %s is not the catalog's %s; not served (a runtime or model other than the published pair)", s.hash, runtimeID, s.m.ExecutionHash))
		return
	}
	cctx, cancel := context.WithCancel(ctx)
	s.stop, s.done = cancel, make(chan struct{})
	sup := supervise.New(p.log)
	sup.Add(p.child(bin, gguf, s))
	s.live.Store(true)
	p.setPhase(s, "starting", "loading the model")
	go func(d chan struct{}) { defer close(d); sup.Run(cctx) }(s.done)
	go func() {
		if _, _, err := waitHealthy(cctx, s); err == nil {
			p.mu.Lock()
			if cctx.Err() == nil && !s.failed.Load() {
				s.phase, s.detail = "ready", "scores after each task close"
			}
			p.mu.Unlock()
		}
	}()
}

// untilRevoked returns when ctx ends or the consent is withdrawn, so a revoke stops a download mid-stream.
func (p *Plane) untilRevoked(ctx context.Context) {
	t := time.NewTicker(p.cfg.Poll)
	defer t.Stop()
	for p.cfg.Consented() {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// child is one slot's llama-server: loopback only, one request slot, low priority, half the cores (slots never compute at once), an API key per start held only in env.
func (p *Plane) child(bin, gguf string, s *slot) supervise.Child {
	logPath := filepath.Join(p.cfg.StateDir, "rm", "runtime-"+s.m.Slot()+".log")
	return supervise.Child{
		Name:    ChildName + "-" + s.m.Slot(),
		Backoff: p.cfg.Backoff,
		Breaker: p.cfg.Breaker,
		Start: func(ctx context.Context) (*exec.Cmd, error) {
			port, err := freePort()
			if err != nil {
				return nil, err
			}
			var k [16]byte
			if _, err := rand.Read(k[:]); err != nil {
				return nil, err
			}
			key := hex.EncodeToString(k[:])
			threads := max(1, runtime.NumCPU()/2)
			cmd := exec.CommandContext(ctx, bin, "-m", gguf, "--host", "127.0.0.1", "--port", strconv.Itoa(port), //nolint:gosec // G204: bin is FindRM() or an operator-set MARK1_RM; args are fixed
				"-np", "1", "-c", strconv.Itoa(ctxTokens), "-t", strconv.Itoa(threads), "--prio", "-1",
				"--cache-ram", "0", "--ctx-checkpoints", "0", "--no-webui", "--offline", "--log-file", logPath)
			procattr.Hide(cmd)
			cmd.Env = supervise.ChildEnv("LLAMA_API_KEY=" + key)
			cmd.Cancel = func() error { return cmd.Process.Kill() }
			cmd.WaitDelay = stopGrace
			s.key.Store(&key)
			s.port.Store(int64(port))
			return cmd, nil
		},
		OnExit: func(error) { s.port.Store(0) },
		OnFailed: func() {
			s.failed.Store(true)
			s.live.Store(false)
			p.setPhase(s, "failed", "runtime crash-looped; see "+logPath+" (retried after `mark1 off`/on or when the reward model is switched off and on)")
			p.report()
		},
	}
}

func (p *Plane) anyLive() bool {
	for _, s := range p.slots {
		if s.live.Load() {
			return true
		}
	}
	return false
}

// renderLoop takes each closed task's diff as it closes and queues the render; a full backlog drops its oldest task, counted as rm_backlog.
func (p *Plane) renderLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case c := <-p.closes:
			if !p.anyLive() {
				continue
			}
			rctx, cancel := context.WithTimeout(ctx, renderTimeout)
			r := p.prompt(rctx, c)
			cancel()
			if r.Abstain != "" {
				p.log.Info("rm: abstained", "task", hex.EncodeToString(c.task[:]), "reason", r.Abstain)
				continue
			}
			p.qmu.Lock()
			if len(p.backlog) >= p.cfg.Backlog {
				old := p.backlog[0]
				p.backlog = p.backlog[1:]
				p.dropped.Add(1)
				p.log.Warn("rm: abstained", "task", hex.EncodeToString(old.c.task[:]), "reason", AbstainBacklog)
			}
			p.backlog = append(p.backlog, job{c, r})
			p.qmu.Unlock()
			select {
			case p.wake <- struct{}{}:
			default:
			}
		}
	}
}

func (p *Plane) next() (job, bool) {
	p.qmu.Lock()
	defer p.qmu.Unlock()
	if len(p.backlog) == 0 {
		return job{}, false
	}
	j := p.backlog[0]
	p.backlog = p.backlog[1:]
	return j, true
}

// scoreLoop scores queued tasks oldest first on every live slot in turn: one inference at a time across both models.
func (p *Plane) scoreLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.wake:
		}
		for j, ok := p.next(); ok && ctx.Err() == nil; j, ok = p.next() {
			for _, s := range p.slots {
				if !s.live.Load() {
					continue
				}
				sctx, cancel := context.WithTimeout(ctx, scoreTimeout)
				score, err := p.complete(sctx, s, j.r.Prefix)
				cancel()
				if err != nil {
					p.log.Warn("rm: abstained", "task", hex.EncodeToString(j.c.task[:]), "model", s.m.ModelID(), "reason", AbstainNoRuntime, "err", err)
					continue
				}
				if err := p.admit(ctx, s, j.c, score); err != nil {
					p.log.Warn("rm: score not recorded", "model", s.m.ModelID(), "err", err)
				}
			}
		}
	}
}

// Prompt is the whole model input for one task: Render over the task text and the diff, nothing else.
func Prompt(task string, diff []byte) Rendered {
	if task == "" {
		return Rendered{Abstain: AbstainNoTask}
	}
	return Render(strings.ToValidUTF8(task, "\uFFFD"), string(bytes.ToValidUTF8(diff, []byte("\uFFFD"))), MaxDiffChars)
}

func (p *Plane) prompt(ctx context.Context, c closed) Rendered {
	task, ok := p.cfg.Intent(c.session, c.task)
	if !ok || p.cfg.Scanner == nil {
		return Rendered{Abstain: AbstainNoTask}
	}
	diff, outcome, _ := p.cfg.Scanner.Admit(p.cfg.Diff(ctx, c.session, c.task))
	if outcome == redact.Quarantine {
		return Rendered{Abstain: AbstainNoChange}
	}
	return Prompt(task, diff)
}

// scoreRequest is training_jobs/rm/export.py SCORE_REQUEST, the request HF↔GGUF parity was measured under.
var scoreRequest = map[string]any{
	"n_predict": 1, "n_probs": 2, "post_sampling_probs": true, "temperature": 1.0, "top_k": 0, "top_p": 1.0, "min_p": 0.0,
	"typical_p": 1.0, "repeat_penalty": 1.0, "presence_penalty": 0.0, "frequency_penalty": 0.0, "cache_prompt": false,
}

func post(ctx context.Context, base, key, path string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("runtime %s: HTTP %d", path, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}

func tokenize(ctx context.Context, base, key, text string, special bool) ([]int, error) {
	var out struct {
		Tokens []int `json:"tokens"`
	}
	err := post(ctx, base, key, "/tokenize", map[string]any{"content": text, "add_special": false, "parse_special": special}, &out)
	return out.Tokens, err
}

// inputIDs is objective.encode on the served GGUF's own tokenizer: tokenize(prefix)[:MaxSeqLen−len(suffix)] ‖ tokenize(Suffix), no BOS; the prefix is split like split_special_tokens=True, the suffix and answers like tokenizer.encode.
func inputIDs(ctx context.Context, base, key string, m Manifest, prefix string) (ids []int, yes, no int, err error) {
	body, err := tokenize(ctx, base, key, prefix, false)
	if err != nil {
		return nil, 0, 0, err
	}
	suffix, err := tokenize(ctx, base, key, Suffix, true)
	if err != nil {
		return nil, 0, 0, err
	}
	y, err := tokenize(ctx, base, key, m.Scoring.Yes, true)
	if err != nil {
		return nil, 0, 0, err
	}
	n, err := tokenize(ctx, base, key, m.Scoring.No, true)
	if err != nil {
		return nil, 0, 0, err
	}
	if len(y) != 1 || len(n) != 1 || y[0] == n[0] || len(suffix) == 0 || len(suffix) >= MaxSeqLen {
		return nil, 0, 0, fmt.Errorf("runtime tokenizer: %q→%v, %q→%v, suffix %d tokens: not a scoring vocabulary", m.Scoring.Yes, y, m.Scoring.No, n, len(suffix))
	}
	return append(body[:min(len(body), MaxSeqLen-len(suffix))], suffix...), y[0], n[0], nil
}

// complete scores one rendered prefix on one slot: σ(logit(yes) − logit(no)) at the final position, read as ln p(yes) − ln p(no) with both answers +100-biased so they are the top two.
func (p *Plane) complete(ctx context.Context, s *slot, prefix string) (float64, error) {
	base, key, err := waitHealthy(ctx, s)
	if err != nil {
		return 0, err
	}
	ids, yes, no, err := inputIDs(ctx, base, key, s.m, prefix)
	if err != nil {
		return 0, err
	}
	return logitDiff(ctx, base, key, ids, yes, no)
}

func logitDiff(ctx context.Context, base, key string, ids []int, yes, no int) (float64, error) {
	req := map[string]any{"prompt": ids, "logit_bias": [][]any{{yes, logitBias}, {no, logitBias}}}
	for k, v := range scoreRequest {
		req[k] = v
	}
	var out struct {
		Probs []struct {
			Top []struct {
				ID      int      `json:"id"`
				Prob    *float64 `json:"prob"`
				Logprob *float64 `json:"logprob"`
			} `json:"top_probs"`
		} `json:"completion_probabilities"`
	}
	if err := post(ctx, base, key, "/completion", req, &out); err != nil {
		return 0, err
	}
	if len(out.Probs) == 0 {
		return 0, errors.New("runtime returned no probabilities")
	}
	lp := map[int]float64{}
	for _, t := range out.Probs[0].Top {
		switch {
		case t.Logprob != nil:
			lp[t.ID] = *t.Logprob
		case t.Prob != nil:
			lp[t.ID] = math.Log(max(*t.Prob, 1e-300))
		}
	}
	ly, okY := lp[yes]
	ln, okN := lp[no]
	sc := 1 / (1 + math.Exp(ln-ly))
	if !okY || !okN || math.IsNaN(sc) {
		return 0, fmt.Errorf("runtime did not rank both answer tokens %d and %d", yes, no)
	}
	return sc, nil
}

func waitHealthy(ctx context.Context, s *slot) (string, string, error) {
	for {
		if port, key := s.port.Load(), s.key.Load(); port != 0 && key != nil {
			base := "http://127.0.0.1:" + strconv.FormatInt(port, 10)
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/health", nil)
			if resp, err := http.DefaultClient.Do(req); err == nil {
				_ = resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					return base, *key, nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return "", "", errors.New("runtime not healthy within the score timeout")
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func (p *Plane) admit(ctx context.Context, s *slot, c closed, score float64) error {
	rs := &m1pv1.RmScore{
		ModelId: s.m.ModelID(), Score: score, CalibrationVersion: s.m.CalibrationVersion,
		ExecutionHash: s.hash, Locus: m1pv1.JudgeLocus_JUDGE_LOCUS_CLIENT_SIDE,
	}
	p.mu.Lock()
	signer := p.signer
	p.mu.Unlock()
	Sign(signer, rs)
	actx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return p.cfg.Admit(actx, &m1pv1.Event{
		SessionId: c.session[:], TaskId: c.task[:], OccurredAt: timestamppb.Now(),
		Body: &m1pv1.Event_RmScore{RmScore: rs},
	})
}

// Sign is AnchorVote's scheme: Ed25519 over the deterministic marshal with signature cleared, no domain prefix; no key or a failure leaves it unsigned, never forged.
func Sign(k identity.DeviceKey, rs *m1pv1.RmScore) {
	if k == nil {
		return
	}
	rs.Signature = nil
	canon, err := proto.MarshalOptions{Deterministic: true}.Marshal(rs)
	if err != nil {
		return
	}
	if sig, err := k.Sign(canon); err == nil {
		rs.Signature = sig
	}
}

// Status is <state>/rm/status.json: what `mark1 status`, `mark1 doctor` and the app show; State is the worst model's, Models each served model's own.
type Status struct {
	State   string        `json:"state"`
	ModelID string        `json:"model_id,omitempty"`
	Detail  string        `json:"detail"`
	Models  []ModelStatus `json:"models,omitempty"`
	// Backlog is how many closed tasks this session dropped unscored because the queue was full (abstain rm_backlog).
	Backlog int64     `json:"rm_backlog,omitempty"`
	At      time.Time `json:"at"`
}

type ModelStatus struct {
	ModelID   string `json:"model_id"`
	State     string `json:"state"`
	Detail    string `json:"detail,omitempty"`
	SizeBytes int64  `json:"size_bytes,omitempty"`
}

func StatusPath(stateDir string) string { return filepath.Join(stateDir, "rm", "status.json") }

func ReadStatus(stateDir string) (Status, bool) {
	var s Status
	b, err := os.ReadFile(StatusPath(stateDir)) //nolint:gosec // G304: under the state dir
	return s, err == nil && json.Unmarshal(b, &s) == nil
}

// Healthy: every state but a crash loop, a failed/mismatched download or a refused execution hash is a truthful, working posture.
func (s Status) Healthy() bool {
	return s.State != "failed" && s.State != "download_failed" && s.State != "refused"
}

func (p *Plane) status(state, model, detail string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.writeStatus(Status{State: state, ModelID: model, Detail: detail})
}

func (p *Plane) writeStatus(st Status) {
	if cur, ok := ReadStatus(p.cfg.StateDir); ok && cur.State == st.State && cur.ModelID == st.ModelID && cur.Detail == st.Detail && cur.Backlog == st.Backlog {
		return
	}
	st.At = time.Now().UTC()
	b, _ := json.Marshal(st)
	path := StatusPath(p.cfg.StateDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err == nil {
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, b, 0o600); err == nil {
			_ = os.Rename(tmp, path)
		}
	}
	p.log.Info("rm: runtime state", "state", st.State, "model", st.ModelID, "detail", st.Detail)
}

// Check is the rm_runtime doctor row; no status file means the daemon has not reached the reward model this session, which is not a failure.
func Check(stateDir string) (bool, string) {
	s, ok := ReadStatus(stateDir)
	if !ok {
		return true, "not started (reward model off, or the daemon is not running)"
	}
	d := s.State
	if s.ModelID != "" {
		d += " " + s.ModelID
	}
	return s.Healthy(), d + ": " + s.Detail
}
