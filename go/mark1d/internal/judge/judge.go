// Package judge is the edge half of client-side-first judges (ADR-0008,
// 06 §6.2 steps 3-6, FR-VERIFY-015). A JudgeRequest arrives on the policy SSE
// stream; the daemon answers only for a task it owns, assembles the evidence
// LOCALLY at the consented tier, calls the Messages API once with the
// CUSTOMER'S OWN API key under the request's token budget, and spools one
// JudgeVote{locus: CLIENT_SIDE} per request_id. Nothing but the vote leaves the
// machine; the key is read per call, sent in one header, and never logged,
// spooled or stored. A subscription/OAuth credential is never used (10 §3):
// without an API-key-shaped credential the judge refuses and makes no call.
package judge

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/verdict"
)

const (
	// DefaultBaseURL is the vendor origin; the ONLY host this package ever dials.
	DefaultBaseURL = "https://api.anthropic.com"
	messagesPath   = "/v1/messages"
	apiVersion     = "2023-06-01"
	// maxRubric is verify.proto's "rubric ≤ 16 KiB"; maxBudget matches controld's cap.
	maxRubric = 16 << 10
	maxBudget = 1 << 16
	// maxInflight bounds requests accepted but not yet answered; past it a request is dropped (unmarked, so a repost lands).
	maxInflight = 64
	// maxCalls bounds concurrent model calls on the customer's key.
	maxCalls        = 2
	callTimeout     = 90 * time.Second
	responseBodyMax = 1 << 20
)

var reIdent = regexp.MustCompile(`^[A-Za-z0-9_.:@-]{1,128}$`)

type Config struct {
	// StateDir is the daemon state root; the seen-set lives at <StateDir>/judge/seen (0600).
	StateDir string
	// BaseURL overrides DefaultBaseURL (test seam; a proxy-routed judge would set it too).
	BaseURL string
	// Credential returns the customer's API key or "". nil reads ANTHROPIC_API_KEY —
	// the same reading claudecode.Detect's regime sniff and the proxy provisioning
	// make (adapters/claudecode/claudecode.go apiKeyCredential); D-CU(1) applies
	// identically: a daemon whose env lacks the key is the subscription regime here.
	Credential func() string
	// TenantRoot keys rubric_hash = HMAC_tenant(rubric); nil ⇒ rubric_hash absent, never an unkeyed hash.
	TenantRoot []byte
	// TaskFor and Verdict together are the ownership oracle: the segmenter for a
	// live session, the verdict cache for a task whose session already ended.
	TaskFor func(session, want [16]byte) ([16]byte, bool)
	Verdict func(task [16]byte) (*m1pv1.VerdictEvent, bool)
	// Evidence renders the task's typed E0 evidence (anchors.Votes.Evidence); "" ⇒ nothing to judge.
	Evidence func(verdict.TaskID) string
	Admit    func(context.Context, *m1pv1.Event) error
	Log      *slog.Logger

	HTTPClient *http.Client
}

type Runner struct {
	cfg  Config
	base string
	key  []byte
	log  *slog.Logger
	http *http.Client

	mu       sync.Mutex
	seen     map[string]bool
	inflight map[string]bool
	seenPath string
	calls    chan struct{}
}

func New(cfg Config) (*Runner, error) {
	if cfg.StateDir == "" {
		return nil, errors.New("judge: StateDir required")
	}
	if cfg.TaskFor == nil || cfg.Evidence == nil || cfg.Admit == nil {
		return nil, errors.New("judge: TaskFor, Evidence and Admit required")
	}
	r := &Runner{cfg: cfg, base: strings.TrimRight(cfg.BaseURL, "/"), log: cfg.Log, http: cfg.HTTPClient,
		seen: map[string]bool{}, inflight: map[string]bool{}, calls: make(chan struct{}, maxCalls)}
	if r.base == "" {
		r.base = DefaultBaseURL
	}
	if r.log == nil {
		r.log = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	if r.http == nil {
		r.http = &http.Client{Timeout: callTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	if r.cfg.Credential == nil {
		r.cfg.Credential = func() string { return os.Getenv("ANTHROPIC_API_KEY") }
	}
	if len(cfg.TenantRoot) > 0 {
		var err error
		if r.key, err = hkdf.Key(sha256.New, cfg.TenantRoot, nil, "m1p.judge.rubric", 32); err != nil {
			return nil, err
		}
	}
	dir := filepath.Join(cfg.StateDir, "judge")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	r.seenPath = filepath.Join(dir, "seen")
	f, err := os.OpenFile(r.seenPath, os.O_CREATE|os.O_RDONLY, 0o600)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if id := strings.TrimSpace(sc.Text()); id != "" {
			r.seen[id] = true
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Runner) appendSeen(id string) error {
	f, err := os.OpenFile(r.seenPath, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(f, id)
	return errors.Join(err, f.Close())
}

// Handle is bundle.Client.OnJudgeRequest: decode, own-check, dedupe, then answer off the stream goroutine.
func (r *Runner) Handle(data []byte) {
	req, err := decode(data)
	if err != nil {
		r.log.Warn("judge: request ignored", "err", err)
		return
	}
	if !r.owns(req) {
		return
	}
	r.mu.Lock()
	dup, busy := r.seen[req.GetRequestId()] || r.inflight[req.GetRequestId()], len(r.inflight) >= maxInflight
	if !dup && !busy {
		r.inflight[req.GetRequestId()] = true
	}
	r.mu.Unlock()
	if dup {
		return
	}
	if busy {
		r.log.Warn("judge: request dropped, too many in flight", "request_id", req.GetRequestId())
		return
	}
	go r.serve(req)
}

func decode(data []byte) (*m1pv1.JudgeRequest, error) {
	var req m1pv1.JudgeRequest
	if err := protojson.Unmarshal(data, &req); err != nil {
		return nil, err
	}
	switch {
	case !reIdent.MatchString(req.GetRequestId()), !reIdent.MatchString(req.GetJudgeId()), !reIdent.MatchString(req.GetModel()):
		return nil, errors.New("request_id, judge_id and model must be identifiers")
	case len(req.GetTaskId()) != 16 || len(req.GetSessionId()) != 16:
		return nil, errors.New("task_id and session_id must be 16 bytes")
	case len(req.GetRubric()) == 0 || len(req.GetRubric()) > maxRubric:
		return nil, errors.New("rubric outside 1..16 KiB")
	case req.GetTokenBudget() == 0 || req.GetTokenBudget() > maxBudget:
		return nil, errors.New("token_budget outside bounds")
	case req.GetLocus() != m1pv1.JudgeLocus_JUDGE_LOCUS_CLIENT_SIDE:
		return nil, errors.New("locus is not CLIENT_SIDE")
	}
	return &req, nil
}

func (r *Runner) owns(req *m1pv1.JudgeRequest) bool {
	var sid, tid [16]byte
	copy(sid[:], req.GetSessionId())
	copy(tid[:], req.GetTaskId())
	if _, ok := r.cfg.TaskFor(sid, tid); ok {
		return true
	}
	if r.cfg.Verdict != nil {
		_, ok := r.cfg.Verdict(tid)
		return ok
	}
	return false
}

func (r *Runner) serve(req *m1pv1.JudgeRequest) {
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout+10*time.Second)
	defer cancel()
	vote, reason := r.judge(ctx, req)
	var tid [16]byte
	copy(tid[:], req.GetTaskId())
	ev := &m1pv1.Event{
		SessionId: req.GetSessionId(), TaskId: req.GetTaskId(), OccurredAt: timestamppb.Now(),
		Body: &m1pv1.Event_JudgeVote{JudgeVote: &m1pv1.JudgeVote{
			JudgeId: req.GetJudgeId(), Vote: vote, TierUsed: m1pv1.EvidenceTier_EVIDENCE_TIER_E0,
			RubricHash: r.rubricHash(req.GetRubric()), Locus: m1pv1.JudgeLocus_JUDGE_LOCUS_CLIENT_SIDE,
		}},
	}
	err := r.cfg.Admit(ctx, ev)
	r.mu.Lock()
	if err == nil {
		r.seen[req.GetRequestId()] = true
		err = r.appendSeen(req.GetRequestId())
	}
	r.mu.Unlock()
	if err != nil {
		r.log.Error("judge: vote not recorded", "request_id", req.GetRequestId(), "err", err)
	} else {
		r.log.Info("judge: vote spooled", "request_id", req.GetRequestId(), "judge_id", req.GetJudgeId(), "vote", vote.String(), "reason", reason)
	}
	// Released last: an empty inflight set means every accepted request is fully answered.
	r.mu.Lock()
	delete(r.inflight, req.GetRequestId())
	r.mu.Unlock()
}

// judge decides the vote. Refusals are statements about this verifier plane
// (06 §2.2) -- no key, wrong-shaped key, nothing to show -- and cost no call.
func (r *Runner) judge(ctx context.Context, req *m1pv1.JudgeRequest) (m1pv1.Verdict, string) {
	cred := r.cfg.Credential()
	switch {
	case cred == "":
		return m1pv1.Verdict_VERDICT_REFUSED, "no customer API key: subscription regime, judge never runs on a subscription credential"
	case !apiKeyShaped(cred):
		return m1pv1.Verdict_VERDICT_REFUSED, "credential is not an Anthropic API key shape"
	}
	var tid [16]byte
	copy(tid[:], req.GetTaskId())
	// ponytail: E0 only -- E1 needs redaction-receipted hunk assembly and consents.Read(stateDir).E1 (the control API's Step-4 record); E2 the vpc|selfhost profile. tier_used says so.
	evidence := r.cfg.Evidence(verdict.TaskID(tid))
	if evidence == "" {
		return m1pv1.Verdict_VERDICT_REFUSED, "no typed evidence on this device"
	}
	r.calls <- struct{}{}
	defer func() { <-r.calls }()
	stop, text, err := r.call(ctx, cred, req, evidence)
	if err != nil {
		r.log.Warn("judge: model call failed", "request_id", req.GetRequestId(), "err", err)
		return m1pv1.Verdict_VERDICT_ERROR, "model call failed"
	}
	return parseVerdict(stop, text), "model"
}

type messagesRequest struct {
	Model     string        `json:"model"`
	MaxTokens uint32        `json:"max_tokens"`
	System    []systemBlock `json:"system"`
	Messages  []message     `json:"messages"`
}

type systemBlock struct {
	Type         string            `json:"type"`
	Text         string            `json:"text"`
	CacheControl map[string]string `json:"cache_control"`
}

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type messagesResponse struct {
	StopReason string `json:"stop_reason"`
	Content    []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
}

// call is the one Messages request, shaped exactly as the cloud locus's
// (python/adjudicator/app/judges/cloud_path.py) minus its region pin, so the
// two loci judge the same prompt bytes and calibrate as one population.
func (r *Runner) call(ctx context.Context, cred string, req *m1pv1.JudgeRequest, evidence string) (string, string, error) {
	body, err := json.Marshal(messagesRequest{
		Model: req.GetModel(), MaxTokens: req.GetTokenBudget(),
		System:   []systemBlock{{Type: "text", Text: req.GetRubric(), CacheControl: map[string]string{"type": "ephemeral"}}},
		Messages: []message{{Role: "user", Content: evidence}},
	})
	if err != nil {
		return "", "", err
	}
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, r.base+messagesPath, bytes.NewReader(body))
	if err != nil {
		return "", "", err
	}
	hr.Header.Set("x-api-key", cred)
	hr.Header.Set("anthropic-version", apiVersion)
	hr.Header.Set("content-type", "application/json")
	resp, err := r.http.Do(hr)
	if err != nil {
		return "", "", errors.New("transport error") // never the URL-bearing error text: it can echo the request
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, responseBodyMax))
	if err != nil {
		return "", "", err
	}
	if resp.StatusCode/100 != 2 {
		return "", "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var out messagesResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", "", err
	}
	var text strings.Builder
	for _, b := range out.Content {
		if b.Type == "text" {
			text.WriteString(b.Text)
		}
	}
	return out.StopReason, text.String(), nil
}

// parseVerdict is cloud_path.parse_verdict, byte for byte in behaviour: a model
// refusal IS the judge refusing; anything the vocabulary cannot name is ERROR.
func parseVerdict(stopReason, text string) m1pv1.Verdict {
	if stopReason == "refusal" {
		return m1pv1.Verdict_VERDICT_REFUSED
	}
	switch strings.ToLower(strings.Trim(strings.TrimSpace(text), "`.")) {
	case "satisfied":
		return m1pv1.Verdict_VERDICT_SATISFIED
	case "violated":
		return m1pv1.Verdict_VERDICT_VIOLATED
	case "refused":
		return m1pv1.Verdict_VERDICT_REFUSED
	}
	return m1pv1.Verdict_VERDICT_ERROR
}

// apiKeyShaped is rust/mark1-proxy/src/guard/shape.rs is_anthropic_api_key:
// `sk-ant-api<NN>-<body>`. Every OAuth artifact shares the sk-ant- stem
// (sk-ant-oat/ort/sid) and fails here, as does a JWT and any other vendor's key.
func apiKeyShaped(c string) bool {
	rest, ok := strings.CutPrefix(c, "sk-ant-api")
	if !ok || len(rest) < 4 || rest[0] < '0' || rest[0] > '9' || rest[1] < '0' || rest[1] > '9' || rest[2] != '-' {
		return false
	}
	for _, b := range []byte(rest[3:]) {
		switch {
		case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9', b == '-', b == '_':
		default:
			return false
		}
	}
	return true
}

func (r *Runner) rubricHash(rubric string) []byte {
	if r.key == nil {
		return nil
	}
	mac := hmac.New(sha256.New, r.key)
	mac.Write([]byte(rubric))
	return mac.Sum(nil)
}
