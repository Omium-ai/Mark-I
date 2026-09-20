package control

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/anchors"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/verdict"
)

// A session whose end is tailer-inferred never sends SessionEnd (opencode's session.idle is a turn, not an end), so any event refreshes `seen` and live() drops a session quiet for liveIdleTTL.
// ponytail: the verify ring, checkpoint ring and last_run are memory-only since boot; the spool is the durable record and is never re-read here.
const (
	subscriberBuffer = 256
	maxLiveSessions  = 64
	liveIdleTTL      = 30 * time.Minute
	verifyRing       = 1024
	checkpointRing   = 256
)

var marshal = protojson.MarshalOptions{UseProtoNames: true}

type LiveSession struct {
	Agent     string `json:"agent"`
	Project   string `json:"project"`
	SessionID string `json:"session_id"`
	Tokens    uint64 `json:"tokens"`
	// Cwd is the hook process's directory (Hello.cwd); Watched is false when no enabled root contains it, and EnablePath is the root to offer (the git top level above cwd, else cwd).
	Cwd        string `json:"cwd,omitempty"`
	Watched    bool   `json:"watched"`
	EnablePath string `json:"enable_path,omitempty"`
	started    time.Time
	seen       time.Time
}

type frame struct {
	family string
	data   []byte
}

// Hub is the tap on capture's one admission door: SSE fan-out plus the live-session table.
type Hub struct {
	mu       sync.Mutex
	subs     map[chan frame]struct{}
	sessions map[[16]byte]*LiveSession
	cwds     map[[16]byte]string
	locate   func(sid [16]byte) (agent, cwd string, ok bool)
	// tokensFile persists each live session's token count across daemon restarts (a restart zeroed the founder's live card mid-session); seeds carries what the last run knew.
	tokensFile  string
	seeds       map[string]uint64
	tokensDirty bool
	verify      []map[string]any  // GET /v1/verify/events rows, arrival order
	checkpoints []map[string]any  // GET /v1/receipts rows, arrival order
	lastRun     map[string]string // anchor id -> occurred_at of its newest vote since boot
	// spend sizes the verify plane's savings estimates: the newest request's tokens per session (what a follow-up request re-reads) and each task's running total (an attempt's mean cost).
	lastRequest map[[16]byte]uint64
	taskTokens  map[[16]byte]uint64
	resolver    func(id uuid.UUID) (agent, root string, ok bool)
}

// SetTokensFile arms the per-session token persistence at path: the last run's counts seed a session's live card, and counts flush every few seconds while they change.
func (h *Hub) SetTokensFile(path string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.tokensFile = path
	h.seeds = map[string]uint64{}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &h.seeds)
	}
}

// FlushTokens writes the live sessions' token counts when they changed; called on a ticker by the daemon and at shutdown.
func (h *Hub) FlushTokens() {
	h.mu.Lock()
	if h.tokensFile == "" || !h.tokensDirty {
		h.mu.Unlock()
		return
	}
	out := map[string]uint64{}
	for id, s := range h.sessions {
		out[uuid.UUID(id).String()] = s.Tokens
	}
	h.tokensDirty = false
	path := h.tokensFile
	h.mu.Unlock()
	if b, err := json.Marshal(out); err == nil {
		_ = os.WriteFile(path+".tmp", b, 0o600)
		_ = os.Rename(path+".tmp", path)
	}
}

// SetCwd records a session's hook cwd (Hello.cwd) so live can say where an unwatched agent is running.
func (h *Hub) SetCwd(session [16]byte, cwd string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cwds[session] = cwd
}

// SetLocator installs the fallback for a session no enabled root claims: the agent and the session's own root (its transcript's first cwd) so the app can offer to watch it. nil is legal.
func (h *Hub) SetLocator(f func(sid [16]byte) (agent, cwd string, ok bool)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.locate = f
}

// SetSessionResolver installs the tailer fleet's session table (tailers.Resolve): live consults it before the transcript-head fallback, since a derived session id's cwd is known only to its vendor's tailer.
func (h *Hub) SetSessionResolver(f func(id uuid.UUID) (agent, root string, ok bool)) {
	h.mu.Lock()
	h.resolver = f
	h.mu.Unlock()
}

func NewHub() *Hub {
	return &Hub{subs: map[chan frame]struct{}{}, sessions: map[[16]byte]*LiveSession{}, cwds: map[[16]byte]string{}, lastRun: map[string]string{}, lastRequest: map[[16]byte]uint64{}, taskTokens: map[[16]byte]uint64{}}
}

// EstimateBlock is what a Stop the gate refused saved: the follow-up request the human would have sent re-reads the context, so one request at this session's newest size. 0 when no usage has been seen.
func (h *Hub) EstimateBlock(session [16]byte) uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.lastRequest[session]
}

// EstimateArrest is what the knee saved: the next attempt, at this task's mean attempt cost so far.
func (h *Hub) EstimateArrest(task [16]byte, attempts uint32) uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.taskTokens[task] / uint64(max(attempts, 1))
}

func family(ev *m1pv1.Event) string {
	switch ev.GetBody().(type) {
	case *m1pv1.Event_SessionStart:
		return "session_start"
	case *m1pv1.Event_Turn:
		return "turn"
	case *m1pv1.Event_ToolUse:
		return "tool"
	case *m1pv1.Event_Usage:
		return "usage"
	case *m1pv1.Event_VerdictEvent:
		return "verdict"
	case *m1pv1.Event_MemoryInjection, *m1pv1.Event_CortexInjection:
		return "injection"
	case *m1pv1.Event_RouteDecision:
		return "route_decision"
	case *m1pv1.Event_CoverageTransition:
		return "coverage_transition"
	case *m1pv1.Event_AnchorVote:
		if ev.GetAnchorVote().GetIntegrity().GetTamper() {
			return "tamper"
		}
	}
	return ""
}

// Publish never blocks the admitter: a subscriber subscriberBuffer frames behind loses the frame.
func (h *Hub) Publish(ev *m1pv1.Event) {
	fam := family(ev)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.track(ev)
	if fam == "" {
		return
	}
	switch fam {
	case "verdict":
		ve := ev.GetVerdictEvent()
		h.verifyRow(ev, "verdict", map[string]any{
			"verdict": enumWord(ve.GetVerdict().String(), "VERDICT_"), "mode": modeWord(ve.GetPosterior()), "state": certWord(ve.GetCertification()), "certificate_id": nullable(ve.GetNoiseCertId()),
		})
	case "tamper":
		h.verifyRow(ev, "tamper", map[string]any{"anchor_id": ev.GetAnchorVote().GetAnchorId()})
		return
	}
	data, err := frameJSON(ev)
	if err != nil {
		return
	}
	h.fanout(frame{family: fam, data: data})
}

// frameJSON is the protojson Event with its three ids re-spelled as dashed UUIDs (protojson's base64 is not what any app-facing surface renders); the body stays protojson verbatim.
func frameJSON(ev *m1pv1.Event) ([]byte, error) {
	raw, err := marshal.Marshal(ev)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	for k, b := range map[string][]byte{"event_id": ev.GetEventId(), "session_id": ev.GetSessionId(), "task_id": ev.GetTaskId()} {
		if len(b) > 0 {
			m[k] = idString(b)
		}
	}
	return json.Marshal(m)
}

// Arrest is the knee stop the gate answered (fabric.Gate.Answer's "retry loop arrested at the knee" row); the gate carries no event, so this is its only record.
func (h *Hub) Arrest(session, task [16]byte, k verdict.KneeState, evidenceRef string) {
	row := map[string]any{
		"type": "arrest", "id": uuid.NewString(), "time": time.Now().UTC().Format(time.RFC3339),
		"task_id": uuid.UUID(task).String(), "session_id": uuid.UUID(session).String(),
		"attempt": k.N, "p_lcb": nil, "v": nil, "c_n": nil, "inequality": nil, "evidence_ref": nullable(evidenceRef),
	}
	if k.Evaluable {
		row["p_lcb"], row["v"], row["c_n"] = k.PLCB, k.VTask, k.CostN
		row["inequality"] = fmt.Sprintf("%.3f * %.2f <= %.2f", k.PLCB, k.VTask, k.CostN)
	}
	data, _ := json.Marshal(row)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.verify = ring(append(h.verify, row), verifyRing)
	h.fanout(frame{family: "arrest", data: data})
}

func (h *Hub) verifyRow(ev *m1pv1.Event, kind string, fields map[string]any) {
	row := map[string]any{
		"type": kind, "id": idString(ev.GetEventId()), "time": eventTime(ev),
		"task_id": idString(ev.GetTaskId()), "session_id": idString(ev.GetSessionId()),
	}
	maps.Copy(row, fields)
	h.verify = ring(append(h.verify, row), verifyRing)
}

// idString is the canonical dashed UUID every app-facing surface renders a 16-byte id as; anything else (an absent task id) stays bare hex.
func idString(b []byte) string {
	if id, err := uuid.FromBytes(b); err == nil {
		return id.String()
	}
	return hex.EncodeToString(b)
}

func (h *Hub) fanout(f frame) {
	for ch := range h.subs {
		select {
		case ch <- f:
		default:
		}
	}
}

func ring[T any](s []T, n int) []T {
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}

func eventTime(ev *m1pv1.Event) string {
	if ts := ev.GetOccurredAt(); ts != nil {
		return ts.AsTime().UTC().Format(time.RFC3339)
	}
	return time.Now().UTC().Format(time.RFC3339)
}

func enumWord(name, prefix string) string {
	return strings.ToLower(strings.TrimPrefix(name, prefix))
}

// certWord is the proto's own reading: unspecified is treated as uncertified.
func certWord(c m1pv1.CertificationStatus) string {
	if c == m1pv1.CertificationStatus_CERTIFICATION_STATUS_UNSPECIFIED {
		return "uncertified"
	}
	return enumWord(c.String(), "CERTIFICATION_STATUS_")
}

// modeWord is the posterior's argmax class: the Chow band withholds the satisfied WORD below 8/9 (bootstrap rows top out near 0.7), so a task every anchor passed reads refused on the wire with its mode at satisfied — the app labels by mode and certifies by state.
func modeWord(post []float64) any {
	if len(post) != 4 {
		return nil
	}
	best := int32(0)
	for i, p := range post[1:] {
		if p > post[best] {
			best = int32(i + 1) // #nosec G115 -- 1..3
		}
	}
	return enumWord(m1pv1.Verdict(best+1).String(), "VERDICT_")
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func (h *Hub) track(ev *m1pv1.Event) {
	switch b := ev.GetBody().(type) {
	case *m1pv1.Event_AnchorVote:
		h.lastRun[b.AnchorVote.GetAnchorId()] = eventTime(ev)
	case *m1pv1.Event_ReceiptCheckpoint:
		cp := b.ReceiptCheckpoint
		h.checkpoints = ring(append(h.checkpoints, map[string]any{
			"seq": cp.GetCheckpointSeq(), "time": eventTime(ev), "events_covered": cp.GetLeafCount(),
			"merkle_root": hex.EncodeToString(cp.GetMerkleRoot()), "key_id": cp.GetKeyId(),
		}), checkpointRing)
	}
	if len(ev.GetSessionId()) != 16 {
		return
	}
	var sid [16]byte
	copy(sid[:], ev.GetSessionId())
	switch b := ev.GetBody().(type) {
	case *m1pv1.Event_SessionStart:
		h.sessions[sid] = &LiveSession{Agent: b.SessionStart.GetAgent(), SessionID: uuid.UUID(sid).String(), Tokens: h.seeds[uuid.UUID(sid).String()], started: time.Now(), seen: time.Now()}
		for len(h.sessions) > maxLiveSessions {
			var oldest [16]byte
			var at time.Time
			for id, s := range h.sessions {
				if at.IsZero() || s.started.Before(at) {
					oldest, at = id, s.started
				}
			}
			delete(h.sessions, oldest)
		}
	case *m1pv1.Event_SessionEnd:
		delete(h.sessions, sid)
		delete(h.lastRequest, sid)
	case *m1pv1.Event_Usage, *m1pv1.Event_ToolUse, *m1pv1.Event_Turn:
		// a session the daemon did not see start (it restarted mid-session — the founder's live list emptied on every restart) is live from its first event; live() names the agent and project through the resolver
		if h.sessions[sid] == nil {
			id := uuid.UUID(sid).String()
			h.sessions[sid] = &LiveSession{SessionID: id, Tokens: h.seeds[id], started: time.Now(), seen: time.Now()}
		}
	}
	switch b := ev.GetBody().(type) {
	case *m1pv1.Event_Usage:
		u := b.Usage
		total := u.GetInputTokens() + u.GetOutputTokens() + u.GetCacheCreationInputTokens() + u.GetCacheReadInputTokens()
		if s := h.sessions[sid]; s != nil {
			s.Tokens += total
			h.tokensDirty = true
		}
		h.lastRequest[sid] = total
		if len(ev.GetTaskId()) == 16 {
			var tid [16]byte
			copy(tid[:], ev.GetTaskId())
			h.taskTokens[tid] += total
		}
	case *m1pv1.Event_TaskClose:
		if len(ev.GetTaskId()) == 16 {
			var tid [16]byte
			copy(tid[:], ev.GetTaskId())
			delete(h.taskTokens, tid)
		}
	}
	if s := h.sessions[sid]; s != nil {
		s.seen = time.Now()
	}
}

func (h *Hub) subscribe() (<-chan frame, func()) {
	ch := make(chan frame, subscriberBuffer)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		delete(h.subs, ch)
		h.mu.Unlock()
	}
}

// live resolves each unattributed session's project (the wire carries no cwd) outside the lock the admitter's Tap takes, and caches a hit: the fleet resolver first, then resolve (the transcript-head fallback).
func (h *Hub) live(resolve func(agent string, sid [16]byte) string) []LiveSession {
	h.mu.Lock()
	out := make([]LiveSession, 0, len(h.sessions))
	ids := make([][16]byte, 0, len(h.sessions))
	for id, s := range h.sessions {
		if time.Since(s.seen) > liveIdleTTL {
			delete(h.sessions, id)
			delete(h.cwds, id)
			continue
		}
		out = append(out, *s)
		out[len(out)-1].Cwd = h.cwds[id]
		ids = append(ids, id)
	}
	resolver, locate := h.resolver, h.locate
	h.mu.Unlock()
	defer func() {
		for i := range out {
			out[i].Watched = out[i].Project != ""
			if out[i].Watched {
				continue
			}
			if locate != nil {
				if agent, cwd, ok := locate(ids[i]); ok {
					out[i].Cwd = cwd
					if out[i].Agent == "" {
						out[i].Agent = agent
					}
				}
			}
			if out[i].Cwd != "" {
				if p := anchors.GitTop(out[i].Cwd); !tooBroad(p) {
					out[i].EnablePath = p
				}
			}
		}
	}()
	for i := range out {
		if out[i].Project != "" {
			continue
		}
		p := ""
		if resolver != nil {
			if agent, root, ok := resolver(ids[i]); ok && (agent == "" || out[i].Agent == "" || agent == out[i].Agent) {
				p = root
				if out[i].Agent == "" {
					out[i].Agent = agent
				}
			}
		}
		if p == "" && resolve != nil {
			p = resolve(out[i].Agent, ids[i])
		}
		if p == "" {
			continue
		}
		out[i].Project = p
		h.mu.Lock()
		if s := h.sessions[ids[i]]; s != nil {
			s.Project = p
			if s.Agent == "" {
				s.Agent = out[i].Agent
			}
		}
		h.mu.Unlock()
	}
	return out
}

// tooBroad: the home directory, the filesystem root or a drive root is never offered as a project — an agent started there is told to start inside one.
func tooBroad(p string) bool {
	clean := filepath.Clean(p)
	if home, err := os.UserHomeDir(); err == nil && clean == filepath.Clean(home) {
		return true
	}
	return clean == filepath.Dir(clean) || filepath.VolumeName(clean)+string(filepath.Separator) == clean
}

func (h *Hub) lastRuns() map[string]string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return maps.Clone(h.lastRun)
}

func (h *Hub) verifyEvents() []map[string]any {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]map[string]any{}, h.verify...)
}

// checkpointsBefore returns the checkpoints seen since boot newest first, those with seq < before when before > 0.
func (h *Hub) checkpointsBefore(before uint64) []map[string]any {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := []map[string]any{}
	for i := len(h.checkpoints) - 1; i >= 0; i-- {
		if cp := h.checkpoints[i]; before == 0 || cp["seq"].(uint64) < before {
			out = append(out, cp)
		}
	}
	return out
}
