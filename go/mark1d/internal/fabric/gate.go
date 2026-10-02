// The GateQuery handler (04 §2.3): a cache READ, never a computation — it is
// constructed with a verdict.Reader only, so fusion is structurally out of
// reach. Check order is normative: off-check first (invariant 2), then D-AA's
// task resolution (nothing downstream may be keyed by the all-zero sentinel),
// then the ≤3-consecutive-blocks-per-task cap, then the hourly ceiling
// (M1E-5002 ⇒ allow), then the deadline, THEN the cache read -- and a BLOCK
// only if blocking is armed (FR-POLICY-006: the operator's on-disk opt-in AND
// a policy that has not opened the gate).
package fabric

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/hostprofile"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/obs"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/off"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/policy"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/verdict"
)

const (
	// maxConsecutiveBlocks is the local hard cap (FR-VERIFY-010): a bundle
	// may LOWER it, never raise it — hence a constant, not a config knob.
	maxConsecutiveBlocks = 3
	// DefaultHourlyCeiling: the docs fix the mechanism (hourly ceiling,
	// M1E-5002 ⇒ allow, bundle may lower) but no document states the built-in
	// number; 30 keeps a runaway block loop under one block per two minutes.
	DefaultHourlyCeiling = 30
	// cacheReadBudget is 04 §2.3 D-Y(c)'s own budget, applied when the query
	// states no deadline.
	cacheReadBudget = 5 * time.Millisecond
	// settleMargin is what the cache read and the shim's own margin keep out of a Settle wait.
	settleMargin = 200 * time.Millisecond
)

// Gate error codes (08 §9): fail-open, always.
const (
	CodeGateTimeout = "M1E-5001" // cache miss / expired deadline ⇒ allow + Dropped{gate_timeout}
	CodeGateCap     = "M1E-5002" // local hard cap hit ⇒ allow
	CodeStaleCert   = "M1E-3006" // fail-static built-ins ⇒ allow, flagged stale_cert
)

// Gate answers GateQuery from the verdict cache. Reader is the ONLY verdict
// surface it holds — future fusion-at-the-gate requires changing this
// constructor, visibly.
type Gate struct {
	reader   verdict.Reader
	blocks   *verdict.Blocks
	stateDir string
	// HourlyCeiling is LOWERED from the bundle's gates section by ApplyGates;
	// zero means DefaultHourlyCeiling. Atomic access: ApplyGates also runs from the bundle client's apply goroutine while Answer serves.
	HourlyCeiling uint32
	// consecutiveCap is the same for max_consecutive_blocks; zero means
	// maxConsecutiveBlocks. Unexported: only ApplyGates' clamp writes it.
	consecutiveCap atomic.Uint32
	// opened: the applied policy set stop_gate_enabled=false. The zero value
	// is the compiled default (armed, subject to the local opt-in), so a gate
	// that never saw a bundle behaves as it always did.
	opened atomic.Bool
	// Profiles is the ADR-0013 per-session host-profile registry; nil, or an
	// unknown session, reads as hostprofile.Default. Answer reads it and logs
	// it once per session; it decides nothing on it in this revision.
	Profiles *hostprofile.Registry
	// Log carries the once-per-session profile line; nil logs nothing.
	Log         *slog.Logger
	profileSeen sync.Map // session → struct{}: the debug line is printed once
	// TaskFor is D-AA parts 2 and 3: the daemon's segmenter resolves the
	// connection's session plus the query's (possibly empty) task_id to a real
	// task, or misses. nil means no segmenter is wired, so every query misses —
	// which is M1E-5001, the fail-open direction.
	TaskFor func(session, want [16]byte) ([16]byte, bool)
	// AgentFor resolves the connection's session to the agent its SessionStart named (control.Hub.AgentFor); nil or "" means no per-agent pause can match, so the query gates normally.
	AgentFor func(session [16]byte) string
	// Settle runs the task's owed anchors and returns when they have voted or ctx ends (anchors.Scheduler.Settle); nil reads the cache as it stands.
	Settle func(ctx context.Context, session, task [16]byte)
	// Now is a test seam; nil means time.Now.
	Now func() time.Time
	// OnDropped receives the Dropped{gate_timeout} accounting for M1E-5001
	// answers (wired to capture.AccountDropped); nil is legal.
	OnDropped func(reason string)
	// Evidence is FR-VERIFY-011's evidence_ref source: the failing anchors'
	// typed evidence for a task, rendered by whoever still holds the votes.
	// The cache does not — verdict.Cached carries the fused VerdictEvent and
	// the knee, and the anchors tee strips EvidenceRecord before fusion — so
	// this is a lookup seam exactly like TaskFor, read on BLOCK, at the knee
	// and on a correction, never a computation. nil, or an empty answer, leaves
	// evidence_ref empty and the shim renders no `[evidence: …]` suffix
	// (mark1-hookshim/src/gate.rs).
	Evidence func(task verdict.TaskID) string
	// Corrections is the CORRECTION channel's source (verdict.Engine.TakeCorrections); nil ⇒ the channel answers empty.
	Corrections func(session [16]byte) []verdict.Correction
	// Health counts answers and the read latency SLO-7 is judged on; nil is
	// legal — an unwired gauge must never change what the gate answers.
	Health *obs.Health
	// OnArrest observes every knee stop the gate actually told the human about (the control API's arrest row); nil is legal.
	OnArrest func(session, task [16]byte, k verdict.KneeState, evidenceRef string)
	// OnCap observes every consecutive-block cap that ended a loop with the verdict still violated (told to the human like a knee stop); nil is legal.
	OnCap func(session, task [16]byte, blocks uint32, evidenceRef string)
	// OnBlock observes every BLOCK the gate answered (the ledger's GuardDecision row); nil is legal.
	OnBlock func(session, task [16]byte, k verdict.KneeState, evidenceRef string)
}

func NewGate(r verdict.Reader, blocks *verdict.Blocks, stateDir string) *Gate {
	return &Gate{reader: r, blocks: blocks, stateDir: stateDir}
}

// ApplyGates is FR-POLICY-006's clamp: a bundle's gates section can move this
// gate from closed toward open and never past the local hard caps
// (FR-VERIFY-010, "regardless of bundle content"). max_consecutive_blocks and
// hourly_block_ceiling take min(bundle, built-in) -- the decoder already
// refuses a raise, this is the edge-side floor if it ever does not -- and 0
// means the built-in, as controld and the decoder read it. stop_gate_enabled
// false opens the gate; true does NOT arm it, because arming also needs the
// operator's local opt-in artifact, which no bundle can supply. Boot-time,
// before Serve: the fields are plain, like the rest of the wiring.
func (g *Gate) ApplyGates(sec policy.GatesSection) {
	g.opened.Store(!sec.StopGateEnabled)
	g.consecutiveCap.Store(min(uint32(sec.MaxConsecutiveBlocks), maxConsecutiveBlocks))
	ceiling := uint32(DefaultHourlyCeiling)
	if h := sec.HourlyBlockCeiling; h > 0 && h < DefaultHourlyCeiling {
		ceiling = uint32(h)
	}
	atomic.StoreUint32(&g.HourlyCeiling, ceiling)
}

// OptInPath is the local on-disk tenant opt-in artifact FR-POLICY-006 names
// and no document places: `mark1 enable --stop-gate` writes it (0600,
// {"stop_gate": true, "ts": <RFC 3339>, "user": <OS account>}), `mark1 off`
// and a future `--no-stop-gate` remove it. Without it the stop gate answers
// ALLOW whatever the bundle says.
func OptInPath(stateDir string) string { return filepath.Join(stateDir, "gates", "opt-in.json") }

// optIn is the artifact's shape: stop_gate arms the gate; exploration is D-EF's local half of ε>0 consent.
type optIn struct {
	StopGate    bool `json:"stop_gate"`
	Exploration bool `json:"exploration"`
}

// optedIn reads the artifact per query, like the off-marker stat: an opt-in
// written while the daemon runs takes effect on the next Stop. Anything but a
// well-formed {"stop_gate": true} -- absent, unreadable, garbage, false -- is
// "not opted in", the fail-open direction — per field.
// ponytail: one ReadFile+Unmarshal of a <100-byte file per query, inside the
// 5 ms budget TestGateLatency asserts; mtime-cache it if that ever slips.
func optedIn(stateDir string) (a optIn) {
	raw, err := os.ReadFile(OptInPath(stateDir))
	if err != nil || json.Unmarshal(raw, &a) != nil {
		return optIn{}
	}
	return a
}

// ExplorationEpsilon is D-EF's edge half: a bundle's ε applies only under a local "exploration": true, else 0 (propensity 1.0).
func ExplorationEpsilon(stateDir string, eps float64) float64 {
	if optedIn(stateDir).Exploration {
		return eps
	}
	return 0
}

// armed is FR-POLICY-006: opted in on disk AND the applied policy left the gate closed.
func (g *Gate) armed() bool { return !g.opened.Load() && optedIn(g.stateDir).StopGate }

func (g *Gate) evidence(task verdict.TaskID) string {
	if g.Evidence == nil {
		return ""
	}
	return g.Evidence(task)
}

func verdictName(v m1pv1.Verdict) string {
	return strings.ToLower(strings.TrimPrefix(v.String(), "VERDICT_"))
}

// Context answers ContextQuery{CORRECTION} (08 §5.1 PostToolUse row): the session's queued revisions, one line each, facts only; other channels are another ContextChain handler's.
func (g *Gate) Context(_ context.Context, q ContextQuery, session [16]byte) string {
	if q.Channel != uint32(m1pv1.InjectionChannel_INJECTION_CHANNEL_CORRECTION) || g.Corrections == nil {
		return ""
	}
	var lines []string
	for _, c := range g.Corrections(session) {
		line := fmt.Sprintf("[mark1 correction] a slow verifier finished after the last verdict: %s was revised to %s", verdictName(c.Previous), verdictName(c.Revised))
		if ev := g.evidence(c.Task); ev != "" {
			line += "; evidence: " + ev
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func (g *Gate) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now()
}

func (g *Gate) dropped() {
	g.Health.GateTimeout()
	if g.OnDropped != nil {
		g.OnDropped("gate_timeout")
	}
}

// resolve is D-AA in one place: an empty task_id resolves through the session,
// a named one is honoured only inside its own session, and a task_id that is
// neither 16 bytes nor absent is a malformed address rather than a lookup.
// Every path that fails here answers ALLOW; none of them touches a counter.
func (g *Gate) resolve(q *m1pv1.GateQuery, session [16]byte) (verdict.TaskID, bool) {
	var want [16]byte
	switch b := q.GetTaskId(); len(b) {
	case 0:
	case 16:
		copy(want[:], b)
	default:
		return verdict.TaskID{}, false
	}
	if g.TaskFor == nil {
		return verdict.TaskID{}, false
	}
	got, ok := g.TaskFor(session, want)
	if !ok || got == ([16]byte{}) {
		return verdict.TaskID{}, false
	}
	return got, true
}

func allow(reason string) *m1pv1.GateVerdict {
	return &m1pv1.GateVerdict{Decision: m1pv1.GateDecision_GATE_DECISION_ALLOW, Reason: reason}
}

// note makes D-X's accounting visible where the decision is. Votes from
// verifiers the bundle does not list contribute no likelihood and no coverage
// (D-AB), so an answer fused from fewer voters than actually ran must say so —
// otherwise a BLOCK reads as if the whole ensemble agreed, and the one signal
// that a machine is running a verifier the tenant's bundle never listed is
// visible nowhere at all.
func note(v *m1pv1.GateVerdict, unknown uint32) *m1pv1.GateVerdict {
	if unknown == 0 {
		return v
	}
	if v.Reason != "" {
		v.Reason += " "
	}
	v.Reason += fmt.Sprintf("[%d unlisted vote(s) contributed no evidence]", unknown)
	return v
}

// Answer is the whole gate path: memory only (04 §8.3 — the off-check is one
// file stat), budget ≤5 ms. session is the connection's authenticated Hello
// session id (08 §4.3) — the channel D-AA resolves an empty task_id through.
// ProfileFor is the session's ADR-0013 host profile as the gate sees it:
// Default when no registry is wired or the session declared nothing. Logged
// at debug the first time a session is asked for.
func (g *Gate) ProfileFor(session [16]byte) hostprofile.Profile {
	p := hostprofile.Default
	if g.Profiles != nil {
		p = g.Profiles.Get(session)
	}
	if _, seen := g.profileSeen.LoadOrStore(session, struct{}{}); !seen && g.Log != nil {
		g.Log.Debug("gate: host profile", "session", hex.EncodeToString(session[:]), "host_id", p.HostID, "arrest_mode", string(p.ArrestMode), "default", p.IsDefault())
	}
	return p
}

func (g *Gate) Answer(q *m1pv1.GateQuery, session [16]byte) (v *m1pv1.GateVerdict) {
	// ADR-0013: read and log the profile; nothing below decides on it yet.
	// Part 4 selects the arrest sink from ArrestMode here.
	_ = g.ProfileFor(session)
	received := g.now()
	// Named return + defer so the digest covers EVERY exit, including the
	// fail-open ones: a gate that got slow only on its refusal paths would be
	// invisible to SLO-7 if the instrument sat on the happy path alone.
	defer func() { g.Health.GateAnswer(g.now().Sub(received), v.GetDecision()) }()

	// 1. mark1 off / MARK1_DISABLE=1 — before ANY gate evaluation (invariant 2).
	// ponytail: an uncached stat per query; off's 1 s stat cache when it exists.
	if off.Off(g.stateDir) {
		return allow("mark1_off")
	}
	// 1b. POST /v1/agents/{name}/pause — the per-agent marker, same posture, same place: before any counter or read.
	if g.AgentFor != nil {
		if a := g.AgentFor(session); a != "" && off.AgentOff(g.stateDir, a) {
			return allow("agent_paused")
		}
	}

	// 2. D-AA: resolve the task BEFORE any counter is keyed by it. An
	// unresolvable query never reaches the cap, the ceiling or the cache, so the
	// all-zero sentinel is structurally incapable of addressing any of them.
	task, ok := g.resolve(q, session)
	if !ok {
		g.dropped()
		return allow(CodeGateTimeout + " no open task for this session")
	}
	ctr := g.blocks.Counters(session, task, received)

	// 3. ≤3 consecutive blocks per task (or fewer, if the bundle lowered it).
	capN := g.consecutiveCap.Load()
	if capN == 0 {
		capN = maxConsecutiveBlocks
	}
	if ctr.Consecutive >= capN {
		// The cap is a retry loop Mark 1 ends: the human is told (08 §5.1's Stop row, like the knee) and the ledger records it (block_cap), else the loop's last state — the failure still there — is invisible to everyone; in bootstrap the knee never fires, so this is the arrest a tester actually gets.
		v := allow(CodeGateCap + " consecutive block cap")
		if e, ok := g.reader.Get(task); ok && e.Verdict.GetVerdict() == m1pv1.Verdict_VERDICT_VIOLATED {
			ev := g.evidence(task)
			v.SystemMessage = fmt.Sprintf("mark1 stop-gate: retry loop stopped after %d blocks — the verdict is still violated; a person should look", ctr.Consecutive)
			if ev != "" {
				v.SystemMessage += "; evidence: " + ev
			}
			if g.OnCap != nil {
				g.OnCap(session, task, ctr.Consecutive, ev)
			}
		}
		return v
	}
	// 4. hourly block ceiling.
	ceiling := atomic.LoadUint32(&g.HourlyCeiling)
	if ceiling == 0 {
		ceiling = DefaultHourlyCeiling
	}
	if ctr.Hourly >= ceiling {
		return allow(CodeGateCap + " hourly block ceiling")
	}
	// 5. Expired deadline ⇒ allow + Dropped{gate_timeout}. deadline_ms is the
	// shim's remaining budget from frame send; D-Y(c): 0 is UNSPECIFIED, not
	// "already expired", so the daemon answers under its own budget instead of
	// switching gating off for any writer that omits the field.
	budget := time.Duration(q.GetDeadlineMs()) * time.Millisecond
	if budget == 0 {
		budget = cacheReadBudget
	}
	if g.now().Sub(received) >= budget {
		g.dropped()
		return allow(CodeGateTimeout + " gate deadline expired")
	}
	// 5b. The anchors the task still owes run now (04 §2.2: slow anchors at Stop) and the read below waits for them within the budget — the gate still never computes, it only reads later.
	if g.Settle != nil {
		if wait := budget - settleMargin - g.now().Sub(received); wait > 0 {
			sctx, cancel := context.WithTimeout(context.Background(), wait)
			g.Settle(sctx, session, task)
			cancel()
		}
	}
	// 6. THE cache read — a map lookup, never a computation.
	e, ok := g.reader.Get(task)
	if !ok {
		g.dropped()
		return allow(CodeGateTimeout + " verdict cache miss")
	}
	v = &m1pv1.GateVerdict{
		Decision:  m1pv1.GateDecision_GATE_DECISION_ALLOW,
		Verdict:   e.Verdict.GetVerdict(),
		Posterior: e.Verdict.GetPosterior(),
	}
	if e.Knee.Stale {
		v.Reason = CodeStaleCert + " stale_cert"
		return note(v, e.UnknownVoters)
	}
	// BLOCK forces continuation: verdict violated AND another attempt is still
	// economical (p̂_LCB(n)·V(task) > c(n)). At the knee — or any other verdict
	// — the agent is allowed to stop, with verdict + evidence as the reason.
	if e.Verdict.GetVerdict() == m1pv1.Verdict_VERDICT_VIOLATED && !e.Knee.Stop {
		// 7. FR-POLICY-006: the one closed answer opens unless the operator
		// opted in on disk AND the applied policy left the gate closed. Sits
		// here, not before the cache read, so every other posture keeps its
		// own reason (M1E-5001 is still a cache miss on an unarmed daemon)
		// and the artifact is read only when a BLOCK is otherwise due. No
		// counter moves: an opened block is not a block. M1E-5002 is 08 §9's
		// only local, fail-open, stop-allowed row; there is no dedicated code
		// for the normal open posture, and M1E-3006 would misreport a fresh
		// bundle as stale.
		if g.opened.Load() {
			v.Reason = CodeGateCap + " stop gate opened by policy"
			return note(v, e.UnknownVoters)
		}
		if !optedIn(g.stateDir).StopGate {
			v.Reason = CodeGateCap + " stop gate not opted in locally"
			return note(v, e.UnknownVoters)
		}
		g.blocks.RecordBlock(session, task, received)
		v.Decision = m1pv1.GateDecision_GATE_DECISION_BLOCK
		// FR-VERIFY-011: below the knee the failure evidence IS the
		// continuation reason. Only here — an ALLOW has no failing anchor to
		// name, and a knee stop surfaces the verdict, not a retry target.
		v.EvidenceRef = g.evidence(task)
		if g.OnBlock != nil {
			g.OnBlock(session, task, e.Knee, v.EvidenceRef)
		}
		// D-AN(c): !Stop is also how "no knee table", "n below the first row"
		// (D-Y(b)) and "no p_lcb on the row" (D-Z) arrive here. Printing the
		// inequality then states a false one (0.000 · V > c) and reads as
		// certainly-hopeless — the reading D-Z forbids. Not evaluable ⇒ no
		// numbers.
		if e.Knee.Evaluable {
			v.Reason = fmt.Sprintf("verdict violated below the knee (attempt %d): p̂_LCB %.3f · V %.2f > c(n) %.2f", e.Knee.N, e.Knee.PLCB, e.Knee.VTask, e.Knee.CostN)
		} else {
			v.Reason = fmt.Sprintf("verdict violated; the knee is not evaluable at attempt %d, so continuation is not arrested", e.Knee.N)
		}
		return note(v, e.UnknownVoters)
	}
	g.blocks.RecordAllow(task)
	if e.Knee.Stop {
		v.Reason = fmt.Sprintf("knee governor: stop at attempt %d — p̂_LCB %.3f · V %.2f ≤ c(n) %.2f under %s", e.Knee.N, e.Knee.PLCB, e.Knee.VTask, e.Knee.CostN, e.Knee.CostBasis)
		// 08 §5.1 Stop row at the knee: the human is told, never the model — and only where a BLOCK was otherwise due.
		if e.Verdict.GetVerdict() == m1pv1.Verdict_VERDICT_VIOLATED && g.armed() {
			v.SystemMessage = "mark1 stop-gate: retry loop arrested at the knee — verdict violated; " + v.Reason
			ev := g.evidence(task)
			if ev != "" {
				v.SystemMessage += "; evidence: " + ev
			}
			if g.OnArrest != nil {
				g.OnArrest(session, task, e.Knee, ev)
			}
		}
	}
	return note(v, e.UnknownVoters)
}
