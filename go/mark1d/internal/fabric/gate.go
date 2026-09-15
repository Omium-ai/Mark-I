// The GateQuery handler (04 §2.3): a cache READ, never a computation — it is
// constructed with a verdict.Reader only, so fusion is structurally out of
// reach. Check order is normative: off-check first (invariant 2), then D-AA's
// task resolution (nothing downstream may be keyed by the all-zero sentinel),
// then the ≤3-consecutive-blocks-per-task cap, then the hourly ceiling
// (M1E-5002 ⇒ allow), then the deadline, THEN the cache read.
package fabric

import (
	"fmt"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/obs"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/off"
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
	// HourlyCeiling may be LOWERED by the wiring pass from the bundle's
	// gates-section; zero means DefaultHourlyCeiling.
	HourlyCeiling uint32
	// TaskFor is D-AA parts 2 and 3: the daemon's segmenter resolves the
	// connection's session plus the query's (possibly empty) task_id to a real
	// task, or misses. nil means no segmenter is wired, so every query misses —
	// which is M1E-5001, the fail-open direction.
	TaskFor func(session, want [16]byte) ([16]byte, bool)
	// Now is a test seam; nil means time.Now.
	Now func() time.Time
	// OnDropped receives the Dropped{gate_timeout} accounting for M1E-5001
	// answers (wired to capture.AccountDropped); nil is legal.
	OnDropped func(reason string)
	// Evidence is FR-VERIFY-011's evidence_ref source: the failing anchors'
	// typed evidence for a task, rendered by whoever still holds the votes.
	// The cache does not — verdict.Cached carries the fused VerdictEvent and
	// the knee, and the anchors tee strips EvidenceRecord before fusion — so
	// this is a lookup seam exactly like TaskFor, read on BLOCK only and never
	// a computation. nil, or an empty answer, leaves evidence_ref empty and the
	// shim renders no `[evidence: …]` suffix (mark1-hookshim/src/gate.rs).
	Evidence func(task verdict.TaskID) string
	// Health counts answers and the read latency SLO-7 is judged on; nil is
	// legal — an unwired gauge must never change what the gate answers.
	Health *obs.Health
}

func NewGate(r verdict.Reader, blocks *verdict.Blocks, stateDir string) *Gate {
	return &Gate{reader: r, blocks: blocks, stateDir: stateDir}
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
func (g *Gate) Answer(q *m1pv1.GateQuery, session [16]byte) (v *m1pv1.GateVerdict) {
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

	// 2. D-AA: resolve the task BEFORE any counter is keyed by it. An
	// unresolvable query never reaches the cap, the ceiling or the cache, so the
	// all-zero sentinel is structurally incapable of addressing any of them.
	task, ok := g.resolve(q, session)
	if !ok {
		g.dropped()
		return allow(CodeGateTimeout + " no open task for this session")
	}
	ctr := g.blocks.Counters(session, task, received)

	// 3. ≤3 consecutive blocks per task.
	if ctr.Consecutive >= maxConsecutiveBlocks {
		return allow(CodeGateCap + " consecutive block cap")
	}
	// 4. hourly block ceiling.
	ceiling := g.HourlyCeiling
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
		g.blocks.RecordBlock(session, task, received)
		v.Decision = m1pv1.GateDecision_GATE_DECISION_BLOCK
		// FR-VERIFY-011: below the knee the failure evidence IS the
		// continuation reason. Only here — an ALLOW has no failing anchor to
		// name, and a knee stop surfaces the verdict, not a retry target.
		if g.Evidence != nil {
			v.EvidenceRef = g.Evidence(task)
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
	}
	return note(v, e.UnknownVoters)
}
