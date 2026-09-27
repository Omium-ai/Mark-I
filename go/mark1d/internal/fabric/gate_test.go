package fabric

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/off"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/policy"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/taskseg"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/verdict"
)

type stubReader map[verdict.TaskID]verdict.Cached

func (r stubReader) Get(t verdict.TaskID) (verdict.Cached, bool) { e, ok := r[t]; return e, ok }

func violatedEntry(stop, stale bool) verdict.Cached {
	return verdict.Cached{
		Verdict: &m1pv1.VerdictEvent{
			Stage:     m1pv1.VerdictStage_VERDICT_STAGE_PROVISIONAL,
			Verdict:   m1pv1.Verdict_VERDICT_VIOLATED,
			Posterior: []float64{0.02, 0.90, 0.05, 0.03},
		},
		Knee:       verdict.KneeState{N: 2, R: 2, PLCB: 0.4, Basis: "certified", VTask: 10, CostN: 1, CostBasis: "usd", Stop: stop, Stale: stale, Evaluable: true},
		ComputedAt: time.Now(),
	}
}

func query(task byte, deadlineMs uint32) *m1pv1.GateQuery {
	id := make([]byte, 16)
	id[0] = task
	return &m1pv1.GateQuery{TaskId: id, Gate: m1pv1.GateKind_GATE_KIND_STOP, DeadlineMs: deadlineMs}
}

// testSession is the connection every gate test speaks from, and ownAll is
// what the segmenter does for a task that session owns (D-AA part 3): honour
// the name, refuse everything else.
var testSession = [16]byte{0xAA}

func ownAll(session, want [16]byte) ([16]byte, bool) {
	if session != testSession || want == ([16]byte{}) {
		return [16]byte{}, false
	}
	return want, true
}

// optedInDir is a state dir carrying the FR-POLICY-006 opt-in artifact
// `mark1 enable --stop-gate` writes -- the precondition for every BLOCK below.
func optedInDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeOptIn(t, dir, `{"stop_gate":true,"ts":"2026-09-15T00:00:00Z","user":"test"}`)
	return dir
}

func writeOptIn(t *testing.T, stateDir, body string) {
	t.Helper()
	p := OptInPath(stateDir)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func blockableGate(t *testing.T, entries stubReader) *Gate {
	t.Helper()
	g := NewGate(entries, verdict.NewBlocks(), optedInDir(t))
	g.TaskFor = ownAll
	return g
}

// TestGateBlocksBelowKnee: violated verdict, retry still economical ⇒ BLOCK
// with the verdict + posterior riding the reply.
func TestGateBlocksBelowKnee(t *testing.T) {
	g := blockableGate(t, stubReader{{1}: violatedEntry(false, false)})
	v := g.Answer(query(1, 5000), testSession)
	if v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_BLOCK {
		t.Fatalf("decision %v reason %q, want BLOCK below the knee", v.GetDecision(), v.GetReason())
	}
	if v.GetVerdict() != m1pv1.Verdict_VERDICT_VIOLATED || len(v.GetPosterior()) != 4 {
		t.Fatalf("reply lost the fused verdict: %v", v)
	}
}

// TestGateKneeStops: at the knee the governor STOPS the loop — the agent is
// allowed to stop even though the verdict is violated.
func TestGateKneeStops(t *testing.T) {
	g := blockableGate(t, stubReader{{1}: violatedEntry(true, false)})
	v := g.Answer(query(1, 5000), testSession)
	if v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_ALLOW || !strings.Contains(v.GetReason(), "knee") {
		t.Fatalf("decision %v reason %q, want ALLOW with knee reason", v.GetDecision(), v.GetReason())
	}
}

// TestGateOffShortCircuits pins invariant 2: with the OFF marker present the
// answer is allow BEFORE caps, deadline, or cache are consulted — even a
// blockable entry and an expired deadline change nothing.
func TestGateOffShortCircuits(t *testing.T) {
	dir := t.TempDir()
	g := NewGate(stubReader{{1}: violatedEntry(false, false)}, verdict.NewBlocks(), dir)
	g.OnDropped = func(string) { t.Fatal("off-check must precede deadline accounting") }
	if err := os.WriteFile(filepath.Join(dir, "OFF"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	v := g.Answer(query(1, 0), testSession) // no deadline stated: off still wins
	if v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_ALLOW || v.GetReason() != "mark1_off" {
		t.Fatalf("off gate answered %v %q", v.GetDecision(), v.GetReason())
	}
}

// TestGatePerAgentPauseShortCircuits: a paused agent's session answers allow
// before counters, deadline or cache, like the OFF marker; another agent's
// session on the same daemon still blocks, and an unresolvable session gates
// normally (no pause can match a session nobody named).
func TestGatePerAgentPauseShortCircuits(t *testing.T) {
	g := blockableGate(t, stubReader{{1}: violatedEntry(false, false)})
	other := [16]byte{0xBB}
	g.TaskFor = func(session, want [16]byte) ([16]byte, bool) { return want, want != [16]byte{} }
	g.AgentFor = func(s [16]byte) string {
		switch s {
		case testSession:
			return "codex"
		case other:
			return "claudecode"
		}
		return ""
	}
	if v := g.Answer(query(1, 5000), testSession); v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_BLOCK {
		t.Fatalf("unpaused codex answered %v %q, want BLOCK", v.GetDecision(), v.GetReason())
	}
	marker := off.AgentMarker(g.stateDir, "codex")
	if err := os.MkdirAll(filepath.Dir(marker), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	g.OnDropped = func(string) { t.Fatal("pause-check must precede deadline accounting") }
	if v := g.Answer(query(1, 0), testSession); v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_ALLOW || v.GetReason() != "agent_paused" {
		t.Fatalf("paused codex answered %v %q", v.GetDecision(), v.GetReason())
	}
	g.OnDropped = nil
	if v := g.Answer(query(1, 5000), other); v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_BLOCK {
		t.Fatalf("claudecode answered %v %q while only codex is paused, want BLOCK", v.GetDecision(), v.GetReason())
	}
	if v := g.Answer(query(1, 5000), [16]byte{0xCC}); v.GetReason() == "agent_paused" {
		t.Fatal("a session with no agent cannot match a pause")
	}
}

// TestGateConsecutiveCap: the 4th query on a task with 3 consecutive blocks
// answers allow (M1E-5002) without reading the cache decision.
func TestGateConsecutiveCap(t *testing.T) {
	g := blockableGate(t, stubReader{{1}: violatedEntry(false, false)})
	for i := range 3 {
		if v := g.Answer(query(1, 5000), testSession); v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_BLOCK {
			t.Fatalf("block %d: got %v %q", i+1, v.GetDecision(), v.GetReason())
		}
	}
	var capped struct {
		blocks uint32
		n      int
	}
	g.OnCap = func(_, _ [16]byte, blocks uint32, _ string) { capped.blocks, capped.n = blocks, capped.n+1 }
	v := g.Answer(query(1, 5000), testSession)
	if v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_ALLOW || !strings.Contains(v.GetReason(), "consecutive") {
		t.Fatalf("4th answer %v %q, want M1E-5002 consecutive-cap allow", v.GetDecision(), v.GetReason())
	}
	// the loop's end is told to the human (the verdict is still violated) and recorded once, as the arrest a bootstrap tester gets
	if !strings.Contains(v.GetSystemMessage(), "retry loop stopped after 3 blocks") || capped.n != 1 || capped.blocks != 3 {
		t.Fatalf("cap must be told and recorded: message %q, OnCap %+v", v.GetSystemMessage(), capped)
	}
}

// TestGateConsecutiveCapClearsOnPublish is the gate-side end state of D-Y:
// the streak resets on any cache publish for the task, so a capped task starts
// blocking again the moment new evidence lands. Driven through the SHIPPING
// verdict.Engine — the reset lives on the publish side, and a stub reader
// could only prove the stub. The gate's own check order (04 §2.3) is unchanged
// and untouched: the cap still short-circuits before the cache read, which is
// exactly why an allow can never carry the reset.
func TestGateConsecutiveCapClearsOnPublish(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	blocks := verdict.NewBlocks()
	// No knee rows ⇒ Stop is false at every n (D-Y(b)/D-Z), which is the
	// blockable state; one verifier whose reject column is decisive gives
	// VIOLATED inside the Chow band.
	eng := verdict.NewEngine(verdict.BundleMatrices{
		Priors: verdict.DefaultPriors,
		Verifiers: map[string]verdict.VerifierParams{"build": {Confusion: verdict.Confusion{
			{0.98, 0.01, 0.01},
			{0.02, 0.97, 0.01},
			{0.10, 0.10, 0.80},
			{0.34, 0.33, 0.33},
		}}},
		VTask:     10,
		CostBasis: "usd",
	}, blocks, nil)
	go eng.Run(ctx)

	var task verdict.TaskID
	task[0] = 1
	votes := []verdict.AnchorVote{{AnchorID: "build", Vote: m1pv1.Verdict_VERDICT_VIOLATED}}
	publish := func() {
		t.Helper()
		prev, _ := eng.Reader().Get(task)
		eng.Recompute(task, votes, 0)
		for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); { // a deadline, not an iteration count: Windows sleeps in quanta
			if e, ok := eng.Reader().Get(task); ok && e.ComputedAt.After(prev.ComputedAt) {
				if e.Verdict.GetVerdict() != m1pv1.Verdict_VERDICT_VIOLATED {
					t.Fatalf("fused %v, want VIOLATED — the bundle no longer makes this task blockable", e.Verdict.GetVerdict())
				}
				return
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatal("the engine never published")
	}

	g := NewGate(eng.Reader(), blocks, optedInDir(t))
	g.TaskFor = ownAll
	publish()
	for i := range maxConsecutiveBlocks {
		if v := g.Answer(query(1, 5000), testSession); v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_BLOCK {
			t.Fatalf("block %d: got %v %q", i+1, v.GetDecision(), v.GetReason())
		}
	}
	if v := g.Answer(query(1, 5000), testSession); !strings.Contains(v.GetReason(), "consecutive") {
		t.Fatalf("cap not reached: %v %q", v.GetDecision(), v.GetReason())
	}

	publish() // new evidence — no longer the same situation
	if v := g.Answer(query(1, 5000), testSession); v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_BLOCK {
		t.Fatalf("after a publish the gate answered %v %q — the cap has degraded to three blocks per task per daemon lifetime", v.GetDecision(), v.GetReason())
	}
}

// TestGateHourlyCeiling: blocks across DIFFERENT tasks share the hourly
// ceiling; at the ceiling every task allows (M1E-5002).
func TestGateHourlyCeiling(t *testing.T) {
	g := blockableGate(t, stubReader{
		{1}: violatedEntry(false, false),
		{2}: violatedEntry(false, false),
		{3}: violatedEntry(false, false),
	})
	g.HourlyCeiling = 2
	g.Answer(query(1, 5000), testSession) // block 1
	g.Answer(query(2, 5000), testSession) // block 2 — ceiling reached
	v := g.Answer(query(3, 5000), testSession)
	if v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_ALLOW || !strings.Contains(v.GetReason(), "hourly") {
		t.Fatalf("over-ceiling answer %v %q, want M1E-5002 hourly allow", v.GetDecision(), v.GetReason())
	}
}

// TestGateDeadlineExpired: a deadline that really has expired while the
// handler ran answers allow and accounts Dropped{gate_timeout} (M1E-5001) —
// before the cache is read.
func TestGateDeadlineExpired(t *testing.T) {
	g := blockableGate(t, stubReader{{1}: violatedEntry(false, false)})
	base := time.Now()
	calls := 0
	g.Now = func() time.Time {
		calls++
		return base.Add(time.Duration(calls-1) * 10 * time.Second)
	}
	dropped := 0
	g.OnDropped = func(r string) {
		if r != "gate_timeout" {
			t.Fatalf("dropped reason %q", r)
		}
		dropped++
	}
	v := g.Answer(query(1, 5000), testSession)
	if v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_ALLOW || !strings.Contains(v.GetReason(), CodeGateTimeout) || dropped != 1 {
		t.Fatalf("expired deadline: %v %q dropped=%d", v.GetDecision(), v.GetReason(), dropped)
	}
}

// TestGateDeadlineUnspecified pins D-Y(c): deadline_ms == 0 is UNSPECIFIED,
// not expired. The query is answered from the cache under the daemon's own
// 5 ms budget — a writer that omits the field is gated, not silently exempt,
// and nothing is accounted as a timeout.
func TestGateDeadlineUnspecified(t *testing.T) {
	g := blockableGate(t, stubReader{{1}: violatedEntry(false, false)})
	g.OnDropped = func(string) { t.Fatal("an unstated deadline is not a gate_timeout") }
	v := g.Answer(query(1, 0), testSession)
	if v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_BLOCK {
		t.Fatalf("deadline_ms=0 answered %v %q, want the ordinary cache answer", v.GetDecision(), v.GetReason())
	}
}

// TestGateCacheMiss: no entry for the task ⇒ ALLOW + Dropped{gate_timeout}
// (M1E-5001) — a verdict subsystem failure can never block a developer.
func TestGateCacheMiss(t *testing.T) {
	g := blockableGate(t, stubReader{})
	dropped := 0
	g.OnDropped = func(string) { dropped++ }
	v := g.Answer(query(9, 5000), testSession)
	if v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_ALLOW || !strings.Contains(v.GetReason(), "cache miss") || dropped != 1 {
		t.Fatalf("cache miss: %v %q dropped=%d", v.GetDecision(), v.GetReason(), dropped)
	}
}

// TestGateSentinelIsNeverAnAddress is D-AA part 1: the all-zero TaskID is a
// sentinel, so a query that resolves to nothing must never reach the cache, the
// consecutive cap or the hourly ceiling under it. A cache deliberately seeded
// AT the sentinel is the trap — before D-AA it answered BLOCK.
func TestGateSentinelIsNeverAnAddress(t *testing.T) {
	g := blockableGate(t, stubReader{{}: violatedEntry(false, false)})
	dropped := 0
	g.OnDropped = func(string) { dropped++ }
	v := g.Answer(&m1pv1.GateQuery{Gate: m1pv1.GateKind_GATE_KIND_STOP, DeadlineMs: 5000}, testSession)
	if v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_ALLOW || dropped != 1 {
		t.Fatalf("empty task_id answered %v %q dropped=%d, want a fail-open miss", v.GetDecision(), v.GetReason(), dropped)
	}
	if !strings.Contains(v.GetReason(), CodeGateTimeout) {
		t.Fatalf("unresolved-task reason %q, want the %s posture", v.GetReason(), CodeGateTimeout)
	}
}

// TestGateHonoursOnlyItsOwnSessionsTask is D-AA part 3: naming a task is
// allowed, naming ANOTHER session's task is a miss and not a lookup.
func TestGateHonoursOnlyItsOwnSessionsTask(t *testing.T) {
	g := blockableGate(t, stubReader{{1}: violatedEntry(false, false)})
	if v := g.Answer(query(1, 5000), testSession); v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_BLOCK {
		t.Fatalf("owning session answered %v %q, want BLOCK", v.GetDecision(), v.GetReason())
	}
	other := [16]byte{0xBB}
	if v := g.Answer(query(1, 5000), other); v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_ALLOW {
		t.Fatalf("a foreign session read task 1 and got %v %q", v.GetDecision(), v.GetReason())
	}
}

// TestGateStaleCert pins the fail-static posture: a stale-bundle entry
// answers allow flagged M1E-3006, regardless of the fused verdict.
func TestGateStaleCert(t *testing.T) {
	g := blockableGate(t, stubReader{{1}: violatedEntry(false, true)})
	v := g.Answer(query(1, 5000), testSession)
	if v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_ALLOW || !strings.Contains(v.GetReason(), "stale_cert") {
		t.Fatalf("stale entry: %v %q, want allow + stale_cert", v.GetDecision(), v.GetReason())
	}
}

// TestGateLatency asserts the 08 §4.2 budget on the handler itself (not the
// socket): a cache-hit answer in ≤5 ms. Measured warm, worst-of-100.
func TestGateLatency(t *testing.T) {
	g := blockableGate(t, stubReader{{1}: violatedEntry(true, false)})
	q := query(1, 5000)
	g.Answer(q, testSession) // warm the off-check stat path
	samples := make([]time.Duration, 0, 100)
	for range 100 {
		start := time.Now()
		g.Answer(q, testSession)
		samples = append(samples, time.Since(start))
	}
	slices.Sort(samples)
	// p90 is the handler; the worst sample on a shared Windows runner is one scheduler quantum, so it only bounds a hang.
	if p90, worst := samples[89], samples[99]; p90 > 5*time.Millisecond || worst > 50*time.Millisecond {
		t.Fatalf("gate handler p90 %v (budget 5ms, 08 §4.2), worst %v (hang ceiling 50ms)", p90, worst)
	}
}

// TestGateReasonSurfacesUnknownVoters: D-X made unlisted voters an accounting
// fact so they would be VISIBLE. The cache has counted them since it was
// written and nothing in the daemon read the field, so a BLOCK fused from one
// listed voter while three unlisted ones also ran was indistinguishable from
// unanimity.
func TestGateReasonSurfacesUnknownVoters(t *testing.T) {
	e := violatedEntry(false, false)
	e.UnknownVoters = 3
	g := blockableGate(t, stubReader{{1}: e})
	v := g.Answer(query(1, 5000), testSession)
	if v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_BLOCK {
		t.Fatalf("decision %v, want BLOCK", v.GetDecision())
	}
	if !strings.Contains(v.GetReason(), "3 unlisted") {
		t.Fatalf("BLOCK reason %q does not account the 3 unlisted votes (D-X)", v.GetReason())
	}
	// And an entry with none says nothing — the note is a fact, not decoration.
	g2 := blockableGate(t, stubReader{{1}: violatedEntry(false, false)})
	if r := g2.Answer(query(1, 5000), testSession).GetReason(); strings.Contains(r, "unlisted") {
		t.Fatalf("reason %q annotates zero unlisted votes", r)
	}
}

// TestGateHourlyCeilingIsPerSession is D-AN(a): the ceiling used to be an
// unkeyed counter, so one session burning it disabled gating for every other
// session on the box until the window rolled. It fails toward ALLOW, which is
// exactly why nobody would ever have reported it.
func TestGateHourlyCeilingIsPerSession(t *testing.T) {
	g := NewGate(stubReader{
		{1}: violatedEntry(false, false),
		{2}: violatedEntry(false, false),
	}, verdict.NewBlocks(), optedInDir(t))
	// Every session owns the task it names here; the point under test is the
	// ceiling, not D-AA's resolution.
	g.TaskFor = func(_, want [16]byte) ([16]byte, bool) { return want, want != [16]byte{} }
	g.HourlyCeiling = 1

	if v := g.Answer(query(1, 5000), testSession); v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_BLOCK {
		t.Fatalf("session A's first query %v %q, want BLOCK", v.GetDecision(), v.GetReason())
	}
	other := [16]byte{0xBB}
	if v := g.Answer(query(2, 5000), other); v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_BLOCK {
		t.Fatalf("session B answered %v %q on its own task — session A's blocks disabled B's gating", v.GetDecision(), v.GetReason())
	}
	// A is genuinely at ITS ceiling: the counter still exists, it is just keyed.
	if v := g.Answer(query(1, 5000), testSession); !strings.Contains(v.GetReason(), "hourly") {
		t.Fatalf("session A over its own ceiling answered %v %q", v.GetDecision(), v.GetReason())
	}
}

// TestGateBlockReasonStatesNoFalseInequality is D-AN(c). !Stop is also how "no
// knee table", "n below the first row" (D-Y(b)) and "no p_lcb on the row" (D-Z)
// reach the BLOCK branch, and printing the inequality there stated an
// arithmetically FALSE one — 0.000 · 10.00 > 0.50 — which reads as the
// "absent collapses to certainly-hopeless" that D-Z forbids.
func TestGateBlockReasonStatesNoFalseInequality(t *testing.T) {
	e := violatedEntry(false, false)
	e.Knee = verdict.KneeState{N: 1, VTask: 10, CostBasis: "usd"} // nothing evaluated
	g := blockableGate(t, stubReader{{1}: e})
	v := g.Answer(query(1, 5000), testSession)
	if v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_BLOCK {
		t.Fatalf("decision %v, want BLOCK (an unevaluable knee never arrests continuation)", v.GetDecision())
	}
	for _, claim := range []string{">", "p̂_LCB", "0.000"} {
		if strings.Contains(v.GetReason(), claim) {
			t.Fatalf("reason %q asserts %q, but no inequality was evaluated", v.GetReason(), claim)
		}
	}
	if !strings.Contains(v.GetReason(), "not evaluable") {
		t.Fatalf("reason %q does not say the knee was not evaluable", v.GetReason())
	}
	// And an entry that WAS evaluated still shows its arithmetic.
	g2 := blockableGate(t, stubReader{{1}: violatedEntry(false, false)})
	if r := g2.Answer(query(1, 5000), testSession).GetReason(); !strings.Contains(r, "(attempt 2, repair round 2): p̂_LCB 0.400 · V 10.00 > c(r) 1.00") {
		t.Fatalf("an evaluated knee lost its arithmetic: %q", r)
	}
}

// TestGatePriorKneeIsNotWordedAsAMeasurement is ADR-0012's wording rule: a bootstrap prior reads "prior p(r)", never p̂_LCB, and the reason names both n and r.
func TestGatePriorKneeIsNotWordedAsAMeasurement(t *testing.T) {
	below, stop := violatedEntry(false, false), violatedEntry(true, false)
	below.Knee.N, below.Knee.R, below.Knee.Basis = 3, 1, "prior"
	stop.Knee.N, stop.Knee.R, stop.Knee.Basis = 5, 3, "prior"
	g := blockableGate(t, stubReader{{1}: below, {2}: stop})
	if r := g.Answer(query(1, 5000), testSession).GetReason(); r != "verdict violated below the knee (attempt 3, repair round 1): prior p(r) 0.400 · V 10.00 > c(r) 1.00" {
		t.Fatalf("block reason %q", r)
	}
	v := g.Answer(query(2, 5000), testSession)
	if !strings.Contains(v.GetReason(), "stop at attempt 5, repair round 3 — prior p(r) 0.400") || strings.Contains(v.GetSystemMessage(), "p̂_LCB") {
		t.Fatalf("knee reason %q / message %q", v.GetReason(), v.GetSystemMessage())
	}
}

// TestGateUnrecordedKneeBasisClaimsNeither is ADR-0013: a bundle that did not say where p came from is worded as neither a prior nor a measured bound.
func TestGateUnrecordedKneeBasisClaimsNeither(t *testing.T) {
	stop := violatedEntry(true, false)
	stop.Knee.N, stop.Knee.R, stop.Knee.Basis = 4, 2, "unknown"
	v := blockableGate(t, stubReader{{1}: stop}).Answer(query(1, 5000), testSession)
	if !strings.Contains(v.GetReason(), "repair round 2 — p(r), basis unrecorded 0.400") || strings.Contains(v.GetSystemMessage(), "p̂_LCB") || strings.Contains(v.GetSystemMessage(), "prior p(r)") {
		t.Fatalf("knee reason %q / message %q", v.GetReason(), v.GetSystemMessage())
	}
}

// segScript drives a real Segmenter through the prompt→tool opening that mints
// a task, so these two tests exercise the shipping resolver rather than a stub
// of it — the defect they pin lived precisely in the resolver.
func segScript(s *taskseg.Segmenter, sess [16]byte, files ...string) {
	s.Observe(&m1pv1.Event{SessionId: sess[:], Body: &m1pv1.Event_Turn{
		Turn: &m1pv1.Turn{Initiator: m1pv1.Initiator_INITIATOR_HUMAN},
	}}, nil)
	s.Observe(&m1pv1.Event{SessionId: sess[:], Body: &m1pv1.Event_ToolUse{
		ToolUse: &m1pv1.ToolUse{ToolName: "Edit"},
	}}, files)
}

// segRevised feeds the REVISED VerdictEvent the Engine emits for a slow-anchor
// completion and returns the resolutions it closed with.
func segRevised(s *taskseg.Segmenter, sess, task [16]byte) []m1pv1.Resolution {
	var out []m1pv1.Resolution
	for _, ev := range s.Observe(&m1pv1.Event{
		SessionId: sess[:], TaskId: task[:], EventId: make([]byte, 16),
		Body: &m1pv1.Event_VerdictEvent{VerdictEvent: &m1pv1.VerdictEvent{
			Stage: m1pv1.VerdictStage_VERDICT_STAGE_REVISED, Verdict: m1pv1.Verdict_VERDICT_VIOLATED,
		}},
	}, nil) {
		if c, ok := ev.Body.(*m1pv1.Event_TaskClose); ok {
			out = append(out, c.TaskClose.GetResolution())
		}
	}
	return out
}

// TestGateBlocksAfterAVerdictClosedTheTask is D-AR, the chain that made the
// stop gate stop working on a real session: a slow anchor publishes REVISED
// VIOLATED, the emitted VerdictEvent closes the task RESOLUTION_VERDICT for the
// ledger, and the shim's next Stop query carries an empty task_id by design
// (D-AA). Ledger closure is not gate lifetime — build, vet and test are the
// strongest evidence class in the system and were the one class that
// structurally could not stop the agent.
func TestGateBlocksAfterAVerdictClosedTheTask(t *testing.T) {
	seg := taskseg.New(nil)
	segScript(seg, testSession, "a.go")
	task, ok := seg.TaskFor(testSession, [16]byte{})
	if !ok {
		t.Fatal("setup: the segmenter opened no task")
	}
	if got := segRevised(seg, testSession, task); len(got) != 1 || got[0] != m1pv1.Resolution_RESOLUTION_VERDICT {
		t.Fatalf("the verdict closed %v, want exactly one RESOLUTION_VERDICT (the denominator must be untouched)", got)
	}

	g := NewGate(stubReader{task: violatedEntry(false, false)}, verdict.NewBlocks(), optedInDir(t))
	g.TaskFor = seg.TaskFor
	// The shim's sentinel query: task_id empty, exactly as gate.rs sends it.
	v := g.Answer(&m1pv1.GateQuery{Gate: m1pv1.GateKind_GATE_KIND_STOP, DeadlineMs: 5000}, testSession)
	if v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_BLOCK {
		t.Fatalf("decision %v reason %q — a VERDICT_VIOLATED sat in the cache and the gate answered allow", v.GetDecision(), v.GetReason())
	}
}

// TestReopenedTaskIsNotUngatedByAStaleStreak is D-AR's consequence. R3 reopens
// under the SAME task_id, so a consecutive-block streak left at the cap
// short-circuits the reopened attempt's first query at step 3 (M1E-5002, ALLOW)
// BEFORE the cache is ever read: the new attempt runs entirely ungated on the
// previous attempt's state. D-Y always said the streak resets on task close.
func TestReopenedTaskIsNotUngatedByAStaleStreak(t *testing.T) {
	blocks := verdict.NewBlocks()
	seg := taskseg.New(nil)
	seg.OnClose = func(t taskseg.TaskID) { blocks.ResetTask(t) }
	segScript(seg, testSession, "a.go")
	task, _ := seg.TaskFor(testSession, [16]byte{})

	g := NewGate(stubReader{task: violatedEntry(false, false)}, blocks, optedInDir(t))
	g.TaskFor = seg.TaskFor
	sentinel := &m1pv1.GateQuery{Gate: m1pv1.GateKind_GATE_KIND_STOP, DeadlineMs: 5000}
	for i := range maxConsecutiveBlocks {
		if v := g.Answer(sentinel, testSession); v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_BLOCK {
			t.Fatalf("block %d answered %v %q, want BLOCK", i, v.GetDecision(), v.GetReason())
		}
	}
	if v := g.Answer(sentinel, testSession); !strings.Contains(v.GetReason(), CodeGateCap) {
		t.Fatalf("the cap did not engage: %v %q", v.GetDecision(), v.GetReason())
	}

	segRevised(seg, testSession, task)  // ledger close
	segScript(seg, testSession, "a.go") // R3: same task_id, new attempt
	if again, _ := seg.TaskFor(testSession, [16]byte{}); again != task {
		t.Fatalf("setup: R3 minted %x instead of reopening %x", again, task)
	}
	if v := g.Answer(sentinel, testSession); v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_BLOCK {
		t.Fatalf("the reopened attempt answered %v %q — it ran ungated on the previous attempt's streak", v.GetDecision(), v.GetReason())
	}
}

// TestGateBlockCarriesEvidenceRef is FR-VERIFY-011's below-knee half at the
// daemon: a BLOCK names the failing anchor's typed evidence in evidence_ref
// (the shim appends it as `[evidence: …]` to the continuation reason), and no
// ALLOW — knee stop, cache miss, cap — carries one, because none of them has a
// failing anchor to name.
func TestGateBlockCarriesEvidenceRef(t *testing.T) {
	const ref = "ruff:E501 errors=2 warnings=0 files=1"
	entries := stubReader{{1}: violatedEntry(false, false), {2}: violatedEntry(true, false)}
	g := blockableGate(t, entries)
	g.Evidence = func(task verdict.TaskID) string {
		if task == (verdict.TaskID{1}) {
			return ref
		}
		return "evidence for a task that was not asked about"
	}

	v := g.Answer(query(1, 5000), testSession)
	if v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_BLOCK {
		t.Fatalf("decision %v %q, want BLOCK", v.GetDecision(), v.GetReason())
	}
	if v.GetEvidenceRef() != ref {
		t.Fatalf("BLOCK evidence_ref %q, want the failing anchor's typed evidence %q", v.GetEvidenceRef(), ref)
	}

	// At the knee: ALLOW with the verdict surfaced, no retry target to name.
	if v := g.Answer(query(2, 5000), testSession); v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_ALLOW || v.GetEvidenceRef() != "" {
		t.Fatalf("knee stop answered %v evidence_ref %q, want ALLOW with none", v.GetDecision(), v.GetEvidenceRef())
	}
	// Cache miss: fail-open ALLOW, nothing to name.
	if v := g.Answer(query(3, 5000), testSession); v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_ALLOW || v.GetEvidenceRef() != "" {
		t.Fatalf("cache miss answered %v evidence_ref %q, want ALLOW with none", v.GetDecision(), v.GetEvidenceRef())
	}
	// No seam wired: BLOCK still blocks, evidence_ref honestly empty.
	g.Evidence = nil
	if v := g.Answer(query(1, 5000), testSession); v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_BLOCK || v.GetEvidenceRef() != "" {
		t.Fatalf("unwired seam answered %v evidence_ref %q, want BLOCK with none", v.GetDecision(), v.GetEvidenceRef())
	}
}

// gates is a bundle gates section as the decoder hands it over.
func gates(enabled bool, mcb uint8, hourly uint64) policy.GatesSection {
	return policy.GatesSection{StopGateEnabled: enabled, MaxConsecutiveBlocks: mcb, HourlyBlockCeiling: hourly}
}

// blockUntilAllow answers the query until the gate stops blocking and returns
// how many BLOCKs it gave first, plus the first ALLOW.
func blockUntilAllow(t *testing.T, g *Gate, q *m1pv1.GateQuery) (int, *m1pv1.GateVerdict) {
	t.Helper()
	for n := range 10 {
		if v := g.Answer(q, testSession); v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_BLOCK {
			return n, v
		}
	}
	t.Fatal("the gate blocked 10 times in a row -- no cap is live")
	return 0, nil
}

// TestGatesClampNeverExceedsLocalHardCaps is FR-VERIFY-010 at the gate: a
// bundle's gates section may lower the consecutive cap and the hourly ceiling
// and can never raise either past the compiled defaults -- including a value
// the decoder's own bound should already have refused.
func TestGatesClampNeverExceedsLocalHardCaps(t *testing.T) {
	cases := []struct {
		name    string
		sec     policy.GatesSection
		wantMCB int
		wantHC  uint32
	}{
		{"at the caps", gates(true, 3, 30), 3, 30},
		{"lowered", gates(true, 2, 10), 2, 10},
		{"decoder-bypassed raise", gates(true, 4, 31), 3, 30},
		{"zero means built-in", gates(true, 0, 0), 3, DefaultHourlyCeiling},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := blockableGate(t, stubReader{{1}: violatedEntry(false, false)})
			g.ApplyGates(tc.sec)
			if g.HourlyCeiling != tc.wantHC {
				t.Fatalf("hourly ceiling %d after %+v, want %d", g.HourlyCeiling, tc.sec, tc.wantHC)
			}
			// The consecutive cap is asserted by behaviour: blocks stop at it.
			if n, v := blockUntilAllow(t, g, query(1, 5000)); n != tc.wantMCB || !strings.Contains(v.GetReason(), "consecutive") {
				t.Fatalf("%d blocks then %v %q after %+v, want %d then the consecutive cap", n, v.GetDecision(), v.GetReason(), tc.sec, tc.wantMCB)
			}
		})
	}
}

// TestStopGateDisabledByBundleAllows: stop_gate_enabled=false is the
// closed→open move a bundle IS allowed to make (FR-POLICY-006, 11 §9's "ship a
// bundle with gates opened"). The answer is ALLOW under M1E-5002 before any
// counter or accounting, and a later bundle may close it again.
func TestStopGateDisabledByBundleAllows(t *testing.T) {
	g := blockableGate(t, stubReader{{1}: violatedEntry(false, false)})
	g.ApplyGates(gates(false, 3, 30))
	v := g.Answer(query(1, 5000), testSession)
	if v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_ALLOW || !strings.Contains(v.GetReason(), CodeGateCap) || !strings.Contains(v.GetReason(), "opened") {
		t.Fatalf("bundle-opened gate answered %v %q, want ALLOW %s", v.GetDecision(), v.GetReason(), CodeGateCap)
	}
	// The verdict still rides the ALLOW (the human sees what was found), and
	// an opened block is not a block: no streak, no ceiling charge.
	if v.GetVerdict() != m1pv1.Verdict_VERDICT_VIOLATED || g.blocks.Counters(testSession, verdict.TaskID{1}, time.Now()).Consecutive != 0 {
		t.Fatalf("opened answer %v counted a block or dropped the verdict", v)
	}
	g.ApplyGates(gates(true, 3, 30))
	if v := g.Answer(query(1, 5000), testSession); v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_BLOCK {
		t.Fatalf("re-closed gate answered %v %q, want BLOCK", v.GetDecision(), v.GetReason())
	}
}

// TestStopGateRequiresLocalOptIn is FR-POLICY-006's other half: no on-disk
// opt-in artifact ⇒ ALLOW whatever the bundle says, so the control plane can
// never tighten an edge into blocking a developer who did not ask for it.
func TestStopGateRequiresLocalOptIn(t *testing.T) {
	dir := t.TempDir() // no artifact
	g := NewGate(stubReader{{1}: violatedEntry(false, false)}, verdict.NewBlocks(), dir)
	g.TaskFor = ownAll
	g.ApplyGates(gates(true, 3, 30)) // the bundle asks for blocking
	v := g.Answer(query(1, 5000), testSession)
	if v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_ALLOW || !strings.Contains(v.GetReason(), CodeGateCap) || !strings.Contains(v.GetReason(), "opted in") {
		t.Fatalf("no opt-in answered %v %q, want ALLOW %s naming the opt-in", v.GetDecision(), v.GetReason(), CodeGateCap)
	}
	// A malformed or negative artifact is not an opt-in either.
	for _, body := range []string{`{"stop_gate":false}`, `not json`, ``} {
		writeOptIn(t, dir, body)
		if v := g.Answer(query(1, 5000), testSession); v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_ALLOW {
			t.Fatalf("artifact %q armed the gate: %v %q", body, v.GetDecision(), v.GetReason())
		}
	}
	// The real artifact arms the BLOCK path -- without a daemon restart.
	writeOptIn(t, dir, `{"stop_gate":true,"ts":"2026-09-15T00:00:00Z","user":"test"}`)
	if v := g.Answer(query(1, 5000), testSession); v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_BLOCK {
		t.Fatalf("opted-in gate answered %v %q, want BLOCK below the knee", v.GetDecision(), v.GetReason())
	}
}

// TestExplorationEpsilonNeedsLocalOptIn — D-EF's edge half: ε>0 is 0 without a local "exploration": true; stop_gate neither grants nor loses it.
func TestExplorationEpsilonNeedsLocalOptIn(t *testing.T) {
	dir := t.TempDir()
	for _, body := range []string{"", `{"stop_gate":true}`, `{"exploration":false}`, `{"exploration":"true"}`, `not json`} {
		if body != "" {
			writeOptIn(t, dir, body)
		}
		if got := ExplorationEpsilon(dir, 0.05); got != 0 {
			t.Fatalf("artifact %q applied ε %v, want 0", body, got)
		}
	}
	writeOptIn(t, dir, `{"stop_gate":false,"exploration":true}`)
	if got := ExplorationEpsilon(dir, 0.05); got != 0.05 {
		t.Fatalf("exploration opt-in applied ε %v, want 0.05", got)
	}
	if optedIn(dir).StopGate {
		t.Fatal("exploration opt-in must not arm the stop gate")
	}
}

// TestHourlyCeilingFromBundleIsWiredIntoTheGate: the bundle's
// hourly_block_ceiling reaches the ceiling check through ApplyGates -- blocks
// stop at the bundle's number, not at DefaultHourlyCeiling.
func TestHourlyCeilingFromBundleIsWiredIntoTheGate(t *testing.T) {
	entries := stubReader{{1}: violatedEntry(false, false), {2}: violatedEntry(false, false), {3}: violatedEntry(false, false)}
	g := blockableGate(t, entries)
	g.ApplyGates(gates(true, 3, 2))
	g.Answer(query(1, 5000), testSession) // block 1
	g.Answer(query(2, 5000), testSession) // block 2 -- the bundle's ceiling
	v := g.Answer(query(3, 5000), testSession)
	if v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_ALLOW || !strings.Contains(v.GetReason(), "hourly") {
		t.Fatalf("third block under a bundle ceiling of 2 answered %v %q, want M1E-5002 hourly allow", v.GetDecision(), v.GetReason())
	}
	// Control: the same three queries under the compiled default all block.
	g2 := blockableGate(t, entries)
	g2.ApplyGates(gates(true, 3, 0))
	for i := 1; i <= 3; i++ {
		if v := g2.Answer(query(byte(i), 5000), testSession); v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_BLOCK {
			t.Fatalf("default ceiling: query %d answered %v %q, want BLOCK", i, v.GetDecision(), v.GetReason())
		}
	}
}

// countingReader counts every cache read the gate makes.
type countingReader struct {
	verdict.Reader
	gets atomic.Int64
}

func (c *countingReader) Get(t verdict.TaskID) (verdict.Cached, bool) {
	c.gets.Add(1)
	return c.Reader.Get(t)
}

// TestGateReadDoesNoFusionOrAnchorWork (FR-VERIFY-007): the Engine's injected clock is the Fuser-call counter (step calls it once per Fuse); no anchor seam reaches a Gate at all.
func TestGateReadDoesNoFusionOrAnchorWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var fuses atomic.Int64
	blocks := verdict.NewBlocks()
	eng := verdict.NewEngine(verdict.BundleMatrices{
		Priors: verdict.DefaultPriors,
		Verifiers: map[string]verdict.VerifierParams{"build": {Confusion: verdict.Confusion{
			{0.98, 0.01, 0.01}, {0.02, 0.97, 0.01}, {0.10, 0.10, 0.80}, {0.34, 0.33, 0.33},
		}}},
		VTask: 10, CostBasis: "usd",
	}, blocks, func() time.Time { fuses.Add(1); return time.Now() })
	go eng.Run(ctx)

	var task verdict.TaskID
	task[0] = 1
	eng.Recompute(task, []verdict.AnchorVote{{AnchorID: "build", Vote: m1pv1.Verdict_VERDICT_VIOLATED}}, 0)
	for range 200 {
		if _, ok := eng.Reader().Get(task); ok {
			break
		}
		time.Sleep(time.Millisecond)
	}
	before, ok := eng.Reader().Get(task)
	if !ok || fuses.Load() != 1 {
		t.Fatalf("priming: cached %v, fuses %d — the counter does not count", ok, fuses.Load())
	}

	reader := &countingReader{Reader: eng.Reader()}
	g := NewGate(reader, blocks, optedInDir(t))
	g.TaskFor = ownAll
	const n = 50
	for i := range n {
		if v := g.Answer(query(1, 5000), testSession); v.GetDecision() == m1pv1.GateDecision_GATE_DECISION_UNSPECIFIED {
			t.Fatalf("answer %d: %v", i, v)
		}
	}
	// The consecutive cap trips inside the loop and short-circuits before the read, so reads ≤ n.
	if got := reader.gets.Load(); got == 0 || got > n {
		t.Fatalf("%d cache reads for %d answers", got, n)
	}
	time.Sleep(20 * time.Millisecond)
	if fuses.Load() != 1 {
		t.Fatalf("%d fusion passes during %d gate answers, want 0 (FR-VERIFY-007: the gate reads, never computes)", fuses.Load()-1, n)
	}
	after, _ := eng.Reader().Get(task)
	if after.Verdict != before.Verdict || !after.ComputedAt.Equal(before.ComputedAt) {
		t.Fatal("the cache entry changed under gate reads — something published")
	}
}

// TestGateKneeCarriesSystemMessage is FR-VERIFY-011's at-knee half at the
// daemon (08 §5.1 Stop row, founder ruling 2026-09-16): an armed gate that
// would have BLOCKed but for the knee answers ALLOW with system_message
// naming the verdict, the knee economics and the typed evidence — for the
// human, so it is not the continuation reason and evidence_ref stays empty.
// Below the knee, on a non-violated knee stop, on an unarmed gate and on a
// stale bundle it is empty: the shim prints nothing it did not get.
func TestGateKneeCarriesSystemMessage(t *testing.T) {
	const ref = "cargo-check-warm:E0001 errors=1 warnings=0 files=1"
	satisfiedAtKnee := violatedEntry(true, false)
	satisfiedAtKnee.Verdict.Verdict = m1pv1.Verdict_VERDICT_SATISFIED
	entries := stubReader{{1}: violatedEntry(true, false), {2}: violatedEntry(false, false), {3}: satisfiedAtKnee, {4}: violatedEntry(true, true)}
	g := blockableGate(t, entries)
	g.Evidence = func(task verdict.TaskID) string {
		if task == (verdict.TaskID{1}) {
			return ref
		}
		return ""
	}
	var arrests []string
	g.OnArrest = func(session, task [16]byte, k verdict.KneeState, evidenceRef string) {
		arrests = append(arrests, fmt.Sprintf("%x task %x n=%d stop=%v %s", session[:2], task[:1], k.N, k.Stop, evidenceRef))
	}

	v := g.Answer(query(1, 5000), testSession)
	if want := []string{fmt.Sprintf("%x task 01 n=2 stop=true %s", testSession[:2], ref)}; !reflect.DeepEqual(arrests, want) {
		t.Fatalf("OnArrest saw %q, want %q", arrests, want)
	}
	if v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_ALLOW || v.GetEvidenceRef() != "" {
		t.Fatalf("knee answered %v evidence_ref %q, want ALLOW with none (the shim reads evidence_ref on BLOCK only)", v.GetDecision(), v.GetEvidenceRef())
	}
	want := "mark1 stop-gate: retry loop arrested at the knee — verdict violated; knee governor: stop at attempt 2, repair round 2 — p̂_LCB 0.400 · V 10.00 ≤ c(r) 1.00 under usd; evidence: " + ref
	if v.GetSystemMessage() != want {
		t.Fatalf("system_message\n got: %q\nwant: %q", v.GetSystemMessage(), want)
	}
	if strings.Contains(v.GetSystemMessage(), "/") {
		t.Fatalf("system_message carries a path: %q", v.GetSystemMessage())
	}
	for name, task := range map[string]byte{"below the knee": 2, "satisfied at the knee": 3, "stale at the knee": 4} {
		if v := g.Answer(query(task, 5000), testSession); v.GetSystemMessage() != "" {
			t.Fatalf("%s: system_message %q, want empty", name, v.GetSystemMessage())
		}
	}
	if len(arrests) != 1 {
		t.Fatalf("OnArrest fired %d times over the non-arrest answers, want exactly the one knee stop", len(arrests))
	}
	// No evidence seam: the message still surfaces the verdict and the knee.
	g.Evidence = nil
	if v := g.Answer(query(1, 5000), testSession); v.GetSystemMessage() != strings.TrimSuffix(want, "; evidence: "+ref) {
		t.Fatalf("unwired evidence: system_message %q", v.GetSystemMessage())
	}
	// Unarmed: the gate never forced a loop, so there is nothing to arrest.
	g.ApplyGates(gates(false, 0, 0))
	if v := g.Answer(query(1, 5000), testSession); v.GetSystemMessage() != "" {
		t.Fatalf("gate opened by policy: system_message %q, want empty", v.GetSystemMessage())
	}
	g = NewGate(entries, verdict.NewBlocks(), t.TempDir())
	g.TaskFor = ownAll
	if v := g.Answer(query(1, 5000), testSession); v.GetSystemMessage() != "" || v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_ALLOW {
		t.Fatalf("not opted in: %v system_message %q, want ALLOW with empty", v.GetDecision(), v.GetSystemMessage())
	}
}

// correctionEngine is the shipping verdict.Engine under a decisive verifier,
// scoped to testSession, publishing on the test's say-so.
func correctionEngine(t *testing.T) (*verdict.Engine, func(task verdict.TaskID, revised bool, v m1pv1.Verdict)) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	eng := verdict.NewEngine(verdict.BundleMatrices{
		Priors: verdict.DefaultPriors,
		Verifiers: map[string]verdict.VerifierParams{"build": {Confusion: verdict.Confusion{
			{0.98, 0.01, 0.01},
			{0.02, 0.97, 0.01},
			{0.10, 0.10, 0.80},
			{0.34, 0.33, 0.33},
		}}},
		VTask: 10, CostBasis: "usd",
	}, verdict.NewBlocks(), nil)
	eng.SessionFor = func(verdict.TaskID) ([16]byte, bool) { return testSession, true }
	go eng.Run(ctx)
	publish := func(task verdict.TaskID, revised bool, v m1pv1.Verdict) {
		t.Helper()
		prev, _ := eng.Reader().Get(task)
		votes := []verdict.AnchorVote{{AnchorID: "build", Vote: v}}
		if revised {
			eng.PublishRevised(task, votes, 1)
		} else {
			eng.Recompute(task, votes, 1)
		}
		for range 200 {
			if e, ok := eng.Reader().Get(task); ok && e.ComputedAt.After(prev.ComputedAt) {
				if e.Verdict.GetVerdict() != v {
					t.Fatalf("build:%v fused to %v", v, e.Verdict.GetVerdict())
				}
				return
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatal("the engine never published")
	}
	return eng, publish
}

// TestGateCorrectionChannelDrainsTheSessionQueue is FR-VERIFY-008's
// correction at the daemon's handler: the CORRECTION pull renders every
// revision the engine queued for the pulling session since its last pull —
// verdict names and the typed evidence, no paths — and a second pull is empty.
// Other channels are not this handler's and answer empty whatever is queued.
func TestGateCorrectionChannelDrainsTheSessionQueue(t *testing.T) {
	eng, publish := correctionEngine(t)
	g := NewGate(eng.Reader(), verdict.NewBlocks(), t.TempDir())
	g.Corrections = eng.TakeCorrections
	g.Evidence = func(task verdict.TaskID) string {
		if task == (verdict.TaskID{1}) {
			return "build:E0001 errors=1 warnings=0 files=1"
		}
		return ""
	}
	correction := ContextQuery{Channel: uint32(m1pv1.InjectionChannel_INJECTION_CHANNEL_CORRECTION), DeadlineMs: 240}
	ctx := context.Background()

	if got := g.Context(ctx, correction, testSession); got != "" {
		t.Fatalf("nothing queued, yet %q", got)
	}
	publish(verdict.TaskID{1}, false, m1pv1.Verdict_VERDICT_SATISFIED)
	publish(verdict.TaskID{1}, true, m1pv1.Verdict_VERDICT_VIOLATED)
	publish(verdict.TaskID{2}, false, m1pv1.Verdict_VERDICT_VIOLATED)
	publish(verdict.TaskID{2}, true, m1pv1.Verdict_VERDICT_SATISFIED)
	for _, ch := range []m1pv1.InjectionChannel{m1pv1.InjectionChannel_INJECTION_CHANNEL_HOOK_CONTEXT, m1pv1.InjectionChannel_INJECTION_CHANNEL_REACTIVE_PITFALL, m1pv1.InjectionChannel_INJECTION_CHANNEL_UNSPECIFIED} {
		if got := g.Context(ctx, ContextQuery{Channel: uint32(ch), Error: "Exit code 1"}, testSession); got != "" {
			t.Fatalf("channel %v answered %q from the gate", ch, got)
		}
	}
	if got := g.Context(ctx, correction, [16]byte{0xBB}); got != "" {
		t.Fatalf("another session pulled this session's corrections: %q", got)
	}
	want := "[mark1 correction] a slow verifier finished after the last verdict: satisfied was revised to violated; evidence: build:E0001 errors=1 warnings=0 files=1\n" +
		ctxCorrectionText
	if got := g.Context(ctx, correction, testSession); got != want {
		t.Fatalf("correction\n got: %q\nwant: %q", got, want)
	}
	if got := g.Context(ctx, correction, testSession); got != "" {
		t.Fatalf("a second pull re-delivered %q", got)
	}
	g.Corrections = nil
	publish(verdict.TaskID{1}, true, m1pv1.Verdict_VERDICT_SATISFIED)
	if got := g.Context(ctx, correction, testSession); got != "" {
		t.Fatalf("unwired seam answered %q", got)
	}
}

// TestContextChainServesBothChannelsOnOneSession is the wiring cmd/main.go
// installs: ContextChain{gate, memory} behind SetContextHandler. Over the real
// session, a CORRECTION pull is answered by the gate and never reaches the
// memory handler's text, and a pitfall pull is answered by the memory handler
// with the gate silent — both replies pinned to the shim's bytes.
func TestContextChainServesBothChannelsOnOneSession(t *testing.T) {
	eng, publish := correctionEngine(t)
	g := NewGate(eng.Reader(), verdict.NewBlocks(), t.TempDir())
	g.Corrections = eng.TakeCorrections
	mem := &recordingContext{got: make(chan ContextQuery, 4), session: make(chan [16]byte, 4), text: ctxReplyText}
	l := listenLoopback(t)
	srv := NewServer(func(context.Context, []byte) error { return nil }, nil)
	srv.SetContextHandler(ContextChain{g, mem})
	go srv.Serve(context.Background(), l) //nolint:errcheck // closed by cleanup
	t.Cleanup(func() { _ = l.Close(); srv.Close() })
	c := dial(t, l.Addr().String())
	hello(t, c)

	publish(verdict.TaskID{1}, false, m1pv1.Verdict_VERDICT_VIOLATED)
	publish(verdict.TaskID{1}, true, m1pv1.Verdict_VERDICT_SATISFIED)
	if err := WriteFrame(c, mustHex(t, ctxCorrectionQueryHex)); err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(readRawFrame(t, c)); got != ctxCorrectionReplyHex {
		t.Fatalf("correction reply %s, want %s", got, ctxCorrectionReplyHex)
	}
	select {
	case q := <-mem.got:
		t.Fatalf("the memory handler saw the CORRECTION query %+v", q)
	default:
	}
	if err := WriteFrame(c, mustHex(t, ctxQueryHex)); err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(readRawFrame(t, c)); got != ctxReplyHex {
		t.Fatalf("pitfall reply %s, want the memory handler's %s", got, ctxReplyHex)
	}
	if q := <-mem.got; q.Channel != uint32(m1pv1.InjectionChannel_INJECTION_CHANNEL_REACTIVE_PITFALL) {
		t.Fatalf("memory handler saw %+v", q)
	}
	// Drained: the next CORRECTION pull falls through to memory, which owns
	// no such channel — an empty reply, the query visible to it only as a miss.
	if err := WriteFrame(c, mustHex(t, ctxCorrectionQueryHex)); err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(readRawFrame(t, c)); got != ctxReplyEmpty {
		t.Fatalf("drained correction reply %s, want %s", got, ctxReplyEmpty)
	}
	if q := <-mem.got; q.Channel != uint32(m1pv1.InjectionChannel_INJECTION_CHANNEL_CORRECTION) {
		t.Fatalf("memory handler saw %+v after the drain", q)
	}
}

// TestApplyGatesArmsALiveGate: a bundle fetched after boot reaches the gate through ApplyGates while Answer serves — the enrollment moment — and the armed/opened posture flips without a restart; -race is the second half of this test.
func TestApplyGatesArmsALiveGate(t *testing.T) {
	entries := stubReader{{1}: violatedEntry(false, false)}
	g := blockableGate(t, entries)
	g.ApplyGates(policy.GatesSection{}) // no bundle at boot: opened (FR-POLICY-005 gates open)
	if v := g.Answer(query(1, 5000), testSession); v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_ALLOW || !strings.Contains(v.GetReason(), "opened") {
		t.Fatalf("boot with no bundle: %v %q, want ALLOW opened by policy", v.GetDecision(), v.GetReason())
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			g.ApplyGates(gates(i%2 == 1, 3, 30))
		}
		g.ApplyGates(gates(true, 3, 30)) // the bootstrap bundle lands
	}()
	for i := 0; i < 200; i++ {
		g.Answer(query(1, 5000), testSession)
	}
	<-done
	g.blocks.ResetTask(verdict.TaskID{1}) // the interleaved blocks hit the cap; new evidence resets it (D-Y)
	if v := g.Answer(query(1, 5000), testSession); v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_BLOCK {
		t.Fatalf("after the bundle applied live: %v %q, want BLOCK", v.GetDecision(), v.GetReason())
	}
}
