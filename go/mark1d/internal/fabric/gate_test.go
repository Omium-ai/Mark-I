package fabric

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"

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
		Knee:       verdict.KneeState{N: 2, PLCB: 0.4, VTask: 10, CostN: 1, CostBasis: "usd", Stop: stop, Stale: stale, Evaluable: true},
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

func blockableGate(t *testing.T, entries stubReader) *Gate {
	t.Helper()
	g := NewGate(entries, verdict.NewBlocks(), t.TempDir())
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

// TestGateConsecutiveCap: the 4th query on a task with 3 consecutive blocks
// answers allow (M1E-5002) without reading the cache decision.
func TestGateConsecutiveCap(t *testing.T) {
	g := blockableGate(t, stubReader{{1}: violatedEntry(false, false)})
	for i := range 3 {
		if v := g.Answer(query(1, 5000), testSession); v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_BLOCK {
			t.Fatalf("block %d: got %v %q", i+1, v.GetDecision(), v.GetReason())
		}
	}
	v := g.Answer(query(1, 5000), testSession)
	if v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_ALLOW || !strings.Contains(v.GetReason(), "consecutive") {
		t.Fatalf("4th answer %v %q, want M1E-5002 consecutive-cap allow", v.GetDecision(), v.GetReason())
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
		for range 200 {
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

	g := NewGate(eng.Reader(), blocks, t.TempDir())
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
	worst := time.Duration(0)
	for range 100 {
		start := time.Now()
		g.Answer(q, testSession)
		if d := time.Since(start); d > worst {
			worst = d
		}
	}
	if worst > 5*time.Millisecond {
		t.Fatalf("gate handler worst case %v, budget 5ms (08 §4.2)", worst)
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
	}, verdict.NewBlocks(), t.TempDir())
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
	if r := g2.Answer(query(1, 5000), testSession).GetReason(); !strings.Contains(r, "p̂_LCB 0.400 · V 10.00 > c(n) 1.00") {
		t.Fatalf("an evaluated knee lost its arithmetic: %q", r)
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

	g := NewGate(stubReader{task: violatedEntry(false, false)}, verdict.NewBlocks(), t.TempDir())
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

	g := NewGate(stubReader{task: violatedEntry(false, false)}, blocks, t.TempDir())
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
