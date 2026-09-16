package verdict

import (
	"context"
	"testing"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

// plcb is the D-Z presence marker in test tables: &v is "the compiler fitted
// this row", nil is "it did not".
func plcb(v float64) *float64 { return &v }

func kneeBundle() BundleMatrices {
	m := golden32Bundle()
	m.VTask = 10.0
	m.CostBasis = "usd"
	// p̂_LCB·V vs c(n): n=1: 8 > 0.5 go; n=2: 4 > 1.0 go; n=3: 1.5 ≤ 2.0 stop.
	m.Knee = []KneeRow{
		{N: 1, CostN: 0.50, PLCB: plcb(0.80)},
		{N: 2, CostN: 1.00, PLCB: plcb(0.40)},
		{N: 3, CostN: 2.00, PLCB: plcb(0.15)},
	}
	return m
}

// step runs one queued job on the test goroutine — the recompute goroutine's
// body, without racing the assertions.
func (e *Engine) drainOne(t *testing.T) {
	t.Helper()
	select {
	case j := <-e.slow:
		e.step(context.Background(), j)
	case j := <-e.fast:
		e.step(context.Background(), j)
	default:
		t.Fatal("no job queued")
	}
}

// TestKneeComputedAtPublish pins 04 §2.3: the knee is evaluated when the
// entry is published — Stop flips across the table with attempt n, and the
// gate-facing Cached carries the full evaluation, not inputs.
func TestKneeComputedAtPublish(t *testing.T) {
	e := NewEngine(kneeBundle(), NewBlocks(), nil)
	task := TaskID{9}

	for _, tc := range []struct {
		n    int
		stop bool
	}{{1, false}, {2, false}, {3, true}, {7, true} /* clamps to last row */} {
		e.Recompute(task, golden32Votes(), tc.n)
		e.drainOne(t)
		got, ok := e.Reader().Get(task)
		if !ok {
			t.Fatalf("n=%d: no cache entry after publish", tc.n)
		}
		if got.Knee.Stop != tc.stop {
			t.Fatalf("n=%d: Stop=%v, want %v (p̂_LCB·V vs c(n))", tc.n, got.Knee.Stop, tc.stop)
		}
		if got.Knee.N != tc.n || got.Knee.VTask != 10.0 || got.Knee.CostBasis != "usd" {
			t.Fatalf("n=%d: knee state %+v not stamped from bundle", tc.n, got.Knee)
		}
		if got.Verdict.Stage != m1pv1.VerdictStage_VERDICT_STAGE_PROVISIONAL {
			t.Fatalf("fast recompute published stage %v, want PROVISIONAL", got.Verdict.Stage)
		}
		if got.ComputedAt.IsZero() {
			t.Fatal("ComputedAt not stamped")
		}
	}
}

// TestStaleBundleNeverStops pins the M1E-3006 fail-static posture: a stale
// bundle still fuses but the knee never stops and the entry is flagged.
func TestStaleBundleNeverStops(t *testing.T) {
	m := kneeBundle()
	m.Stale = true
	e := NewEngine(m, NewBlocks(), nil)
	e.Recompute(TaskID{9}, golden32Votes(), 3) // n=3 stops when fresh
	e.drainOne(t)
	got, _ := e.Reader().Get(TaskID{9})
	if got.Knee.Stop || !got.Knee.Stale {
		t.Fatalf("stale bundle: Stop=%v Stale=%v, want never-stop + flagged", got.Knee.Stop, got.Knee.Stale)
	}
}

// TestRevisedSupersedes pins the fast/slow split: a slow-anchor completion
// publishes REVISED and replaces the PROVISIONAL entry.
func TestRevisedSupersedes(t *testing.T) {
	e := NewEngine(kneeBundle(), NewBlocks(), nil)
	task := TaskID{4}
	e.Recompute(task, golden32Votes(), 1)
	e.drainOne(t)
	e.PublishRevised(task, golden32Votes(), 2)
	e.drainOne(t)
	got, _ := e.Reader().Get(task)
	if got.Verdict.Stage != m1pv1.VerdictStage_VERDICT_STAGE_REVISED {
		t.Fatalf("stage %v, want REVISED superseding the cache entry", got.Verdict.Stage)
	}
	if got.Knee.N != 2 {
		t.Fatalf("revised publish kept old knee n=%d", got.Knee.N)
	}
}

// TestFastTriggerLatestWins pins 04 §8.2's depth-1 debounce: three triggers
// before the goroutine runs leave exactly the newest.
func TestFastTriggerLatestWins(t *testing.T) {
	e := NewEngine(kneeBundle(), NewBlocks(), nil)
	task := TaskID{5}
	e.Recompute(task, golden32Votes(), 1)
	e.Recompute(task, golden32Votes(), 2)
	e.Recompute(task, golden32Votes(), 3)
	e.drainOne(t)
	got, _ := e.Reader().Get(task)
	if got.Knee.N != 3 {
		t.Fatalf("published n=%d, want 3 (latest-wins)", got.Knee.N)
	}
	select {
	case <-e.fast:
		t.Fatal("debounce queued more than depth 1")
	default:
	}
}

// TestEngineRunRace exercises the real goroutine under -race: concurrent
// triggers + reads, no torn map, entries eventually visible.
func TestEngineRunRace(t *testing.T) {
	e := NewEngine(kneeBundle(), NewBlocks(), nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)
	task := TaskID{6}
	done := make(chan struct{})
	go func() {
		for i := range 200 {
			e.Recompute(task, golden32Votes(), i%4+1)
		}
		// A queued fast PROVISIONAL consumed after the REVISED would overwrite
		// it — correct by contract (the next debounce re-publishes), but this
		// test wants a deterministic terminal state, so drain first.
		for len(e.fast) > 0 {
			time.Sleep(time.Millisecond)
		}
		e.PublishRevised(task, golden32Votes(), 5)
		close(done)
	}()
	r := e.Reader()
	for range 200 {
		r.Get(task)
	}
	<-done
	deadline := time.Now().Add(2 * time.Second)
	for {
		if got, ok := r.Get(task); ok && got.Verdict.Stage == m1pv1.VerdictStage_VERDICT_STAGE_REVISED {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("REVISED publish never became visible")
		}
		time.Sleep(time.Millisecond)
	}
}

// TestBlocksCounters pins the hard-cap tracker: D-Y — an allow does NOT reset
// the streak, a task reset does; the hourly count survives across tasks and
// resets when the window rolls.
func TestBlocksCounters(t *testing.T) {
	b := NewBlocks()
	t0 := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	a, c := TaskID{1}, TaskID{2}
	sess := [16]byte{7}
	b.RecordBlock(sess, a, t0)
	b.RecordBlock(sess, a, t0)
	b.RecordBlock(sess, c, t0)
	if got := b.Counters(sess, a, t0); got.Consecutive != 2 || got.Hourly != 3 {
		t.Fatalf("counters %+v, want consecutive 2 hourly 3", got)
	}
	b.RecordAllow(a)
	if got := b.Counters(sess, a, t0); got.Consecutive != 2 {
		t.Fatalf("D-Y: an allow carries no evidence and must not reset: %+v", got)
	}
	b.ResetTask(a)
	if got := b.Counters(sess, a, t0); got.Consecutive != 0 || got.Hourly != 3 {
		t.Fatalf("task reset clears only the task streak: %+v", got)
	}
	if got := b.Counters(sess, c, t0.Add(time.Hour)); got.Hourly != 0 || got.Consecutive != 1 {
		t.Fatalf("hour roll: %+v, want hourly 0, consecutive kept", got)
	}
}

// TestPublishResetsConsecutiveStreak is D-Y: without a publish-side reset the
// ≤3-consecutive cap degrades to "3 blocks per task per daemon lifetime" —
// the gate short-circuits before the cache read, so an allow can never carry
// the reset and no later evidence could ever re-arm per-task blocking.
func TestPublishResetsConsecutiveStreak(t *testing.T) {
	b := NewBlocks()
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	e := NewEngine(kneeBundle(), b, func() time.Time { return now })
	task := TaskID{11}
	sess := [16]byte{3}
	for range 3 {
		b.RecordBlock(sess, task, now)
	}
	if got := b.Counters(sess, task, now); got.Consecutive != 3 {
		t.Fatalf("setup: consecutive %d, want 3 (at the cap)", got.Consecutive)
	}

	e.Recompute(task, golden32Votes(), 1) // new evidence lands
	e.drainOne(t)
	if got := b.Counters(sess, task, now); got.Consecutive != 0 {
		t.Fatalf("PROVISIONAL publish left consecutive=%d, want 0", got.Consecutive)
	}
	got, _ := e.Reader().Get(task)
	if got.Blocks.Consecutive != 0 {
		t.Fatalf("published entry snapshotted the pre-reset count %d — the gate would keep reading the cap", got.Blocks.Consecutive)
	}
	if got := b.Counters(sess, task, now); got.Hourly != 3 {
		t.Fatalf("the hourly window is cross-task within a session and must survive a publish: %d", got.Hourly)
	}

	b.RecordBlock(sess, task, now)
	e.PublishRevised(task, golden32Votes(), 2)
	e.drainOne(t)
	if got := b.Counters(sess, task, now); got.Consecutive != 0 {
		t.Fatalf("REVISED publish left consecutive=%d, want 0", got.Consecutive)
	}
}

// TestKneeBelowFirstRowNeverStops is D-Y(b): attempts below the table's first
// row do not clamp up to it — Stop is false and row 1's economics never leak
// into the state the gate prints.
func TestKneeBelowFirstRowNeverStops(t *testing.T) {
	m := kneeBundle()
	m.Knee = []KneeRow{{N: 1, CostN: 9.00, PLCB: plcb(0.80)}} // row 1 alone says stop
	for _, n := range []int{0, -3} {
		k := kneeFor(&m, n)
		if k.Stop {
			t.Fatalf("n=%d: Stop=true before attempt 1 exists", n)
		}
		if k.N != n || k.PLCB != 0 || k.CostN != 0 {
			t.Fatalf("n=%d: %+v carries row-1 numbers under the caller's n", n, k)
		}
		if k.Evaluable {
			t.Fatalf("n=%d: %+v claims an evaluation nothing performed (D-AN(c))", n, k)
		}
	}
	if k := kneeFor(&m, 1); !k.Stop {
		t.Fatal("n=1: the row that exists must still be evaluated")
	}
}

// TestKneeAbsentPLCBNeverStops is D-Z: p_lcb is optional on the wire, so a row
// without one is not evaluable at that n. 0.0 is a legitimate bound and must
// stay distinguishable from absence — absent never stops, 0.0 always does.
func TestKneeAbsentPLCBNeverStops(t *testing.T) {
	m := kneeBundle()
	m.Knee = []KneeRow{{N: 1, CostN: 2.00}} // c(n) high enough that any p̂ stops
	k := kneeFor(&m, 1)
	if k.Stop {
		t.Fatalf("unfitted row stopped the loop: %+v", k)
	}
	// D-AN(c): the gate prints the inequality only when there was one.
	if k.Evaluable {
		t.Fatalf("an unfitted row is not evaluable: %+v", k)
	}
	m.Knee = []KneeRow{{N: 1, CostN: 2.00, PLCB: plcb(0.0)}}
	if k := kneeFor(&m, 1); !k.Stop || !k.Evaluable {
		t.Fatalf("p̂_LCB = 0.0 is a measured hopeless attempt and must stop: %+v", k)
	}
}

// TestCachedCountsUnknownVoters is D-X's accounting half: a voter the bundle
// does not list contributes no likelihood, but it is never silently dropped.
func TestCachedCountsUnknownVoters(t *testing.T) {
	e := NewEngine(kneeBundle(), NewBlocks(), nil)
	task := TaskID{12}
	votes := append(golden32Votes(),
		AnchorVote{AnchorID: "mystery-linter", Vote: m1pv1.Verdict_VERDICT_VIOLATED},
		AnchorVote{AnchorID: "another-stranger", Vote: m1pv1.Verdict_VERDICT_SATISFIED},
	)
	e.Recompute(task, votes, 1)
	e.drainOne(t)
	got, _ := e.Reader().Get(task)
	if got.UnknownVoters != 2 {
		t.Fatalf("UnknownVoters=%d, want 2 — unlisted voters must be counted", got.UnknownVoters)
	}
}

// TestAdjudicatedPublishIsEmitted is D-AM(R3): the fused verdict was produced
// and cached but never admitted as an Event, and taskseg's RESOLUTION_VERDICT
// arm is reachable ONLY from an admitted VerdictEvent. Every task therefore
// aged out RESOLUTION_UNRESOLVED_SESSION_END — 100% of the TVO denominator —
// while the gate was serving a fused VIOLATED verdict off the cache.
//
// PROVISIONAL is deliberately not emitted: 04 §9.2 makes it an ACTIVE→ACTIVE
// recompute, one per debounce round, and it closes nothing.
func TestAdjudicatedPublishIsEmitted(t *testing.T) {
	e := NewEngine(kneeBundle(), NewBlocks(), nil)
	task := TaskID{4}
	var emitted []*m1pv1.VerdictEvent
	var forTask []TaskID
	e.Emit = func(_ context.Context, ve *m1pv1.VerdictEvent, id TaskID) {
		emitted = append(emitted, ve)
		forTask = append(forTask, id)
	}

	e.Recompute(task, golden32Votes(), 1)
	e.drainOne(t)
	if len(emitted) != 0 {
		t.Fatalf("a PROVISIONAL recompute emitted %d events; it closes no task (04 §9.2)", len(emitted))
	}

	e.PublishRevised(task, golden32Votes(), 2)
	e.drainOne(t)
	if len(emitted) != 1 {
		t.Fatalf("REVISED publish emitted %d events, want 1 — nothing can ever close RESOLUTION_VERDICT without it", len(emitted))
	}
	if emitted[0].GetStage() != m1pv1.VerdictStage_VERDICT_STAGE_REVISED {
		t.Fatalf("emitted stage %v, want REVISED", emitted[0].GetStage())
	}
	if forTask[0] != task {
		t.Fatalf("emitted for task %x, want %x", forTask[0], task)
	}
	// The cache is the gate's answer and must be published first: an admission
	// that blocks under spool backpressure must not delay it.
	if got, ok := e.Reader().Get(task); !ok || got.Verdict.GetStage() != m1pv1.VerdictStage_VERDICT_STAGE_REVISED {
		t.Fatal("the emit path replaced the publish instead of following it")
	}
}

// decisiveBundle is one verifier whose every column is decisive, so a single
// vote's verdict is its own: satisfied ⇒ SATISFIED, violated ⇒ VIOLATED and
// error ⇒ ERROR (Thm 5.2's infra-dominant path). The knee rows are kneeBundle's.
func decisiveBundle() BundleMatrices {
	m := kneeBundle()
	m.Verifiers = map[string]VerifierParams{"build": {Confusion: Confusion{
		{0.98, 0.01, 0.01},
		{0.02, 0.97, 0.01},
		{0.10, 0.10, 0.80},
		{0.34, 0.33, 0.33},
	}}}
	return m
}

func buildVote(v m1pv1.Verdict) []AnchorVote { return []AnchorVote{{AnchorID: "build", Vote: v}} }

// TestRevisedThatChangesTheVerdictQueuesACorrection pins 04 §2.3's fast/slow
// split at the wire's source: a REVISED publish whose argmax differs from the
// entry it supersedes queues one Correction for the task's session; a REVISED
// that agrees, a REVISED with nothing to supersede, and a second revision back
// to the verdict the agent saw all queue nothing. One pull drains the queue.
func TestRevisedThatChangesTheVerdictQueuesACorrection(t *testing.T) {
	const (
		satisfied = m1pv1.Verdict_VERDICT_SATISFIED
		violated  = m1pv1.Verdict_VERDICT_VIOLATED
		errored   = m1pv1.Verdict_VERDICT_ERROR
	)
	sid := [16]byte{0xAA, 7}
	e := NewEngine(decisiveBundle(), NewBlocks(), nil)
	e.SessionFor = func(TaskID) ([16]byte, bool) { return sid, true }
	task := TaskID{21}
	publish := func(revised bool, v m1pv1.Verdict) {
		t.Helper()
		if revised {
			e.PublishRevised(task, buildVote(v), 1)
		} else {
			e.Recompute(task, buildVote(v), 1)
		}
		e.drainOne(t)
		if got, _ := e.Reader().Get(task); got.Verdict.GetVerdict() != v {
			t.Fatalf("build:%v fused to %v — the decisive bundle is no longer decisive", v, got.Verdict.GetVerdict())
		}
	}

	publish(false, violated)
	publish(true, satisfied)
	got := e.TakeCorrections(sid)
	if len(got) != 1 || got[0] != (Correction{Task: task, Previous: violated, Revised: satisfied}) {
		t.Fatalf("corrections %+v, want exactly one violated→satisfied", got)
	}
	if again := e.TakeCorrections(sid); len(again) != 0 {
		t.Fatalf("a second pull re-delivered %+v", again)
	}

	// Same argmax: superseded, not corrected.
	publish(true, satisfied)
	if got := e.TakeCorrections(sid); len(got) != 0 {
		t.Fatalf("an agreeing REVISED queued %+v", got)
	}
	// Revised, then revised back before the pull: the agent saw nothing wrong.
	publish(true, violated)
	publish(true, satisfied)
	if got := e.TakeCorrections(sid); len(got) != 0 {
		t.Fatalf("a revision undone before the pull still queued %+v", got)
	}
	// Two revisions away from what the agent saw collapse to one correction
	// naming the verdict it saw, not the intermediate one.
	publish(true, violated)
	publish(true, errored)
	got = e.TakeCorrections(sid)
	if len(got) != 1 || got[0] != (Correction{Task: task, Previous: satisfied, Revised: errored}) {
		t.Fatalf("two revisions queued %+v, want one satisfied→error", got)
	}

	// A REVISED with no entry to supersede corrects nothing: no gate ever
	// answered on a verdict for this task.
	e.PublishRevised(TaskID{22}, buildVote(violated), 1)
	e.drainOne(t)
	if got := e.TakeCorrections(sid); len(got) != 0 {
		t.Fatalf("first-ever REVISED queued %+v", got)
	}
	// A fast PROVISIONAL that disagrees is a recompute, never a correction.
	publish(false, violated)
	if got := e.TakeCorrections(sid); len(got) != 0 {
		t.Fatalf("a PROVISIONAL publish queued %+v", got)
	}

	// Unscoped: no session, no queue.
	for _, sf := range []func(TaskID) ([16]byte, bool){nil, func(TaskID) ([16]byte, bool) { return [16]byte{}, false }} {
		e.SessionFor = sf
		publish(false, violated)
		publish(true, satisfied)
		if got := e.TakeCorrections(sid); len(got) != 0 {
			t.Fatalf("session-less engine queued %+v", got)
		}
		// D-AT: no connection can ever Hello as the all-zero session, so a
		// correction parked under it is a leak nothing drains.
		if got := e.TakeCorrections([16]byte{}); len(got) != 0 {
			t.Fatalf("session-less engine queued %+v under the zero sentinel", got)
		}
	}
}
