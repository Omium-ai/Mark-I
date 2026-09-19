package anchors

import (
	"context"
	"testing"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/verdict"
)

// voteMatrices: one fast anchor and one slow one, both sharp rejecters, so a
// single VIOLATED vote lands VIOLATED and the publish is unambiguous.
func voteMatrices() verdict.BundleMatrices {
	sharp := verdict.Confusion{{0.9, 0.05, 0.05}, {0.05, 0.9, 0.05}, {0.3, 0.3, 0.4}, {0.2, 0.2, 0.6}}
	return verdict.BundleMatrices{
		Priors: verdict.DefaultPriors,
		Verifiers: map[string]verdict.VerifierParams{
			"ruff@cat-1":  {Confusion: sharp},
			"tests@cat-9": {Confusion: sharp},
		},
	}
}

func runEngine(t *testing.T, m verdict.BundleMatrices) *verdict.Engine {
	t.Helper()
	eng := verdict.NewEngine(m, verdict.NewBlocks(), nil)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go eng.Run(ctx)
	return eng
}

func waitCached(t *testing.T, r verdict.Reader, task verdict.TaskID, what string, ok func(verdict.Cached) bool) verdict.Cached {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if e, found := r.Get(task); found && ok(e) {
			return e
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
	return verdict.Cached{}
}

// votesFor stands the segmenter in: honour whatever task the event names,
// refuse the sentinel — D-AA parts 1 and 3 with no state machine attached.
func votesFor(em Emitter, eng *verdict.Engine, entries []CatalogEntry) *Votes {
	v := NewVotes(em, eng, entries)
	v.TaskFor = func(_, want [16]byte) ([16]byte, bool) { return want, want != [16]byte{} }
	return v
}

func anchorVoteEvent(task verdict.TaskID, id string, v m1pv1.Verdict, tamper bool) *m1pv1.Event {
	return &m1pv1.Event{
		SessionId: make([]byte, 16),
		TaskId:    task[:],
		Body: &m1pv1.Event_AnchorVote{AnchorVote: &m1pv1.AnchorVote{
			AnchorId:  id,
			Vote:      v,
			Integrity: &m1pv1.AnchorIntegrity{Tamper: tamper},
		}},
	}
}

// TestVotesFeedFusionAndCapture is the recompute loop: the vote the Runner
// emits reaches capture admission unchanged AND lands a fused PROVISIONAL
// verdict in the gate-readable cache.
func TestVotesFeedFusionAndCapture(t *testing.T) {
	em := &fakeEmitter{}
	eng := runEngine(t, voteMatrices())
	v := votesFor(em, eng, []CatalogEntry{{ID: "ruff@cat-1", Class: ClassFast}})

	task := verdict.TaskID{1, 2, 3}
	if err := v.Admit(context.Background(), anchorVoteEvent(task, "ruff@cat-1", m1pv1.Verdict_VERDICT_VIOLATED, false)); err != nil {
		t.Fatal(err)
	}
	if got := em.all(); len(got) != 1 || got[0].GetAnchorVote().GetAnchorId() != "ruff@cat-1" {
		t.Fatalf("capture saw %v, want the vote passed through unchanged", got)
	}
	e := waitCached(t, eng.Reader(), task, "the fused verdict", func(verdict.Cached) bool { return true })
	if e.Verdict.GetVerdict() != m1pv1.Verdict_VERDICT_VIOLATED {
		t.Fatalf("verdict = %v, want VIOLATED from the sharp rejecter", e.Verdict.GetVerdict())
	}
	if e.Verdict.GetStage() != m1pv1.VerdictStage_VERDICT_STAGE_PROVISIONAL {
		t.Fatalf("stage = %v, want PROVISIONAL from a fast anchor", e.Verdict.GetStage())
	}
	if e.Knee.N != 1 {
		t.Fatalf("attempt = %d, want the first attempt", e.Knee.N)
	}
}

// TestVotesSlowAnchorPublishesRevised: a slow anchor's completion supersedes
// the PROVISIONAL entry with a REVISED one carrying both votes (04 §2.3's
// fast/slow split).
func TestVotesSlowAnchorPublishesRevised(t *testing.T) {
	eng := runEngine(t, voteMatrices())
	v := votesFor(&fakeEmitter{}, eng, []CatalogEntry{
		{ID: "ruff@cat-1", Class: ClassFast},
		{ID: "tests@cat-9", Class: ClassSlow},
	})

	task := verdict.TaskID{9}
	ctx := context.Background()
	if err := v.Admit(ctx, anchorVoteEvent(task, "ruff@cat-1", m1pv1.Verdict_VERDICT_SATISFIED, false)); err != nil {
		t.Fatal(err)
	}
	waitCached(t, eng.Reader(), task, "the provisional verdict", func(e verdict.Cached) bool {
		return e.Verdict.GetStage() == m1pv1.VerdictStage_VERDICT_STAGE_PROVISIONAL
	})
	if err := v.Admit(ctx, anchorVoteEvent(task, "tests@cat-9", m1pv1.Verdict_VERDICT_VIOLATED, false)); err != nil {
		t.Fatal(err)
	}
	e := waitCached(t, eng.Reader(), task, "the revised verdict", func(e verdict.Cached) bool {
		return e.Verdict.GetStage() == m1pv1.VerdictStage_VERDICT_STAGE_REVISED
	})
	if e.Verdict.GetVoteCount() != 2 {
		t.Fatalf("vote_count = %d, want both votes fused", e.Verdict.GetVoteCount())
	}
	if e.Knee.N != 1 {
		t.Fatalf("attempt = %d: a slow completion is late evidence for the SAME attempt", e.Knee.N)
	}
}

// TestVotesSecondRunOfAnAnchorIsANewAttempt pins the attempt-counting rule the
// knee is evaluated at: an anchor runs once per debounce round, so its second
// vote is the next round.
// TestVotesSecondRunOfAnAnchorIsANewAttempt: an attempt is a new state of the tree — a re-vote with the same evidence (a debounce re-run over an unchanged tree) stays on the same attempt; a re-vote whose evidence changed opens the next one.
func TestVotesSecondRunOfAnAnchorIsANewAttempt(t *testing.T) {
	eng := runEngine(t, voteMatrices())
	v := votesFor(&fakeEmitter{}, eng, []CatalogEntry{{ID: "ruff@cat-1", Class: ClassFast}})
	task := verdict.TaskID{4}
	ctx := context.Background()
	withErrors := func(n uint32) *m1pv1.Event {
		ev := anchorVoteEvent(task, "ruff@cat-1", m1pv1.Verdict_VERDICT_VIOLATED, false)
		ev.GetAnchorVote().Evidence = &m1pv1.EvidenceRecord{Tool: "ruff", DiagnosticCode: "F821", Counts: &m1pv1.EvidenceCounts{Errors: n, FilesAffected: 1}}
		return ev
	}
	for i := range 3 {
		if err := v.Admit(ctx, withErrors(uint32(3-i))); err != nil {
			t.Fatal(err)
		}
		want := i + 1
		waitCached(t, eng.Reader(), task, "attempt bump", func(e verdict.Cached) bool { return e.Knee.N == want })
	}
	for range 4 {
		if err := v.Admit(ctx, withErrors(1)); err != nil { // the same evidence again: still attempt 3
			t.Fatal(err)
		}
	}
	time.Sleep(200 * time.Millisecond)
	if e := waitCached(t, eng.Reader(), task, "cached", func(verdict.Cached) bool { return true }); e.Knee.N != 3 {
		t.Fatalf("re-observing an unchanged tree bumped the attempt to %d", e.Knee.N)
	}
}

// TestVotesTamperedVoteCarriesTheFlag: the integrity envelope, not the vote
// value, decides admissibility — a tampered vote must reach fusion FLAGGED so
// it never enters the likelihood (Thm 5.2: infra failure is not a violation).
func TestVotesTamperedVoteCarriesTheFlag(t *testing.T) {
	eng := runEngine(t, voteMatrices())
	v := votesFor(&fakeEmitter{}, eng, []CatalogEntry{{ID: "ruff@cat-1", Class: ClassFast}})
	task := verdict.TaskID{5}
	if err := v.Admit(context.Background(), anchorVoteEvent(task, "ruff@cat-1", m1pv1.Verdict_VERDICT_VIOLATED, true)); err != nil {
		t.Fatal(err)
	}
	e := waitCached(t, eng.Reader(), task, "the fused verdict", func(verdict.Cached) bool { return true })
	if e.Verdict.GetVerdict() == m1pv1.Verdict_VERDICT_VIOLATED {
		t.Fatal("a tampered vote reached the likelihood — it must never state a violation")
	}
	if e.Verdict.GetVoteCount() != 0 {
		t.Fatalf("vote_count = %d, want the tampered vote excluded", e.Verdict.GetVoteCount())
	}
}

// TestVotesIgnoreNonAnchorBodies: every other event still passes through, and
// no phantom cache entry appears for it.
func TestVotesIgnoreNonAnchorBodies(t *testing.T) {
	em := &fakeEmitter{}
	eng := runEngine(t, voteMatrices())
	v := votesFor(em, eng, nil)
	ev := &m1pv1.Event{SessionId: make([]byte, 16), TaskId: make([]byte, 16), Body: &m1pv1.Event_ToolUse{ToolUse: &m1pv1.ToolUse{ToolName: "Bash"}}}
	if err := v.Admit(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if len(em.all()) != 1 {
		t.Fatal("a non-anchor event must still reach capture")
	}
	time.Sleep(50 * time.Millisecond)
	if _, ok := eng.Reader().Get(verdict.TaskID{}); ok {
		t.Fatal("a ToolUse published a verdict — only anchor votes are evidence")
	}
}

// TestVotesNeverFuseUnderTheSentinel is D-AA part 1 on the vote side: a vote
// whose task cannot be resolved is admitted to capture and contributes NOTHING
// to fusion. Before D-AA it landed under the all-zero TaskID, where it answered
// every other session's gate.
func TestVotesNeverFuseUnderTheSentinel(t *testing.T) {
	em := &fakeEmitter{}
	eng := runEngine(t, voteMatrices())
	v := votesFor(em, eng, []CatalogEntry{{ID: "ruff@cat-1", Class: ClassFast}})
	ev := anchorVoteEvent(verdict.TaskID{}, "ruff@cat-1", m1pv1.Verdict_VERDICT_VIOLATED, false)
	if err := v.Admit(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if len(em.all()) != 1 {
		t.Fatal("an unresolved vote must still reach capture — the ledger and the verdict plane are separate")
	}
	time.Sleep(50 * time.Millisecond)
	if e, ok := eng.Reader().Get(verdict.TaskID{}); ok {
		t.Fatalf("the sentinel holds a %v verdict — it is an address again", e.Verdict.GetVerdict())
	}
}
