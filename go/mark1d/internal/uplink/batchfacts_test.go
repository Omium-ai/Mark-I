package uplink

import (
	"testing"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"google.golang.org/protobuf/proto"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/spool"
)

func factRecord(t *testing.T, ev *m1pv1.Event) spool.Record {
	t.Helper()
	b, err := proto.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	return spool.Record{Payload: b}
}

// TestBatchFactsCountsActedAndRecommendedApart is FR-SPINE-052: over the
// same records batchLeaves seals, batchFacts notes each leaf's session and
// task, counts a task-bearing GuardDecision as acted and an
// ArrestRecommendation as recommended — never the one as the other — and
// skips a ReceiptCheckpoint exactly as the leaf rule does.
func TestBatchFactsCountsActedAndRecommendedApart(t *testing.T) {
	s1, s2 := make([]byte, 16), make([]byte, 16)
	s1[0], s2[0] = 1, 2
	t1, t2 := make([]byte, 16), make([]byte, 16)
	t1[0], t2[0] = 7, 8
	recs := []spool.Record{
		factRecord(t, &m1pv1.Event{SessionId: s1, TaskId: t1, Body: &m1pv1.Event_GuardDecision{GuardDecision: &m1pv1.GuardDecision{Outcome: m1pv1.GuardOutcome_GUARD_OUTCOME_ARRESTED}}}),
		factRecord(t, &m1pv1.Event{SessionId: s1, Body: &m1pv1.Event_GuardDecision{GuardDecision: &m1pv1.GuardDecision{Outcome: m1pv1.GuardOutcome_GUARD_OUTCOME_REFUSED}}}), // no task: not an arrest
		factRecord(t, &m1pv1.Event{SessionId: s2, TaskId: t2, Body: &m1pv1.Event_ArrestRecommendation{ArrestRecommendation: &m1pv1.ArrestRecommendation{Kind: "knee_arrest"}}}),
		factRecord(t, &m1pv1.Event{SessionId: s2, TaskId: t2, Body: &m1pv1.Event_ArrestRecommendation{ArrestRecommendation: &m1pv1.ArrestRecommendation{Kind: "stop_gate_block"}}}),
		factRecord(t, &m1pv1.Event{SessionId: s2, TaskId: t1, Body: &m1pv1.Event_Usage{Usage: &m1pv1.Usage{}}}),
		factRecord(t, &m1pv1.Event{SessionId: s1, Body: &m1pv1.Event_ReceiptCheckpoint{ReceiptCheckpoint: &m1pv1.ReceiptCheckpoint{CheckpointSeq: 1}}}),
	}
	f := batchFacts(recs)
	if f.ArrestsActed != 1 || f.ArrestsRecommended != 2 {
		t.Fatalf("acted=%d recommended=%d, want 1 and 2", f.ArrestsActed, f.ArrestsRecommended)
	}
	var k1, k2, kt1, kt2 [16]byte
	copy(k1[:], s1)
	copy(k2[:], s2)
	copy(kt1[:], t1)
	copy(kt2[:], t2)
	if len(f.Tasks) != 2 || len(f.Tasks[k1]) != 1 || len(f.Tasks[k2]) != 2 {
		t.Fatalf("sessions/tasks = %v", f.Tasks)
	}
	if _, ok := f.Tasks[k1][kt1]; !ok {
		t.Fatal("session 1 lost its task")
	}
	if _, ok := f.Tasks[k2][kt1]; !ok {
		t.Fatal("session 2 lost the task its usage leaf named")
	}
	if _, ok := f.Tasks[k2][kt2]; !ok {
		t.Fatal("session 2 lost the recommended task")
	}
	if len(batchLeaves(recs)) != 5 {
		t.Fatalf("leaf rule drifted: %d leaves, want 5", len(batchLeaves(recs)))
	}
}
