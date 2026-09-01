package chproj

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

func col(t *testing.T, name string) int {
	t.Helper()
	for i, c := range Columns {
		if c == name {
			return i
		}
	}
	t.Fatalf("no column %s", name)
	return -1
}

func v7(t *testing.T) uuid.UUID {
	t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func v7b(t *testing.T) []byte {
	t.Helper()
	id := v7(t)
	return id[:]
}

func TestUsageRowMapping(t *testing.T) {
	tenant, device := uuid.New(), uuid.New()
	eventID, session, batchID := v7(t), v7(t), v7(t)
	at := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	idem := make([]byte, 32)
	idem[0] = 0x7F
	b := &m1pv1.Batch{
		BatchId:   batchID[:],
		SessionId: session[:],
		Sdk:       &m1pv1.SdkInfo{Agent: "claudecode"},
		Events: []*m1pv1.Event{{
			EventId: eventID[:], Seq: 41, SessionEpoch: 2, SessionId: session[:],
			OccurredAt: timestamppb.New(at),
			Body: &m1pv1.Event_Usage{Usage: &m1pv1.Usage{
				IdemKey: idem, Model: "claude-test-1",
				InputTokens: 2113, OutputTokens: 388, CacheReadInputTokens: 19244,
			}},
		}},
	}
	rows := RowsFromBatch(b, tenant, device, at)
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(rows))
	}
	r := rows[0]
	checks := map[string]any{
		"tenant_id": tenant, "device_id": device, "event_id": eventID,
		"session_id": session, "seq": uint64(41), "session_epoch": uint32(2),
		"event_type": "Usage", "event_class": "billing", "agent": "claudecode",
		"model": "claude-test-1", "input_tokens": uint64(2113),
		"output_tokens": uint64(388), "cache_read_input_tokens": uint64(19244),
		"idem_key": string(idem),
	}
	for name, want := range checks {
		if got := r[col(t, name)]; got != want {
			t.Errorf("%s: want %v, got %v", name, want, got)
		}
	}
}

// EdgeHealth is the one body capture.Admit lets through without a session_id
// (11 §2.3: health is per-device). Batch.session_id is only the head record's,
// so back-filling from it would file device health under whichever session it
// was batched behind — silently, and with a plausible-looking uuid.
func TestDeviceScopedHealthKeepsNoSession(t *testing.T) {
	tenant, device := uuid.New(), uuid.New()
	session, batchID := v7(t), v7(t)
	at := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	b := &m1pv1.Batch{
		BatchId: batchID[:], SessionId: session[:],
		Sdk: &m1pv1.SdkInfo{Agent: "claudecode"},
		Events: []*m1pv1.Event{
			{EventId: v7b(t), Seq: 1, SessionId: session[:], OccurredAt: timestamppb.New(at),
				Body: &m1pv1.Event_SessionStart{SessionStart: &m1pv1.SessionStart{}}},
			{EventId: v7b(t), Seq: 1, OccurredAt: timestamppb.New(at),
				Body: &m1pv1.Event_EdgeHealth{EdgeHealth: &m1pv1.EdgeHealth{EdgeVersion: "test"}}},
		},
	}
	rows := RowsFromBatch(b, tenant, device, at)
	if len(rows) != 2 {
		t.Fatalf("want 2 rows, got %d", len(rows))
	}
	if got := rows[0][col(t, "session_id")]; got != session {
		t.Errorf("a session-bearing event lost its session: %v", got)
	}
	if got := rows[1][col(t, "session_id")]; got != uuid.Nil {
		t.Errorf("device health was attributed to session %v — the batch head's, not its own", got)
	}
	if got := rows[1][col(t, "device_id")]; got != device {
		t.Errorf("device health lost its device: %v", got)
	}
}

func TestVerdictRowMapping(t *testing.T) {
	eventID := v7(t)
	certID := uuid.New()
	b := &m1pv1.Batch{
		BatchId: v7b(t), SentAt: timestamppb.Now(),
		Events: []*m1pv1.Event{{
			EventId: eventID[:], Seq: 1,
			Body: &m1pv1.Event_VerdictEvent{VerdictEvent: &m1pv1.VerdictEvent{
				Stage:       m1pv1.VerdictStage_VERDICT_STAGE_PROVISIONAL,
				Verdict:     m1pv1.Verdict_VERDICT_SATISFIED,
				Posterior:   []float64{0.86, 0.09, 0.03, 0.02},
				NoiseCertId: certID.String(),
			}},
		}},
	}
	r := RowsFromBatch(b, uuid.New(), uuid.New(), time.Now())[0]
	if r[col(t, "verdict")] != "satisfied" || r[col(t, "verdict_stage")] != "provisional" {
		t.Fatalf("verdict enums: %v / %v", r[col(t, "verdict")], r[col(t, "verdict_stage")])
	}
	// posterior[4] order is frozen: [satisfied, violated, refused, error]
	if r[col(t, "p_satisfied")] != float32(0.86) || r[col(t, "p_error")] != float32(0.02) {
		t.Fatalf("posterior columns: %v", r)
	}
	if r[col(t, "noise_cert_id")] != certID {
		t.Fatalf("noise_cert_id: %v", r[col(t, "noise_cert_id")])
	}
	if r[col(t, "event_class")] != "verdict" {
		t.Fatalf("event_class: %v", r[col(t, "event_class")])
	}
}

// Dropped{} rows derive DETERMINISTIC event_ids from (batch_id, index):
// replay collapses in the ReplacingMergeTree instead of double-counting the
// loss ledger.
func TestDroppedRowsAreReplayDeterministic(t *testing.T) {
	batchID := v7(t)
	b := &m1pv1.Batch{
		BatchId: batchID[:], SentAt: timestamppb.New(time.Date(2026, 8, 29, 9, 0, 0, 0, time.UTC)),
		Dropped: []*m1pv1.Dropped{{
			Reason:          m1pv1.DropReason_DROP_REASON_SPOOL_SHED,
			Quantity:        17,
			DurabilityClass: m1pv1.DurabilityClass_DURABILITY_CLASS_DIAGNOSTIC,
		}},
	}
	tenant, device := uuid.New(), uuid.New()
	r1 := RowsFromBatch(b, tenant, device, time.Now())[0]
	r2 := RowsFromBatch(b, tenant, device, time.Now().Add(time.Hour))[0] // "replayed later"
	if r1[col(t, "event_id")] != r2[col(t, "event_id")] {
		t.Fatal("dropped-row event_id is not replay-deterministic")
	}
	if r1[col(t, "occurred_at")] != r2[col(t, "occurred_at")] {
		t.Fatal("dropped-row occurred_at must come from sent_at, not receipt time")
	}
	if r1[col(t, "event_type")] != "Dropped" ||
		r1[col(t, "dropped_reason")] != "spool_shed" ||
		r1[col(t, "dropped_durability_class")] != "diagnostic" ||
		r1[col(t, "dropped_quantity")] != uint64(17) {
		t.Fatalf("dropped mapping: %v", r1)
	}
}

func TestSecurityEventRowDeterministic(t *testing.T) {
	tenant, device, batch := uuid.New(), uuid.New(), uuid.New()
	r1 := SecurityEventRow(tenant, device, batch, "x", time.Now())
	r2 := SecurityEventRow(tenant, device, batch, "x", time.Now().Add(time.Minute))
	if r1[col(t, "event_id")] != r2[col(t, "event_id")] {
		t.Fatal("security event_id must derive from batch_id (replayed attack ⇒ one row)")
	}
	if r1[col(t, "event_type")] != "GuardDecision" {
		t.Fatalf("event_type: %v", r1[col(t, "event_type")])
	}
}

func TestRowWidthMatchesColumns(t *testing.T) {
	b := &m1pv1.Batch{
		BatchId: v7b(t), SentAt: timestamppb.Now(),
		Events:  []*m1pv1.Event{{EventId: v7b(t), Seq: 1, Body: &m1pv1.Event_TaskOpen{TaskOpen: &m1pv1.TaskOpen{}}}},
		Dropped: []*m1pv1.Dropped{{Quantity: 1}},
	}
	for i, r := range RowsFromBatch(b, uuid.New(), uuid.New(), time.Now()) {
		if len(r) != len(Columns) {
			t.Fatalf("row %d: %d values for %d columns", i, len(r), len(Columns))
		}
	}
	if len(SecurityEventRow(uuid.New(), uuid.New(), uuid.New(), "", time.Now())) != len(Columns) {
		t.Fatal("security row width")
	}
}
