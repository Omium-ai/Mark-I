package ingest

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/chproj"
	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

const contribDiff = "diff --git a/x.go b/x.go\n+func secretSauce() {}\n"

func contributionEvent(t *testing.T, session uuid.UUID, seq uint64) *m1pv1.Event {
	t.Helper()
	eid, task := mustV7(t), mustV7(t)
	return &m1pv1.Event{
		EventId: eid[:], Seq: seq, SessionId: session[:], TaskId: task[:],
		OccurredAt: timestamppb.New(time.Date(2026, 9, 26, 10, 0, 0, 0, time.UTC)),
		Body: &m1pv1.Event_OutcomeContribution{OutcomeContribution: &m1pv1.OutcomeContribution{
			TaskId: task[:], IntentTextRedacted: "add the sauce", DiffRedacted: contribDiff,
			RedactionReceiptRef: bytes.Repeat([]byte{7}, 32), Generator: "claudecode/claude-test-1",
			Labels: &m1pv1.OutcomeLabels{Survival_30D: 0.5, Reverted: m1pv1.OutcomeLabel_OUTCOME_LABEL_NO},
		}},
	}
}

func TestContributionWithoutConsentIs422AndNeverLands(t *testing.T) {
	h := newHarness(t)
	session := mustV7(t)
	b, id := testBatch(t, contributionEvent(t, session, 1))
	rec := h.post(t, id, encodeBatch(t, b), nil)
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "contribution_consent") {
		t.Fatalf("no m1_082 row saying contribute_outcomes: want 422 contribution_consent, got %d %s", rec.Code, rec.Body.String())
	}
	if len(h.store.keys()) != 0 {
		t.Fatal("an unconsented contribution landed")
	}
}

func TestContributionBatchedWithOtherEventsIs422(t *testing.T) {
	h := newHarness(t)
	session := mustV7(t)
	b, id := testBatch(t, usageEvent(t, session, 1), contributionEvent(t, session, 2))
	rec := h.post(t, id, encodeBatch(t, b), nil)
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "contribution_not_alone") {
		t.Fatalf("a contribution must travel alone (its object is deletable, the replay log is not): %d %s", rec.Code, rec.Body.String())
	}
}

func TestContributionShapeRefused(t *testing.T) {
	h := newHarness(t)
	ev := contributionEvent(t, mustV7(t), 1)
	ev.GetOutcomeContribution().RedactionReceiptRef = nil
	b, id := testBatch(t, ev)
	if rec := h.post(t, id, encodeBatch(t, b), nil); rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "contribution_shape") {
		t.Fatalf("no redaction receipt: %d %s", rec.Code, rec.Body.String())
	}
}

func TestContributionProjectsAnIndexRowOnly(t *testing.T) {
	ev := contributionEvent(t, mustV7(t), 1)
	b, _ := testBatch(t, ev)
	rows := chproj.RowsFromBatch(b, uuid.New(), uuid.New(), time.Now())
	if len(rows) != 1 {
		t.Fatalf("rows = %d", len(rows))
	}
	payload, _ := rows[0][33].(string)
	if strings.Contains(payload, "secretSauce") || strings.Contains(payload, "add the sauce") {
		t.Fatalf("task text or diff reached m1p_events: %s", payload)
	}
	if !strings.Contains(payload, "claudecode/claude-test-1") || !strings.Contains(payload, "OUTCOME_LABEL_NO") {
		t.Fatalf("index row lost its labels or generator: %s", payload)
	}
}
