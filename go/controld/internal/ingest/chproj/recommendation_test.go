package chproj

import (
	"strings"
	"testing"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"github.com/google/uuid"
)

// TestArrestRecommendationProjects is FR-SPINE-045: an
// ArrestRecommendation event (ADR-0015) reaches the m1p_events row shape
// through the reflection-driven projector with event_type
// "ArrestRecommendation", the diagnostic class, and a payload in proto field
// names that migrations/m1_ch_003_arrest_recommendations.sql's materialized
// view extracts (kind, k_star_estimate, projected_cost, turn, evidence_ref).
// It is not an unknown type, so it is never counted as projector drift.
func TestArrestRecommendationProjects(t *testing.T) {
	ev := &m1pv1.Event{
		SessionId: make([]byte, 16), TaskId: make([]byte, 16),
		Body: &m1pv1.Event_ArrestRecommendation{ArrestRecommendation: &m1pv1.ArrestRecommendation{
			Kind: "knee_arrest", Reason: "p̂_LCB too low", KStarEstimate: 3, ProjectedCost: 4200, Turn: 7, EvidenceRef: "evidence/x",
		}},
	}
	id := uuid.New()
	ev.EventId = id[:]
	if IsUnknownType(ev) {
		t.Fatal("ArrestRecommendation reads as an unknown type to this build")
	}
	if got := BodyTypeName(ev); got != "ArrestRecommendation" {
		t.Fatalf("event_type %q, want ArrestRecommendation", got)
	}
	if got := eventClass("ArrestRecommendation"); got != "diagnostic" {
		t.Fatalf("event_class %q, want diagnostic", got)
	}
	payload := payloadJSON(ev)
	for _, key := range []string{`"kind":"knee_arrest"`, `"k_star_estimate":3`, `"projected_cost":"4200"`, `"turn":7`, `"evidence_ref":"evidence/x"`} {
		if !strings.Contains(payload, key) {
			t.Fatalf("payload lacks %s (the m1_ch_003 view extracts it):\n%s", key, payload)
		}
	}
	rows := RowsFromBatch(&m1pv1.Batch{SessionId: make([]byte, 16), Events: []*m1pv1.Event{ev}}, uuid.New(), uuid.New(), time.Now())
	if len(rows) != 1 {
		t.Fatalf("%d row(s), want 1", len(rows))
	}
}
