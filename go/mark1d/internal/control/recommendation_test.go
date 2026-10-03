package control

import (
	"strings"
	"testing"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

// TestRecommendationReachesTheControlAPI is FR-SPINE-044's control-API path:
// an admitted ArrestRecommendation fans out on the SSE stream as its own
// family and lands in the verify ring as a `recommendation` row — never as
// an `arrest` row, which is FR-SPINE-046's edge-side count separation.
func TestRecommendationReachesTheControlAPI(t *testing.T) {
	h := NewHub()
	ch, cancel := h.subscribe()
	defer cancel()
	ev := &m1pv1.Event{
		EventId: make([]byte, 16), SessionId: []byte{0xaa, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, TaskId: []byte{0xbb, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		Body: &m1pv1.Event_ArrestRecommendation{ArrestRecommendation: &m1pv1.ArrestRecommendation{Kind: "knee_arrest", Reason: "below the knee", KStarEstimate: 2, ProjectedCost: 777}},
	}
	h.Publish(ev)
	f := <-ch
	if f.family != "recommendation" {
		t.Fatalf("SSE family %q, want recommendation", f.family)
	}
	if !strings.Contains(string(f.data), "knee_arrest") || !strings.Contains(string(f.data), "777") {
		t.Fatalf("SSE frame lacks the recommendation: %s", f.data)
	}
	rows := h.verifyEvents()
	if len(rows) != 1 || rows[0]["type"] != "recommendation" || rows[0]["kind"] != "knee_arrest" {
		t.Fatalf("verify ring = %v, want one recommendation row", rows)
	}
	for _, r := range rows {
		if r["type"] == "arrest" {
			t.Fatal("a recommendation was filed as an arrest")
		}
	}
}
