package control

import (
	"strings"
	"testing"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

// TestProposalReachesTheControlAPI is FR-SPINE-048's control-API path: an
// admitted MemoryProposal fans out on the SSE stream as family `proposal`
// and lands in the verify ring as a `proposal` row — never as an injection.
func TestProposalReachesTheControlAPI(t *testing.T) {
	h := NewHub()
	ch, cancel := h.subscribe()
	defer cancel()
	ev := &m1pv1.Event{
		EventId: make([]byte, 16), SessionId: make([]byte, 16), TaskId: make([]byte, 16),
		Body: &m1pv1.Event_MemoryProposal{MemoryProposal: &m1pv1.MemoryProposal{Category: m1pv1.ProposalCategory_PROPOSAL_CATEGORY_CONVENTION, CandidateGuidance: "config lives in yaml", Evidence: "pack"}},
	}
	h.Publish(ev)
	f := <-ch
	if f.family != "proposal" {
		t.Fatalf("SSE family %q, want proposal", f.family)
	}
	if !strings.Contains(string(f.data), "config lives in yaml") {
		t.Fatalf("SSE frame lacks the proposal: %s", f.data)
	}
	rows := h.verifyEvents()
	if len(rows) != 1 || rows[0]["type"] != "proposal" || rows[0]["category"] != "PROPOSAL_CATEGORY_CONVENTION" || rows[0]["evidence"] != "pack" {
		t.Fatalf("verify ring = %v, want one proposal row", rows)
	}
}
