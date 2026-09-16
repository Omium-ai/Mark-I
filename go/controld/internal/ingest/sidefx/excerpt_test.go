package sidefx

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

func excerptEvent(t *testing.T, tier m1pv1.EvidenceTier, subject uuid.UUID, receipt []byte) *m1pv1.Event {
	t.Helper()
	id := uuidV7(t)
	return &m1pv1.Event{EventId: id[:], Body: &m1pv1.Event_EvidenceExcerpt{EvidenceExcerpt: &m1pv1.EvidenceExcerpt{
		Tier: tier, EvidenceEventId: subject[:], AttachmentName: "attach.x.e1", RedactionReceiptId: receipt}}}
}

func excerptRefusalsTotal(t *testing.T, code string) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range families {
		if mf.GetName() != "controld_ingest_excerpt_refusals_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "code" && l.GetValue() == code {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}

func TestEffectsFromBatchProjectsOnlyE1Excerpts(t *testing.T) {
	subject := uuidV7(t)
	receipt := bytes.Repeat([]byte{7}, 32)
	b := &m1pv1.Batch{Events: []*m1pv1.Event{
		excerptEvent(t, m1pv1.EvidenceTier_EVIDENCE_TIER_E1, subject, receipt),
		excerptEvent(t, m1pv1.EvidenceTier_EVIDENCE_TIER_E2, subject, nil),
		excerptEvent(t, m1pv1.EvidenceTier_EVIDENCE_TIER_E0, subject, receipt),
	}}
	effects := EffectsFromBatch(b, time.Now())
	if len(effects) != 3 {
		t.Fatalf("effects = %d, want 3", len(effects))
	}
	x := effects[0].Excerpt
	if x == nil || !bytes.Equal(x.ReceiptID, receipt) || x.SubjectID != subject {
		t.Fatalf("E1 mapping wrong: %+v", x)
	}
	if effects[1].Excerpt != nil || effects[2].Excerpt != nil {
		t.Fatal("E2/E0 excerpts must not claim a redaction receipt")
	}
}

// With no receipt row reachable, EVERY E1 excerpt is refused and paged: the door fails closed.
func TestExcerptWithoutAReceiptRowIsRefusedAsASecurityEvent(t *testing.T) {
	var pages []string
	s := New(nullDB{}, &fakeChain{}, func(_, _, _ uuid.UUID, detail string, _ time.Time) {
		pages = append(pages, detail)
	}, 1, 8)
	t.Cleanup(s.Close)
	tenant, device := testTenant(t), uuid.New()
	before := excerptRefusalsTotal(t, "unknown_receipt")
	malformedBefore := excerptRefusalsTotal(t, "malformed")

	ev := uuidV7(t)
	s.Apply(context.Background(), tenant, device, time.Now(), "", []Effect{
		{EventID: ev, Excerpt: &Excerpt{ReceiptID: bytes.Repeat([]byte{7}, 32), SubjectID: uuidV7(t)}},
		{EventID: uuidV7(t), Excerpt: &Excerpt{ReceiptID: []byte{1, 2, 3}, SubjectID: uuidV7(t)}},
		{EventID: uuidV7(t), Excerpt: &Excerpt{ReceiptID: bytes.Repeat([]byte{7}, 32)}},
	})
	if got := excerptRefusalsTotal(t, "unknown_receipt") - before; got != 1 {
		t.Fatalf("unknown_receipt refusals = %v, want 1", got)
	}
	if got := excerptRefusalsTotal(t, "malformed") - malformedBefore; got != 2 {
		t.Fatalf("malformed refusals = %v, want 2", got)
	}
	if len(pages) != 3 || !strings.Contains(pages[0], "unknown_receipt") {
		t.Fatalf("security events = %q, want one per refusal", pages)
	}
	if got := s.PendingLeafCount(tenant, device); got != 3 {
		t.Fatalf("pending leaves = %d, want 3: a refused excerpt is still a landed event under the next checkpoint", got)
	}
}
