package sidefx

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/receipts"
	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

// deletionGolden is the byte-exact signed payload the edge writes beside its bytes (mark1d uplink/retention_test.go pins
// the same string): the two modules cannot import each other, so one literal in each is what keeps them agreeing.
const deletionGolden = `{"batch_id":"0192a1b2-0000-7000-8000-00000000000b","deleted_at":"2026-09-16T12:00:00.25Z","device_id":"9d2b1f0e-2222-4222-8222-222222222222","device_key_id":"ed25519:0123456789abcdef","event_count":2,"quarantined_at":"2026-08-17T12:00:00Z","reason":"retention_30d","tenant_id":"9d2b1f0e-1111-4111-8111-111111111111","type":"quarantine_deletion","v":1}`

var (
	goldenT0     = time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	goldenBatch  = uuid.MustParse("0192a1b2-0000-7000-8000-00000000000b")
	goldenTenant = "9d2b1f0e-1111-4111-8111-111111111111"
	goldenDevice = "9d2b1f0e-2222-4222-8222-222222222222"
)

func goldenDeletion() *QuarantineDeletion {
	return &QuarantineDeletion{
		BatchID: goldenBatch, EventCount: 2,
		QuarantinedAt: goldenT0.Add(-30 * 24 * time.Hour), DeletedAt: goldenT0.Add(250 * time.Millisecond),
		Reason: DeletionReason, DeviceKeyID: "ed25519:0123456789abcdef", DeviceSignature: bytes.Repeat([]byte{1}, 64),
	}
}

func TestDeletionPayloadRebuildsTheEdgeGoldenExactly(t *testing.T) {
	text, err := receipts.CanonicalJSON(DeletionPayload(goldenTenant, goldenDevice, goldenDeletion()))
	if err != nil {
		t.Fatal(err)
	}
	if text != deletionGolden {
		t.Fatalf("reconstruction drifted from the edge receipt:\n%s\n%s", text, deletionGolden)
	}
}

// The wire's unix ms rebuild the receipt's RFC3339Nano rendering only because both sides truncate to whole ms.
func TestEffectsFromBatchMapsQuarantineDeletionAtMillisecondPrecision(t *testing.T) {
	d := goldenDeletion()
	id := uuidV7(t)
	ev := &m1pv1.Event{EventId: id[:], Body: &m1pv1.Event_QuarantineDeletion{QuarantineDeletion: &m1pv1.QuarantineDeletion{
		BatchId: d.BatchID[:], EventCount: 2,
		QuarantinedAtMs: uint64(d.QuarantinedAt.UnixMilli()), DeletedAtMs: uint64(d.DeletedAt.UnixMilli()),
		Reason: DeletionReason, DeviceKeyId: d.DeviceKeyID, DeviceSignature: d.DeviceSignature,
	}}}
	effects := EffectsFromBatch(&m1pv1.Batch{Events: []*m1pv1.Event{ev}}, goldenT0)
	if len(effects) != 1 || effects[0].Deletion == nil {
		t.Fatalf("want one deletion effect, got %+v", effects)
	}
	got := effects[0].Deletion
	if got.BatchID != d.BatchID || got.EventCount != 2 || !got.QuarantinedAt.Equal(d.QuarantinedAt) || !got.DeletedAt.Equal(d.DeletedAt) ||
		got.Reason != DeletionReason || got.DeviceKeyID != d.DeviceKeyID || !bytes.Equal(got.DeviceSignature, d.DeviceSignature) {
		t.Fatalf("wire mapping drifted: %+v", got)
	}
	if MillisString(got.DeletedAt) != "2026-09-16T12:00:00.25Z" {
		t.Fatalf("ms rendering %q", MillisString(got.DeletedAt))
	}
}

// Every malformed shape is refused BEFORE any key lookup, as a security event and a counter; the event is still a
// landed leaf of the next checkpoint, it just carries no receipt to append.
func TestQuarantineDeletionMalformedShapesAreSecurityEvents(t *testing.T) {
	var pages []string
	s, mem := newTestSidefx(&fakeChain{}, func(_, _, _ uuid.UUID, detail string, _ time.Time) { pages = append(pages, detail) })
	t.Cleanup(s.Close)
	tenant, device := testTenant(t), uuid.New()
	before := testutil.ToFloat64(deletionRefusals.WithLabelValues(string(receipts.DefectPayloadMismatch)))

	mutate := map[string]func(*QuarantineDeletion){
		"nil batch":       func(d *QuarantineDeletion) { d.BatchID = uuid.Nil },
		"no key id":       func(d *QuarantineDeletion) { d.DeviceKeyID = "" },
		"short signature": func(d *QuarantineDeletion) { d.DeviceSignature = d.DeviceSignature[:63] },
		"free-text reason": func(d *QuarantineDeletion) {
			d.Reason = "operator"
		},
		"zero quarantined_at": func(d *QuarantineDeletion) { d.QuarantinedAt = time.Time{} },
		"zero deleted_at":     func(d *QuarantineDeletion) { d.DeletedAt = time.Time{} },
	}
	var effects []Effect
	for _, m := range mutate {
		d := goldenDeletion()
		m(d)
		effects = append(effects, Effect{EventID: uuidV7(t), Deletion: d})
	}
	s.Apply(context.Background(), tenant, device, time.Now(), "", effects)

	if got := testutil.ToFloat64(deletionRefusals.WithLabelValues(string(receipts.DefectPayloadMismatch))) - before; got != float64(len(mutate)) {
		t.Fatalf("payload_mismatch refusals = %v, want %d", got, len(mutate))
	}
	if len(pages) != len(mutate) {
		t.Fatalf("security events = %d, want one per malformed deletion: %q", len(pages), pages)
	}
	for _, p := range pages {
		if !strings.Contains(p, "QuarantineDeletion refused (payload_mismatch)") {
			t.Fatalf("security event must name the refusal: %q", p)
		}
	}
	if got := s.PendingLeafCount(tenant, device); got != len(mutate) {
		t.Fatalf("pending leaves = %d, want %d: a refused deletion is still a landed event", got, len(mutate))
	}
	for _, l := range mem.pending(device) {
		if l.del != nil {
			t.Fatal("a refused deletion must carry nothing into the seal")
		}
	}
}
