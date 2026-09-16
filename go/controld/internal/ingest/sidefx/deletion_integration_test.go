//go:build integration

package sidefx_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/sidefx"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/receipts"
)

func v7(t *testing.T) uuid.UUID {
	t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func counterValue(t *testing.T, name, label, value string) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range families {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			if label == "" {
				return m.GetCounter().GetValue()
			}
			for _, l := range m.GetLabel() {
				if l.GetName() == label && l.GetValue() == value {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}

// signedDeletion plays the edge's sweep: the receipt payload signed under the enrolled key over the identity controld
// will rebuild from the verified claims (uplink/retention.go receiptDeletion).
func (h *pgHarness) signedDeletion(t *testing.T, device uuid.UUID, batch uuid.UUID, at time.Time) *sidefx.QuarantineDeletion {
	t.Helper()
	d := &sidefx.QuarantineDeletion{
		BatchID: batch, EventCount: 3,
		QuarantinedAt: at.Add(-31 * 24 * time.Hour).Truncate(time.Millisecond), DeletedAt: at.Truncate(time.Millisecond),
		Reason: sidefx.DeletionReason, DeviceKeyID: h.deviceKey.KeyID(),
	}
	signed, err := receipts.OriginSign(h.deviceKey, sidefx.DeletionPayload(h.tenantA.String(), device.String(), d))
	if err != nil {
		t.Fatal(err)
	}
	d.DeviceSignature = signed.DeviceSig
	return d
}

type receiptRow struct {
	seq        int64
	recordType string
	subject    *uuid.UUID
	payload    map[string]any
	idemKey    *string
	deviceSig  []byte
	prevHash   []byte
	hash       []byte
}

func (h *pgHarness) chainRows(t *testing.T) []receiptRow {
	t.Helper()
	rows, err := h.admin.Query(context.Background(),
		`SELECT seq, record_type, subject_id, payload, idempotency_key, device_signature, prev_receipt_hash, receipt_hash
		   FROM m1_receipts WHERE tenant_id = $1 ORDER BY seq`, h.tenantA.UUID())
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []receiptRow
	for rows.Next() {
		var r receiptRow
		var payload string
		if err := rows.Scan(&r.seq, &r.recordType, &r.subject, &payload, &r.idemKey, &r.deviceSig, &r.prevHash, &r.hash); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(payload), &r.payload); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

// The edge's QuarantineDeletion lands as a quarantine_deletion record in the SAME transaction as the checkpoint that
// seals its leaf: chain position checkpoint+1, prev hash = the checkpoint's hash, subject = batch_id, origin edge,
// no device signature on the row (m1_002's origin equivalence), idempotency key edge:<batch>.
func TestIntegrationEdgeQuarantineDeletionIsReceiptedUnderItsCheckpoint(t *testing.T) {
	h := setupPG(t)
	ctx := context.Background()
	s := sidefx.New(h.db, h.store, func(_, _, _ uuid.UUID, detail string, _ time.Time) { t.Errorf("unexpected security event: %s", detail) }, 1, 8)
	t.Cleanup(s.Close)
	now := time.Date(2026, 9, 16, 12, 0, 0, 250_000_000, time.UTC)
	batch, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	d := h.signedDeletion(t, h.deviceA, batch, now)
	leafID := v7(t)
	before := counterValue(t, "controld_ingest_quarantine_deletions_appended_total", "", "")

	s.Apply(ctx, h.tenantA, h.deviceA, now, "", []sidefx.Effect{{EventID: leafID, Deletion: d}})
	if got := s.PendingLeafCount(h.tenantA, h.deviceA); got != 1 {
		t.Fatalf("pending = %d, want the deletion leaf waiting for its checkpoint", got)
	}
	if len(h.chainRows(t)) != 0 {
		t.Fatal("the record must wait for the seal: no receipt, no row")
	}
	cp := h.sealCheckpoint(t, h.deviceA, []uuid.UUID{leafID}, now)
	s.Apply(ctx, h.tenantA, h.deviceA, now, "", []sidefx.Effect{{EventID: cp.EventID, Checkpoint: &cp}})

	rows := h.chainRows(t)
	if len(rows) != 2 || rows[0].recordType != "checkpoint" || rows[1].recordType != "quarantine_deletion" {
		t.Fatalf("chain = %+v, want [checkpoint, quarantine_deletion]", rows)
	}
	rec := rows[1]
	if rec.seq != 2 || string(rec.prevHash) != string(rows[0].hash) {
		t.Fatalf("the deletion record must chain directly behind its checkpoint: seq %d", rec.seq)
	}
	if rec.subject == nil || *rec.subject != batch || rec.deviceSig != nil || rec.idemKey == nil || *rec.idemKey != "edge:"+batch.String() {
		t.Fatalf("row shape: subject %v sig %v idem %v", rec.subject, rec.deviceSig, rec.idemKey)
	}
	want := map[string]any{
		"type": "quarantine_deletion", "origin": "edge", "reason": "retention_30d", "event_count": float64(3),
		"quarantined_at": sidefx.MillisString(d.QuarantinedAt), "deleted_at": "2026-09-16T12:00:00.25Z",
		"device_key_id": h.deviceKey.KeyID(), "subject_id": batch.String(), "tenant_id": h.tenantA.String(),
	}
	for k, v := range want {
		if rec.payload[k] != v {
			t.Fatalf("payload[%s] = %v, want %v (%v)", k, rec.payload[k], v, rec.payload)
		}
	}
	if got := counterValue(t, "controld_ingest_quarantine_deletions_appended_total", "", "") - before; got != 1 {
		t.Fatalf("appended counter moved by %v, want 1", got)
	}
	seq, _, _, err := h.store.Head(ctx, h.tenantA)
	if err != nil || seq != 2 {
		t.Fatalf("head seq %d err %v, want 2", seq, err)
	}

	// Restart + replay (05 §2.5): the same leaf and the same checkpoint come around again; the chain's duplicate
	// detection consumes the prefix and NO second record is written.
	s2 := sidefx.New(h.db, h.store, func(_, _, _ uuid.UUID, detail string, _ time.Time) { t.Errorf("replay paged security: %s", detail) }, 1, 8)
	t.Cleanup(s2.Close)
	s2.Apply(ctx, h.tenantA, h.deviceA, now, "", []sidefx.Effect{{EventID: leafID, Deletion: d}, {EventID: cp.EventID, Checkpoint: &cp}})
	if rows := h.chainRows(t); len(rows) != 2 {
		t.Fatalf("replay doubled the chain: %d rows", len(rows))
	}
	if got := s2.PendingLeafCount(h.tenantA, h.deviceA); got != 0 {
		t.Fatalf("replayed prefix not consumed: %d pending", got)
	}

	// A second edge event naming the SAME batch under a fresh seal: the idempotency pre-check keeps one record per
	// batch and never fails the checkpoint over it.
	again := v7(t)
	s2.Apply(ctx, h.tenantA, h.deviceA, now, "", []sidefx.Effect{{EventID: again, Deletion: h.signedDeletion(t, h.deviceA, batch, now.Add(time.Hour))}})
	cp2 := h.sealCheckpoint(t, h.deviceA, []uuid.UUID{again}, now.Add(time.Hour))
	s2.Apply(ctx, h.tenantA, h.deviceA, now, "", []sidefx.Effect{{EventID: cp2.EventID, Checkpoint: &cp2}})
	rows = h.chainRows(t)
	if len(rows) != 3 || rows[2].recordType != "checkpoint" {
		t.Fatalf("second seal: chain = %d rows, want the checkpoint appended and no second deletion record", len(rows))
	}
}

// A signature that does not verify, a key the tenant never enrolled, or another device's key: each is a security
// event and a counter, the checkpoint still seals the leaf, and nothing is appended for it.
func TestIntegrationEdgeQuarantineDeletionRefusalsPageAndNeverAppend(t *testing.T) {
	h := setupPG(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	otherDevice := uuid.New()
	if _, err := h.admin.Exec(ctx, `INSERT INTO m1_devices (id, tenant_id, platform, hostname_hmac) VALUES ($1, $2, 'linux', $3)`,
		otherDevice, h.tenantA.UUID(), make([]byte, 32)); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		device uuid.UUID
		mutate func(*sidefx.QuarantineDeletion)
		code   string
	}{
		{"tampered signature", h.deviceA, func(d *sidefx.QuarantineDeletion) { d.DeviceSignature[5] ^= 0x40 }, "bad_signature"},
		{"altered field", h.deviceA, func(d *sidefx.QuarantineDeletion) { d.EventCount++ }, "bad_signature"},
		{"unknown key", h.deviceA, func(d *sidefx.QuarantineDeletion) { d.DeviceKeyID = "ed25519:ffffffffffffffff" }, "unknown_key"},
		{"another device's key", otherDevice, func(*sidefx.QuarantineDeletion) {}, "unknown_key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var pages []string
			s := sidefx.New(h.db, h.store, func(_, device, _ uuid.UUID, detail string, _ time.Time) {
				if device != tc.device {
					t.Errorf("security event names device %s, want %s", device, tc.device)
				}
				pages = append(pages, detail)
			}, 1, 8)
			t.Cleanup(s.Close)
			before := counterValue(t, "controld_ingest_quarantine_deletion_refusals_total", "code", tc.code)
			rowsBefore := len(h.chainRows(t))

			d := h.signedDeletion(t, h.deviceA, v7(t), now)
			tc.mutate(d)
			leafID := v7(t)
			s.Apply(ctx, h.tenantA, tc.device, now, "", []sidefx.Effect{{EventID: leafID, Deletion: d}})
			if len(pages) != 1 || !strings.Contains(pages[0], "QuarantineDeletion refused ("+tc.code+")") {
				t.Fatalf("security events = %q, want one naming %s", pages, tc.code)
			}
			if got := counterValue(t, "controld_ingest_quarantine_deletion_refusals_total", "code", tc.code) - before; got != 1 {
				t.Fatalf("refusal counter %s moved by %v, want 1", tc.code, got)
			}
			if tc.device != h.deviceA {
				return // the other device has no enrolled key to seal with; the refusal above is the whole test
			}
			cp := h.sealCheckpoint(t, h.deviceA, []uuid.UUID{leafID}, now)
			s.Apply(ctx, h.tenantA, h.deviceA, now, "", []sidefx.Effect{{EventID: cp.EventID, Checkpoint: &cp}})
			rows := h.chainRows(t)
			if len(rows) != rowsBefore+1 || rows[len(rows)-1].recordType != "checkpoint" {
				t.Fatalf("a refused deletion must still seal as a plain leaf and append nothing else: %d -> %d rows", rowsBefore, len(rows))
			}
		})
	}
}

// Tenant B's session cannot see, seal or receipt tenant A's deletion: the key lookup runs under RLS and the record
// class shares m1_receipts' tenant wall.
func TestIntegrationEdgeQuarantineDeletionIsTenantScoped(t *testing.T) {
	h := setupPG(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	var pages []string
	s := sidefx.New(h.db, h.store, func(_, _, _ uuid.UUID, detail string, _ time.Time) { pages = append(pages, detail) }, 1, 8)
	t.Cleanup(s.Close)
	d := h.signedDeletion(t, h.deviceA, v7(t), now)
	s.Apply(ctx, h.tenantB, h.deviceA, now, "", []sidefx.Effect{{EventID: v7(t), Deletion: d}})
	if len(pages) != 1 || !strings.Contains(pages[0], "unknown_key") {
		t.Fatalf("tenant B presenting tenant A's key must read as unknown_key under RLS: %q", pages)
	}
	var n int
	if err := h.admin.QueryRow(ctx, `SELECT count(*) FROM m1_receipts WHERE record_type = 'quarantine_deletion'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("records = %d err %v, want none", n, err)
	}
}
