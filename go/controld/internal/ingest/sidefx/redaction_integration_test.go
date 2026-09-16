//go:build integration

package sidefx_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/sidefx"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/receipts"
)

// redactionPayload is the edge's receipt.Redaction.Payload field set (go/mark1d/internal/receipt/redaction.go).
func redactionPayload(tenant querychoke.TenantID, device uuid.UUID, keyID string, subject uuid.UUID, pre, post [32]byte) map[string]any {
	return map[string]any{
		"v": 1, "type": "redaction", "tenant_id": tenant.String(), "device_id": device.String(),
		"device_key_id": keyID, "subject_id": subject.String(), "issued_at": "2026-09-16T12:00:00Z", "tier": "E1",
		"pre_hash": hex.EncodeToString(pre[:]), "post_hash": hex.EncodeToString(post[:]),
		"classes": map[string]any{"api_key": 2}, "span_digests": []any{"0011223344556677", "8899aabbccddeeff"},
	}
}

type pager struct{ details []string }

func (p *pager) page(_, _, _ uuid.UUID, detail string, _ time.Time) {
	p.details = append(p.details, detail)
}

func TestIntegrationRedactionReceiptAdmitBindAndRefuse(t *testing.T) {
	h := setupPG(t)
	ctx := context.Background()
	pg := &pager{}
	s := sidefx.New(h.db, h.store, pg.page, 1, 8)
	t.Cleanup(s.Close)

	// A second enrolled device in tenant A: the receipt is per DEVICE, not per tenant.
	var deviceA2 uuid.UUID
	if err := h.admin.QueryRow(ctx,
		`INSERT INTO m1_devices (tenant_id, platform, hostname_hmac) VALUES ($1, 'linux', $2) RETURNING id`,
		h.tenantA.UUID(), make([]byte, 32)).Scan(&deviceA2); err != nil {
		t.Fatal(err)
	}
	subject := uuid.Must(uuid.NewV7())
	pre, post := sha256.Sum256([]byte("raw")), sha256.Sum256([]byte("sanitized"))
	payload := redactionPayload(h.tenantA, h.deviceA, h.deviceKey.KeyID(), subject, pre, post)
	signed, err := receipts.OriginSign(h.deviceKey, payload)
	if err != nil {
		t.Fatal(err)
	}

	boundEvent := func(receipt [32]byte) *uuid.UUID {
		t.Helper()
		var bound *uuid.UUID
		if err := h.admin.QueryRow(ctx,
			`SELECT excerpt_event_id FROM m1_redaction_receipts WHERE tenant_id = $1 AND receipt_id = $2`,
			h.tenantA.UUID(), receipt[:]).Scan(&bound); err != nil {
			t.Fatal(err)
		}
		return bound
	}
	apply := func(tenant querychoke.TenantID, device uuid.UUID, event uuid.UUID, receipt []byte, subj uuid.UUID) {
		t.Helper()
		s.Apply(ctx, tenant, device, time.Now(), "", []sidefx.Effect{
			{EventID: event, Excerpt: &sidefx.Excerpt{ReceiptID: receipt, SubjectID: subj}}})
	}

	t.Run("admit_under_the_enrolled_key", func(t *testing.T) {
		id, err := s.AdmitRedactionReceipt(ctx, h.tenantA, h.deviceA, signed.PayloadText, signed.DeviceSig)
		if err != nil {
			t.Fatal(err)
		}
		if id != signed.ReceiptHash {
			t.Fatal("receipt id is not sha256(domain prefix || payload): the edge and server would name different receipts")
		}
		// Re-upload (attach retry) is a no-op, not a second row.
		if _, err := s.AdmitRedactionReceipt(ctx, h.tenantA, h.deviceA, signed.PayloadText, signed.DeviceSig); err != nil {
			t.Fatal(err)
		}
		var n int
		if err := h.admin.QueryRow(ctx, `SELECT count(*) FROM m1_redaction_receipts WHERE receipt_id = $1`, id[:]).Scan(&n); err != nil || n != 1 {
			t.Fatalf("rows = %d (%v), want exactly 1", n, err)
		}
		if boundEvent(id) != nil {
			t.Fatal("a freshly admitted receipt must be unbound until its excerpt lands")
		}
	})

	t.Run("admit_refusals", func(t *testing.T) {
		otherKey, err := receipts.NewSigner([]byte(strings.Repeat("3", 32)))
		if err != nil {
			t.Fatal(err)
		}
		foreign := redactionPayload(h.tenantA, h.deviceA, otherKey.KeyID(), subject, pre, post)
		foreignSigned, _ := receipts.OriginSign(otherKey, foreign)
		wrongTenant := redactionPayload(h.tenantB, h.deviceA, h.deviceKey.KeyID(), subject, pre, post)
		wrongTenantSigned, _ := receipts.OriginSign(h.deviceKey, wrongTenant)
		notE1 := redactionPayload(h.tenantA, h.deviceA, h.deviceKey.KeyID(), subject, pre, post)
		notE1["tier"] = "E2"
		notE1Signed, _ := receipts.OriginSign(h.deviceKey, notE1)
		tamperedSig := append([]byte(nil), signed.DeviceSig...)
		tamperedSig[0] ^= 1
		cases := map[string]struct {
			payload string
			sig     []byte
			code    receipts.Defect
		}{
			"unknown key":       {foreignSigned.PayloadText, foreignSigned.DeviceSig, receipts.DefectUnknownKey},
			"another tenant":    {wrongTenantSigned.PayloadText, wrongTenantSigned.DeviceSig, receipts.DefectPayloadMismatch},
			"not tier E1":       {notE1Signed.PayloadText, notE1Signed.DeviceSig, receipts.DefectPayloadMismatch},
			"bad signature":     {signed.PayloadText, tamperedSig, receipts.DefectBadSignature},
			"non-canonical":     {" " + signed.PayloadText, signed.DeviceSig, receipts.DefectNonCanonicalPayload},
			"not a json object": {"[1]", signed.DeviceSig, receipts.DefectNonCanonicalPayload},
		}
		for name, c := range cases {
			_, err := s.AdmitRedactionReceipt(ctx, h.tenantA, h.deviceA, c.payload, c.sig)
			if r, ok := receipts.AsRefusal(err); !ok || r.Code != c.code {
				t.Errorf("%s: err = %v, want refusal %s", name, err, c.code)
			}
		}
		// Device B presenting device A's receipt: the key belongs to another device.
		_, err = s.AdmitRedactionReceipt(ctx, h.tenantB, h.deviceB, signed.PayloadText, signed.DeviceSig)
		if r, ok := receipts.AsRefusal(err); !ok || r.Code != receipts.DefectPayloadMismatch {
			t.Errorf("device B: err = %v, want payload_mismatch", err)
		}
		// Device A2 (same tenant) signing with device A's key: the key is not its own.
		a2 := redactionPayload(h.tenantA, deviceA2, h.deviceKey.KeyID(), subject, pre, post)
		a2Signed, _ := receipts.OriginSign(h.deviceKey, a2)
		_, err = s.AdmitRedactionReceipt(ctx, h.tenantA, deviceA2, a2Signed.PayloadText, a2Signed.DeviceSig)
		if r, ok := receipts.AsRefusal(err); !ok || r.Code != receipts.DefectUnknownKey {
			t.Errorf("device A2 under A's key: err = %v, want unknown_key", err)
		}
		var n int
		if err := h.admin.QueryRow(ctx, `SELECT count(*) FROM m1_redaction_receipts`).Scan(&n); err != nil || n != 1 {
			t.Fatalf("rows = %d, want the one admitted receipt only", n)
		}
	})

	excerpt := uuid.Must(uuid.NewV7())
	t.Run("refused_before_bound", func(t *testing.T) {
		forged := make([]byte, 32)
		_, _ = rand.Read(forged)
		before := len(pg.details)
		apply(h.tenantA, h.deviceA, uuid.Must(uuid.NewV7()), forged, subject)                                // unknown receipt id
		apply(h.tenantA, h.deviceA, uuid.Must(uuid.NewV7()), signed.ReceiptHash[:], uuid.Must(uuid.NewV7())) // wrong subject
		apply(h.tenantB, h.deviceB, uuid.Must(uuid.NewV7()), signed.ReceiptHash[:], subject)                 // another tenant's receipt
		apply(h.tenantA, deviceA2, uuid.Must(uuid.NewV7()), signed.ReceiptHash[:], subject)                  // a sibling device's receipt
		if got := pg.details[before:]; len(got) != 4 {
			t.Fatalf("security events = %q, want one per refusal", got)
		}
		for _, d := range pg.details[before:] {
			if !strings.Contains(d, "unknown_receipt") {
				t.Errorf("refusal %q is not named unknown_receipt", d)
			}
		}
		if boundEvent(signed.ReceiptHash) != nil {
			t.Fatal("a refused excerpt bound the receipt")
		}
	})

	t.Run("bind_once", func(t *testing.T) {
		before := len(pg.details)
		apply(h.tenantA, h.deviceA, excerpt, signed.ReceiptHash[:], subject)
		apply(h.tenantA, h.deviceA, excerpt, signed.ReceiptHash[:], subject) // replayed batch
		if got := boundEvent(signed.ReceiptHash); got == nil || *got != excerpt {
			t.Fatalf("bound = %v, want the excerpt event %s", got, excerpt)
		}
		if len(pg.details) != before {
			t.Fatalf("a matching excerpt was paged: %q", pg.details[before:])
		}
		apply(h.tenantA, h.deviceA, uuid.Must(uuid.NewV7()), signed.ReceiptHash[:], subject) // a second excerpt on one receipt
		if got := boundEvent(signed.ReceiptHash); got == nil || *got != excerpt {
			t.Fatal("a second excerpt re-bound the receipt")
		}
		if len(pg.details) != before+1 {
			t.Fatal("a second excerpt on a bound receipt was not refused")
		}
		if _, err := h.admin.Exec(ctx, `UPDATE m1_redaction_receipts SET excerpt_event_id = $1 WHERE receipt_id = $2`,
			uuid.New(), signed.ReceiptHash[:]); err == nil {
			t.Fatal("the bind-once trigger let excerpt_event_id move")
		}
		if _, err := h.admin.Exec(ctx, `DELETE FROM m1_redaction_receipts WHERE receipt_id = $1`, signed.ReceiptHash[:]); err == nil {
			t.Fatal("the receipt row was deletable")
		}
	})

	t.Run("rls_hides_the_receipt_from_tenant_b", func(t *testing.T) {
		var n int
		err := h.db.WithTenant(ctx, h.tenantB, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM m1_redaction_receipts`).Scan(&n)
		})
		if err != nil || n != 0 {
			t.Fatalf("tenant B sees %d receipt(s) (%v), want 0", n, err)
		}
	})
}
