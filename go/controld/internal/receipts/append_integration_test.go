//go:build integration

package receipts_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/receipts"
)

type appendAck struct {
	ReceiptID   string `json:"receipt_id"`
	Seq         int64  `json:"seq"`
	ReceiptHash string `json:"receipt_hash"`
	Payload     string `json:"payload"`
}

func appendServer(t *testing.T, h *harness) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	receipts.NewModule(receipts.ModuleDeps{
		DB: h.db, PG: h.db, ObsCfg: obs.Config{ServiceName: "controld-append-it"},
		Store: h.store, IntelServiceToken: "intel-secret",
	}).RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func doAppend(t *testing.T, srv *httptest.Server, body map[string]any) (int, appendAck, string) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, srv.URL+appendPath, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer intel-secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	text, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var ack appendAck
	if resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal(text, &ack); err != nil {
			t.Fatalf("200 body is not the ack shape: %s", text)
		}
	}
	return resp.StatusCode, ack, string(text)
}

func chainRows(t *testing.T, h *harness, tenant querychoke.TenantID) []receipts.Receipt {
	t.Helper()
	var out []receipts.Receipt
	err := h.db.WithTenant(context.Background(), tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(context.Background(),
			`SELECT seq, payload, receipt_hash, device_signature, server_key_id, server_signature FROM m1_receipts ORDER BY seq`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r receipts.Receipt
			var hash []byte
			if err := rows.Scan(&r.Seq, &r.PayloadText, &hash, &r.DeviceSig, &r.ServerKeyID, &r.ServerSig); err != nil {
				return err
			}
			r.ReceiptHash = [32]byte(hash)
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestIntegrationAppendRouteIsIdempotentVerifiableAndTenantScoped(t *testing.T) {
	h := setup(t)
	srv := appendServer(t, h)
	subject := v7(t)
	body := map[string]any{
		"tenant_id": h.tenantA.String(), "record_type": "memory_admission", "subject_id": subject.String(),
		"idempotency_key": "memory.admit:2026-08-01:" + subject.String(),
		"payload":         map[string]any{"kind": "pitfall", "lcb_micro": 250000, "n_obs": 10},
	}

	code, first, text := doAppend(t, srv, body)
	if code != http.StatusOK || first.Seq != 1 {
		t.Fatalf("first append: %d %s", code, text)
	}
	// The idempotent repeat: same (tenant, class, key) ⇒ the SAME receipt, no new link, whatever the fields say now.
	body["payload"] = map[string]any{"kind": "pitfall", "lcb_micro": 1, "n_obs": 99}
	code, again, text := doAppend(t, srv, body)
	if code != http.StatusOK || again != first {
		t.Fatalf("repeat append: %d %s, want the first ack %+v", code, text, first)
	}
	if seq, _, _, err := h.store.Head(context.Background(), h.tenantA); err != nil || seq != 1 {
		t.Fatalf("head after repeat: seq=%d err=%v, want 1 (a repeat must not move the chain)", seq, err)
	}
	// The same subject under a NEW key is a new act (re-admission after retire) and a new link.
	body["idempotency_key"] = "memory.admit:2026-09-01:" + subject.String()
	if code, second, text := doAppend(t, srv, body); code != http.StatusOK || second.Seq != 2 || second.ReceiptID == first.ReceiptID {
		t.Fatalf("same subject, new key: %d %s, want a second link", code, text)
	}
	// A key is scoped per class: the same key text under corpus_export is a third link.
	body["record_type"], body["subject_id"] = "corpus_export", v7(t).String()
	if code, third, text := doAppend(t, srv, body); code != http.StatusOK || third.Seq != 3 {
		t.Fatalf("same key, other class: %d %s", code, text)
	}

	// The Go verify_chain: both links verify under the published server chain key and the hash the ack carried is the row's.
	rows := chainRows(t, h, h.tenantA)
	keys := receipts.KeySet{}
	keys.Add(h.chainKey.Public(), receipts.RoleServerChain)
	if rep := receipts.VerifyChain(rows, keys, 1); !rep.Valid || rep.IntactPrefixSeq != 3 {
		t.Fatalf("chain through the append route does not verify: %+v", rep)
	}
	if strings.Contains(rows[0].PayloadText, "idempotency_key") || strings.Contains(rows[0].PayloadText, "memory.admit:") {
		t.Fatalf("the idempotency key leaked into the signed payload: %s", rows[0].PayloadText)
	}
	if got := hex.EncodeToString(rows[0].ReceiptHash[:]); got != first.ReceiptHash || rows[0].PayloadText != first.Payload {
		t.Fatalf("ack (hash %s, payload %q) is not row 1 (hash %s, payload %q)", first.ReceiptHash, first.Payload, got, rows[0].PayloadText)
	}
	if !strings.Contains(rows[0].PayloadText, `"subject_id":"`+subject.String()+`"`) || !strings.Contains(rows[0].PayloadText, `"lcb_micro":250000`) {
		t.Fatalf("payload lost the subject or the class fields: %s", rows[0].PayloadText)
	}

	// RLS: tenant B sees none of it, and B presenting A's exact key + subject lands in B's OWN chain at seq 1.
	if got := chainRows(t, h, h.tenantB); len(got) != 0 {
		t.Fatalf("tenant B reads %d of tenant A's receipts", len(got))
	}
	body["tenant_id"], body["subject_id"], body["record_type"] = h.tenantB.String(), subject.String(), "memory_admission"
	body["idempotency_key"] = "memory.admit:2026-08-01:" + subject.String()
	code, b, text := doAppend(t, srv, body)
	if code != http.StatusOK || b.Seq != 1 || b.ReceiptID == first.ReceiptID {
		t.Fatalf("tenant B append under A's key: %d %s (A's ack %+v) — the idempotency read leaked across tenants", code, text, first)
	}
	if seq, _, _, err := h.store.Head(context.Background(), h.tenantA); err != nil || seq != 3 {
		t.Fatalf("tenant A head moved to %d on tenant B's append (err %v)", seq, err)
	}

	// The partial unique index is the race guard behind the SELECT: a raw duplicate key is refused by name.
	err := h.db.WithTenant(context.Background(), h.tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `
			INSERT INTO m1_receipts (tenant_id, seq, prev_receipt_hash, receipt_hash, payload, record_type,
			   server_key_id, server_signature, subject_id, idempotency_key)
			VALUES ($1, 4, $2, $3, '{"probe":true}', 'memory_admission', $4, $5, $6, $7)`,
			h.tenantA.UUID(), rows[2].ReceiptHash[:], bytes.Repeat([]byte{0x5c}, 32),
			h.chainKey.KeyID(), bytes.Repeat([]byte{0x5d}, 64), subject, "memory.admit:2026-08-01:"+subject.String())
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "uq_m1_receipts_idempotency") {
		t.Fatalf("duplicate (tenant, class, key) row: want uq_m1_receipts_idempotency violation, got %v", err)
	}
}

func TestIntegrationAppendReplaysPythonExactBody(t *testing.T) {
	h := setup(t)
	srv := appendServer(t, h)
	raw, err := os.ReadFile("testdata/receipt_append_body.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Body map[string]any `json:"body"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	fixture.Body["tenant_id"] = h.tenantA.String() // the fixture's tenant exists nowhere; the shape is what is locked
	code, ack, text := doAppend(t, srv, fixture.Body)
	if code != http.StatusOK || ack.Seq != 1 {
		t.Fatalf("python's exact body: %d %s", code, text)
	}
	if _, err := uuid.Parse(ack.ReceiptID); err != nil || len(ack.ReceiptHash) != 64 {
		t.Fatalf("ack shape drifted from what client.py decodes: %s", text)
	}
}
