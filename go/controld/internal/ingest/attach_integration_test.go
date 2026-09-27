//go:build integration

package ingest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/chproj"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/s3land"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/sidefx"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/receipts"
)

// attachRig is the E1 path under the real schema: the attach/consent/evidence routes as the NOBYPASSRLS role, deviceA's enrolled key, stage 11 for bindings.
type attachRig struct {
	q     *quarantinePG
	h     *harness
	store *fakeStore
	sfx   *sidefx.Sidefx
	sec   *fakeSecurity
	key   *receipts.Signer
}

func newAttachRig(t *testing.T) *attachRig {
	t.Helper()
	q := setupQuarantinePG(t)
	key, err := receipts.NewSigner(bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.admin.Exec(context.Background(), `INSERT INTO m1_device_keys (tenant_id, device_id, key_id, public_key) VALUES ($1, $2, $3, $4)`,
		q.tenantA.UUID(), q.deviceA, key.KeyID(), []byte(key.Public())); err != nil {
		t.Fatal(err)
	}
	r := &attachRig{q: q, store: newFakeStore(), sec: &fakeSecurity{}, key: key}
	proj := chproj.New(&fakeInserter{}, 1, 10)
	r.sfx = sidefx.New(q.db, q.chain, func(uuid.UUID, uuid.UUID, uuid.UUID, string, time.Time) {}, 1, 10)
	r.sfx.SetLeafStore(sidefx.NewMemoryLeafStore())
	t.Cleanup(func() { proj.Close(); r.sfx.Close() })
	r.h = &harness{mux: http.NewServeMux(), store: r.store, token: auth.Mint(testKey, q.tenantA.UUID(), q.deviceA, time.Hour)}
	New(Deps{
		Verifier: auth.NewHMACVerifier(testKey, auth.StaticRevocations{}),
		ObsCfg:   obs.Config{ServiceName: "controld-test"},
		PG:       fakeReady{}, Store: r.store, Proj: proj, Sidefx: r.sfx, Security: r.sec, DB: q.db, IntelServiceToken: testServiceToken, EvidenceToken: testEvidenceToken,
	}).RegisterRoutes(r.h.mux)
	return r
}

func (r *attachRig) consent(t *testing.T, token, body string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/api/v1/consents", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	if rec := r.h.serve(req); rec.Code != http.StatusOK {
		t.Fatalf("consent %s: %d %s", body, rec.Code, rec.Body.String())
	}
}

// own lands a TaskOpen for task from device (stage 11, m1_106).
func (r *attachRig) own(t *testing.T, device, task uuid.UUID) {
	t.Helper()
	r.sfx.Apply(context.Background(), r.q.tenantA, device, time.Now(), "", []sidefx.Effect{{EventID: mustV7(t), Task: task}})
}

func (r *attachRig) send(t *testing.T, token string, task uuid.UUID, part string) (*httptest.ResponseRecorder, [32]byte) {
	t.Helper()
	pre, post := sha256.Sum256([]byte("raw "+part)), sha256.Sum256([]byte(part))
	s, err := receipts.OriginSign(r.key, map[string]any{
		"v": 1, "type": "redaction", "tenant_id": r.q.tenantA.String(), "device_id": r.q.deviceA.String(),
		"device_key_id": r.key.KeyID(), "subject_id": task.String(), "issued_at": "2026-09-26T12:00:00Z", "tier": "E1",
		"pre_hash": hex.EncodeToString(pre[:]), "post_hash": hex.EncodeToString(post[:]),
		"classes": map[string]any{}, "span_digests": []any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]string{"payload": s.PayloadText, "device_key_id": r.key.KeyID(), "device_signature": hex.EncodeToString(s.DeviceSig)})
	return r.h.serve(attachRequest(t, token, attachPart{"receipt", string(b)}, attachPart{"attach." + task.String() + ".e1", part})), s.ReceiptHash
}

func (r *attachRig) read(tenant, task uuid.UUID, purpose string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/internal/v1/evidence/"+task.String()+"?purpose="+purpose, nil)
	req.Header.Set("Authorization", "Bearer "+testEvidenceToken)
	req.Header.Set(TenantHeader, tenant.String())
	return r.h.serve(req)
}

// bind lands the EvidenceExcerpt naming receipt (stage 11), after which the part may be served.
func (r *attachRig) bind(t *testing.T, task uuid.UUID, receipt [32]byte) {
	t.Helper()
	r.sfx.Apply(context.Background(), r.q.tenantA, r.q.deviceA, time.Now(), "", []sidefx.Effect{{EventID: mustV7(t), Excerpt: &sidefx.Excerpt{ReceiptID: receipt[:], SubjectID: task}}})
}

func (r *attachRig) sweep(t *testing.T, at time.Time) int {
	t.Helper()
	j := NewQuarantineSweep(r.q.db, r.store, r.q.chain, receipts.StaticTenants([]uuid.UUID{r.q.tenantA.UUID()}))
	j.Clock(func() time.Time { return at }, nil)
	n, err := j.SweepEvidence(context.Background(), r.q.tenantA.UUID())
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// TestIntegrationAttachE1EndToEnd: consent-gated idempotent landing, second-ruleset quarantine, tenant-scoped read, receipted deletion.
func TestIntegrationAttachE1EndToEnd(t *testing.T) {
	r := newAttachRig(t)
	q, h, store, sec, ctx := r.q, r.h, r.store, r.sec, context.Background()
	consent := func(e1 bool) {
		t.Helper()
		r.consent(t, h.token, fmt.Sprintf(`{"e1":%t,"cloud_judge":true,"training":false,"team":false}`, e1))
	}
	send := func(task uuid.UUID, part string) (*httptest.ResponseRecorder, [32]byte) {
		t.Helper()
		r.own(t, q.deviceA, task)
		return r.send(t, h.token, task, part)
	}
	read := func(tenant, task uuid.UUID) *httptest.ResponseRecorder { return r.read(tenant, task, "judge") }
	bind := func(task uuid.UUID, receipt [32]byte) { t.Helper(); r.bind(t, task, receipt) }
	sweep := func(at time.Time) int { t.Helper(); return r.sweep(t, at) }

	task := mustV7(t)
	part := "make the flaky test deterministic\x00diff --git a/a_test.go b/a_test.go\n@@ -1 +1 @@\n-sleep(1)\n+wait()\n"
	consent(false)
	if rec, _ := send(task, part); rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "e1_consent") {
		t.Fatalf("e1 off: %d %s", rec.Code, rec.Body.String())
	}
	consent(true)
	rec, receipt := send(task, part)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"landed"`) {
		t.Fatalf("consented attach: %d %s", rec.Code, rec.Body.String())
	}
	if rec, _ := send(task, part); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"duplicate"`) {
		t.Fatalf("retry of the same part must be the idempotent duplicate: %d %s", rec.Code, rec.Body.String())
	}
	if rec, _ := send(task, part+"+more\n"); rec.Code != http.StatusConflict {
		t.Fatalf("different bytes for a landed task: %d %s", rec.Code, rec.Body.String())
	}
	if keys := store.keys(); len(keys) != 1 || keys[0] != s3land.EvidenceKey(q.tenantA.UUID(), task) {
		t.Fatalf("landed %v", keys)
	}
	var indexed []byte
	if err := q.admin.QueryRow(ctx, `SELECT receipt_id FROM m1_evidence_attachments WHERE task_id = $1`, task).Scan(&indexed); err != nil || !bytes.Equal(indexed, receipt[:]) {
		t.Fatalf("index row does not name the receipt: %x %v", indexed, err)
	}

	if rec := read(q.tenantA.UUID(), task); rec.Code != http.StatusNotFound {
		t.Fatalf("before its EvidenceExcerpt lands the part is not served: %d", rec.Code)
	}
	bind(task, receipt)
	rec = read(q.tenantA.UUID(), task)
	var got struct{ Tier, Intent, Hunks, ReceiptID string }
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil || got.Tier != "E1" ||
		got.Intent != "make the flaky test deterministic" || !strings.HasPrefix(got.Hunks, "diff --git a/a_test.go") {
		t.Fatalf("bound read: %d %s", rec.Code, rec.Body.String())
	}
	if rec := read(q.tenantB.UUID(), task); rec.Code != http.StatusNotFound {
		t.Fatalf("tenant B read tenant A's evidence: %d %s", rec.Code, rec.Body.String())
	}

	flagged := mustV7(t)
	if rec, _ := send(flagged, "ship it\x00+AWS = \"AKIAIOSFODNN7EXAMPLE\"\n"); rec.Code != http.StatusAccepted || !strings.Contains(rec.Body.String(), "aws_access_key_id") {
		t.Fatalf("second ruleset hit: %d %s", rec.Code, rec.Body.String())
	}
	var n int
	if err := q.admin.QueryRow(ctx, `SELECT count(*) FROM m1_evidence_attachments WHERE task_id = $1`, flagged).Scan(&n); err != nil || n != 0 {
		t.Fatalf("a quarantined part was indexed: %d %v", n, err)
	}
	if err := q.admin.QueryRow(ctx, `SELECT count(*) FROM m1_quarantined_batches WHERE object_key LIKE '%/quarantine/v1/%e1-' || $1 || '.bin'`, flagged.String()).Scan(&n); err != nil || n != 1 {
		t.Fatalf("quarantine tombstone: %d %v", n, err)
	}
	for _, k := range store.keys() {
		if strings.Contains(k, "/evidence/v1/"+flagged.String()) {
			t.Fatal("a flagged part landed under the evidence prefix")
		}
	}
	if len(sec.quarantines) != 1 {
		t.Fatalf("tenant alert not recorded: %v", sec.quarantines)
	}

	if n := sweep(time.Now()); n != 0 {
		t.Fatalf("a live, consented, fresh part was swept: %d", n)
	}
	consent(false)
	if rec := read(q.tenantA.UUID(), task); rec.Code != http.StatusNotFound {
		t.Fatalf("withdrawn evidence still served: %d", rec.Code)
	}
	if n := sweep(time.Now()); n != 1 {
		t.Fatalf("withdrawal sweep closed %d, want 1", n)
	}
	if out, _ := store.Probe(ctx, s3land.EvidenceKey(q.tenantA.UUID(), task), nil); out != s3land.NotLanded {
		t.Fatal("withdrawn evidence object survived the sweep")
	}
	deletion := func(task uuid.UUID) string {
		t.Helper()
		var payload string
		if err := q.admin.QueryRow(ctx, `SELECT r.payload FROM m1_receipts r JOIN m1_evidence_attachments e ON e.deletion_receipt_id = r.id
			WHERE r.record_type = 'evidence_deletion' AND r.subject_id = $1 AND e.deleted_at IS NOT NULL`, task).Scan(&payload); err != nil {
			t.Fatalf("no evidence_deletion receipt closes %s: %v", task, err)
		}
		return payload
	}
	if p := deletion(task); !strings.Contains(p, `"reason":"withdrawn"`) || !strings.Contains(p, `"object":"deleted"`) {
		t.Fatalf("withdrawal receipt %s", p)
	}

	consent(true)
	aged := mustV7(t)
	if rec, _ := send(aged, "tidy\x00diff --git a/b b/b\n"); rec.Code != http.StatusOK {
		t.Fatalf("second part: %d %s", rec.Code, rec.Body.String())
	}
	if n := sweep(time.Now().Add(EvidenceRetention - time.Hour)); n != 0 {
		t.Fatalf("swept %d before 30 days", n)
	}
	if n := sweep(time.Now().Add(EvidenceRetention + time.Hour)); n != 1 {
		t.Fatalf("retention sweep closed %d, want 1", n)
	}
	if p := deletion(aged); !strings.Contains(p, `"reason":"retention_30d"`) {
		t.Fatalf("retention receipt %s", p)
	}
	if n := sweep(time.Now().Add(EvidenceRetention + 2*time.Hour)); n != 0 {
		t.Fatalf("a closed row was receipted twice: %d", n)
	}

	raced := mustV7(t)
	if rec, _ := send(raced, "race\x00diff --git a/c b/c\n"); rec.Code != http.StatusOK {
		t.Fatalf("third part: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := q.admin.Exec(ctx, `INSERT INTO m1_device_consents (tenant_id, device_id, e1, cloud_judge, training, recorded_at)
		VALUES ($1, $2, false, true, false, now() - interval '1 hour')`, q.tenantA.UUID(), q.deviceA); err != nil {
		t.Fatal(err)
	}
	if n := sweep(time.Now()); n != 1 {
		t.Fatalf("a withdrawal written last but stamped an hour early (m1_105) closed %d, want 1", n)
	}
	if p := deletion(raced); !strings.Contains(p, `"reason":"withdrawn"`) {
		t.Fatalf("clock-stepped withdrawal receipt %s", p)
	}
}
