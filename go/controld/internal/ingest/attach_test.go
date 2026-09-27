package ingest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

type attachPart struct{ name, body string }

func attachRequest(t *testing.T, token string, parts ...attachPart) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for _, p := range parts {
		w, err := mw.CreateFormFile(p.name, p.name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(p.body))
	}
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/attach", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

// receiptFor is a receipt part whose payload claims subject and part; the signature is not what these unit tests reach.
func receiptFor(t *testing.T, subject uuid.UUID, part string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(part))
	payload, _ := json.Marshal(map[string]any{"subject_id": subject.String(), "post_hash": hex.EncodeToString(sum[:])})
	b, _ := json.Marshal(map[string]string{"payload": string(payload), "device_key_id": "k", "device_signature": strings.Repeat("00", 64)})
	return string(b)
}

func (h *harness) serve(req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)
	return rec
}

func TestAttachWithoutConsentIs422AndLandsNothing(t *testing.T) {
	h := newHarness(t)
	task := mustV7(t)
	part := "fix it\x00diff --git a/x b/x\n"
	rec := h.serve(attachRequest(t, h.token, attachPart{"receipt", receiptFor(t, task, part)}, attachPart{"attach." + task.String() + ".e1", part}))
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "e1_consent") {
		t.Fatalf("no m1_082 row saying e1: want 422 e1_consent, got %d %s", rec.Code, rec.Body.String())
	}
	if len(h.store.keys()) != 0 {
		t.Fatal("an unconsented E1 part landed")
	}
}

func TestAttachShapeRefusalsLandNothing(t *testing.T) {
	h := newHarness(t)
	task := mustV7(t)
	part := "fix it\x00diff --git a/x b/x\n"
	name := "attach." + task.String() + ".e1"
	big := "x\x00" + strings.Repeat("y", MaxAttachPart)
	for label, tc := range map[string]struct {
		req  *http.Request
		code int
	}{
		"no_token":         {attachRequest(t, "", attachPart{"receipt", receiptFor(t, task, part)}, attachPart{name, part}), http.StatusUnauthorized},
		"no_receipt":       {attachRequest(t, h.token, attachPart{name, part}), http.StatusBadRequest},
		"two_parts":        {attachRequest(t, h.token, attachPart{"receipt", receiptFor(t, task, part)}, attachPart{name, part}, attachPart{name, part}), http.StatusBadRequest},
		"bad_name":         {attachRequest(t, h.token, attachPart{"receipt", receiptFor(t, task, part)}, attachPart{"attach.x.e1", part}), http.StatusBadRequest},
		"oversized":        {attachRequest(t, h.token, attachPart{"receipt", receiptFor(t, task, big)}, attachPart{name, big}), http.StatusRequestEntityTooLarge},
		"no_nul":           {attachRequest(t, h.token, attachPart{"receipt", receiptFor(t, task, "hunks")}, attachPart{name, "hunks"}), http.StatusRequestEntityTooLarge},
		"subject_mismatch": {attachRequest(t, h.token, attachPart{"receipt", receiptFor(t, mustV7(t), part)}, attachPart{name, part}), http.StatusUnprocessableEntity},
		"hash_mismatch":    {attachRequest(t, h.token, attachPart{"receipt", receiptFor(t, task, part+"x")}, attachPart{name, part}), http.StatusUnprocessableEntity},
	} {
		if rec := h.serve(tc.req); rec.Code != tc.code {
			t.Errorf("%s: got %d %s, want %d", label, rec.Code, rec.Body.String(), tc.code)
		}
	}
	if len(h.store.keys()) != 0 {
		t.Fatal("a refused attach landed")
	}
}

func TestEvidenceReadRequiresItsOwnCredentialAndAPurpose(t *testing.T) {
	h := newHarness(t)
	task := mustV7(t)
	for label, tc := range map[string]struct {
		bearer, tenant, purpose string
		code                    int
	}{
		"none":           {"", h.tenant.String(), "judge", http.StatusForbidden},
		"wrong":          {testEvidenceToken + "x", h.tenant.String(), "judge", http.StatusForbidden},
		"shared_service": {testServiceToken, h.tenant.String(), "judge", http.StatusForbidden},
		"device_token":   {h.token, h.tenant.String(), "judge", http.StatusForbidden},
		"no_tenant":      {testEvidenceToken, "", "judge", http.StatusBadRequest},
		"nil_tenant":     {testEvidenceToken, uuid.Nil.String(), "judge", http.StatusBadRequest},
		"no_purpose":     {testEvidenceToken, h.tenant.String(), "", http.StatusBadRequest},
		"bad_purpose":    {testEvidenceToken, h.tenant.String(), "training", http.StatusBadRequest},
	} {
		req := httptest.NewRequest(http.MethodGet, "/internal/v1/evidence/"+task.String()+"?purpose="+tc.purpose, nil)
		if tc.bearer != "" {
			req.Header.Set("Authorization", "Bearer "+tc.bearer)
		}
		req.Header.Set(TenantHeader, tc.tenant)
		if rec := h.serve(req); rec.Code != tc.code {
			t.Errorf("%s: got %d %s, want %d", label, rec.Code, rec.Body.String(), tc.code)
		}
	}
}

func TestEvidenceReadIsClosedWithoutItsCredential(t *testing.T) {
	h := newHarness(t)
	mux := http.NewServeMux()
	New(Deps{Verifier: tenantOnlyVerifier{h.tenant}, PG: fakeReady{}, Store: h.store, Proj: h.proj, Sidefx: h.sfx, DB: h.tomb, IntelServiceToken: testServiceToken}).RegisterRoutes(mux)
	for _, bearer := range []string{"", testServiceToken, testEvidenceToken} {
		req := httptest.NewRequest(http.MethodGet, "/internal/v1/evidence/"+mustV7(t).String()+"?purpose=rm", nil)
		req.Header.Set("Authorization", "Bearer "+bearer)
		req.Header.Set(TenantHeader, h.tenant.String())
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("no EVIDENCE_READ_TOKEN configured, bearer %q: got %d, want 403", bearer, rec.Code)
		}
	}
}
