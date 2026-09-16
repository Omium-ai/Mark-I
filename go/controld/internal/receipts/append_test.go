package receipts_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/receipts"
)

const appendPath = "/internal/v1/receipts/append"

// storelessAppendMux has no store and no DB: every refusal must land before either is touched, and a request passing every guard answers 503 from the store gate (a guard placed after the DB would panic into obs' recover and answer 500).
func storelessAppendMux(t *testing.T, token string) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	receipts.NewModule(receipts.ModuleDeps{
		ObsCfg:            obs.Config{ServiceName: "receipts-append-test"},
		IntelServiceToken: token,
	}).RegisterRoutes(mux)
	return mux
}

func postAppend(mux *http.ServeMux, bearer, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, appendPath, strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", bearer)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

const goodBody = `{"tenant_id":"6b9f0f2e-4c1d-4a4e-8f0a-9d2b7c5e3a10","record_type":"memory_admission",` +
	`"subject_id":"189d8bb1-cba6-5f57-9312-46b0b6cb8154","idempotency_key":"memory.admit:2026-08-01:189d8bb1",` +
	`"payload":{"kind":"pitfall","lcb_micro":250000}}`

func TestAppendPassesEveryGuardBeforeTheStoreGate(t *testing.T) {
	w := postAppend(storelessAppendMux(t, "intel-secret"), "Bearer intel-secret", goodBody)
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "not wired") {
		t.Fatalf("valid request on a storeless module: got %d %s, want 503 from the store gate", w.Code, w.Body.String())
	}
}

func TestAppendRefusesServiceCredentialBeforeReadingTheBody(t *testing.T) {
	mux := storelessAppendMux(t, "intel-secret")
	for name, bearer := range map[string]string{
		"missing":      "",
		"bare":         "Bearer ",
		"wrong":        "Bearer intel-secre",
		"not-a-bearer": "Basic intel-secret",
	} {
		// A body that would otherwise pass: only the credential can be the cause.
		if w := postAppend(mux, bearer, goodBody); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "M1E-1001") {
			t.Errorf("%s credential: got %d %s, want 403 M1E-1001", name, w.Code, w.Body.String())
		}
	}
	// An empty configured token verifies NOTHING (querychoke service.go): the surface is absent, never open.
	if w := postAppend(storelessAppendMux(t, ""), "Bearer ", goodBody); w.Code != http.StatusForbidden {
		t.Errorf("empty configured token + empty bearer: got %d, want 403", w.Code)
	}
	if w := postAppend(storelessAppendMux(t, ""), "Bearer x", goodBody); w.Code != http.StatusForbidden {
		t.Errorf("empty configured token + any bearer: got %d, want 403", w.Code)
	}
}

func TestAppendRefusesEveryClassOutsideTheInternalSet(t *testing.T) {
	mux := storelessAppendMux(t, "intel-secret")
	for _, class := range []string{"checkpoint", "coverage_transition", "guard_contamination", "discontinuity", "key_rotation", "quarantine_deletion", "prompt_capture", ""} {
		body := strings.Replace(goodBody, "memory_admission", class, 1)
		w := postAppend(mux, "Bearer intel-secret", body)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `\"`+class+`\"`) {
			t.Errorf("class %q: got %d %s, want 400 naming the class", class, w.Code, w.Body.String())
		}
	}
	for class := range receipts.InternalRecordTypes {
		if !receipts.ServerRecordTypes[class] || receipts.DeviceOriginTypes[class] {
			t.Errorf("InternalRecordTypes holds %q, which is not a server-originated class", class)
		}
	}
	if receipts.InternalRecordTypes["key_rotation"] || receipts.InternalRecordTypes["quarantine_deletion"] {
		t.Error("key_rotation and quarantine_deletion are controld's own acts and must not be requestable over the internal route")
	}
}

func TestAppendRefusesMalformedIdentityAndPayload(t *testing.T) {
	mux := storelessAppendMux(t, "intel-secret")
	cases := map[string]string{
		"not json":         `{`,
		"tenant not uuid":  strings.Replace(goodBody, "6b9f0f2e-4c1d-4a4e-8f0a-9d2b7c5e3a10", "tenant-a", 1),
		"nil tenant":       strings.Replace(goodBody, "6b9f0f2e-4c1d-4a4e-8f0a-9d2b7c5e3a10", "00000000-0000-0000-0000-000000000000", 1),
		"subject missing":  strings.Replace(goodBody, "189d8bb1-cba6-5f57-9312-46b0b6cb8154", "", 1),
		"nil subject":      strings.Replace(goodBody, "189d8bb1-cba6-5f57-9312-46b0b6cb8154", "00000000-0000-0000-0000-000000000000", 1),
		"key missing":      strings.Replace(goodBody, `"idempotency_key":"memory.admit:2026-08-01:189d8bb1",`, "", 1),
		"key empty":        strings.Replace(goodBody, "memory.admit:2026-08-01:189d8bb1", "", 1),
		"key too long":     strings.Replace(goodBody, "memory.admit:2026-08-01:189d8bb1", strings.Repeat("k", 201), 1),
		"reserved seq key": strings.Replace(goodBody, `"lcb_micro":250000`, `"seq":9`, 1),
		"reserved tenant":  strings.Replace(goodBody, `"lcb_micro":250000`, `"tenant_id":"x"`, 1),
		"float payload":    strings.Replace(goodBody, `250000`, `2.5`, 1),
		"exponent payload": strings.Replace(goodBody, `250000`, `1e5`, 1),
	}
	for name, body := range cases {
		if w := postAppend(mux, "Bearer intel-secret", body); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "M1E-2001") {
			t.Errorf("%s: got %d %s, want 400 M1E-2001", name, w.Code, w.Body.String())
		}
	}
}

// The Go half of the append-seam lock (testdata/receipt_append_body.json): client.py's exact body passes every guard of the real handler.
func TestAppendAcceptsPythonExactBody(t *testing.T) {
	raw, err := os.ReadFile("testdata/receipt_append_body.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Body     json.RawMessage `json:"body"`
		Response struct {
			ReceiptID   string `json:"receipt_id"`
			Seq         int64  `json:"seq"`
			ReceiptHash string `json:"receipt_hash"`
			Payload     string `json:"payload"`
		} `json:"response"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	w := postAppend(storelessAppendMux(t, "intel-secret"), "Bearer intel-secret", string(fixture.Body))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("python's exact body refused before the store gate: %d %s", w.Code, w.Body.String())
	}
	if fixture.Response.ReceiptID == "" || fixture.Response.Seq < 1 || len(fixture.Response.ReceiptHash) != 64 {
		t.Fatalf("fixture response is not the {receipt_id, seq, receipt_hash-hex, payload} shape the handler writes: %+v", fixture.Response)
	}
	// The fixture payload is canonical text a Python verifier hashes as-is: DecodePayload → CanonicalJSON must round-trip byte-identical.
	tree, err := receipts.DecodePayload([]byte(fixture.Response.Payload))
	if err != nil {
		t.Fatal(err)
	}
	if again, err := receipts.CanonicalJSON(tree); err != nil || again != fixture.Response.Payload {
		t.Fatalf("fixture payload is not canonical: %v\n%s\n%s", err, again, fixture.Response.Payload)
	}
}
