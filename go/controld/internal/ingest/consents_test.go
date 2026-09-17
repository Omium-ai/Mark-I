package ingest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
)

func (h *harness) putConsents(t *testing.T, bearer, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/api/v1/consents", strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)
	return rec
}

// TestConsentsRouteIsDeviceTokenOnlyAndWhole: the relay is refused without a
// device token (401), with a tenant-only principal (403), with a partial or
// unknown-field body (400: a partial write must never read as a revocation of
// what it omitted), and with no consent store (503); a whole body under the
// device token reaches the store exactly once.
func TestConsentsRouteIsDeviceTokenOnlyAndWhole(t *testing.T) {
	h := newHarness(t)
	whole := `{"e1":true,"cloud_judge":false,"training":true}`
	if rec := h.putConsents(t, "", whole); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d %s", rec.Code, rec.Body.String())
	}
	userOnly := http.NewServeMux()
	New(Deps{Verifier: tenantOnlyVerifier{h.tenant}, PG: fakeReady{}, Store: h.store, Proj: h.proj, Sidefx: h.sfx, Security: h.sec, DB: h.tomb}).RegisterRoutes(userOnly)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/consents", strings.NewReader(whole))
	req.Header.Set("Authorization", "Bearer user")
	rr := httptest.NewRecorder()
	userOnly.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "M1E-1001") {
		t.Fatalf("tenant-only principal (the Mark 1 user token): %d %s", rr.Code, rr.Body.String())
	}
	for _, body := range []string{`{"e1":true,"training":true}`, `{"e1":true,"cloud_judge":false,"training":true,"extra":1}`, `{"e1":"yes","cloud_judge":false,"training":true}`, ``} {
		if rec := h.putConsents(t, h.token, body); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "M1E-2001") {
			t.Fatalf("body %q: %d %s", body, rec.Code, rec.Body.String())
		}
	}
	if h.tomb.calls != 0 {
		t.Fatalf("a refused body reached the store %d times", h.tomb.calls)
	}
	rec := h.putConsents(t, h.token, whole)
	if rec.Code != http.StatusOK || h.tomb.calls != 1 || !strings.Contains(rec.Body.String(), "recorded_at") {
		t.Fatalf("whole body: %d %s (store calls %d)", rec.Code, rec.Body.String(), h.tomb.calls)
	}
	nodb := New(Deps{Verifier: h.verifier, PG: fakeReady{}, Store: h.store, Proj: h.proj, Sidefx: h.sfx, Security: h.sec})
	mux := http.NewServeMux()
	nodb.RegisterRoutes(mux)
	req = httptest.NewRequest(http.MethodPut, "/api/v1/consents", strings.NewReader(whole))
	req.Header.Set("Authorization", "Bearer "+h.token)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable || !strings.Contains(rr.Body.String(), "M1E-9500") {
		t.Fatalf("no store: %d %s", rr.Code, rr.Body.String())
	}
}

// tenantOnlyVerifier is userauth.TenantVerifier's shape: a tenant and a subject, no device.
type tenantOnlyVerifier struct{ tenant uuid.UUID }

func (v tenantOnlyVerifier) Verify(context.Context, string) (auth.Claims, error) {
	return auth.Claims{TenantID: v.tenant, Subject: "user:1", ExpiresAt: time.Now().Add(time.Hour)}, nil
}
