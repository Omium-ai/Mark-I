package server

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
)

type stubVerifier struct{ claims auth.Claims }

func (s stubVerifier) Verify(context.Context, string) (auth.Claims, error) { return s.claims, nil }

// captureLog swaps the default slog handler for a buffer for the test's lifetime.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

func loggedMux(t *testing.T) http.Handler {
	t.Helper()
	tenant, device := uuid.MustParse("11111111-1111-4111-8111-111111111111"), uuid.MustParse("22222222-2222-4222-8222-222222222222")
	chain := Chain(stubVerifier{auth.Claims{TenantID: tenant, DeviceID: device}}, obs.Config{ServiceName: "t"}, nil)
	mux := http.NewServeMux()
	mux.Handle("GET /api/v1/sessions/{id}", chain(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})))
	mux.Handle("POST /m1p/v1/ingest", chain(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})))
	mux.HandleFunc("GET /healthz", func(http.ResponseWriter, *http.Request) {})
	return RequestLog(mux)
}

func do(h http.Handler, method, path string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(`{"secret_body":"never-logged"}`))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestRequestLogLineIsRedactedAndCarriesPrincipal(t *testing.T) {
	buf := captureLog(t)
	rec := do(loggedMux(t), http.MethodGet, "/api/v1/sessions/abc?token=qs-secret", map[string]string{
		"Authorization": "Bearer top-secret-token", "X-Request-Id": "req-42", "Cookie": "session=cookie-secret",
	})
	if rec.Code != http.StatusTeapot {
		t.Fatalf("status %d", rec.Code)
	}
	line := buf.String()
	if strings.Count(line, "\n") != 1 {
		t.Fatalf("want exactly one line, got %q", line)
	}
	for _, want := range []string{"method=GET", "route=\"GET /api/v1/sessions/{id}\"", "status=418", "duration_ms=",
		"request_id=req-42", "tenant=11111111-1111-4111-8111-111111111111", "device=22222222-2222-4222-8222-222222222222"} {
		if !strings.Contains(line, want) {
			t.Errorf("log line lacks %s: %s", want, line)
		}
	}
	for _, leak := range []string{"top-secret-token", "Authorization", "Bearer", "cookie-secret", "secret_body", "qs-secret", "/abc"} {
		if strings.Contains(line, leak) {
			t.Errorf("log line leaks %q: %s", leak, line)
		}
	}
	if got := rec.Header().Get("X-Request-Id"); got != "req-42" {
		t.Fatalf("request id not echoed: %q", got)
	}
}

func TestRequestLogMintsIDWhenInboundIsUnsafe(t *testing.T) {
	buf := captureLog(t)
	rec := do(loggedMux(t), http.MethodGet, "/api/v1/sessions/abc", map[string]string{
		"Authorization": "Bearer x", "X-Request-Id": "bad id\nwith newline",
	})
	got := rec.Header().Get("X-Request-Id")
	if _, err := uuid.Parse(got); err != nil {
		t.Fatalf("unsafe inbound id must be replaced by a uuid, got %q", got)
	}
	if !strings.Contains(buf.String(), "request_id="+got) || strings.Contains(buf.String(), "newline") {
		t.Fatalf("log line must carry the minted id and never the inbound one: %s", buf.String())
	}
}

func TestRequestLogUnauthenticatedNon2xxStillLogs(t *testing.T) {
	buf := captureLog(t)
	rec := do(loggedMux(t), http.MethodGet, "/api/v1/sessions/abc", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", rec.Code)
	}
	line := buf.String()
	if !strings.Contains(line, "status=401") || strings.Contains(line, "tenant=") {
		t.Fatalf("401 must log without a principal: %s", line)
	}
}

func TestRequestLogSamplesIngest2xxAndSkipsProbes(t *testing.T) {
	buf := captureLog(t)
	h := loggedMux(t)
	ingestSeen.Store(0)
	for range 100 {
		do(h, http.MethodPost, "/m1p/v1/ingest", map[string]string{"Authorization": "Bearer x"})
	}
	if n := strings.Count(buf.String(), "route=\"POST /m1p/v1/ingest\""); n != 2 {
		t.Fatalf("ingest 2xx must log 1 in 50: got %d lines of 100", n)
	}
	buf.Reset()
	for range 3 {
		do(h, http.MethodGet, "/healthz", nil)
	}
	if buf.Len() != 0 {
		t.Fatalf("healthz 2xx must not log: %s", buf.String())
	}
	do(h, http.MethodGet, "/nope", nil)
	if !strings.Contains(buf.String(), "status=404") {
		t.Fatalf("unmatched route must log its 404: %s", buf.String())
	}
}
