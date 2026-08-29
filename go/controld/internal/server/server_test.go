package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type stubModule struct {
	name string
	err  error
}

func (s stubModule) Name() string                  { return s.name }
func (s stubModule) RegisterRoutes(*http.ServeMux) {}
func (s stubModule) Ready(context.Context) error   { return s.err }

func ready(t *testing.T, s *Server) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	s.ReadyHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	return rec
}

// /readyz is the AND of per-module contributors (05 §1.4), and drain step 1
// flips it to 503 before anything else (05 §1.5).
func TestReadyzAndsContributorsAndDrainFlips(t *testing.T) {
	s := New("0", time.Second)
	s.Register(stubModule{name: "ok"})
	if rec := ready(t, s); rec.Code != http.StatusOK {
		t.Fatalf("healthy modules: want 200, got %d", rec.Code)
	}

	s2 := New("0", time.Second)
	s2.Register(stubModule{name: "ok"}, stubModule{name: "ingest", err: errors.New("s3 down")})
	rec := ready(t, s2)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("one failing contributor must fail readiness: %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "ingest") {
		t.Fatalf("readiness must name the failing module: %s", rec.Body.String())
	}

	s.draining.Store(true)
	if rec := ready(t, s); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("draining server must be unready: %d", rec.Code)
	}
}
