package server

import (
	"context"
	"log/slog"
	"net/http"
	"regexp"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// principal is the per-request slot Stamp fills after auth; it lives in the request context so the mux-level logger can read what an inner middleware learned.
type principal struct{ tenant, device uuid.UUID }

type principalKey struct{}

// Stamp records the authenticated principal on the request's log line; a no-op outside RequestLog.
func Stamp(ctx context.Context, tenant, device uuid.UUID) {
	if p, ok := ctx.Value(principalKey{}).(*principal); ok {
		p.tenant, p.device = tenant, device
	}
}

// requestIDOK bounds an inbound X-Request-Id so a caller cannot inject log-line noise; anything else is replaced.
var requestIDOK = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// ingestSeen drives the 1-in-50 sample of ingest 2xx lines; every other route logs every request.
var ingestSeen atomic.Uint64

type logRecorder struct {
	http.ResponseWriter
	code int
}

func (l *logRecorder) WriteHeader(c int) {
	if l.code == 0 {
		l.code = c
	}
	l.ResponseWriter.WriteHeader(c)
}

func (l *logRecorder) Write(b []byte) (int, error) {
	if l.code == 0 {
		l.code = http.StatusOK
	}
	return l.ResponseWriter.Write(b)
}

// Unwrap keeps http.ResponseController (policydist's SSE flush) working through the wrapper.
func (l *logRecorder) Unwrap() http.ResponseWriter { return l.ResponseWriter }

// RequestLog is the one mux-level access log: method, route pattern, status, duration, principal, request id. Never headers, bodies or tokens.
func RequestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		id := r.Header.Get("X-Request-Id")
		if !requestIDOK.MatchString(id) {
			id = uuid.NewString()
		}
		w.Header().Set("X-Request-Id", id)
		p := &principal{}
		rec := &logRecorder{ResponseWriter: w}
		r = r.WithContext(context.WithValue(r.Context(), principalKey{}, p))
		next.ServeHTTP(rec, r)
		if rec.code == 0 {
			rec.code = http.StatusOK
		}
		if !shouldLog(r.Pattern, rec.code) {
			return
		}
		attrs := []any{"method", r.Method, "route", r.Pattern, "status", rec.code,
			"duration_ms", time.Since(start).Milliseconds(), "request_id", id}
		if p.tenant != uuid.Nil {
			attrs = append(attrs, "tenant", p.tenant.String())
		}
		if p.device != uuid.Nil {
			attrs = append(attrs, "device", p.device.String())
		}
		slog.Info("http", attrs...)
	})
}

func shouldLog(pattern string, code int) bool {
	if code < 200 || code > 299 {
		return true
	}
	switch pattern {
	case "GET /healthz", "GET /readyz":
		return false
	case "POST /m1p/v1/ingest", "POST /internal/v1/ingest/service":
		return ingestSeen.Add(1)%50 == 1
	}
	return true
}
