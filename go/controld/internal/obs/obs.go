// Package obs provides the canonical Omium observability helpers for Go services:
//   - omium_http_* Prometheus metrics (same names/labels as the Python lib)
//   - net/http middleware for HTTP ingress
//   - A metrics HTTP server that serves /metrics, /health, and /healthz
//
// VENDORED from Omium-platform/core-services/policy-engine/internal/obs/obs.go
// per 13 §1 ("reuse is by vendoring ... with the source path recorded in the
// vendored file's header"). NOT byte-identical, one deletion: the estate
// file's omium_grpc_* metric families and gRPC interceptors are removed,
// because 13 §7.3's no-grpc depguard rule denies google.golang.org/grpc
// repo-wide ("No gRPC in Mark 1 — M1P is plain HTTPS") and 13 §3.4's pinned
// go.mod carries no grpc module. 13 §3.2's "byte-identical" is unsatisfiable
// alongside those two — the C4 build report records the contradiction. The
// HTTP surface below is byte-identical to the estate file.
//
// Prometheus only — zero OpenTelemetry (05 §1.7, CON-005/ADR-0005). Scraping
// is by pod annotation (prometheus.io/port: "9092"); no ServiceMonitor.
package obs

import (
	"fmt"
	"log"
	"net/http"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Config drives instrumentation for a single process.
type Config struct {
	// ServiceName is the logical service ("controld"). Becomes the
	// `service` label on every metric.
	ServiceName string
	// MetricsPort is the TCP port for the /metrics HTTP server. Empty = do not start.
	MetricsPort string
}

var (
	httpRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "omium_http_requests_total",
		Help: "Total HTTP requests handled by the service",
	}, []string{"service", "method", "path", "status"})

	httpDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "omium_http_request_duration_seconds",
		Help:    "HTTP request duration in seconds",
		Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0},
	}, []string{"service", "method", "path"})

	httpInFlight = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "omium_http_in_flight",
		Help: "HTTP requests currently being handled",
	}, []string{"service"})

	httpExceptions = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "omium_http_exceptions_total",
		Help: "Unhandled exceptions / panics during HTTP request handling",
	}, []string{"service", "method", "path", "exc_type"})
)

// statusRecorder lets the middleware observe the final HTTP status code.
type statusRecorder struct {
	http.ResponseWriter
	code    int
	written bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.written {
		s.code = code
		s.written = true
	}
	s.ResponseWriter.WriteHeader(code)
}

// Unwrap exposes the wrapped writer to http.ResponseController, which is how
// a handler reaches Flush and SetWriteDeadline through a wrapper. Without it
// the SSE stream in policydist cannot flush (every event sits in the bufio
// writer) and cannot clear the server's 30 s WriteTimeout (every stream dies
// at 30 s). ADDITION to the estate-vendored file, noted because this file's
// header claims the HTTP surface is byte-identical to it; the two Write paths
// above are unchanged.
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.written {
		s.code = http.StatusOK
		s.written = true
	}
	return s.ResponseWriter.Write(b)
}

// HTTPMiddleware wraps an http.Handler with request counting, duration, in-flight
// gauging, and panic recovery. `pathTemplate` is optional — callers that know
// their routes (e.g. chi) can pass a fn returning the route template to prevent
// label cardinality blow-up. Pass nil to fall back to r.URL.Path.
func (c Config) HTTPMiddleware(pathTemplate func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			httpInFlight.WithLabelValues(c.ServiceName).Inc()
			defer httpInFlight.WithLabelValues(c.ServiceName).Dec()

			rec := &statusRecorder{ResponseWriter: w, code: http.StatusOK}

			path := r.URL.Path
			defer func() {
				if pathTemplate != nil {
					if tpl := pathTemplate(r); tpl != "" {
						path = tpl
					}
				}
				if rv := recover(); rv != nil {
					excType := fmt.Sprintf("%T", rv)
					httpExceptions.WithLabelValues(c.ServiceName, r.Method, path, excType).Inc()
					log.Printf("[obs] panic in %s %s: %v\n%s", r.Method, path, rv, debug.Stack())
					http.Error(rec, "internal server error", http.StatusInternalServerError)
					rec.code = http.StatusInternalServerError
				}
				httpRequests.WithLabelValues(
					c.ServiceName, r.Method, path, strconv.Itoa(rec.code),
				).Inc()
				httpDuration.WithLabelValues(c.ServiceName, r.Method, path).
					Observe(time.Since(start).Seconds())
			}()

			next.ServeHTTP(rec, r)
		})
	}
}

// StartMetricsServer starts a tiny HTTP server exposing /metrics and /health.
// Extra handlers can be registered via `extra` (e.g. a custom /ready probe).
// Runs in a goroutine and logs fatal errors; returns immediately.
func (c Config) StartMetricsServer(extra map[string]http.Handler) {
	if c.MetricsPort == "" {
		log.Println("[obs] MetricsPort empty — skipping metrics server")
		return
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	healthz := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"healthy","service":"` + c.ServiceName + `"}`))
	}
	mux.HandleFunc("/health", healthz)
	mux.HandleFunc("/healthz", healthz)
	for path, h := range extra {
		mux.Handle(path, h)
	}

	addr := fmt.Sprintf(":%s", c.MetricsPort)
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		log.Printf("[obs] metrics server listening on %s", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[obs] metrics server error: %v", err)
		}
	}()
}
