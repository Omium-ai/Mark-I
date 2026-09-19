// Package server owns the shared mux, the middleware chain, and the
// health/readiness/drain contracts (05 §1.4–1.5). Modules register routes
// under their own path prefix and contribute their own readiness probe
// (05 §0.2) — the server never knows what a module needs to be ready, only
// whether it says so.
package server

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"
)

// Module is what Register accepts: routes plus a readiness contributor.
type Module interface {
	Name() string
	// RegisterRoutes mounts the module's handlers on the shared mux.
	RegisterRoutes(mux *http.ServeMux)
	// Ready probes the dependencies THIS module needs to honor its own
	// contract (05 §1.4) — e.g. ingest probes Postgres + S3 and deliberately
	// NOT ClickHouse, because its ack promise is S3-durability.
	Ready(ctx context.Context) error
}

// Drainer is an OPTIONAL module capability, checked at shutdown. It exists for
// long-lived responses: http.Server.Shutdown waits for connections to go idle,
// and an SSE stream never does, so without this a deploy burns the whole drain
// budget before killing the streams anyway. 05 §1.5 step 2 names the required
// behaviour for policydist — "close SSE policy streams with a final
// `event: ping` and connection close" — and this is where it is invoked.
type Drainer interface {
	Drain()
}

// Server is the process's single HTTP front (05 §0.1: one deployment surface).
type Server struct {
	mux      *http.ServeMux
	modules  []Module
	draining atomic.Bool
	drain    time.Duration
	addr     string
}

func New(port string, drainTimeout time.Duration) *Server {
	s := &Server{mux: http.NewServeMux(), drain: drainTimeout, addr: ":" + port}
	// /healthz — process liveness: 200 once the listener is up; only
	// deadlock/panic takes it down (05 §1.4). Unauthenticated by design
	// (08 §3.5).
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"healthy","service":"controld"}`))
	})
	s.mux.Handle("GET /readyz", s.ReadyHandler())
	return s
}

func (s *Server) Register(mods ...Module) {
	for _, m := range mods {
		m.RegisterRoutes(s.mux)
		s.modules = append(s.modules, m)
	}
}

// ReadyHandler ANDs the per-module contributors (05 §1.4). During drain it is
// 503 unconditionally — step 1 of shutdown flips it before anything else so
// the LB stops routing (05 §1.5).
func (s *Server) ReadyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.draining.Load() {
			http.Error(w, `{"ready":false,"reason":"draining"}`, http.StatusServiceUnavailable)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		for _, m := range s.modules {
			if err := m.Ready(ctx); err != nil {
				http.Error(w, `{"ready":false,"module":"`+m.Name()+`"}`, http.StatusServiceUnavailable)
				return
			}
		}
		_, _ = w.Write([]byte(`{"ready":true}`))
	})
}

// Run serves until SIGTERM/SIGINT, then drains (05 §1.5): flip readiness,
// stop accepting, let in-flight requests complete under the drain timeout
// (default 25 s < the pod's 30 s grace). The one request class that matters
// is an ingest batch mid-pipeline: the S3 PUT either completes (ack sent) or
// it doesn't (no ack, edge retries under 08 §2.5) — there is no state in
// which a batch is half-acked, so a deploy costs latency, never data.
func (s *Server) Run(ctx context.Context) error {
	srv := &http.Server{
		Addr:    s.addr,
		Handler: RequestLog(s.mux),
		// The §8.3 inbound timeouts: read header 5 s, full request 60 s,
		// response write 30 s.
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		log.Printf("controld listening on %s", s.addr)
		errCh <- srv.ListenAndServe()
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	select {
	case err := <-errCh:
		return err // listener failure is boot refusal R7 territory: die loudly
	case <-sig:
	case <-ctx.Done():
	}

	s.draining.Store(true)
	// Readiness is 503 from the line above; long-lived responses get told to
	// end before Shutdown starts waiting on them (05 §1.5 steps 1–2).
	for _, m := range s.modules {
		if d, ok := m.(Drainer); ok {
			d.Drain()
		}
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), s.drain)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return nil
}
