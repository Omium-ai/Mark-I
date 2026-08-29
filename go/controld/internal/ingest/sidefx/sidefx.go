// Package sidefx is stage 11 of the ingest pipeline: post-ack Postgres
// side-effects (05 §2.1). Same posture as chproj: never affects the ack,
// every write idempotent, recoverable from the landing object via replay
// (05 §2.5).
//
// C4 SCOPE vs the full stage-11 list ("checkpoint leaves, CoverageTransition
// rows, device last_seen_at"):
//   - device last_seen_at — implemented below.
//   - CoverageTransition rows — DEFERRED: coverage_transitions.receipt_id is
//     NOT NULL (migrations/m1_043_coverage.sql — every transition is
//     per-event receipted, C13), so the insert cannot exist before the
//     server-side receipt writer, which lands with the receipt row (13 §11
//     C6 wires the vendored receipt package + Go mirror). ApplyCoverage is
//     the seam it will fill.
//   - checkpoint pending leaves — DEFERRED for the same reason: no
//     pending-leaf table exists in the frozen migrations; the checkpoint
//     builder (a pgWorker path, 05 §7.3) ships with the receipt machinery.
//
// Both deferrals are recorded in the C4 build report.
package sidefx

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/pg"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
)

var sidefxSeconds = promauto.NewHistogram(prometheus.HistogramOpts{
	Name: "controld_ingest_sidefx_seconds",
	Help: "Postgres side-effect duration per landed batch (05 §2.1 stage 11)",
})

// DB is the WithTenant-shaped seam (05 §7.2); *pg.TenantDB satisfies it and
// unit tests fake it.
type DB interface {
	WithTenant(ctx context.Context, t querychoke.TenantID, fn func(pgx.Tx) error) error
}

// The seam stays honest at compile time: the production TenantDB IS the DB.
var _ DB = (*pg.TenantDB)(nil)

type job struct {
	tenant querychoke.TenantID
	device uuid.UUID
	seenAt time.Time
}

// Sidefx applies the per-batch side effects on a small async pool (stage 11
// rides "the same worker" tier as projection, 05 §2.1).
type Sidefx struct {
	db     DB
	queue  chan job
	wg     sync.WaitGroup
	closed sync.Once
}

func New(db DB, workers, depth int) *Sidefx {
	s := &Sidefx{db: db, queue: make(chan job, depth)}
	for i := 0; i < workers; i++ {
		s.wg.Add(1)
		go s.worker()
	}
	return s
}

// Enqueue schedules the batch's side effects. Non-blocking for the same
// reason as chproj.Enqueue: the ack already happened, and last_seen_at is
// re-derivable from any later batch.
func (s *Sidefx) Enqueue(tenant querychoke.TenantID, device uuid.UUID, seenAt time.Time) bool {
	select {
	case s.queue <- job{tenant: tenant, device: device, seenAt: seenAt}:
		return true
	default:
		return false
	}
}

func (s *Sidefx) worker() {
	defer s.wg.Done()
	for j := range s.queue {
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second) // §8.3 worker budget
		err := s.ApplyLastSeen(ctx, j.tenant, j.device, j.seenAt)
		cancel()
		if err != nil {
			// Post-ack: log and move on; the durable truth is in S3 and a
			// later batch (or replay) re-derives last_seen_at.
			log.Printf("sidefx: last_seen update failed (tenant %s): %v", j.tenant, err)
			continue
		}
		sidefxSeconds.Observe(time.Since(start).Seconds())
	}
}

// ApplyLastSeen stamps m1_devices.last_seen_at under the tenant GUC. GREATEST
// makes it idempotent AND replay-safe: re-applying an old batch can never
// move the timestamp backwards (05 §2.1: "all idempotent upserts").
func (s *Sidefx) ApplyLastSeen(ctx context.Context, tenant querychoke.TenantID, device uuid.UUID, seenAt time.Time) error {
	return s.db.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`UPDATE m1_devices
			    SET last_seen_at = GREATEST(COALESCE(last_seen_at, 'epoch'::timestamptz), $2)
			  WHERE id = $1`,
			device, seenAt)
		return err
	})
}

// Close drains and stops (05 §1.5 step 4).
func (s *Sidefx) Close() {
	s.closed.Do(func() { close(s.queue) })
	s.wg.Wait()
}
