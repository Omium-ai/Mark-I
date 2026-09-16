package ingest

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/registry"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/s3land"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/sidefx"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/receipts"
)

// Founder ruling 2026-09-16: 30 days, then delete, receipted (07 §S3 layout; 05 §2.3 step 4). No knob.
const (
	QuarantineRetention = 30 * 24 * time.Hour
	sweepEvery          = 24 * time.Hour
)

var (
	tombstoneFailures = promauto.NewCounter(prometheus.CounterOpts{
		Name: "controld_ingest_quarantine_tombstone_failures_total",
		Help: "Flagged batches refused (503) because the m1_quarantined_batches marker could not be written (05 §2.3)",
	})
	sweepOutcomes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "controld_ingest_quarantine_sweep_total",
		Help: "Cloud quarantine sweep outcomes per tombstone: retention_30d, lifecycle_backstop, error (m1_080)",
	}, []string{"outcome"})
)

var errNoTombstoneStore = errors.New("ingest: quarantine tombstone store unwired (Deps.DB); flagged batch refused")

// tombstone marks the batch never-replayable BEFORE its twin lands: a marker without an object ages out under the
// sweep's backstop receipt, an object without a marker would replay (05 §2.3). ON CONFLICT: the 08 §2.5 retry re-POSTs.
func (m *Module) tombstone(ctx context.Context, tenant querychoke.TenantID, batchID uuid.UUID, key string, events int, at time.Time) error {
	if m.db == nil {
		return errNoTombstoneStore
	}
	return m.db.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO m1_quarantined_batches (tenant_id, batch_id, quarantined_at, object_key, event_count)
			VALUES ($1, $2, $3, $4, $5) ON CONFLICT (tenant_id, batch_id) DO NOTHING`,
			tenant.UUID(), batchID, at.UTC(), key, events)
		return err
	})
}

// tombstoned is Replay's never-replay read (07: the marker is the row). nil db keeps only the object probe — the
// belt-and-braces for twins that predate m1_080, which Replay ORs in either way.
func tombstoned(ctx context.Context, db registry.DB, tenant querychoke.TenantID, batchID uuid.UUID) (bool, error) {
	if db == nil {
		return false, nil
	}
	found := false
	err := db.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		var one int
		scanErr := tx.QueryRow(ctx, `SELECT 1 FROM m1_quarantined_batches WHERE batch_id = $1`, batchID).Scan(&one)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return nil
		}
		found = scanErr == nil
		return scanErr
	})
	return found, err
}

// QuarantineSweep is the daily cloud half of the ruling: every tombstone at or past 30 days loses its object and gains
// a quarantine_deletion receipt, the receipt and the tombstone close in ONE transaction (05 §2.3 step 4).
type QuarantineSweep struct {
	db      registry.DB
	store   s3land.Store
	chain   *receipts.Store
	tenants receipts.TenantSource
	now     func() time.Time
	tick    <-chan time.Time
}

func NewQuarantineSweep(db registry.DB, store s3land.Store, chain *receipts.Store, tenants receipts.TenantSource) *QuarantineSweep {
	return &QuarantineSweep{db: db, store: store, chain: chain, tenants: tenants, now: time.Now}
}

// Clock injects the time source and tick channel (the WitnessJob seam); production keeps the defaults.
func (j *QuarantineSweep) Clock(now func() time.Time, tick <-chan time.Time) {
	j.now, j.tick = now, tick
}

// Run sweeps at entry and every 24 h until ctx ends.
func (j *QuarantineSweep) Run(ctx context.Context) {
	tick := j.tick
	if tick == nil {
		t := time.NewTicker(sweepEvery)
		defer t.Stop()
		tick = t.C
	}
	for {
		if err := j.RunOnce(ctx); err != nil {
			log.Printf("ingest: quarantine sweep tick failed: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick:
		}
	}
}

// RunOnce sweeps every tenant; one tenant's failure is logged and counted, never fatal to the others.
func (j *QuarantineSweep) RunOnce(ctx context.Context) error {
	ids, err := j.tenants(ctx)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if _, err := j.SweepTenant(ctx, id); err != nil {
			sweepOutcomes.WithLabelValues("error").Inc()
			log.Printf("ingest: quarantine sweep for tenant %s failed: %v", id, err)
		}
	}
	return nil
}

type expiredTombstone struct {
	batchID       uuid.UUID
	key           string
	quarantinedAt time.Time
	events        int
}

// SweepTenant deletes and receipts every expired tombstone for one tenant; returns how many it closed.
func (j *QuarantineSweep) SweepTenant(ctx context.Context, id uuid.UUID) (int, error) {
	tenant, err := querychoke.FromClaims(auth.Claims{TenantID: id})
	if err != nil {
		return 0, err
	}
	now := j.now()
	var due []expiredTombstone
	err = j.db.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT batch_id, object_key, quarantined_at, event_count FROM m1_quarantined_batches
			 WHERE quarantined_at <= $1 AND deleted_at IS NULL ORDER BY quarantined_at`, now.Add(-QuarantineRetention))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e expiredTombstone
			if err := rows.Scan(&e.batchID, &e.key, &e.quarantinedAt, &e.events); err != nil {
				return err
			}
			due = append(due, e)
		}
		return rows.Err()
	})
	if err != nil {
		return 0, err
	}
	closed := 0
	for _, e := range due {
		reason, err := j.deleteObject(ctx, e.key)
		if err != nil {
			sweepOutcomes.WithLabelValues("error").Inc()
			log.Printf("ingest: quarantine sweep: %s not deleted, next sweep retries: %v", e.key, err)
			continue
		}
		if err := j.receipt(ctx, tenant, e, reason, now); err != nil {
			sweepOutcomes.WithLabelValues("error").Inc()
			log.Printf("ingest: quarantine sweep: %s deleted but not receipted, next sweep names the backstop: %v", e.key, err)
			continue
		}
		sweepOutcomes.WithLabelValues(reason).Inc()
		closed++
	}
	return closed, nil
}

// deleteObject is delete-first so the receipt describes an observed state: an object the 32 d lifecycle (or a crashed
// earlier pass) already removed is receipted as lifecycle_backstop, not as a deletion that did not happen here.
func (j *QuarantineSweep) deleteObject(ctx context.Context, key string) (string, error) {
	out, err := j.store.Probe(ctx, key, nil)
	if err != nil {
		return "", err
	}
	if out == s3land.NotLanded {
		return "lifecycle_backstop", nil
	}
	if err := j.store.Delete(ctx, key); err != nil {
		return "", err
	}
	return sidefx.DeletionReason, nil
}

// receipt appends the quarantine_deletion record and closes the tombstone in one transaction; the FOR UPDATE on the
// still-open row is what keeps two replicas from receipting one deletion twice.
func (j *QuarantineSweep) receipt(ctx context.Context, tenant querychoke.TenantID, e expiredTombstone, reason string, now time.Time) error {
	return j.db.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		var one int
		switch err := tx.QueryRow(ctx,
			`SELECT 1 FROM m1_quarantined_batches WHERE batch_id = $1 AND deleted_at IS NULL FOR UPDATE`, e.batchID).Scan(&one); {
		case errors.Is(err, pgx.ErrNoRows):
			return nil
		case err != nil:
			return err
		}
		rec, err := j.chain.AppendServerRecordTx(ctx, tx, tenant, receipts.ServerRecord{
			RecordType: "quarantine_deletion",
			SubjectID:  e.batchID,
			IssuedAt:   now,
			Fields: map[string]any{
				"origin": "cloud", "reason": reason, "event_count": e.events,
				"quarantined_at": sidefx.MillisString(e.quarantinedAt), "deleted_at": sidefx.MillisString(now),
			},
			IdempotencyKey: "cloud:" + e.batchID.String(),
		})
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx,
			`UPDATE m1_quarantined_batches SET deleted_at = $2, receipt_id = $3 WHERE batch_id = $1 AND deleted_at IS NULL`,
			e.batchID, now.UTC(), rec.ReceiptID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("tombstone %s did not close", e.batchID)
		}
		return nil
	})
}
