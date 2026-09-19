// The hourly witness-head job (m1_003; 07 §"Witness heads"): every hour, per
// tenant, sign a statement of the current head and publish it OUTSIDE Omium's
// control, then record the completed publication. Publish FIRST, insert AFTER
// — every row records a publication that happened; a failed hour is a missing
// row, which the hourly cadence makes visible (m1_003 header). Idle chains
// are re-witnessed anyway: "the head is STILL X at hour H" is what makes a
// later rollback detectable.

package receipts

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
)

// WitnessDomainPrefix is m1_003's own domain: a witness statement can never
// be replayed as a receipt or vice versa.
const WitnessDomainPrefix = "mark1-witness-v1\x00"

var witnessPublished = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "controld_receipts_witness_published_total",
	Help: "Witness-head publications by outcome (m1_003; 05 §4.4 hourly cadence)",
}, []string{"outcome"})

// Destination is what a completed publication reports back — m1_003's two
// all-or-nothing destination column groups. At least one group must be whole
// or the INSERT fails ck_m1_wh_some_destination, which is correct: a witness
// to nowhere is a log line, not a control.
type Destination struct {
	LogBackend        *string
	LogEntryIndex     *int64
	LogInclusionProof *string
	BucketURI         *string
	ETag              *string
	RetainUntil       *time.Time
}

// Publisher writes the signed statement somewhere Omium cannot edit (the
// transparency log and/or the customer's object-lock bucket). An error means
// NOT published — the job inserts nothing and the hour goes visibly missing.
type Publisher interface {
	Publish(ctx context.Context, tenant uuid.UUID, statement, signature []byte, keyID string) (Destination, error)
}

// TenantSource yields the tenants to witness. It is a seam because
// m1_tenants is FORCE-RLS'd (m1_001) and controld_app holds no sanctioned
// cross-tenant enumeration path (05 §7.3's pgWorker table does not list this
// job; m1_060 dissolved controld_worker) — the list must come from outside
// the tenant-scoped pool. ponytail: env-configured tenant list at the cmd
// seam; upgrade path is a sanctioned enumeration surface (a future
// migration's SECURITY DEFINER lister or the federation worker role).
type TenantSource func(ctx context.Context) ([]uuid.UUID, error)

// StaticTenants adapts a fixed list (cmd wiring, tests).
func StaticTenants(ids []uuid.UUID) TenantSource {
	return func(context.Context) ([]uuid.UUID, error) { return ids, nil }
}

type WitnessJob struct {
	db       DB
	signer   *Signer
	pub      Publisher
	tenants  TenantSource
	interval time.Duration
	now      func() time.Time
	tick     <-chan time.Time // nil ⇒ Run owns a real time.Ticker at interval
}

// NewWitnessJob builds the hourly loop. interval <= 0 defaults to the
// m1_003-stated hour; it is not otherwise configurable in production — the
// cadence is part of the ≤1 h rewrite-detection bound (10 §R-13).
func NewWitnessJob(db DB, signer *Signer, pub Publisher, tenants TenantSource, interval time.Duration) *WitnessJob {
	if interval <= 0 {
		interval = time.Hour
	}
	return &WitnessJob{db: db, signer: signer, pub: pub, tenants: tenants, interval: interval, now: time.Now}
}

// Clock injects the job's time source and tick channel, so a test can drive
// two "hours" through Run in milliseconds and watch the real publisher fire
// twice — the cadence clause of FR-SPINE-019 observed as elapsed (fake) time
// rather than interval arithmetic. Production never calls it: the real
// ticker and time.Now are the defaults. Call before Run.
func (j *WitnessJob) Clock(now func() time.Time, tick <-chan time.Time) {
	j.now, j.tick = now, tick
}

// Run ticks until ctx ends. Singleton discipline rides inside RunOnce (the
// per-tenant advisory xact lock + the freshness check), so extra replicas
// running this loop skip work instead of double-publishing (05 §8.1).
func (j *WitnessJob) Run(ctx context.Context) {
	if ids, err := j.tenants(ctx); err == nil {
		log.Printf("receipts: witness started: %d tenants, publisher %v, every %s (m1_003)", len(ids), j.pub, j.interval)
	}
	tick := j.tick
	if tick == nil {
		t := time.NewTicker(j.interval)
		defer t.Stop()
		tick = t.C
	}
	for {
		if err := j.RunOnce(ctx); err != nil {
			log.Printf("receipts: witness tick failed: %v", err) // next tick catches up (05 §1.5)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick:
		}
	}
}

// RunOnce witnesses every tenant whose last witness row is older than the
// interval. Per-tenant failures are logged and counted, never fatal to the
// tick: one tenant's broken bucket must not silence every other tenant's
// witness.
func (j *WitnessJob) RunOnce(ctx context.Context) error {
	ids, err := j.tenants(ctx)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := j.witnessTenant(ctx, id); err != nil {
			witnessPublished.WithLabelValues("error").Inc()
			log.Printf("receipts: witness for tenant %s failed: %v", id, err)
		}
	}
	return nil
}

var errSkipWitness = errors.New("receipts: witness skipped")

func (j *WitnessJob) witnessTenant(ctx context.Context, id uuid.UUID) error {
	tenant, err := querychoke.FromClaims(auth.Claims{TenantID: id})
	if err != nil {
		return err
	}
	err = j.db.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		// Election by advisory xact lock (05 §8.1's singleton rule): the
		// loser of a concurrent tick skips — a skipped tick is caught up by
		// the next one, never doubled.
		var got bool
		if err := tx.QueryRow(ctx,
			`SELECT pg_try_advisory_xact_lock(hashtextextended('m1_witness_' || $1::text, 0))`,
			id).Scan(&got); err != nil {
			return err
		}
		if !got {
			return errSkipWitness
		}
		// Idempotent-resumable cursor = the table itself (05 §1.5): a fresh
		// row within the interval means this hour is already witnessed.
		var last *time.Time
		if err := tx.QueryRow(ctx,
			`SELECT max(witnessed_at) FROM m1_witness_heads`).Scan(&last); err != nil {
			return err
		}
		if last != nil && j.now().Sub(*last) < j.interval {
			return errSkipWitness
		}
		var seq, ckpt int64
		var hash []byte
		switch err := tx.QueryRow(ctx,
			`SELECT seq, head_hash, checkpoint_seq FROM m1_receipt_chain_head WHERE tenant_id = $1`,
			id).Scan(&seq, &hash, &ckpt); {
		case errors.Is(err, pgx.ErrNoRows):
			return errSkipWitness // no chain yet
		case err != nil:
			return err
		}
		if seq == 0 {
			return errSkipWitness // an empty chain has nothing to witness (m1_003 CHECK)
		}

		witnessedAt := j.now().UTC().Truncate(time.Second)
		// Exactly m1_003's five statement fields, canonicalised with the one
		// serialisation discipline the whole spine uses.
		statement, err := CanonicalJSON(map[string]any{
			"tenant_id":      id.String(),
			"seq":            seq,
			"hash":           hex.EncodeToString(hash),
			"checkpoint_seq": ckpt,
			"witnessed_at":   witnessedAt.Format(time.RFC3339),
		})
		if err != nil {
			return err
		}
		sig, err := j.signer.Sign(append([]byte(WitnessDomainPrefix), statement...))
		if err != nil {
			return err
		}

		// Publish FIRST — the row below records a COMPLETED publication.
		// Publishing inside the tx is deliberate: a crash between publish and
		// insert loses only the row, and the external copy (the evidence)
		// survives; the next tick re-publishes and re-inserts, which is
		// harmless duplication of evidence, never loss.
		dest, err := j.pub.Publish(ctx, id, []byte(statement), sig, j.signer.KeyID())
		if err != nil {
			return fmt.Errorf("publish: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO m1_witness_heads
			  (tenant_id, witnessed_seq, witnessed_hash, witnessed_checkpoint_seq, witnessed_at,
			   statement, server_key_id, server_signature,
			   log_backend, log_entry_index, log_inclusion_proof,
			   object_bucket_uri, object_etag, object_retain_until)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
			id, seq, hash, ckpt, witnessedAt, statement, j.signer.KeyID(), sig,
			dest.LogBackend, dest.LogEntryIndex, dest.LogInclusionProof,
			dest.BucketURI, dest.ETag, dest.RetainUntil); err != nil {
			return err
		}
		witnessPublished.WithLabelValues("published").Inc()
		return nil
	})
	if errors.Is(err, errSkipWitness) {
		witnessPublished.WithLabelValues("skipped").Inc()
		return nil
	}
	return err
}
