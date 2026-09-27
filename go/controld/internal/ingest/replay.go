package ingest

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/chproj"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/registry"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/s3land"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/sidefx"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

// Replay is 05 §2.5: a worker entrypoint, NOT an HTTP route. It lists the
// ingest prefix for (tenant, date-range) and re-runs stages 5, 10, 11 from
// the landing objects — ClickHouse recovery/rebuild, the ADR-0001 re-key
// migration, and skip-and-retain re-projection all ride this one function.
// Idempotent end-to-end because every downstream write keys on event_id
// (including the derived Dropped-row ids); lexicographic key order ≈
// chronological replay order by the uuidv7 key scheme — a design property,
// not a coincidence.
//
// The quarantine prefix is NEVER replayed by this path (05 §2.3: the ingest
// prefix is replayed mechanically; a secret there would resurface forever).
func Replay(ctx context.Context, db registry.DB, store s3land.Store, ins chproj.Inserter, sfx *sidefx.Sidefx,
	tenant querychoke.TenantID, from, to time.Time) (int, error) {
	tenantUUID := tenant.UUID()
	replayed := 0
	err := walkLanded(ctx, store, tenant, from, to, func(key string, compressed []byte, device uuid.UUID, batch *m1pv1.Batch, landed time.Time) error {
		// Quarantined AFTER landing (Rescan under a newer ruleset): the
		// m1_quarantined_batches tombstone is the marker (07 §S3 layout) —
		// the twin itself dies at 30 d. The ingest object is immutable and
		// stays, but 05 §2.3's rule is that the quarantine prefix is never
		// replayed — so neither is a batch that now lives there. The twin's
		// existence is still honoured as a belt-and-braces OR for objects
		// that predate m1_080; Divergent counts too: anything quarantined
		// under this batch_id disqualifies it, whatever bytes the twin holds.
		batchID, _ := uuid.FromBytes(batch.GetBatchId())
		if marked, err := tombstoned(ctx, db, tenant, batchID); err != nil {
			return err
		} else if marked {
			log.Printf("ingest: replay %s: skipped, tombstoned (05 §2.3)", key)
			return nil
		}
		if q, err := store.Probe(ctx, s3land.QuarantineKey(tenantUUID, batchID), compressed); err != nil {
			return err
		} else if q != s3land.NotLanded {
			log.Printf("ingest: replay %s: skipped, quarantined after landing (05 §2.3)", key)
			return nil
		}
		// The device stamp rides the landing object's metadata (the
		// token that carried it is long gone); the landing key already
		// proves the tenant.
		// Stage 10 synchronously (replay is a batch job; the async pool
		// is for the request path), stage 11 via the sidefx pool.
		rows := chproj.RowsFromBatch(batch, tenantUUID, device, landed) // received_at reproduces the original receipt (ADR-0013)
		if err := ins.InsertRows(ctx, chproj.Table, chproj.Columns, rows); err != nil {
			return err
		}
		if sfx != nil && device != uuid.Nil && device != ServiceDevice {
			// The full stage-11 effect set replays too: pending leaves and
			// checkpoint seals re-derive from the landing objects — the
			// recovery story the in-memory pending-leaf set depends on.
			// BLOCKING enqueue: replay is the bulk path that fills the
			// queues, and a dropped effect here has no later replay to
			// recover it — backpressure, never drop (05 §2.5).
			if err := sfx.EnqueueBlocking(ctx, tenant, device, landed, sidefx.EffectsFromBatch(batch, landed)); err != nil {
				return err
			}
		}
		replayed++
		if replayed%100 == 0 {
			log.Printf("ingest: replay progress: %d objects (tenant %s)", replayed, tenantUUID)
		}
		return nil
	})
	return replayed, err
}

// Rescan is the ruleset-bump half of 05 §2.3 that the request path cannot
// reach: a batch that landed CLEAN under an older stage-7 edition and would
// be flagged today is re-acked as Duplicate by the ingest-key probe ABOVE the
// recorder on any re-POST (pipeline.go, deliberately — one landed batch,
// one response, forever). So the module's CURRENT edition (the bumped one —
// a ruleset bump is a new binary) is applied here, over the landing objects
// themselves, the way Replay re-runs stages 5/10/11: stage 7 re-runs, and a
// hit raises the same tenant alert the live path raises — through the same
// recorder, which a Module cannot be built without — and lands the object
// under the quarantine prefix, the marker Replay honours above. The ingest
// object is left where it is: landing objects are immutable by contract
// (05 §2.2), and the rows it already projected stay in the ledger — the alert
// names the batch; un-projecting is triage's job, not a scan's.
//
// A worker entrypoint like Replay, not a route. Idempotent: the alert's
// event_id derives from batch_id + M1E-7002 and the twin's Land is the
// conditional PUT, so a second pass over the same day re-derives,
// re-collapses and re-Duplicates instead of doubling anything.
func (m *Module) Rescan(ctx context.Context, tenant querychoke.TenantID, from, to time.Time) (int, error) {
	tenantUUID := tenant.UUID()
	flagged := 0
	err := walkLanded(ctx, m.store, tenant, from, to, func(key string, compressed []byte, device uuid.UUID, batch *m1pv1.Batch, _ time.Time) error {
		hits := m.scanner.Scan(batch)
		if len(hits) == 0 {
			return nil
		}
		batchID, _ := uuid.FromBytes(batch.GetBatchId())
		qkey := s3land.QuarantineKey(tenantUUID, batchID)
		if err := m.tombstone(ctx, tenant, batchID, qkey, len(batch.GetEvents()), m.now()); err != nil {
			return err
		}
		outcome, err := m.store.Land(ctx, qkey, compressed, tenantUUID, device)
		if err != nil {
			return err
		}
		if outcome == s3land.Divergent {
			return fmt.Errorf("quarantine twin holds different bytes for batch %s", batchID)
		}
		m.security.RecordQuarantine(tenantUUID, device, batchID, hitClasses(hits), m.now())
		quarantinesTotal.Inc()
		flagged++
		log.Printf("ingest: rescan %s: flagged under ruleset %s, quarantined (05 §2.3)", key, m.scanner.Version)
		return nil
	})
	return flagged, err
}

// walkLanded lists the ingest prefix for (tenant, date-range) and hands each
// landing object to visit already through stage 5 (same bounds as live
// ingest: an object that no longer decodes within bounds is a defect to
// surface, not to skip silently). Errors carry the key.
func walkLanded(ctx context.Context, store s3land.Store, tenant querychoke.TenantID, from, to time.Time,
	visit func(key string, compressed []byte, device uuid.UUID, batch *m1pv1.Batch, landed time.Time) error) error {
	if tenant.IsZero() {
		return fmt.Errorf("ingest: replay requires a tenant")
	}
	tenantUUID := tenant.UUID()
	for day := from.UTC().Truncate(24 * time.Hour); !day.After(to.UTC()); day = day.Add(24 * time.Hour) {
		keys, err := store.List(ctx, s3land.IngestPrefix(tenantUUID, day))
		if err != nil {
			return err
		}
		contributions, err := store.List(ctx, s3land.ContributionPrefix(tenantUUID, day))
		if err != nil {
			return err
		}
		keys = append(keys, contributions...)
		for _, key := range keys {
			compressed, device, landed, err := store.Get(ctx, key)
			if err != nil {
				return err
			}
			decoded, err := decodeZstdBounded(compressed)
			if err != nil {
				return fmt.Errorf("ingest: replay %s: %w", key, err)
			}
			var batch m1pv1.Batch
			if err := proto.Unmarshal(decoded, &batch); err != nil {
				return fmt.Errorf("ingest: replay %s: %w", key, err)
			}
			if landed.IsZero() {
				landed = day
			}
			if err := visit(key, compressed, device, &batch, landed); err != nil {
				return fmt.Errorf("ingest: replay %s: %w", key, err)
			}
		}
	}
	return nil
}
