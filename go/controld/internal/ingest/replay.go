package ingest

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/chproj"
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
func Replay(ctx context.Context, store s3land.Store, ins chproj.Inserter, sfx *sidefx.Sidefx,
	tenant querychoke.TenantID, from, to time.Time) (int, error) {
	if tenant.IsZero() {
		return 0, fmt.Errorf("ingest: replay requires a tenant")
	}
	tenantUUID := tenant.UUID()
	replayed := 0
	for day := from.UTC().Truncate(24 * time.Hour); !day.After(to.UTC()); day = day.Add(24 * time.Hour) {
		keys, err := store.List(ctx, s3land.IngestPrefix(tenantUUID, day))
		if err != nil {
			return replayed, err
		}
		for _, key := range keys {
			compressed, device, err := store.Get(ctx, key)
			if err != nil {
				return replayed, err
			}
			// Stage 5 re-run, same bounds as live ingest: a landing object
			// that no longer decodes within bounds is a defect to surface,
			// not to skip silently.
			decoded, err := decodeZstdBounded(compressed)
			if err != nil {
				return replayed, fmt.Errorf("ingest: replay %s: %w", key, err)
			}
			var batch m1pv1.Batch
			if err := proto.Unmarshal(decoded, &batch); err != nil {
				return replayed, fmt.Errorf("ingest: replay %s: %w", key, err)
			}
			// The device stamp rides the landing object's metadata (the
			// token that carried it is long gone); the landing key already
			// proves the tenant.
			// Stage 10 synchronously (replay is a batch job; the async pool
			// is for the request path), stage 11 via the sidefx pool.
			rows := chproj.RowsFromBatch(&batch, tenantUUID, device, day)
			if err := ins.InsertRows(ctx, chproj.Table, chproj.Columns, rows); err != nil {
				return replayed, fmt.Errorf("ingest: replay %s: %w", key, err)
			}
			if sfx != nil && device != uuid.Nil {
				sfx.Enqueue(tenant, device, day)
			}
			replayed++
		}
	}
	return replayed, nil
}
