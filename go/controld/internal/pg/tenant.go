package pg

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
)

// TenantDB is the ONLY shape modules receive the app pool in (05 §7.2 rule b):
// the raw pool is not exported to request code, so "forgot the GUC" is not
// writable on the request path. Its single query method is WithTenant-shaped.
type TenantDB struct {
	pool *pgxpool.Pool
}

func NewTenantDB(pool *pgxpool.Pool) *TenantDB { return &TenantDB{pool: pool} }

// WithTenant is the Go analogue of the estate's asyncpg set_local_tenant
// (05 §7.2): set_config(..., true) is TRANSACTION-LOCAL, so the GUC rolls
// back with the tx and can never outlive it onto a reused pooled connection.
// It takes the validated TenantID newtype (05 §7.2 rule a) — the GUC value
// comes from verified claims via the type system, never from a string a
// handler assembled. Under the RLS policies' NULLIF form, an unset GUC
// matches NOTHING (05 §7.1), so even a bypass of this helper reads zero rows,
// never all rows — that is the second wall; this is the first.
func (db *TenantDB) WithTenant(ctx context.Context, t querychoke.TenantID,
	fn func(pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, db.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`SELECT set_config('app.tenant_id', $1, true)`, t.String()); err != nil {
			return err
		}
		return fn(tx)
	})
}

// Ready is the ingest readiness contributor's Postgres half (05 §1.4).
func (db *TenantDB) Ready(ctx context.Context) error { return db.pool.Ping(ctx) }
