// Package pg is the shared Postgres substrate: pool construction with the
// per-connection NOBYPASSRLS assertion, and the tenant-GUC discipline that
// makes "forgot the tenant" unwritable on the request path (05 §1.6, §7.2).
//
// ONE POOL, NOT TWO. 05 §1.1 opens a second pool as `controld_worker`
// (BYPASSRLS), but migrations/m1_060_roles_and_grants.sql:41-48 — the frozen
// DDL that actually runs — DISSOLVES controld_worker in favor of the single
// `mark1_federation_worker` role scoped to dprelease. None of the C4 modules
// is a sanctioned bypass path (05 §7.3's table), so no worker pool exists
// here; dprelease opens its own against the federation role in its row
// (WS-7). The 05-vs-m1_060 disagreement is recorded in the C4 build report.
package pg

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var errBypassRLSRole = errors.New(
	"pg: connection role has BYPASSRLS or SUPERUSER — refusing (R2 posture, 05 §7.2: " +
		"the RLS-inert-via-rds_superuser failure, made structurally unrepeatable)")

// Open builds the request-path pool. AfterConnect is NOT for tenant identity
// (connections are pooled and shared across tenants — a session-level tenant
// GUC would be a cross-tenant leak by connection reuse, 05 §7.2); it does
// connection hygiene plus the per-connection safety assertion, so the R2 boot
// refusal holds continuously, not just at boot.
func Open(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("pg: parse dsn: %w", err)
	}
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		var bypass bool
		if err := c.QueryRow(ctx,
			`SELECT rolbypassrls OR rolsuper FROM pg_roles WHERE rolname = current_user`,
		).Scan(&bypass); err != nil {
			return err
		}
		if bypass {
			return errBypassRLSRole
		}
		_, err := c.Exec(ctx, `SET application_name = 'controld'`)
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("pg: pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pg: ping: %w", err)
	}
	return pool, nil
}

// MustOpenApp is boot step 2 (05 §1.1). Unreachable store at boot ⇒ crashloop
// on purpose (05 §1.2): no degraded half-boot.
func MustOpenApp(ctx context.Context, dsn string) *pgxpool.Pool {
	pool, err := Open(ctx, dsn)
	if err != nil {
		log.Fatalf("pg: boot refusal (05 §1.2): %v", err)
	}
	return pool
}

// AssertNoBypassRLS is boot refusal R2 (05 §1.2), queried from pg_roles: the
// binary refuses to run as a role that would make its RLS decorative. The
// AfterConnect check above repeats this per-connection; the boot assertion
// exists so the refusal is visible as a crashloop, not a per-request error.
func AssertNoBypassRLS(ctx context.Context, pool *pgxpool.Pool) error {
	var bypass bool
	if err := pool.QueryRow(ctx,
		`SELECT rolbypassrls OR rolsuper FROM pg_roles WHERE rolname = current_user`,
	).Scan(&bypass); err != nil {
		return fmt.Errorf("pg: cannot read pg_roles: %w", err)
	}
	if bypass {
		return errBypassRLSRole
	}
	return nil
}

// MustAssertNoBypassRLS is boot step 3 (05 §1.1).
func MustAssertNoBypassRLS(ctx context.Context, pool *pgxpool.Pool) {
	if err := AssertNoBypassRLS(ctx, pool); err != nil {
		log.Fatalf("pg: boot refusal R2 (05 §1.2): %v", err)
	}
}
