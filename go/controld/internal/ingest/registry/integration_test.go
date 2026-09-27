//go:build integration

package registry_test

// DSN-gated Postgres integration (house style, 12 / 05 §7.5): a scratch
// database gets the real migrations, a NOBYPASSRLS login role stands in for
// controld_app, and the tests prove m1_063 end to end — the window semantics
// its header states, the RLS wall between tenants (negative direction), and
// the SELECT-only grant.
//
// Gate: M1_MIGRATE_PG_DSN (privileged DSN for scratch setup). Absent ⇒ skip,
// unless M1_REQUIRE_STORES=1 ⇒ fail.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/registry"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/pg"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
)

func pgDSN(t *testing.T) string {
	t.Helper()
	v := os.Getenv("M1_MIGRATE_PG_DSN")
	if v == "" {
		if os.Getenv("M1_REQUIRE_STORES") == "1" {
			t.Fatal("M1_MIGRATE_PG_DSN required (M1_REQUIRE_STORES=1) but unset")
		}
		t.Skip("M1_MIGRATE_PG_DSN unset; skipping Postgres-backed test")
	}
	return v
}

type harness struct {
	admin        *pgx.Conn // privileged, connected to the scratch db
	db           *pg.TenantDB
	tenantA      querychoke.TenantID
	tenantB      querychoke.TenantID
	migrationDir string
	appPoolQuery func(ctx context.Context, sql string, args ...any) (int64, error)
}

func setup(t *testing.T) *harness {
	t.Helper()
	ctx := context.Background()
	dsn := pgDSN(t)

	adminCfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, err := pgx.ConnectConfig(ctx, adminCfg)
	if err != nil {
		t.Fatalf("cannot reach test Postgres: %v", err)
	}
	scratch := fmt.Sprintf("controld_registry_it_%d", time.Now().UnixNano())
	role := fmt.Sprintf("registryapp_%d", time.Now().UnixNano())
	if _, err := bootstrap.Exec(ctx, "CREATE DATABASE "+scratch); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cctx := context.Background()
		_, _ = bootstrap.Exec(cctx, "DROP DATABASE IF EXISTS "+scratch+" WITH (FORCE)")
		_, _ = bootstrap.Exec(cctx, "DROP ROLE IF EXISTS "+role)
		_ = bootstrap.Close(cctx)
	})

	scratchCfg := adminCfg.Copy()
	scratchCfg.Database = scratch
	admin, err := pgx.ConnectConfig(ctx, scratchCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })

	// The real migrations, in filename order, under the cluster advisory lock
	// the sibling harnesses hold for the same reason (m1_060 touches global
	// role tuples).
	if _, err := bootstrap.Exec(ctx, `SELECT pg_advisory_lock(7231060)`); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join("..", "..", "..", "..", "..", "migrations")
	files, err := filepath.Glob(filepath.Join(dir, "m1_[0-9]*.sql"))
	if err != nil || len(files) == 0 {
		t.Fatalf("migrations not found: %v (%d)", err, len(files))
	}
	sort.Strings(files)
	for _, f := range files {
		if strings.Contains(filepath.Base(f), "m1_ch_") {
			continue
		}
		sql, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Exec(ctx, string(sql)); err != nil {
			t.Fatalf("migration %s: %v", filepath.Base(f), err)
		}
	}
	_, err = admin.Exec(ctx, fmt.Sprintf(
		"CREATE ROLE %s LOGIN PASSWORD 'registrytest' NOBYPASSRLS NOSUPERUSER; GRANT controld_app TO %s", role, role))
	if _, uerr := bootstrap.Exec(ctx, `SELECT pg_advisory_unlock(7231060)`); uerr != nil {
		t.Fatal(uerr)
	}
	if err != nil {
		t.Fatal(err)
	}

	var orgID uuid.UUID
	if err := admin.QueryRow(ctx,
		`INSERT INTO m1_organizations (name, primary_domain) VALUES ('registry-it', 'registry-it.example') RETURNING id`,
	).Scan(&orgID); err != nil {
		t.Fatal(err)
	}
	mkTenant := func(name string) querychoke.TenantID {
		var tid uuid.UUID
		if err := admin.QueryRow(ctx,
			`INSERT INTO m1_tenants (org_id, name) VALUES ($1, $2) RETURNING id`, orgID, name).Scan(&tid); err != nil {
			t.Fatal(err)
		}
		t2, err := querychoke.FromClaims(auth.Claims{TenantID: tid, DeviceID: uuid.New()})
		if err != nil {
			t.Fatal(err)
		}
		return t2
	}

	appDSN := fmt.Sprintf("postgres://%s:registrytest@%s:%d/%s?sslmode=disable",
		role, adminCfg.Host, adminCfg.Port, scratch)
	pool, err := pg.Open(ctx, appDSN)
	if err != nil {
		t.Fatalf("pg.Open as NOBYPASSRLS role: %v", err)
	}
	t.Cleanup(pool.Close)

	return &harness{
		admin: admin, db: pg.NewTenantDB(pool),
		tenantA: mkTenant("tenant-a"), tenantB: mkTenant("tenant-b"),
		migrationDir: dir,
		appPoolQuery: func(ctx context.Context, sql string, args ...any) (int64, error) {
			var n int64
			err := pool.QueryRow(ctx, sql, args...).Scan(&n)
			return n, err
		},
	}
}

func (h *harness) window(t *testing.T, tenant querychoke.TenantID) registry.Window {
	t.Helper()
	w, err := registry.NewPG(h.db).Window(context.Background(), tenant)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func (h *harness) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := h.admin.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func TestSchemaWindowIsTenantScoped(t *testing.T) {
	h := setup(t)
	ctx := context.Background()

	t.Run("fresh_database_serves_the_seed_row_to_everyone", func(t *testing.T) {
		for _, tenant := range []querychoke.TenantID{h.tenantA, h.tenantB} {
			w := h.window(t, tenant)
			if !reflect.DeepEqual(w.Accepted, []string{"m1p.v1"}) {
				t.Fatalf("accepted: %v", w.Accepted)
			}
			if w.NotesURI["m1p.v1"] != "https://docs.omium.ai/mark1/upgrade/m1p-v1" || len(w.MinEdge) != 0 || len(w.Closes) != 0 {
				t.Fatalf("seed row misread: %+v", w)
			}
		}
	})

	// Release v2, then pin tenant A past v1: v1 closed an hour ago, v2 open.
	h.exec(t, `INSERT INTO m1_schema_versions (schema, released_at, min_edge, notes_uri)
	           VALUES ('m1p.v2', now(), '2.0.0', 'https://docs.omium.ai/mark1/upgrade/m1p-v2')`)
	h.exec(t, `INSERT INTO m1_tenant_schema_windows (tenant_id, schema, window_closes)
	           VALUES ($1, 'm1p.v1', now() - interval '1 hour'), ($1, 'm1p.v2', NULL)`, h.tenantA.UUID())

	t.Run("tenant_rows_narrow_that_tenant_only", func(t *testing.T) {
		a := h.window(t, h.tenantA)
		if !reflect.DeepEqual(a.Accepted, []string{"m1p.v2"}) {
			t.Fatalf("tenant A accepted: %v", a.Accepted)
		}
		if a.Closes["m1p.v1"] == nil || !a.Closes["m1p.v1"].Before(time.Now()) {
			t.Fatalf("tenant A's v1 close not reported: %v", a.Closes)
		}
		accepted, minEdge, closes, notes := a.Hint("m1p.v1")
		if !reflect.DeepEqual(accepted, []string{"m1p.v2"}) || minEdge == nil || *minEdge != "2.0.0" ||
			closes == nil || notes != "https://docs.omium.ai/mark1/upgrade/m1p-v2" {
			t.Fatalf("hint: %v %v %v %q", accepted, minEdge, closes, notes)
		}
		// Tenant B has no rows: A's narrowing must not leak. B accepts every
		// unretired schema, and sees no close for v1.
		b := h.window(t, h.tenantB)
		if !reflect.DeepEqual(b.Accepted, []string{"m1p.v1", "m1p.v2"}) {
			t.Fatalf("tenant B accepted: %v (tenant A's window leaked)", b.Accepted)
		}
		if len(b.Closes) != 0 {
			t.Fatalf("tenant B sees tenant A's window rows: %v", b.Closes)
		}
	})

	t.Run("global_retirement_applies_only_to_unnarrowed_tenants", func(t *testing.T) {
		h.exec(t, `UPDATE m1_schema_versions SET retired_at = now() WHERE schema = 'm1p.v1'`)
		t.Cleanup(func() { h.exec(t, `UPDATE m1_schema_versions SET retired_at = NULL WHERE schema = 'm1p.v1'`) })
		if b := h.window(t, h.tenantB); !reflect.DeepEqual(b.Accepted, []string{"m1p.v2"}) {
			t.Fatalf("retired v1 still accepted for an unnarrowed tenant: %v", b.Accepted)
		}
		// An explicit tenant row for a retired schema keeps that tenant on
		// it: per-tenant retirement, never a fleet-wide flag day (08 §10.2).
		h.exec(t, `INSERT INTO m1_tenant_schema_windows (tenant_id, schema) VALUES ($1, 'm1p.v1')`, h.tenantB.UUID())
		t.Cleanup(func() { h.exec(t, `DELETE FROM m1_tenant_schema_windows WHERE tenant_id = $1`, h.tenantB.UUID()) })
		if b := h.window(t, h.tenantB); !reflect.DeepEqual(b.Accepted, []string{"m1p.v1"}) {
			t.Fatalf("tenant B's explicit v1 window lost to global retirement: %v", b.Accepted)
		}
	})

	// -----------------------------------------------------------------------
	// RLS. The negative direction is the only one that proves anything.
	// -----------------------------------------------------------------------
	t.Run("rls_denies_the_wrong_tenant", func(t *testing.T) {
		count := func(tenant querychoke.TenantID) int64 {
			var n int64
			if err := h.db.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
				return tx.QueryRow(ctx, `SELECT count(*) FROM m1_tenant_schema_windows`).Scan(&n)
			}); err != nil {
				t.Fatal(err)
			}
			return n
		}
		// The authority holds A's two rows: the zero below is RLS, not an
		// empty table.
		if n := count(h.tenantA); n != 2 {
			t.Fatalf("tenant A sees %d of its own rows; an RLS policy that denies everybody is a broken service", n)
		}
		if n := count(h.tenantB); n != 0 {
			t.Fatalf("tenant B read %d of tenant A's window rows", n)
		}
		// Raw pool, no WithTenant: NULLIF makes an unset GUC match nothing.
		n, err := h.appPoolQuery(ctx, `SELECT count(*) FROM m1_tenant_schema_windows`)
		if err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatalf("unset GUC saw %d rows; the NULLIF floor failed", n)
		}
		// The catalog is global by design: visible with and without a GUC.
		if n, err := h.appPoolQuery(ctx, `SELECT count(*) FROM m1_schema_versions`); err != nil || n != 2 {
			t.Fatalf("m1_schema_versions must be global: n=%d err=%v", n, err)
		}
	})

	t.Run("app_role_is_select_only", func(t *testing.T) {
		for _, stmt := range []string{
			`INSERT INTO m1_tenant_schema_windows (tenant_id, schema) VALUES ('` + h.tenantA.String() + `', 'm1p.v2')`,
			`UPDATE m1_tenant_schema_windows SET window_closes = NULL`,
			`DELETE FROM m1_tenant_schema_windows`,
			`INSERT INTO m1_schema_versions (schema, released_at, notes_uri) VALUES ('m1p.v3', now(), 'x')`,
			`UPDATE m1_schema_versions SET retired_at = NULL`,
			`DELETE FROM m1_schema_versions`,
		} {
			err := h.db.WithTenant(ctx, h.tenantA, func(tx pgx.Tx) error {
				_, e := tx.Exec(ctx, stmt)
				return e
			})
			if err == nil {
				t.Fatalf("controld_app executed %q — a tenant-side widening path exists", stmt)
			}
			if !strings.Contains(err.Error(), "permission denied") {
				t.Fatalf("%q failed for the wrong reason: %v", stmt, err)
			}
		}
	})

	t.Run("migration_is_idempotent", func(t *testing.T) {
		sql, err := os.ReadFile(filepath.Join(h.migrationDir, "m1_063_schema_registry.sql"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.admin.Exec(ctx, string(sql)); err != nil {
			t.Fatalf("re-applying m1_063 over a populated database: %v", err)
		}
		var seeds, windows int64
		if err := h.admin.QueryRow(ctx, `SELECT count(*) FROM m1_schema_versions WHERE schema = 'm1p.v1'`).Scan(&seeds); err != nil {
			t.Fatal(err)
		}
		if err := h.admin.QueryRow(ctx, `SELECT count(*) FROM m1_tenant_schema_windows`).Scan(&windows); err != nil {
			t.Fatal(err)
		}
		if seeds != 1 || windows != 2 {
			t.Fatalf("re-run changed data: seeds=%d windows=%d", seeds, windows)
		}
		if a := h.window(t, h.tenantA); !reflect.DeepEqual(a.Accepted, []string{"m1p.v2"}) {
			t.Fatalf("re-run changed tenant A's window: %v", a.Accepted)
		}
	})
}
