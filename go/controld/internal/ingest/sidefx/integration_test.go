package sidefx_test

// DSN-gated Postgres integration (house style, 12 / 05 §7.5): a scratch
// database gets the real migrations, a NOBYPASSRLS login role stands in for
// controld_app, and the tests prove the two walls independently — the
// tenant-GUC discipline (05 §7.2) and RLS-with-NULLIF (05 §7.1) — plus the R2
// posture that pg.Open REFUSES a bypass-capable role.
//
// Gate: M1_TEST_PG_DSN (superuser DSN for scratch setup). Absent ⇒ skip,
// unless M1_REQUIRE_STORES=1 ⇒ fail.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/sidefx"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/pg"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
)

func pgDSN(t *testing.T) string {
	t.Helper()
	v := os.Getenv("M1_TEST_PG_DSN")
	if v == "" {
		if os.Getenv("M1_REQUIRE_STORES") == "1" {
			t.Fatal("M1_TEST_PG_DSN required (M1_REQUIRE_STORES=1) but unset")
		}
		t.Skip("M1_TEST_PG_DSN unset; skipping Postgres-backed test")
	}
	return v
}

type pgHarness struct {
	admin   *pgx.Conn // superuser, connected to the scratch db
	db      *pg.TenantDB
	tenantA querychoke.TenantID
	tenantB querychoke.TenantID
	deviceA uuid.UUID
	deviceB uuid.UUID
	// appPoolQuery queries the raw app pool with NO tenant GUC — the
	// unset-GUC-matches-nothing probe (05 §7.1).
	appPoolQuery func(ctx context.Context, sql string, args ...any) (int64, error)
}

func setupPG(t *testing.T) *pgHarness {
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

	scratch := fmt.Sprintf("controld_c4_it_%d", time.Now().UnixNano())
	role := fmt.Sprintf("c4app_%d", time.Now().UnixNano())
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

	// The real migrations, in filename order — the tests run against exactly
	// what prod will execute (05 §7.4).
	files, err := filepath.Glob(filepath.Join("..", "..", "..", "..", "..", "migrations", "m1_0*.sql"))
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

	// A login stand-in for controld_app (which is passwordless by design —
	// m1_060: credentials are injected at cutover, never committed). It
	// INHERITS controld_app's grants but keeps its own NOBYPASSRLS attribute,
	// which is the one that matters (BYPASSRLS does not inherit).
	if _, err := admin.Exec(ctx, fmt.Sprintf(
		"CREATE ROLE %s LOGIN PASSWORD 'c4test' NOBYPASSRLS NOSUPERUSER; GRANT controld_app TO %s", role, role)); err != nil {
		t.Fatal(err)
	}

	// Seed two tenants + one device each, as superuser (RLS bypassed by
	// attribute — which is exactly why the app path must never run as one).
	var orgID uuid.UUID
	if err := admin.QueryRow(ctx,
		`INSERT INTO m1_organizations (name, primary_domain) VALUES ('c4-it', 'c4-it.example') RETURNING id`,
	).Scan(&orgID); err != nil {
		t.Fatal(err)
	}
	mkTenant := func(name string) (uuid.UUID, uuid.UUID) {
		var tid, did uuid.UUID
		if err := admin.QueryRow(ctx,
			`INSERT INTO m1_tenants (org_id, name) VALUES ($1, $2) RETURNING id`, orgID, name,
		).Scan(&tid); err != nil {
			t.Fatal(err)
		}
		if err := admin.QueryRow(ctx,
			`INSERT INTO m1_devices (tenant_id, platform, hostname_hmac) VALUES ($1, 'linux', $2) RETURNING id`,
			tid, make([]byte, 32),
		).Scan(&did); err != nil {
			t.Fatal(err)
		}
		return tid, did
	}
	tA, dA := mkTenant("tenant-a")
	tB, dB := mkTenant("tenant-b")

	appDSN := fmt.Sprintf("postgres://%s:c4test@%s:%d/%s?sslmode=disable",
		role, adminCfg.Host, adminCfg.Port, scratch)
	pool, err := pg.Open(ctx, appDSN)
	if err != nil {
		t.Fatalf("pg.Open as NOBYPASSRLS role: %v", err)
	}
	t.Cleanup(pool.Close)

	claimsA := auth.Claims{TenantID: tA, DeviceID: dA}
	claimsB := auth.Claims{TenantID: tB, DeviceID: dB}
	tenantA, err := querychoke.FromClaims(claimsA)
	if err != nil {
		t.Fatal(err)
	}
	tenantB, err := querychoke.FromClaims(claimsB)
	if err != nil {
		t.Fatal(err)
	}

	return &pgHarness{
		admin: admin, db: pg.NewTenantDB(pool),
		tenantA: tenantA, tenantB: tenantB, deviceA: dA, deviceB: dB,
		appPoolQuery: func(ctx context.Context, sql string, args ...any) (int64, error) {
			var n int64
			err := pool.QueryRow(ctx, sql, args...).Scan(&n)
			return n, err
		},
	}
}

// R2, continuously: pg.Open must REFUSE a superuser/BYPASSRLS DSN — the
// RLS-inert-via-rds_superuser failure made structurally unrepeatable.
func TestIntegrationOpenRefusesBypassCapableRole(t *testing.T) {
	dsn := pgDSN(t)
	if _, err := pg.Open(context.Background(), dsn); err == nil {
		t.Fatal("pg.Open accepted a superuser role (R2 must refuse, 05 §1.2/§7.2)")
	}
}

func TestIntegrationSidefxAndRLS(t *testing.T) {
	h := setupPG(t)
	ctx := context.Background()
	s := sidefx.New(h.db, 1, 8)
	t.Cleanup(s.Close)

	t1 := time.Date(2026, 8, 29, 10, 0, 0, 0, time.UTC)

	t.Run("last_seen_upsert_idempotent", func(t *testing.T) {
		if err := s.ApplyLastSeen(ctx, h.tenantA, h.deviceA, t1); err != nil {
			t.Fatal(err)
		}
		var got time.Time
		if err := h.admin.QueryRow(ctx,
			`SELECT last_seen_at FROM m1_devices WHERE id = $1`, h.deviceA).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if !got.Equal(t1) {
			t.Fatalf("last_seen_at: want %v got %v", t1, got)
		}
		// Replaying an OLDER batch must not move the timestamp backwards.
		if err := s.ApplyLastSeen(ctx, h.tenantA, h.deviceA, t1.Add(-time.Hour)); err != nil {
			t.Fatal(err)
		}
		if err := h.admin.QueryRow(ctx,
			`SELECT last_seen_at FROM m1_devices WHERE id = $1`, h.deviceA).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if !got.Equal(t1) {
			t.Fatalf("replay moved last_seen_at backwards: %v", got)
		}
	})

	t.Run("cross_tenant_read_denied", func(t *testing.T) {
		var n int64
		err := h.db.WithTenant(ctx, h.tenantA, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM m1_devices`).Scan(&n)
		})
		if err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Fatalf("tenant A sees %d devices; RLS wall is decorative", n)
		}
	})

	t.Run("cross_tenant_write_matches_nothing", func(t *testing.T) {
		// Tenant A's GUC + tenant B's device: the UPDATE must touch 0 rows —
		// the exact ingest-arm shape of the tenant-isolation suite (05 §9).
		if err := s.ApplyLastSeen(ctx, h.tenantA, h.deviceB, t1); err != nil {
			t.Fatal(err)
		}
		var seen *time.Time
		if err := h.admin.QueryRow(ctx,
			`SELECT last_seen_at FROM m1_devices WHERE id = $1`, h.deviceB).Scan(&seen); err != nil {
			t.Fatal(err)
		}
		if seen != nil {
			t.Fatalf("cross-tenant write landed: %v", *seen)
		}
	})

	t.Run("unset_guc_matches_nothing", func(t *testing.T) {
		// Raw pool, no WithTenant: the NULLIF policy form must return zero
		// rows, never all rows (05 §7.1).
		n, err := h.appPoolQuery(ctx, `SELECT count(*) FROM m1_devices`)
		if err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatalf("unset GUC saw %d rows; the NULLIF floor failed", n)
		}
	})
}
