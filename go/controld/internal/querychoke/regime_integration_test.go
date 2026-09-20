//go:build integration

package querychoke_test

// DSN-gated (M1_TEST_PG_DSN; M1_REQUIRE_STORES=1 fails instead of skipping): the
// report handler resolving a REAL m1_075 row through pg.TenantDB under the tenant
// GUC — an external test package because pg imports querychoke. The ledger side
// is a canned Runner (the ClickHouse suite in integration_test.go owns that half).

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/pg"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
)

type cannedRunner struct{ byTemplate map[string]*querychoke.Rows }

func (c cannedRunner) Run(_ context.Context, q querychoke.Query) (*querychoke.Rows, error) {
	return c.byTemplate[q.Template().Name()], nil
}

func TestIntegrationReportGuaranteeGradeFromTenantRegimeRow(t *testing.T) {
	dsn := os.Getenv("M1_TEST_PG_DSN")
	if dsn == "" {
		if os.Getenv("M1_REQUIRE_STORES") == "1" {
			t.Fatal("M1_TEST_PG_DSN required (M1_REQUIRE_STORES=1) but unset")
		}
		t.Skip("M1_TEST_PG_DSN unset; skipping Postgres-backed test")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("cannot reach test Postgres: %v", err)
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	pool, err := pg.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("pg.Open (NOBYPASSRLS role required): %v", err)
	}
	t.Cleanup(pool.Close)

	// Two tenants, one regime row: B's report must never resolve through A's row (m1_075 RLS).
	mkTenant := func() uuid.UUID {
		t.Helper()
		tag := "regime-it-" + uuid.NewString()[:8]
		tenant := uuid.New()
		err := pgx.BeginFunc(ctx, admin, func(tx pgx.Tx) error {
			var org uuid.UUID
			if err := tx.QueryRow(ctx, `INSERT INTO m1_organizations (name, primary_domain) VALUES ($1, $2) RETURNING id`, tag, tag+".example").Scan(&org); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tenant.String()); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO m1_tenants (id, org_id, name) VALUES ($1, $2, $3)`, tenant, org, tag)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return tenant
	}
	setRegime := func(tenant uuid.UUID, basis string, model *string, limit *int64, shadow *float64) {
		t.Helper()
		err := pgx.BeginFunc(ctx, admin, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tenant.String()); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO m1_tenant_regimes (tenant_id, cost_basis, price_model_id, window_limit_tokens, shadow_price_usd, v_default, set_by)
				VALUES ($1, $2, $3, $4, $5, 25, 'regime-it')
				ON CONFLICT (tenant_id) DO UPDATE SET cost_basis = EXCLUDED.cost_basis, price_model_id = EXCLUDED.price_model_id,
				  window_limit_tokens = EXCLUDED.window_limit_tokens, shadow_price_usd = EXCLUDED.shadow_price_usd, set_at = now()`,
				tenant, basis, model, limit, shadow)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	tenantA, tenantB := mkTenant(), mkTenant()
	sonnet := "claude-sonnet-5"
	setRegime(tenantA, "usd", &sonnet, nil, nil)

	reg, err := querychoke.LoadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	const key = "regime-it-key"
	m := querychoke.New(querychoke.Deps{
		Registry: reg,
		Runner: cannedRunner{byTemplate: map[string]*querychoke.Rows{
			"tvo_report": {Rows: []map[string]any{{
				"day": time.Now().UTC(), "task_seg_version": "task_seg.v1",
				"tokens_total": uint64(300), "tasks_verified": uint64(3), "tasks_unresolved": uint64(0),
				"retry_loop_tokens": uint64(0), "reexploration_tokens": uint64(0), "over_model_tokens": uint64(0),
				"observed_ms": uint64(980), "bypass_ms": uint64(20), "disabled_ms": uint64(0), "dropped_billing": uint64(0),
			}}},
			"dropped_by_tenant_day": {Rows: []map[string]any{{"dropped_billing": uint64(0), "events_billing_ingested": uint64(100)}}},
			"certified_outcomes":    {Rows: []map[string]any{{"certified": uint64(3)}}}, // a certified tenant: this test is about the regime row
		}},
		Verifier: auth.NewHMACVerifier([]byte(key), auth.StaticRevocations{}),
		ObsCfg:   obs.Config{ServiceName: "querychoke-regime-it"},
		Regimes:  querychoke.PGRegimes{DB: pg.NewTenantDB(pool)},
	})
	mux := http.NewServeMux()
	m.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	get := func(tenant uuid.UUID, basis string) map[string]any {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/reports/tvo?window=1d&cost_basis="+basis, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+auth.Mint([]byte(key), tenant, uuid.New(), time.Hour))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		var body map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: %d %v %v", basis, resp.StatusCode, body, err)
		}
		return body
	}

	// A: usd pinned ⇒ guarantee-grade with the table digest; B: no row ⇒ indicative, A's row invisible.
	a := get(tenantA, "auto")
	if a["guarantee_grade"] != true || a["cost_basis"] != "usd" || !strings.HasPrefix(a["price_table_version"].(string), "model_prices.v1@sha256:") {
		t.Fatalf("tenant A usd regime: %v", a)
	}
	b := get(tenantB, "auto")
	if b["guarantee_grade"] != false || b["refusal"] != "cost basis unresolved: no pinned model_prices row for usd (06 §8.4)" {
		t.Fatalf("tenant B without a row resolved a basis: %v", b)
	}
	if _, ok := b["price_table_version"]; ok {
		t.Fatalf("tenant B stamped a price table: %v", b)
	}

	// A re-set to quota with a confirmed S: auto ⇒ quota guarantee-grade, no price pin; usd asked ⇒ indicative.
	limit, shadow := int64(100_000), 150.0
	setRegime(tenantA, "quota", nil, &limit, &shadow)
	a = get(tenantA, "auto")
	if a["guarantee_grade"] != true || a["cost_basis"] != "quota" {
		t.Fatalf("tenant A quota regime: %v", a)
	}
	if _, ok := a["price_table_version"]; ok {
		t.Fatalf("quota report claims a price pin: %v", a)
	}
	if a = get(tenantA, "usd"); a["guarantee_grade"] != false || a["cost_basis"] != "usd" {
		t.Fatalf("usd asked of a quota tenant: %v", a)
	}

	// A pinned to a model the table carries but cannot price (vendor publishes no cache-write price): indicative, by name.
	gemini := "gemini-2.5-flash"
	setRegime(tenantA, "usd", &gemini, nil, nil)
	if a = get(tenantA, "auto"); a["guarantee_grade"] != false || !strings.Contains(a["refusal"].(string), "no pinned model_prices row for usd") {
		t.Fatalf("unpinned model: %v", a)
	}
}
