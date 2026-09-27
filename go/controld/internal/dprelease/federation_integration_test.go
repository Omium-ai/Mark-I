//go:build integration

// DSN-gated Postgres integration for the federation boundary (house style, 12 /
// 05 §7.5): a scratch database gets the real migrations, and the tests prove
// what m1_041 + m1_064 claim — THE DATABASE REFUSES, NOT THE APP. Publication
// writes go through dprelease.Worker on a login role standing in for
// mark1_federation_worker (BYPASSRLS, m1_060 §5); ε-ledger reads and direct
// spends go through one standing in for intel_app (NOBYPASSRLS, under the
// tenant GUC, m1_060 §4). Negative controls disable each trigger inside a
// rolled-back transaction as the table OWNER (the bootstrap role — neither app
// role may, and that is asserted too).
//
// Gate: M1_MIGRATE_PG_DSN (privileged DSN for scratch setup). Absent ⇒ skip,
// unless M1_REQUIRE_STORES=1 ⇒ fail.

package dprelease_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/dprelease"
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
	admin     *pgx.Conn         // the bootstrap role on the scratch db: owns every table
	fed       *pgx.Conn         // BYPASSRLS login role, member of mark1_federation_worker: raw SQL for negative controls
	w         *dprelease.Worker // the same role through the package under test
	intelPool *pgxpool.Pool     // NOBYPASSRLS login role, member of intel_app
	intel     *pg.TenantDB
	owner     querychoke.TenantID // owns the seeded artifacts; contributes nothing
	other     querychoke.TenantID // contributes nothing, holds no budget: the RLS "B" side
}

// contributor is one (tenant, org, contribution row) triple behind an artifact.
type contributor struct{ tenant, org, contribution uuid.UUID }

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
	stamp := time.Now().UnixNano()
	scratch := fmt.Sprintf("controld_fed_it_%d", stamp)
	fedRole := fmt.Sprintf("fedw_%d", stamp)
	intelRole := fmt.Sprintf("intel_%d", stamp)
	if _, err := bootstrap.Exec(ctx, "CREATE DATABASE "+scratch); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cctx := context.Background()
		_, _ = bootstrap.Exec(cctx, "DROP DATABASE IF EXISTS "+scratch+" WITH (FORCE)")
		_, _ = bootstrap.Exec(cctx, "DROP ROLE IF EXISTS "+fedRole)
		_, _ = bootstrap.Exec(cctx, "DROP ROLE IF EXISTS "+intelRole)
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
	files, err := filepath.Glob(filepath.Join("..", "..", "..", "..", "migrations", "m1_[0-9]*.sql"))
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
	// BYPASSRLS is a role ATTRIBUTE, not a grant: membership in
	// mark1_federation_worker carries its table privileges but not its bypass,
	// so the worker stand-in is minted with the attribute itself — the exact
	// shape doc.go says the dprelease pool opens with.
	_, err = admin.Exec(ctx, fmt.Sprintf(
		"CREATE ROLE %s LOGIN PASSWORD 'fedtest' BYPASSRLS NOSUPERUSER; GRANT mark1_federation_worker TO %s; "+
			"CREATE ROLE %s LOGIN PASSWORD 'fedtest' NOBYPASSRLS NOSUPERUSER; GRANT intel_app TO %s",
		fedRole, fedRole, intelRole, intelRole))
	if _, uerr := bootstrap.Exec(ctx, `SELECT pg_advisory_unlock(7231060)`); uerr != nil {
		t.Fatal(uerr)
	}
	if err != nil {
		t.Fatal(err)
	}

	mkTenant := func(name string) querychoke.TenantID {
		var tid uuid.UUID
		if err := admin.QueryRow(ctx, `
			WITH o AS (INSERT INTO m1_organizations (name, primary_domain) VALUES ($1, $1 || '.example') RETURNING id)
			INSERT INTO m1_tenants (org_id, name) SELECT id, $1 FROM o RETURNING id`, name).Scan(&tid); err != nil {
			t.Fatal(err)
		}
		tenant, err := querychoke.FromClaims(auth.Claims{TenantID: tid, DeviceID: uuid.New()})
		if err != nil {
			t.Fatal(err)
		}
		return tenant
	}

	dsnFor := func(role string) string {
		return fmt.Sprintf("postgres://%s:fedtest@%s:%d/%s?sslmode=disable", role, adminCfg.Host, adminCfg.Port, scratch)
	}
	fed, err := pgx.Connect(ctx, dsnFor(fedRole))
	if err != nil {
		t.Fatalf("connect as federation worker: %v", err)
	}
	t.Cleanup(func() { _ = fed.Close(context.Background()) })
	w, err := dprelease.Open(ctx, dsnFor(fedRole))
	if err != nil {
		t.Fatalf("dprelease.Open as the worker role: %v", err)
	}
	t.Cleanup(w.Close)
	intelPool, err := pg.Open(ctx, dsnFor(intelRole))
	if err != nil {
		t.Fatalf("pg.Open as NOBYPASSRLS intel role: %v", err)
	}
	t.Cleanup(intelPool.Close)
	// The inverse refusal: the NOBYPASSRLS role is not a federation worker.
	if _, err := dprelease.Open(ctx, dsnFor(intelRole)); err == nil {
		t.Fatal("dprelease.Open accepted a NOBYPASSRLS role")
	}

	return &harness{
		admin: admin, fed: fed, w: w, intelPool: intelPool, intel: pg.NewTenantDB(intelPool),
		owner: mkTenant(fmt.Sprintf("fed-owner-%d", stamp)),
		other: mkTenant(fmt.Sprintf("fed-other-%d", stamp)),
	}
}

func (h *harness) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := h.admin.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// artifact seeds one 'pattern' artifact owned by h.owner with n contributing
// tenants, each in its own org, each org billing+domain-verified on
// m1_organizations (the one predicate, m1_001:50-53) with a distinct billing
// customer and domain root (so each is its own derived collusion group), and
// each tenant holding the 05 §5.2 4.0 budget.
func (h *harness) artifact(t *testing.T, n int) (uuid.UUID, []contributor) {
	t.Helper()
	ctx := context.Background()
	var art uuid.UUID
	if err := h.admin.QueryRow(ctx,
		`INSERT INTO memory_artifacts (tenant_id, abstraction, kind, body) VALUES ($1, 'pattern', 'fix_pattern', '{}') RETURNING id`,
		h.owner.UUID()).Scan(&art); err != nil {
		t.Fatal(err)
	}
	rows, err := h.admin.Query(ctx, `
		WITH o AS (
		  INSERT INTO m1_organizations (name, primary_domain, domain_verified_at, domain_verification_method, billing_customer_id, billing_verified_at)
		  SELECT 'fed-it-' || g, gen_random_uuid() || '.example', now(), 'dns_txt', 'cus_' || gen_random_uuid(), now()
		    FROM generate_series(1, $1) g RETURNING id
		), tn AS (
		  INSERT INTO m1_tenants (org_id, name) SELECT id, 'fed-it' FROM o RETURNING id, org_id
		), b AS (
		  INSERT INTO tenant_privacy_budgets (tenant_id, epsilon_cap) SELECT id, 4.0 FROM tn
		)
		INSERT INTO artifact_contributions (artifact_id, tenant_id, org_id, span_digest)
		SELECT $2, id, org_id, sha256(id::text::bytea) FROM tn RETURNING tenant_id, org_id, id`, n, art)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (contributor, error) {
		var c contributor
		return c, r.Scan(&c.tenant, &c.org, &c.contribution)
	})
	if err != nil || len(cs) != n {
		t.Fatalf("seed %d contributors: got %d, %v", n, len(cs), err)
	}
	return art, cs
}

// review files an already-approved review for art through the worker role —
// which is itself a finding (CON-011 ledger, 5): the "named human" is a text
// column the worker can fill in. Unchanged by m1_064.
func (h *harness) review(t *testing.T, art uuid.UUID, body, state string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	reviewer, decided := "reviewer@omium.test", "now()"
	if state == "pending" {
		reviewer, decided = "", "NULL"
	}
	if err := h.fed.QueryRow(context.Background(), `
		INSERT INTO publication_review_queue (artifact_id, abstraction, candidate_body, state, reviewer, decided_at)
		VALUES ($1, 'pattern', $2, $3, NULLIF($4, ''), `+decided+`) RETURNING id`,
		art, body, state, reviewer).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// publish is the worker's write through the package: one transaction, gate +
// debit at COMMIT (m1_064 header). ε = 0.1 per counted tenant.
func (h *harness) publish(art, review uuid.UUID, body string, spans [][]uuid.UUID) (uuid.UUID, error) {
	return h.w.Publish(context.Background(), dprelease.Publication{
		ArtifactID: art, ReviewID: review, ReceiptID: uuid.New(), Body: body, Spans: spans, Epsilon: 0.1,
	})
}

func ids(cs []contributor) []uuid.UUID {
	out := make([]uuid.UUID, len(cs))
	for i, c := range cs {
		out[i] = c.contribution
	}
	return out
}

// span5 is the minimum publishable body: one span, five independent producers.
func span5(cs []contributor) [][]uuid.UUID { return [][]uuid.UUID{ids(cs[:5])} }

// wantPgErr asserts err is a server-side refusal with the given SQLSTATE whose
// message carries every frag (a constraint violation names its constraint in
// the message, so a frag can pin WHICH constraint refused).
func wantPgErr(t *testing.T, err error, code string, frags ...string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		t.Fatalf("want SQLSTATE %s containing %q, got: %v", code, frags, err)
	}
	for _, frag := range frags {
		if pgErr.Code != code || !strings.Contains(pgErr.Message, frag) {
			t.Fatalf("want SQLSTATE %s containing %q, got %s: %s", code, frags, pgErr.Code, pgErr.Message)
		}
	}
}

const checkViolation = "23514"

func (h *harness) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := h.admin.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// triggerEnabled reads pg_trigger: 'O' is the origin-enabled default. Every
// negative control below ends by asserting it, so a control can never leave
// the gate off.
func (h *harness) triggerEnabled(t *testing.T, name string) {
	t.Helper()
	var state string
	if err := h.admin.QueryRow(context.Background(),
		`SELECT tgenabled::text FROM pg_trigger WHERE tgname = $1 AND tgrelid = 'artifact_publications'::regclass`, name).Scan(&state); err != nil || state != "O" {
		t.Fatalf("trigger %s: enabled=%q err=%v", name, state, err)
	}
}

// -----------------------------------------------------------------------------
// FR-FED-001/003: k. The trigger's first predicate counts DISTINCT tenant_id
// over federation_contributions (m1_064) and refuses below 25.
// -----------------------------------------------------------------------------
func TestIntegrationKMGateRefusesBelowK(t *testing.T) {
	h := setup(t)
	ctx := context.Background()

	t.Run("24_verified_contributors_refused_at_the_database", func(t *testing.T) {
		art, cs := h.artifact(t, 24)
		review := h.review(t, art, "body-24", "approved")
		_, err := h.publish(art, review, "body-24", span5(cs))
		wantPgErr(t, err, checkViolation, "(k,m) gate", "k=24", "need k>=25")
		if n := h.count(t, `SELECT count(*) FROM artifact_publications WHERE artifact_id = $1`, art); n != 0 {
			t.Fatalf("refused publication persisted: n=%d", n)
		}
	})

	t.Run("25_verified_contributors_accepted", func(t *testing.T) {
		art, cs := h.artifact(t, 25)
		review := h.review(t, art, "body-25", "approved")
		if _, err := h.publish(art, review, "body-25", span5(cs)); err != nil {
			t.Fatalf("k=25 must pass: %v", err)
		}
	})

	// The HAVING form (dprelease.candidateSQL) and the trigger agree: the
	// worker can only FIND what the trigger would admit.
	t.Run("candidate_query_is_the_having_form_of_the_gate", func(t *testing.T) {
		pass, _ := h.artifact(t, 25)
		fail, _ := h.artifact(t, 24)
		cands, err := h.w.Candidates(ctx)
		if err != nil {
			t.Fatal(err)
		}
		found := map[uuid.UUID]bool{}
		for _, c := range cands {
			found[c] = true
		}
		if !found[pass] || found[fail] {
			t.Fatalf("candidates: pass=%v fail=%v", found[pass], found[fail])
		}
		rows, err := h.w.Contributions(ctx, pass)
		if err != nil || len(rows) != 25 {
			t.Fatalf("Contributions: %d rows, %v", len(rows), err)
		}
		if _, err := dprelease.Release(rows, dprelease.EpsilonRelease); err != nil {
			t.Fatalf("Release over the gate rows: %v", err)
		}
		if rows[0].ArtifactID != pass || rows[0].CollusionGroupID == uuid.Nil {
			t.Fatalf("view row %+v", rows[0])
		}
	})

	// The gate is a DEFERRED constraint trigger (m1_064 header), NOT a BEFORE
	// INSERT trigger: inside an explicit transaction the INSERT succeeds and the
	// refusal arrives from COMMIT.
	t.Run("refusal_arrives_at_commit_not_at_insert", func(t *testing.T) {
		art, _ := h.artifact(t, 24)
		review := h.review(t, art, "body-deferred", "approved")
		tx, err := h.fed.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO artifact_publications (artifact_id, abstraction, review_id, body, epsilon_spent, receipt_id)
			VALUES ($1, 'pattern', $2, 'body-deferred', 0.1, gen_random_uuid())`, art, review); err != nil {
			t.Fatalf("deferred gate fired at INSERT: %v", err)
		}
		wantPgErr(t, tx.Commit(ctx), checkViolation, "(k,m) gate")
	})

	// FIXED (a): m1_001's columns ARE what the gate reads. org_verification is
	// a view over m1_organizations, so there is no second row to diverge.
	t.Run("one_verification_truth_m1_organizations_columns", func(t *testing.T) {
		var kind string
		if err := h.admin.QueryRow(ctx, `SELECT relkind::text FROM pg_class WHERE relname = 'org_verification'`).Scan(&kind); err != nil || kind != "v" {
			t.Fatalf("org_verification relkind=%q err=%v; want a view", kind, err)
		}
		art, cs := h.artifact(t, 25)
		h.exec(t, `UPDATE m1_organizations SET billing_verified_at = NULL WHERE id = $1`, cs[0].org)
		review := h.review(t, art, "body-split", "approved")
		_, err := h.publish(art, review, "body-split", span5(cs[1:]))
		wantPgErr(t, err, checkViolation, "k=24")
		h.exec(t, `UPDATE m1_organizations SET billing_verified_at = now() WHERE id = $1`, cs[0].org)
		if _, err := h.publish(art, review, "body-split", span5(cs[1:])); err != nil {
			t.Fatalf("re-verified on m1_organizations must count again: %v", err)
		}
	})

	// FIXED (f): an opted-out tenant's contribution counts toward nothing and is charged nothing.
	t.Run("opted_out_tenant_counts_toward_nothing", func(t *testing.T) {
		art, cs := h.artifact(t, 25)
		h.exec(t, `UPDATE m1_tenants SET federation_opted_out_at = now() WHERE id = $1`, cs[0].tenant)
		review := h.review(t, art, "body-optout", "approved")
		_, err := h.publish(art, review, "body-optout", span5(cs[1:]))
		wantPgErr(t, err, checkViolation, "k=24")
		if rows, err := h.w.Contributions(ctx, art); err != nil || len(rows) != 24 {
			t.Fatalf("opted-out row reached the worker: %d rows, %v", len(rows), err)
		}

		art2, cs2 := h.artifact(t, 26)
		h.exec(t, `UPDATE m1_tenants SET federation_opted_out_at = now() WHERE id = $1`, cs2[0].tenant)
		review2 := h.review(t, art2, "body-optout-2", "approved")
		_, err = h.publish(art2, review2, "body-optout-2", span5(cs2))
		wantPgErr(t, err, checkViolation, "intersection-reconstruction: 1 span(s)")
		pub, err := h.publish(art2, review2, "body-optout-2", span5(cs2[1:]))
		if err != nil {
			t.Fatal(err)
		}
		if n := h.count(t, `SELECT count(*) FROM epsilon_ledger WHERE publication_id = $1`, pub); n != 25 {
			t.Fatalf("charged %d tenants, want the 25 counted", n)
		}
		if n := h.count(t, `SELECT count(*) FROM epsilon_ledger WHERE tenant_id = $1`, cs2[0].tenant); n != 0 {
			t.Fatal("opted-out tenant was charged")
		}
	})

	t.Run("negative_control_trigger_disabled_by_owner_admits_the_same_row", func(t *testing.T) {
		art, _ := h.artifact(t, 24)
		review := h.review(t, art, "body-control", "approved")
		_, err := h.fed.Exec(ctx, `ALTER TABLE artifact_publications DISABLE TRIGGER km_publication_gate`)
		wantPgErr(t, err, "42501", "must be owner")
		tx, err := h.admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, `ALTER TABLE artifact_publications DISABLE TRIGGER km_publication_gate`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO artifact_publications (artifact_id, abstraction, review_id, body, epsilon_spent, receipt_id)
			VALUES ($1, 'pattern', $2, 'body-control', 0.1, gen_random_uuid())`, art, review); err != nil {
			t.Fatalf("with the trigger off the fixture itself refuses — the refusal above was not the trigger: %v", err)
		}
		if _, err := tx.Exec(ctx, `SET CONSTRAINTS ALL IMMEDIATE`); err != nil {
			t.Fatal(err)
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		h.triggerEnabled(t, "km_publication_gate")
	})
}

// -----------------------------------------------------------------------------
// FR-FED-002/004: m and the per-span rule, both over federation_contributions
// with collusion_group_id DERIVED from shared billing / domain root (m1_064).
// -----------------------------------------------------------------------------
func TestIntegrationIntersectionRequiresMIndependentProducers(t *testing.T) {
	h := setup(t)

	t.Run("span_with_4_producers_refused_5_admitted", func(t *testing.T) {
		art, cs := h.artifact(t, 25)
		review := h.review(t, art, "body-span", "approved")
		_, err := h.publish(art, review, "body-span", [][]uuid.UUID{ids(cs[:4])})
		wantPgErr(t, err, checkViolation, "intersection-reconstruction: 1 span(s)")
		if _, err := h.publish(art, review, "body-span", span5(cs)); err != nil {
			t.Fatalf("5 independent producers must pass: %v", err)
		}
	})

	// FIXED (e): two orgs on one Stripe customer collapse to one group.
	t.Run("shared_billing_customer_collapses_to_one_group_per_span", func(t *testing.T) {
		art, cs := h.artifact(t, 25)
		h.exec(t, `UPDATE m1_organizations SET billing_customer_id = 'cus_shared' WHERE id = ANY($1)`, []uuid.UUID{cs[0].org, cs[1].org})
		review := h.review(t, art, "body-collude", "approved")
		_, err := h.publish(art, review, "body-collude", span5(cs))
		wantPgErr(t, err, checkViolation, "intersection-reconstruction: 1 span(s)")
		if _, err := h.publish(art, review, "body-collude", [][]uuid.UUID{ids(cs[:6])}); err != nil {
			t.Fatalf("6 orgs in 5 groups must pass: %v", err)
		}
	})

	// FIXED (e): a shared registrable domain root collapses too, and the
	// collapse is transitive (A–billing–B, B–domain–C ⇒ one group).
	t.Run("shared_domain_root_collapses_transitively", func(t *testing.T) {
		art, cs := h.artifact(t, 25)
		h.exec(t, `UPDATE m1_organizations SET billing_customer_id = 'cus_chain' WHERE id = ANY($1)`, []uuid.UUID{cs[0].org, cs[1].org})
		h.exec(t, `UPDATE m1_organizations SET primary_domain = id || '.holding.example' WHERE id = ANY($1)`, []uuid.UUID{cs[1].org, cs[2].org})
		var groups int
		if err := h.admin.QueryRow(context.Background(),
			`SELECT count(DISTINCT collusion_group_id) FROM org_verification WHERE org_id = ANY($1)`,
			[]uuid.UUID{cs[0].org, cs[1].org, cs[2].org}).Scan(&groups); err != nil || groups != 1 {
			t.Fatalf("A-billing-B-domain-C derived %d groups, want 1 (err=%v)", groups, err)
		}
		review := h.review(t, art, "body-chain", "approved")
		_, err := h.publish(art, review, "body-chain", [][]uuid.UUID{ids(cs[:6])})
		wantPgErr(t, err, checkViolation, "intersection-reconstruction: 1 span(s)")
		if _, err := h.publish(art, review, "body-chain", [][]uuid.UUID{ids(cs[:7])}); err != nil {
			t.Fatalf("7 orgs in 5 groups must pass: %v", err)
		}
	})

	// Collusion collapse at the artifact: 25 tenants (k passes) on 4 billing
	// customers (m fails) — "five tenants of one holding company count once".
	t.Run("25_tenants_on_4_billing_customers_refused_on_m", func(t *testing.T) {
		art, cs := h.artifact(t, 25)
		for i, c := range cs {
			h.exec(t, `UPDATE m1_organizations SET billing_customer_id = $1 WHERE id = $2`, fmt.Sprintf("cus_group_%d", i%4), c.org)
		}
		review := h.review(t, art, "body-m", "approved")
		_, err := h.publish(art, review, "body-m", span5(cs))
		wantPgErr(t, err, checkViolation, "k=25, m=4")
	})

	// FIXED (b): the per-span join carries the verified predicate.
	t.Run("unverified_org_does_not_count_toward_a_spans_m", func(t *testing.T) {
		art, cs := h.artifact(t, 26)
		h.exec(t, `UPDATE m1_organizations SET billing_verified_at = NULL WHERE id = $1`, cs[0].org)
		review := h.review(t, art, "body-unverified", "approved")
		_, err := h.publish(art, review, "body-unverified", span5(cs))
		wantPgErr(t, err, checkViolation, "intersection-reconstruction: 1 span(s)")
		if _, err := h.publish(art, review, "body-unverified", [][]uuid.UUID{ids(cs[:6])}); err != nil {
			t.Fatalf("5 verified of 6 must pass: %v", err)
		}
	})

	// FIXED (c): a body with no spans is not a reconstructed body.
	t.Run("zero_spans_refused", func(t *testing.T) {
		art, _ := h.artifact(t, 25)
		review := h.review(t, art, "body-nospan", "approved")
		_, err := h.publish(art, review, "body-nospan", nil)
		wantPgErr(t, err, checkViolation, "has no spans")
	})

	// A producer row citing another artifact's contribution proves nothing for this span.
	t.Run("foreign_artifact_contribution_does_not_produce_a_span", func(t *testing.T) {
		art, cs := h.artifact(t, 25)
		_, foreign := h.artifact(t, 25)
		review := h.review(t, art, "body-foreign", "approved")
		_, err := h.publish(art, review, "body-foreign", [][]uuid.UUID{append(ids(cs[:4]), foreign[0].contribution)})
		wantPgErr(t, err, checkViolation, "intersection-reconstruction: 1 span(s)")
	})
}

// -----------------------------------------------------------------------------
// FR-FED-006: 'invariant' is excluded by CHECK at both federation sites
// (m1_041:61, :81), by the composite FK that binds the label to the artifact
// row (:64, :82), and by m1_040:82 which stops kind/abstraction mislabeling.
// -----------------------------------------------------------------------------
func TestIntegrationInvariantArtifactsAreExcludedBySchema(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	var inv uuid.UUID
	if err := h.admin.QueryRow(ctx,
		`INSERT INTO memory_artifacts (tenant_id, abstraction, kind, body) VALUES ($1, 'invariant', 'invariant', '{}') RETURNING id`,
		h.owner.UUID()).Scan(&inv); err != nil {
		t.Fatal(err)
	}

	_, err := h.fed.Exec(ctx, `INSERT INTO publication_review_queue (artifact_id, abstraction, candidate_body) VALUES ($1, 'invariant', 'x')`, inv)
	wantPgErr(t, err, checkViolation, `"publication_review_queue_abstraction_check"`) // m1_041:61
	_, err = h.fed.Exec(ctx, `
		INSERT INTO artifact_publications (artifact_id, abstraction, review_id, body, epsilon_spent, receipt_id)
		VALUES ($1, 'invariant', gen_random_uuid(), 'x', 0, gen_random_uuid())`, inv)
	wantPgErr(t, err, checkViolation, `"artifact_publications_abstraction_check"`) // m1_041:81
	// The package path carries the artifact's OWN abstraction, so the CHECK is what refuses.
	_, err = h.publish(inv, uuid.New(), "x", nil)
	wantPgErr(t, err, checkViolation, `"artifact_publications_abstraction_check"`)
	// Relabeling the queue row 'pattern' does not dodge it: the composite FK
	// binds the abstraction to the artifact row (m1_041:64).
	_, err = h.fed.Exec(ctx, `INSERT INTO publication_review_queue (artifact_id, abstraction, candidate_body) VALUES ($1, 'pattern', 'x')`, inv)
	wantPgErr(t, err, "23503", "publication_review_queue")
	// And relabeling the artifact itself 'pattern' while kind stays 'invariant'
	// fails m1_040:82.
	_, err = h.admin.Exec(ctx, `UPDATE memory_artifacts SET abstraction = 'pattern' WHERE id = $1`, inv)
	wantPgErr(t, err, checkViolation, `"invariant_kinds_agree"`) // m1_040:82
}

// -----------------------------------------------------------------------------
// FR-FED-005 / NFR-PRIVACY-003: the ε debit is the gate trigger's own last
// step (m1_064 (g)). A publication cannot commit without one ledger row per
// counted tenant, and a refused debit rolls the publication back.
// -----------------------------------------------------------------------------
func TestIntegrationPublicationRequiresLedgerDebit(t *testing.T) {
	h := setup(t)
	ctx := context.Background()

	t.Run("every_counted_tenant_is_charged_in_the_publication_transaction", func(t *testing.T) {
		art, cs := h.artifact(t, 25)
		review := h.review(t, art, "body-debit", "approved")
		pub, err := h.publish(art, review, "body-debit", span5(cs))
		if err != nil {
			t.Fatal(err)
		}
		var n int
		var eps, sum string
		if err := h.admin.QueryRow(ctx,
			`SELECT count(*), min(epsilon)::text, sum(epsilon)::text FROM epsilon_ledger WHERE publication_id = $1 AND mechanism = $2`,
			pub, dprelease.Mechanism).Scan(&n, &eps, &sum); err != nil || n != 25 || eps != "0.100000" || sum != "2.500000" {
			t.Fatalf("ledger for %s: n=%d min=%s sum=%s err=%v", pub, n, eps, sum, err)
		}
		if n := h.count(t, `SELECT count(*) FROM epsilon_ledger l JOIN artifact_contributions c ON c.tenant_id = l.tenant_id AND c.artifact_id = $1 WHERE l.publication_id = $2`, art, pub); n != 25 {
			t.Fatalf("%d ledger rows belong to contributors, want 25", n)
		}
		// A second charge for the same (tenant, publication) is unexpressible.
		_, err = h.admin.Exec(ctx, `SELECT fed_debit_epsilon($1, ARRAY[$2::uuid], 0.1, gen_random_uuid())`, pub, cs[0].tenant)
		wantPgErr(t, err, "23505", "uq_epsilon_ledger_publication")
	})

	t.Run("contributor_without_a_budget_row_refuses_the_publication", func(t *testing.T) {
		art, cs := h.artifact(t, 25)
		h.exec(t, `DELETE FROM tenant_privacy_budgets WHERE tenant_id = $1`, cs[3].tenant)
		review := h.review(t, art, "body-nobudget", "approved")
		_, err := h.publish(art, review, "body-nobudget", span5(cs))
		wantPgErr(t, err, checkViolation, "no privacy budget provisioned")
		if n := h.count(t, `SELECT count(*) FROM artifact_publications WHERE artifact_id = $1`, art); n != 0 {
			t.Fatal("publication persisted without its debit")
		}
		if n := h.count(t, `SELECT count(*) FROM epsilon_ledger l JOIN artifact_contributions c ON c.tenant_id = l.tenant_id WHERE c.artifact_id = $1`, art); n != 0 {
			t.Fatalf("%d partial debits survived the rollback", n)
		}
	})

	t.Run("exhausted_contributor_refuses_the_publication_and_no_debit_lands", func(t *testing.T) {
		art, cs := h.artifact(t, 25)
		h.exec(t, `INSERT INTO epsilon_ledger (tenant_id, mechanism, epsilon, receipt_id) VALUES ($1, 'laplace_int', 3.95, gen_random_uuid())`, cs[7].tenant)
		review := h.review(t, art, "body-exhausted", "approved")
		_, err := h.publish(art, review, "body-exhausted", span5(cs))
		wantPgErr(t, err, checkViolation, "privacy budget exhausted")
		if n := h.count(t, `SELECT count(*) FROM artifact_publications WHERE artifact_id = $1`, art); n != 0 {
			t.Fatal("publication persisted past an exhausted budget")
		}
		if n := h.count(t, `SELECT count(*) FROM epsilon_ledger WHERE publication_id IS NOT NULL AND tenant_id = ANY($1)`, tenantsOf(cs)); n != 0 {
			t.Fatalf("%d debits landed for a refused release", n)
		}
	})

	t.Run("zero_epsilon_publication_is_refused", func(t *testing.T) {
		art, cs := h.artifact(t, 25)
		review := h.review(t, art, "body-zero", "approved")
		_, err := h.w.Publish(ctx, dprelease.Publication{ArtifactID: art, ReviewID: review, ReceiptID: uuid.New(), Body: "body-zero", Spans: span5(cs), Epsilon: 0})
		wantPgErr(t, err, checkViolation, "epsilon_ledger_epsilon_check")
	})

	// Negative control: with the gate off, the same row commits with NO ledger
	// rows — the debit is the trigger's, not the fixture's.
	t.Run("negative_control_gate_disabled_commits_without_debit", func(t *testing.T) {
		art, _ := h.artifact(t, 25)
		review := h.review(t, art, "body-control", "approved")
		tx, err := h.admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, `ALTER TABLE artifact_publications DISABLE TRIGGER km_publication_gate`); err != nil {
			t.Fatal(err)
		}
		var pub uuid.UUID
		if err := tx.QueryRow(ctx, `
			INSERT INTO artifact_publications (artifact_id, abstraction, review_id, body, epsilon_spent, receipt_id)
			VALUES ($1, 'pattern', $2, 'body-control', 0.1, gen_random_uuid()) RETURNING id`, art, review).Scan(&pub); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `SET CONSTRAINTS ALL IMMEDIATE`); err != nil {
			t.Fatal(err)
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM epsilon_ledger WHERE publication_id = $1`, pub).Scan(&n); err != nil || n != 0 {
			t.Fatalf("gate off yet %d debits (err=%v): the coupling is not the trigger", n, err)
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		h.triggerEnabled(t, "km_publication_gate")
	})
}

func tenantsOf(cs []contributor) []uuid.UUID {
	out := make([]uuid.UUID, len(cs))
	for i, c := range cs {
		out[i] = c.tenant
	}
	return out
}

// -----------------------------------------------------------------------------
// FIXED (d): published evidence is append-only at the trigger layer, binding
// the owner, on all three publication tables (m1_064).
// -----------------------------------------------------------------------------
func TestIntegrationPublicationsAreAppendOnly(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	art, cs := h.artifact(t, 25)
	review := h.review(t, art, "body-ao", "approved")
	pub, err := h.publish(art, review, "body-ao", span5(cs))
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.fed.Exec(ctx, `UPDATE artifact_publications SET body = 'x' WHERE id = $1`, pub)
	wantPgErr(t, err, "42501", "permission denied")
	for _, stmt := range []string{
		`UPDATE artifact_publications SET body = 'x' WHERE id = $1`,
		`DELETE FROM artifact_publications WHERE id = $1`,
		`UPDATE publication_spans SET span_index = 9 WHERE publication_id = $1`,
		`DELETE FROM publication_spans WHERE publication_id = $1`,
		`UPDATE publication_span_producers SET span_index = 9 WHERE publication_id = $1`,
		`DELETE FROM publication_span_producers WHERE publication_id = $1`,
	} {
		_, err := h.admin.Exec(ctx, stmt, pub)
		wantPgErr(t, err, checkViolation, "append-only")
	}
	// Postgres checks FK references before BEFORE TRUNCATE fires, so the referenced tables are truncated with their referrers.
	_, err = h.admin.Exec(ctx, `TRUNCATE publication_span_producers`)
	wantPgErr(t, err, checkViolation, "publication_span_producers is append-only")
	_, err = h.admin.Exec(ctx, `TRUNCATE artifact_publications, publication_spans, publication_span_producers, epsilon_ledger`)
	wantPgErr(t, err, checkViolation, "append-only")
}

// -----------------------------------------------------------------------------
// NFR-PRIVACY-003: the ε ledger (m1_041:246-272). Advisory-lock serialized,
// fail-closed on a missing budget row, fail-closed on a GUC mismatch via RLS,
// append-only at the trigger layer as well as the grant layer.
// -----------------------------------------------------------------------------
func TestIntegrationEpsilonLedgerExhaustionIsSerialized(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	h.exec(t, `INSERT INTO tenant_privacy_budgets (tenant_id, epsilon_cap) VALUES ($1, 1.0)`, h.owner.UUID())
	spend := func(tenant querychoke.TenantID, rowTenant uuid.UUID, eps string, gate <-chan struct{}) error {
		return h.intel.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
			if gate != nil {
				<-gate
			}
			_, err := tx.Exec(ctx,
				`INSERT INTO epsilon_ledger (tenant_id, mechanism, epsilon, receipt_id) VALUES ($1, 'laplace_int', $2, gen_random_uuid())`,
				rowTenant, eps)
			return err
		})
	}
	sum := func() string {
		var s string
		if err := h.admin.QueryRow(ctx, `SELECT coalesce(sum(epsilon), 0)::text FROM epsilon_ledger WHERE tenant_id = $1`, h.owner.UUID()).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}

	t.Run("two_concurrent_debits_over_cap_exactly_one_commits", func(t *testing.T) {
		start := make(chan struct{})
		errs := make([]error, 2)
		var wg sync.WaitGroup
		for i := range errs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs[i] = spend(h.owner, h.owner.UUID(), "0.6", start)
			}()
		}
		close(start)
		wg.Wait()
		ok, refused := 0, 0
		for _, err := range errs {
			if err == nil {
				ok++
				continue
			}
			wantPgErr(t, err, checkViolation, "privacy budget exhausted")
			refused++
		}
		if ok != 1 || refused != 1 {
			t.Fatalf("ok=%d refused=%d: %v", ok, refused, errs)
		}
		if s := sum(); s != "0.600000" {
			t.Fatalf("ledger sum %s; the cap is 1.0 and a second 0.6 landed", s)
		}
	})

	t.Run("exactly_reaching_the_cap_is_allowed_crossing_it_is_not", func(t *testing.T) {
		if err := spend(h.owner, h.owner.UUID(), "0.4", nil); err != nil {
			t.Fatalf("0.6 + 0.4 = cap must pass (m1_041:261 is strict >): %v", err)
		}
		wantPgErr(t, spend(h.owner, h.owner.UUID(), "0.000001", nil), checkViolation, "privacy budget exhausted")
	})

	t.Run("no_budget_row_means_no_spending", func(t *testing.T) {
		wantPgErr(t, spend(h.other, h.other.UUID(), "0.000001", nil), checkViolation, "no privacy budget provisioned")
	})

	// m1_041:216-219: a caller whose GUC is another tenant sees no budget row
	// under RLS, so the trigger refuses BEFORE the RLS WITH CHECK ever runs.
	t.Run("guc_mismatch_fails_closed_through_rls", func(t *testing.T) {
		wantPgErr(t, spend(h.other, h.owner.UUID(), "0.000001", nil), checkViolation, "no privacy budget provisioned")
	})

	t.Run("negative_control_trigger_disabled_by_owner_admits_the_over_budget_row", func(t *testing.T) {
		_, err := h.intelPool.Exec(ctx, `ALTER TABLE epsilon_ledger DISABLE TRIGGER epsilon_budget_gate`)
		wantPgErr(t, err, "42501", "must be owner")
		tx, err := h.admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, `ALTER TABLE epsilon_ledger DISABLE TRIGGER epsilon_budget_gate`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO epsilon_ledger (tenant_id, mechanism, epsilon, receipt_id) VALUES ($1, 'laplace_int', 5.0, gen_random_uuid())`,
			h.owner.UUID()); err != nil {
			t.Fatalf("with the trigger off the fixture itself refuses — the refusals above were not the trigger: %v", err)
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		var state string
		if err := h.admin.QueryRow(ctx, `SELECT tgenabled::text FROM pg_trigger WHERE tgname = 'epsilon_budget_gate'`).Scan(&state); err != nil || state != "O" {
			t.Fatalf("epsilon_budget_gate enabled=%q err=%v", state, err)
		}
		if s := sum(); s != "1.000000" {
			t.Fatalf("control leaked into the ledger: sum=%s", s)
		}
	})

	t.Run("append_only_binds_the_owner_too", func(t *testing.T) {
		for _, stmt := range []string{
			`UPDATE epsilon_ledger SET epsilon = 0 WHERE tenant_id = $1`,
			`DELETE FROM epsilon_ledger WHERE tenant_id = $1`,
		} {
			_, err := h.admin.Exec(ctx, stmt, h.owner.UUID())
			wantPgErr(t, err, checkViolation, "append-only")
		}
		_, err := h.admin.Exec(ctx, `TRUNCATE epsilon_ledger`)
		wantPgErr(t, err, checkViolation, "append-only")
	})
}

// -----------------------------------------------------------------------------
// CON-011: publication_review_queue.decided_is_attributed (m1_041:72) and the
// trigger's review checks.
// -----------------------------------------------------------------------------
func TestIntegrationReviewQueueRequiresReviewer(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	art, cs := h.artifact(t, 25)

	for _, c := range []struct{ name, cols, vals string }{
		{"approved_without_reviewer", "state, decided_at", "'approved', now()"},
		{"approved_without_decided_at", "state, reviewer", "'approved', 'reviewer@omium.test'"},
		{"rejected_without_reviewer", "state, decided_at", "'rejected', now()"},
	} {
		t.Run(c.name+"_refused", func(t *testing.T) {
			_, err := h.fed.Exec(ctx, fmt.Sprintf(
				`INSERT INTO publication_review_queue (artifact_id, abstraction, candidate_body, %s) VALUES ($1, 'pattern', 'x', %s)`, c.cols, c.vals), art)
			wantPgErr(t, err, checkViolation, `"decided_is_attributed"`) // m1_041:72
		})
	}

	t.Run("pending_row_needs_no_reviewer_but_cannot_be_published_against", func(t *testing.T) {
		pending := h.review(t, art, "body-pending", "pending")
		_, err := h.publish(art, pending, "body-pending", span5(cs))
		wantPgErr(t, err, checkViolation, "which is not approved")
		// Approving it without attribution is refused on UPDATE as well.
		_, err = h.fed.Exec(ctx, `UPDATE publication_review_queue SET state = 'approved' WHERE id = $1`, pending)
		wantPgErr(t, err, checkViolation, "decided_is_attributed")
	})

	t.Run("published_bytes_must_equal_the_reviewed_bytes", func(t *testing.T) {
		review := h.review(t, art, "body-exact", "approved")
		_, err := h.publish(art, review, "body-exact ", span5(cs))
		wantPgErr(t, err, checkViolation, "differs from the reviewed bytes")
	})
}

// -----------------------------------------------------------------------------
// RLS where 07 puts it: artifact_contributions (m1_040:145-160) and the ε pair
// (m1_041:303-315) are tenant-scoped; the publication tables are global BY
// DESIGN (m1_041:14-18). The negative direction is the one that proves anything.
// FR-FED-007 rides the same harness: the tenant-visible read through the choke.
// -----------------------------------------------------------------------------
func TestIntegrationFederationRLS(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	art, cs := h.artifact(t, 25)
	review := h.review(t, art, "body-rls", "approved")
	pub, err := h.publish(art, review, "body-rls", span5(cs))
	if err != nil {
		t.Fatal(err)
	}
	h.exec(t, `INSERT INTO tenant_privacy_budgets (tenant_id, epsilon_cap) VALUES ($1, 1.0)`, h.owner.UUID())
	h.exec(t, `INSERT INTO epsilon_ledger (tenant_id, mechanism, epsilon, receipt_id) VALUES ($1, 'laplace_int', 0.1, gen_random_uuid())`, h.owner.UUID())
	tenantA, err := querychoke.FromClaims(auth.Claims{TenantID: cs[0].tenant, DeviceID: uuid.New()})
	if err != nil {
		t.Fatal(err)
	}

	count := func(t *testing.T, tenant *querychoke.TenantID, sql string) int64 {
		t.Helper()
		var n int64
		var qerr error
		if tenant == nil {
			qerr = h.intelPool.QueryRow(ctx, sql).Scan(&n)
		} else {
			qerr = h.intel.WithTenant(ctx, *tenant, func(tx pgx.Tx) error { return tx.QueryRow(ctx, sql).Scan(&n) })
		}
		if qerr != nil {
			t.Fatal(qerr)
		}
		return n
	}

	for _, tc := range []struct {
		table  string
		tenant *querychoke.TenantID
		want   int64
	}{
		{"artifact_contributions", &tenantA, 1}, // its own row: the policy admits somebody
		{"artifact_contributions", &h.other, 0}, // tenant B, GUC set to B, sees none of A's
		{"artifact_contributions", nil, 0},      // unset GUC: the NULLIF floor
		{"epsilon_ledger", &tenantA, 1},         // its own debit for pub
		{"epsilon_ledger", &h.owner, 1},
		{"epsilon_ledger", &h.other, 0},
		{"epsilon_ledger", nil, 0}, // the 26 rows exist; an unset GUC sees none
		{"tenant_privacy_budgets", &h.other, 0},
		{"artifact_publications", nil, 1}, // no tenant column, no RLS: global by design
	} {
		name := tc.table + "/no-guc"
		if tc.tenant != nil {
			name = tc.table + "/" + tc.tenant.String()[:8]
		}
		if n := count(t, tc.tenant, `SELECT count(*) FROM `+tc.table); n != tc.want {
			t.Fatalf("%s: saw %d rows, want %d", name, n, tc.want)
		}
	}

	// FR-FED-007: the (k,m) defaults and ε balance a contributing tenant sees.
	b, err := dprelease.ReadBudget(ctx, h.intel, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	if b.K != 25 || b.M != 5 || b.EpsilonCap != 4.0 || b.EpsilonSpent != 0.1 || len(b.Ledger) != 1 {
		t.Fatalf("budget for A: %+v", b)
	}
	if b.Ledger[0].PublicationID == nil || *b.Ledger[0].PublicationID != pub || b.Ledger[0].Mechanism != dprelease.Mechanism {
		t.Fatalf("ledger row for A: %+v", b.Ledger[0])
	}
	if _, err := dprelease.ReadBudget(ctx, h.intel, h.other); !errors.Is(err, dprelease.ErrNoBudget) {
		t.Fatalf("tenant B (no budget, no rows): err=%v", err)
	}

	// The one sanctioned cross-tenant read: the federation worker sees every
	// contribution, which is what count(DISTINCT tenant_id) needs (m1_060:62).
	var n int64
	if err := h.fed.QueryRow(ctx, `SELECT count(*) FROM artifact_contributions WHERE artifact_id = $1`, art).Scan(&n); err != nil || n != 25 {
		t.Fatalf("federation worker saw %d contributions, want 25 (err=%v)", n, err)
	}
	// And nothing on the ledger: its bypass is scoped to the federation read set (m1_060:211-214).
	_, err = h.fed.Exec(ctx, `SELECT count(*) FROM epsilon_ledger`)
	wantPgErr(t, err, "42501", "permission denied")
	// Nor on the tenant registry beyond the three opt-out columns (m1_064).
	_, err = h.fed.Exec(ctx, `SELECT oidc_client_secret_ref FROM m1_tenants`)
	wantPgErr(t, err, "42501", "permission denied")
	// The debit definer is the worker's alone: intel_app cannot burn a budget through it.
	_, err = h.intelPool.Exec(ctx, `SELECT fed_debit_epsilon($1, ARRAY[$2::uuid], 0.1, gen_random_uuid())`, pub, h.owner.UUID())
	wantPgErr(t, err, "42501", "permission denied for function fed_debit_epsilon")
}
