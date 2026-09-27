//go:build integration

package appapi

// m1_105 under FORCE RLS: every "latest row" read takes the row written last (row_seq), never the newest timestamp, so a clock stepped backwards between writes cannot resurrect the older one.

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
)

func TestIntegrationLatestRowsAreTheLastWrittenWhateverTheClockSays(t *testing.T) {
	r := setupPG(t)
	ctx := context.Background()
	tenant := r.tenant("rowseq", "us-east-1")

	device := r.enrollDevice(tenant, "omium:alice", "approved")
	code, tok, pub := make([]byte, 32), make([]byte, 32), make([]byte, 32)
	for _, b := range [][]byte{code, tok, pub} {
		_, _ = rand.Read(b)
	}
	if _, err := r.admin.Exec(ctx, `UPDATE m1_device_enrollments SET status = 'revoked' WHERE device_id = $1`, device); err != nil {
		t.Fatal(err)
	}
	if _, err := r.admin.Exec(ctx, `INSERT INTO m1_device_enrollments (tenant_id, device_id, device_code_hash, token_hash, device_pubkey, oidc_subject, status, started_at, token_expires_at)
		VALUES ($1, $2, $3, $4, $5, 'omium:carol', 'approved', now() - interval '1 hour', now())`, tenant, device, code, tok, pub); err != nil {
		t.Fatal(err)
	}
	var owners map[string]string
	var subject string
	if err := r.db.WithTenant(ctx, r.tid(tenant), func(tx pgx.Tx) error {
		var err error
		if owners, err = deviceOwners(ctx, tx, tenant); err != nil {
			return err
		}
		subject, err = subjectOf(ctx, tx, auth.Claims{TenantID: tenant, DeviceID: device})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if owners[device.String()] != "omium:carol" || subject != "omium:carol" {
		t.Fatalf("a re-enrollment stamped an hour early lost to the older one: owners=%v subject=%q", owners, subject)
	}
	if v, err := querychoke.NewPGViewers(r.db).Viewer(ctx, r.tid(tenant), auth.Claims{TenantID: tenant, DeviceID: device}); err != nil || v.Subject != "omium:carol" {
		t.Fatalf("viewer of the re-enrolled device: %+v %v", v, err)
	}

	var verifier uuid.UUID
	if err := r.admin.QueryRow(ctx, `INSERT INTO m1_verifiers (verifier_key, kind, version, display_name, definition) VALUES ($1, 'judge', 1, 'j', '{}') RETURNING id`,
		"judge:rowseq-"+uuid.NewString()[:8]).Scan(&verifier); err != nil {
		t.Fatal(err)
	}
	var older, newer uuid.UUID
	for _, c := range []struct {
		id   *uuid.UUID
		skew string
	}{{&older, "0"}, {&newer, "-1 hour"}} {
		if err := r.admin.QueryRow(ctx, `INSERT INTO noise_certificates (tenant_id, verifier_id, status, issued_at, expires_at)
			VALUES ($1, $2, 'bootstrapping', now() + $3::interval, now() + interval '30 days') RETURNING id`, tenant, verifier, c.skew).Scan(c.id); err != nil {
			t.Fatal(err)
		}
	}
	certs := r.ok("/api/v1/verify/certificates", tenant, "certificates.json")["certificates"].([]any)
	if len(certs) != 2 || certs[0].(map[string]any)["id"] != newer.String() {
		t.Fatalf("the certificate written last lists first whatever its issued_at: %v", certs)
	}

	for _, s := range []struct {
		members int
		skew    string
	}{{3, "0"}, {5, "-1 hour"}} {
		var set uuid.UUID
		if err := r.admin.QueryRow(ctx, `INSERT INTO gold_sets (tenant_id, agent, frozen_at) VALUES ($1, 'claudecode', now() + $2::interval) RETURNING id`, tenant, s.skew).Scan(&set); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < s.members; i++ {
			digest := make([]byte, 32)
			_, _ = rand.Read(digest)
			if _, err := r.admin.Exec(ctx, `INSERT INTO gold_set_members (gold_set_id, tenant_id, task_digest, true_label, label_source) VALUES ($1, $2, $3, 'satisfied', 't3')`, set, tenant, digest); err != nil {
				t.Fatal(err)
			}
		}
	}
	if p := r.ok("/api/v1/verify/labels", tenant, "labels.json"); p["frozen"].(float64) != 5 {
		t.Fatalf("the snapshot frozen last is the one a certificate cites: %v", p)
	}
}

// appRoles are every runtime role a migration grants to; the migrator and the suite role are neither.
var appRoles = []string{"controld_app", "adjudicator_app", "intel_app", "mark1_federation_worker"}

// A column-level SELECT never covers a column added after it, so a role that reads a row_seq table through one would fail every ORDER BY row_seq in prod while a superuser test passes (the m1_090 intel_app grant did exactly that).
func TestIntegrationEveryRoleThatReadsARowSeqTableReadsRowSeq(t *testing.T) {
	r := setupPG(t)
	ctx := context.Background()
	rows, err := r.admin.Query(ctx, `SELECT table_name FROM information_schema.columns WHERE table_schema = 'public' AND column_name = 'row_seq' ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	tables, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	if len(tables) < 7 {
		t.Fatalf("m1_105's seven row_seq tables, found %v", tables)
	}
	for _, tbl := range tables {
		for _, role := range appRoles {
			var reads, readsSeq bool
			if err := r.admin.QueryRow(ctx, `SELECT has_any_column_privilege($1, $2, 'SELECT'), has_column_privilege($1, $2, 'row_seq', 'SELECT')`, role, tbl).Scan(&reads, &readsSeq); err != nil {
				t.Fatal(err)
			}
			if reads && !readsSeq {
				t.Errorf("%s reads %s but not its row_seq", role, tbl)
			}
		}
	}
	for q, want := range map[string]bool{
		`has_column_privilege('intel_app', 'm1_device_enrollments', 'row_seq', 'SELECT')`:    true,
		`has_column_privilege('intel_app', 'm1_device_enrollments', 'token_hash', 'SELECT')`: false,
		`has_table_privilege('intel_app', 'm1_device_enrollments', 'SELECT')`:                false,
	} {
		var got bool
		if err := r.admin.QueryRow(ctx, "SELECT "+q).Scan(&got); err != nil || got != want {
			t.Errorf("%s = %v (%v), want %v", q, got, err, want)
		}
	}
}

// The Python services' row_seq statements, verbatim, run AS the role that runs them in prod under the tenant GUC: a missing grant is `permission denied` here, not in the weekly digest. controld's own readers run as controld_app through setupPG's pool.
func TestIntegrationRowSeqReadersRunAsTheirProdRoles(t *testing.T) {
	r := setupPG(t)
	ctx := context.Background()
	tenant := r.tenant("rowseq-roles", "us-east-1")
	r.enrollDevice(tenant, "omium:alice", "approved")
	var set uuid.UUID
	if err := r.admin.QueryRow(ctx, `INSERT INTO gold_sets (tenant_id, agent) VALUES ($1, 'claudecode') RETURNING id`, tenant).Scan(&set); err != nil {
		t.Fatal(err)
	}
	type stmt struct {
		source, sql string
		args        []any
	}
	byRole := map[string][]stmt{
		"intel_app": {
			{"intel/app/digest/weekly.py _DEVICE_OWNERS", `SELECT DISTINCT ON (device_id) device_id::text AS device_id, oidc_subject
  FROM m1_device_enrollments
 WHERE tenant_id = $1 AND device_id IS NOT NULL AND oidc_subject IS NOT NULL
   AND status IN ('approved', 'revoked')
 ORDER BY device_id, row_seq DESC`, []any{tenant}},
			{"intel/app/memory/extract.py device_owners", "SELECT DISTINCT ON (device_id) device_id, oidc_subject FROM m1_device_enrollments " +
				"WHERE tenant_id = $1 AND device_id IS NOT NULL AND oidc_subject IS NOT NULL " +
				"AND status IN ('approved', 'revoked') ORDER BY device_id, row_seq DESC", []any{tenant}},
			{"intel/app/memory/retrieve.py LATEST_TEAM_CONSENT", "SELECT (SELECT c.team FROM m1_device_consents c JOIN m1_device_enrollments e " +
				"ON e.device_id = c.device_id AND e.tenant_id = c.tenant_id AND e.status = 'approved' " +
				"WHERE c.tenant_id = $1 AND e.oidc_subject = $2 ORDER BY c.row_seq DESC LIMIT 1)", []any{tenant, "omium:alice"}},
			{"intel/app/corpus/export.py training_consented", "SELECT bool_and(training) FROM (SELECT DISTINCT ON (device_id) training" +
				" FROM m1_device_consents WHERE tenant_id = $1" +
				" ORDER BY device_id, row_seq DESC) d", []any{tenant}},
			{"intel/app/corpus/contributions.py LIVE_ROWS", `SELECT c.event_id, c.batch_id, c.session_id, c.task_id, c.object_key, c.received_at
  FROM m1_outcome_contributions c
 WHERE c.withdrawn_at IS NULL AND c.deleted_at IS NULL
   AND coalesce((SELECT d.contribute_outcomes FROM m1_device_consents d
                  WHERE d.device_id = c.device_id ORDER BY d.row_seq DESC LIMIT 1), false)
   AND NOT EXISTS (SELECT 1 FROM m1_quarantined_batches q WHERE q.batch_id = c.batch_id)
 ORDER BY c.received_at, c.event_id`, nil},
		},
		"adjudicator_app": {
			{"adjudicator/app/rm/cloud.py cloud_devices", "SELECT DISTINCT ON (device_id) device_id, e1, cloud_rm FROM m1_device_consents " +
				"WHERE tenant_id = $1 ORDER BY device_id, row_seq DESC", []any{tenant}},
			{"adjudicator/app/jobs/nightly.py _latest_set", "SELECT id, agent, frozen_at FROM gold_sets WHERE tenant_id = $1 " +
				"AND (frozen_at IS NOT NULL) = $2 ORDER BY row_seq DESC LIMIT 1", []any{tenant, true}},
			{"adjudicator/app/jobs/nightly.py gold_refresh", "SELECT id, agent FROM gold_sets WHERE tenant_id = $1 AND frozen_at IS NULL " +
				"ORDER BY row_seq", []any{tenant}},
			{"adjudicator/app/jobs/nightly.py _gold_labels", "SELECT DISTINCT ON (task_digest) task_digest, true_label::text AS true_label " +
				"FROM gold_set_members WHERE tenant_id = $1 AND label_source IN ('t3', 'human') " +
				"ORDER BY task_digest, row_seq DESC", []any{tenant}},
			{"adjudicator/app/certs/store.py latest", `SELECT id, status, rho_plus, rho_minus, natarajan_lcb, issued_at, expires_at
            FROM noise_certificates
            WHERE tenant_id = $1
            ORDER BY (status = 'certified' AND expires_at > now()) DESC,
                     row_seq DESC
            LIMIT 1`, []any{tenant}},
			{"adjudicator/app/gold/select.py add members", `INSERT INTO gold_set_members
              (gold_set_id, tenant_id, task_digest, true_label, label_source)
            VALUES ($1, $2, $3, $4::verdict, $5)
            ON CONFLICT (gold_set_id, task_digest)
              DO UPDATE SET true_label = EXCLUDED.true_label,
                            label_source = EXCLUDED.label_source,
                            labeled_at = now(),
                            row_seq = DEFAULT`, []any{set, tenant, make([]byte, 32), "satisfied", "t3"}},
			{"adjudicator/app/gold/select.py freeze_gold_set", "UPDATE gold_sets SET frozen_at = now(), row_seq = DEFAULT " +
				"WHERE id = $1 AND frozen_at IS NULL", []any{set}},
		},
	}
	for role, stmts := range byRole {
		for _, s := range stmts {
			tx, err := r.admin.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			_, err = tx.Exec(ctx, "SET LOCAL ROLE "+role)
			if err == nil {
				_, err = tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tenant.String())
			}
			if err == nil {
				_, err = tx.Exec(ctx, s.sql, s.args...)
			}
			_ = tx.Rollback(ctx)
			if err != nil {
				t.Errorf("%s as %s: %v", s.source, role, err)
			}
		}
	}
}

// m1_105 numbers every existing row, so a migration role that FORCE RLS would filter must fail the file outright (row_security = off), never number nothing and leave the table half-migrated.
func TestIntegrationRowSeqBackfillRefusesARoleThatCannotSeeEveryRow(t *testing.T) {
	dsn := os.Getenv("M1_MIGRATE_PG_DSN")
	if dsn == "" {
		if os.Getenv("M1_REQUIRE_STORES") == "1" {
			t.Fatal("M1_MIGRATE_PG_DSN required (M1_REQUIRE_STORES=1) but unset")
		}
		t.Skip("M1_MIGRATE_PG_DSN unset; skipping Postgres-backed test")
	}
	ctx := context.Background()
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	boot, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	scratch := fmt.Sprintf("controld_rowseq_rls_%d", time.Now().UnixNano())
	migrator := "m1_105_nobypass_" + strconv.FormatInt(time.Now().UnixNano(), 36)
	if _, err := boot.Exec(ctx, "CREATE DATABASE "+scratch); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = boot.Exec(c, "DROP DATABASE IF EXISTS "+scratch+" WITH (FORCE)")
		_, _ = boot.Exec(c, "DROP ROLE IF EXISTS "+migrator)
		_ = boot.Close(c)
	})
	sc := cfg.Copy()
	sc.Database = scratch
	admin, err := pgx.ConnectConfig(ctx, sc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	if _, err := boot.Exec(ctx, `SELECT pg_advisory_lock(7231060)`); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join("..", "..", "..", "..", "migrations", "m1_[0-9]*.sql"))
	sort.Strings(files)
	var m105 string
	for _, f := range files {
		base := filepath.Base(f)
		if base >= "m1_105" {
			if strings.HasPrefix(base, "m1_105_") {
				m105 = f
			}
			continue
		}
		sql, err := os.ReadFile(f)
		if err == nil {
			_, err = admin.Exec(ctx, string(sql))
		}
		if err != nil {
			_, _ = boot.Exec(ctx, `SELECT pg_advisory_unlock(7231060)`)
			t.Fatalf("%s: %v", base, err)
		}
	}
	_, roleErr := admin.Exec(ctx, "CREATE ROLE "+migrator+" NOBYPASSRLS NOSUPERUSER")
	if _, err := boot.Exec(ctx, `SELECT pg_advisory_unlock(7231060)`); err != nil || roleErr != nil {
		t.Fatal(err, roleErr)
	}
	var org, tenant uuid.UUID
	if err := admin.QueryRow(ctx, `INSERT INTO m1_organizations (name, primary_domain) VALUES ('rls', 'rls.example') RETURNING id`).Scan(&org); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `INSERT INTO m1_tenants (org_id, name, region) VALUES ($1, 'rls', 'us-east-1') RETURNING id`, org).Scan(&tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `INSERT INTO gold_sets (tenant_id, agent) VALUES ($1, 'claudecode')`, tenant); err != nil {
		t.Fatal(err)
	}
	for _, tbl := range []string{"m1_device_consents", "m1_device_enrollments", "bundle_acks", "gold_sets", "gold_set_members", "noise_certificates", "m1_verifier_promotion_transitions"} {
		if _, err := admin.Exec(ctx, "ALTER TABLE "+tbl+" OWNER TO "+migrator); err != nil {
			t.Fatal(err)
		}
	}
	sql, err := os.ReadFile(m105)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, "SET ROLE "+migrator); err != nil {
		t.Fatal(err)
	}
	_, err = admin.Exec(ctx, string(sql))
	_, _ = admin.Exec(ctx, "ROLLBACK")
	if _, rerr := admin.Exec(ctx, "RESET ROLE"); rerr != nil {
		t.Fatal(rerr)
	}
	if err == nil || !strings.Contains(err.Error(), "row-level security") {
		t.Fatalf("m1_105 as a role FORCE RLS filters: %v, want the row-level security refusal", err)
	}
	var added bool
	if err := admin.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE column_name = 'row_seq' AND table_schema = 'public')`).Scan(&added); err != nil || added {
		t.Fatalf("the refused run left row_seq behind: %v %v", added, err)
	}
	for i := 0; i < 2; i++ {
		if _, err := admin.Exec(ctx, string(sql)); err != nil {
			t.Fatalf("m1_105 run %d as a role that sees every row: %v", i+1, err)
		}
	}
	var seq *int64
	if err := admin.QueryRow(ctx, `SELECT row_seq FROM gold_sets WHERE tenant_id = $1`, tenant).Scan(&seq); err != nil || seq == nil || *seq != 1 {
		t.Fatalf("backfilled row_seq %v (%v), want 1", seq, err)
	}
}
