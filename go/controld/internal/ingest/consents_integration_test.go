//go:build integration

package ingest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/receipts"
)

// TestIntegrationDeviceConsentsLandAppendOnlyUnderRLS: PUT /api/v1/consents
// under the device token writes one m1_082 row per call as the NOBYPASSRLS
// controld role; the latest row per device is the state intel reads
// (training_consented's query), history stays, nothing updates or deletes,
// and the other tenant sees no row.
func TestIntegrationDeviceConsentsLandAppendOnlyUnderRLS(t *testing.T) {
	q := setupQuarantinePG(t)
	mux := http.NewServeMux()
	New(Deps{
		Verifier: auth.NewHMACVerifier(testKey, auth.StaticRevocations{}),
		ObsCfg:   obs.Config{ServiceName: "controld-test"},
		PG:       fakeReady{}, Store: newFakeStore(), DB: q.db,
	}).RegisterRoutes(mux)
	token := auth.Mint(testKey, q.tenantA.UUID(), q.deviceA, time.Hour)
	put := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPut, "/api/v1/consents", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}
	for _, body := range []string{`{"e1":true,"cloud_judge":true,"training":true,"team":true}`, `{"e1":true,"cloud_judge":false,"training":false}`, `{"e1":true,"cloud_judge":false,"training":false,"team":false}`} {
		if rec := put(body); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "recorded_at") {
			t.Fatalf("%s: %d %s", body, rec.Code, rec.Body.String())
		}
	}
	ctx := context.Background()
	var n int
	if err := q.admin.QueryRow(ctx, `SELECT count(*) FROM m1_device_consents WHERE device_id = $1`, q.deviceA).Scan(&n); err != nil || n != 3 {
		t.Fatalf("rows = %d %v, want 3 (history kept)", n, err)
	}
	var teams []bool
	rows, err := q.admin.Query(ctx, `SELECT team FROM m1_device_consents WHERE device_id = $1 ORDER BY row_seq`, q.deviceA)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var b bool
		_ = rows.Scan(&b)
		teams = append(teams, b)
	}
	if len(teams) != 3 || !teams[0] || !teams[1] || teams[2] {
		t.Fatalf("team column: %v, want [true true false] (absent keeps the device's value, explicit false turns it off)", teams)
	}
	// intel's read (python/intel/app/corpus/export.py training_consented), run as the app role under tenant A's GUC.
	const latest = `SELECT bool_and(training) FROM (SELECT DISTINCT ON (device_id) training FROM m1_device_consents ORDER BY device_id, row_seq DESC) d`
	var training *bool
	if err := q.db.WithTenant(ctx, q.tenantA, func(tx pgx.Tx) error { return tx.QueryRow(ctx, latest).Scan(&training) }); err != nil {
		t.Fatal(err)
	}
	if training == nil || *training {
		t.Fatalf("latest row per device wins: training = %v, want false", training)
	}
	if err := q.db.WithTenant(ctx, q.tenantB, func(tx pgx.Tx) error { return tx.QueryRow(ctx, latest).Scan(&training) }); err != nil {
		t.Fatal(err)
	}
	if training != nil {
		t.Fatalf("tenant B read tenant A's consent through RLS: %v", *training)
	}
	if _, err := q.admin.Exec(ctx, `UPDATE m1_device_consents SET training = true WHERE device_id = $1`, q.deviceA); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("UPDATE must be refused: %v", err)
	}
	if _, err := q.admin.Exec(ctx, `DELETE FROM m1_device_consents WHERE device_id = $1`, q.deviceA); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("DELETE must be refused: %v", err)
	}
}

// TestIntegrationTheLastWrittenConsentWinsWhateverItsClockSays: every m1_082 reader takes the row written last (row_seq, m1_105), so a withdrawal or re-grant stamped earlier by a stepped-back clock still wins.
func TestIntegrationTheLastWrittenConsentWinsWhateverItsClockSays(t *testing.T) {
	q := setupQuarantinePG(t)
	ctx := context.Background()
	store := newFakeStore()
	m := New(Deps{
		Verifier: auth.NewHMACVerifier(testKey, auth.StaticRevocations{}),
		ObsCfg:   obs.Config{ServiceName: "controld-test"},
		PG:       fakeReady{}, Store: store, DB: q.db,
	})
	record := func(on bool, skew string) {
		t.Helper()
		if _, err := q.admin.Exec(ctx, `INSERT INTO m1_device_consents (tenant_id, device_id, e1, cloud_judge, training, contribute_outcomes, recorded_at)
			VALUES ($1, $2, $3, $3, $3, $3, now() + $4::interval)`, q.tenantA.UUID(), q.deviceA, on, skew); err != nil {
			t.Fatal(err)
		}
	}
	state := func() (bool, bool, bool) {
		t.Helper()
		e1, err := m.e1Consented(ctx, q.tenantA, q.deviceA)
		if err != nil {
			t.Fatal(err)
		}
		contrib, err := m.contributionConsented(ctx, false, q.tenantA, q.deviceA)
		if err != nil {
			t.Fatal(err)
		}
		var training *bool
		if err := q.db.WithTenant(ctx, q.tenantA, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT bool_and(training) FROM (SELECT DISTINCT ON (device_id) training FROM m1_device_consents ORDER BY device_id, row_seq DESC) d`).Scan(&training)
		}); err != nil {
			t.Fatal(err)
		}
		return e1, contrib, training != nil && *training
	}

	record(true, "0")
	if e1, c, tr := state(); !e1 || !c || !tr {
		t.Fatalf("granted: e1=%v contribute=%v training=%v", e1, c, tr)
	}
	key := "contrib/clock-step"
	if _, err := q.admin.Exec(ctx, `INSERT INTO m1_outcome_contributions (tenant_id, event_id, batch_id, device_id, session_id, task_id, object_key)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`, q.tenantA.UUID(), uuid.New(), uuid.New(), q.deviceA, uuid.New(), uuid.New(), key); err != nil {
		t.Fatal(err)
	}
	record(false, "-1 hour")
	if e1, c, tr := state(); e1 || c || tr {
		t.Fatalf("a withdrawal stamped an hour early lost to the grant: e1=%v contribute=%v training=%v", e1, c, tr)
	}
	sweep := NewQuarantineSweep(q.db, store, q.chain, receipts.StaticTenants([]uuid.UUID{q.tenantA.UUID()}))
	if n, err := sweep.SweepContributions(ctx, q.tenantA.UUID()); err != nil || n != 1 {
		t.Fatalf("the sweep missed the early-stamped withdrawal: %d %v", n, err)
	}
	record(true, "-2 hours")
	if e1, c, tr := state(); !e1 || !c || !tr {
		t.Fatalf("a re-grant stamped two hours early lost to the withdrawal: e1=%v contribute=%v training=%v", e1, c, tr)
	}
}
