//go:build integration

package ingest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
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
	for _, body := range []string{`{"e1":true,"cloud_judge":true,"training":true,"team":true}`, `{"e1":true,"cloud_judge":false,"training":false}`} {
		if rec := put(body); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "recorded_at") {
			t.Fatalf("%s: %d %s", body, rec.Code, rec.Body.String())
		}
	}
	ctx := context.Background()
	var n int
	if err := q.admin.QueryRow(ctx, `SELECT count(*) FROM m1_device_consents WHERE device_id = $1`, q.deviceA).Scan(&n); err != nil || n != 2 {
		t.Fatalf("rows = %d %v, want 2 (history kept)", n, err)
	}
	var teams []bool
	rows, err := q.admin.Query(ctx, `SELECT team FROM m1_device_consents WHERE device_id = $1 ORDER BY recorded_at`, q.deviceA)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var b bool
		_ = rows.Scan(&b)
		teams = append(teams, b)
	}
	if len(teams) != 2 || !teams[0] || teams[1] {
		t.Fatalf("team column: %v, want [true false] (absent reads false)", teams)
	}
	// intel's read (python/intel/app/corpus/export.py training_consented), run as the app role under tenant A's GUC.
	const latest = `SELECT bool_and(training) FROM (SELECT DISTINCT ON (device_id) training FROM m1_device_consents ORDER BY device_id, recorded_at DESC) d`
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
