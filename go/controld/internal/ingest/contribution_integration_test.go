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

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/chproj"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/s3land"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/sidefx"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/receipts"
)

// TestIntegrationContributionConsentLandWithdrawSweep: refused without consent; lands indexed (m1_096); withdrawal stamps and the sweep deletes.
func TestIntegrationContributionConsentLandWithdrawSweep(t *testing.T) {
	q := setupQuarantinePG(t)
	ctx := context.Background()
	store := newFakeStore()
	proj := chproj.New(&fakeInserter{}, 1, 10)
	sfx := sidefx.New(&fakeDB{}, nil, nil, 1, 10)
	sfx.SetLeafStore(sidefx.NewMemoryLeafStore())
	t.Cleanup(func() { proj.Close(); sfx.Close() })
	h := &harness{mux: http.NewServeMux(), store: store, token: auth.Mint(testKey, q.tenantA.UUID(), q.deviceA, time.Hour)}
	New(Deps{
		Verifier: auth.NewHMACVerifier(testKey, auth.StaticRevocations{}),
		ObsCfg:   obs.Config{ServiceName: "controld-test"},
		PG:       fakeReady{}, Store: store, Proj: proj, Sidefx: sfx, Security: &fakeSecurity{}, DB: q.db,
	}).RegisterRoutes(h.mux)
	consent := func(body string) {
		req := httptest.NewRequest(http.MethodPut, "/api/v1/consents", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+h.token)
		rec := httptest.NewRecorder()
		h.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("consent %s: %d %s", body, rec.Code, rec.Body.String())
		}
	}
	send := func() (*httptest.ResponseRecorder, uuid.UUID) {
		b, id := testBatch(t, contributionEvent(t, mustV7(t), 1))
		return h.post(t, id, encodeBatch(t, b), nil), id
	}

	consent(`{"e1":true,"cloud_judge":false,"training":true}`)
	if rec, _ := send(); rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "contribution_consent") {
		t.Fatalf("consent off: %d %s", rec.Code, rec.Body.String())
	}
	consent(`{"e1":true,"cloud_judge":false,"training":true,"contribute_outcomes":true}`)
	rec, batch := send()
	if rec.Code != http.StatusOK {
		t.Fatalf("consented contribution: %d %s", rec.Code, rec.Body.String())
	}
	key := s3land.ContributionKey(q.tenantA.UUID(), batch)
	if keys := store.keys(); len(keys) != 1 || keys[0] != key {
		t.Fatalf("landed %v, want only %s (never the replay log's ingest prefix)", keys, key)
	}
	var indexed string
	if err := q.admin.QueryRow(ctx, `SELECT object_key FROM m1_outcome_contributions WHERE batch_id = $1 AND withdrawn_at IS NULL`, batch).Scan(&indexed); err != nil || indexed != key {
		t.Fatalf("index row: %q %v", indexed, err)
	}

	consent(`{"e1":true,"cloud_judge":false,"training":true,"contribute_outcomes":false}`)
	var withdrawn *time.Time
	if err := q.admin.QueryRow(ctx, `SELECT withdrawn_at FROM m1_outcome_contributions WHERE batch_id = $1`, batch).Scan(&withdrawn); err != nil || withdrawn == nil {
		t.Fatalf("withdrawal did not mark the past contribution: %v %v", withdrawn, err)
	}
	n, err := NewQuarantineSweep(q.db, store, q.chain, receipts.StaticTenants([]uuid.UUID{q.tenantA.UUID()})).SweepContributions(ctx, q.tenantA.UUID())
	if err != nil || n != 1 {
		t.Fatalf("sweep deleted %d, %v", n, err)
	}
	if len(store.keys()) != 0 {
		t.Fatalf("withdrawn contribution object survived the sweep: %v", store.keys())
	}
	var deleted *time.Time
	if err := q.admin.QueryRow(ctx, `SELECT deleted_at FROM m1_outcome_contributions WHERE batch_id = $1`, batch).Scan(&deleted); err != nil || deleted == nil {
		t.Fatalf("deleted_at not stamped: %v %v", deleted, err)
	}
	if rec, _ := send(); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("after withdrawal a new contribution is refused: %d", rec.Code)
	}
}
