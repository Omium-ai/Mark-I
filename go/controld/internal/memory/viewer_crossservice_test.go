//go:build integration && unix

package memory

// 15-teams §Memory end to end: this module resolving the viewer and the real mark1-intel filtering on it, over the shared migrated Postgres (m1_090's owner_subject). The owner reads their artifact as theirs; a teammate neither reads it nor acts on it, and intel's refusal reaches the app unchanged.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
)

func TestIntegrationCrossServiceViewerSubjectFiltersMemory(t *testing.T) {
	h := itSetup(t)
	ctx := context.Background()
	tenant, device := h.tenant()
	art := h.plant(tenant, "viewer: alice's guidance")
	alice, bob := "omium:alice-"+uuid.NewString(), "omium:bob-"+uuid.NewString() // the shared database keeps rows; one active membership per subject
	if err := pgx.BeginFunc(ctx, h.admin, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tenant.String()); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO m1_team_members (tenant_id, subject, role) VALUES ($1, $2, 'owner'), ($1, $3, 'member')`, tenant, alice, bob); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE memory_artifacts SET owner_subject = $2 WHERE id = $1`, art, alice)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	intelURL := startIntel(t, h.dsn, h.serveReceipts(smokeSvc).URL)
	as := func(subject string) *httptest.Server {
		m := New(Deps{Verifier: h.verify, ObsCfg: obs.Config{ServiceName: "controld-memory-viewer-it"}, IntelBaseURL: intelURL, IntelServiceToken: smokeSvc,
			Viewers: fakeViewers{v: querychoke.Viewer{Subject: subject, Team: true}}})
		mux := http.NewServeMux()
		m.RegisterRoutes(mux)
		api := httptest.NewServer(mux)
		t.Cleanup(api.Close)
		return api
	}
	tok := h.mint(tenant, device)

	if status, raw := itDo(t, http.MethodGet, as(alice).URL+"/api/v1/memory/artifacts", tok, ""); status != http.StatusOK || !strings.Contains(raw, art.String()) || !strings.Contains(raw, `"mine":true`) {
		t.Fatalf("the owner reads their artifact as theirs: %d %s", status, raw)
	}
	teammate := as(bob)
	if status, raw := itDo(t, http.MethodGet, teammate.URL+"/api/v1/memory/artifacts", tok, ""); status != http.StatusOK || strings.Contains(raw, art.String()) {
		t.Fatalf("a teammate must not read an unshared artifact: %d %s", status, raw)
	}
	status, raw := itDo(t, http.MethodPost, teammate.URL+"/api/v1/memory/artifacts/"+art.String()+"/pin", tok, "")
	if status != http.StatusForbidden || !strings.Contains(raw, `"reason":"not_owner"`) {
		t.Fatalf("a teammate pinning another's artifact: %d %s", status, raw)
	}
}
