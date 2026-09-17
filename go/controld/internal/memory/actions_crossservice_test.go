//go:build integration && unix

package memory

// The memory actions end to end (spec §5.5): a device token on this module, the real mark1-intel behind it on the shared migrated Postgres, and controld's real receipts append route (the same mux) taking intel's retire receipt -- so the chain row, the state flip and the response are one act, and tenant B's artifact reads as 404 under A's token with no receipt minted.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/appapi/schemacheck"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/receipts"
)

// serveReceipts mounts controld's receipts module (the internal append route intel's retire rides) on its own socket; the memory module follows once intel's URL is known.
func (h *itHarness) serveReceipts(serviceToken string) *httptest.Server {
	h.t.Helper()
	signer, err := receipts.NewSigner(bytes.Repeat([]byte{0x51}, 32))
	if err != nil {
		h.t.Fatal(err)
	}
	if err := receipts.RegisterServerKey(context.Background(), h.admin, signer); err != nil {
		h.t.Fatal(err)
	}
	obsCfg := obs.Config{ServiceName: "controld-memory-actions-it"}
	rc := receipts.NewModule(receipts.ModuleDeps{DB: h.db, PG: h.db, Verifier: h.verify, ObsCfg: obsCfg, Store: receipts.NewStore(h.db, signer), IntelServiceToken: serviceToken})
	mux := http.NewServeMux()
	rc.RegisterRoutes(mux)
	api := httptest.NewServer(mux)
	h.t.Cleanup(api.Close)
	return api
}

func (h *itHarness) artifact(tenant, id uuid.UUID) (state string, pinned bool, scope string, receipt *uuid.UUID) {
	h.t.Helper()
	ctx := context.Background()
	tx, err := h.admin.Begin(ctx)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tenant.String()); err != nil {
		h.t.Fatal(err)
	}
	if err := tx.QueryRow(ctx, `SELECT state::text, pinned, scope, receipt_id FROM memory_artifacts WHERE id = $1`, id).Scan(&state, &pinned, &scope, &receipt); err != nil {
		h.t.Fatal(err)
	}
	return
}

func (h *itHarness) receiptsFor(tenant, subject uuid.UUID) []string {
	h.t.Helper()
	ctx := context.Background()
	tx, err := h.admin.Begin(ctx)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tenant.String()); err != nil {
		h.t.Fatal(err)
	}
	rows, err := tx.Query(ctx, `SELECT record_type || ' ' || payload FROM m1_receipts WHERE tenant_id = $1 AND subject_id = $2 ORDER BY seq`, tenant, subject)
	if err != nil {
		h.t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			h.t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

func TestIntegrationCrossServiceMemoryActionsRetireIsReceiptedAndTenantBound(t *testing.T) {
	h := itSetup(t)
	schemas := schemacheck.Load(t, "../appapi/schema")
	tenantA, deviceA := h.tenant()
	tenantB, _ := h.tenant()
	artA := h.plant(tenantA, "actions: tenant A guidance")
	artB := h.plant(tenantB, "actions: tenant B guidance")

	chain := h.serveReceipts(smokeSvc)
	memAPI := h.serve(startIntel(t, h.dsn, chain.URL), smokeSvc)
	tokA := h.mint(tenantA, deviceA)

	// pin + share: flags flip in-tenant and are served on the artifacts read the app consumes.
	status, raw := itDo(t, http.MethodPost, memAPI.URL+"/api/v1/memory/artifacts/"+artA.String()+"/pin", tokA, "")
	if status != http.StatusOK || raw != `{"artifact_id":"`+artA.String()+`","pinned":true}` {
		t.Fatalf("pin: %d %s", status, raw)
	}
	schemas.Validate("memory_action.json", []byte(raw))
	if status, raw = itDo(t, http.MethodPost, memAPI.URL+"/api/v1/memory/artifacts/"+artA.String()+"/share", tokA, ""); status != http.StatusOK || !strings.Contains(raw, `"scope":"team"`) {
		t.Fatalf("share: %d %s", status, raw)
	}
	if state, pinned, scope, _ := h.artifact(tenantA, artA); state != "admitted" || !pinned || scope != "team" {
		t.Fatalf("row after pin+share: %s %v %s", state, pinned, scope)
	}
	status, raw = itDo(t, http.MethodGet, memAPI.URL+"/api/v1/memory/artifacts", tokA, "")
	if status != http.StatusOK || !strings.Contains(raw, `"pinned":true`) || !strings.Contains(raw, `"scope":"team"`) || !strings.Contains(raw, `"n":10`) {
		t.Fatalf("artifacts read carries the action fields: %d %s", status, raw)
	}

	// Tenant B's artifact under A's token: 404 on every action, no flag moved, no receipt minted.
	for _, action := range actions {
		if status, raw = itDo(t, http.MethodPost, memAPI.URL+"/api/v1/memory/artifacts/"+artB.String()+"/"+action, tokA, actionBody(action)); status != http.StatusNotFound || !strings.Contains(raw, "M1E-2009") {
			t.Fatalf("%s on B's artifact: %d %s", action, status, raw)
		}
	}
	if state, pinned, scope, _ := h.artifact(tenantB, artB); state != "admitted" || pinned || scope != "mine" {
		t.Fatalf("B's row moved: %s %v %s", state, pinned, scope)
	}
	if got := h.receiptsFor(tenantB, artB); len(got) != 0 {
		t.Fatalf("receipts minted for B: %v", got)
	}

	// retire: one receipt in the chain, the flip carrying its id, the response naming both; a repeat is the same act.
	status, raw = itDo(t, http.MethodPost, memAPI.URL+"/api/v1/memory/artifacts/"+artA.String()+"/retire", tokA, `{"reason":"advice went stale"}`)
	if status != http.StatusOK {
		t.Fatalf("retire: %d %s", status, raw)
	}
	schemas.Validate("memory_action.json", []byte(raw))
	var res struct {
		ArtifactID string `json:"artifact_id"`
		State      string `json:"state"`
		ReceiptID  string `json:"receipt_id"`
	}
	if err := json.Unmarshal([]byte(raw), &res); err != nil || res.State != "retired" || res.ArtifactID != artA.String() {
		t.Fatalf("retire body: %s (%v)", raw, err)
	}
	state, _, _, receipt := h.artifact(tenantA, artA)
	if state != "retired" || receipt == nil || receipt.String() != res.ReceiptID {
		t.Fatalf("row after retire: %s receipt=%v, response %s", state, receipt, res.ReceiptID)
	}
	rows := h.receiptsFor(tenantA, artA)
	if len(rows) != 1 || !strings.HasPrefix(rows[0], "memory_admission ") || !strings.Contains(rows[0], `"act":"retire"`) || !strings.Contains(rows[0], `"reason":"advice went stale"`) || !strings.Contains(rows[0], `"by":"device:`+deviceA.String()+`"`) || !strings.Contains(rows[0], `"from_state":"admitted"`) {
		t.Fatalf("chain for A's artifact: %v", rows)
	}
	if status, again := itDo(t, http.MethodPost, memAPI.URL+"/api/v1/memory/artifacts/"+artA.String()+"/retire", tokA, `{"reason":"again"}`); status != http.StatusOK || again != raw {
		t.Fatalf("repeat retire: %d %s (first %s)", status, again, raw)
	}
	if got := h.receiptsFor(tenantA, artA); len(got) != 1 {
		t.Fatalf("repeat minted a second receipt: %v", got)
	}
	if status, raw = itDo(t, http.MethodGet, memAPI.URL+"/api/v1/memory/artifacts", tokA, ""); status != http.StatusOK || strings.Contains(raw, artA.String()) {
		t.Fatalf("retired artifact still served: %d %s", status, raw)
	}

	// outcomes: A's evidence only.
	status, raw = itDo(t, http.MethodGet, memAPI.URL+"/api/v1/memory/outcomes", tokA, "")
	if status != http.StatusOK || !strings.Contains(raw, artA.String()) || strings.Contains(raw, artB.String()) || strings.Contains(raw, tenantB.String()) {
		t.Fatalf("outcomes: %d %s", status, raw)
	}
	schemas.Validate("memory_outcomes.json", []byte(raw))
}
