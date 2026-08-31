//go:build integration

// Without this tag the file compiled into the default build while setupQC/seed/
// mustTenant — which it needs — did not, so the whole querychoke test package
// failed to typecheck and confinement/golden-band/templates never ran at all.
// It needs a live ClickHouse and two seeded tenants, so `integration` is where
// it belongs, not a copy of the helpers.

package querychoke

// Cross-service smoke (12 §4 posture, over the wave-7 pair): controld's
// querychoke module served on a real socket against the scratch ClickHouse
// (real m1_ch_001/002 DDL via setupQC), two tenants seeded in m1p_events,
// then BOTH consumers of the 08 §3.3 surface run as tenant A and must never
// see tenant B's rows:
//
//   leg 1 — GET /api/v1/reports/tvo (08 §3.3) over live HTTP;
//   leg 2 — mark1-intel's QuerychokeReader (python/intel/app/tvo/reader.py),
//           executed via `uv run` against the live choke URL — the actual
//           cross-language, cross-process seam ADR-0010 §2.2 describes.
//
// PRODUCTION-WRITE GUARD: ADR-0001/ADR-0010 are UNSIGNED. The only writes
// here land in the per-run scratch database (setupQC creates and drops it),
// driven directly through the test's runner handle; the module is built with
// RollupWriteEnabled=false, so the HTTP write route stays dark.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
)

const smokeHMACKey = "cross-service-smoke-key"

func TestIntegrationCrossServiceSmokeTenantIsolation(t *testing.T) {
	rig := setupQC(t)
	ctx := t.Context()
	conn := rig.ingest // seeding rides the INSERT-only principal (chproj path)

	// Two tenants in m1p_events, B carrying the sentinel token count.
	tenantA, tenantB := uuid.New(), uuid.New()
	sessionA, sessionB := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	seed(t, rig, conn, tenantA, sessionA, 100, 5)
	seed(t, rig, conn, tenantB, sessionB, 987_654, 7)

	// One rollup row per tenant for today (the report window ends today UTC,
	// module.go parseWindow), written through the same ADR-0010 template the
	// idempotency test drives — scratch db, test lane only (WHY header).
	reg, err := LoadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	rollup, _ := reg.Lookup("tvo_rollup_tenant_day")
	day := time.Now().UTC().Format(time.DateOnly)
	for _, seedRow := range []struct {
		tenant uuid.UUID
		tokens uint64
	}{{tenantA, 100}, {tenantB, 987_654}} {
		q, err := BuildWrite(mustTenant(t, seedRow.tenant), rollup,
			fmt.Sprintf("smoke|%s|%s", day, seedRow.tenant), Params{
				"day":                  day,
				"series":               "task_seg.v1",
				"tokens_total":         seedRow.tokens,
				"cost_usd":             "1.0",
				"tasks_verified":       []uuid.UUID{uuid.New()},
				"tasks_unresolved":     []uuid.UUID{},
				"retry_loop_tokens":    uint64(0),
				"reexploration_tokens": uint64(0),
				"over_model_tokens":    uint64(0),
				"observed_ms":          uint64(90),
				"bypass_ms":            uint64(10),
				"disabled_ms":          uint64(0),
				"dropped_billing":      uint64(0),
			})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := rig.runner.Run(ctx, q); err != nil {
			t.Fatal(err)
		}
	}

	// The module as main.go wires it, on a real socket; the dev HMAC verifier
	// stands in for the Ed25519 one (AUTH_DEV_MODE seam) — tenancy stamping is
	// identical: Claims → FromClaims → Build.
	m := New(Deps{
		Registry: reg,
		Runner:   rig.runner,
		Verifier: auth.NewHMACVerifier([]byte(smokeHMACKey), auth.StaticRevocations{}),
		ObsCfg:   obs.Config{ServiceName: "smoke"},
	})
	mux := http.NewServeMux()
	m.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()
	bearerA := auth.Mint([]byte(smokeHMACKey), tenantA, uuid.New(), time.Hour)

	bMarkers := map[string]string{
		tenantB.String():  "tenant B's tenant id",
		sessionB.String(): "tenant B's session id",
		"987654":          "tenant B's sentinel token count",
	}

	// Leg 1 — the report path as tenant A. window=30d so the seeded day is in
	// range without a midnight race; A's tvo is exactly 100/1 — a lost tenant
	// predicate would merge B's rollup and move it.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/reports/tvo?window=30d", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+bearerA)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("report status %d: %s", resp.StatusCode, body)
	}
	var report struct {
		TVO float64 `json:"tvo"`
	}
	if err := json.Unmarshal(body, &report); err != nil {
		t.Fatalf("report decode: %v: %s", err, body)
	}
	if report.TVO != 100 {
		t.Fatalf("tenant A tvo = %v, want exactly 100 (tenant B's rollup leaked in?): %s", report.TVO, body)
	}
	for marker, what := range bMarkers {
		if strings.Contains(string(body), marker) {
			t.Errorf("report leaked %s: %s", what, body)
		}
	}

	// Leg 2 — intel's reader over the live choke, cross-process. Same bearer,
	// usage_by_session + dropped_by_tenant_day over the seeded day.
	uvPath, err := exec.LookPath("uv")
	if err != nil {
		t.Skipf("uv not on PATH; python leg not run (report this honestly): %v", err)
	}
	markerList := make([]string, 0, len(bMarkers))
	for marker := range bMarkers {
		markerList = append(markerList, marker)
	}
	markerJSON, _ := json.Marshal(markerList)
	cmd := exec.CommandContext(ctx, uvPath, "run", "--frozen", "--all-packages", "python", "-c", smokePy)
	cmd.Dir = "../../../.."
	cmd.Env = append(os.Environ(),
		"M1_SMOKE_CHOKE_URL="+ts.URL,
		"M1_SMOKE_BEARER_A="+bearerA,
		"M1_SMOKE_A_SESSION="+sessionA.String(),
		"M1_SMOKE_B_MARKERS="+string(markerJSON),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("intel reader leg: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "smoke ok") {
		t.Fatalf("intel reader leg produced no verdict:\n%s", out)
	}
}

// smokePy drives python/intel/app/tvo/reader.py — intel's ONLY ledger read
// path — against the live choke as tenant A and refuses any tenant-B marker.
// Dates are seed()'s fixed day (2026-08-28), so the assertion is time-stable.
const smokePy = `
import asyncio, json, os
import httpx
from app.tvo.reader import QuerychokeReader

async def main():
    markers = json.loads(os.environ["M1_SMOKE_B_MARKERS"])
    want = os.environ["M1_SMOKE_A_SESSION"]
    bearer = os.environ["M1_SMOKE_BEARER_A"]
    async with httpx.AsyncClient() as http:
        reader = QuerychokeReader(http, os.environ["M1_SMOKE_CHOKE_URL"])
        window = {"from": "2026-08-28", "to": "2026-08-28"}
        for template in ("usage_by_session", "dropped_by_tenant_day"):
            res = await reader.run_template(template, window, bearer=bearer)
            dump = json.dumps([dict(r) for r in res.rows])
            if template == "usage_by_session":
                assert want in dump, f"tenant A session missing from {template}: {dump}"
            for m in markers:
                assert m not in dump, f"TENANT LEAK via {template}: {m}: {dump}"
    print("smoke ok")

asyncio.run(main())
`
