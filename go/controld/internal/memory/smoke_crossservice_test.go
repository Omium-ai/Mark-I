//go:build integration && unix

package memory

// Cross-service smoke (12 §4 posture, the querychoke smoke's shape): the real mark1-intel app
// (uvicorn, PYTHONPATH=python/intel) on the shared migrated Postgres, this module on a real
// socket in front of it, a device token minted by the production signer for an enrolled
// m1_devices row, and the real edge cache (go/mark1d/internal/memory, its own Run via the
// smoke driver test) syncing the admitted artifact a planted row provides -- with tenant B's
// twin never crossing. Then the reactive tier: POST match as the device recovers the planted
// pitfall within D29 over the halfvec column.

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	smokePlanted = "Exit code 1\nFAIL test_retry_backoff: expected 3 attempts, saw 1"
	smokeNear    = "Exit code 1\nFAIL test_retry_backoff: expected 3 attempts, saw none"
	smokeSvc     = "cross-service-smoke-service-token"
)

// plant is intel's own PG fixture chain (tests/test_memory_pg.py _mk_cert + _plant) in SQL: a certified cert, then an admitted pitfall whose guidance carries the marker.
func (h *itHarness) plant(tenant uuid.UUID, guidance string) uuid.UUID {
	h.t.Helper()
	ctx := context.Background()
	var id uuid.UUID
	err := pgx.BeginFunc(ctx, h.admin, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tenant.String()); err != nil {
			return err
		}
		var verifier, gold, cert uuid.UUID
		if err := tx.QueryRow(ctx, `INSERT INTO m1_verifiers (verifier_key, kind, version, display_name, definition) VALUES ($1, 'judge', 1, 'smoke judge', '{}'::jsonb) RETURNING id`, "judge:memsmoke-"+uuid.NewString()[:8]).Scan(&verifier); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO gold_sets (tenant_id, agent, frozen_at) VALUES ($1, 'claudecode', now()) RETURNING id`, tenant).Scan(&gold); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO noise_certificates (tenant_id, verifier_id, gold_set_id, status, rho_plus, rho_minus, natarajan_lcb, gold_n, identifiable, issued_at, expires_at) VALUES ($1, $2, $3, 'certified', 0.05, 0.05, 0.8, 200, true, now(), now() + interval '1 day') RETURNING id`, tenant, verifier, gold).Scan(&cert); err != nil {
			return err
		}
		body, _ := json.Marshal(map[string]any{"trigger": smokePlanted, "guidance": guidance, "evidence": []string{"d1"}, "support_n": 1})
		return tx.QueryRow(ctx, `INSERT INTO memory_artifacts (tenant_id, abstraction, kind, body, state, lcb, n_obs, cert_id, admitted_at) VALUES ($1, 'instance', 'pitfall', $2::jsonb, 'admitted', 0.25, 10, $3, now()) RETURNING id`, tenant, string(body), cert).Scan(&id)
	})
	if err != nil {
		h.t.Fatal(err)
	}
	return id
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func uvCmd(ctx context.Context, t *testing.T, env []string, args ...string) *exec.Cmd {
	t.Helper()
	uvPath, err := exec.LookPath("uv")
	if err != nil {
		t.Skipf("uv not on PATH; python legs not run (report this honestly): %v", err)
	}
	cmd := exec.CommandContext(ctx, uvPath, append([]string{"run", "--frozen", "--all-packages"}, args...)...)
	cmd.Dir = repoRoot(t)
	// PYTHONPATH pins `app` to python/intel (adjudicator exports the same top-level package; see querychoke's smoke).
	cmd.Env = append(append(os.Environ(), "PYTHONPATH=python/intel"), env...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	return cmd
}

// startIntel boots the real app on a free port against the shared test database and waits for /healthz; chokeURL is where its receipt appends go (an unreachable port when the leg needs none).
func startIntel(t *testing.T, dsn, chokeURL string) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	ctx, cancel := context.WithCancel(context.Background())
	pgDSN := dsn
	if !strings.Contains(pgDSN, "sslmode=") {
		pgDSN += map[bool]string{true: "&", false: "?"}[strings.Contains(pgDSN, "?")] + "sslmode=disable"
	}
	cmd := uvCmd(ctx, t, []string{
		"INTEL_PG_DSN=" + pgDSN,
		"INTEL_QUERYCHOKE_BASE_URL=" + chokeURL,
		"INTEL_ADJUDICATOR_BASE_URL=http://127.0.0.1:1",
		"INTEL_QUERYCHOKE_TOKEN=" + smokeSvc,
	}, "python", "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", fmt.Sprint(port), "--log-level", "warning")
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = cmd.Wait() })
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := http.Get(base + "/healthz"); err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return base
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatal("intel did not become healthy")
	return ""
}

func TestIntegrationCrossServiceSmokeEdgeCacheSyncsPlantedArtifacts(t *testing.T) {
	h := itSetup(t)
	ctx := context.Background()
	tenantA, deviceA := h.tenant()
	tenantB, deviceB := h.tenant()
	artA := h.plant(tenantA, "run the retry test with --attempts 3")
	artB := h.plant(tenantB, "TENANT-B-SENTINEL-GUIDANCE")

	// The halfvec stamp is intel's embed_missing (retrieve.py) -- the same code the nightly job runs.
	stamp := uvCmd(ctx, t, []string{"M1_SMOKE_PG_DSN=" + h.dsn, "M1_SMOKE_TENANTS=" + tenantA.String() + "," + tenantB.String()}, "python", "-c", smokeStampPy)
	if out, err := stamp.CombinedOutput(); err != nil || !strings.Contains(string(out), "stamped 2") {
		t.Fatalf("embed_missing leg: %v\n%s", err, out)
	}

	intelURL := startIntel(t, h.dsn, "http://127.0.0.1:1")
	api := h.serve(intelURL, smokeSvc)
	tokA := h.mint(tenantA, deviceA)
	bMarkers := map[string]string{tenantB.String(): "tenant B's tenant id", artB.String(): "tenant B's artifact id", "TENANT-B-SENTINEL": "tenant B's guidance"}

	// Leg 1 -- the real edge cache's Run, cross-process (mark1d's internal package is unimportable here).
	stateDir := t.TempDir()
	edge := exec.CommandContext(ctx, "go", "test", "-tags", "integration", "-count=1", "-run", "^TestSmokeDriverRunSyncsFromEnv$", "./internal/memory/")
	edge.Dir = filepath.Join(repoRoot(t), "go", "mark1d")
	edge.Env = append(os.Environ(), "M1_SMOKE_MEMORY_URL="+api.URL, "M1_SMOKE_DEVICE_TOKEN="+tokA, "M1_SMOKE_STATE_DIR="+stateDir)
	if out, err := edge.CombinedOutput(); err != nil {
		t.Fatalf("edge cache leg: %v\n%s", err, out)
	}
	custody, err := os.ReadFile(filepath.Join(stateDir, "memory", "artifacts.json"))
	if err != nil {
		t.Fatalf("edge left no custody file: %v", err)
	}
	var synced struct {
		Artifacts []struct {
			ID       string `json:"artifact_id"`
			Kind     string `json:"kind"`
			Digest   string `json:"error_sig_digest"`
			Guidance string `json:"guidance"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(custody, &synced); err != nil {
		t.Fatalf("custody decode: %v: %s", err, custody)
	}
	if len(synced.Artifacts) != 1 || synced.Artifacts[0].ID != artA.String() || synced.Artifacts[0].Kind != "pitfall" || synced.Artifacts[0].Digest == "" {
		t.Fatalf("edge synced %s, want exactly tenant A's planted pitfall %s", custody, artA)
	}
	for marker, what := range bMarkers {
		if strings.Contains(string(custody), marker) {
			t.Errorf("edge custody leaked %s: %s", what, custody)
		}
	}
	if strings.Contains(string(custody), "tenant") {
		t.Errorf("tenant field on the public wire: %s", custody)
	}

	// Leg 2 -- the reactive fuzz tier as the device: the near paraphrase recovers the planted pitfall within D29.
	body, _ := json.Marshal(map[string]any{"error": smokeNear, "limit": 3})
	status, raw := itDo(t, http.MethodPost, api.URL+"/api/v1/memory/match", tokA, string(body))
	if status != http.StatusOK {
		t.Fatalf("match: %d %s", status, raw)
	}
	var match struct {
		Artifacts []struct {
			ID       string  `json:"artifact_id"`
			Distance float64 `json:"distance"`
		} `json:"artifacts"`
		SignatureDigest string `json:"signature_digest"`
	}
	if err := json.Unmarshal([]byte(raw), &match); err != nil {
		t.Fatalf("match decode: %v: %s", err, raw)
	}
	if len(match.Artifacts) != 1 || match.Artifacts[0].ID != artA.String() || match.Artifacts[0].Distance > 0.15 || match.SignatureDigest == "" {
		t.Fatalf("match answered %s, want tenant A's pitfall within 0.15", raw)
	}
	for marker, what := range bMarkers {
		if strings.Contains(raw, marker) {
			t.Errorf("match leaked %s: %s", what, raw)
		}
	}

	// The symmetric negative: tenant B's device, same route, same intel -- only B's row, never A's.
	status, raw = itDo(t, http.MethodGet, api.URL+"/api/v1/memory/artifacts", h.mint(tenantB, deviceB), "")
	if status != http.StatusOK || !strings.Contains(raw, artB.String()) || strings.Contains(raw, artA.String()) || strings.Contains(raw, tenantA.String()) {
		t.Fatalf("tenant B's view: %d %s (want only %s)", status, raw, artB)
	}
}

const smokeStampPy = `
import asyncio, os
import asyncpg
from app.db import _tenant_guc_reset
from app.memory import retrieve

async def main():
    conn = await asyncpg.connect(dsn=os.environ["M1_SMOKE_PG_DSN"])
    await _tenant_guc_reset(conn)
    n = 0
    for tenant in os.environ["M1_SMOKE_TENANTS"].split(","):
        n += await retrieve.embed_missing(conn, tenant)
    await conn.close()
    print(f"stamped {n}")

asyncio.run(main())
`
