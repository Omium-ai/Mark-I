//go:build integration

package memory

// DSN-gated (M1_TEST_PG_DSN, the migrated shared test database; M1_REQUIRE_STORES=1 fails
// instead of skipping): the production Ed25519 verifier over enroll's RevocationCache reading a
// real m1_devices row, the module on a real socket, and a fake intel behind it.

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/enroll"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/pg"
)

func itDSN(t *testing.T) string {
	t.Helper()
	v := os.Getenv("M1_TEST_PG_DSN")
	if v == "" {
		if os.Getenv("M1_REQUIRE_STORES") == "1" {
			t.Fatal("M1_TEST_PG_DSN required (M1_REQUIRE_STORES=1) but unset")
		}
		t.Skip("M1_TEST_PG_DSN unset; skipping Postgres-backed test")
	}
	return v
}

type itHarness struct {
	t      *testing.T
	dsn    string
	admin  *pgx.Conn
	cache  *enroll.RevocationCache
	signer *auth.Signer
	verify auth.Verifier
}

func itSetup(t *testing.T) *itHarness {
	t.Helper()
	ctx := context.Background()
	dsn := itDSN(t)
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
	db := pg.NewTenantDB(pool)
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	signer, err := auth.NewSigner(seed)
	if err != nil {
		t.Fatal(err)
	}
	cache := enroll.NewRevocationCache(db, 60*time.Second)
	return &itHarness{t: t, dsn: dsn, admin: admin, cache: cache, signer: signer, verify: auth.NewEd25519Verifier(signer.Public(), cache)}
}

// tenant plants an org + tenant + one enrolled device under the tenant GUC (the RLS-confined path intel's own PG fixtures use).
func (h *itHarness) tenant() (tenant, device uuid.UUID) {
	h.t.Helper()
	ctx := context.Background()
	tag := "memsmoke-" + uuid.NewString()[:8]
	tenant = uuid.New()
	err := pgx.BeginFunc(ctx, h.admin, func(tx pgx.Tx) error {
		var org uuid.UUID
		if err := tx.QueryRow(ctx, `INSERT INTO m1_organizations (name, primary_domain) VALUES ($1, $2) RETURNING id`, tag, tag+".example").Scan(&org); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tenant.String()); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO m1_tenants (id, org_id, name) VALUES ($1, $2, $3)`, tenant, org, tag); err != nil {
			return err
		}
		hostname := make([]byte, 32)
		_, _ = rand.Read(hostname)
		return tx.QueryRow(ctx, `INSERT INTO m1_devices (tenant_id, platform, hostname_hmac, last_seen_at) VALUES ($1, 'linux-x86_64', $2, now()) RETURNING id`, tenant, hostname).Scan(&device)
	})
	if err != nil {
		h.t.Fatal(err)
	}
	return tenant, device
}

func (h *itHarness) revoke(tenant, device uuid.UUID) {
	h.t.Helper()
	ctx := context.Background()
	err := pgx.BeginFunc(ctx, h.admin, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tenant.String()); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE m1_devices SET revoked_at = now(), revoked_by = 'sec@omium.ai' WHERE id = $1`, device)
		if err == nil && tag.RowsAffected() != 1 {
			return fmt.Errorf("revoke touched %d rows", tag.RowsAffected())
		}
		return err
	})
	if err != nil {
		h.t.Fatal(err)
	}
	h.cache.Invalidate(device)
}

// mint is what enroll's poll/refresh handlers call (handlers.go / store.go): the production signer, 1 h.
func (h *itHarness) mint(tenant, device uuid.UUID) string {
	h.t.Helper()
	now := time.Now()
	tok, err := h.signer.Mint(tenant, device, "ed25519:integration", now, now.Add(time.Hour))
	if err != nil {
		h.t.Fatal(err)
	}
	return tok
}

func (h *itHarness) serve(intelURL, serviceToken string) *httptest.Server {
	h.t.Helper()
	m := New(Deps{Verifier: h.verify, ObsCfg: obs.Config{ServiceName: "controld-memory-it"}, IntelBaseURL: intelURL, IntelServiceToken: serviceToken})
	mux := http.NewServeMux()
	m.RegisterRoutes(mux)
	api := httptest.NewServer(mux)
	h.t.Cleanup(api.Close)
	return api
}

func itDo(t *testing.T, method, url, bearer, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("X-Mark1-Edge-Version", "mark1d/it")
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

func TestIntegrationDeviceTokenGatesTheProxyAgainstTheRegistry(t *testing.T) {
	h := itSetup(t)
	intel := newFakeIntel(t)
	api := h.serve(intel.URL, serviceToken)
	tenantA, deviceA := h.tenant()
	tenantB, _ := h.tenant()
	tokA := h.mint(tenantA, deviceA)

	status, body := itDo(t, http.MethodGet, api.URL+"/api/v1/memory/artifacts", tokA, "")
	if status != http.StatusOK || body != artifactsDoc {
		t.Fatalf("enrolled device: %d %s", status, body)
	}
	if call := intel.last(t); call.path != intelArtifacts+"?tenant_id="+tenantA.String() || call.auth != "Bearer "+serviceToken {
		t.Fatalf("intel saw %s with %q", call.path, call.auth)
	}
	status, body = itDo(t, http.MethodPost, api.URL+"/api/v1/memory/match", tokA, `{"error":"Exit code 1\nFAIL x","limit":3}`)
	if status != http.StatusOK || body != matchDoc {
		t.Fatalf("match: %d %s", status, body)
	}
	if call := intel.last(t); !strings.Contains(string(call.body), `"tenant_id":"`+tenantA.String()+`"`) {
		t.Fatalf("match upstream body %s lacks the claims tenant", call.body)
	}

	// A well-signed token for a device the registry does not hold is terminal (revocation.go: no row = revoked).
	before := intel.count()
	if status, body = itDo(t, http.MethodGet, api.URL+"/api/v1/memory/artifacts", h.mint(tenantB, uuid.New()), ""); status != http.StatusForbidden || !strings.Contains(body, "M1E-1003") {
		t.Fatalf("unknown device: %d %s", status, body)
	}
	if status, body = itDo(t, http.MethodGet, api.URL+"/api/v1/memory/artifacts", tokA+"x", ""); status != http.StatusUnauthorized || !strings.Contains(body, "M1E-1002") {
		t.Fatalf("tampered signature: %d %s", status, body)
	}

	// Revocation through the real seam (05 §3.4): the same token dies with M1E-1003 on both routes.
	h.revoke(tenantA, deviceA)
	for _, c := range []struct{ method, path, body string }{{http.MethodGet, "/api/v1/memory/artifacts", ""}, {http.MethodPost, "/api/v1/memory/match", `{"error":"x","limit":3}`}} {
		if status, body = itDo(t, c.method, api.URL+c.path, tokA, c.body); status != http.StatusForbidden || !strings.Contains(body, "M1E-1003") {
			t.Fatalf("%s %s after revoke: %d %s", c.method, c.path, status, body)
		}
	}
	if intel.count() != before {
		t.Fatalf("intel called %d times by refused tokens", intel.count()-before)
	}
}
