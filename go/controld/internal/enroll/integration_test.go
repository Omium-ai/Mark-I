package enroll_test

// DSN-gated Postgres integration (house style, 12 / 05 §7.5): a scratch
// database gets the real migrations, a NOBYPASSRLS login role stands in for
// controld_app, and the tenant IdP is an httptest mock serving a real JWKS
// with a real ES256 key — the OIDC verification path is the production one,
// down to the pinned-JWKS parse. Covers the 05 §3.1 state machine over the
// wire (start/poll/approve/deny/expire/replay), the PoP refresh, revocation
// (epoch bump + fail-closed verify), the §3.6 fingerprint registry, and the
// RLS seams.
//
// Gate: M1_TEST_PG_DSN (superuser DSN for scratch setup). Absent ⇒ skip,
// unless M1_REQUIRE_STORES=1 ⇒ fail.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/enroll"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/pg"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
)

func pgDSN(t *testing.T) string {
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

// clock is the shared fake time: it starts at real now (DB rows are stamped
// by Postgres now(), and the 15-min expiry check compares the two) and only
// moves forward when a test advances it past a pacing or expiry window.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// mockIdP is the tenant IdP: RFC 8628 device-authorization + token endpoints
// and an ES256 key whose public half is the tenant row's PINNED JWKS.
type mockIdP struct {
	srv *httptest.Server
	key *ecdsa.PrivateKey

	mu    sync.Mutex
	seq   int
	state map[string]string // idp device_code → pending | approved:<sub> | denied | expired
}

func newMockIdP(t *testing.T) *mockIdP {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := &mockIdP{key: key, state: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /device_authorization", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		m.seq++
		code := fmt.Sprintf("idp-dc-%d", m.seq)
		m.state[code] = "pending"
		m.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code": code, "user_code": "WDJB-MJHT",
			"verification_uri": m.srv.URL + "/activate",
			"expires_in":       900, "interval": 1,
		})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		code := r.FormValue("device_code")
		aud := r.FormValue("client_id")
		m.mu.Lock()
		st := m.state[code]
		m.mu.Unlock()
		switch {
		case strings.HasPrefix(st, "approved:"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "at", "token_type": "Bearer",
				"id_token": m.signJWT(strings.TrimPrefix(st, "approved:"), aud),
			})
		case st == "denied":
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "access_denied"})
		case st == "expired":
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "expired_token"})
		default:
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "authorization_pending"})
		}
	})
	m.srv = httptest.NewServer(mux)
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mockIdP) signJWT(sub, aud string) string {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: m.key},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		panic(err)
	}
	now := time.Now()
	payload, _ := json.Marshal(map[string]any{
		"iss": m.srv.URL, "sub": sub, "aud": aud,
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	})
	jws, err := signer.Sign(payload)
	if err != nil {
		panic(err)
	}
	raw, err := jws.CompactSerialize()
	if err != nil {
		panic(err)
	}
	return raw
}

func (m *mockIdP) jwksJSON(t *testing.T) string {
	t.Helper()
	b, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: m.key.Public(), KeyID: "k1", Algorithm: "ES256", Use: "sig"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// setLatest marks the most recently minted IdP code — the CLI-side test
// only ever holds OUR opaque device_code, so approval targets "the grant the
// user is looking at", which is how the real IdP screen works too.
func (m *mockIdP) setLatest(state string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state[fmt.Sprintf("idp-dc-%d", m.seq)] = state
}

type harness struct {
	t       *testing.T
	admin   *pgx.Conn
	db      *pg.TenantDB
	idp     *mockIdP
	clk     *clock
	signer  *auth.Signer
	cache   *enroll.RevocationCache
	verify  auth.Verifier
	api     *httptest.Server
	tenantA uuid.UUID
	tenantB uuid.UUID
}

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
	scratch := fmt.Sprintf("controld_enroll_it_%d", time.Now().UnixNano())
	role := fmt.Sprintf("enrollapp_%d", time.Now().UnixNano())
	if _, err := bootstrap.Exec(ctx, "CREATE DATABASE "+scratch); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cctx := context.Background()
		_, _ = bootstrap.Exec(cctx, "DROP DATABASE IF EXISTS "+scratch+" WITH (FORCE)")
		_, _ = bootstrap.Exec(cctx, "DROP ROLE IF EXISTS "+role)
		_ = bootstrap.Close(cctx)
	})

	scratchCfg := adminCfg.Copy()
	scratchCfg.Database = scratch
	admin, err := pgx.ConnectConfig(ctx, scratchCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })

	// The real migrations, in filename order (05 §7.4). m1_060's GRANTs touch
	// cluster-GLOBAL role tuples, so concurrent scratch setups across test
	// packages collide ("tuple concurrently updated"); the migration+role
	// phase serializes on a cluster advisory lock held on the shared
	// bootstrap session (a Fatal path releases it when Cleanup closes the
	// session).
	if _, err := bootstrap.Exec(ctx, `SELECT pg_advisory_lock(7231060)`); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join("..", "..", "..", "..", "migrations", "m1_0*.sql"))
	if err != nil || len(files) == 0 {
		t.Fatalf("migrations not found: %v (%d)", err, len(files))
	}
	sort.Strings(files)
	for _, f := range files {
		sql, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Exec(ctx, string(sql)); err != nil {
			t.Fatalf("migration %s: %v", filepath.Base(f), err)
		}
	}
	_, err = admin.Exec(ctx, fmt.Sprintf(
		"CREATE ROLE %s LOGIN PASSWORD 'enrolltest' NOBYPASSRLS NOSUPERUSER; GRANT controld_app TO %s", role, role))
	if _, uerr := bootstrap.Exec(ctx, `SELECT pg_advisory_unlock(7231060)`); uerr != nil {
		t.Fatal(uerr)
	}
	if err != nil {
		t.Fatal(err)
	}

	idp := newMockIdP(t)

	var orgID uuid.UUID
	if err := admin.QueryRow(ctx,
		`INSERT INTO m1_organizations (name, primary_domain) VALUES ('enroll-it', 'enroll-it.example') RETURNING id`,
	).Scan(&orgID); err != nil {
		t.Fatal(err)
	}
	var tenantA uuid.UUID
	if err := admin.QueryRow(ctx, `
		INSERT INTO m1_tenants (org_id, name,
		  oidc_issuer, oidc_client_id, oidc_jwks_uri, oidc_jwks_pinned,
		  oidc_device_authorization_endpoint, oidc_token_endpoint, oidc_discovered_at,
		  operator_audience, operator_admin_claim, operator_admin_value)
		VALUES ($1, 'tenant-a', $2, 'mark1-cli-client', $3, $4, $5, $6, now(),
		        'mark1-console', 'roles', 'm1-admin')
		RETURNING id`,
		orgID, idp.srv.URL, idp.srv.URL+"/jwks", idp.jwksJSON(t),
		idp.srv.URL+"/device_authorization", idp.srv.URL+"/token",
	).Scan(&tenantA); err != nil {
		t.Fatal(err)
	}
	// Tenant B: exists but never onboarded an IdP — enrollment must refuse it.
	var tenantB uuid.UUID
	if err := admin.QueryRow(ctx,
		`INSERT INTO m1_tenants (org_id, name) VALUES ($1, 'tenant-b') RETURNING id`, orgID,
	).Scan(&tenantB); err != nil {
		t.Fatal(err)
	}

	appDSN := fmt.Sprintf("postgres://%s:enrolltest@%s:%d/%s?sslmode=disable",
		role, adminCfg.Host, adminCfg.Port, scratch)
	pool, err := pg.Open(ctx, appDSN)
	if err != nil {
		t.Fatalf("pg.Open as NOBYPASSRLS role: %v", err)
	}
	t.Cleanup(pool.Close)
	db := pg.NewTenantDB(pool)

	clk := &clock{t: time.Now()}
	signer, err := auth.NewSigner([]byte("integration-test-seed-32-bytes!!"))
	if err != nil {
		t.Fatal(err)
	}
	cache := enroll.NewRevocationCache(db, 60*time.Second)
	verify := auth.NewEd25519Verifier(signer.Public(), cache)

	mod := enroll.New(enroll.Deps{
		DB: db, PG: db, Signer: signer, Verifier: verify,
		ObsCfg: obs.Config{ServiceName: "controld-test"}, Cache: cache,
		PublicBaseURL: "https://api.test.example", ServerMinEdge: "1.0.0",
		Now: clk.Now,
	})
	mux := http.NewServeMux()
	mod.RegisterRoutes(mux)
	api := httptest.NewServer(mux)
	t.Cleanup(api.Close)

	return &harness{
		t: t, admin: admin, db: db, idp: idp, clk: clk,
		signer: signer, cache: cache, verify: verify, api: api,
		tenantA: tenantA, tenantB: tenantB,
	}
}

func (h *harness) post(path string, body any, hdr map[string]string) (int, map[string]any) {
	h.t.Helper()
	raw, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, h.api.URL+path, bytes.NewReader(raw))
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return h.do(req)
}

func (h *harness) get(path string, hdr map[string]string) (int, map[string]any) {
	h.t.Helper()
	req, err := http.NewRequest(http.MethodGet, h.api.URL+path, nil)
	if err != nil {
		h.t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return h.do(req)
}

func (h *harness) do(req *http.Request) (int, map[string]any) {
	h.t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	return resp.StatusCode, body
}

func errCode(body map[string]any) string {
	if e, ok := body["error"].(map[string]any); ok {
		if c, ok := e["code"].(string); ok {
			return c
		}
	}
	return ""
}

// startEnrollment runs /device/start for tenant A with a fresh device key.
func (h *harness) startEnrollment() (ed25519.PrivateKey, string) {
	h.t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		h.t.Fatal(err)
	}
	status, body := h.post("/api/v1/enroll/device/start", map[string]any{
		"client": "mark1-cli", "client_version": "1.4.2",
		"device_pubkey": "ed25519:" + base64.StdEncoding.EncodeToString(pub),
		"platform":      "linux-x86_64",
		// The CLI's exact wire form (go/mark1/internal/enroll): prefix included,
		// so this suite exercises the same string parseHostnameHash sees live.
		"hostname_hash": "hmac-sha256:" + strings.Repeat("ab", 32),
		"tenant":        h.tenantA.String(),
	}, nil)
	if status != http.StatusOK {
		h.t.Fatalf("start: %d %v", status, body)
	}
	if body["user_code"] != "WDJB-MJHT" || body["device_code"] == "" {
		h.t.Fatalf("start body: %v", body)
	}
	return priv, body["device_code"].(string)
}

func (h *harness) poll(code string) (int, map[string]any) {
	h.t.Helper()
	h.clk.Advance(6 * time.Second) // respect the flow's own interval (§8.2)
	return h.post("/api/v1/enroll/device/poll", map[string]string{"device_code": code}, nil)
}

// popRefresh runs the §3.3 nonce+signature refresh for a device.
func (h *harness) popRefresh(priv ed25519.PrivateKey, device uuid.UUID) (int, map[string]any) {
	h.t.Helper()
	status, body := h.post("/api/v1/enroll/nonce", map[string]string{
		"tenant_id": h.tenantA.String(), "device_id": device.String(),
	}, nil)
	if status != http.StatusOK {
		h.t.Fatalf("nonce: %d %v", status, body)
	}
	nonce := body["nonce"].(string)
	requestedAt := time.Now().UTC().Format(time.RFC3339)
	sig := ed25519.Sign(priv, []byte(nonce+device.String()+requestedAt))
	return h.post("/api/v1/enroll/token", map[string]any{
		"device_id": device.String(),
		"signed_nonce": map[string]string{
			"nonce": nonce, "requested_at": requestedAt,
			"sig": base64.RawURLEncoding.EncodeToString(sig),
		},
	}, nil)
}

func (h *harness) operatorToken(role string) string {
	return h.mintOperatorJWT("ops@enroll-it.example", "mark1-console", role, h.tenantA)
}

// mintOperatorJWT mints a console-style operator token. boundTenant rides the
// m1_tenant claim (idp.go operatorTenantClaim) — the binding that stops two
// tenants on one IdP administering each other; uuid.Nil omits the claim
// (a pre-ruling token, which the server must refuse).
func (h *harness) mintOperatorJWT(sub, aud, role string, boundTenant uuid.UUID) string {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: h.idp.key},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		h.t.Fatal(err)
	}
	now := time.Now()
	claims := map[string]any{
		"iss": h.idp.srv.URL, "sub": sub, "aud": aud,
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		"roles": []string{role},
	}
	if boundTenant != uuid.Nil {
		claims["m1_tenant"] = boundTenant.String()
	}
	payload, _ := json.Marshal(claims)
	jws, err := signer.Sign(payload)
	if err != nil {
		h.t.Fatal(err)
	}
	raw, err := jws.CompactSerialize()
	if err != nil {
		h.t.Fatal(err)
	}
	return raw
}

func TestIntegrationEnrollmentLifecycle(t *testing.T) {
	h := setup(t)
	ctx := context.Background()

	var (
		devicePriv  ed25519.PrivateKey
		deviceCode  string
		deviceID    uuid.UUID
		deviceToken string
	)

	t.Run("start_registers_pending", func(t *testing.T) {
		devicePriv, deviceCode = h.startEnrollment()
		var status string
		if err := h.admin.QueryRow(ctx,
			`SELECT status FROM m1_device_enrollments`).Scan(&status); err != nil || status != "pending" {
			t.Fatalf("enrollment row: %q %v", status, err)
		}
		// A tenant that never onboarded an IdP cannot start (m1_001 ENG-05).
		st, body := h.post("/api/v1/enroll/device/start", map[string]any{
			"device_pubkey": "ed25519:" + base64.StdEncoding.EncodeToString(make([]byte, 32)),
			"platform":      "linux", "hostname_hash": strings.Repeat("cd", 32),
			"tenant": h.tenantB.String(),
		}, nil)
		if st != http.StatusBadRequest || errCode(body) != "M1E-2001" {
			t.Fatalf("un-onboarded tenant: %d %v", st, body)
		}
	})

	t.Run("poll_pending_then_pacing", func(t *testing.T) {
		st, body := h.poll(deviceCode)
		if st != http.StatusAccepted || body["status"] != "pending" {
			t.Fatalf("pending poll: %d %v", st, body)
		}
		// Immediate re-poll (no clock advance) violates `interval` ⇒ M1E-9001.
		st, body = h.post("/api/v1/enroll/device/poll", map[string]string{"device_code": deviceCode}, nil)
		if st != http.StatusTooManyRequests || errCode(body) != "M1E-9001" {
			t.Fatalf("pacing: %d %v", st, body)
		}
	})

	t.Run("approval_issues_token", func(t *testing.T) {
		h.idp.setLatest("approved:alice@enroll-it.example")
		st, body := h.poll(deviceCode)
		if st != http.StatusOK || body["status"] != "active" {
			t.Fatalf("active poll: %d %v", st, body)
		}
		deviceToken = body["device_token"].(string)
		var err error
		deviceID, err = uuid.Parse(body["device_id"].(string))
		if err != nil {
			t.Fatal(err)
		}
		if body["server_min_edge"] != "1.0.0" || body["key_manifest_uri"] != "/.well-known/mark1-keys" {
			t.Fatalf("handshake fields: %v", body)
		}
		if exp := body["expires_in"].(float64); exp <= 0 || exp > 86400 {
			t.Fatalf("expires_in outside the ≤24h ceiling: %v", exp)
		}
		// The issued token verifies through the PRODUCTION verifier and
		// stamps the right identity.
		claims, err := h.verify.Verify(ctx, deviceToken)
		if err != nil {
			t.Fatalf("issued token rejected: %v", err)
		}
		if claims.TenantID != h.tenantA || claims.DeviceID != deviceID {
			t.Fatalf("claims mismatch: %+v", claims)
		}
		// DB shape: approved grant, device row, live key with derived key_id.
		var status, keyID string
		var subject string
		if err := h.admin.QueryRow(ctx, `
			SELECT e.status, e.oidc_subject, k.key_id
			  FROM m1_device_enrollments e JOIN m1_device_keys k ON k.device_id = e.device_id
			 WHERE e.device_id = $1`, deviceID).Scan(&status, &subject, &keyID); err != nil {
			t.Fatal(err)
		}
		if status != "approved" || subject != "alice@enroll-it.example" || !strings.HasPrefix(keyID, "ed25519:") {
			t.Fatalf("approved rows: %s %s %s", status, subject, keyID)
		}
	})

	t.Run("replayed_code_is_consumed", func(t *testing.T) {
		st, body := h.poll(deviceCode)
		if st != http.StatusBadRequest || errCode(body) != "M1E-1004" {
			t.Fatalf("replay must be M1E-1004 (single-use, §3.5 case 2): %d %v", st, body)
		}
	})

	t.Run("tampered_token_rejected", func(t *testing.T) {
		bad := deviceToken[:len(deviceToken)-2] + "xx"
		if _, err := h.verify.Verify(ctx, bad); !errors.Is(err, auth.ErrBadToken) {
			t.Fatalf("want ErrBadToken, got %v", err)
		}
	})

	t.Run("pop_refresh", func(t *testing.T) {
		st, body := h.popRefresh(devicePriv, deviceID)
		if st != http.StatusOK {
			t.Fatalf("refresh: %d %v", st, body)
		}
		if _, err := h.verify.Verify(ctx, body["device_token"].(string)); err != nil {
			t.Fatalf("refreshed token rejected: %v", err)
		}
		// Heartbeat: refresh stamps last_seen_at (05 §3.3).
		var seen *time.Time
		if err := h.admin.QueryRow(ctx,
			`SELECT last_seen_at FROM m1_devices WHERE id = $1`, deviceID).Scan(&seen); err != nil || seen == nil {
			t.Fatalf("last_seen_at not stamped: %v %v", seen, err)
		}
	})

	t.Run("pop_refresh_wrong_key_rejected", func(t *testing.T) {
		_, wrongKey, _ := ed25519.GenerateKey(rand.Reader)
		st, body := h.popRefresh(wrongKey, deviceID)
		if st != http.StatusUnauthorized || errCode(body) != "M1E-1002" {
			t.Fatalf("wrong key must be 401 M1E-1002: %d %v", st, body)
		}
	})

	t.Run("refresh_budget_not_drainable_without_key", func(t *testing.T) {
		// device_id is not a secret (poll body, enrollment.json, --json). An
		// unauthenticated flood naming it must burn NO refresh budget — §8.2's
		// 12/day bucket debits only after proof-of-possession, or an attacker
		// 429s the victim until its ≤24 h token dies (denial-of-refresh).
		for i := 0; i < 20; i++ {
			st, body := h.post("/api/v1/enroll/token", map[string]any{
				"device_id":    deviceID.String(),
				"signed_nonce": map[string]string{},
			}, nil)
			if st != http.StatusUnauthorized || errCode(body) != "M1E-1002" {
				t.Fatalf("bogus refresh %d: %d %v (want 401 M1E-1002, never 429)", i, st, body)
			}
		}
		if st, body := h.popRefresh(devicePriv, deviceID); st != http.StatusOK {
			t.Fatalf("genuine refresh starved by unauthenticated flood: %d %v", st, body)
		}
	})

	t.Run("nonce_single_use_on_wire", func(t *testing.T) {
		st, body := h.post("/api/v1/enroll/nonce", map[string]string{
			"tenant_id": h.tenantA.String(), "device_id": deviceID.String(),
		}, nil)
		if st != http.StatusOK {
			t.Fatalf("nonce: %d %v", st, body)
		}
		nonce := body["nonce"].(string)
		requestedAt := time.Now().UTC().Format(time.RFC3339)
		sig := base64.RawURLEncoding.EncodeToString(
			ed25519.Sign(devicePriv, []byte(nonce+deviceID.String()+requestedAt)))
		req := map[string]any{
			"device_id": deviceID.String(),
			"signed_nonce": map[string]string{
				"nonce": nonce, "requested_at": requestedAt, "sig": sig,
			},
		}
		if st, body := h.post("/api/v1/enroll/token", req, nil); st != http.StatusOK {
			t.Fatalf("first use: %d %v", st, body)
		}
		// The identical signed request replays into nothing (§3.5 case 4).
		if st, body := h.post("/api/v1/enroll/token", req, nil); st != http.StatusUnauthorized || errCode(body) != "M1E-1002" {
			t.Fatalf("replay must be 401 M1E-1002: %d %v", st, body)
		}
	})

	t.Run("fingerprints", func(t *testing.T) {
		fp := strings.Repeat("5a", 32)
		hdr := map[string]string{"Authorization": "Bearer " + deviceToken}
		for range 2 { // idempotent re-provisioning (uq_m1_fp_live)
			st, body := h.post("/api/v1/enroll/fingerprints",
				map[string]string{"fingerprint": fp, "upstream_class": "anthropic"}, hdr)
			if st != http.StatusOK {
				t.Fatalf("register: %d %v", st, body)
			}
		}
		st, body := h.get("/api/v1/enroll/fingerprints", hdr)
		if st != http.StatusOK {
			t.Fatalf("list: %d %v", st, body)
		}
		items := body["fingerprints"].([]any)
		if len(items) != 1 {
			t.Fatalf("want exactly 1 live fingerprint, got %d", len(items))
		}
		got := items[0].(map[string]any)
		if got["fingerprint"] != fp || got["upstream_class"] != "anthropic" {
			t.Fatalf("fingerprint row: %v", got)
		}
		// No device token, no registry (trust boundary).
		if st, _ := h.get("/api/v1/enroll/fingerprints", nil); st != http.StatusUnauthorized {
			t.Fatalf("unauthenticated fingerprint read: %d", st)
		}
	})

	t.Run("rls_seams", func(t *testing.T) {
		tb, err := querychoke.FromClaims(auth.Claims{TenantID: h.tenantB})
		if err != nil {
			t.Fatal(err)
		}
		for _, table := range []string{"m1_device_enrollments", "m1_devices", "m1_device_keys", "m1_device_credential_fingerprints"} {
			var n int64
			if err := h.db.WithTenant(ctx, tb, func(tx pgx.Tx) error {
				return tx.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&n)
			}); err != nil {
				t.Fatal(err)
			}
			if n != 0 {
				t.Fatalf("tenant B read %d rows of tenant A's %s", n, table)
			}
			// And the authority really holds rows (the zero above is RLS,
			// not an empty table).
			if err := h.admin.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&n); err != nil || n == 0 {
				t.Fatalf("%s unexpectedly empty as admin: %d %v", table, n, err)
			}
		}
	})

	t.Run("denied_is_terminal", func(t *testing.T) {
		_, code := h.startEnrollment()
		h.idp.setLatest("denied")
		st, body := h.poll(code)
		if st != http.StatusForbidden || errCode(body) != "M1E-1005" {
			t.Fatalf("denial: %d %v", st, body)
		}
		// Terminal from the ROW: the IdP is not consulted again.
		st, body = h.poll(code)
		if st != http.StatusForbidden || errCode(body) != "M1E-1005" {
			t.Fatalf("denial replay: %d %v", st, body)
		}
	})

	t.Run("code_expires_after_15m", func(t *testing.T) {
		_, code := h.startEnrollment()
		h.clk.Advance(16 * time.Minute)
		st, body := h.poll(code)
		if st != http.StatusBadRequest || errCode(body) != "M1E-1004" {
			t.Fatalf("expiry: %d %v", st, body)
		}
		var status string
		if err := h.admin.QueryRow(ctx, `
			SELECT status FROM m1_device_enrollments
			 WHERE device_code_hash = sha256($1::bytea)`, []byte(code)).Scan(&status); err != nil || status != "expired" {
			t.Fatalf("row status: %q %v", status, err)
		}
		// EXPIRED is terminal: a later poll repeats M1E-1004 without reviving.
		st, body = h.poll(code)
		if st != http.StatusBadRequest || errCode(body) != "M1E-1004" {
			t.Fatalf("expired replay: %d %v", st, body)
		}
	})

	t.Run("unknown_code_rejected", func(t *testing.T) {
		st, body := h.poll(encodeGarbageCode(h.tenantA))
		if st != http.StatusBadRequest || errCode(body) != "M1E-1004" {
			t.Fatalf("unknown code: %d %v", st, body)
		}
	})

	t.Run("cross_tenant_operator_binding", func(t *testing.T) {
		// Tenant C: onboarded against the SAME IdP as tenant A — same issuer,
		// same pinned JWKS, same audience, same admin claim/value. Nothing in
		// that config is per-tenant, so without the m1_tenant binding a genuine
		// A-admin token would verify cleanly against C's config and administer
		// C's fleet (the finding this test pins closed).
		var tenantC uuid.UUID
		if err := h.admin.QueryRow(ctx, `
			INSERT INTO m1_tenants (org_id, name,
			  oidc_issuer, oidc_client_id, oidc_jwks_uri, oidc_jwks_pinned,
			  oidc_device_authorization_endpoint, oidc_token_endpoint, oidc_discovered_at,
			  operator_audience, operator_admin_claim, operator_admin_value)
			SELECT org_id, 'tenant-c', oidc_issuer, oidc_client_id, oidc_jwks_uri, oidc_jwks_pinned,
			       oidc_device_authorization_endpoint, oidc_token_endpoint, oidc_discovered_at,
			       operator_audience, operator_admin_claim, operator_admin_value
			  FROM m1_tenants WHERE id = $1 RETURNING id`, h.tenantA).Scan(&tenantC); err != nil {
			t.Fatal(err)
		}
		before := operatorMismatchCount(t)
		st, body := h.post("/api/v1/enroll/revoke",
			map[string]string{"device_id": deviceID.String(), "reason": "cross-tenant"},
			map[string]string{
				"Authorization": "Bearer " + h.operatorToken("m1-admin"), // bound to tenant A
				"X-M1-Tenant":   tenantC.String(),
			})
		if st != http.StatusForbidden || errCode(body) != "M1E-1001" {
			t.Fatalf("cross-tenant revoke: %d %v (want 403 M1E-1001)", st, body)
		}
		if got := operatorMismatchCount(t); got != before+1 {
			t.Fatalf("cross-tenant attempt must be a security event: counter %v -> %v", before, got)
		}
		// The device is untouched: the refusal happened before any write.
		var revoked bool
		if err := h.admin.QueryRow(ctx,
			`SELECT revoked_at IS NOT NULL FROM m1_devices WHERE id = $1`, deviceID).Scan(&revoked); err != nil || revoked {
			t.Fatalf("cross-tenant attempt revoked the device: %v %v", revoked, err)
		}
		// A token with NO m1_tenant binding at all is refused too — fail
		// closed: an unbound admin token is exactly the pre-ruling shape.
		st, body = h.get("/api/v1/enroll/devices", map[string]string{
			"Authorization": "Bearer " + h.mintOperatorJWT("ops@enroll-it.example", "mark1-console", "m1-admin", uuid.Nil),
			"X-M1-Tenant":   h.tenantA.String(),
		})
		if st != http.StatusForbidden || errCode(body) != "M1E-1001" {
			t.Fatalf("unbound operator token: %d %v (want 403 M1E-1001)", st, body)
		}
	})

	t.Run("revoke", func(t *testing.T) {
		hdr := map[string]string{
			"Authorization": "Bearer " + h.operatorToken("m1-admin"),
			"X-M1-Tenant":   h.tenantA.String(),
		}
		// A non-admin operator token is refused (M1E-1001).
		badHdr := map[string]string{
			"Authorization": "Bearer " + h.operatorToken("m1-viewer"),
			"X-M1-Tenant":   h.tenantA.String(),
		}
		st, body := h.post("/api/v1/enroll/revoke",
			map[string]string{"device_id": deviceID.String(), "reason": "offboarding"}, badHdr)
		if st != http.StatusForbidden || errCode(body) != "M1E-1001" {
			t.Fatalf("non-admin revoke: %d %v", st, body)
		}
		// Unknown device 404s.
		st, body = h.post("/api/v1/enroll/revoke",
			map[string]string{"device_id": uuid.NewString(), "reason": "x"}, hdr)
		if st != http.StatusNotFound || errCode(body) != "M1E-1006" {
			t.Fatalf("unknown device: %d %v", st, body)
		}
		// The real revoke.
		st, body = h.post("/api/v1/enroll/revoke",
			map[string]string{"device_id": deviceID.String(), "reason": "offboarding"}, hdr)
		if st != http.StatusOK || body["state"] != "revoked" {
			t.Fatalf("revoke: %d %v", st, body)
		}
		// Authority row + the §3.4 epoch bump, exactly once.
		var epoch int64
		var revokedBy string
		if err := h.admin.QueryRow(ctx, `
			SELECT t.revocation_epoch, d.revoked_by
			  FROM m1_tenants t JOIN m1_devices d ON d.tenant_id = t.id
			 WHERE d.id = $1`, deviceID).Scan(&epoch, &revokedBy); err != nil {
			t.Fatal(err)
		}
		if epoch != 1 || revokedBy != "ops@enroll-it.example" {
			t.Fatalf("epoch/attribution: %d %q", epoch, revokedBy)
		}
		// Idempotent re-revoke: 200, but the epoch does not double-bump.
		if st, _ := h.post("/api/v1/enroll/revoke",
			map[string]string{"device_id": deviceID.String(), "reason": "again"}, hdr); st != http.StatusOK {
			t.Fatalf("re-revoke: %d", st)
		}
		if err := h.admin.QueryRow(ctx,
			`SELECT revocation_epoch FROM m1_tenants WHERE id = $1`, h.tenantA).Scan(&epoch); err != nil || epoch != 1 {
			t.Fatalf("epoch double-bumped: %d %v", epoch, err)
		}
		// The still-unexpired token now fails verification as REVOKED — for
		// the revoked reason, not a signature reason.
		if _, err := h.verify.Verify(ctx, deviceToken); !errors.Is(err, auth.ErrRevoked) {
			t.Fatalf("want ErrRevoked, got %v", err)
		}
		// PoP refresh is terminal too: 403 M1E-1003, re-enroll.
		st, body = h.popRefresh(devicePriv, deviceID)
		if st != http.StatusForbidden || errCode(body) != "M1E-1003" {
			t.Fatalf("refresh after revoke: %d %v", st, body)
		}
		// The approved grant row is closed (drops out of the token index).
		var status string
		if err := h.admin.QueryRow(ctx, `
			SELECT status FROM m1_device_enrollments WHERE device_id = $1`, deviceID).Scan(&status); err != nil || status != "revoked" {
			t.Fatalf("grant not closed: %q %v", status, err)
		}
		// 05 §3.6(b) as a database fact: the same revoke tx retired every live
		// credential fingerprint, so the uq_m1_fp_live row is CLOSED — zero
		// live rows, the stamped row still present for audit.
		var live, total int64
		if err := h.admin.QueryRow(ctx, `
			SELECT count(*) FILTER (WHERE revoked_at IS NULL), count(*)
			  FROM m1_device_credential_fingerprints WHERE device_id = $1`, deviceID).Scan(&live, &total); err != nil {
			t.Fatal(err)
		}
		if live != 0 || total == 0 {
			t.Fatalf("fingerprints after revoke: %d live / %d total (want 0 live, rows retained)", live, total)
		}
	})

	t.Run("devices_list", func(t *testing.T) {
		hdr := map[string]string{
			"Authorization": "Bearer " + h.operatorToken("m1-admin"),
			"X-M1-Tenant":   h.tenantA.String(),
		}
		st, body := h.get("/api/v1/enroll/devices", hdr)
		if st != http.StatusOK {
			t.Fatalf("list: %d %v", st, body)
		}
		devices := body["devices"].([]any)
		if len(devices) != 1 { // only one device was ever minted
			t.Fatalf("want 1 device, got %d", len(devices))
		}
		d := devices[0].(map[string]any)
		if d["device_id"] != deviceID.String() || d["state"] != "revoked" {
			t.Fatalf("device row: %v", d)
		}
		// No operator token, no fleet view.
		if st, _ := h.get("/api/v1/enroll/devices", nil); st != http.StatusForbidden {
			t.Fatalf("unauthenticated list: %d", st)
		}
	})
}

// operatorMismatchCount reads the security-event counter for cross-tenant
// operator attempts off the default registry (promauto registers it there).
func operatorMismatchCount(t *testing.T) float64 {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() == "controld_enroll_operator_tenant_mismatch_total" {
			return mf.GetMetric()[0].GetCounter().GetValue()
		}
	}
	return 0
}

// encodeGarbageCode builds a structurally valid device_code that hashes to
// nothing in the registry.
func encodeGarbageCode(tenant uuid.UUID) string {
	hdr, _ := json.Marshal(map[string]any{
		"v": 1, "t": tenant.String(), "p": "linux",
		"h": hex.EncodeToString(make([]byte, 32)),
	})
	return base64.RawURLEncoding.EncodeToString(hdr) + ".never-issued"
}
