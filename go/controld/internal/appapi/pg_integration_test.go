//go:build integration

package appapi

// DSN-gated (M1_MIGRATE_PG_DSN; M1_REQUIRE_STORES=1 fails instead of skipping): the three Postgres-backed routes against a scratch database carrying the REAL migration tree (m1_079's grant included), as a NOBYPASSRLS role granted controld_app — so every read here runs under FORCE RLS + the tenant GUC. Two tenants, every row planted for both, and the admin view is the authority that turns "B saw none of A's rows" into a finding.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/pg"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/policydist"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/receipts"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/userauth"
)

type pgRig struct {
	t       *testing.T
	admin   *pgx.Conn
	db      *pg.TenantDB
	store   *policydist.Store
	api     *httptest.Server
	schema  *schemaSet
	orgID   uuid.UUID
	userKey *ecdsa.PrivateKey
}

func setupPG(t *testing.T) *pgRig {
	t.Helper()
	dsn := os.Getenv("M1_MIGRATE_PG_DSN")
	if dsn == "" {
		if os.Getenv("M1_REQUIRE_STORES") == "1" {
			t.Fatal("M1_MIGRATE_PG_DSN required (M1_REQUIRE_STORES=1) but unset")
		}
		t.Skip("M1_MIGRATE_PG_DSN unset; skipping Postgres-backed test")
	}
	ctx := context.Background()
	adminCfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, err := pgx.ConnectConfig(ctx, adminCfg)
	if err != nil {
		t.Fatalf("cannot reach test Postgres: %v", err)
	}
	scratch := fmt.Sprintf("controld_appapi_it_%d", time.Now().UnixNano())
	role := fmt.Sprintf("appapiapp_%d", time.Now().UnixNano())
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

	// The whole migration tree in filename order; m1_060 touches cluster-global roles, so the phase serializes on the shared advisory lock.
	if _, err := bootstrap.Exec(ctx, `SELECT pg_advisory_lock(7231060)`); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join("..", "..", "..", "..", "migrations", "m1_0*.sql"))
	if err != nil || len(files) == 0 {
		t.Fatalf("migrations not found: %v", err)
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
	_, roleErr := admin.Exec(ctx, fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD 'appapitest' NOBYPASSRLS NOSUPERUSER; GRANT controld_app TO %s", role, role))
	if _, err := bootstrap.Exec(ctx, `SELECT pg_advisory_unlock(7231060)`); err != nil {
		t.Fatal(err)
	}
	if roleErr != nil {
		t.Fatal(roleErr)
	}

	pool, err := pg.Open(ctx, fmt.Sprintf("postgres://%s:appapitest@%s:%d/%s?sslmode=disable", role, adminCfg.Host, adminCfg.Port, scratch))
	if err != nil {
		t.Fatalf("pg.Open as NOBYPASSRLS role: %v", err)
	}
	t.Cleanup(pool.Close)
	db := pg.NewTenantDB(pool)

	chainSigner, err := receipts.NewSigner(bytes.Repeat([]byte{0x33}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := receipts.RegisterServerKey(ctx, admin, chainSigner); err != nil {
		t.Fatal(err)
	}
	ring, err := policydist.DeriveKeyring(bytes.Repeat([]byte{0x44}, 32))
	if err != nil {
		t.Fatal(err)
	}
	store := policydist.NewStore(db, receipts.NewStore(db, chainSigner), ring, chainSigner)

	var orgID uuid.UUID
	if err := admin.QueryRow(ctx, `INSERT INTO m1_organizations (name, primary_domain) VALUES ('appapi-it', 'appapi-it.example') RETURNING id`).Scan(&orgID); err != nil {
		t.Fatal(err)
	}

	reg, err := querychoke.LoadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	userKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	userJWK := jose.JSONWebKey{Key: userKey.Public(), Algorithm: "ES256", Use: "sig", KeyID: "it"}
	userJWKS, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{userJWK}})
	users, err := userauth.New("https://issuer.it", string(userJWKS))
	if err != nil {
		t.Fatal(err)
	}
	// main.go's `reads` composition: the device verifier first, the Mark 1 user token beside it (desktop spec §7.2).
	verifier := auth.Multi(auth.NewHMACVerifier([]byte(testKey), auth.StaticRevocations{}), users.TenantVerifier())
	obsCfg := obs.Config{ServiceName: "appapi-pg-it"}
	run := &fakeRunner{}
	m := New(Deps{
		Verifier: verifier, ObsCfg: obsCfg, Registry: reg, Runner: run,
		Reports: querychoke.New(querychoke.Deps{Registry: reg, Runner: run, Verifier: verifier, ObsCfg: obsCfg}),
		PG:      db, Regimes: querychoke.PGRegimes{DB: db},
	})
	mux := http.NewServeMux()
	m.RegisterRoutes(mux)
	api := httptest.NewServer(mux)
	t.Cleanup(api.Close)
	return &pgRig{t: t, admin: admin, db: db, store: store, api: api, schema: loadSchemas(t), orgID: orgID, userKey: userKey}
}

// userToken mints the platform's Mark 1 user token (ES256, aud mark1) for sub over tenant.
func (r *pgRig) userToken(sub string, tenant uuid.UUID) string {
	r.t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: r.userKey}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		r.t.Fatal(err)
	}
	now := time.Now()
	payload, _ := json.Marshal(map[string]any{
		"iss": "https://issuer.it", "aud": "mark1", "sub": sub, "email": sub + "@it.example",
		"tenant_id": tenant.String(), "rol": []string{"member"}, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	})
	jws, err := signer.Sign(payload)
	if err != nil {
		r.t.Fatal(err)
	}
	raw, err := jws.CompactSerialize()
	if err != nil {
		r.t.Fatal(err)
	}
	return raw
}

func (r *pgRig) tenant(name, region string) uuid.UUID {
	r.t.Helper()
	var id uuid.UUID
	if err := r.admin.QueryRow(context.Background(), `INSERT INTO m1_tenants (org_id, name, region) VALUES ($1, $2, $3) RETURNING id`, r.orgID, name, region).Scan(&id); err != nil {
		r.t.Fatal(err)
	}
	return id
}

func (r *pgRig) tid(id uuid.UUID) querychoke.TenantID {
	r.t.Helper()
	t, err := querychoke.FromClaims(auth.Claims{TenantID: id})
	if err != nil {
		r.t.Fatal(err)
	}
	return t
}

func (r *pgRig) get(path string, tenant uuid.UUID) (int, []byte) {
	return r.getAs(path, auth.Mint([]byte(testKey), tenant, uuid.New(), time.Hour))
}

func (r *pgRig) getAs(path, bearer string) (int, []byte) {
	r.t.Helper()
	req, err := http.NewRequest(http.MethodGet, r.api.URL+path, nil)
	if err != nil {
		r.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	return resp.StatusCode, buf.Bytes()
}

func (r *pgRig) ok(path string, tenant uuid.UUID, schema string) map[string]any {
	r.t.Helper()
	code, body := r.get(path, tenant)
	if code != http.StatusOK {
		r.t.Fatalf("GET %s: %d %s", path, code, body)
	}
	r.schema.Validate(schema, body)
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		r.t.Fatal(err)
	}
	return out
}

func (r *pgRig) adminCount(table string) int64 {
	r.t.Helper()
	var n int64
	if err := r.admin.QueryRow(context.Background(), "SELECT count(*) FROM "+table).Scan(&n); err != nil {
		r.t.Fatal(err)
	}
	return n
}

func TestIntegrationMeAndRegimeUnderRLS(t *testing.T) {
	r := setupPG(t)
	ctx := context.Background()
	tenantA, tenantB := r.tenant("Acme", "eu-west-1"), r.tenant("Globex", "us-east-1")
	if _, err := r.admin.Exec(ctx, `INSERT INTO m1_tenant_regimes (tenant_id, cost_basis, price_model_id, v_default, set_by) VALUES ($1, 'usd', 'claude-opus-5', 25, 'appapi-it')`, tenantA); err != nil {
		t.Fatal(err)
	}
	me := r.ok("/api/v1/me", tenantA, "me.json")
	tenant := me["tenant"].(map[string]any)
	if tenant["id"] != tenantA.String() || tenant["name"] != "Acme" || tenant["region"] != "eu-west-1" || me["region"] != "eu-west-1" || tenant["status"] != "active" {
		t.Fatalf("tenant: %v", me)
	}
	if me["user"].(map[string]any)["kind"] != "device" || me["plan"] != nil {
		t.Fatalf("device principal, plan placeholder: %v", me)
	}
	if reg := me["regime"].(map[string]any); reg["cost_basis"] != "usd" || reg["price_model_id"] != "claude-opus-5" {
		t.Fatalf("regime from m1_075: %v", reg)
	}
	meB := r.ok("/api/v1/me", tenantB, "me.json")
	if meB["regime"] != nil || meB["tenant"].(map[string]any)["name"] != "Globex" {
		t.Fatalf("no regime row ⇒ null; own tenant row: %v", meB)
	}
	if raw, _ := json.Marshal(meB); strings.Contains(string(raw), "Acme") || strings.Contains(string(raw), tenantA.String()) {
		t.Fatalf("B's /me carried A: %s", raw)
	}
	// The desktop app's principal (spec §7.2): the Mark 1 user token reads its own tenant, /me names the user, and a token for B never sees A.
	sub := uuid.NewString()
	code, body := r.getAs("/api/v1/me", r.userToken(sub, tenantA))
	if code != http.StatusOK {
		t.Fatalf("user token on /me: %d %s", code, body)
	}
	r.schema.Validate("me.json", body)
	var meU map[string]any
	_ = json.Unmarshal(body, &meU)
	if u := meU["user"].(map[string]any); u["kind"] != "user" || u["id"] != sub || meU["tenant"].(map[string]any)["name"] != "Acme" {
		t.Fatalf("user principal: %v", meU)
	}
	if code, body := r.getAs("/api/v1/me", r.userToken(sub, tenantB)); code != http.StatusOK || strings.Contains(string(body), "Acme") {
		t.Fatalf("user token for B: %d %s", code, body)
	}
	if code, _ := r.getAs("/api/v1/me", r.userToken(sub, tenantA)+"x"); code != http.StatusUnauthorized {
		t.Fatalf("tampered user token admitted: %d", code)
	}
}

func TestIntegrationCertificatesUnderRLS(t *testing.T) {
	r := setupPG(t)
	ctx := context.Background()
	tenantA, tenantB := r.tenant("Acme", "eu-west-1"), r.tenant("Globex", "us-east-1")
	var verifierID uuid.UUID
	if err := r.admin.QueryRow(ctx, `INSERT INTO m1_verifiers (verifier_key, kind, version, display_name, definition) VALUES ('judge:e1-default', 'judge', 2, 'E1 judge', '{"model":"x"}') RETURNING id`).Scan(&verifierID); err != nil {
		t.Fatal(err)
	}
	var certA, certB uuid.UUID
	if err := r.admin.QueryRow(ctx, `INSERT INTO noise_certificates (tenant_id, verifier_id, status, rho_plus, rho_minus, natarajan_lcb, gold_n, identifiable, issued_at, expires_at)
		VALUES ($1, $2, 'bootstrapping', 0.12, 0.08, 0.31, 120, true, now() - interval '1 day', now() + interval '29 days') RETURNING id`, tenantA, verifierID).Scan(&certA); err != nil {
		t.Fatal(err)
	}
	if err := r.admin.QueryRow(ctx, `INSERT INTO noise_certificates (tenant_id, verifier_id) VALUES ($1, $2) RETURNING id`, tenantB, verifierID).Scan(&certB); err != nil {
		t.Fatal(err)
	}
	if r.adminCount("noise_certificates") != 2 {
		t.Fatal("authority view: two certificates exist")
	}
	body := r.ok("/api/v1/verify/certificates", tenantA, "certificates.json")
	certs := body["certificates"].([]any)
	if len(certs) != 1 {
		t.Fatalf("A sees exactly its own certificate: %v", body)
	}
	c := certs[0].(map[string]any)
	if c["id"] != certA.String() || c["status"] != "bootstrapping" || c["rho_plus"] != 0.12 || c["natarajan_lcb"] != 0.31 || c["gold_n"] != float64(120) || c["identifiable"] != true || c["active"] != false {
		t.Fatalf("certificate row: %v", c)
	}
	if v := c["verifier"].(map[string]any); v["id"] != verifierID.String() || v["key"] != "judge:e1-default" || v["kind"] != "judge" || v["version"] != float64(2) || v["display_name"] != "E1 judge" {
		t.Fatalf("verifier join: %v", v)
	}
	if c["issued_at"] == nil || c["expires_at"] == nil || c["receipt_id"] != nil {
		t.Fatalf("timestamps and the absent receipt: %v", c)
	}
	bodyB := r.ok("/api/v1/verify/certificates", tenantB, "certificates.json")
	certsB := bodyB["certificates"].([]any)
	if len(certsB) != 1 || certsB[0].(map[string]any)["id"] != certB.String() || certsB[0].(map[string]any)["status"] != "uncertified" || certsB[0].(map[string]any)["rho_plus"] != nil {
		t.Fatalf("B sees exactly its own, nulls intact: %v", bodyB)
	}
	if raw, _ := json.Marshal(bodyB); strings.Contains(string(raw), certA.String()) {
		t.Fatalf("A's certificate leaked to B: %s", raw)
	}
}

func canonicalSections(t *testing.T) []byte {
	t.Helper()
	opts := cbor.CoreDetEncOptions()
	opts.Time, opts.TimeTag = cbor.TimeUnix, cbor.EncTagRequired
	enc, err := opts.EncMode()
	if err != nil {
		t.Fatal(err)
	}
	plcb, debounce, maxItems, optIn := 0.91, uint64(250), uint64(8), true
	raw, err := enc.Marshal(policydist.Sections{
		Verify: policydist.VerifySection{
			Anchors:   []policydist.AnchorEnable{{CatalogID: "pytest.exit_code", Enabled: true, DebounceMS: &debounce}},
			Verifiers: []policydist.VerifierModel{{VerifierID: "pytest@1.2.3", Confusion: [4][3]float64{{0.9, 0.05, 0.05}, {0.05, 0.9, 0.05}, {0.1, 0.1, 0.8}, {0.2, 0.2, 0.6}}}},
			Priors:    [4]float64{0.7, 0.15, 0.1, 0.05},
		},
		Route: policydist.RouteSection{
			CPVS:             []policydist.CPVSRow{{TaskClass: "edit.small", ModelID: "claude-sonnet", PPass: 0.82, TokensEst: 1200}},
			Ladders:          []policydist.Ladder{{LadderID: "default", Rungs: []policydist.Rung{{ModelID: "claude-haiku", KeepPrefix: true}, {ModelID: "claude-opus"}}}},
			Knee:             policydist.KneeTable{CostBasis: "usd", Rows: []policydist.KneeRow{{N: 1, CN: 0.01, PLCB: &plcb}, {N: 2, CN: 0.02}}, VDefault: 1.5},
			Exploration:      &policydist.Exploration{Epsilon: 0.03},
			ExplorationOptIn: &optIn,
		},
		Memory:    policydist.MemorySection{InjectionRules: []policydist.InjectionRule{{Facet: "repo.conventions", MaxItems: &maxItems}}, Budgets: policydist.MemoryBudgets{PackTokensMax: 4000}},
		Cortex:    policydist.CortexSection{MapBudgetTokens: policydist.BudgetRange{Min: 500, Max: 2000}, Channels: []string{"session_start"}},
		Gates:     policydist.GatesSection{StopGateEnabled: true, MaxConsecutiveBlocks: 3, HourlyBlockCeiling: 20},
		AgentMaps: policydist.AgentMapsSection{Agents: []policydist.AgentMap{{AgentID: "claudecode", AgentVersion: "1.0.88", HookFields: map[string]string{"session_id": "/session_id"}, TailerRules: map[string]string{"tool_use": "/message/content/0/name"}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestIntegrationRouteBundleFromCatalog(t *testing.T) {
	r := setupPG(t)
	ctx := context.Background()
	tenantA, tenantB := r.tenant("Acme", "eu-west-1"), r.tenant("Globex", "us-east-1")
	sections := canonicalSections(t)
	pub, err := r.store.Publish(ctx, r.tid(tenantA), policydist.Draft{Channel: "stable", MaxAge: 15 * time.Minute, SectionsCBOR: sections})
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	// The compiler's hand-off row for that publication, carrying the price-table stamp in knee_note (policy_compiler/jobs.py).
	const priced = "model_prices.v1@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if _, err := r.admin.Exec(ctx, `INSERT INTO bundle_drafts (tenant_id, channel, window_start, verify_cbor, route_cbor, memory_cbor, cortex_cbor, gates_cbor, agent_maps_cbor, draft_hash, max_age, knee_gate_ok, knee_note, state, published_seq)
		VALUES ($1, 'stable', now(), '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', $2, interval '15 minutes', true, $3, 'published', $4)`,
		tenantA, bytes.Repeat([]byte{0xab}, 32), "implied knee 2 within +-1 of k*; priced by "+priced, pub.Seq); err != nil {
		t.Fatal(err)
	}

	body := r.ok("/api/v1/route/bundle", tenantA, "route_bundle.json")
	if body["channel"] != "stable" || body["seq"] != float64(pub.Seq) || body["max_age_s"] != float64(900) || body["signing_key_id"] == "" {
		t.Fatalf("catalog head: %v", body)
	}
	ladders := body["ladders"].([]any)
	if len(ladders) != 1 || len(ladders[0].(map[string]any)["rungs"].([]any)) != 2 || ladders[0].(map[string]any)["rungs"].([]any)[0].(map[string]any)["keep_prefix"] != true {
		t.Fatalf("ladders: %v", ladders)
	}
	knee := body["knee"].(map[string]any)
	rows := knee["rows"].([]any)
	if knee["cost_basis"] != "usd" || knee["v_default"] != 1.5 || len(rows) != 2 || rows[0].(map[string]any)["p_lcb"] != 0.91 || rows[1].(map[string]any)["p_lcb"] != nil {
		t.Fatalf("knee table, D-Z null preserved: %v", knee)
	}
	if body["epsilon"] != 0.03 || body["exploration_opt_in"] != true || body["price_table_version"] != priced {
		t.Fatalf("epsilon, opt-in, price table: %v", body)
	}
	if body["cpvs"].([]any)[0].(map[string]any)["task_class"] != "edit.small" {
		t.Fatalf("cpvs: %v", body["cpvs"])
	}
	// Second read is served from the memo: same body, byte for byte.
	if again := r.ok("/api/v1/route/bundle?channel=stable", tenantA, "route_bundle.json"); jsonString(t, again) != jsonString(t, body) {
		t.Fatalf("memoized read differs: %v vs %v", again, body)
	}
	// B has no bundle: 404 M1E-3004, and never A's catalog row (RLS + the tenant predicate).
	for _, path := range []string{"/api/v1/route/bundle", "/api/v1/route/bundle?channel=canary", "/api/v1/route/bundle?channel=Bad%20Channel"} {
		code, raw := r.get(path, tenantB)
		r.schema.Validate("error.json", raw)
		if code != http.StatusNotFound || !strings.Contains(string(raw), "M1E-3004") || strings.Contains(string(raw), "claude-haiku") {
			t.Fatalf("GET %s as B: %d %s", path, code, raw)
		}
	}
	// A superseding publication moves the head; the memo keys on seq, so the new head is decoded, not the cached one.
	second, err := r.store.Publish(ctx, r.tid(tenantA), policydist.Draft{Channel: "stable", MaxAge: 30 * time.Minute, SectionsCBOR: sections})
	if err != nil {
		t.Fatal(err)
	}
	if head := r.ok("/api/v1/route/bundle", tenantA, "route_bundle.json"); head["seq"] != float64(second.Seq) || head["max_age_s"] != float64(1800) || head["price_table_version"] != nil {
		t.Fatalf("new head without a drafts row: %v", head)
	}
}
