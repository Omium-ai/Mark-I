//go:build integration

// DSN-gated Postgres integration for policy distribution (house style, 12 /
// 05 §7.5): a scratch database gets the real migrations, a NOBYPASSRLS login
// role stands in for controld_app, and the suite proves the properties the
// schema claims rather than the ones Go happens to enforce.
//
// THE THREE THINGS THIS FILE EXISTS FOR:
//  1. A seq cannot be reused and a published body cannot be mutated -- AS THE
//     DATABASE, with the table owner doing the mutating, because a rule only
//     Go obeys is a rule an incident ignores.
//  2. A wrong-tenant read returns ZERO rows on every table this module writes.
//     This estate shipped 61 FORCE-RLS tables that were inert; a test that only
//     proves the right tenant can read proves nothing, so every assertion here
//     is paired with an admin count proving the zero was RLS and not emptiness.
//  3. A bundle carrying a command string never gets a seq. The refusal must
//     happen before the head row moves, or a bad compile burns a sequence
//     number the chain can never reuse.
//
// Internal test package on purpose: it reuses validSections() and mustEncode()
// from bundle_test.go, so the bytes published here are the same bytes the unit
// suite validates.
//
// Gate: M1_MIGRATE_PG_DSN (privileged DSN for scratch setup). Absent => skip,
// unless M1_REQUIRE_STORES=1 => fail.

package policydist

import (
	"bufio"
	"bytes"
	"context"
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
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/pg"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/receipts"
)

// TEST-ONLY seeds. Anything signed by these is worthless outside this file.
var (
	itChainSeed   = bytes.Repeat([]byte{0x33}, 32)
	itSectionSeed = bytes.Repeat([]byte{0x44}, 32)
	itTokenSeed   = bytes.Repeat([]byte{0x55}, 32)
)

// The privileged DSN: this harness creates its own scratch database and applies
// the full migration tree, and m1_060 mints a BYPASSRLS role — which PG16 permits
// only to a role that already holds it. The tests themselves run as the
// unprivileged role minted below, never as this one.
func itPGDSN(t *testing.T) string {
	t.Helper()
	v := os.Getenv("M1_MIGRATE_PG_DSN")
	if v == "" {
		if os.Getenv("M1_REQUIRE_STORES") == "1" {
			t.Fatal("M1_MIGRATE_PG_DSN required (M1_REQUIRE_STORES=1) but unset")
		}
		t.Skip("M1_MIGRATE_PG_DSN unset; skipping Postgres-backed test")
	}
	return v
}

type itHarness struct {
	t     *testing.T
	admin *pgx.Conn // owner/superuser: the authority view, and the mutations RLS must not hide
	db    *pg.TenantDB
	mod   *Module
	ring  *Keyring
	api   *httptest.Server

	tenantA, tenantB            querychoke.TenantID
	tenantAID, tenantBID        uuid.UUID
	deviceA1, deviceA2, deviceB uuid.UUID
	tokenA1, tokenA2, tokenB    string
}

func itSetup(t *testing.T) *itHarness {
	t.Helper()
	ctx := context.Background()
	dsn := itPGDSN(t)

	adminCfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, err := pgx.ConnectConfig(ctx, adminCfg)
	if err != nil {
		t.Fatalf("cannot reach test Postgres: %v", err)
	}
	scratch := fmt.Sprintf("controld_policydist_it_%d", time.Now().UnixNano())
	role := fmt.Sprintf("policydistapp_%d", time.Now().UnixNano())
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

	// The real migrations in filename order (05 §7.4) -- including m1_060's
	// role matrix and m1_062's transparency log, which is the ordering the
	// grants depend on. m1_060 touches cluster-GLOBAL role tuples, so the
	// migration+role phase serializes on the same advisory lock the other
	// store-backed packages use.
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
	_, roleErr := admin.Exec(ctx, fmt.Sprintf(
		"CREATE ROLE %s LOGIN PASSWORD 'policydisttest' NOBYPASSRLS NOSUPERUSER; GRANT controld_app TO %s", role, role))
	if _, uerr := bootstrap.Exec(ctx, `SELECT pg_advisory_unlock(7231060)`); uerr != nil {
		t.Fatal(uerr)
	}
	if roleErr != nil {
		t.Fatal(roleErr)
	}

	var orgID uuid.UUID
	if err := admin.QueryRow(ctx,
		`INSERT INTO m1_organizations (name, primary_domain) VALUES ('policydist-it', 'policydist-it.example') RETURNING id`,
	).Scan(&orgID); err != nil {
		t.Fatal(err)
	}
	newTenant := func(name string) uuid.UUID {
		var id uuid.UUID
		if err := admin.QueryRow(ctx,
			`INSERT INTO m1_tenants (org_id, name) VALUES ($1, $2) RETURNING id`, orgID, name).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	newDevice := func(tenant uuid.UUID) uuid.UUID {
		var id uuid.UUID
		// last_seen_at inside 24 h: AckCoverage's denominator is "active
		// devices", and a device that has never phoned home is not one.
		if err := admin.QueryRow(ctx, `
			INSERT INTO m1_devices (tenant_id, platform, hostname_hmac, last_seen_at)
			VALUES ($1, 'linux-x86_64', decode(repeat('ab', 32), 'hex'), now())
			RETURNING id`, tenant).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	tenantAID, tenantBID := newTenant("tenant-a"), newTenant("tenant-b")

	chainSigner, err := receipts.NewSigner(itChainSeed)
	if err != nil {
		t.Fatal(err)
	}
	if err := receipts.RegisterServerKey(ctx, admin, chainSigner); err != nil {
		t.Fatal(err)
	}

	appDSN := fmt.Sprintf("postgres://%s:policydisttest@%s:%d/%s?sslmode=disable",
		role, adminCfg.Host, adminCfg.Port, scratch)
	pool, err := pg.Open(ctx, appDSN)
	if err != nil {
		t.Fatalf("pg.Open as NOBYPASSRLS role: %v", err)
	}
	t.Cleanup(pool.Close)
	db := pg.NewTenantDB(pool)

	ring, err := DeriveKeyring(itSectionSeed)
	if err != nil {
		t.Fatal(err)
	}
	tokenSigner, err := auth.NewSigner(itTokenSeed)
	if err != nil {
		t.Fatal(err)
	}
	mod := NewModule(ModuleDeps{
		Store:    NewStore(db, receipts.NewStore(db, chainSigner), ring, chainSigner),
		PG:       db,
		Verifier: auth.NewEd25519Verifier(tokenSigner.Public(), auth.StaticRevocations{}),
		ObsCfg:   obs.Config{ServiceName: "controld-policydist-it"},
	})
	mux := http.NewServeMux()
	mod.RegisterRoutes(mux)
	api := httptest.NewServer(mux)
	t.Cleanup(api.Close)

	h := &itHarness{
		t: t, admin: admin, db: db, mod: mod, ring: ring, api: api,
		tenantA: itTenant(t, tenantAID), tenantB: itTenant(t, tenantBID),
		tenantAID: tenantAID, tenantBID: tenantBID,
		deviceA1: newDevice(tenantAID), deviceA2: newDevice(tenantAID), deviceB: newDevice(tenantBID),
	}
	mint := func(tenant, device uuid.UUID) string {
		now := time.Now()
		tok, err := tokenSigner.Mint(tenant, device, "ed25519:integration", now, now.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	h.tokenA1 = mint(tenantAID, h.deviceA1)
	h.tokenA2 = mint(tenantAID, h.deviceA2)
	h.tokenB = mint(tenantBID, h.deviceB)
	return h
}

func itTenant(t *testing.T, id uuid.UUID) querychoke.TenantID {
	t.Helper()
	tid, err := querychoke.FromClaims(auth.Claims{TenantID: id})
	if err != nil {
		t.Fatal(err)
	}
	return tid
}

func (h *itHarness) draft(channel string) Draft {
	return Draft{Channel: channel, MaxAge: 15 * time.Minute, SectionsCBOR: mustEncode(h.t, validSections())}
}

// adminCount is the authority view: superuser, no tenant GUC, no RLS. It is
// what turns "tenant B saw zero rows" from a tautology into a finding.
func (h *itHarness) adminCount(table string) int64 {
	h.t.Helper()
	var n int64
	if err := h.admin.QueryRow(context.Background(), "SELECT count(*) FROM "+table).Scan(&n); err != nil {
		h.t.Fatalf("admin count of %s: %v", table, err)
	}
	return n
}

func (h *itHarness) headSeq(channel string) int64 {
	h.t.Helper()
	var seq int64
	err := h.admin.QueryRow(context.Background(),
		`SELECT head_seq FROM bundle_channel_heads WHERE tenant_id = $1 AND channel = $2`,
		h.tenantAID, channel).Scan(&seq)
	if err == pgx.ErrNoRows {
		return -1 // no head row at all, which is distinguishable from head 0
	}
	if err != nil {
		h.t.Fatal(err)
	}
	return seq
}

func (h *itHarness) req(method, path, token string, body io.Reader, hdr map[string]string) *http.Response {
	h.t.Helper()
	req, err := http.NewRequest(method, h.api.URL+path, body)
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp
}

// itClose exists only so the deferred close is a checked call: errcheck is on
// for _test.go in this repo, and `defer resp.Body.Close()` is not.
func itClose(r *http.Response) { _ = r.Body.Close() }

// itErr returns the 08 §9 code and the operator-facing message together: a
// bare status in a failure message sends the next reader back to the debugger.
func itErr(t *testing.T, resp *http.Response) (string, string) {
	t.Helper()
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(raw, &body)
	return body.Error.Code, body.Error.Message
}

func itErrCode(t *testing.T, resp *http.Response) string {
	t.Helper()
	code, _ := itErr(t, resp)
	return code
}

// ---------------------------------------------------------------------------

func TestIntegrationPolicyDistribution(t *testing.T) {
	h := itSetup(t)
	ctx := context.Background()

	var first, second Published

	t.Run("publish_chains_forward", func(t *testing.T) {
		var err error
		first, err = h.mod.Publish(ctx, h.tenantA, h.draft("stable"))
		if err != nil {
			t.Fatalf("first publish: %v", err)
		}
		if first.Seq != 1 || first.TLogIndex != 0 || first.TreeSize != 1 {
			t.Fatalf("first publication: seq %d leaf %d size %d", first.Seq, first.TLogIndex, first.TreeSize)
		}
		second, err = h.mod.Publish(ctx, h.tenantA, h.draft("stable"))
		if err != nil {
			t.Fatalf("second publish: %v", err)
		}
		if second.Seq != 2 {
			t.Fatalf("second publication seq %d, want 2", second.Seq)
		}
		// The chain: seq 2's prev_hash IS seq 1's body hash, as a stored fact.
		var prev []byte
		if err := h.admin.QueryRow(ctx,
			`SELECT prev_hash FROM policy_bundles WHERE tenant_id = $1 AND channel = 'stable' AND seq = 2`,
			h.tenantAID).Scan(&prev); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(prev, first.BodySHA256[:]) {
			t.Fatalf("seq 2 prev_hash %x does not chain to seq 1 body %x", prev, first.BodySHA256)
		}
		// And the head advanced with it, inside the same transaction.
		if got := h.headSeq("stable"); got != 2 {
			t.Fatalf("head_seq %d, want 2", got)
		}
		// Both publications are in the log, and the catalog's tlog_index
		// points at the leaf whose hash is the body hash.
		var leafHash []byte
		if err := h.admin.QueryRow(ctx,
			`SELECT l.leaf_hash FROM tlog_leaves l
			  JOIN policy_bundles b ON b.tlog_index = l.leaf_index AND b.tenant_id = l.tenant_id
			 WHERE b.tenant_id = $1 AND b.channel = 'stable' AND b.seq = 2`, h.tenantAID).Scan(&leafHash); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(leafHash, second.BodySHA256[:]) {
			t.Fatalf("leaf %x is not the published body %x", leafHash, second.BodySHA256)
		}
		// The publication receipt exists and is the row the catalog points at.
		var recordType string
		if err := h.admin.QueryRow(ctx,
			`SELECT r.record_type FROM m1_receipts r
			  JOIN policy_bundles b ON b.receipt_id = r.id
			 WHERE b.tenant_id = $1 AND b.seq = 2`, h.tenantAID).Scan(&recordType); err != nil {
			t.Fatal(err)
		}
		if recordType != "bundle_publication" {
			t.Fatalf("receipt class %q", recordType)
		}
	})

	t.Run("served_bundle_verifies_end_to_end", func(t *testing.T) {
		// Round trip through the wire, then through the DECODER an edge would
		// run: if the served bytes did not decode, every edge would report
		// M1E-3001 and we would find out from the fleet.
		resp := h.req(http.MethodGet, "/api/v1/policy/bundle?channel=stable", h.tokenA1, nil, nil)
		defer itClose(resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET bundle: %d", resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); ct != "application/cbor" {
			t.Fatalf("Content-Type %q", ct)
		}
		if resp.Header.Get("ETag") != second.ETag {
			t.Fatalf("ETag %q, want %q", resp.Header.Get("ETag"), second.ETag)
		}
		if resp.Header.Get("X-Mark1-Bundle-Seq") != "2" {
			t.Fatalf("seq header %q", resp.Header.Get("X-Mark1-Bundle-Seq"))
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(body, second.Body) {
			t.Fatal("served bytes differ from the signed bytes")
		}
		b, err := Unmarshal(body)
		if err != nil {
			t.Fatalf("served bundle does not decode: %v", err)
		}
		if b.Seq != 2 || b.Channel != "stable" || b.Inclusion == nil {
			t.Fatalf("decoded envelope: seq %d channel %q inclusion %v", b.Seq, b.Channel, b.Inclusion != nil)
		}
		if !bytes.Equal(b.TenantID, func() []byte { id := h.tenantAID; return id[:] }()) {
			t.Fatal("served bundle names the wrong tenant")
		}
		// Every section carries its OWN signature under its OWN key, over the
		// input the edge rebuilds from the bytes it received. Six sections, six
		// distinct key ids: a single-key bundle would pass a naive check and
		// then make one key compromise a compromise of all six sections.
		secBytes, err := sectionBytes(b.Sections)
		if err != nil {
			t.Fatal(err)
		}
		wantKeyIDs := h.ring.PublicKeyIDs()
		seenKeys := map[string]string{}
		for _, name := range SectionNames {
			sig, ok := b.Signatures[name]
			if !ok {
				t.Fatalf("no signature for section %q", name)
			}
			if len(sig.Sig) != 64 {
				t.Fatalf("section %q signature is %d bytes", name, len(sig.Sig))
			}
			if sig.KeyID != wantKeyIDs[name] {
				t.Fatalf("section %q signed under %q, want %q", name, sig.KeyID, wantKeyIDs[name])
			}
			if prev, dup := seenKeys[sig.KeyID]; dup {
				t.Fatalf("sections %q and %q share a signing key", prev, name)
			}
			seenKeys[sig.KeyID] = name
			input, err := SigningInput(b, name, secBytes[name])
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.HasPrefix(input, []byte(BundleDomainPrefix)) {
				t.Fatalf("section %q signing input is not domain-separated", name)
			}
		}
		// The inclusion proof the edge verifies before it decodes anything.
		if !VerifyInclusion(second.BodySHA256[:], b.Inclusion.LeafIndex, b.Inclusion.TreeSize,
			b.Inclusion.AuditPath, [32]byte(b.Inclusion.RootHash)) {
			t.Fatal("the served inclusion proof does not verify against the served root")
		}
		var storedRoot []byte
		if err := h.admin.QueryRow(ctx,
			`SELECT root_hash FROM tlog_signed_heads WHERE tenant_id = $1 AND tree_size = $2`,
			h.tenantAID, int64(b.Inclusion.TreeSize)).Scan(&storedRoot); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(storedRoot, b.Inclusion.RootHash) {
			t.Fatal("the served root is not the signed root of record")
		}
	})

	t.Run("conditional_get_is_304", func(t *testing.T) {
		resp := h.req(http.MethodGet, "/api/v1/policy/bundle?channel=stable", h.tokenA1, nil,
			map[string]string{"If-None-Match": second.ETag})
		defer itClose(resp)
		if resp.StatusCode != http.StatusNotModified {
			t.Fatalf("conditional GET: %d, want 304", resp.StatusCode)
		}
		// A stale validator must NOT 304 -- that is how a fleet pins itself to
		// an old bundle forever.
		resp2 := h.req(http.MethodGet, "/api/v1/policy/bundle?channel=stable", h.tokenA1, nil,
			map[string]string{"If-None-Match": first.ETag})
		defer itClose(resp2)
		if resp2.StatusCode != http.StatusOK {
			t.Fatalf("stale validator: %d, want 200", resp2.StatusCode)
		}
	})

	t.Run("unknown_channel_is_3004", func(t *testing.T) {
		resp := h.req(http.MethodGet, "/api/v1/policy/bundle?channel=canary", h.tokenA2, nil, nil)
		defer itClose(resp)
		if resp.StatusCode != http.StatusNotFound || itErrCode(t, resp) != "M1E-3004" {
			t.Fatalf("unknown channel: %d", resp.StatusCode)
		}
	})

	t.Run("ack_intake_and_coverage", func(t *testing.T) {
		ackHdr := map[string]string{
			"Content-Type":         "application/json",
			"X-Mark1-Edge-Version": "1.4.2",
		}
		ack := func(token string, seq int64, hash [32]byte, extra string) *http.Response {
			body := fmt.Sprintf(`{"channel":"stable","seq":%d,"bundle_hash":"%s","result":"applied"%s}`,
				seq, hex.EncodeToString(hash[:]), extra)
			return h.req(http.MethodPost, "/api/v1/policy/ack", token, strings.NewReader(body), ackHdr)
		}
		resp := ack(h.tokenA1, 2, second.BodySHA256, "")
		defer itClose(resp)
		if resp.StatusCode != http.StatusOK {
			code, msg := itErr(t, resp)
			t.Fatalf("ack: %d %s %s", resp.StatusCode, code, msg)
		}
		// The ledger stamped the identity from CLAIMS, not from the body: the
		// body carries neither, and the row still names the right device.
		var device uuid.UUID
		var edgeVersion string
		if err := h.admin.QueryRow(ctx,
			`SELECT device_id, edge_version FROM bundle_acks WHERE tenant_id = $1 AND seq = 2`,
			h.tenantAID).Scan(&device, &edgeVersion); err != nil {
			t.Fatal(err)
		}
		if device != h.deviceA1 || edgeVersion != "1.4.2" {
			t.Fatalf("ack row: device %s edge %q", device, edgeVersion)
		}

		// An ACK for a seq nobody published is the composite FK's job.
		bad := ack(h.tokenA2, 99, second.BodySHA256, "")
		defer itClose(bad)
		if bad.StatusCode != http.StatusBadRequest {
			t.Fatalf("ack for an unpublished seq: %d, want 400", bad.StatusCode)
		}

		// Coverage: 2 active devices for tenant A, 1 on head.
		cov, err := h.mod.store.AckCoverage(ctx, h.tenantA, "stable", nil)
		if err != nil {
			t.Fatal(err)
		}
		if cov.HeadSeq != 2 || cov.ActiveDevices != 2 || cov.OnHead != 1 {
			t.Fatalf("coverage %+v", cov)
		}
		if cov.HeadRatio() != 0.5 {
			t.Fatalf("head ratio %v", cov.HeadRatio())
		}
		// 05 §4.3(a): a rejection cannot be erased by a later 'applied' from
		// the same device on the same seq -- ON CONFLICT DO NOTHING, and the
		// canary keeps seeing the rejection.
		rej := h.req(http.MethodPost, "/api/v1/policy/ack", h.tokenA2, strings.NewReader(
			fmt.Sprintf(`{"channel":"stable","seq":2,"bundle_hash":"%s","result":"rejected","reject_code":"M1E-3005"}`,
				hex.EncodeToString(second.BodySHA256[:]))), ackHdr)
		defer itClose(rej)
		if rej.StatusCode != http.StatusOK {
			t.Fatalf("rejected ack: %d", rej.StatusCode)
		}
		retract := ack(h.tokenA2, 2, second.BodySHA256, "")
		defer itClose(retract)
		if retract.StatusCode != http.StatusOK {
			t.Fatalf("retracting ack: %d", retract.StatusCode)
		}
		var result, code string
		if err := h.admin.QueryRow(ctx,
			`SELECT result, reject_code FROM bundle_acks WHERE device_id = $1 AND seq = 2`,
			h.deviceA2).Scan(&result, &code); err != nil {
			t.Fatal(err)
		}
		if result != "rejected" || code != "M1E-3005" {
			t.Fatalf("a device erased its own rejection: %q %q", result, code)
		}
		cov, err = h.mod.store.AckCoverage(ctx, h.tenantA, "stable", nil)
		if err != nil {
			t.Fatal(err)
		}
		if cov.Rejected != 1 || cov.CommandString != 1 {
			t.Fatalf("coverage after rejection: %+v", cov)
		}
		if d, why := Decide(cov, RolloutState{CohortPercent: 5, SoakElapsed: 2 * time.Hour}); d != DecisionHalt {
			t.Fatalf("an M1E-3005 ACK did not halt the rollout: %s (%s)", d, why)
		}
	})

	t.Run("sse_hint_reaches_a_live_stream", func(t *testing.T) {
		// Push is an optimisation over the poll, but a push path that silently
		// never delivers looks exactly like a quiet fleet.
		streamCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		req, err := http.NewRequestWithContext(streamCtx, http.MethodGet,
			h.api.URL+"/api/v1/policy/stream?channel=stable", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+h.tokenA1)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer itClose(resp)
		if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "text/event-stream" {
			t.Fatalf("stream: %d %q", resp.StatusCode, resp.Header.Get("Content-Type"))
		}
		// Headers are written AFTER subscribe(), so the subscription is live.
		third, err := h.mod.Publish(ctx, h.tenantA, h.draft("stable"))
		if err != nil {
			t.Fatal(err)
		}
		lines := make(chan string, 8)
		go func() {
			sc := bufio.NewScanner(resp.Body)
			for sc.Scan() {
				select {
				case lines <- sc.Text():
				case <-streamCtx.Done():
					return
				}
			}
		}()
		deadline := time.After(10 * time.Second)
		var sawEvent bool
		for {
			select {
			case l := <-lines:
				if l == "event: bundle" {
					sawEvent = true
					continue
				}
				if sawEvent && strings.HasPrefix(l, "data: ") {
					want := fmt.Sprintf(`{"seq":%d,"etag":%s}`, third.Seq, third.ETag)
					if l[len("data: "):] != want {
						t.Fatalf("hint payload %q, want %q", l[len("data: "):], want)
					}
					return
				}
			case <-deadline:
				t.Fatal("no bundle hint arrived on a live stream within 10s")
			}
		}
	})

	// -----------------------------------------------------------------------
	// The database is the enforcer, not this package.
	// -----------------------------------------------------------------------

	t.Run("database_refuses_seq_reuse_and_mutation", func(t *testing.T) {
		// Every statement below runs as the TABLE OWNER on the admin
		// connection. A rule that only binds the application role is a rule an
		// incident-response session walks straight through.
		var body []byte
		var hash, prev []byte
		if err := h.admin.QueryRow(ctx, `
			SELECT body_cbor, body_sha256, prev_hash FROM policy_bundles
			 WHERE tenant_id = $1 AND channel = 'stable' AND seq = 2`, h.tenantAID).
			Scan(&body, &hash, &prev); err != nil {
			t.Fatal(err)
		}
		insert := func(seq int64, prevHash []byte) error {
			_, err := h.admin.Exec(ctx, `
				INSERT INTO policy_bundles
				  (tenant_id, channel, seq, body_cbor, body_sha256, prev_hash, max_age,
				   signatures, signing_key_id, tlog_index, tlog_proof, receipt_id)
				SELECT $1, 'stable', $2, body_cbor, sha256($3::bytea), $4, max_age,
				       signatures, signing_key_id, tlog_index, tlog_proof, receipt_id
				  FROM policy_bundles WHERE tenant_id = $1 AND channel = 'stable' AND seq = 2`,
				h.tenantAID, seq, []byte(fmt.Sprintf("forgery-%d", seq)), prevHash)
			return err
		}
		cases := []struct {
			name string
			run  func() error
			want string
		}{
			{"reuse an already-published seq", func() error { return insert(2, prev) },
				"regressions and gaps are unrepresentable"},
			{"rewind to an earlier seq", func() error { return insert(1, nil) },
				"regressions and gaps are unrepresentable"},
			{"skip ahead, leaving a gap", func() error { return insert(9, hash) },
				"regressions and gaps are unrepresentable"},
			{"chain to the wrong parent", func() error {
				headSeq := h.headSeq("stable")
				return insert(headSeq+1, make([]byte, 32))
			}, "does not chain to head"},
			{"mutate a published body", func() error {
				_, err := h.admin.Exec(ctx,
					`UPDATE policy_bundles SET body_cbor = $1 WHERE tenant_id = $2 AND seq = 2`,
					append(body, 0x00), h.tenantAID)
				return err
			}, "append-only"},
			{"delete a published bundle", func() error {
				_, err := h.admin.Exec(ctx, `DELETE FROM policy_bundles WHERE tenant_id = $1 AND seq = 2`, h.tenantAID)
				return err
			}, "append-only"},
			{"truncate the catalog", func() error {
				_, err := h.admin.Exec(ctx, `TRUNCATE policy_bundles CASCADE`)
				return err
			}, "append-only"},
			{"rewrite a log leaf", func() error {
				_, err := h.admin.Exec(ctx,
					`UPDATE tlog_leaves SET leaf_hash = sha256('x') WHERE tenant_id = $1 AND leaf_index = 0`, h.tenantAID)
				return err
			}, "append-only"},
			{"delete a log leaf", func() error {
				_, err := h.admin.Exec(ctx, `DELETE FROM tlog_leaves WHERE tenant_id = $1`, h.tenantAID)
				return err
			}, "append-only"},
			{"truncate the log", func() error {
				_, err := h.admin.Exec(ctx, `TRUNCATE tlog_leaves CASCADE`)
				return err
			}, "append-only"},
			{"leave a gap in the log", func() error {
				_, err := h.admin.Exec(ctx,
					`INSERT INTO tlog_leaves (tenant_id, leaf_index, kind, leaf_hash)
					 VALUES ($1, 99, 'policy_bundle', sha256('gap'))`, h.tenantAID)
				return err
			}, "gaps and rewrites are unrepresentable"},
			{"reuse a log leaf index", func() error {
				_, err := h.admin.Exec(ctx,
					`INSERT INTO tlog_leaves (tenant_id, leaf_index, kind, leaf_hash)
					 VALUES ($1, 0, 'policy_bundle', sha256('reuse'))`, h.tenantAID)
				return err
			}, "gaps and rewrites are unrepresentable"},
			{"rewrite a signed head", func() error {
				_, err := h.admin.Exec(ctx,
					`UPDATE tlog_signed_heads SET root_hash = sha256('y') WHERE tenant_id = $1`, h.tenantAID)
				return err
			}, "append-only"},
		}
		headBefore := h.headSeq("stable")
		bundlesBefore, leavesBefore := h.adminCount("policy_bundles"), h.adminCount("tlog_leaves")
		ran := 0
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				err := tc.run()
				if err == nil {
					t.Fatalf("the database ACCEPTED it -- %s is not enforced in the schema", tc.name)
				}
				if !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("refused for the wrong reason: %v (want %q)", err, tc.want)
				}
				ran++
			})
		}
		// Tripwire: a table that stopped iterating would report success having
		// proven nothing at all.
		if ran != len(cases) || ran < 10 {
			t.Fatalf("ran %d of %d refusal cases", ran, len(cases))
		}
		if h.headSeq("stable") != headBefore {
			t.Fatal("a refused publication still moved the channel head")
		}
		if h.adminCount("policy_bundles") != bundlesBefore || h.adminCount("tlog_leaves") != leavesBefore {
			t.Fatal("a refused write still changed the row counts")
		}
	})

	t.Run("app_role_cannot_mutate_at_all", func(t *testing.T) {
		// The other half of the same rule: the runtime role holds no UPDATE and
		// no DELETE, so the trigger is a second line, never the only one.
		for _, stmt := range []string{
			`UPDATE policy_bundles SET seq = seq + 100`,
			`DELETE FROM policy_bundles`,
			`DELETE FROM bundle_acks`,
			`UPDATE tlog_leaves SET leaf_hash = sha256('z')`,
			`DELETE FROM tlog_signed_heads`,
		} {
			err := h.db.WithTenant(ctx, h.tenantA, func(tx pgx.Tx) error {
				_, e := tx.Exec(ctx, stmt)
				return e
			})
			if err == nil {
				t.Fatalf("controld_app executed %q", stmt)
			}
			if !strings.Contains(err.Error(), "permission denied") {
				t.Fatalf("%q failed for the wrong reason: %v", stmt, err)
			}
		}
	})

	// -----------------------------------------------------------------------
	// RLS. The negative direction is the only one that proves anything.
	// -----------------------------------------------------------------------

	t.Run("rls_denies_the_wrong_tenant", func(t *testing.T) {
		tables := []string{
			"policy_bundles", "bundle_channel_heads", "bundle_acks",
			"tlog_heads", "tlog_leaves", "tlog_signed_heads", "m1_receipts",
		}
		for _, table := range tables {
			t.Run(table, func(t *testing.T) {
				// The authority holds rows: the zero below is RLS, not an
				// empty table. Without this line the whole test is vacuous.
				if n := h.adminCount(table); n == 0 {
					t.Fatalf("%s is empty, so a zero-row read proves nothing", table)
				}
				var n int64
				if err := h.db.WithTenant(ctx, h.tenantB, func(tx pgx.Tx) error {
					return tx.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&n)
				}); err != nil {
					t.Fatal(err)
				}
				if n != 0 {
					t.Fatalf("tenant B read %d rows of tenant A's %s", n, table)
				}
				// And tenant A does see its own -- an RLS policy that denies
				// everybody is a broken service, not a secure one.
				var mine int64
				if err := h.db.WithTenant(ctx, h.tenantA, func(tx pgx.Tx) error {
					return tx.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&mine)
				}); err != nil {
					t.Fatal(err)
				}
				if mine == 0 {
					t.Fatalf("tenant A cannot see its own %s", table)
				}
			})
		}
		// A NULL/unset GUC must match NOTHING. This is the exact shape of the
		// 61-inert-table incident: FORCE RLS present, policy present, and a
		// connection that saw everything anyway.
		var leaked int64
		if err := h.db.WithTenant(ctx, h.tenantB, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', '', true)`); err != nil {
				return err
			}
			return tx.QueryRow(ctx, `SELECT count(*) FROM policy_bundles`).Scan(&leaked)
		}); err != nil {
			t.Fatal(err)
		}
		if leaked != 0 {
			t.Fatalf("an empty app.tenant_id read %d bundles", leaked)
		}
		// The connecting role must not be able to opt out of any of it.
		var bypass bool
		if err := h.db.WithTenant(ctx, h.tenantA, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx,
				`SELECT rolbypassrls OR rolsuper FROM pg_roles WHERE rolname = current_user`).Scan(&bypass)
		}); err != nil {
			t.Fatal(err)
		}
		if bypass {
			t.Fatal("the runtime role inherits BYPASSRLS; every policy above is decorative")
		}
	})

	t.Run("cross_tenant_reads_and_acks_over_http", func(t *testing.T) {
		// Tenant B holds a genuine, unexpired, correctly signed device token
		// and asks for the channel tenant A publishes on.
		resp := h.req(http.MethodGet, "/api/v1/policy/bundle?channel=stable", h.tokenB, nil, nil)
		defer itClose(resp)
		if resp.StatusCode != http.StatusNotFound || itErrCode(t, resp) != "M1E-3004" {
			t.Fatalf("cross-tenant bundle read: %d", resp.StatusCode)
		}
		// And cannot ACK into A's ledger, even naming a real (channel, seq).
		ackResp := h.req(http.MethodPost, "/api/v1/policy/ack", h.tokenB, strings.NewReader(
			fmt.Sprintf(`{"channel":"stable","seq":2,"bundle_hash":"%s","result":"applied"}`,
				hex.EncodeToString(second.BodySHA256[:]))),
			map[string]string{"Content-Type": "application/json", "X-Mark1-Edge-Version": "1.4.2"})
		defer itClose(ackResp)
		if ackResp.StatusCode != http.StatusBadRequest {
			t.Fatalf("cross-tenant ack: %d, want 400", ackResp.StatusCode)
		}
		var n int64
		if err := h.admin.QueryRow(ctx,
			`SELECT count(*) FROM bundle_acks WHERE tenant_id = $1`, h.tenantBID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatalf("tenant B wrote %d ACK rows", n)
		}
	})

	// -----------------------------------------------------------------------
	// The publish-side gate: a bad bundle never gets a seq.
	// -----------------------------------------------------------------------

	t.Run("command_string_never_reserves_a_seq", func(t *testing.T) {
		headBefore := h.headSeq("stable")
		bundlesBefore := h.adminCount("policy_bundles")
		leavesBefore := h.adminCount("tlog_leaves")
		receiptsBefore := h.adminCount("m1_receipts")

		s := validSections()
		// 07's rule (1): every tstr in a bundle is a constrained identifier. A
		// shell string in an agent id is the exact thing the edge decoder
		// rejects with M1E-3005, so it must die here first.
		s.AgentMaps.Agents[0].AgentID = "claudecode; rm -rf /"
		_, err := h.mod.Publish(ctx, h.tenantA, Draft{
			Channel: "stable", MaxAge: 15 * time.Minute, SectionsCBOR: mustEncode(t, s),
		})
		if err == nil {
			t.Fatal("a bundle carrying a command string was published")
		}
		var rej *RejectError
		if !errors.As(err, &rej) || rej.Code != "M1E-3005" {
			t.Fatalf("want M1E-3005, got %v", err)
		}
		if h.headSeq("stable") != headBefore {
			t.Fatal("the refused bundle burned a sequence number")
		}
		if h.adminCount("policy_bundles") != bundlesBefore {
			t.Fatal("the refused bundle reached the catalog")
		}
		if h.adminCount("tlog_leaves") != leavesBefore {
			t.Fatal("the refused bundle reached the transparency log")
		}
		if h.adminCount("m1_receipts") != receiptsBefore {
			t.Fatal("the refused bundle was receipted")
		}
		// The channel still works afterwards: the refusal left no half-state.
		p, err := h.mod.Publish(ctx, h.tenantA, h.draft("stable"))
		if err != nil {
			t.Fatalf("publish after a refusal: %v", err)
		}
		if p.Seq != headBefore+1 {
			t.Fatalf("next publication took seq %d, want %d", p.Seq, headBefore+1)
		}
	})

	t.Run("rollback_is_a_forward_publication", func(t *testing.T) {
		// The product's central claim, exercised: to undo a bundle you publish
		// the old content again at a HIGHER seq. There is no unpublish verb,
		// and the edge's anti-rollback check is never fought.
		before := h.headSeq("stable")
		restored, err := h.mod.Publish(ctx, h.tenantA, h.draft("stable"))
		if err != nil {
			t.Fatal(err)
		}
		if restored.Seq <= before {
			t.Fatalf("a rollback moved the seq backwards: %d -> %d", before, restored.Seq)
		}
		served, err := h.mod.store.Latest(ctx, h.tenantA, "stable")
		if err != nil {
			t.Fatal(err)
		}
		if served.Seq != restored.Seq {
			t.Fatalf("the head serves seq %d, not the newest %d", served.Seq, restored.Seq)
		}
	})

	t.Run("drain_ends_streams_with_a_ping", func(t *testing.T) {
		streamCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		req, err := http.NewRequestWithContext(streamCtx, http.MethodGet,
			h.api.URL+"/api/v1/policy/stream?channel=stable", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+h.tokenA2)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer itClose(resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("stream: %d", resp.StatusCode)
		}
		h.mod.Drain()
		sc := bufio.NewScanner(resp.Body)
		var got []string
		for sc.Scan() {
			got = append(got, sc.Text())
		}
		// 05 §1.5: a final ping, then the stream ends. EOF without the ping
		// would be indistinguishable from a network fault.
		if len(got) == 0 || got[0] != "event: ping" {
			t.Fatalf("drain did not close the stream with a ping: %v", got)
		}
	})
}
