// Tests drive the full 08 §3.1 device-code flow against an httptest stub
// speaking exactly the documented shapes — controld's enroll module is
// doc-only today, so the stub IS the executable contract.
package enroll

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Omium-ai/omium-mark1/go/mark1/internal/cli"
)

// testTenant is a fixed UUID string: controld's handleStart uuid.Parses the
// tenant field, so the stub (the executable contract) holds the CLI to a value
// the real server would accept.
const testTenant = "0191c2f3-7a10-7cc3-b1aa-3f60be1a9e01"

func testEnv(t *testing.T, server string) (*cli.Env, *bytes.Buffer) {
	t.Helper()
	out := &bytes.Buffer{}
	return &cli.Env{
		StateDir: t.TempDir(), Server: server, JSON: true,
		Stdout: out, Stderr: os.Stderr, Version: "test",
	}, out
}

// enrollStub serves §3.1: /start hands out the device code (interval 0 keeps
// tests fast), /poll answers pending `pendings` times then active.
func enrollStub(t *testing.T, pendings int) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	polls := &atomic.Int32{}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/enroll/device/start", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("start body: %v", err)
		}
		for _, field := range []string{"client", "client_version", "device_pubkey", "platform", "hostname_hash", "tenant"} {
			if body[field] == "" || body[field] == nil {
				t.Errorf("start body missing %s", field)
			}
		}
		// Mirror controld's handleStart admission exactly (handlers.go:64,
		// codec.go parseHostnameHash): the stub failing here is the
		// client/server contract break the two halves' separate suites missed.
		if tenant, _ := body["tenant"].(string); tenant != testTenant {
			t.Errorf("start tenant = %v, want the --tenant value %s verbatim", body["tenant"], testTenant)
		}
		hh, _ := body["hostname_hash"].(string)
		trimmed, ok := strings.CutPrefix(hh, "hmac-sha256:")
		if !ok {
			t.Errorf("hostname_hash %q lacks the hmac-sha256: prefix controld strips", hh)
		}
		if raw, err := hex.DecodeString(trimmed); err != nil || len(raw) != 32 {
			t.Errorf("hostname_hash %q does not decode to 32 bytes after the prefix", hh)
		}
		// Exact re-derivation: the pseudonym must be HMAC-SHA256 keyed by the
		// TENANT UUID string (m1_001's per-tenant property) — keying it by
		// anything travelling in this same request (the old device-pubkey bug)
		// would let any row-holder invert it by brute-forcing hostnames.
		host, _ := os.Hostname()
		m := hmac.New(sha256.New, []byte(testTenant))
		m.Write([]byte(host))
		if want := hex.EncodeToString(m.Sum(nil)); trimmed != want {
			t.Errorf("hostname_hash = %q, want HMAC-SHA256(tenant-uuid, hostname) = %q", trimmed, want)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code": "dc-1", "user_code": "WDJB-MJHT",
			"verification_uri": "https://idp.example/activate",
			"expires_in":       900, "interval": 0,
		})
	})
	mux.HandleFunc("POST /api/v1/enroll/device/poll", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			DeviceCode string `json:"device_code"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("poll body: %v", err)
			return
		}
		if body.DeviceCode != "dc-1" {
			t.Errorf("poll device_code %q", body.DeviceCode)
		}
		if int(polls.Add(1)) <= pendings {
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "pending"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "active", "device_id": "dev-1", "tenant_id": "ten-1",
			"device_token": "tok-1", "expires_in": 86400,
			"tenant_root_hex": stubTenantRoot,
			"server_min_edge": "1.0.0",
			"endpoints":       map[string]string{"ingest": "https://ingest.example"},
			"bundle_section_keys": []map[string]string{
				{"section": "verify", "key_id": "ed25519:stub", "pubkey_hex": stubTenantRoot},
			},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, polls
}

// stubTenantRoot is the 04 §2.9 root the stub server delivers (32 bytes hex).
const stubTenantRoot = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

// TestEnrollPersistsTenantRoot: the root rides the ACTIVE poll body as
// tenant_root_hex and lands in enrollment.json beside the token — the 0600
// file mark1d reads its identity from, so the daemon never needs --tenant-salt.
func TestEnrollPersistsTenantRoot(t *testing.T) {
	srv, _ := enrollStub(t, 0)
	env, _ := testEnv(t, srv.URL)
	if err := Run(context.Background(), env, Options{Tenant: testTenant}); err != nil {
		t.Fatal(err)
	}
	doc, err := env.LoadEnrollment()
	if err != nil || doc.TenantRootHex != stubTenantRoot {
		t.Fatalf("persisted tenant_root_hex %q, want %q (%v)", doc.TenantRootHex, stubTenantRoot, err)
	}
	raw, err := os.ReadFile(env.EnrollmentPath())
	if err != nil || !bytes.Contains(raw, []byte(`"tenant_root_hex": "`+stubTenantRoot+`"`)) {
		t.Fatalf("enrollment.json lacks the wire key tenant_root_hex:\n%s", raw)
	}
}

// TestEnrollPinsBundleKeys: the ACTIVE body's bundle_section_keys land in <state>/policy/keys.json, the 0600 trust file mark1d's bundle client verifies every bundle against (04 §2.6) — pinned at enrollment, never fetched from the server it checks.
func TestEnrollPinsBundleKeys(t *testing.T) {
	srv, _ := enrollStub(t, 0)
	env, _ := testEnv(t, srv.URL)
	if err := Run(context.Background(), env, Options{Tenant: testTenant}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(env.PinnedKeysPath())
	if err != nil {
		t.Fatalf("policy/keys.json not written: %v", err)
	}
	if fi, _ := os.Stat(env.PinnedKeysPath()); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("keys.json mode %o", fi.Mode().Perm())
	}
	var tf struct {
		BundleSectionKeys []struct {
			Section   string `json:"section"`
			PubkeyHex string `json:"pubkey_hex"`
		} `json:"bundle_section_keys"`
	}
	if err := json.Unmarshal(raw, &tf); err != nil || len(tf.BundleSectionKeys) != 1 || tf.BundleSectionKeys[0].Section != "verify" || tf.BundleSectionKeys[0].PubkeyHex != stubTenantRoot {
		t.Fatalf("keys.json %s (%v)", raw, err)
	}
	if err := pinBundleKeys(env, nil); err != nil {
		t.Fatal(err)
	}
	if err := pinBundleKeys(env, json.RawMessage(`[]`)); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.ReadFile(env.PinnedKeysPath()); !bytes.Equal(again, raw) {
		t.Fatal("an absent or empty list must leave the existing pin alone")
	}
}

func TestEnrollHappyPath(t *testing.T) {
	srv, polls := enrollStub(t, 2)
	env, out := testEnv(t, srv.URL)
	if err := Run(context.Background(), env, Options{Tenant: testTenant}); err != nil {
		t.Fatal(err)
	}
	if polls.Load() != 3 {
		t.Fatalf("polled %d times, want 3 (2 pending + 1 active)", polls.Load())
	}
	var res Result
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatalf("stdout not one JSON object: %v (%q)", err, out.String())
	}
	if !res.OK || res.DeviceID != "dev-1" || res.State != "active" {
		t.Fatalf("result %+v", res)
	}
	// The enrollment doc and device key land 0600 under the state dir (§7.1).
	for _, path := range []string{env.EnrollmentPath(), env.DeviceKeyPath()} {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %o, want 0600", path, fi.Mode().Perm())
		}
	}
	doc, err := env.LoadEnrollment()
	if err != nil || doc.DeviceToken != "tok-1" || doc.TenantID != "ten-1" {
		t.Fatalf("persisted doc %+v %v", doc, err)
	}
}

func TestEnrollIdempotentWhenActive(t *testing.T) {
	srv, polls := enrollStub(t, 0)
	env, out := testEnv(t, srv.URL)
	if err := Run(context.Background(), env, Options{Tenant: testTenant}); err != nil {
		t.Fatal(err)
	}
	before := polls.Load()
	out.Reset()
	// §7.1: an already-ACTIVE device re-prints its identity and exits 0 —
	// and never re-runs the flow (a new key would orphan the receipt chain).
	if err := Run(context.Background(), env, Options{Tenant: testTenant}); err != nil {
		t.Fatal(err)
	}
	if polls.Load() != before {
		t.Fatal("re-enroll hit the server; must be local-only")
	}
	var res Result
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatalf("idempotent stdout %q: %v", out.String(), err)
	}
	if !res.OK || res.DeviceID != "dev-1" {
		t.Fatalf("idempotent result %+v", res)
	}
}

// deadDocReEnroll drives one item-1 recovery path: a stored enrollment in a
// dead state (revoked, or active-but-token-expired) must fall through to a
// FRESH enrollment that mints a NEW device key — the old identity's receipts
// stay attributable server-side because revocation is columns, not deletion
// (m1_001 m1_devices), so rotating the local key orphans nothing.
func deadDocReEnroll(t *testing.T, dead cli.Enrollment) {
	t.Helper()
	srv, polls := enrollStub(t, 0)
	env, out := testEnv(t, srv.URL)

	// First enrollment establishes the original key.
	if err := Run(context.Background(), env, Options{Tenant: testTenant}); err != nil {
		t.Fatal(err)
	}
	oldSeed, err := os.ReadFile(env.DeviceKeyPath())
	if err != nil {
		t.Fatal(err)
	}
	dead.Version = 1
	if err := env.SaveEnrollment(&dead); err != nil {
		t.Fatal(err)
	}

	// A fresh enroll without --tenant surfaces the dead state as usage
	// guidance (§7.1: fresh enrollments require the tenant UUID).
	before := polls.Load()
	err = Run(context.Background(), env, Options{})
	var ee *cli.ExitError
	if !errors.As(err, &ee) || ee.Code != cli.ExitUsage {
		t.Fatalf("tenantless re-enroll over dead doc: got %v, want exit 2", err)
	}
	if polls.Load() != before {
		t.Fatal("tenantless refusal must be local-only")
	}

	// With --tenant: full flow re-runs under a freshly minted key.
	out.Reset()
	if err := Run(context.Background(), env, Options{Tenant: testTenant}); err != nil {
		t.Fatal(err)
	}
	if polls.Load() == before {
		t.Fatal("re-enroll over a dead doc never hit the server")
	}
	newSeed, err := os.ReadFile(env.DeviceKeyPath())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(oldSeed, newSeed) {
		t.Fatal("device key not rotated: re-presenting the dead identity's key would re-earn the refusal")
	}
	fi, err := os.Stat(env.DeviceKeyPath())
	if err != nil {
		t.Fatalf("rotated key missing: %v", err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("rotated key mode %o (atomic swap must preserve 0600)", fi.Mode().Perm())
	}
	doc, err := env.LoadEnrollment()
	if err != nil || doc.State != cli.StateActive || doc.DeviceToken != "tok-1" {
		t.Fatalf("post-re-enroll doc %+v %v, want active with the fresh token", doc, err)
	}
	var res Result
	if err := json.Unmarshal(out.Bytes(), &res); err != nil || !res.OK || res.State != cli.StateActive {
		t.Fatalf("re-enroll result %+v (%v)", res, err)
	}
}

func TestReEnrollAfterRevocation(t *testing.T) {
	deadDocReEnroll(t, cli.Enrollment{
		State: cli.StateRevoked, DeviceID: "dev-old", TenantID: "ten-1",
		DeviceToken: "tok-old", TokenExpiresAt: time.Now().Add(time.Hour),
	})
}

func TestReEnrollAfterTokenExpiry(t *testing.T) {
	deadDocReEnroll(t, cli.Enrollment{
		State: cli.StateActive, DeviceID: "dev-old", TenantID: "ten-1",
		DeviceToken: "tok-old", TokenExpiresAt: time.Now().Add(-time.Minute),
	})
}

// TestEnrollSurfacesExpiredNotActive pins the status half of item 1: a doc
// past token_expires_at must never re-print as ACTIVE (the old bug treated
// any doc on disk as live).
func TestEnrollSurfacesExpiredNotActive(t *testing.T) {
	srv, _ := enrollStub(t, 0)
	env, _ := testEnv(t, srv.URL)
	if err := env.SaveEnrollment(&cli.Enrollment{
		Version: 1, State: cli.StateActive, DeviceID: "dev-old",
		DeviceToken: "tok-old", TokenExpiresAt: time.Now().Add(-time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	if got := mustLoad(t, env).LiveState(time.Now()); got != cli.StateExpired {
		t.Fatalf("LiveState = %q, want expired", got)
	}
}

func mustLoad(t *testing.T, env *cli.Env) *cli.Enrollment {
	t.Helper()
	doc, err := env.LoadEnrollment()
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestEnrollDeniedAtIdP(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/enroll/device/start", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"device_code": "dc", "user_code": "U", "verification_uri": "u", "expires_in": 900, "interval": 0})
	})
	mux.HandleFunc("POST /api/v1/enroll/device/poll", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, `{"error":{"code":"M1E-1005","message":"denied"}}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	env, _ := testEnv(t, srv.URL)
	err := Run(context.Background(), env, Options{Tenant: testTenant})
	var ee *cli.ExitError
	if !errors.As(err, &ee) || ee.Code != cli.ExitNotEnrolled || ee.M1E != "M1E-1005" {
		t.Fatalf("got %v, want exit 3 M1E-1005", err)
	}
}

func TestEnrollExpiredCode(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/enroll/device/start", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"device_code": "dc", "user_code": "U", "verification_uri": "u", "expires_in": 900, "interval": 0})
	})
	mux.HandleFunc("POST /api/v1/enroll/device/poll", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprint(w, `{"error":{"code":"M1E-1004","message":"expired"}}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	env, _ := testEnv(t, srv.URL)
	err := Run(context.Background(), env, Options{Tenant: testTenant})
	var ee *cli.ExitError
	if !errors.As(err, &ee) || ee.Code != cli.ExitRefused || ee.M1E != "M1E-1004" {
		t.Fatalf("got %v, want exit 4 M1E-1004", err)
	}
}

func TestEnrollRefusesLooseDeviceKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits do not exist here; owner-only on Windows is an ACL, which nothing in the daemon sets yet — NFR-SECURITY-007 residual")
	}
	srv, _ := enrollStub(t, 0)
	env, _ := testEnv(t, srv.URL)
	if err := os.MkdirAll(env.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(env.DeviceKeyPath(), make([]byte, 32), 0o644); err != nil {
		t.Fatal(err)
	}
	err := Run(context.Background(), env, Options{Tenant: testTenant})
	var ee *cli.ExitError
	if !errors.As(err, &ee) || ee.Code != cli.ExitRuntime {
		t.Fatalf("got %v; a 0644 device key must refuse", err)
	}
}

func TestEnrollMissingTenantIsUsage(t *testing.T) {
	// No --tenant ⇒ the server would answer 400 M1E-2001 unconditionally
	// (handleStart's routing key); the CLI refuses locally with exit 2 instead
	// of a doomed round-trip. Server URL is unreachable on purpose: reaching
	// the network here would BE the failure.
	env, _ := testEnv(t, "http://unreachable.invalid")
	err := Run(context.Background(), env, Options{})
	var ee *cli.ExitError
	if !errors.As(err, &ee) || ee.Code != cli.ExitUsage {
		t.Fatalf("got %v, want exit 2 (usage)", err)
	}
}

func TestEnrollBadChannelIsUsage(t *testing.T) {
	env, _ := testEnv(t, "http://unreachable.invalid")
	err := Run(context.Background(), env, Options{Channel: "nightly"})
	var ee *cli.ExitError
	if !errors.As(err, &ee) || ee.Code != cli.ExitUsage {
		t.Fatalf("got %v, want exit 2", err)
	}
}
