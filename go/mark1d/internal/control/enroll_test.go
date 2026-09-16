package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/coverage"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/identity"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/receipt"
)

const (
	tenantA = "0191a000-0000-7000-8000-000000000001"
	tenantB = "0191a000-0000-7000-8000-000000000002"
	deviceA = "0191b000-0000-7000-8000-000000000001"
)

// mintToken is controld auth.Signer.Mint's shape (m1tok.v1.<claims>.<sig>); the signature is junk because the daemon holds no server key to check it.
func mintToken(tenant, device, keyID string) string {
	claims, _ := json.Marshal(map[string]any{"tenant_id": tenant, "device_id": device, "key_id": keyID, "iat": 1, "exp": 2})
	return "m1tok.v1." + base64.RawURLEncoding.EncodeToString(claims) + "." + base64.RawURLEncoding.EncodeToString([]byte("sig"))
}

func activeFor(tenant, device, keyID string) map[string]any {
	return map[string]any{
		"status": "active", "device_id": device, "tenant_id": tenant, "device_token": mintToken(tenant, device, keyID),
		"expires_in": 86400, "server_min_edge": "1.2.0", "key_manifest_uri": "/.well-known/mark1-keys", "tenant_root_hex": "0a0b",
		"endpoints": map[string]string{"ingest": "https://api.example/m1p/v1/ingest", "attach": "https://api.example/api/v1/attach", "policy_stream": "https://api.example/api/v1/policy/stream"},
	}
}

// cliEnrollment mirrors go/mark1/internal/cli.Enrollment and cmd/main.go's reader field for field.
type cliEnrollment struct {
	Version        int       `json:"version"`
	State          string    `json:"state"`
	DeviceID       string    `json:"device_id"`
	TenantID       string    `json:"tenant_id"`
	DeviceToken    string    `json:"device_token"`
	TokenExpiresAt time.Time `json:"token_expires_at"`
	TenantRootHex  string    `json:"tenant_root_hex"`
	Server         string    `json:"server"`
	Channel        string    `json:"channel"`
	ServerMinEdge  string    `json:"server_min_edge"`
	KeyManifestURI string    `json:"key_manifest_uri"`
	Endpoints      struct {
		Ingest       string `json:"ingest"`
		Attach       string `json:"attach"`
		PolicyStream string `json:"policy_stream"`
	} `json:"endpoints"`
	EnrolledAt time.Time `json:"enrolled_at"`
}

func TestEnrollHandoffPersistsTheCLIsDocument(t *testing.T) {
	s, dir := newServer(t)
	hooks := 0
	s.SetEnrolled(func() { hooks++ })
	var responses [][]byte
	do := func(method, path string, body any) (*http.Response, []byte) {
		resp, b := call(t, s, method, path, body)
		responses = append(responses, b)
		return resp, b
	}

	resp, body := do(http.MethodGet, "/v1/enroll", nil)
	want(t, resp, body, http.StatusOK, "")
	if strings.TrimSpace(string(body)) != `{"enrolled":false}` {
		t.Fatalf("fresh state %s", body)
	}
	resp, body = do(http.MethodPost, "/v1/enroll", activeFor(tenantA, deviceA, "ed25519:0000000000000000"))
	want(t, resp, body, http.StatusConflict, "M1E-2001")

	resp, body = do(http.MethodPost, "/v1/enroll/keygen", nil)
	want(t, resp, body, http.StatusOK, "")
	var kg struct {
		DevicePubkey string `json:"device_pubkey"`
		KeyID        string `json:"key_id"`
	}
	decodeTo(t, body, &kg)
	seed, err := os.ReadFile(filepath.Join(dir, "device.key"))
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("device.key %d bytes, %v", len(seed), err)
	}
	if fi, _ := os.Stat(filepath.Join(dir, "device.key")); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("device.key mode %o", fi.Mode().Perm())
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if kg.DevicePubkey != "ed25519:"+base64.StdEncoding.EncodeToString(pub) || kg.KeyID != identity.DeriveKeyID(pub) {
		t.Fatalf("keygen %s does not name the seed on disk", body)
	}
	resp, body = do(http.MethodPost, "/v1/enroll/keygen", map[string]string{"tenant_id": tenantA})
	want(t, resp, body, http.StatusOK, "")
	var again struct {
		DevicePubkey string `json:"device_pubkey"`
		KeyID        string `json:"key_id"`
	}
	decodeTo(t, body, &again)
	if seed2, _ := os.ReadFile(filepath.Join(dir, "device.key")); again != kg || !bytes.Equal(seed, seed2) {
		t.Fatalf("keygen must be idempotent: %+v vs %+v", again, kg)
	}
	resp, body = do(http.MethodPost, "/v1/enroll/keygen", map[string]string{"nope": "x"})
	want(t, resp, body, http.StatusBadRequest, "M1E-2001")

	active := activeFor(tenantA, deviceA, kg.KeyID)
	active["future_field"] = "additive server evolution is not a refusal"
	before := time.Now()
	resp, body = do(http.MethodPost, "/v1/enroll", active)
	want(t, resp, body, http.StatusOK, "")
	var out struct {
		TenantID   string `json:"tenant_id"`
		DeviceID   string `json:"device_id"`
		EnrolledAt string `json:"enrolled_at"`
	}
	decodeTo(t, body, &out)
	if out.TenantID != tenantA || out.DeviceID != deviceA {
		t.Fatalf("enroll %s", body)
	}
	if _, err := time.Parse(time.RFC3339, out.EnrolledAt); err != nil {
		t.Fatal(err)
	}
	if hooks != 1 {
		t.Fatalf("enrolled hook ran %d times, want 1", hooks)
	}

	fi, err := os.Stat(filepath.Join(dir, "enrollment.json"))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("enrollment.json mode %o, want 0600", fi.Mode().Perm())
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "enrollment.json"))
	var doc cliEnrollment
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("document is not the CLI's shape: %v: %s", err, raw)
	}
	if doc.Version != 1 || doc.State != "active" || doc.DeviceID != deviceA || doc.TenantID != tenantA ||
		doc.DeviceToken != active["device_token"] || doc.TenantRootHex != "0a0b" || doc.Server != "https://api.example" ||
		doc.Channel != "stable" || doc.ServerMinEdge != "1.2.0" || doc.KeyManifestURI != "/.well-known/mark1-keys" ||
		doc.Endpoints.Ingest != "https://api.example/m1p/v1/ingest" || doc.Endpoints.Attach != "https://api.example/api/v1/attach" ||
		doc.Endpoints.PolicyStream != "https://api.example/api/v1/policy/stream" {
		t.Fatalf("document %s", raw)
	}
	if exp := doc.TokenExpiresAt.Sub(before); exp < 86400*time.Second-time.Minute || exp > 86400*time.Second+time.Minute {
		t.Fatalf("token_expires_at is %v from now, want expires_in", exp)
	}
	if doc.EnrolledAt.Before(before.Add(-time.Second)) || doc.EnrolledAt.After(time.Now()) {
		t.Fatalf("enrolled_at %v", doc.EnrolledAt)
	}
	if key, err := receipt.OpenKey(filepath.Join(dir, "device.key")); err != nil || key.KeyID() != kg.KeyID {
		t.Fatalf("the sealer's own reader: %v", err)
	}

	resp, body = do(http.MethodGet, "/v1/enroll", nil)
	want(t, resp, body, http.StatusOK, "")
	var st struct {
		Enrolled  bool   `json:"enrolled"`
		State     string `json:"state"`
		TenantID  string `json:"tenant_id"`
		DeviceID  string `json:"device_id"`
		ExpiresAt string `json:"expires_at"`
		KeyID     string `json:"key_id"`
	}
	decodeTo(t, body, &st)
	if !st.Enrolled || st.State != "active" || st.TenantID != tenantA || st.DeviceID != deviceA || st.KeyID != kg.KeyID {
		t.Fatalf("state %s", body)
	}
	if at, err := time.Parse(time.RFC3339, st.ExpiresAt); err != nil || !at.Equal(doc.TokenExpiresAt.Truncate(time.Second)) {
		t.Fatalf("expires_at %q vs %v (%v)", st.ExpiresAt, doc.TokenExpiresAt, err)
	}

	resp, body = do(http.MethodPost, "/v1/enroll/keygen", map[string]string{"tenant_id": tenantB})
	want(t, resp, body, http.StatusConflict, "M1E-2001")
	resp, body = do(http.MethodPost, "/v1/enroll", activeFor(tenantB, deviceA, kg.KeyID))
	want(t, resp, body, http.StatusConflict, "M1E-2001")
	if raw2, _ := os.ReadFile(filepath.Join(dir, "enrollment.json")); !bytes.Equal(raw, raw2) {
		t.Fatal("a refused tenant switch must not touch the document")
	}
	resp, body = do(http.MethodPost, "/v1/enroll", activeFor(tenantA, deviceA, kg.KeyID))
	want(t, resp, body, http.StatusOK, "")
	if hooks != 2 {
		t.Fatalf("re-enroll under the same tenant (token refresh) must run the hook: %d", hooks)
	}

	resp, body = do(http.MethodDelete, "/v1/enroll", nil)
	want(t, resp, body, http.StatusOK, "")
	if strings.TrimSpace(string(body)) != `{"enrolled":false,"key_id":"`+kg.KeyID+`"}` {
		t.Fatalf("sign-out %s", body)
	}
	if _, err := os.Stat(filepath.Join(dir, "enrollment.json")); !os.IsNotExist(err) {
		t.Fatal("sign-out must remove the document")
	}
	if seed3, _ := os.ReadFile(filepath.Join(dir, "device.key")); !bytes.Equal(seed, seed3) {
		t.Fatal("sign-out must keep the key")
	}
	if hooks != 3 {
		t.Fatalf("hook after sign-out: %d", hooks)
	}
	resp, body = do(http.MethodDelete, "/v1/enroll", nil)
	want(t, resp, body, http.StatusOK, "")
	if hooks != 3 {
		t.Fatal("a second sign-out has nothing to announce")
	}
	lines := readLines(t, coverage.JournalPath(dir))
	if len(lines) != 1 || !strings.Contains(lines[0], `"kind":"disable"`) || !strings.Contains(lines[0], `"reason":"mark1_off"`) || !strings.Contains(lines[0], `"scope":"all"`) {
		t.Fatalf("journal %v", lines)
	}
	rec := &recorder{}
	cov := coverage.New(rec.admit, []byte("k"))
	if n, err := cov.DrainJournal(context.Background(), dir); err != nil || n != 1 {
		t.Fatalf("drain %d %v", n, err)
	}
	ct := rec.events[0].GetCoverageTransition()
	if ct.GetKind() != m1pv1.CoverageKind_COVERAGE_KIND_DISABLE || ct.GetReasonCode() != coverage.ReasonMark1Off || !bytes.Equal(ct.GetWorkspaceId(), coverage.DeviceWide()) {
		t.Fatalf("receipted transition %v", ct)
	}

	priv := ed25519.NewKeyFromSeed(seed)
	for _, secret := range [][]byte{seed, priv, []byte(hex.EncodeToString(seed)), []byte(base64.StdEncoding.EncodeToString(seed)),
		[]byte(base64.RawStdEncoding.EncodeToString(seed)), []byte(base64.URLEncoding.EncodeToString(seed)), []byte(base64.RawURLEncoding.EncodeToString(seed))} {
		for _, b := range responses {
			if bytes.Contains(b, secret) {
				t.Fatalf("private key material in a response: %s", b)
			}
		}
	}
}

func TestEnrollRefusesABodyForAnotherDevice(t *testing.T) {
	s, dir := newServer(t)
	planted := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	if err := os.WriteFile(filepath.Join(dir, "device.key"), planted, 0o600); err != nil {
		t.Fatal(err)
	}
	_, body := call(t, s, http.MethodPost, "/v1/enroll/keygen", nil)
	var kg struct {
		DevicePubkey string `json:"device_pubkey"`
		KeyID        string `json:"key_id"`
	}
	decodeTo(t, body, &kg)
	pub := ed25519.NewKeyFromSeed(planted).Public().(ed25519.PublicKey)
	if kg.DevicePubkey != "ed25519:"+base64.StdEncoding.EncodeToString(pub) {
		t.Fatalf("keygen must adopt, never overwrite, a planted key: %s", body)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "device.key")); !bytes.Equal(b, planted) {
		t.Fatal("keygen overwrote device.key")
	}

	otherPub, _, _ := ed25519.GenerateKey(nil)
	bad := map[string]map[string]any{
		"another key":         activeFor(tenantA, deviceA, identity.DeriveKeyID(otherPub)),
		"device_id mismatch":  activeFor(tenantA, deviceA, kg.KeyID),
		"tenant_id mismatch":  activeFor(tenantA, deviceA, kg.KeyID),
		"malformed token":     activeFor(tenantA, deviceA, kg.KeyID),
		"opaque token":        activeFor(tenantA, deviceA, kg.KeyID),
		"claims not json":     activeFor(tenantA, deviceA, kg.KeyID),
		"two-part token":      activeFor(tenantA, deviceA, kg.KeyID),
		"status pending":      activeFor(tenantA, deviceA, kg.KeyID),
		"no token":            activeFor(tenantA, deviceA, kg.KeyID),
		"expires_in zero":     activeFor(tenantA, deviceA, kg.KeyID),
		"tenant not a uuid":   activeFor(tenantA, deviceA, kg.KeyID),
		"device not a uuid":   activeFor(tenantA, deviceA, kg.KeyID),
		"unknown field only":  {"extra": 1},
		"expires_in negative": activeFor(tenantA, deviceA, kg.KeyID),
	}
	bad["device_id mismatch"]["device_id"] = "0191b000-0000-7000-8000-0000000000ff"
	bad["tenant_id mismatch"]["tenant_id"] = tenantB
	bad["malformed token"]["device_token"] = "m1tok.v1.!!!.sig"
	bad["opaque token"]["device_token"] = "opaque"
	bad["claims not json"]["device_token"] = "m1tok.v1." + base64.RawURLEncoding.EncodeToString([]byte("nope")) + ".sig"
	bad["two-part token"]["device_token"] = strings.TrimPrefix(mintToken(tenantA, deviceA, kg.KeyID), "m1tok.v1.")
	bad["status pending"]["status"] = "pending"
	bad["no token"]["device_token"] = ""
	bad["expires_in zero"]["expires_in"] = 0
	bad["expires_in negative"]["expires_in"] = -1
	bad["tenant not a uuid"]["tenant_id"] = "tenant_1"
	bad["device not a uuid"]["device_id"] = "dev_1"
	status := map[string]int{"another key": 409, "device_id mismatch": 409, "tenant_id mismatch": 409, "malformed token": 409, "opaque token": 409, "claims not json": 409, "two-part token": 409}
	for name, b := range bad {
		resp, body := call(t, s, http.MethodPost, "/v1/enroll", b)
		wantStatus := status[name]
		if wantStatus == 0 {
			wantStatus = http.StatusBadRequest
		}
		if resp.StatusCode != wantStatus || !strings.Contains(string(body), `"code":"M1E-2001"`) {
			t.Fatalf("%s: %d %s, want %d", name, resp.StatusCode, body, wantStatus)
		}
		if _, err := os.Stat(filepath.Join(dir, "enrollment.json")); !os.IsNotExist(err) {
			t.Fatalf("%s: a refused body must not be persisted", name)
		}
	}
	resp, body := call(t, s, http.MethodPost, "/v1/enroll", []int{1, 2})
	want(t, resp, body, http.StatusBadRequest, "M1E-2001")
	if _, body := call(t, s, http.MethodGet, "/v1/enroll", nil); strings.TrimSpace(string(body)) != `{"enrolled":false,"key_id":"`+kg.KeyID+`"}` {
		t.Fatalf("state after refusals %s", body)
	}
}

func TestEnrollStateIsLiveNotStored(t *testing.T) {
	s, dir := newServer(t)
	write := func(state string, exp time.Time) {
		t.Helper()
		doc := map[string]any{"version": 1, "state": state, "device_id": deviceA, "tenant_id": tenantA, "device_token": "t", "token_expires_at": exp, "server": "https://api.example", "channel": "stable", "endpoints": map[string]any{}, "enrolled_at": exp}
		b, _ := json.Marshal(doc)
		if err := writeAtomic(filepath.Join(dir, "enrollment.json"), b); err != nil {
			t.Fatal(err)
		}
	}
	state := func() string {
		_, body := call(t, s, http.MethodGet, "/v1/enroll", nil)
		var st struct {
			Enrolled bool   `json:"enrolled"`
			State    string `json:"state"`
		}
		decodeTo(t, body, &st)
		if st.Enrolled != (st.State == "active") {
			t.Fatalf("enrolled must mean live active: %s", body)
		}
		return st.State
	}
	write("active", time.Now().Add(-time.Minute))
	if got := state(); got != "expired" {
		t.Fatalf("a document past token_expires_at is %q, want expired", got)
	}
	resp, body := call(t, s, http.MethodPost, "/v1/enroll/keygen", map[string]string{"tenant_id": tenantB})
	want(t, resp, body, http.StatusOK, "")
	write("revoked", time.Now().Add(time.Hour))
	if got := state(); got != "revoked" {
		t.Fatalf("a stamped revoked document is %q, want revoked", got)
	}
	resp, body = call(t, s, http.MethodPost, "/v1/enroll/keygen", map[string]string{"tenant_id": tenantB})
	want(t, resp, body, http.StatusOK, "")
	write("active", time.Now().Add(time.Hour))
	if got := state(); got != "active" {
		t.Fatalf("%q, want active", got)
	}
	resp, body = call(t, s, http.MethodPost, "/v1/enroll/keygen", map[string]string{"tenant_id": tenantB})
	want(t, resp, body, http.StatusConflict, "M1E-2001")
	resp, body = call(t, s, http.MethodPost, "/v1/enroll/keygen", map[string]string{"tenant_id": tenantA})
	want(t, resp, body, http.StatusOK, "")
	if runtime.GOOS != "windows" {
		if err := os.Chmod(filepath.Join(dir, "enrollment.json"), 0o640); err != nil {
			t.Fatal(err)
		}
		resp, body = call(t, s, http.MethodGet, "/v1/enroll", nil)
		want(t, resp, body, http.StatusInternalServerError, "M1E-9500")
	}
	if err := os.WriteFile(filepath.Join(dir, "enrollment.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	resp, body = call(t, s, http.MethodGet, "/v1/enroll", nil)
	want(t, resp, body, http.StatusInternalServerError, "M1E-9500")
}

func TestServerOfRecoversTheControlPlaneBase(t *testing.T) {
	for in, want := range map[string]string{
		"https://api.example/m1p/v1/ingest":       "https://api.example",
		"https://api.example/mark1/m1p/v1/ingest": "https://api.example/mark1",
		"https://ingest.example/other/path":       "https://ingest.example",
		"http://127.0.0.1:8080/m1p/v1/ingest":     "http://127.0.0.1:8080",
		"not a url":                               "",
		"":                                        "",
		"/m1p/v1/ingest":                          "",
	} {
		if got := serverOf(in); got != want {
			t.Errorf("serverOf(%q) = %q, want %q", in, got, want)
		}
	}
}
