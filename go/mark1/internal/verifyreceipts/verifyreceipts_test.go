// Two rungs of proof: a fake verifier script pins the orchestration contract
// (args, exit-code passthrough, fetch translation), and an end-to-end run of
// the REAL tools/verifier binary over the conformance receipt vectors proves
// the whole §7.7 loop with real crypto, tamper case included. The second rung
// builds the binary if it is missing rather than skipping (see realVerifier),
// so a lane that ships no Rust toolchain fails loudly instead of reporting
// FR-CLI-007 green by never running it.
//
// "with every Omium endpoint blackholed" (02 FR-SPINE-020, 12 §12's
// conf_verifier_offline) is not provable from inside a test process that could
// always just not have called out: tools/ci/verifier_offline_gate.sh runs these
// same two tests inside an empty network namespace, with a probe proving the
// namespace really does blackhole.
package verifyreceipts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Omium-ai/omium-mark1/go/mark1/internal/cli"
)

// fakeVerifierEnvVar switches TestMain into fake-verifier mode: the fixture
// used to be a `#!/bin/sh` script named "fake-verifier" with no extension,
// which Windows cannot exec (no shebang, no .exe). This test binary re-exec's
// itself as MARK1_VERIFIER instead, which is exec'able on every OS. Same
// shape as go/mark1d/internal/supervise/proxy_test.go's "port-then-crash"
// child mode.
const fakeVerifierEnvVar = "MARK1_TEST_FAKE_VERIFIER"

func TestMain(m *testing.M) {
	if os.Getenv(fakeVerifierEnvVar) == "1" {
		os.Exit(runFakeVerifier())
	}
	os.Exit(m.Run())
}

// runFakeVerifier mirrors the old shell script: it copies the --chain and
// --keys inputs (read off argv exactly as verifyreceipts.Run built them)
// into the dir named by MARK1_TEST_FAKE_VERIFIER_DIR, prints a verdict, and
// returns MARK1_TEST_FAKE_VERIFIER_EXIT as the exit code.
func runFakeVerifier() int {
	// os.Args = [self, "verify", "--chain", <path>, "--keys", <path>, ...]
	if len(os.Args) < 6 || os.Args[1] != "verify" {
		return 2
	}
	dir := os.Getenv(fakeVerifierEnvVar + "_DIR")
	chain, err := os.ReadFile(os.Args[3])
	if err != nil {
		return 9
	}
	if err := os.WriteFile(filepath.Join(dir, "got-chain.jsonl"), chain, 0o600); err != nil {
		return 9
	}
	keys, err := os.ReadFile(os.Args[5])
	if err != nil {
		return 9
	}
	if err := os.WriteFile(filepath.Join(dir, "got-keys.json"), keys, 0o600); err != nil {
		return 9
	}
	exitCode, err := strconv.Atoi(os.Getenv(fakeVerifierEnvVar + "_EXIT"))
	if err != nil {
		return 9
	}
	fmt.Printf("{\"ok\":%v,\"checked\":{\"receipts\":1},\"defects\":[]}\n", exitCode == 0)
	return exitCode
}

func testEnv(t *testing.T, server string) (*cli.Env, *bytes.Buffer) {
	t.Helper()
	out := &bytes.Buffer{}
	return &cli.Env{StateDir: t.TempDir(), Server: server, JSON: true, Stdout: out, Stderr: os.Stderr}, out
}

// fakeVerifier arranges for this test binary — re-exec'd as MARK1_VERIFIER —
// to copy its --chain and --keys inputs into dir (so tests can inspect what
// the CLI built) and exit with the given code. See runFakeVerifier.
func fakeVerifier(t *testing.T, dir string, exitCode int) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(fakeVerifierEnvVar, "1")
	t.Setenv(fakeVerifierEnvVar+"_DIR", dir)
	t.Setenv(fakeVerifierEnvVar+"_EXIT", strconv.Itoa(exitCode))
	return self
}

func TestVerifierMissingIsRuntimeFailure(t *testing.T) {
	t.Setenv("MARK1_VERIFIER", "")
	t.Setenv("PATH", t.TempDir())
	env, _ := testEnv(t, "http://unused.invalid")
	err := Run(context.Background(), env, Options{From: "x.jsonl"})
	var ee *cli.ExitError
	if !errors.As(err, &ee) || ee.Code != cli.ExitRuntime || !strings.Contains(ee.Msg, "mark1-verifier") {
		t.Fatalf("got %v, want honest exit 1 about the missing binary", err)
	}
}

func TestOfflineRequiresLocalInputs(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MARK1_VERIFIER", fakeVerifier(t, dir, 0))
	env, _ := testEnv(t, "http://unused.invalid")
	err := Run(context.Background(), env, Options{Offline: true, From: "x.jsonl"})
	var ee *cli.ExitError
	if !errors.As(err, &ee) || ee.Code != cli.ExitUsage {
		t.Fatalf("got %v, want exit 2 (--offline sans --keys)", err)
	}
}

func TestAgainstWitnessRequiresSnapshot(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MARK1_VERIFIER", fakeVerifier(t, dir, 0))
	env, _ := testEnv(t, "http://unused.invalid")
	err := Run(context.Background(), env, Options{From: "x.jsonl", AgainstWitness: true})
	var ee *cli.ExitError
	if !errors.As(err, &ee) || ee.Code != cli.ExitUsage {
		t.Fatalf("got %v, want exit 2", err)
	}
}

func TestFromFilePassthroughAndVerdicts(t *testing.T) {
	dir := t.TempDir()
	chain := filepath.Join(dir, "export.jsonl")
	if err := os.WriteFile(chain, []byte(`{"seq":1}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(dir, "keys.json")
	if err := os.WriteFile(keys, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}

	// Valid chain: verifier exit 0 → ours 0, report passed through verbatim.
	t.Setenv("MARK1_VERIFIER", fakeVerifier(t, dir, 0))
	env, out := testEnv(t, "http://unused.invalid")
	if err := Run(context.Background(), env, Options{From: chain, Keys: keys, Offline: true}); err != nil {
		t.Fatal(err)
	}
	var rep map[string]any
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil || rep["ok"] != true {
		t.Fatalf("report %q: %v", out.String(), err)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "got-chain.jsonl"))
	if string(got) != `{"seq":1}`+"\n" {
		t.Fatalf("--from file not passed verbatim: %q", got)
	}

	// Defect: verifier exit 5 → ours 5, never summarized away.
	t.Setenv("MARK1_VERIFIER", fakeVerifier(t, dir, 5))
	env2, _ := testEnv(t, "http://unused.invalid")
	err := Run(context.Background(), env2, Options{From: chain, Keys: keys, Offline: true})
	var ee *cli.ExitError
	if !errors.As(err, &ee) || ee.Code != cli.ExitVerify || !ee.Emitted {
		t.Fatalf("got %v, want emitted exit 5", err)
	}
}

func TestFromDirConcatenatesInNameOrder(t *testing.T) {
	dir := t.TempDir()
	exp := filepath.Join(dir, "exports")
	if err := os.MkdirAll(exp, 0o700); err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(dir, "keys.json")
	for path, body := range map[string]string{
		filepath.Join(exp, "b.jsonl"): `{"seq":2}` + "\n",
		filepath.Join(exp, "a.jsonl"): `{"seq":1}`, // no trailing newline on purpose
		keys:                          `{}`,
	} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("MARK1_VERIFIER", fakeVerifier(t, dir, 0))
	env, _ := testEnv(t, "http://unused.invalid")
	if err := Run(context.Background(), env, Options{From: exp, Keys: keys, Offline: true}); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "got-chain.jsonl"))
	if string(got) != `{"seq":1}`+"\n"+`{"seq":2}`+"\n" {
		t.Fatalf("concatenation %q", got)
	}
}

// exportLine renders one export row exactly as controld's handleExport does
// (JSONL via json.Encoder — the byte-loadable verifier ExportRow).
func exportLine(seq int) string {
	return fmt.Sprintf(`{"seq":%d,"payload":"{\"seq\":%d}","receipt_hash_hex":"cc33","server_key_id":"srvkey","server_signature_hex":"bb22","device_key_id":"devkey","device_signature_hex":"aa11"}`+"\n", seq, seq)
}

// exportStub serves 08 §7.7's amended default network path: the
// /api/v1/receipts/export + /api/v1/receipts/keys pair, device-token
// authenticated, export paged by the exclusive since_seq cursor.
func exportStub(t *testing.T, totalRows int) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	authed := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("Authorization") != "Bearer tok-1" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, `{"error":{"code":"M1E-1002","message":"bad token"}}`)
			return false
		}
		return true
	}
	mux.HandleFunc("GET /api/v1/receipts/export", func(w http.ResponseWriter, r *http.Request) {
		if !authed(w, r) {
			return
		}
		since, _ := strconv.Atoi(r.URL.Query().Get("since_seq"))
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit <= 0 || limit > 5000 {
			limit = 5000 // mirror controld's pageParams cap
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		for seq := since + 1; seq <= totalRows && seq <= since+limit; seq++ {
			_, _ = fmt.Fprint(w, exportLine(seq))
		}
	})
	mux.HandleFunc("GET /api/v1/receipts/keys", func(w http.ResponseWriter, r *http.Request) {
		if !authed(w, r) {
			return
		}
		_, _ = fmt.Fprint(w, `{"server_chain_keys":[{"pubkey_hex":"deadbeef","key_id":"srvkey"}],"device_keys":[{"pubkey_hex":"beefdead","key_id":"devkey","tenant_id":"t-1"}]}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func enrollFor(t *testing.T, env *cli.Env) {
	t.Helper()
	if err := env.SaveEnrollment(&cli.Enrollment{
		Version: 1, State: "active", DeviceToken: "tok-1",
		TokenExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
}

// TestFetchExportByteRoundTrip pins the amended §7.7 contract: what the
// export endpoint serves is what the verifier reads — byte for byte, no
// translation layer, keys landed verbatim from /api/v1/receipts/keys.
func TestFetchExportByteRoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MARK1_VERIFIER", fakeVerifier(t, dir, 0))
	srv := exportStub(t, 2)
	env, _ := testEnv(t, srv.URL)
	enrollFor(t, env)
	if err := Run(context.Background(), env, Options{}); err != nil {
		t.Fatal(err)
	}
	chain, err := os.ReadFile(filepath.Join(dir, "got-chain.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if want := exportLine(1) + exportLine(2); string(chain) != want {
		t.Fatalf("chain not the export bytes verbatim:\n got %q\nwant %q", chain, want)
	}
	keys, err := os.ReadFile(filepath.Join(dir, "got-keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(keys), `"pubkey_hex":"deadbeef"`) {
		t.Fatalf("keys not landed verbatim: %q", keys)
	}
}

// TestFetchExportPages proves the exclusive since_seq paging: 5001 rows span
// two pages (the server caps a page at 5000) and the file carries every row
// exactly once, in order.
func TestFetchExportPages(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MARK1_VERIFIER", fakeVerifier(t, dir, 0))
	srv := exportStub(t, 5001)
	env, _ := testEnv(t, srv.URL)
	enrollFor(t, env)
	if err := Run(context.Background(), env, Options{}); err != nil {
		t.Fatal(err)
	}
	chain, err := os.ReadFile(filepath.Join(dir, "got-chain.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(chain), "\n"), "\n")
	if len(lines) != 5001 {
		t.Fatalf("chain holds %d rows, want 5001 (page-boundary row lost or doubled)", len(lines))
	}
	for i, l := range lines {
		if want := strings.TrimSuffix(exportLine(i+1), "\n"); l != want {
			t.Fatalf("row %d = %q, want %q", i+1, l, want)
		}
	}
}

// TestFetchAuthRefusalStampsEnrollment is item-1 class coverage at this call
// site: a 401/M1E-1003 during the export fetch surfaces exit 3 AND stamps the
// stored enrollment REVOKED, so status/enroll show the recovery path.
func TestFetchAuthRefusalStampsEnrollment(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MARK1_VERIFIER", fakeVerifier(t, dir, 0))
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/receipts/export", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprint(w, `{"error":{"code":"M1E-1003","message":"device revoked"}}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	env, _ := testEnv(t, srv.URL)
	enrollFor(t, env)
	err := Run(context.Background(), env, Options{})
	var ee *cli.ExitError
	if !errors.As(err, &ee) || ee.Code != cli.ExitNotEnrolled || ee.M1E != "M1E-1003" {
		t.Fatalf("got %v, want exit 3 M1E-1003", err)
	}
	doc, err := env.LoadEnrollment()
	if err != nil || doc.State != cli.StateRevoked {
		t.Fatalf("enrollment state %v (%v), want revoked stamped by NoteAuthRefusal", doc, err)
	}
}

func TestFetchNotEnrolled(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MARK1_VERIFIER", fakeVerifier(t, dir, 0))
	env, _ := testEnv(t, "http://unused.invalid")
	err := Run(context.Background(), env, Options{})
	var ee *cli.ExitError
	if !errors.As(err, &ee) || ee.Code != cli.ExitNotEnrolled {
		t.Fatalf("got %v, want exit 3", err)
	}
}

// --- End-to-end against the REAL verifier over the conformance vectors ---

const repoRoot = "../../../.."

// realVerifier returns the SHIPPED verifier binary, building it if it is not
// there yet.
//
// It used to t.Skip() when target/debug/mark1-verifier was absent, which made
// FR-CLI-007 a false green: the row cites the two tests below as the proof
// that the real binary verifies a real chain, and `just test-go` runs in a CI
// job that never builds any Rust — so on every lane that mattered the "proof"
// was a skip, and a skip and a pass are the same exit code. Building here is
// the same move controld's TestIntegrationVerifierE2EExportRoundTrip already
// makes for the same binary, so the two verifier e2e suites now have one
// precondition story rather than two.
//
// cargo absent is the only remaining skip, and M1_REQUIRE_STORES=1 inverts it
// into a failure exactly as it does for a missing DSN (12 §11.4): a developer
// without a Rust toolchain still gets the fake-verifier rungs, while no CI lane
// can report this requirement green without having executed it.
func realVerifier(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	binName := "mark1-verifier"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	bin := filepath.Join(root, "target", "debug", binName)
	if _, err := os.Stat(bin); err == nil {
		return bin
	}
	if _, err := exec.LookPath("cargo"); err != nil {
		if os.Getenv("M1_REQUIRE_STORES") == "1" {
			t.Fatal("cargo required (M1_REQUIRE_STORES=1) but not found: FR-CLI-007's evidence is the real mark1-verifier binary running, and this lane cannot build it — skipping here would report the requirement green without ever executing it")
		}
		t.Skip("cargo not found and target/debug/mark1-verifier not built; orchestration is proven by the fake-verifier tests above")
	}
	// --locked: the verifier the customer audits is the one Cargo.lock pins.
	build := exec.Command("cargo", "build", "--locked", "-p", "mark1-verifier")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("cargo build --locked -p mark1-verifier: %v\n%s", err, out)
	}
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("cargo build reported success but %s is absent (%v) — the build produced no binary to test", bin, err)
	}
	return bin
}

// vectorExport renders the conformance receipt vectors as §7.7 export
// inputs: chain rows are already in the verifier's vocabulary; the payload
// column is the exact signed canonical text.
func vectorExport(t *testing.T, dir string, tamper bool) (chainPath, keysPath string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot, "conformance", "vectors", "receipt", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Keys map[string]struct {
			PublicHex string `json:"public_hex"`
		} `json:"keys"`
		Chain []struct {
			Seq                uint64  `json:"seq"`
			CanonicalJSON      string  `json:"canonical_json"`
			ReceiptHashHex     string  `json:"receipt_hash_hex"`
			DeviceKeyID        *string `json:"device_key_id"`
			DeviceSignatureHex *string `json:"device_signature_hex"`
			ServerKeyID        string  `json:"server_key_id"`
			ServerSignatureHex string  `json:"server_signature_hex"`
		} `json:"chain"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	var chain bytes.Buffer
	for i, r := range manifest.Chain {
		sig := r.ServerSignatureHex
		if tamper && i == len(manifest.Chain)-1 {
			// Flip one hex digit of the last server signature: the verdict
			// must be a NAMED defect, exit 5 (08 §7.7).
			flip := byte('0')
			if sig[0] == '0' {
				flip = '1'
			}
			sig = string(flip) + sig[1:]
		}
		row := map[string]any{
			"seq": r.Seq, "payload": r.CanonicalJSON, "receipt_hash_hex": r.ReceiptHashHex,
			"device_key_id": r.DeviceKeyID, "device_signature_hex": r.DeviceSignatureHex,
			"server_key_id": r.ServerKeyID, "server_signature_hex": sig,
		}
		line, _ := json.Marshal(row)
		chain.Write(append(line, '\n'))
	}
	chainPath = filepath.Join(dir, "chain.jsonl")
	if err := os.WriteFile(chainPath, chain.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	keys := map[string]any{
		"server_chain_keys": []map[string]string{{"pubkey_hex": manifest.Keys["server"].PublicHex}},
		"device_keys":       []map[string]string{{"pubkey_hex": manifest.Keys["device"].PublicHex}},
	}
	keysData, _ := json.Marshal(keys)
	keysPath = filepath.Join(dir, "keys.json")
	if err := os.WriteFile(keysPath, keysData, 0o600); err != nil {
		t.Fatal(err)
	}
	return chainPath, keysPath
}

func TestEndToEndRealVerifierValidChain(t *testing.T) {
	bin := realVerifier(t)
	t.Setenv("MARK1_VERIFIER", bin)
	dir := t.TempDir()
	chain, keys := vectorExport(t, dir, false)
	env, out := testEnv(t, "http://unused.invalid")
	if err := Run(context.Background(), env, Options{From: chain, Keys: keys, Offline: true}); err != nil {
		t.Fatalf("valid vector chain rejected: %v (stdout %s)", err, out.String())
	}
	var rep struct {
		OK      bool `json:"ok"`
		Checked struct {
			Receipts int `json:"receipts"`
		} `json:"checked"`
	}
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil || !rep.OK || rep.Checked.Receipts == 0 {
		t.Fatalf("report %q: %v", out.String(), err)
	}
}

func TestEndToEndRealVerifierTamperedChain(t *testing.T) {
	bin := realVerifier(t)
	t.Setenv("MARK1_VERIFIER", bin)
	dir := t.TempDir()
	chain, keys := vectorExport(t, dir, true)
	env, out := testEnv(t, "http://unused.invalid")
	err := Run(context.Background(), env, Options{From: chain, Keys: keys, Offline: true})
	var ee *cli.ExitError
	if !errors.As(err, &ee) || ee.Code != cli.ExitVerify {
		t.Fatalf("tampered chain: got %v, want exit 5", err)
	}
	// Defects are enumerated, never summarized away (§7.7); the kind
	// vocabulary is the verifier's — the CLI passes it through untouched.
	var rep struct {
		OK      bool `json:"ok"`
		Defects []struct {
			Seq  uint64 `json:"seq"`
			Kind string `json:"kind"`
		} `json:"defects"`
	}
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil || rep.OK || len(rep.Defects) == 0 {
		t.Fatalf("defect not enumerated in report %q: %v", out.String(), err)
	}
	if rep.Defects[0].Seq != 4 || rep.Defects[0].Kind == "" {
		t.Fatalf("defect not named: %+v", rep.Defects)
	}
}
