// Two rungs of proof: a fake verifier script pins the orchestration contract
// (args, exit-code passthrough, fetch translation), and — when the real
// tools/verifier binary is built at target/debug/mark1-verifier — an
// end-to-end run over the conformance receipt vectors proves the whole §7.7
// loop with real crypto, tamper case included.
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
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Omium-ai/omium-mark1/go/mark1/internal/cli"
)

func testEnv(t *testing.T, server string) (*cli.Env, *bytes.Buffer) {
	t.Helper()
	out := &bytes.Buffer{}
	return &cli.Env{StateDir: t.TempDir(), Server: server, JSON: true, Stdout: out, Stderr: os.Stderr}, out
}

// fakeVerifier writes a shell stand-in for mark1-verifier that copies its
// --chain and --keys inputs into dir (so tests can inspect what the CLI
// built) and exits with the given code.
func fakeVerifier(t *testing.T, dir string, exitCode int) string {
	t.Helper()
	script := fmt.Sprintf(`#!/bin/sh
# $1=verify $2=--chain $3=<path> $4=--keys $5=<path> [--json...]
[ "$1" = "verify" ] || exit 2
cp "$3" %q/got-chain.jsonl
cp "$5" %q/got-keys.json
echo '{"ok":%v,"checked":{"receipts":1},"defects":[]}'
exit %d
`, dir, dir, exitCode == 0, exitCode)
	path := filepath.Join(dir, "fake-verifier")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
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
	os.WriteFile(keys, []byte(`{}`), 0o600)

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
	os.MkdirAll(exp, 0o700)
	os.WriteFile(filepath.Join(exp, "b.jsonl"), []byte(`{"seq":2}`+"\n"), 0o600)
	os.WriteFile(filepath.Join(exp, "a.jsonl"), []byte(`{"seq":1}`), 0o600) // no trailing newline on purpose
	keys := filepath.Join(dir, "keys.json")
	os.WriteFile(keys, []byte(`{}`), 0o600)
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
			fmt.Fprint(w, `{"error":{"code":"M1E-1002","message":"bad token"}}`)
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
			fmt.Fprint(w, exportLine(seq))
		}
	})
	mux.HandleFunc("GET /api/v1/receipts/keys", func(w http.ResponseWriter, r *http.Request) {
		if !authed(w, r) {
			return
		}
		fmt.Fprint(w, `{"server_chain_keys":[{"pubkey_hex":"deadbeef","key_id":"srvkey"}],"device_keys":[{"pubkey_hex":"beefdead","key_id":"devkey","tenant_id":"t-1"}]}`)
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
		fmt.Fprint(w, `{"error":{"code":"M1E-1003","message":"device revoked"}}`)
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

func realVerifier(t *testing.T) string {
	t.Helper()
	bin, err := filepath.Abs(filepath.Join(repoRoot, "target", "debug", "mark1-verifier"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skip("target/debug/mark1-verifier not built (run `cargo build -p mark1-verifier`); orchestration is proven by the fake-verifier tests above")
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
	os.WriteFile(chainPath, chain.Bytes(), 0o600)
	keys := map[string]any{
		"server_chain_keys": []map[string]string{{"pubkey_hex": manifest.Keys["server"].PublicHex}},
		"device_keys":       []map[string]string{{"pubkey_hex": manifest.Keys["device"].PublicHex}},
	}
	keysData, _ := json.Marshal(keys)
	keysPath = filepath.Join(dir, "keys.json")
	os.WriteFile(keysPath, keysData, 0o600)
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
