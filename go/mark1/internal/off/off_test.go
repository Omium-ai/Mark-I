package off

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/Omium-ai/omium-mark1/go/mark1/internal/cli"
	"github.com/Omium-ai/omium-mark1/go/mark1/internal/enable"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/claudecode"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/codex"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/copilot"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/cursor"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/gemini"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/opencode"
)

func testEnv(t *testing.T) (*cli.Env, *bytes.Buffer) {
	t.Helper()
	out := &bytes.Buffer{}
	return &cli.Env{StateDir: t.TempDir(), JSON: true, Stdout: out, Stderr: os.Stderr}, out
}

// shortSocket avoids the ~104-byte sun_path ceiling t.TempDir can blow.
func shortSocket(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "m1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "s.sock")
}

func TestOffWritesMarkerDaemonDown(t *testing.T) {
	env, out := testEnv(t)
	// No enrollment on purpose: the kill switch has no auth precondition —
	// §7.6 lists no exit 3.
	if err := Run(env, Options{Socket: shortSocket(t), ObserveGrace: 100 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(env.OffMarkerPath())
	if err != nil {
		t.Fatalf("OFF marker: %v", err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("marker mode %o, want 0600", fi.Mode().Perm())
	}
	var res Result
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatalf("stdout not one JSON object: %v", err)
	}
	if !res.OK || res.Scope != "all" || !res.ByteEquality || res.Daemon != "not running" {
		t.Fatalf("result %+v", res)
	}
	// The marker itself carries the auditable window.
	data, _ := os.ReadFile(env.OffMarkerPath())
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil || m["scope"] != "all" {
		t.Fatalf("marker content %q: %v", data, err)
	}
}

func TestOffIsIdempotent(t *testing.T) {
	env, out := testEnv(t)
	sock := shortSocket(t)
	opts := Options{Socket: sock, ObserveGrace: 50 * time.Millisecond}
	if err := Run(env, opts); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := Run(env, opts); err != nil {
		t.Fatalf("second off: %v", err)
	}
	if _, err := os.Stat(env.OffMarkerPath()); err != nil {
		t.Fatal("marker gone after idempotent re-run")
	}
}

func TestOffDurationLandsInMarkerAndResult(t *testing.T) {
	env, out := testEnv(t)
	if err := Run(env, Options{Socket: shortSocket(t), Duration: 2 * time.Hour, ObserveGrace: 50 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	var res Result
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatalf("stdout %q: %v", out.String(), err)
	}
	until, err := time.Parse(time.RFC3339, res.Until)
	if err != nil || time.Until(until) < time.Hour {
		t.Fatalf("until %q: %v", res.Until, err)
	}
}

// TestOffVerifiesDaemonObserved plays mark1d's half: an accepting socket
// that closes after the marker appears (mark1d's off.WatchCtx cancels the
// fabric listener) must be reported "observed".
func TestOffVerifiesDaemonObserved(t *testing.T) {
	env, out := testEnv(t)
	sock := shortSocket(t)
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
			// Close the listener once the marker exists — the daemon's 1 Hz
			// stat loop, compressed for tests.
			if _, err := os.Stat(env.OffMarkerPath()); err == nil {
				_ = l.Close()
				return
			}
		}
	}()
	if err := Run(env, Options{Socket: sock, ObserveGrace: 3 * time.Second}); err != nil {
		t.Fatal(err)
	}
	var res Result
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatalf("stdout %q: %v", out.String(), err)
	}
	if res.Daemon != "observed" {
		t.Fatalf("daemon %q, want observed", res.Daemon)
	}
}

func TestOffStillCapturingIsPartial(t *testing.T) {
	env, out := testEnv(t)
	sock := shortSocket(t)
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	err = Run(env, Options{Socket: sock, ObserveGrace: 200 * time.Millisecond})
	var ee *cli.ExitError
	if !errors.As(err, &ee) || ee.Code != cli.ExitRuntime || !ee.Emitted {
		t.Fatalf("got %v, want emitted exit 1 (§7.6 partial)", err)
	}
	// The marker stays regardless — off is in force even when the daemon
	// misbehaves; the shim's own marker check is the backstop.
	if _, err := os.Stat(env.OffMarkerPath()); err != nil {
		t.Fatal("partial off removed the marker")
	}
	var res Result
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.OK || res.Daemon != "still capturing" {
		t.Fatalf("result %+v", res)
	}
}

// TestOffListsManifestsItCannotRevert: a manifest the §8.4 engine refuses
// (here, one that never carried a post-image to compare against) is LISTED and
// makes the command partial. Silence would tell a user their config is clean
// while our block is still in it.
func TestOffListsManifestsItCannotRevert(t *testing.T) {
	env, out := testEnv(t)
	mdir := filepath.Join(env.ProvisionedDir(), "claudecode")
	if err := os.MkdirAll(mdir, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(mdir, "hooks.manifest.json")
	if err := os.WriteFile(manifest, []byte(`{"target_path":"/tmp/x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	err := Run(env, Options{Socket: shortSocket(t), ObserveGrace: 50 * time.Millisecond})
	var ee *cli.ExitError
	if !errors.As(err, &ee) || ee.Code != cli.ExitRuntime {
		t.Fatalf("got %v, want exit 1 (§7.6: anything not reverted is listed)", err)
	}
	var res Result
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatalf("stdout %q: %v", out.String(), err)
	}
	if len(res.NotReverted) != 1 || res.NotReverted[0] != manifest || res.ByteEquality {
		t.Fatalf("result %+v", res)
	}
}

// provisioned plants a real user settings file, applies the real §8 fragment,
// and asserts the fragment actually landed. Every off test below depends on
// that: an `off` measured against a file we never wrote to is byte-equal for
// the wrong reason and would pass forever.
func provisioned(t *testing.T, env *cli.Env) (target string, original []byte) {
	t.Helper()
	target = filepath.Join(t.TempDir(), "settings.json")
	const body = `{
  "model": "opus",
  "hooks": {
    "Stop": [
      { "matcher": "", "hooks": [ { "type": "command", "command": "/usr/bin/mine.sh" } ] }
    ]
  }
}
`
	if err := os.WriteFile(target, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := claudecode.ApplyFragment(target, env.StateDir, "")
	if err != nil || !res.Changed {
		t.Fatalf("setup apply: %v %+v", err, res)
	}
	after, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(after, []byte("_mark1_managed")) {
		t.Fatalf("setup: no fragment landed, so this test proves nothing:\n%s", after)
	}
	return target, []byte(body)
}

// TestOffRevertsToByteEquality is §7.6's byte_equality promise end to end
// through the CLI: enable's fragment goes in, `mark1 off` takes it out, and
// the user's file is the file they had.
func TestOffRevertsToByteEquality(t *testing.T) {
	env, out := testEnv(t)
	target, original := provisioned(t, env)

	if err := Run(env, Options{Socket: shortSocket(t), ObserveGrace: 50 * time.Millisecond}); err != nil {
		t.Fatalf("off reported partial: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("off did not restore the user's bytes\n--- want\n%s\n--- got\n%s", original, got)
	}
	var res Result
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatalf("stdout %q: %v", out.String(), err)
	}
	if !res.OK || !res.ByteEquality || len(res.NotReverted) != 0 {
		t.Fatalf("result %+v", res)
	}
	if len(res.Reverted) != 1 || res.Reverted[0].Kind != "verbatim" || res.Reverted[0].Target != target {
		t.Fatalf("reverted %+v", res.Reverted)
	}
	// The manifest is gone, so a second off is a clean no-op rather than a
	// permanent partial.
	if _, err := os.Stat(claudecode.ManifestPath(env.StateDir)); !os.IsNotExist(err) {
		t.Fatalf("manifest survived revert: %v", err)
	}
	out.Reset()
	if err := Run(env, Options{Socket: shortSocket(t), ObserveGrace: 50 * time.Millisecond}); err != nil {
		t.Fatalf("second off: %v", err)
	}
}

// TestEnableThenOffIsByteEqual is the named CI test off_byte_equality (F-46) at
// the level a customer actually experiences it: the real `mark1 enable`
// provisions, the real `mark1 off` reverts, and the settings file is
// byte-identical to the one they had. The single-package tests above can drift
// from each other; this one cannot, because it runs both commands.
//
// It runs the API-key case on purpose, so BOTH fragments are in the file at
// once. Two fragments fencing one file is where byte-equality is actually at
// risk: each records a whole-file pre-image, and reverting them in the wrong
// order restores a snapshot that puts the other one back.
func TestEnableThenOffIsByteEqual(t *testing.T) {
	env, out := testEnv(t)
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-test-key")
	if err := os.MkdirAll(env.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// A real listener on a real port, answering the way the guard answers a
	// request carrying no M1-Cred-Ref (rust/mark1-proxy/src/router.rs:143-149).
	// `mark1 enable` probes the published port before it will write the base-URL
	// fragment, so a literal port here is a port nothing holds — enable would
	// write only the hooks fragment and this test would stop covering the
	// two-fragments-in-one-file case it exists for.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"M1E-8001","message":"request without a valid M1-Cred-Ref"}}`))
	}))
	t.Cleanup(srv.Close)
	proxyURL := "http://" + srv.Listener.Addr().String()
	port := strconv.Itoa(srv.Listener.Addr().(*net.TCPAddr).Port)
	if err := os.WriteFile(claudecode.ProxyPortPath(env.StateDir), []byte(port), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := env.SaveEnrollment(&cli.Enrollment{
		Version: 1, State: "active", DeviceID: "dev-1",
		DeviceToken: "tok", TokenExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	settings := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settings), 0o700); err != nil {
		t.Fatal(err)
	}
	const body = `{
  "model": "opus",
  "cleanupPeriodDays": 60,
  "hooks": {
    "Stop": [
      { "matcher": "", "hooks": [ { "type": "command", "command": "/usr/bin/mine.sh" } ] }
    ]
  }
}
`
	if err := os.WriteFile(settings, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := enable.Run(env, enable.Options{Path: t.TempDir(), Home: home}); err != nil {
		t.Fatal(err)
	}
	provisionedBytes, err := os.ReadFile(settings)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(provisionedBytes, []byte(body)) {
		t.Fatal("enable wrote nothing, so the off below would be byte-equal for the wrong reason")
	}
	for _, key := range []string{"_mark1_managed", "_mark1_managed_baseurl", proxyURL} {
		if !bytes.Contains(provisionedBytes, []byte(key)) {
			t.Fatalf("enable did not write %s, so this test proves less than it claims:\n%s", key, provisionedBytes)
		}
	}

	out.Reset()
	if err := Run(env, Options{Socket: shortSocket(t), ObserveGrace: 50 * time.Millisecond}); err != nil {
		t.Fatalf("off: %v", err)
	}
	got, err := os.ReadFile(settings)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte(body)) {
		t.Fatalf("enable -> off is not byte-equal\n--- want\n%s\n--- got\n%s", body, got)
	}
	var res Result
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatalf("stdout %q: %v", out.String(), err)
	}
	if !res.OK || !res.ByteEquality {
		t.Fatalf("result %+v", res)
	}
	kinds := map[string]string{}
	for _, r := range res.Reverted {
		kinds[r.Agent] = r.Kind
	}
	// The hooks fragment reaching its verbatim path is the observable proof the
	// base-URL fragment came out first: had the order been reversed, the file
	// would no longer match the hooks post-image and this would read "surgical".
	if kinds["claudecode"] != "verbatim" || kinds["claudecode/baseurl"] != "surgical" {
		t.Fatalf("reverted %+v", res.Reverted)
	}
}

// TestOffSurgicalAfterAUserEditIsHonest: the user changed their own settings
// after we provisioned, so the pre-image is stale and byte-equality is
// genuinely false. §7.6 wants the bool truthful, not flattering — and the
// user's later edit must survive.
func TestOffSurgicalAfterAUserEditIsHonest(t *testing.T) {
	env, out := testEnv(t)
	target, _ := provisioned(t, env)
	b, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	edited := bytes.Replace(b, []byte(`"model": "opus"`), []byte(`"model": "sonnet", "verbose": true`), 1)
	if bytes.Equal(edited, b) {
		t.Fatal("fixture drift: nothing outside the fence to edit")
	}
	if err := os.WriteFile(target, edited, 0o600); err != nil {
		t.Fatal(err)
	}

	// A surgical revert is still a complete revert: exit 0, byte_equality false.
	if err := Run(env, Options{Socket: shortSocket(t), ObserveGrace: 50 * time.Millisecond}); err != nil {
		t.Fatalf("a surgical revert failed the command: %v", err)
	}
	var res Result
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatalf("stdout %q: %v", out.String(), err)
	}
	if res.ByteEquality {
		t.Fatalf("byte_equality=true after a user edit: %+v", res)
	}
	if len(res.Reverted) != 1 || res.Reverted[0].Kind != "surgical" {
		t.Fatalf("reverted %+v", res.Reverted)
	}
	got, _ := os.ReadFile(target)
	if bytes.Contains(got, []byte("_mark1_managed")) || bytes.Contains(got, []byte("mark1-hookshim")) {
		t.Fatalf("surgical revert left our lines behind:\n%s", got)
	}
	if !bytes.Contains(got, []byte(`"sonnet"`)) || !bytes.Contains(got, []byte("/usr/bin/mine.sh")) {
		t.Fatalf("surgical revert ate the user's own settings:\n%s", got)
	}
}

func TestOnRemovesMarkerAndIsIdempotent(t *testing.T) {
	env, out := testEnv(t)
	if err := Run(env, Options{Socket: shortSocket(t), ObserveGrace: 50 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := On(env); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(env.OffMarkerPath()); !os.IsNotExist(err) {
		t.Fatal("marker survived `mark1 on`")
	}
	var res map[string]any
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatalf("first on stdout %q: %v", out.String(), err)
	}
	if res["was_off"] != true {
		t.Fatalf("first on: %v", res)
	}
	out.Reset()
	if err := On(env); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatalf("second on stdout %q: %v", out.String(), err)
	}
	if res["was_off"] != false {
		t.Fatalf("second on: %v", res)
	}
}

// TestOffCoverageJournal: §7.6 step 4 — the disable window is attributable.
func TestOffCoverageJournal(t *testing.T) {
	env, _ := testEnv(t)
	if err := Run(env, Options{Socket: shortSocket(t), ObserveGrace: 50 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(env.CoveragePath())
	if err != nil {
		t.Fatalf("coverage journal: %v", err)
	}
	var rec map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &rec); err != nil || rec["kind"] != "disable" {
		t.Fatalf("journal %q: %v", data, err)
	}
}

// TestOffRemovesTheStopGateOptIn: a paused install must not block (FR-POLICY-006),
// so off takes the opt-in artifact out with the fragments and says so; `mark1 on`
// does not bring it back — only `mark1 enable --stop-gate` at a terminal does.
func TestOffRemovesTheStopGateOptIn(t *testing.T) {
	env, out := testEnv(t)
	if err := env.WriteStopGateOptIn("2026-09-15T00:00:00Z", "alice"); err != nil {
		t.Fatal(err)
	}
	opts := Options{Socket: shortSocket(t), ObserveGrace: 50 * time.Millisecond}
	if err := Run(env, opts); err != nil {
		t.Fatal(err)
	}
	var res Result
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatalf("stdout %q: %v", out.String(), err)
	}
	if res.StopGate != "removed" || !res.OK {
		t.Fatalf("result %+v, want stop_gate removed", res)
	}
	if _, err := os.Stat(env.StopGateOptInPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("opt-in still on disk after off: %v", err)
	}
	if err := On(env); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(env.StopGateOptInPath()); err == nil {
		t.Fatal("`mark1 on` restored the opt-in")
	}
	out.Reset()
	if err := Run(env, opts); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(out.Bytes(), &res); err != nil || res.StopGate != "not_opted_in" {
		t.Fatalf("second off %+v %v, want stop_gate not_opted_in", res, err)
	}
}

// TestEnableThenOffIsByteEqualForCodex: 08 §8.4 through the CLI for both codex
// mechanisms — a user's hooks.json comes back byte-equal (B); an absent one
// is created by enable and gone again after off (A).
func TestEnableThenOffIsByteEqualForCodex(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script codex stub")
	}
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "codex"), []byte("#!/bin/sh\necho codex-cli 0.154.0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	t.Setenv("CODEX_HOME", "")
	const original = "{\n  \"description\": \"mine\",\n  \"hooks\": {\"PreToolUse\": [ {\"matcher\":\"shell\", \"hooks\": [ {\"type\":\"command\",\"command\":\"echo hi\"} ] } ]}\n}\n"
	for _, tc := range []struct{ name, body, kind string }{
		{"fenced (B)", original, "verbatim"},
		{"owned (A)", "", "verbatim"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, out := testEnv(t)
			if err := env.SaveEnrollment(&cli.Enrollment{
				Version: 1, State: "active", DeviceID: "dev-1",
				DeviceToken: "tok", TokenExpiresAt: time.Now().Add(time.Hour),
			}); err != nil {
				t.Fatal(err)
			}
			home := t.TempDir()
			hooks := filepath.Join(home, ".codex", "hooks.json")
			if err := os.MkdirAll(filepath.Dir(hooks), 0o700); err != nil {
				t.Fatal(err)
			}
			if tc.body != "" {
				if err := os.WriteFile(hooks, []byte(tc.body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if err := enable.Run(env, enable.Options{Path: t.TempDir(), Home: home, NoAnchors: true}); err != nil {
				t.Fatal(err)
			}
			provisioned, err := os.ReadFile(hooks)
			if err != nil || !bytes.Contains(provisioned, []byte(`"_mark1"`)) || bytes.Equal(provisioned, []byte(tc.body)) {
				t.Fatalf("enable did not fence hooks.json (%v):\n%s", err, provisioned)
			}
			out.Reset()
			if err := Run(env, Options{Socket: shortSocket(t), ObserveGrace: 50 * time.Millisecond}); err != nil {
				t.Fatalf("off: %v", err)
			}
			got, rerr := os.ReadFile(hooks)
			switch {
			case tc.body == "" && !os.IsNotExist(rerr):
				t.Fatalf("mechanism A off must delete the owned file: %v\n%s", rerr, got)
			case tc.body != "" && !bytes.Equal(got, []byte(tc.body)):
				t.Fatalf("enable -> off is not byte-equal\n--- want\n%s\n--- got\n%s", tc.body, got)
			}
			var res Result
			if err := json.Unmarshal(out.Bytes(), &res); err != nil {
				t.Fatalf("stdout %q: %v", out.String(), err)
			}
			if !res.OK || !res.ByteEquality {
				t.Fatalf("result %+v", res)
			}
			kinds := map[string]string{}
			for _, r := range res.Reverted {
				kinds[r.Agent] = r.Kind
			}
			if kinds["codex"] != tc.kind {
				t.Fatalf("reverted %+v, want codex %s", res.Reverted, tc.kind)
			}
			if _, err := os.Stat(codex.ManifestPath(env.StateDir)); !os.IsNotExist(err) {
				t.Fatalf("codex manifest survived off: %v", err)
			}
		})
	}
}

// TestOffKeepsTheExplorationOptIn: off disarms blocking; D-EF's contractual
// exploration half is not an arming and survives in the same artifact.
func TestOffKeepsTheExplorationOptIn(t *testing.T) {
	env, out := testEnv(t)
	if err := env.UpdateOptIn("2026-09-15T00:00:00Z", "alice", func(a *cli.OptIn) { a.StopGate, a.Exploration = true, true }); err != nil {
		t.Fatal(err)
	}
	if err := Run(env, Options{Socket: shortSocket(t), ObserveGrace: 50 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	var res Result
	if err := json.Unmarshal(out.Bytes(), &res); err != nil || res.StopGate != "removed" {
		t.Fatalf("result %+v %v, want stop_gate removed", res, err)
	}
	if a := env.ReadOptIn(); a.StopGate || !a.Exploration {
		t.Fatalf("artifact after off %+v, want stop_gate false and exploration kept", a)
	}
}

// enrolledWithBin is an enrolled env plus a fake home and a hermetic PATH
// holding one shell stub answering --version; the vendor HOME vars are blanked.
func enrolledWithBin(t *testing.T, name, banner string) (*cli.Env, *bytes.Buffer, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell-script stub")
	}
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\necho "+banner+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	for _, v := range []string{"CODEX_HOME", "GEMINI_CLI_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "COPILOT_HOME", "COPILOT_PROVIDERS_CONFIG", "COPILOT_PROVIDER_BASE_URL", "COPILOT_PROVIDER_API_KEY"} {
		t.Setenv(v, "")
	}
	env, out := testEnv(t)
	if err := env.SaveEnrollment(&cli.Enrollment{
		Version: 1, State: "active", DeviceID: "dev-1",
		DeviceToken: "tok", TokenExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	return env, out, t.TempDir()
}

func revertedKinds(t *testing.T, out *bytes.Buffer) (Result, map[string]string) {
	t.Helper()
	var res Result
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatalf("stdout %q: %v", out.String(), err)
	}
	kinds := map[string]string{}
	for _, r := range res.Reverted {
		kinds[r.Agent] = r.Kind
	}
	return res, kinds
}

// TestEnableThenOffIsByteEqualForGemini: 08 §8.4 through the CLI for mechanism
// B — the user's ~/.gemini/settings.json comes back byte-equal.
func TestEnableThenOffIsByteEqualForGemini(t *testing.T) {
	env, out, home := enrolledWithBin(t, "gemini", "0.59.0")
	const original = "{\n  \"theme\": \"mine\",\n  \"hooks\": {\"BeforeTool\": [ {\"matcher\":\"*\", \"hooks\": [ {\"type\":\"command\",\"command\":\"echo hi\"} ] } ]}\n}\n"
	settings := filepath.Join(home, ".gemini", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settings), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settings, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := enable.Run(env, enable.Options{Path: t.TempDir(), Home: home, NoAnchors: true}); err != nil {
		t.Fatal(err)
	}
	provisioned, err := os.ReadFile(settings)
	if err != nil || !bytes.Contains(provisioned, []byte(`"_mark1"`)) {
		t.Fatalf("enable did not fence settings.json (%v):\n%s", err, provisioned)
	}
	out.Reset()
	if err := Run(env, Options{Socket: shortSocket(t), ObserveGrace: 50 * time.Millisecond}); err != nil {
		t.Fatalf("off: %v", err)
	}
	if got, _ := os.ReadFile(settings); !bytes.Equal(got, []byte(original)) {
		t.Fatalf("enable -> off is not byte-equal\n--- want\n%s\n--- got\n%s", original, got)
	}
	res, kinds := revertedKinds(t, out)
	if !res.OK || !res.ByteEquality || kinds["gemini"] != "verbatim" {
		t.Fatalf("result %+v", res)
	}
	if _, err := os.Stat(gemini.ManifestPath(env.StateDir)); !os.IsNotExist(err) {
		t.Fatalf("gemini manifest survived off: %v", err)
	}
}

// TestEnableThenOffDeletesTheOpenCodePlugin: mechanism A through the CLI — the
// owned plugin is gone after off; one the user edited is retained, listed as
// not reverted, and makes the command partial (exit 1).
func TestEnableThenOffDeletesTheOpenCodePlugin(t *testing.T) {
	for _, edited := range []bool{false, true} {
		t.Run(map[bool]string{false: "owned", true: "user-edited"}[edited], func(t *testing.T) {
			env, out, home := enrolledWithBin(t, "opencode", "1.18.31")
			plugin := filepath.Join(home, ".config", "opencode", "plugins", "mark1.js")
			if err := os.MkdirAll(filepath.Dir(filepath.Dir(plugin)), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := enable.Run(env, enable.Options{Path: t.TempDir(), Home: home, NoAnchors: true}); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(plugin); err != nil {
				t.Fatalf("enable did not plant the plugin: %v", err)
			}
			mine := []byte("// mine\n")
			if edited {
				if err := os.WriteFile(plugin, mine, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			out.Reset()
			err := Run(env, Options{Socket: shortSocket(t), ObserveGrace: 50 * time.Millisecond})
			res, kinds := revertedKinds(t, out)
			if !edited {
				if err != nil {
					t.Fatalf("off: %v", err)
				}
				if _, serr := os.Stat(plugin); !os.IsNotExist(serr) {
					t.Fatalf("mechanism A off must delete the owned file: %v", serr)
				}
				if !res.OK || !res.ByteEquality || kinds["opencode"] != "verbatim" {
					t.Fatalf("result %+v", res)
				}
				if _, err := os.Stat(opencode.ManifestPath(env.StateDir)); !os.IsNotExist(err) {
					t.Fatalf("opencode manifest survived off: %v", err)
				}
				return
			}
			var ee *cli.ExitError
			if !errors.As(err, &ee) || ee.Code != cli.ExitRuntime {
				t.Fatalf("got %v, want exit 1 (a retained plugin is partial)", err)
			}
			if got, _ := os.ReadFile(plugin); !bytes.Equal(got, mine) {
				t.Fatalf("off touched a file whose bytes are no longer ours:\n%s", got)
			}
			if _, ok := kinds["opencode"]; ok || res.OK || res.ByteEquality || len(res.NotReverted) != 1 || res.NotReverted[0] != opencode.ManifestPath(env.StateDir) {
				t.Fatalf("result %+v", res)
			}
		})
	}
}

// TestEnableThenOffDeletesTheCopilotHooksFile: mechanism A through the CLI — the
// owned $COPILOT_HOME/hooks/mark1.json is gone after off; one the user edited is
// retained, listed as not reverted, and makes the command partial (exit 1).
func TestEnableThenOffDeletesTheCopilotHooksFile(t *testing.T) {
	for _, edited := range []bool{false, true} {
		t.Run(map[bool]string{false: "owned", true: "user-edited"}[edited], func(t *testing.T) {
			env, out, home := enrolledWithBin(t, "copilot", "1.0.85")
			hooks := filepath.Join(home, ".copilot", "hooks", "mark1.json")
			if err := os.MkdirAll(filepath.Dir(filepath.Dir(hooks)), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := enable.Run(env, enable.Options{Path: t.TempDir(), Home: home, NoAnchors: true}); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(hooks); err != nil {
				t.Fatalf("enable did not write the owned file: %v", err)
			}
			mine := []byte("{\"version\":1,\"hooks\":{}}\n")
			if edited {
				if err := os.WriteFile(hooks, mine, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			out.Reset()
			err := Run(env, Options{Socket: shortSocket(t), ObserveGrace: 50 * time.Millisecond})
			res, kinds := revertedKinds(t, out)
			if !edited {
				if err != nil {
					t.Fatalf("off: %v", err)
				}
				if _, serr := os.Stat(hooks); !os.IsNotExist(serr) {
					t.Fatalf("mechanism A off must delete the owned file: %v", serr)
				}
				if !res.OK || !res.ByteEquality || kinds["copilot"] != "verbatim" {
					t.Fatalf("result %+v", res)
				}
				if _, err := os.Stat(copilot.ManifestPath(env.StateDir)); !os.IsNotExist(err) {
					t.Fatalf("copilot manifest survived off: %v", err)
				}
				return
			}
			var ee *cli.ExitError
			if !errors.As(err, &ee) || ee.Code != cli.ExitRuntime {
				t.Fatalf("got %v, want exit 1 (a retained hooks file is partial)", err)
			}
			if got, _ := os.ReadFile(hooks); !bytes.Equal(got, mine) {
				t.Fatalf("off touched a file whose bytes are no longer ours:\n%s", got)
			}
			if _, ok := kinds["copilot"]; ok || res.OK || res.ByteEquality || len(res.NotReverted) != 1 || res.NotReverted[0] != copilot.ManifestPath(env.StateDir) {
				t.Fatalf("result %+v", res)
			}
		})
	}
}

// TestEnableThenOffIsByteEqualForCursor: 08 §8.4 through the CLI for both of
// cursor's mechanisms — a pre-existing ~/.cursor/hooks.json comes back byte-equal
// (B) and an owned one is deleted (A).
func TestEnableThenOffIsByteEqualForCursor(t *testing.T) {
	const original = "{\n  \"version\": 1,\n  \"hooks\": {\"preToolUse\": [ {\"command\": \"echo hi\", \"timeout\": 5} ]}\n}\n"
	for _, owned := range []bool{false, true} {
		t.Run(map[bool]string{false: "fenced", true: "owned"}[owned], func(t *testing.T) {
			env, out, home := enrolledWithBin(t, "cursor-agent", "2026.09.10-fd3934a")
			hooks := filepath.Join(home, ".cursor", "hooks.json")
			if err := os.MkdirAll(filepath.Dir(hooks), 0o700); err != nil {
				t.Fatal(err)
			}
			if !owned {
				if err := os.WriteFile(hooks, []byte(original), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if err := enable.Run(env, enable.Options{Path: t.TempDir(), Home: home, NoAnchors: true}); err != nil {
				t.Fatal(err)
			}
			provisioned, err := os.ReadFile(hooks)
			if err != nil || !bytes.Contains(provisioned, []byte(`"_mark1"`)) {
				t.Fatalf("enable did not fence hooks.json (%v):\n%s", err, provisioned)
			}
			out.Reset()
			if err := Run(env, Options{Socket: shortSocket(t), ObserveGrace: 50 * time.Millisecond}); err != nil {
				t.Fatalf("off: %v", err)
			}
			got, serr := os.ReadFile(hooks)
			if owned {
				if !os.IsNotExist(serr) {
					t.Fatalf("mechanism A off must delete the owned file: %v\n%s", serr, got)
				}
			} else if !bytes.Equal(got, []byte(original)) {
				t.Fatalf("enable -> off is not byte-equal\n--- want\n%s\n--- got\n%s", original, got)
			}
			res, kinds := revertedKinds(t, out)
			if !res.OK || !res.ByteEquality || kinds["cursor"] != "verbatim" {
				t.Fatalf("result %+v", res)
			}
			if _, err := os.Stat(cursor.ManifestPath(env.StateDir)); !os.IsNotExist(err) {
				t.Fatalf("cursor manifest survived off: %v", err)
			}
		})
	}
}
