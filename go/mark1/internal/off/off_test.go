package off

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Omium-ai/omium-mark1/go/mark1/internal/cli"
	"github.com/Omium-ai/omium-mark1/go/mark1/internal/enable"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/claudecode"
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
func TestEnableThenOffIsByteEqual(t *testing.T) {
	env, out := testEnv(t)
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
