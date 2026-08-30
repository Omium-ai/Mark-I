package off

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Omium-ai/omium-mark1/go/mark1/internal/cli"
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
	t.Cleanup(func() { os.RemoveAll(dir) })
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
	if fi.Mode().Perm() != 0o600 {
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
	json.Unmarshal(out.Bytes(), &res)
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
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
			// Close the listener once the marker exists — the daemon's 1 Hz
			// stat loop, compressed for tests.
			if _, err := os.Stat(env.OffMarkerPath()); err == nil {
				l.Close()
				return
			}
		}
	}()
	if err := Run(env, Options{Socket: sock, ObserveGrace: 3 * time.Second}); err != nil {
		t.Fatal(err)
	}
	var res Result
	json.Unmarshal(out.Bytes(), &res)
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
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
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

func TestOffListsUnrevertedManifests(t *testing.T) {
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
	json.Unmarshal(out.Bytes(), &res)
	if len(res.NotReverted) != 1 || res.NotReverted[0] != manifest || res.ByteEquality {
		t.Fatalf("result %+v", res)
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
	json.Unmarshal(out.Bytes(), &res)
	if res["was_off"] != true {
		t.Fatalf("first on: %v", res)
	}
	out.Reset()
	if err := On(env); err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(out.Bytes(), &res)
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
