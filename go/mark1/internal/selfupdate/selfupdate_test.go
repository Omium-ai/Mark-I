package selfupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Omium-ai/omium-mark1/go/mark1/internal/cli"
	"github.com/Omium-ai/omium-mark1/go/mark1/internal/service"
	"github.com/Omium-ai/omium-mark1/go/mark1/internal/verifyrelease"
)

func TestManagedProfileRefusesSelfUpdate(t *testing.T) {
	t.Setenv(ProfileEnv, "managed")
	if ok, why := Allowed(); ok || why == "" {
		t.Fatalf("managed fleet allowed a self-update (ok=%v, reason=%q)", ok, why)
	}
	for _, p := range []string{"", "cloud", "vpc", "selfhost"} {
		t.Setenv(ProfileEnv, p)
		if ok, why := Allowed(); !ok || why != "" {
			t.Fatalf("profile %q refused a self-update: %q — only managed is off by default", p, why)
		}
	}
}

func TestDefaultVerifierIsVerifyRelease(t *testing.T) {
	if reflect.ValueOf(verify).Pointer() != reflect.ValueOf(verifyrelease.Run).Pointer() {
		t.Fatal("selfupdate verifies through something other than verifyrelease.Run (FR-POLICY-009: one verifier)")
	}
}

type release struct {
	srv      *httptest.Server
	manifest Manifest
	tarball  []byte
	prov     []byte // nil = 404
	hits     map[string]*int32
}

func tarball(t *testing.T, members map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "./", Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
		t.Fatal(err)
	}
	for name, body := range members {
		if err := tw.WriteHeader(&tar.Header{Name: "./" + name, Typeflag: tar.TypeReg, Mode: 0o755, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func newRelease(t *testing.T, version string, members map[string]string) *release {
	t.Helper()
	r := &release{tarball: tarball(t, members), prov: []byte("{}\n"), hits: map[string]*int32{}}
	for _, p := range []string{"/manifest.json", "/edge.tar.gz", "/edge.tar.gz.sigstore.json"} {
		r.hits[p] = new(int32)
	}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if c := r.hits[req.URL.Path]; c != nil {
			atomic.AddInt32(c, 1)
		}
		switch req.URL.Path {
		case "/manifest.json":
			_ = json.NewEncoder(w).Encode(r.manifest)
		case "/edge.tar.gz":
			_, _ = w.Write(r.tarball)
		case "/edge.tar.gz.sigstore.json":
			if r.prov == nil {
				http.NotFound(w, req)
				return
			}
			_, _ = w.Write(r.prov)
		default:
			http.NotFound(w, req)
		}
	}))
	t.Cleanup(r.srv.Close)
	sum := sha256.Sum256(r.tarball)
	r.manifest = Manifest{
		ManifestSeq: 12,
		Rings:       map[string]string{"stable": version, "canary": version + "-rc1"},
		Artifacts: map[string]map[string]Artifact{version: {
			platform(): {URL: r.srv.URL + "/edge.tar.gz", SHA256: hex.EncodeToString(sum[:])},
		}},
	}
	return r
}

func (r *release) hit(path string) int32 { return atomic.LoadInt32(r.hits[path]) }

func platform() string { return runtime.GOOS + "/" + runtime.GOARCH }

type fixture struct {
	env     *cli.Env
	out     *bytes.Buffer
	home    string
	install string
	calls   []string
	pid     string
}

// newFixture: temp HOME with a registered systemd unit (service resolves to it), a temp install dir holding old binaries, and service.Exec scripted.
func newFixture(t *testing.T, running bool) *fixture {
	t.Helper()
	f := &fixture{home: t.TempDir(), install: t.TempDir(), out: &bytes.Buffer{}, pid: "0"}
	if running {
		f.pid = "77"
	}
	t.Setenv("HOME", f.home)
	t.Setenv("USERPROFILE", f.home) // os.UserHomeDir on Windows
	t.Setenv("XDG_RUNTIME_DIR", "")
	prevPlatform := service.Platform
	service.Platform = "linux" // the fixture is a systemd-user rig whatever the host
	t.Cleanup(func() { service.Platform = prevPlatform })
	f.env = &cli.Env{StateDir: filepath.Join(f.home, ".omium", "mark1"), JSON: true, Stdout: f.out, Stderr: os.Stderr, Version: "0.1.0"}
	unit := filepath.Join(f.home, ".config", "systemd", "user", "mark1d.service")
	if err := os.MkdirAll(filepath.Dir(unit), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unit, []byte("[Service]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, b := range []string{"mark1d", "mark1"} {
		if err := os.WriteFile(filepath.Join(f.install, b), []byte("old "+b), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	prev := service.Exec
	service.Exec = func(name string, args ...string) (string, error) {
		argv := strings.Join(append([]string{name}, args...), " ")
		f.calls = append(f.calls, argv)
		switch {
		case strings.HasPrefix(argv, "systemctl --user show"):
			return f.pid + "\n", nil
		case strings.HasPrefix(argv, "systemctl --user stop"):
			f.pid = "0"
		case strings.HasPrefix(argv, "systemctl --user start"):
			f.pid = "78"
		}
		return "", nil
	}
	t.Cleanup(func() { service.Exec = prev })
	return f
}

func (f *fixture) opts(r *release, check bool) Options {
	return Options{Check: check, Manifest: r.srv.URL + "/manifest.json", InstallDir: f.install, Socket: filepath.Join(f.home, "none.sock")}
}

func (f *fixture) snapshot(t *testing.T) map[string]string {
	t.Helper()
	files := map[string]string{}
	entries, err := os.ReadDir(f.install)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() {
			files[e.Name()+"/"] = ""
			continue
		}
		b, _ := os.ReadFile(filepath.Join(f.install, e.Name()))
		files[e.Name()] = string(b)
	}
	return files
}

func (f *fixture) result(t *testing.T) Result {
	t.Helper()
	var res Result
	if err := json.Unmarshal(f.out.Bytes(), &res); err != nil {
		t.Fatalf("stdout is not one JSON object: %v: %q", err, f.out.String())
	}
	f.out.Reset()
	return res
}

func exitCode(t *testing.T, err error) int {
	t.Helper()
	var ee *cli.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("not an ExitError: %v", err)
	}
	return ee.Code
}

func stubVerify(t *testing.T, err error) *int32 {
	t.Helper()
	calls := new(int32)
	prev := verify
	verify = func(env *cli.Env, opts verifyrelease.Options) error {
		atomic.AddInt32(calls, 1)
		if !strings.HasSuffix(filepath.ToSlash(opts.Artifact), "/.update/edge.tar.gz") || opts.Provenance != opts.Artifact+".sigstore.json" {
			t.Errorf("verifier handed %+v", opts)
		}
		return err
	}
	t.Cleanup(func() { verify = prev })
	return calls
}

func TestCheckReportsTheRingVersionWithoutDownloading(t *testing.T) {
	f := newFixture(t, true)
	r := newRelease(t, "0.2.0", map[string]string{"mark1d": "new"})
	if err := Run(context.Background(), f.env, f.opts(r, true)); err != nil {
		t.Fatal(err)
	}
	res := f.result(t)
	if !res.OK || !res.UpdateAvailable || res.Applied || res.Available != "0.2.0" || res.Current != "0.1.0" || res.Ring != "stable" || res.ManifestSeq != 12 {
		t.Fatalf("check result %+v", res)
	}
	if r.hit("/edge.tar.gz") != 0 || len(f.calls) != 0 {
		t.Fatalf("--check downloaded (%d) or touched the service (%q)", r.hit("/edge.tar.gz"), f.calls)
	}

	doc := &cli.Enrollment{Version: 1, State: cli.StateActive, Channel: "canary", TokenExpiresAt: time.Now().Add(time.Hour)}
	if err := f.env.SaveEnrollment(doc); err != nil {
		t.Fatal(err)
	}
	if err := Run(context.Background(), f.env, f.opts(r, true)); err != nil {
		t.Fatal(err)
	}
	if res = f.result(t); res.Ring != "canary" || res.Available != "0.2.0-rc1" {
		t.Fatalf("enrollment channel not honoured: %+v", res)
	}

	f.env.Version = "0.2.0-rc1"
	if err := Run(context.Background(), f.env, f.opts(r, false)); err != nil {
		t.Fatal(err)
	}
	if res = f.result(t); res.UpdateAvailable || res.Applied || r.hit("/edge.tar.gz") != 0 {
		t.Fatalf("up-to-date install tried to apply: %+v", res)
	}
}

func TestManagedProfileRefusesBeforeAnyNetwork(t *testing.T) {
	f := newFixture(t, false)
	r := newRelease(t, "0.2.0", nil)
	t.Setenv(ProfileEnv, "managed")
	err := Run(context.Background(), f.env, f.opts(r, true))
	if code := exitCode(t, err); code != cli.ExitRefused || r.hit("/manifest.json") != 0 {
		t.Fatalf("exit %d, manifest hits %d: %v", code, r.hit("/manifest.json"), err)
	}
}

func TestReplayedManifestIsRefused(t *testing.T) {
	f := newFixture(t, false)
	r := newRelease(t, "0.2.0", nil)
	seq := filepath.Join(f.env.StateDir, "update", "manifest_seq")
	if err := cli.WriteFileAtomic(seq, []byte("13"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := Run(context.Background(), f.env, f.opts(r, true))
	if code := exitCode(t, err); code != cli.ExitRefused || !strings.Contains(err.Error(), "manifest_seq 12 is below the last applied 13") {
		t.Fatalf("got %v", err)
	}
	if err := cli.WriteFileAtomic(seq, []byte("12"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Run(context.Background(), f.env, f.opts(r, true)); err != nil {
		t.Fatalf("an equal seq is a re-read, not a replay: %v", err)
	}
}

func TestFailedVerificationSwapsNothing(t *testing.T) {
	f := newFixture(t, true)
	r := newRelease(t, "0.2.0", map[string]string{"mark1d": "new mark1d", "mark1": "new mark1"})
	before := f.snapshot(t)

	// The real verifier, handed a bundle that is not a Sigstore bundle: exit 5, and it is verifyrelease's own defect string.
	err := Run(context.Background(), f.env, f.opts(r, false))
	if code := exitCode(t, err); code != cli.ExitVerify || !strings.Contains(err.Error(), "provenance_unparseable") {
		t.Fatalf("real verifier: got %v", err)
	}
	if got := f.snapshot(t); !reflect.DeepEqual(got, before) {
		t.Fatalf("install dir changed after a failed verification: %v", got)
	}

	// No provenance published at all.
	r.prov = nil
	err = Run(context.Background(), f.env, f.opts(r, false))
	if code := exitCode(t, err); code != cli.ExitVerify || !strings.Contains(err.Error(), "provenance_missing") {
		t.Fatalf("missing provenance: got %v", err)
	}

	// A stubbed refusal: the swap is gated on the verifier's verdict, not on the download succeeding.
	r.prov = []byte("{}\n")
	calls := stubVerify(t, cli.Failf(cli.ExitVerify, "", "builder_identity: signed by nobody"))
	err = Run(context.Background(), f.env, f.opts(r, false))
	if code := exitCode(t, err); code != cli.ExitVerify || atomic.LoadInt32(calls) != 1 {
		t.Fatalf("stubbed verifier: exit %d after %d calls: %v", code, atomic.LoadInt32(calls), err)
	}
	if got := f.snapshot(t); !reflect.DeepEqual(got, before) {
		t.Fatalf("install dir changed after a refused verification: %v", got)
	}
	for _, c := range f.calls {
		if strings.Contains(c, "stop") || strings.Contains(c, "start") {
			t.Fatalf("daemon touched before verification passed: %q", f.calls)
		}
	}
}

func TestApplySwapsAtomicallyAndRestartsThroughService(t *testing.T) {
	f := newFixture(t, true)
	r := newRelease(t, "0.2.0", map[string]string{"mark1d": "new mark1d", "mark1": "new mark1", "cortexd": "new cortexd"})
	stubVerify(t, nil)
	if err := Run(context.Background(), f.env, f.opts(r, false)); err != nil {
		t.Fatal(err)
	}
	res := f.result(t)
	if !res.Applied || res.Daemon != "restarted" || res.InstallDir != f.install || len(res.Swapped) != 3 {
		t.Fatalf("result %+v", res)
	}
	want := map[string]string{"mark1d": "new mark1d", "mark1": "new mark1", "cortexd": "new cortexd"}
	if got := f.snapshot(t); !reflect.DeepEqual(got, want) {
		t.Fatalf("install dir after apply: %v (no .old, no .update expected)", got)
	}
	for _, b := range []string{"mark1d", "cortexd"} {
		if fi, _ := os.Stat(filepath.Join(f.install, b)); runtime.GOOS != "windows" && fi.Mode().Perm()&0o111 == 0 {
			t.Fatalf("%s is not executable: %v", b, fi.Mode())
		}
	}
	joined := strings.Join(f.calls, "\n")
	stop, start := strings.Index(joined, "systemctl --user stop mark1d.service"), strings.Index(joined, "systemctl --user start mark1d.service")
	if stop < 0 || start < 0 || stop > start {
		t.Fatalf("stop/start order through service: %q", f.calls)
	}
	if seq, _ := os.ReadFile(filepath.Join(f.env.StateDir, "update", "manifest_seq")); string(seq) != "12" {
		t.Fatalf("manifest_seq persisted as %q", seq)
	}
}

func TestDaemonThatWillNotStopRefusesTheSwap(t *testing.T) {
	f := newFixture(t, true)
	r := newRelease(t, "0.2.0", map[string]string{"mark1d": "new mark1d"})
	stubVerify(t, nil)
	prevExec, prevTimeout := service.Exec, stopTimeout
	stopTimeout = 300 * time.Millisecond
	service.Exec = func(name string, args ...string) (string, error) {
		argv := strings.Join(append([]string{name}, args...), " ")
		f.calls = append(f.calls, argv)
		if strings.HasPrefix(argv, "systemctl --user show") {
			return "77\n", nil
		}
		return "", nil
	}
	t.Cleanup(func() { service.Exec, stopTimeout = prevExec, prevTimeout })
	err := Run(context.Background(), f.env, f.opts(r, false))
	if err == nil || !strings.Contains(err.Error(), "did not stop") {
		t.Fatalf("expected the stop-timeout refusal, got %v", err)
	}
	if got := f.snapshot(t); got["mark1d"] != "old mark1d" {
		t.Fatalf("binary swapped under a live daemon: %v", got)
	}
}

func TestApplyWithDaemonDownDoesNotStartIt(t *testing.T) {
	f := newFixture(t, false)
	r := newRelease(t, "0.2.0", map[string]string{"mark1d": "new mark1d"})
	stubVerify(t, nil)
	if err := Run(context.Background(), f.env, f.opts(r, false)); err != nil {
		t.Fatal(err)
	}
	if res := f.result(t); !res.Applied || res.Daemon != "not running" {
		t.Fatalf("result %+v", res)
	}
	for _, c := range f.calls {
		if strings.Contains(c, "stop") || strings.Contains(c, "start") {
			t.Fatalf("a daemon that was down was started: %q", f.calls)
		}
	}
	if got := f.snapshot(t); got["mark1d"] != "new mark1d" || got["mark1"] != "old mark1" {
		t.Fatalf("install dir %v", got)
	}
}

func TestLiveSessionRefusesTheSwap(t *testing.T) {
	f := newFixture(t, true)
	r := newRelease(t, "0.2.0", map[string]string{"mark1d": "new"})
	sess := filepath.Join(f.env.StateDir, "run", "sessions", "ab12.json")
	if err := cli.WriteFileAtomic(sess, []byte(`{"session_id_hex":"00","started_at":"now"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	err := Run(context.Background(), f.env, f.opts(r, false))
	if code := exitCode(t, err); code != cli.ExitRefused || !strings.Contains(err.Error(), "1 agent session(s) live") {
		t.Fatalf("got %v", err)
	}
	if r.hit("/edge.tar.gz") != 0 {
		t.Fatal("downloaded the release before refusing on a live session")
	}
	// A stale session file with the daemon down is not a live session (cortex.New clears the dir at boot).
	f.pid = "0"
	stubVerify(t, nil)
	if err := Run(context.Background(), f.env, f.opts(r, false)); err != nil {
		t.Fatalf("stale session file blocked an update with the daemon down: %v", err)
	}
}

func TestRunningUnregisteredDaemonIsRefused(t *testing.T) {
	f := newFixture(t, false)
	if err := os.Remove(filepath.Join(f.home, ".config", "systemd", "user", "mark1d.service")); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("", "m1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	r := newRelease(t, "0.2.0", map[string]string{"mark1d": "new"})
	opts := f.opts(r, false)
	opts.Socket = sock
	err = Run(context.Background(), f.env, opts)
	if code := exitCode(t, err); code != cli.ExitRefused || !strings.Contains(err.Error(), "not registered") {
		t.Fatalf("got %v", err)
	}
}

func TestPackageManagerOwnedInstallIsRefused(t *testing.T) {
	f := newFixture(t, false)
	r := newRelease(t, "0.2.0", map[string]string{"mark1d": "new"})
	opts := f.opts(r, false)
	opts.InstallDir = "/usr/bin"
	if runtime.GOOS == "windows" {
		opts.InstallDir = `C:\Program Files\Omium`
	}
	err := Run(context.Background(), f.env, opts)
	if code := exitCode(t, err); code != cli.ExitRefused || !strings.Contains(err.Error(), "package manager") || len(f.calls) != 0 {
		t.Fatalf("got %v (service calls %q)", err, f.calls)
	}
}

func TestDigestMismatchAndForeignMembersAreRefused(t *testing.T) {
	f := newFixture(t, false)
	r := newRelease(t, "0.2.0", map[string]string{"mark1d": "new", "evil": "payload"})
	stubVerify(t, nil)
	before := f.snapshot(t)
	err := Run(context.Background(), f.env, f.opts(r, false))
	if code := exitCode(t, err); code != cli.ExitVerify || !strings.Contains(err.Error(), `unexpected member "./evil"`) {
		t.Fatalf("foreign member: got %v", err)
	}
	r.manifest.Artifacts["0.2.0"][platform()] = Artifact{URL: r.srv.URL + "/edge.tar.gz", SHA256: strings.Repeat("0", 64)}
	err = Run(context.Background(), f.env, f.opts(r, false))
	if code := exitCode(t, err); code != cli.ExitRuntime || !strings.Contains(err.Error(), "does not match the manifest") {
		t.Fatalf("digest: got %v", err)
	}
	if got := f.snapshot(t); !reflect.DeepEqual(got, before) {
		t.Fatalf("install dir changed: %v", got)
	}
}

func TestSwapRollsBackWhenAStagedBinaryIsMissing(t *testing.T) {
	dir, stage := t.TempDir(), t.TempDir()
	for _, b := range []string{"mark1d", "mark1"} {
		if err := os.WriteFile(filepath.Join(dir, b), []byte("old "+b), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(stage, "mark1d"), []byte("new mark1d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := swap(dir, stage, []string{"mark1d", "mark1"}); err == nil {
		t.Fatal("swap succeeded with a staged binary missing")
	}
	for _, b := range []string{"mark1d", "mark1"} {
		if got, _ := os.ReadFile(filepath.Join(dir, b)); string(got) != "old "+b {
			t.Fatalf("%s after rollback: %q", b, got)
		}
		if _, err := os.Stat(filepath.Join(dir, b+".old")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s.old left behind after rollback", b)
		}
	}
}
