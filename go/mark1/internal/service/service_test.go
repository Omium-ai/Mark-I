package service

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/Omium-ai/omium-mark1/go/mark1/internal/cli"
)

const (
	daemon   = "/opt/mark1/mark1d"
	stateDir = "/home/dev/.omium/mark1"
)

func TestRenderMatchesGolden(t *testing.T) {
	for kind, in := range map[string][2]string{
		"launchd":   {daemon, stateDir},
		"systemd":   {daemon, stateDir},
		"autostart": {daemon, stateDir},
		"schtasks":  {`C:\Program Files\Omium\mark1d.exe`, `C:\Users\dev\.omium\mark1`},
	} {
		want, err := os.ReadFile(filepath.Join("testdata", kind+".golden"))
		if err != nil {
			t.Fatal(err)
		}
		if got := Render(kind, in[0], in[1], `DESKTOP\dev`); !bytes.Equal(got, want) {
			t.Errorf("%s drifted from testdata/%s.golden:\n%s", kind, kind, got)
		}
	}
	if Render("nonesuch", daemon, stateDir, "") != nil {
		t.Fatal("unknown kind rendered something")
	}
}

func TestArtifactsEscapeAndCaptureNoSecret(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-secret-0123")
	for _, kind := range []string{"launchd", "systemd", "autostart", "schtasks"} {
		out := string(Render(kind, `/tmp/a"b<c>&d/mark1d`, stateDir, "u"))
		if strings.Contains(out, "sk-ant-secret-0123") {
			t.Fatalf("%s artifact carries the API key", kind)
		}
		switch kind {
		case "launchd", "schtasks":
			if strings.Contains(out, "<c>") || !strings.Contains(out, "&lt;c&gt;&amp;d") {
				t.Fatalf("%s did not XML-escape the path:\n%s", kind, out)
			}
		default:
			if !strings.Contains(out, `"/tmp/a\"b<c>&d/mark1d" --state-dir "`+stateDir+`"`) {
				t.Fatalf("%s did not quote the path:\n%s", kind, out)
			}
		}
	}
}

type fakeExec struct {
	calls   []string
	respond func(argv string) (string, error)
}

func stub(t *testing.T, respond func(argv string) (string, error)) *fakeExec {
	t.Helper()
	f := &fakeExec{respond: respond}
	prev := Exec
	Exec = func(name string, args ...string) (string, error) {
		argv := strings.Join(append([]string{name}, args...), " ")
		f.calls = append(f.calls, argv)
		return f.respond(argv)
	}
	t.Cleanup(func() { Exec = prev })
	return f
}

func (f *fakeExec) reset() { f.calls = nil }

func (f *fakeExec) want(t *testing.T, argv ...string) {
	t.Helper()
	if strings.Join(f.calls, "\n") != strings.Join(argv, "\n") {
		t.Fatalf("argv\n got: %q\nwant: %q", f.calls, argv)
	}
}

func testEnv(t *testing.T) (*cli.Env, *bytes.Buffer) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_RUNTIME_DIR", "")
	out := &bytes.Buffer{}
	return &cli.Env{StateDir: filepath.Join(home, ".omium", "mark1"), JSON: true, Stdout: out, Stderr: os.Stderr}, out
}

func snapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	files := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		files[p] = string(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func decode[T any](t *testing.T, out *bytes.Buffer) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("stdout is not one JSON object: %v: %q", err, out.String())
	}
	out.Reset()
	return v
}

func exitCode(t *testing.T, err error) int {
	t.Helper()
	var ee *cli.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("not an ExitError: %v", err)
	}
	return ee.Code
}

func TestLinuxInstallStatusUninstallRoundTrip(t *testing.T) {
	goos = "linux"
	env, out := testEnv(t)
	home := os.Getenv("HOME")
	pid := "0"
	f := stub(t, func(argv string) (string, error) {
		if strings.HasPrefix(argv, "systemctl --user show") {
			return pid + "\n", nil
		}
		if strings.HasPrefix(argv, "systemctl --user enable --now") {
			pid = "4242"
		}
		if strings.HasPrefix(argv, "systemctl --user disable --now") {
			pid = "0"
		}
		return "", nil
	})
	before := snapshot(t, home)
	opts := Options{Daemon: daemon, Socket: filepath.Join(home, "none.sock")}

	if err := Install(env, opts); err != nil {
		t.Fatal(err)
	}
	unit := filepath.Join(home, ".config", "systemd", "user", "mark1d.service")
	f.want(t,
		"systemctl --user daemon-reload",
		"systemctl --user show -p MainPID --value mark1d.service",
		"systemctl --user daemon-reload",
		"systemctl --user enable --now mark1d.service")
	got, err := os.ReadFile(unit)
	if err != nil || !bytes.Equal(got, Render("systemd", daemon, env.StateDir, "")) {
		t.Fatalf("unit file: %v\n%s", err, got)
	}
	res := decode[Result](t, out)
	if !res.OK || !res.Changed || res.Restarted || res.Supervisor != "systemd" || res.Artifact != unit {
		t.Fatalf("install result %+v", res)
	}

	f.reset()
	if err := Install(env, opts); err != nil {
		t.Fatal(err)
	}
	if res = decode[Result](t, out); res.Changed || res.Restarted {
		t.Fatalf("second install is not idempotent: %+v", res)
	}
	for _, c := range f.calls {
		if strings.Contains(c, "restart") {
			t.Fatalf("unchanged re-install restarted the daemon: %q", f.calls)
		}
	}

	f.reset()
	if err := Query(env, opts); err != nil {
		t.Fatal(err)
	}
	st := decode[Status](t, out)
	if !st.Registered || !st.Running || st.PID != 4242 || st.Supervisor != "systemd" {
		t.Fatalf("status %+v", st)
	}

	f.reset()
	if err := Uninstall(env, opts); err != nil {
		t.Fatal(err)
	}
	f.want(t,
		"systemctl --user show -p MainPID --value mark1d.service",
		"systemctl --user disable --now mark1d.service",
		"systemctl --user daemon-reload")
	if res = decode[Result](t, out); !res.Changed {
		t.Fatalf("uninstall result %+v", res)
	}
	if after := snapshot(t, home); !reflect.DeepEqual(after, before) {
		t.Fatalf("uninstall is not byte-exact: before %v after %v", before, after)
	}
	if err := Query(env, opts); err != nil {
		t.Fatal(err)
	}
	if st = decode[Status](t, out); st.Registered || st.Running {
		t.Fatalf("status after uninstall %+v", st)
	}
	if err := Uninstall(env, opts); err != nil {
		t.Fatalf("second uninstall must be a no-op, got %v", err)
	}
}

func TestLinuxChangedArtifactRestartsARunningDaemon(t *testing.T) {
	goos = "linux"
	env, out := testEnv(t)
	f := stub(t, func(argv string) (string, error) {
		if strings.HasPrefix(argv, "systemctl --user show") {
			return "77\n", nil
		}
		return "", nil
	})
	unit := filepath.Join(os.Getenv("HOME"), ".config", "systemd", "user", "mark1d.service")
	if err := os.MkdirAll(filepath.Dir(unit), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unit, Render("systemd", "/old/mark1d", env.StateDir, ""), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Install(env, Options{Daemon: daemon, Socket: "/nonexistent.sock"}); err != nil {
		t.Fatal(err)
	}
	f.want(t,
		"systemctl --user show -p MainPID --value mark1d.service",
		"systemctl --user daemon-reload",
		"systemctl --user enable --now mark1d.service",
		"systemctl --user restart mark1d.service")
	if res := decode[Result](t, out); !res.Changed || !res.Restarted {
		t.Fatalf("result %+v", res)
	}
}

func TestLinuxFallsBackToAutostartWithoutSystemdUser(t *testing.T) {
	goos = "linux"
	env, out := testEnv(t)
	home := os.Getenv("HOME")
	f := stub(t, func(argv string) (string, error) {
		switch {
		case strings.HasPrefix(argv, "systemctl"):
			return "", errors.New("Failed to connect to bus: No medium found")
		case strings.HasPrefix(argv, "pgrep"):
			return "", errors.New("exit status 1")
		}
		return "", nil
	})
	opts := Options{Daemon: daemon, Socket: "/nonexistent.sock"}
	if err := Install(env, opts); err != nil {
		t.Fatal(err)
	}
	desktop := filepath.Join(home, ".config", "autostart", Label+".desktop")
	me := uid()
	f.want(t,
		"systemctl --user daemon-reload",
		"pgrep -x -u "+me+" mark1d",
		"setsid -f "+daemon+" --state-dir "+env.StateDir)
	got, err := os.ReadFile(desktop)
	if err != nil || !bytes.Equal(got, Render("autostart", daemon, env.StateDir, "")) {
		t.Fatalf("desktop entry: %v\n%s", err, got)
	}
	if res := decode[Result](t, out); res.Supervisor != "autostart" || res.Artifact != desktop {
		t.Fatalf("result %+v", res)
	}

	f.reset()
	if err := Stop(env, opts); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := Start(env, opts); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	f.want(t,
		"pgrep -x -u "+me+" mark1d",
		"pkill -x -u "+me+" mark1d",
		"pgrep -x -u "+me+" mark1d",
		"setsid -f "+daemon+" --state-dir "+env.StateDir)

	f.reset()
	if err := Uninstall(env, opts); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(desktop); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("desktop entry survived uninstall: %v", err)
	}
	f.want(t, "pgrep -x -u "+me+" mark1d")
}

func TestDarwinLaunchdArgv(t *testing.T) {
	goos = "darwin"
	env, out := testEnv(t)
	home := os.Getenv("HOME")
	loadedNow := false
	f := stub(t, func(argv string) (string, error) {
		switch {
		case strings.HasPrefix(argv, "launchctl print"):
			if !loadedNow {
				return "", errors.New("Could not find service")
			}
			return "ai.omium.mark1d = {\n\tactive count = 1\n\tpid = 515\n\tstate = running\n}\n", nil
		case strings.HasPrefix(argv, "launchctl bootstrap"):
			loadedNow = true
		case strings.HasPrefix(argv, "launchctl bootout"):
			loadedNow = false
		}
		return "", nil
	})
	plist := filepath.Join(home, "Library", "LaunchAgents", Label+".plist")
	dom := domain()
	opts := Options{Daemon: daemon, Socket: "/nonexistent.sock"}

	if err := Install(env, opts); err != nil {
		t.Fatal(err)
	}
	f.want(t, "launchctl print "+dom+"/"+Label, "launchctl print "+dom+"/"+Label, "launchctl bootstrap "+dom+" "+plist)
	if got, err := os.ReadFile(plist); err != nil || !bytes.Equal(got, Render("launchd", daemon, env.StateDir, "")) {
		t.Fatalf("plist: %v\n%s", err, got)
	}
	if fi, err := os.Stat(filepath.Join(env.StateDir, "logs")); err != nil || !fi.IsDir() {
		t.Fatalf("launchd log dir not created: %v", err)
	}
	out.Reset()

	f.reset()
	if err := Install(env, Options{Daemon: "/new/mark1d", Socket: "/nonexistent.sock"}); err != nil {
		t.Fatal(err)
	}
	f.want(t, "launchctl print "+dom+"/"+Label, "launchctl print "+dom+"/"+Label,
		"launchctl bootout "+dom+"/"+Label, "launchctl bootstrap "+dom+" "+plist)
	if res := decode[Result](t, out); !res.Changed || !res.Restarted {
		t.Fatalf("result %+v", res)
	}

	f.reset()
	if err := Query(env, opts); err != nil {
		t.Fatal(err)
	}
	if st := decode[Status](t, out); !st.Registered || !st.Running || st.PID != 515 {
		t.Fatalf("status %+v", st)
	}

	f.reset()
	if err := Stop(env, opts); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := Start(env, opts); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	f.want(t,
		"launchctl print "+dom+"/"+Label, "launchctl print "+dom+"/"+Label, "launchctl kill SIGTERM "+dom+"/"+Label,
		"launchctl print "+dom+"/"+Label, "launchctl print "+dom+"/"+Label, "launchctl kickstart "+dom+"/"+Label)

	f.reset()
	if err := Uninstall(env, opts); err != nil {
		t.Fatal(err)
	}
	f.want(t, "launchctl print "+dom+"/"+Label, "launchctl print "+dom+"/"+Label, "launchctl bootout "+dom+"/"+Label)
	if _, err := os.Stat(plist); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("plist survived uninstall: %v", err)
	}
}

func TestWindowsSchtasksArgv(t *testing.T) {
	goos = "windows"
	env, out := testEnv(t)
	registered := false
	f := stub(t, func(argv string) (string, error) {
		switch {
		case strings.HasPrefix(argv, "schtasks /Query"):
			if !registered {
				return "", errors.New("ERROR: The system cannot find the file specified.")
			}
		case strings.HasPrefix(argv, "schtasks /Create"):
			registered = true
		case strings.HasPrefix(argv, "schtasks /Delete"):
			registered = false
		case strings.HasPrefix(argv, "tasklist"):
			if registered {
				return "\"mark1d.exe\",\"9001\",\"Console\",\"1\",\"12,345 K\"\r\n", nil
			}
			return "INFO: No tasks are running which match the specified criteria.\r\n", nil
		}
		return "", nil
	})
	xml := filepath.Join(env.StateDir, "service", "mark1d.task.xml")
	opts := Options{Daemon: `C:\Omium\mark1d.exe`, Socket: "/nonexistent.sock"}
	if err := Install(env, opts); err != nil {
		t.Fatal(err)
	}
	f.want(t,
		"schtasks /Query /TN "+Label,
		"tasklist /FI IMAGENAME eq mark1d.exe /FO CSV /NH",
		"schtasks /Create /F /TN "+Label+" /XML "+xml,
		"schtasks /Run /TN "+Label)
	got, err := os.ReadFile(xml)
	if err != nil || !bytes.Contains(got, []byte("<LogonType>InteractiveToken</LogonType>")) || bytes.Contains(got, []byte("<UserId></UserId>")) {
		t.Fatalf("task xml: %v\n%s", err, got)
	}
	out.Reset()

	f.reset()
	if err := Query(env, opts); err != nil {
		t.Fatal(err)
	}
	if st := decode[Status](t, out); !st.Registered || !st.Running || st.PID != 9001 {
		t.Fatalf("status %+v", st)
	}

	f.reset()
	if err := Uninstall(env, opts); err != nil {
		t.Fatal(err)
	}
	f.want(t,
		"schtasks /Query /TN "+Label,
		"tasklist /FI IMAGENAME eq mark1d.exe /FO CSV /NH",
		"schtasks /End /TN "+Label,
		"schtasks /Delete /F /TN "+Label)
	if _, err := os.Stat(xml); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("task xml survived uninstall: %v", err)
	}
}

func TestStartStopRefuseWhenNotRegistered(t *testing.T) {
	goos = "linux"
	env, _ := testEnv(t)
	stub(t, func(string) (string, error) { return "0\n", nil })
	for _, fn := range []func(*cli.Env, Options) error{Start, Stop} {
		if code := exitCode(t, fn(env, Options{Socket: "/nonexistent.sock"})); code != cli.ExitRefused {
			t.Fatalf("exit %d, want %d", code, cli.ExitRefused)
		}
	}
}

func TestInstallFailsWithoutADaemonBinary(t *testing.T) {
	goos = "linux"
	env, _ := testEnv(t)
	t.Setenv("PATH", t.TempDir())
	stub(t, func(string) (string, error) { return "", nil })
	err := Install(env, Options{})
	if code := exitCode(t, err); code != cli.ExitRuntime || !strings.Contains(err.Error(), "--daemon") {
		t.Fatalf("got %v", err)
	}
}

func TestWaitStoppedPollsTheSupervisor(t *testing.T) {
	goos = "linux"
	env, _ := testEnv(t)
	unit := filepath.Join(os.Getenv("HOME"), ".config", "systemd", "user", "mark1d.service")
	if err := os.MkdirAll(filepath.Dir(unit), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unit, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	polls := 0
	stub(t, func(string) (string, error) {
		polls++
		if polls < 3 {
			return strconv.Itoa(100+polls) + "\n", nil
		}
		return "0\n", nil
	})
	if !WaitStopped(env, "/nonexistent.sock", 5e9) || polls != 3 {
		t.Fatalf("stopped after %d polls", polls)
	}
	stub(t, func(string) (string, error) { return "77\n", nil })
	if WaitStopped(env, "/nonexistent.sock", 0) {
		t.Fatal("a daemon that never exits reported stopped")
	}
}
