// Package service registers mark1d as a login item of the CURRENT USER (04 §11.4): a launchd LaunchAgent, a systemd user unit (an autostart .desktop entry where systemd --user is absent), or a Task Scheduler logon task. Never a Windows Service: session 0 runs as a service account and cannot read the user's agent config files, which are the daemon's whole read surface (08 §8).
// Nothing secret is captured into an artifact — D-CU(1): the daemon's env under a login item is not the developer's shell, and the key must not be copied into a plist or unit to bridge that.
package service

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Omium-ai/omium-mark1/go/mark1/internal/cli"
)

const Label = "ai.omium.mark1d"

type Options struct {
	Daemon string // mark1d path; default beside this executable, then PATH
	Socket string // test seam for the running probe
}

type Status struct {
	OK         bool   `json:"ok"`
	Supervisor string `json:"supervisor"` // launchd|systemd|autostart|schtasks
	Artifact   string `json:"artifact"`
	Registered bool   `json:"registered"`
	Running    bool   `json:"running"`
	PID        int    `json:"pid,omitempty"`
}

type Result struct {
	OK         bool   `json:"ok"`
	Action     string `json:"action"`
	Supervisor string `json:"supervisor"`
	Artifact   string `json:"artifact"`
	Changed    bool   `json:"changed"`
	Restarted  bool   `json:"restarted,omitempty"`
}

// Exec is the one exec seam: argv in, stdout out. Tests script it; nothing here shells out any other way.
var Exec = func(name string, args ...string) (string, error) {
	var out, errb bytes.Buffer
	cmd := exec.Command(name, args...) //nolint:gosec // G204: fixed supervisor binaries, argv as a slice, no shell
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

var Platform = runtime.GOOS // the supervisor kind is a build fact; tests in other packages pin it

type target struct {
	kind, path, daemon, stateDir string
}

// Render is the login-item artifact for kind, byte-exact (goldens under testdata).
func Render(kind, daemon, stateDir, username string) []byte {
	switch kind {
	case "launchd":
		log := path.Join(stateDir, "logs", "mark1d.log") // a launchd artifact is POSIX whatever host renders it
		return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + Label + `</string>
	<key>ProgramArguments</key>
	<array>
		<string>` + xmlEscape(daemon) + `</string>
		<string>--state-dir</string>
		<string>` + xmlEscape(stateDir) + `</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<dict>
		<key>SuccessfulExit</key>
		<false/>
	</dict>
	<key>StandardOutPath</key>
	<string>` + xmlEscape(log) + `</string>
	<key>StandardErrorPath</key>
	<string>` + xmlEscape(log) + `</string>
</dict>
</plist>
`)
	case "systemd":
		return []byte(`[Unit]
Description=Omium Mark 1 daemon (mark1d)
After=default.target

[Service]
ExecStart=` + shQuote(daemon) + ` --state-dir ` + shQuote(stateDir) + `
Restart=on-failure
RestartSec=2

[Install]
WantedBy=default.target
`)
	case "autostart":
		return []byte(`[Desktop Entry]
Type=Application
Name=Omium Mark 1 daemon
Exec=` + shQuote(daemon) + ` --state-dir ` + shQuote(stateDir) + `
NoDisplay=true
X-GNOME-Autostart-enabled=true
`)
	case "schtasks":
		return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Omium Mark 1 daemon (mark1d). A logon task, not a service: it must run in the user's session to read the user's agent config files.</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>` + xmlEscape(username) + `</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>` + xmlEscape(username) + `</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>3</Count>
    </RestartOnFailure>
    <Hidden>true</Hidden>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>` + xmlEscape(daemon) + `</Command>
      <Arguments>--state-dir ` + xmlEscape(shQuote(stateDir)) + `</Arguments>
    </Exec>
  </Actions>
</Task>
`)
	}
	return nil
}

var xmlEscape = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace

// shQuote: systemd, .desktop and schtasks all take a double-quoted word with backslash-escaped quotes.
func shQuote(s string) string { return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"` }

// resolve picks the supervisor for this OS and where its artifact lives. On Linux an existing artifact wins; a fresh install probes systemd --user and falls back to autostart.
func resolve(env *cli.Env, opts Options, probe bool) (*target, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	t := &target{stateDir: env.StateDir}
	switch Platform {
	case "darwin":
		t.kind, t.path = "launchd", filepath.Join(home, "Library", "LaunchAgents", Label+".plist")
	case "windows":
		t.kind, t.path = "schtasks", filepath.Join(env.StateDir, "service", "mark1d.task.xml")
	default:
		unit := filepath.Join(home, ".config", "systemd", "user", "mark1d.service")
		desktop := filepath.Join(home, ".config", "autostart", Label+".desktop")
		switch {
		case exists(unit):
			t.kind, t.path = "systemd", unit
		case exists(desktop):
			t.kind, t.path = "autostart", desktop
		default:
			t.kind, t.path = "systemd", unit
			if probe && run("systemctl", "--user", "daemon-reload") != nil {
				t.kind, t.path = "autostart", desktop
			}
		}
	}
	if probe {
		if t.daemon, err = daemonPath(opts.Daemon); err != nil {
			return nil, err
		}
	}
	return t, nil
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func daemonPath(explicit string) (string, error) {
	if explicit != "" {
		return filepath.Abs(explicit)
	}
	name := "mark1d"
	if Platform == "windows" {
		name += ".exe"
	}
	if exe, err := os.Executable(); err == nil {
		if p := filepath.Join(filepath.Dir(exe), name); exists(p) {
			return p, nil
		}
	}
	if p, err := exec.LookPath(name); err == nil {
		return filepath.Abs(p)
	}
	return "", fmt.Errorf("mark1d not found beside %s or on PATH (pass --daemon)", os.Args[0])
}

func username() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return os.Getenv("USERNAME")
}

func domain() string { return fmt.Sprintf("gui/%d", os.Getuid()) }
func uid() string    { return strconv.Itoa(os.Getuid()) }

func Install(env *cli.Env, opts Options) error {
	t, err := resolve(env, opts, true)
	if err != nil {
		return cli.Failf(cli.ExitRuntime, "", "%v", err)
	}
	want := Render(t.kind, t.daemon, t.stateDir, username())
	have, _ := os.ReadFile(t.path)
	changed := !bytes.Equal(have, want)
	st := status(env, t, opts.Socket)
	if changed {
		if err := cli.WriteFileAtomic(t.path, want, 0o644); err != nil {
			return cli.Failf(cli.ExitRuntime, "", "writing %s: %v", t.path, err)
		}
	}
	if t.kind == "launchd" {
		if err := os.MkdirAll(filepath.Join(t.stateDir, "logs"), 0o700); err != nil { // launchd opens StandardOutPath but never creates its directory
			return cli.Failf(cli.ExitRuntime, "", "log dir: %v", err)
		}
	}
	res := Result{OK: true, Action: "install", Supervisor: t.kind, Artifact: t.path, Changed: changed}
	restart := changed && st.Running
	switch t.kind {
	case "launchd":
		isLoaded := loaded()
		if changed && isLoaded {
			err, isLoaded = run("launchctl", "bootout", domain()+"/"+Label), false
		}
		if err == nil && !isLoaded {
			err = run("launchctl", "bootstrap", domain(), t.path)
		}
	case "systemd":
		if err = run("systemctl", "--user", "daemon-reload"); err == nil {
			err = run("systemctl", "--user", "enable", "--now", "mark1d.service")
		}
		if err == nil && restart {
			err = run("systemctl", "--user", "restart", "mark1d.service")
		}
	case "autostart":
		if restart {
			err = run("pkill", "-x", "-u", uid(), "mark1d")
		}
		if err == nil && (restart || !st.Running) {
			err = run("setsid", "-f", t.daemon, "--state-dir", t.stateDir)
		}
	case "schtasks":
		if err = run("schtasks", "/Create", "/F", "/TN", Label, "/XML", t.path); err == nil && restart {
			err = run("schtasks", "/End", "/TN", Label)
		}
		if err == nil && (restart || !st.Running) {
			err = run("schtasks", "/Run", "/TN", Label)
		}
	}
	if err != nil {
		return cli.Failf(cli.ExitRuntime, "", "%v", err)
	}
	res.Restarted = restart
	return env.Emit(res, func(w io.Writer) {
		_, _ = fmt.Fprintf(w, "mark1d registered with %s (%s); changed: %v, restarted: %v\n", t.kind, t.path, changed, restart)
	})
}

// Uninstall stops the daemon and removes exactly what Install wrote; nothing else under the user's home is touched.
func Uninstall(env *cli.Env, opts Options) error {
	t, err := resolve(env, opts, false)
	if err != nil {
		return cli.Failf(cli.ExitRuntime, "", "%v", err)
	}
	st := status(env, t, opts.Socket)
	switch t.kind {
	case "launchd":
		if loaded() {
			err = run("launchctl", "bootout", domain()+"/"+Label)
		}
	case "systemd":
		if st.Registered {
			err = run("systemctl", "--user", "disable", "--now", "mark1d.service")
		}
	case "autostart":
		if st.Running {
			err = run("pkill", "-x", "-u", uid(), "mark1d")
		}
	case "schtasks":
		if st.Registered {
			_, _ = Exec("schtasks", "/End", "/TN", Label)
			err = run("schtasks", "/Delete", "/F", "/TN", Label)
		}
	}
	if err != nil {
		return cli.Failf(cli.ExitRuntime, "", "%v", err)
	}
	if err := os.Remove(t.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return cli.Failf(cli.ExitRuntime, "", "removing %s: %v", t.path, err)
	}
	if t.kind == "systemd" && st.Registered {
		_, _ = Exec("systemctl", "--user", "daemon-reload")
	}
	res := Result{OK: true, Action: "uninstall", Supervisor: t.kind, Artifact: t.path, Changed: st.Registered}
	return env.Emit(res, func(w io.Writer) {
		_, _ = fmt.Fprintf(w, "mark1d unregistered from %s (%s removed: %v)\n", t.kind, t.path, st.Registered)
	})
}

func Start(env *cli.Env, opts Options) error { return control(env, opts, "start") }
func Stop(env *cli.Env, opts Options) error  { return control(env, opts, "stop") }

func control(env *cli.Env, opts Options, action string) error {
	t, err := resolve(env, opts, false)
	if err != nil {
		return cli.Failf(cli.ExitRuntime, "", "%v", err)
	}
	st := status(env, t, opts.Socket)
	if !st.Registered {
		return cli.Failf(cli.ExitRefused, "", "mark1d is not registered — run `mark1 service install`")
	}
	if err := ctl(t, action); err != nil {
		return cli.Failf(cli.ExitRuntime, "", "%v", err)
	}
	res := Result{OK: true, Action: action, Supervisor: t.kind, Artifact: t.path, Changed: true}
	return env.Emit(res, func(w io.Writer) { _, _ = fmt.Fprintf(w, "mark1d %s via %s\n", action, t.kind) })
}

func ctl(t *target, action string) error {
	switch t.kind + " " + action {
	case "launchd start":
		if loaded() {
			return run("launchctl", "kickstart", domain()+"/"+Label)
		}
		return run("launchctl", "bootstrap", domain(), t.path)
	case "launchd stop":
		if loaded() {
			return run("launchctl", "kill", "SIGTERM", domain()+"/"+Label)
		}
	case "systemd start", "systemd stop":
		return run("systemctl", "--user", action, "mark1d.service")
	case "autostart start":
		// ponytail: setsid -f (util-linux) detaches without a build-tagged SysProcAttr; a pidfile would let stop signal exactly this process.
		daemon, stateDir := desktopExec(t.path)
		return run("setsid", "-f", daemon, "--state-dir", stateDir)
	case "autostart stop":
		return run("pkill", "-x", "-u", uid(), "mark1d")
	case "schtasks start":
		return run("schtasks", "/Run", "/TN", Label)
	case "schtasks stop":
		return run("schtasks", "/End", "/TN", Label)
	}
	return nil
}

var desktopExecRe = regexp.MustCompile(`(?m)^Exec="((?:[^"\\]|\\.)*)" --state-dir "((?:[^"\\]|\\.)*)"$`)

// desktopExec reads the daemon and state dir back out of the .desktop entry so start needs no daemon lookup.
func desktopExec(path string) (daemon, stateDir string) {
	b, _ := os.ReadFile(path)
	m := desktopExecRe.FindSubmatch(b)
	if m == nil {
		return "mark1d", ""
	}
	unq := func(s []byte) string { return strings.ReplaceAll(string(s), `\"`, `"`) }
	return unq(m[1]), unq(m[2])
}

// Query is `mark1 service status`: registered/running/pid, exit 0 even when nothing is registered.
func Query(env *cli.Env, opts Options) error {
	t, err := resolve(env, opts, false)
	if err != nil {
		return cli.Failf(cli.ExitRuntime, "", "%v", err)
	}
	st := status(env, t, opts.Socket)
	return env.Emit(st, func(w io.Writer) {
		_, _ = fmt.Fprintf(w, "supervisor    %s (%s)\nregistered    %v\nrunning       %v (pid %d)\n", st.Supervisor, st.Artifact, st.Registered, st.Running, st.PID)
	})
}

// Live answers "is mark1d up?" for callers that must not swap binaries under it (selfupdate).
func Live(env *cli.Env, socket string) (Status, error) {
	t, err := resolve(env, Options{}, false)
	if err != nil {
		return Status{}, err
	}
	return status(env, t, socket), nil
}

var pidRe = regexp.MustCompile(`(?m)^\s*pid = (\d+)`)

func status(env *cli.Env, t *target, socket string) Status {
	st := Status{OK: true, Supervisor: t.kind, Artifact: t.path, Registered: exists(t.path)}
	switch t.kind {
	case "launchd":
		if out, err := Exec("launchctl", "print", domain()+"/"+Label); err == nil {
			if m := pidRe.FindStringSubmatch(out); m != nil {
				st.PID, _ = strconv.Atoi(m[1])
			}
		}
	case "systemd":
		out, _ := Exec("systemctl", "--user", "show", "-p", "MainPID", "--value", "mark1d.service")
		st.PID, _ = strconv.Atoi(strings.TrimSpace(out))
	case "autostart":
		out, _ := Exec("pgrep", "-x", "-u", uid(), "mark1d")
		st.PID, _ = strconv.Atoi(strings.TrimSpace(strings.SplitN(out, "\n", 2)[0]))
	case "schtasks":
		if _, err := Exec("schtasks", "/Query", "/TN", Label); err != nil {
			st.Registered = false
		}
		out, _ := Exec("tasklist", "/FI", "IMAGENAME eq mark1d.exe", "/FO", "CSV", "/NH")
		if rows, err := csv.NewReader(strings.NewReader(out)).ReadAll(); err == nil && len(rows) > 0 && len(rows[0]) > 1 {
			st.PID, _ = strconv.Atoi(rows[0][1])
		}
	}
	if socket == "" {
		socket, _ = cli.SocketPath()
	}
	st.Running = st.PID > 0 || (socket != "" && cli.DaemonReachable(socket))
	return st
}

func loaded() bool { _, err := Exec("launchctl", "print", domain()+"/"+Label); return err == nil }

func run(name string, args ...string) error { _, err := Exec(name, args...); return err }

// WaitStopped polls until the daemon is gone or the deadline passes.
func WaitStopped(env *cli.Env, socket string, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for {
		st, err := Live(env, socket)
		if err != nil {
			return false
		}
		if !st.Running {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(200 * time.Millisecond)
	}
}
