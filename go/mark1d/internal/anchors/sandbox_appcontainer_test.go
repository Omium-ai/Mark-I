//go:build windows

package anchors

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/fabric"
)

// The windows twins of sandbox_posix_test.go: job-object probes and the two denials the AppContainer adds (named pipe, read outside the grants). Named to sort before sandbox_probe_test.go, whose last test counts these runs.

func init() {
	// capped probe: exit 0 iff this process sits in a job whose user-time and commit limits are set — i.e. Run defaulted the caller-unset caps rather than leaving the job unbounded. A NULL handle names the caller's immediate job.
	extraProbes["capped"] = func() int {
		var x windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
		if err := windows.QueryInformationJobObject(0, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&x)), uint32(unsafe.Sizeof(x)), nil); err != nil {
			return 1
		}
		want := uint32(windows.JOB_OBJECT_LIMIT_JOB_TIME | windows.JOB_OBJECT_LIMIT_JOB_MEMORY | windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
		if x.BasicLimitInformation.LimitFlags&want != want || x.BasicLimitInformation.PerJobUserTimeLimit <= 0 || x.JobMemoryLimit == 0 {
			return 1
		}
		return 0
	}
	// CPU burn for the job-time kill test; the job terminates the tree at the cap, so it never exits on its own.
	extraProbes["spin"] = func() int {
		for {
			_ = time.Now()
		}
	}
	// pipe probe: exit 0 iff the named pipe opened — mark1d's fabric endpoint reachability, asked directly.
	extraProbes["pipe"] = func() int {
		timeout := 2 * time.Second
		c, err := winio.DialPipe(os.Getenv("MARK1_ANCHOR_TEST_ADDR"), &timeout)
		if err != nil {
			return 1
		}
		_ = c.Close()
		return 0
	}
}

// TestSandboxDeniesNamedPipe is the AF_UNIX twin: the fabric pipe's DACL is owner-SID-only (fabric/listener_windows.go) and an AppContainer needs a package ACE on top of the user's, so the anchor cannot open mark1d's own endpoint — no ledger injection from a sandboxed tool.
func TestSandboxDeniesNamedPipe(t *testing.T) {
	base, err := fabric.SocketPath()
	if err != nil {
		t.Fatal(err)
	}
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	path := base + "-anchor-test-" + hex.EncodeToString(b[:])
	ln, err := fabric.Listen(path)
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
	// Control: reachable from outside the sandbox, so a denial is the sandbox.
	timeout := 2 * time.Second
	c, err := winio.DialPipe(path, &timeout)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()

	sb := NewSandbox(t.TempDir())
	spec := probeSpec(t, t.TempDir(), "pipe", map[string]string{"MARK1_ANCHOR_TEST_ADDR": path})
	res, err := runProbeSpec(t, sb, spec)
	if err != nil {
		t.Fatalf("run: %v (stderr: %s)", err, res.Stderr)
	}
	if res.ExitCode == 0 {
		t.Fatal("anchor opened the fabric pipe from inside the AppContainer — the pipe DACL admits packages")
	}
}

// TestSandboxDeniesReadOutsideGrants is where windows is STRONGER than the one-way valve doc.go states for linux/darwin: the ACL allow-list confines reads too, so the exfil probe (read a same-uid file outside the grants, copy it into the worktree) fails and nothing lands.
func TestSandboxDeniesReadOutsideGrants(t *testing.T) {
	sb := NewSandbox(t.TempDir())
	worktree := t.TempDir()
	secret := filepath.Join(t.TempDir(), "redact.key")
	if err := os.WriteFile(secret, []byte("PRIVATE-KEY-MATERIAL"), 0o600); err != nil {
		t.Fatal(err)
	}
	stolen := filepath.Join(worktree, "vendored.txt")
	spec := probeSpec(t, worktree, "exfil", map[string]string{
		"MARK1_ANCHOR_TEST_SRC":  secret,
		"MARK1_ANCHOR_TEST_PATH": stolen,
	})
	res, err := runProbeSpec(t, sb, spec)
	if err != nil {
		t.Fatalf("run: %v (stderr: %s)", err, res.Stderr)
	}
	if _, statErr := os.Stat(stolen); res.ExitCode == 0 || statErr == nil {
		t.Fatalf("a same-uid file outside the grants was read from inside the AppContainer (exit=%d) — read confinement is broken", res.ExitCode)
	}
}

// TestGrantAddsOnePackageACE pins "once per root, never per run": a fresh dir gets exactly one inheritable package ACE, a second grant is a no-op, and a child created afterwards carries it by inheritance.
func TestGrantAddsOnePackageACE(t *testing.T) {
	sb := NewSandbox(t.TempDir())
	if sb.reason != "" {
		kernelLacks(t, sb.reason)
	}
	dir := t.TempDir()
	count := func() uint16 {
		sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		dacl, _, err := sd.DACL()
		if err != nil {
			t.Fatal(err)
		}
		return dacl.AceCount
	}
	before := count()
	if err := sb.grant(dir, readExecMask); err != nil {
		t.Fatal(err)
	}
	if got := count(); got != before+1 {
		t.Fatalf("ACE count %d → %d, want +1", before, got)
	}
	if err := sb.grant(dir, readExecMask); err != nil {
		t.Fatal(err)
	}
	if got := count(); got != before+1 {
		t.Fatalf("second grant changed the DACL: %d ACEs, want %d", got, before+1)
	}
	child := filepath.Join(dir, "child")
	if err := os.Mkdir(child, 0o700); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(child, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || !hasPackageACE(dacl, sb.sid, readExecMask) {
		t.Fatalf("child did not inherit the package ACE (err=%v)", err)
	}
}

// TestRevokeRemovesThePackageACEFromTheTree: the edge/v0.1.7 repair — a grant on an app-install root is taken back from the root and from everything that inherited it, and a root without our ACE is left as it was.
func TestRevokeRemovesThePackageACEFromTheTree(t *testing.T) {
	sb := NewSandbox(t.TempDir())
	if sb.reason != "" {
		kernelLacks(t, sb.reason)
	}
	dir := t.TempDir()
	child := filepath.Join(dir, "app")
	if err := os.Mkdir(child, 0o700); err != nil {
		t.Fatal(err)
	}
	has := func(p string) bool {
		sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		dacl, _, err := sd.DACL()
		if err != nil {
			t.Fatal(err)
		}
		return hasPackageACE(dacl, sb.sid, readExecMask)
	}
	if err := sb.grant(dir, readExecMask); err != nil {
		t.Fatal(err)
	}
	if !has(dir) || !has(child) {
		t.Fatal("grant did not reach the tree")
	}
	if err := sb.revoke(dir); err != nil {
		t.Fatal(err)
	}
	if has(dir) || has(child) {
		t.Fatal("revoke left the package ACE on the root or its child")
	}
	if err := sb.revoke(dir); err != nil {
		t.Fatalf("revoke on a clean dir: %v", err)
	}
	for _, r := range toolchainRoots() {
		if strings.Contains(strings.ToLower(r), `\programs`) || strings.Contains(strings.ToLower(r), `windowsapps`) {
			t.Fatalf("toolchainRoots grants an app-install root again: %s", r)
		}
	}
}

// TestWindowsSandboxRefusesWhenUnavailable: a refused profile is a named refusal, never a degraded run.
func TestWindowsSandboxRefusesWhenUnavailable(t *testing.T) {
	sb := NewSandbox(t.TempDir())
	if st := sb.Status(); st.Available != (sb.reason == "") || sb.FSConfined() != st.Available {
		t.Fatalf("reason %q but FSConfined=%v Status=%+v", sb.reason, sb.FSConfined(), st)
	}
	sb.reason = "forced"
	if st := sb.Status(); sb.FSConfined() || st.Available || st.Reason != "forced" {
		t.Fatalf("refusing sandbox reports %+v", st)
	}
	if _, err := sb.Run(context.Background(), probeSpec(t, t.TempDir(), "env", nil)); !errors.Is(err, ErrSandboxUnavailable) {
		t.Fatalf("run without a profile: %v, want ErrSandboxUnavailable", err)
	}
}

func TestWindowsExitMapping(t *testing.T) {
	for code, want := range map[uint32]struct {
		code int
		sig  string
	}{
		0: {0, ""}, 1: {1, ""}, 2: {2, ""},
		killExit:   {-1, "killed"},
		cpuCapExit: {-1, "CPU time limit exceeded"},
		0xC0000005: {-1, "exception 0xC0000005"},
	} {
		if c, s := windowsExit(code); c != want.code || s != want.sig {
			t.Errorf("windowsExit(%#x) = (%d, %q), want (%d, %q)", code, c, s, want.code, want.sig)
		}
	}
}

func TestToolRoot(t *testing.T) {
	for exe, want := range map[string]string{
		`C:\Go\bin\go.exe`:                         `C:\Go`,
		`C:\w\.venv\Scripts\pytest.exe`:            `C:\w\.venv`,
		`C:\Users\u\AppData\Roaming\npm\tsc.cmd`:   `C:\Users\u\AppData\Roaming\npm`,
		`C:\Users\u\AppData\Local\Temp\x\ruff.cmd`: `C:\Users\u\AppData\Local\Temp\x`,
	} {
		if got := toolRoot(exe); got != want {
			t.Errorf("toolRoot(%s) = %s, want %s", exe, got, want)
		}
	}
}

// TestWindowsEnv: the profile-shaped vars point at the per-run scratch, the pass-throughs come from the daemon, a caller's own key wins, and the result stays sorted (it is EffectiveEnv).
func TestWindowsEnv(t *testing.T) {
	t.Setenv("SystemRoot", `C:\Windows`)
	t.Setenv("PATHEXT", ".EXE;.CMD")
	got := windowsEnv([]string{"PATH=x", "TEMP=keep"}, `C:\s`)
	want := []string{"APPDATA=C:\\s", "COMSPEC=" + os.Getenv("COMSPEC"), "LOCALAPPDATA=C:\\s", "PATH=x", "PATHEXT=.EXE;.CMD", "SystemRoot=C:\\Windows", "TEMP=keep", "TMP=C:\\s", "USERPROFILE=C:\\s"}
	if os.Getenv("COMSPEC") == "" {
		want = append(want[:1], want[2:]...)
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("windowsEnv:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
