//go:build linux

package anchors

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func init() {
	// x32 socket(2) probe: nr 0x40000029 arrives with arch AUDIT_ARCH_X86_64 —
	// the renumbered-ABI path around a nr==SYS_SOCKET match (denyUnixSockets
	// x32SyscallBit). Exit 0 iff the kernel handed back a live socket, i.e.
	// the filter was bypassed; EACCES (filtered) and ENOSYS (kernel built
	// without CONFIG_X86_X32_ABI) both read as denied.
	extraProbes["x32socket"] = func() int {
		if runtime.GOARCH != "amd64" {
			return 1
		}
		fd, _, errno := unix.Syscall(0x40000029, unix.AF_UNIX, unix.SOCK_STREAM, 0)
		if errno != 0 {
			return 1
		}
		_ = unix.Close(int(fd))
		return 0
	}
}

// TestSandboxDeniesX32Socket pins the renumbered-ABI hole: an x32 syscall
// carries arch == AUDIT_ARCH_X86_64 with nr|0x40000000, so a filter matching
// only nr == SYS_SOCKET would allow x32 socket(AF_UNIX) on any
// CONFIG_X86_X32_ABI=y kernel. Vacuously green on kernels without x32 (the
// probe reads ENOSYS as denied) — the assertion bites where the hole exists.
func TestSandboxDeniesX32Socket(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("x32 ABI is an amd64 concern")
	}
	sb := NewSandbox(t.TempDir())
	spec := probeSpec(t, t.TempDir(), "x32socket", nil)
	res, err := runProbeSpec(t, sb, spec)
	if err != nil {
		t.Fatalf("run: %v (stderr: %s)", err, res.Stderr)
	}
	if res.ExitCode == 0 {
		t.Fatal("x32 socket(AF_UNIX) succeeded inside the sandbox — the seccomp filter was bypassed via the renumbered ABI")
	}
}

// TestHelperRefusesUnconfinedInvocation pins the exec-gadget hole: the helper
// reads argv/dir/env from one env var, so anyone who can set it on a mark1d
// launch (wrapper script, systemd EnvironmentFile, an env-forwarding
// supervisor) invokes the helper OUTSIDE Run's namespaces — and the spec's
// author controls its contents, so only a positive check of the confinement
// properties can refuse. A direct invocation from the host must die with
// helperSetupExit, not exec the payload with the network attached.
func TestHelperRefusesUnconfinedInvocation(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	spec, err := json.Marshal(helperSpec{
		Argv: []string{self},
		Dir:  t.TempDir(),
		Env:  []string{probeEnv + "=env"}, // payload exits 0 if the exec happens
	})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(self)
	cmd.Env = []string{helperSpecEnv + "=" + string(spec)}
	out, runErr := cmd.CombinedOutput()
	var ee *exec.ExitError
	if !errors.As(runErr, &ee) || ee.ExitCode() != helperSetupExit {
		t.Fatalf("direct helper invocation did not refuse (err=%v out=%q) — the helper is an unconfined exec gadget", runErr, out)
	}
	if !strings.Contains(string(out), helperStderrPrefix+"confinement check") {
		t.Fatalf("helper refused for the wrong reason: %q", out)
	}
}

// TestTaskDiffWithoutLandlockStaysInTheSandbox (FR-VERIFY-021): a kernel without Landlock still hosts hardened git in the user+net namespaces; before, RequireFSConfined refused it and every task diff came back empty.
func TestTaskDiffWithoutLandlockStaysInTheSandbox(t *testing.T) {
	repo := fixtureRepo(t)
	write(t, filepath.Join(repo, "new.py"), "x = 1\n")
	sb := NewSandbox(t.TempDir())
	sb.landlockMask = 0
	r := NewRunner(sb, &fakeEmitter{}, nil, false)
	r.StateDir = t.TempDir()
	if got := r.TaskDiff(context.Background(), repo); !bytes.Contains(got, []byte("diff --git a/new.py b/new.py")) {
		t.Fatalf("no task diff without Landlock: %q", got)
	}
	if st := diffStatus(t, r.StateDir, repo); st.Via != "sandbox" {
		kernelLacks(t, "unprivileged user namespaces for git ("+st.Detail+")")
	}
}

// TestNewFileSectionNeverBlocksOnAFIFO (review M9): a FIFO where an untracked file was never hangs the read and renders nothing; a file past the cap reads as git's binary section, never whole.
func TestNewFileSectionNeverBlocksOnAFIFO(t *testing.T) {
	dir := canonTemp(t)
	if err := unix.Mkfifo(filepath.Join(dir, "pipe"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "big"), bytes.Repeat([]byte("a\n"), maxNewFileBytes), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	done := make(chan []byte, 1)
	go func() { done <- newFileSection(root, "pipe", "pipe") }()
	select {
	case got := <-done:
		if got != nil {
			t.Fatalf("a FIFO rendered %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the read blocked on a FIFO")
	}
	if _, err := readRegular(root, "pipe"); err == nil {
		t.Fatal("readRegular accepted a FIFO")
	}
	if got := string(newFileSection(root, "big", "big")); !strings.Contains(got, "Binary files /dev/null and b/big differ") {
		t.Fatalf("an oversize file: %.200s", got)
	}
}
