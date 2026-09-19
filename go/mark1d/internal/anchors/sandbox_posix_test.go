//go:build linux || darwin

package anchors

import (
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The probes and tests here are the rlimit/pgid/AF_UNIX half of the contract; sandbox_appcontainer_test.go holds the windows twins. Both sort before sandbox_probe_test.go, whose last test counts them.

func init() {
	// capped probe: exit 0 iff RLIMIT_FSIZE is finite — i.e. a caller-unset
	// limit was defaulted by Run rather than skipped by the helper (uncapped).
	extraProbes["capped"] = func() int {
		var r unix.Rlimit
		if err := unix.Getrlimit(unix.RLIMIT_FSIZE, &r); err != nil {
			return 1
		}
		if r.Cur == unix.RLIM_INFINITY {
			return 1
		}
		return 0
	}
	// CPU burn for the RLIMIT_CPU kill test; never exits on its own. Linux SIGKILLs at a soft=hard cap before any SIGXCPU lands; darwin delivers one SIGXCPU and nothing after, so exit on it the way a default-disposition tool would.
	extraProbes["spin"] = func() int {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGXCPU)
		go func() { <-ch; os.Exit(3) }()
		for {
			_ = time.Now()
		}
	}
}

// TestSandboxDeniesUnixSockets is the other half of "network denied": the
// netns removes every interface but leaves AF_UNIX, and Landlock ABI ≤ 3 does
// not govern connect(2). Without the seccomp filter an anchor reaches any
// same-uid pathname socket — mark1d's own m1p.sock among them, which would be
// unauthenticated ledger injection.
func TestSandboxDeniesUnixSockets(t *testing.T) {
	// OUTSIDE the worktree, and under /tmp rather than t.TempDir(): darwin's /var/folders/… test dirs push sun_path past its 104-byte limit.
	sockDir, err := os.MkdirTemp("/tmp", "m1sock")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	sock := filepath.Join(sockDir, "host.sock")
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
	// Control: reachable from outside the sandbox, so a denial is the sandbox.
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()

	sb := NewSandbox(t.TempDir())
	spec := probeSpec(t, t.TempDir(), "uds", map[string]string{"MARK1_ANCHOR_TEST_ADDR": sock})
	res, err := runProbeSpec(t, sb, spec)
	if err != nil {
		t.Fatalf("run: %v (stderr: %s)", err, res.Stderr)
	}
	if res.ExitCode == 0 {
		t.Fatal("anchor reached a host unix socket from inside the sandbox — AF_UNIX denial is broken")
	}
}

// TestSandboxIsAOneWayValve is a characterization test, not an aspiration: it
// asserts the sandbox behaves EXACTLY as doc.go's "NOT ENFORCED, BY
// CONSTRUCTION" paragraph says — unconfined reads plus a writable worktree let
// consented anchor code copy a same-uid secret into the repo. If this ever
// starts failing, the code gained read confinement and that paragraph is now
// an UNDERclaim; either way doc.go must be edited in the same commit. The
// property is load-bearing for the consent prompt's meaning (11 §5).
func TestSandboxIsAOneWayValve(t *testing.T) {
	sb := NewSandbox(t.TempDir())
	if !sb.FSConfined() {
		kernelLacks(t, "Landlock; the claim under test is about the STRONGEST regime")
	}
	worktree := t.TempDir()
	secret := filepath.Join(t.TempDir(), "redact.key") // stands in for <state>/redact.key
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
	got, readErr := os.ReadFile(stolen)
	if res.ExitCode != 0 || readErr != nil || string(got) != "PRIVATE-KEY-MATERIAL" {
		t.Fatalf("exfiltration into the worktree did not happen (exit=%d err=%v) — "+
			"the sandbox now confines reads; update doc.go's 'NOT ENFORCED, BY CONSTRUCTION' paragraph", res.ExitCode, readErr)
	}
}
