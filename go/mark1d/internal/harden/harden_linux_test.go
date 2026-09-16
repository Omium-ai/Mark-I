package harden

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// TestApplyClearsDumpable is the PR_SET_DUMPABLE half of TestApplyReadsBack,
// read back through prctl(PR_GET_DUMPABLE) rather than through Apply's own
// return.
func TestApplyClearsDumpable(t *testing.T) {
	if err := Apply(); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	got, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got != 0 {
		t.Errorf("PR_GET_DUMPABLE = %d, want 0", got)
	}
}

// crashChildEnv turns a re-run of this test binary into the crashing child.
const crashChildEnv = "MARK1_HARDEN_CRASH_CHILD"

// TestInducedCrashWritesNoCore is 12 §9 row 2's literal clause. The child is
// this test binary re-run on TestInducedCrashChild alone in a fresh cwd: it
// applies hardening, reads RLIMIT_CORE back and writes it to a marker file,
// then dies of SIGABRT. GOTRACEBACK=crash is what makes the death real — the
// Go runtime otherwise catches SIGABRT, prints stacks and exit(2)s, and the
// kernel never gets to decide about a core. The marker keeps this non-vacuous
// on a runner whose `ulimit -c` is already 0 or whose core_pattern is a pipe:
// "no core file" is asserted alongside "the child itself saw {0,0}", and the
// exit must be the SIGABRT it died of, not a clean exit that never crashed.
// Linux only (file suffix): macOS writes cores to /cores, Windows has none.
func TestInducedCrashWritesNoCore(t *testing.T) {
	dir := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestInducedCrashChild$") //nolint:gosec // G204: exe is os.Executable(); this is the re-exec crash child
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), crashChildEnv+"=1", "GOTRACEBACK=crash")
	err = cmd.Run()
	ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !ok || !ws.Signaled() || ws.Signal() != syscall.SIGABRT {
		t.Fatalf("child must die of SIGABRT; run err=%v state=%v", err, cmd.ProcessState)
	}
	marker, err := os.ReadFile(filepath.Join(dir, "rlimit_core"))
	if err != nil {
		t.Fatalf("child writes its RLIMIT_CORE read-back before aborting: %v", err)
	}
	if got := string(marker); got != "0 0" {
		t.Fatalf("RLIMIT_CORE {soft hard} as the child read it back = %q, want \"0 0\"", got)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "core") {
			t.Errorf("induced crash wrote a core: %s", e.Name())
		}
	}
}

// TestInducedCrashChild is the child half of the test above; a no-op unless
// spawned by it.
func TestInducedCrashChild(t *testing.T) {
	if os.Getenv(crashChildEnv) == "" {
		return
	}
	if err := Apply(); err != nil {
		t.Fatal(err)
	}
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &lim); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("rlimit_core", fmt.Appendf(nil, "%d %d", lim.Cur, lim.Max), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = syscall.Kill(os.Getpid(), syscall.SIGABRT)
	select {} // never returns: the runtime is dying of the signal above
}
