//go:build linux || darwin

package anchors

import (
	"context"
	"errors"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// kernelLacks is the ONE skip site for a kernel that cannot host the sandbox.
// Absent feature ⇒ skip, unless M1_REQUIRE_SANDBOX=1 ⇒ fail — the same
// inversion M1_REQUIRE_STORES applies to a missing DSN, for the same reason:
// the sandbox is the security boundary (04 §2.2), and a probe that skips
// reports the boundary green without ever pushing on it. ci.yml sets it on the
// ubuntu leg, after lifting AppArmor's userns restriction: the stock
// ubuntu-24.04 image keeps kernel.apparmor_restrict_unprivileged_userns=1, so
// clone(CLONE_NEWUSER) was EPERM for the test binary and every probe in this
// file skipped while the job read green (FR-VERIFY-002).
func kernelLacks(t *testing.T, feature string) {
	t.Helper()
	if os.Getenv("M1_REQUIRE_SANDBOX") == "1" {
		t.Fatalf("kernel lacks %s (M1_REQUIRE_SANDBOX=1): this leg must exercise the sandbox, not skip it", feature)
	}
	t.Skipf("kernel lacks %s", feature)
}

// probeRuns counts sandbox runs the kernel actually admitted (the child was
// spawned inside the namespaces); TestSandboxProbesNotVacuous reads it.
var probeRuns atomic.Int32

func init() {
	// rlimit probe: exit 0 iff RLIMIT_FSIZE is finite — i.e. a caller-unset
	// limit was defaulted by Run rather than skipped by the helper (uncapped).
	extraProbes["fsize"] = func() int {
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

// These tests EXECUTE the real sandbox — the test binary itself is the anchor,
// steered by probeEnv (main_test.go). A probe exits 0 iff its operation
// SUCCEEDED, so a denial test asserts a nonzero exit.

// probeSpec builds a RunSpec around the test binary. Limits are generous
// except what the individual test tightens: 0 now defaults from DefaultLimits
// in Run, so MemoryBytes is set explicitly huge — no probe but memhog is about
// the memory cap, and none should ever trip over it.
func probeSpec(t *testing.T, worktree, mode string, extraEnv map[string]string) RunSpec {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]string{probeEnv: mode, "PATH": "/usr/bin:/bin"}
	for k, v := range extraEnv {
		env[k] = v
	}
	return RunSpec{
		Argv:       []string{self},
		WorktreeRO: worktree,
		Env:        env,
		Limits:     Limits{Wall: 20 * time.Second, MemoryBytes: 1 << 40, NoFile: 256, OutputCap: 4 << 20},
	}
}

// runProbeSpec runs the spec. A platform that refuses the floor (a kernel
// without unprivileged user namespaces, a macOS without sandbox-exec) refuses
// the run — the contract itself — but that leaves nothing to assert about the
// inner denials, so it is a skip or (M1_REQUIRE_SANDBOX=1) a failure via kernelLacks.
func runProbeSpec(t *testing.T, sb Sandbox, spec RunSpec) (RunResult, error) {
	t.Helper()
	res, err := sb.Run(context.Background(), spec)
	if errors.Is(err, ErrSandboxUnavailable) && !spec.RequireFSConfined {
		kernelLacks(t, "the sandbox floor: "+err.Error())
	}
	probeRuns.Add(1)
	return res, err
}

func TestSandboxDeniesNetwork(t *testing.T) {
	// A live listener the probe could reach if the netns were shared.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
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
	// Control: the dial target is genuinely reachable from OUTSIDE the sandbox,
	// so a failing probe fails because of the sandbox, not a dead listener.
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()

	sb := NewSandbox(t.TempDir())
	spec := probeSpec(t, t.TempDir(), "dial", map[string]string{"MARK1_ANCHOR_TEST_ADDR": ln.Addr().String()})
	res, err := runProbeSpec(t, sb, spec)
	if err != nil {
		t.Fatalf("run: %v (stderr: %s)", err, res.Stderr)
	}
	if res.ExitCode == 0 {
		t.Fatal("anchor reached the network from inside the sandbox — network denial is broken")
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

func TestSandboxWriteConfinement(t *testing.T) {
	sb := NewSandbox(t.TempDir())
	worktree := t.TempDir()
	outside := t.TempDir()

	if !sb.FSConfined() {
		// Honest asymmetry (doc.go): without Landlock (linux) or sandbox-exec
		// (darwin), write confinement is NOT enforced and FSConfined says so;
		// test-class anchors then refuse (asserted below) instead of running unsandboxed.
		spec := probeSpec(t, worktree, "write", map[string]string{"MARK1_ANCHOR_TEST_PATH": outside + "/escape"})
		spec.RequireFSConfined = true
		if _, err := sb.Run(context.Background(), spec); !errors.Is(err, ErrSandboxUnavailable) {
			t.Fatalf("RequireFSConfined without write confinement must refuse, got %v", err)
		}
		kernelLacks(t, "write confinement; its denial is not testable here")
	}

	t.Run("write outside worktree denied", func(t *testing.T) {
		target := outside + "/escape"
		spec := probeSpec(t, worktree, "write", map[string]string{"MARK1_ANCHOR_TEST_PATH": target})
		res, err := runProbeSpec(t, sb, spec)
		if err != nil {
			t.Fatalf("run: %v (stderr: %s)", err, res.Stderr)
		}
		if res.ExitCode == 0 {
			t.Fatal("anchor wrote outside the worktree under write confinement")
		}
		if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("escape file exists — confinement is a lie")
		}
	})
	t.Run("write inside worktree allowed", func(t *testing.T) {
		// The positive control: confinement must not be "everything fails".
		target := worktree + "/inside"
		spec := probeSpec(t, worktree, "write", map[string]string{"MARK1_ANCHOR_TEST_PATH": target})
		res, err := runProbeSpec(t, sb, spec)
		if err != nil {
			t.Fatalf("run: %v (stderr: %s)", err, res.Stderr)
		}
		if res.ExitCode != 0 {
			t.Fatalf("worktree write denied (exit %d) — anchors need their own worktree", res.ExitCode)
		}
	})
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

func TestSandboxKillsCPUHog(t *testing.T) {
	sb := NewSandbox(t.TempDir())
	spec := probeSpec(t, t.TempDir(), "spin", nil)
	spec.Limits.CPUSeconds = 1
	start := time.Now()
	res, err := runProbeSpec(t, sb, spec)
	if err != nil {
		t.Fatalf("run: %v (stderr: %s)", err, res.Stderr)
	}
	if res.ExitCode == 0 || res.TimedOut {
		t.Fatalf("CPU hog was not stopped by the cap: %+v", res)
	}
	// Linux SIGKILLs at a soft=hard cap; darwin delivers SIGXCPU once and the probe exits on it.
	if runtime.GOOS == "linux" && (res.Signal == "" || res.ExitCode != -1) {
		t.Fatalf("CPU hog was not signal-killed: exit=%d signal=%q", res.ExitCode, res.Signal)
	}
	if el := time.Since(start); el > 15*time.Second {
		t.Fatalf("RLIMIT_CPU did not fire near the 1s cap (took %v — wall timer did the work instead)", el)
	}
}

// TestSandboxKillsMemoryHog is the control that the memory cap still bites
// after it moved off RLIMIT_AS: RLIMIT_DATA bounds committed private anonymous
// memory, so a child that touches 2 GiB under a 256 MiB cap must not get it.
// The kernel can be told to only warn (vm ignore_rlimit_data), which would make
// the cap decorative — this is what notices. On darwin the cap is mark1d's RSS watchdog (sandbox_darwin.go), and this is the only proof it fires.
func TestSandboxKillsMemoryHog(t *testing.T) {
	sb := NewSandbox(t.TempDir())
	spec := probeSpec(t, t.TempDir(), "memhog", nil)
	spec.Limits.MemoryBytes = 256 << 20
	res, err := runProbeSpec(t, sb, spec)
	if err != nil {
		t.Fatalf("run: %v (stderr: %s)", err, res.Stderr)
	}
	if res.ExitCode == 0 {
		t.Fatal("anchor committed 2 GiB under a 256 MiB cap — the memory limit is not enforced")
	}
}

func TestSandboxWallClockKill(t *testing.T) {
	sb := NewSandbox(t.TempDir())
	spec := probeSpec(t, t.TempDir(), "sleep", nil)
	spec.Limits.Wall = 500 * time.Millisecond
	res, err := runProbeSpec(t, sb, spec)
	if err != nil {
		t.Fatalf("run: %v (stderr: %s)", err, res.Stderr)
	}
	if !res.TimedOut {
		t.Fatalf("sleeper outlived the wall clock: %+v", res)
	}
}

func TestSandboxKillSwitch(t *testing.T) {
	sb := NewSandbox(t.TempDir())
	spec := probeSpec(t, t.TempDir(), "sleep", nil)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(300 * time.Millisecond)
		cancel() // `mark1 off` semantics: cancel ⇒ SIGKILL the group, immediately
	}()
	start := time.Now()
	res, err := sb.Run(ctx, spec) // not runProbeSpec: the cancelable ctx IS the subject
	if errors.Is(err, ErrSandboxUnavailable) {
		kernelLacks(t, "the sandbox floor: "+err.Error())
	}
	probeRuns.Add(1)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !res.TimedOut || time.Since(start) > 5*time.Second {
		t.Fatalf("context cancel did not kill the anchor promptly: %+v after %v", res, time.Since(start))
	}
}

func TestSandboxOutputCap(t *testing.T) {
	sb := NewSandbox(t.TempDir())
	spec := probeSpec(t, t.TempDir(), "flood", nil)
	spec.Limits.OutputCap = 64 << 10
	res, err := runProbeSpec(t, sb, spec)
	if !errors.Is(err, ErrOutputCap) {
		t.Fatalf("flood err = %v, want ErrOutputCap", err)
	}
	if !res.Truncated {
		t.Fatal("Truncated not set")
	}
	if int64(len(res.Stdout)+len(res.Stderr)) > 64<<10 {
		t.Fatalf("captured %d bytes, over the cap", len(res.Stdout)+len(res.Stderr))
	}
}

// TestSandboxDefaultsUnsetRlimits pins the doc.go claim that CPU/AS/NOFILE/
// FSIZE are ENFORCED per run: the helper treats 0 as "skip", so Run must
// default an unset field — a caller that forgets a limit must never get an
// uncapped run. The probe asserts RLIMIT_FSIZE (left zero here) came out
// finite inside the sandbox.
func TestSandboxDefaultsUnsetRlimits(t *testing.T) {
	sb := NewSandbox(t.TempDir())
	spec := probeSpec(t, t.TempDir(), "fsize", nil)
	spec.Limits.FSizeBytes = 0 // the field under test stays caller-unset
	res, err := runProbeSpec(t, sb, spec)
	if err != nil {
		t.Fatalf("run: %v (stderr: %s)", err, res.Stderr)
	}
	if res.ExitCode != 0 {
		t.Fatal("RLIMIT_FSIZE was infinite inside the sandbox — an unset limit ran uncapped, contradicting doc.go's ENFORCED claim")
	}
}

// TestGroupKillNeverSignalsAfterReap pins the watchdog/reap race: a watcher
// that committed to killing (past its select) can lose the CPU while Wait
// reaps the pid, after which -pgid may name a group the kernel recycled to an
// unrelated process. A committed kill must become a no-op once reaped, and a
// post-reap timeout kill must not flip TimedOut for a run that exited fine.
func TestGroupKillNeverSignalsAfterReap(t *testing.T) {
	fired := 0
	g := &groupKill{sig: func() { fired++ }}
	g.kill(false) // pre-reap cap breach: signals
	if fired != 1 {
		t.Fatalf("pre-reap kill fired %d times, want 1", fired)
	}
	if g.markReaped() {
		t.Fatal("TimedOut reported for a run never timeout-killed")
	}
	g.kill(true) // watcher committed before the reap, ran after it
	if fired != 1 {
		t.Fatal("SIGKILL sent after the reap — lands on a possibly recycled pgid")
	}
	if g.timedOut {
		t.Fatal("post-reap watcher flipped TimedOut on a run that exited on its own")
	}

	g2 := &groupKill{sig: func() {}}
	g2.kill(true)
	if !g2.markReaped() {
		t.Fatal("pre-reap timeout kill not reported as TimedOut")
	}
}

// TestOutputBudgetBreachBeforeArm pins the Start→onExceed window: the copy
// goroutines exist from cmd.Start(), so a write can breach the cap before the
// pgid (and thus the kill func) exists. The latch flips over exactly once, so
// if that first breach finds kill==nil the kill must still fire when armed —
// otherwise no later write can ever fire it and the run outlives its cap.
func TestOutputBudgetBreachBeforeArm(t *testing.T) {
	b := &outputBudget{remaining: 1}
	if got := b.take(8); got != 1 {
		t.Fatalf("take = %d, want the 1 remaining byte", got)
	}
	if !b.exceeded() {
		t.Fatal("budget not marked exceeded after breach")
	}
	killed := false
	b.onExceed(func() { killed = true })
	if !killed {
		t.Fatal("cap breached before the kill was armed and onExceed did not fire it — the run would burn to the wall clock")
	}
}

func TestSandboxEnvScrub(t *testing.T) {
	t.Setenv("AWS_SECRET_ACCESS_KEY", "leaky-canary") // must NOT reach the child
	sb := NewSandbox(t.TempDir())
	spec := probeSpec(t, t.TempDir(), "env", map[string]string{"LANG": "C"})
	res, err := runProbeSpec(t, sb, spec)
	if err != nil {
		t.Fatalf("run: %v (stderr: %s)", err, res.Stderr)
	}
	got := string(res.Stdout)
	if strings.Contains(got, "leaky-canary") || strings.Contains(got, "AWS_SECRET_ACCESS_KEY") {
		t.Fatal("daemon env leaked into the anchor — scrub is broken")
	}
	if strings.Contains(got, helperSpecEnv) {
		t.Fatal("helper spec env leaked into the anchor")
	}
	// __CF_USER_TEXT_ENCODING is the darwin sandbox's own (sandbox_darwin.go cfEncodingEnv); it never appears on linux.
	allowed := map[string]bool{probeEnv: true, "PATH": true, "LANG": true, "TZ": true, "HOME": true, "__CF_USER_TEXT_ENCODING": true}
	seen := map[string]bool{}
	for _, line := range strings.Split(got, "\n") {
		if line == "" {
			continue
		}
		seen[line] = true
		k, _, _ := strings.Cut(line, "=")
		if !allowed[k] {
			t.Errorf("unexpected env var %q in the sandbox", k)
		}
	}
	if !strings.Contains(got, "HOME=") {
		t.Error("sandbox did not provide the scratch HOME")
	}
	// EffectiveEnv (the attestation input) is EXACTLY what the child saw, both ways: an attested var the child lacked and a child var never attested both break the attestation.
	for _, kv := range res.EffectiveEnv {
		if !seen[kv] {
			t.Errorf("attested env %q not present in the child's environment", kv)
		}
		delete(seen, kv)
	}
	for kv := range seen {
		t.Errorf("child env %q was never attested in EffectiveEnv", kv)
	}
}

// TestSandboxProbesNotVacuous is FR-VERIFY-002's guard against what this file
// did on CI for months: every probe above routes through runProbeSpec, and a
// kernel refusing userns skipped them all — a dozen green tests, zero denials
// asserted. Under M1_REQUIRE_SANDBOX=1 it asserts the sandbox really admitted
// at least one run per probe, so a refactor that hands the probes a new skip
// path cannot re-open the hole silently. Source order is run order (this
// package never shuffles), so it stays the LAST test in this file.
func TestSandboxProbesNotVacuous(t *testing.T) {
	if os.Getenv("M1_REQUIRE_SANDBOX") != "1" {
		t.Skip("M1_REQUIRE_SANDBOX unset; the probes above may legitimately skip here")
	}
	want := int32(12) // one per runProbeSpec/KillSwitch run above; +1 for the linux/amd64-only x32 probe (sandbox_linux_test.go)
	if runtime.GOOS == "linux" && runtime.GOARCH == "amd64" {
		want++
	}
	if got := probeRuns.Load(); got < want {
		t.Fatalf("only %d sandbox probes executed, want ≥ %d — a probe above is skipping under M1_REQUIRE_SANDBOX=1 (or this ran under -run/-shuffle without them)", got, want)
	}
}
