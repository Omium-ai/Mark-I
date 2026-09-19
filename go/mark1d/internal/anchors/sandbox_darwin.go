//go:build darwin

package anchors

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// sandboxExec is Apple's Seatbelt front end: deprecated in the man page for a decade, present on 14 and 15, and shipped by Bazel, Chrome and Codex. Its absence refuses every run (CON-009), never degrades.
const sandboxExec = "/usr/bin/sandbox-exec"

// sandboxExecWarning is the stderr line sandbox-exec prints on every invocation from macOS 15; it is the sandbox's, not the anchor's, so Run strips it.
const sandboxExecWarning = "sandbox-exec is deprecated"

// cfEncodingEnv is set by CoreFoundation (setenv in __CFStringGetUserDefaultEncoding) inside any CF-linked process that finds it absent — sandbox-exec included, whose execvp would then hand the anchor a var mark1d never attested. Pre-setting CF's own default keeps EffectiveEnv exact.
const cfEncodingEnv = "__CF_USER_TEXT_ENCODING"

// memPoll is the RSS watchdog cadence; a hog can overshoot the cap by what it commits in one tick.
const memPoll = 250 * time.Millisecond

// DarwinSandbox implements Sandbox with sandbox-exec (network denied, writes confined to worktree + scratch), rlimits in the re-exec'd helper, and a mark1d RSS watchdog for the memory cap. See doc.go.
type DarwinSandbox struct {
	scratchRoot string
	reason      string // non-empty ⇒ every run is refused with it
}

// NewSandbox checks for sandbox-exec once; scratchRoot is where per-run scratch HOMEs live, "" uses the OS temp dir.
func NewSandbox(scratchRoot string) *DarwinSandbox {
	if scratchRoot == "" {
		scratchRoot = os.TempDir()
	}
	s := &DarwinSandbox{scratchRoot: scratchRoot}
	if st, err := os.Stat(sandboxExec); err != nil || !st.Mode().IsRegular() {
		s.reason = sandboxExec + " missing: no Seatbelt front end on this macOS (04 §11.5)"
	}
	return s
}

// FSConfined is true whenever runs are admitted at all: the profile's file-write* deny is part of every run, not an optional regime as Landlock is on Linux.
func (s *DarwinSandbox) FSConfined() bool { return s.reason == "" }

func (s *DarwinSandbox) Status() SandboxStatus {
	return SandboxStatus{Available: s.reason == "", Reason: s.reason}
}

// Run executes spec per the doc.go contract: helper re-exec for rlimits, then sandbox-exec -f <per-run 0600 profile> execs the anchor in place (one pid, same pgid).
func (s *DarwinSandbox) Run(ctx context.Context, spec RunSpec) (RunResult, error) {
	if s.reason != "" {
		return RunResult{}, fmt.Errorf("%w: %s", ErrSandboxUnavailable, s.reason)
	}
	scratch, env, lim, err := prepare(s.scratchRoot, spec)
	if err != nil {
		return RunResult{}, err
	}
	defer func() { _ = os.RemoveAll(scratch) }()
	env = withDefault(env, cfEncodingEnv, fmt.Sprintf("0x%X:0:0", os.Getuid()))
	// Seatbelt matches resolved paths: /tmp and /var live under /private.
	writable := writableRoots(spec, scratch)
	for i, w := range writable {
		if writable[i], err = filepath.EvalSymlinks(w); err != nil {
			return RunResult{}, err
		}
	}
	profile := filepath.Join(scratch, "profile.sb")
	if err := os.WriteFile(profile, []byte(seatbelt(writable)), 0o600); err != nil {
		return RunResult{}, err
	}
	hs := helperSpec{
		Argv:       spec.Argv,
		Dir:        spec.WorktreeRO,
		Env:        env,
		CPUSeconds: lim.CPUSeconds,
		NoFile:     lim.NoFile,
		FSizeBytes: lim.FSizeBytes,
		Profile:    profile,
	}
	watch := func(done <-chan struct{}, pgid int, kill func()) { memWatchdog(done, pgid, lim.MemoryBytes, kill) }
	res, err := runHelper(ctx, hs, lim, &syscall.SysProcAttr{Setpgid: true}, (*exec.Cmd).Start, watch)
	res.Stderr = stripSandboxExecWarning(res.Stderr)
	return res, err
}

var sbQuote = strings.NewReplacer(`\`, `\\`, `"`, `\"`)

// seatbelt is the per-run profile: allow-default (deny-default needs a per-toolchain mach/sysctl/Rosetta allow-list, and reads are unconfined on Linux too), network* denied (TCP/UDP and unix-domain — the netns+seccomp twin), writes denied everywhere but the worktree, scratch and /dev/null.
func seatbelt(writable []string) string {
	q := func(p string) string { return `"` + sbQuote.Replace(p) + `"` }
	allow := ""
	for _, w := range writable {
		allow += " (subpath " + q(w) + ")"
	}
	return "(version 1)\n(allow default)\n(deny network*)\n(deny file-write*)\n" +
		"(allow file-write*" + allow + " (literal \"/dev/null\"))\n"
}

// stripSandboxExecWarning drops the deprecation line so the anchor's captured stderr is the anchor's alone.
func stripSandboxExecWarning(stderr []byte) []byte {
	first, rest, cut := strings.Cut(string(stderr), "\n")
	if !strings.Contains(first, sandboxExecWarning) {
		return stderr
	}
	if !cut {
		return nil
	}
	return []byte(rest)
}

// memWatchdog is the darwin memory cap: the kernel accepts RLIMIT_DATA/AS and enforces neither (and arm64 returns EINVAL past ~418 GB), so mark1d sums the group's resident set every memPoll and kills it past the cap.
// ponytail: /bin/ps per tick; kinfo_proc via sysctl carries no RSS and x/sys has no proc_pidinfo, so this stays until one lands. A ps failure reads as 0 (unmeasured), the wall clock is the backstop.
func memWatchdog(done <-chan struct{}, pgid int, capBytes uint64, kill func()) {
	t := time.NewTicker(memPoll)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			if groupRSS(pgid) > capBytes {
				kill()
				return
			}
		}
	}
}

// groupRSS sums the resident set (bytes) of every process in pgid; ps prints rss in KiB. Filtering here rather than with -g: that flag is a no-op under COMMAND_MODE=legacy and would then sum the whole machine.
func groupRSS(pgid int) uint64 {
	out, err := exec.Command("/bin/ps", "-axo", "pgid=,rss=").Output()
	if err != nil {
		return 0
	}
	want := strconv.Itoa(pgid)
	var sum uint64
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 || f[0] != want {
			continue
		}
		kb, _ := strconv.ParseUint(f[1], 10, 64)
		sum += kb << 10
	}
	return sum
}

// MaybeRunHelper is the re-exec hook (cmd/main.go and TestMain call it FIRST): in helper mode it applies the rlimits, chdirs into the worktree and execs sandbox-exec, which execs the anchor in place. RLIMIT_DATA/AS are never set here: EINVAL on arm64 and unenforced everywhere (memWatchdog is the cap).
func MaybeRunHelper() {
	specJSON := os.Getenv(helperSpecEnv)
	if specJSON == "" {
		return
	}
	spec := helperSpecFromEnv(specJSON)
	helperRlimit(unix.RLIMIT_CPU, spec.CPUSeconds)
	helperRlimit(unix.RLIMIT_NOFILE, spec.NoFile)
	helperRlimit(unix.RLIMIT_FSIZE, spec.FSizeBytes)
	helperNoCore()
	if err := os.Chdir(spec.Dir); err != nil {
		helperDie("chdir: " + err.Error())
	}
	argv := append([]string{sandboxExec, "-f", spec.Profile, "--"}, spec.Argv...)
	if err := unix.Exec(sandboxExec, argv, spec.Env); err != nil {
		helperDie("exec: " + err.Error())
	}
}
