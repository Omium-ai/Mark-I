//go:build linux

package anchors

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// helperSpecEnv carries the run spec into the re-exec'd helper. It is the
// helper process's ENTIRE environment, so the anchor cannot see it: the
// helper replaces the env wholesale at exec with spec.Env.
const helperSpecEnv = "MARK1_ANCHOR_HELPER_SPEC"

// helperSetupExit is the helper's "sandbox setup failed before exec" code,
// disambiguated from a tool's own 125 by the stderr prefix check in Run.
// ponytail: a tool that exits 125 AND prints our prefix is misread as a
// setup failure; a dedicated status pipe if that ever bites.
const helperSetupExit = 125

const helperStderrPrefix = "mark1d-anchor-helper: "

// landlockWriteV1 is the ABI-v1 write-type access set — everything that
// mutates the filesystem. Reads and execute stay unhandled: "read-only
// outside the worktree" allows reads everywhere (doc.go).
const landlockWriteV1 = unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
	unix.LANDLOCK_ACCESS_FS_REMOVE_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
	unix.LANDLOCK_ACCESS_FS_MAKE_CHAR | unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
	unix.LANDLOCK_ACCESS_FS_MAKE_REG | unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
	unix.LANDLOCK_ACCESS_FS_MAKE_FIFO | unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
	unix.LANDLOCK_ACCESS_FS_MAKE_SYM

type helperSpec struct {
	Argv         []string `json:"argv"`
	Dir          string   `json:"dir"`
	Env          []string `json:"env"` // final K=V set, sorted
	CPUSeconds   uint64   `json:"cpu_seconds"`
	MemoryBytes  uint64   `json:"memory_bytes"`
	NoFile       uint64   `json:"nofile"`
	FSizeBytes   uint64   `json:"fsize_bytes"`
	LandlockMask uint64   `json:"landlock_mask"` // 0 ⇒ kernel lacks Landlock; skip
	Writable     []string `json:"writable"`      // worktree + scratch
}

// LinuxSandbox implements Sandbox with unprivileged user+net namespaces,
// rlimits, and Landlock write confinement. See doc.go for the exact enforced
// / not-enforced statement.
type LinuxSandbox struct {
	scratchRoot  string // per-run HOME dirs are created beneath this
	landlockMask uint64 // 0 when the kernel has no Landlock
}

// NewSandbox probes the kernel once (Landlock ABI) and returns the sandbox.
// scratchRoot is where per-run scratch HOMEs live; "" uses the OS temp dir.
func NewSandbox(scratchRoot string) *LinuxSandbox {
	if scratchRoot == "" {
		scratchRoot = os.TempDir()
	}
	return &LinuxSandbox{scratchRoot: scratchRoot, landlockMask: landlockMask()}
}

// landlockMask returns the write-access set the running kernel can handle,
// or 0 when Landlock is absent/disabled.
func landlockMask() uint64 {
	abi, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 {
		return 0
	}
	mask := uint64(landlockWriteV1)
	if abi >= 2 {
		mask |= unix.LANDLOCK_ACCESS_FS_REFER
	}
	if abi >= 3 {
		mask |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
	}
	return mask
}

func (s *LinuxSandbox) FSConfined() bool { return s.landlockMask != 0 }

// Run executes spec per the doc.go contract. Network denial is the floor: a
// kernel that refuses unprivileged CLONE_NEWUSER|CLONE_NEWNET refuses the
// run — there is no unsandboxed fallback (CON-009).
func (s *LinuxSandbox) Run(ctx context.Context, spec RunSpec) (RunResult, error) {
	if len(spec.Argv) == 0 || !strings.HasPrefix(spec.Argv[0], "/") {
		return RunResult{}, errors.New("anchors: RunSpec.Argv[0] must be the absolute consented binary path")
	}
	if spec.RequireFSConfined && !s.FSConfined() {
		// FR-VERIFY-003: test-class anchors refuse rather than run without
		// kernel-enforced write confinement.
		return RunResult{}, fmt.Errorf("%w: write confinement (Landlock) unavailable", ErrSandboxUnavailable)
	}
	scratch, err := os.MkdirTemp(s.scratchRoot, "anchor-scratch-")
	if err != nil {
		return RunResult{}, err
	}
	defer os.RemoveAll(scratch)

	// Final child env: the caller's allow-list plus the sandbox-owned HOME.
	// Sorted so EffectiveEnv (the attestation input) is deterministic.
	envMap := make(map[string]string, len(spec.Env)+1)
	for k, v := range spec.Env {
		envMap[k] = v
	}
	if _, ok := envMap["HOME"]; !ok {
		envMap["HOME"] = scratch
	}
	env := make([]string, 0, len(envMap))
	for k, v := range envMap {
		env = append(env, k+"="+v)
	}
	sort.Strings(env)

	// The helper treats a zero rlimit as "skip", so an unset field here would
	// be an UNCAPPED run — but doc.go states CPU/AS/NOFILE/FSIZE as ENFORCED
	// per run. Default the zeros like Wall/OutputCap below: unset ⇒ default,
	// never unbounded.
	lim := spec.Limits
	def := DefaultLimits(ClassSlow)
	if lim.CPUSeconds == 0 {
		lim.CPUSeconds = def.CPUSeconds
	}
	if lim.MemoryBytes == 0 {
		lim.MemoryBytes = def.MemoryBytes
	}
	if lim.NoFile == 0 {
		lim.NoFile = def.NoFile
	}
	if lim.FSizeBytes == 0 {
		lim.FSizeBytes = def.FSizeBytes
	}

	hs := helperSpec{
		Argv:         spec.Argv,
		Dir:          spec.WorktreeRO,
		Env:          env,
		CPUSeconds:   lim.CPUSeconds,
		MemoryBytes:  lim.MemoryBytes,
		NoFile:       lim.NoFile,
		FSizeBytes:   lim.FSizeBytes,
		LandlockMask: s.landlockMask,
		Writable:     []string{spec.WorktreeRO, scratch},
	}
	specJSON, err := json.Marshal(hs)
	if err != nil {
		return RunResult{}, err
	}
	self, err := os.Executable()
	if err != nil {
		return RunResult{}, err
	}

	outCap := spec.Limits.OutputCap
	if outCap <= 0 {
		outCap = DefaultLimits(ClassSlow).OutputCap // unset ⇒ default, never unbounded
	}
	budget := &outputBudget{remaining: outCap}
	var stdout, stderr capWriter
	stdout.budget, stderr.budget = budget, budget

	cmd := exec.Command(self)
	cmd.Env = []string{helperSpecEnv + "=" + string(specJSON)}
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		// CLONE_NEWNET inside CLONE_NEWUSER: the unprivileged path to a
		// loopback-less netns — the network denial itself.
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: os.Getuid(), HostID: os.Getuid(), Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: os.Getgid(), HostID: os.Getgid(), Size: 1},
		},
		GidMappingsEnableSetgroups: false,
		Setpgid:                    true,            // the kill unit is the process group
		Pdeathsig:                  syscall.SIGKILL, // a dying daemon never orphans an anchor
	}

	start := time.Now()
	if err := cmd.Start(); err != nil {
		// EPERM/EINVAL here is the kernel refusing unprivileged userns —
		// the sandbox floor cannot be established.
		return RunResult{}, fmt.Errorf("%w: %v", ErrSandboxUnavailable, err)
	}
	pgid := cmd.Process.Pid
	gk := &groupKill{sig: func() { _ = syscall.Kill(-pgid, syscall.SIGKILL) }}
	budget.onExceed(func() { gk.kill(false) }) // output cap breach kills the whole group

	watchDone := make(chan struct{})
	go func() {
		wall := spec.Limits.Wall
		if wall <= 0 {
			wall = DefaultLimits(ClassSlow).Wall
		}
		t := time.NewTimer(wall)
		defer t.Stop()
		select {
		case <-ctx.Done(): // the kill switch: `mark1 off` cancels all anchors
		case <-t.C:
		case <-watchDone:
			return
		}
		gk.kill(true)
	}()

	waitErr := cmd.Wait()
	timedOut := gk.markReaped()
	close(watchDone)
	res := RunResult{
		Stdout:       stdout.buf,
		Stderr:       stderr.buf,
		TimedOut:     timedOut,
		Truncated:    budget.exceeded(),
		EffectiveEnv: env,
		Duration:     time.Since(start),
	}

	var ws syscall.WaitStatus
	if cmd.ProcessState != nil {
		ws, _ = cmd.ProcessState.Sys().(syscall.WaitStatus)
	}
	switch {
	case waitErr == nil:
		res.ExitCode = 0
	case ws.Signaled():
		res.ExitCode = -1
		res.Signal = ws.Signal().String()
	default:
		res.ExitCode = ws.ExitStatus()
	}

	if res.Truncated {
		return res, ErrOutputCap
	}
	if res.ExitCode == helperSetupExit && strings.Contains(string(res.Stderr), helperStderrPrefix) {
		return res, fmt.Errorf("anchors: sandbox setup failed: %s", strings.TrimSpace(string(res.Stderr)))
	}
	return res, nil
}

// groupKill serializes every SIGKILL sender with the reap. cmd.Wait() frees
// the leader's pid, and with it the pgid — a later syscall.Kill(-pgid) can
// land on an unrelated process group the kernel recycled the id to. So a kill
// that has committed (watcher past its select, or a cap breach) must re-check
// reaped under the lock, and markReaped is where TimedOut is read: after it,
// no watcher can retroactively flip a run that exited on its own into a
// "timed out" one.
// ponytail: the kernel reaps inside Wait itself, microseconds before
// markReaped runs — a kill in THAT sliver still races pid reuse; closing it
// needs pidfd_send_signal on a pidfd held from Start.
type groupKill struct {
	mu       sync.Mutex
	reaped   bool
	timedOut bool
	sig      func() // syscall.Kill(-pgid, SIGKILL) in production
}

func (g *groupKill) kill(timeout bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.reaped {
		return
	}
	if timeout {
		g.timedOut = true
	}
	g.sig()
}

// markReaped flags the reap and returns whether a timeout kill landed first.
func (g *groupKill) markReaped() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.reaped = true
	return g.timedOut
}

// outputBudget is the shared stdout+stderr cap; breaching it flips exceeded
// once and fires the kill.
type outputBudget struct {
	mu        sync.Mutex
	remaining int64
	over      bool
	kill      func()
}

func (b *outputBudget) onExceed(kill func()) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.kill = kill
	if b.over {
		// A write breached the cap in the Start→onExceed window, when take had
		// no kill to fire and the latch had already flipped — fire it now, or
		// the run burns to the wall clock with its output silently discarded.
		kill()
	}
}

func (b *outputBudget) exceeded() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.over
}

// take grants up to n bytes; a zero grant with over=true means the cap fired.
func (b *outputBudget) take(n int) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	if int64(n) <= b.remaining {
		b.remaining -= int64(n)
		return n
	}
	grant := int(b.remaining)
	b.remaining = 0
	if !b.over {
		b.over = true
		if b.kill != nil {
			b.kill()
		}
	}
	return grant
}

type capWriter struct {
	budget *outputBudget
	buf    []byte
}

// Write never errors: after the cap fires the process is being killed and
// residual pipe bytes are swallowed rather than turned into copy errors.
func (w *capWriter) Write(p []byte) (int, error) {
	if n := w.budget.take(len(p)); n > 0 {
		w.buf = append(w.buf, p[:n]...)
	}
	return len(p), nil
}

// MaybeRunHelper is the re-exec hook: cmd/main.go (and this package's
// TestMain) call it FIRST. When the helper env var is present this process is
// the sandbox child — it applies rlimits and Landlock to itself, scrubs the
// env, chdirs into the worktree, and execs the anchor. It never returns in
// helper mode.
//
// The setup runs pinned to one OS thread: landlock_restrict_self and
// PR_SET_NO_NEW_PRIVS act on the calling thread, and execve then replaces
// the whole process, so the restricted thread is the one that execs.
func MaybeRunHelper() {
	specJSON := os.Getenv(helperSpecEnv)
	if specJSON == "" {
		return
	}
	runtime.LockOSThread()
	helperAssertConfined()
	var spec helperSpec
	if err := json.Unmarshal([]byte(specJSON), &spec); err != nil {
		helperDie("bad spec: " + err.Error())
	}
	rl := func(resource int, v uint64) {
		if v == 0 {
			return // Run defaults every zero field, so this never skips a real limit
		}
		if err := unix.Setrlimit(resource, &unix.Rlimit{Cur: v, Max: v}); err != nil {
			helperDie(fmt.Sprintf("setrlimit(%d): %v", resource, err))
		}
	}
	rl(unix.RLIMIT_CPU, spec.CPUSeconds)
	rl(unix.RLIMIT_AS, spec.MemoryBytes)
	rl(unix.RLIMIT_NOFILE, spec.NoFile)
	rl(unix.RLIMIT_FSIZE, spec.FSizeBytes)
	// Anchors must never dump core: 04 §11.6 posture, and a core file is a
	// worktree-content disclosure channel.
	rl(unix.RLIMIT_CORE, 1) // 0 means "unset" in rl; 1 byte is below any core header

	if spec.LandlockMask != 0 {
		if err := applyLandlock(spec.LandlockMask, spec.Writable); err != nil {
			// The parent promised confinement (it probed the ABI); failing
			// open here would overclaim the sandbox — die instead.
			helperDie("landlock: " + err.Error())
		}
	}
	// The netns denies IP; it does NOT deny AF_UNIX, and Landlock (ABI ≤ 3)
	// does not govern connect(2) — so without this the anchor could reach any
	// same-uid pathname socket, mark1d's own m1p.sock included (07 §5's mode
	// bits stop other USERS, not the anchor). doc.go's "no anchor ever runs
	// network-attached" is only true with this filter, so it is mandatory: a
	// kernel without CONFIG_SECCOMP_FILTER refuses the run rather than
	// running with a hole the docs deny (11 §5 honesty rule).
	if err := denyUnixSockets(); err != nil {
		helperDie("seccomp: " + err.Error())
	}
	if err := os.Chdir(spec.Dir); err != nil {
		helperDie("chdir: " + err.Error())
	}
	if err := unix.Exec(spec.Argv[0], spec.Argv, spec.Env); err != nil {
		helperDie("exec: " + err.Error())
	}
}

func helperDie(msg string) {
	fmt.Fprintln(os.Stderr, helperStderrPrefix+msg)
	os.Exit(helperSetupExit)
}

// helperAssertConfined is the helper's positive self-check that it really is
// inside the parent's fresh user+net namespaces. The Cloneflags at Run only
// confine children Run spawned — the spec env var itself proves nothing (its
// author controls its contents, so any "does the spec match reality" check is
// theater). Without this, anyone who can set MARK1_ANCHOR_HELPER_SPEC on a
// mark1d launch (wrapper script, systemd EnvironmentFile, an env-forwarding
// supervisor) gets arbitrary exec with the host network attached, `mark1 off`
// or not. So test the confinement PROPERTIES directly:
//   - user namespace: the initial userns's /proc/self/uid_map is the identity
//     full-range line "0 0 4294967295"; an unprivileged fresh userns cannot
//     have it (Run installs a single size-1 mapping).
//   - network namespace: the fresh netns has only a DOWN loopback. Require NO
//     interface up at all, loopback included — a live lo alone reaches
//     127.0.0.1 daemons, so "non-loopback only" would be too weak.
//
// Either failing means we were invoked outside Run's namespaces: refuse.
func helperAssertConfined() {
	uidMap, err := os.ReadFile("/proc/self/uid_map")
	if err != nil {
		helperDie("confinement check: uid_map: " + err.Error())
	}
	if f := strings.Fields(string(uidMap)); len(f) == 3 && f[0] == "0" && f[1] == "0" && f[2] == "4294967295" {
		helperDie("confinement check: in the initial user namespace; refusing to exec")
	}
	ifs, err := net.Interfaces()
	if err != nil {
		helperDie("confinement check: interfaces: " + err.Error())
	}
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp != 0 {
			helperDie("confinement check: interface " + ifc.Name + " is up; not in the sandbox netns; refusing to exec")
		}
	}
}

// auditArch is the seccomp_data.arch value for the arch this binary was built
// for. A syscall arriving under any OTHER arch (i386 compat on x86_64, whose
// syscall NUMBERS differ) is refused outright — otherwise a 32-bit child could
// walk past a filter written in 64-bit numbers.
var auditArch = map[string]uint32{
	"amd64":   unix.AUDIT_ARCH_X86_64,
	"arm64":   unix.AUDIT_ARCH_AARCH64,
	"386":     unix.AUDIT_ARCH_I386,
	"arm":     unix.AUDIT_ARCH_ARM,
	"riscv64": unix.AUDIT_ARCH_RISCV64,
}[runtime.GOARCH]

// denyUnixSockets installs a classic-BPF seccomp filter that fails
// socket(AF_UNIX, …) with EACCES — the AF_UNIX half of "network denied"
// (doc.go), which the network namespace does not cover. EACCES rather than
// SIGKILL: a linter that probes for a daemon socket should degrade, not die
// mid-analysis and become an unexplained VERDICT_ERROR.
//
// socketpair(2) stays allowed on purpose: it yields an unnamed pair usable
// only inside the sandboxed process tree (language runtimes use it for their
// own IPC), and it can reach nothing on the host.
// ponytail: hand-rolled cBPF rather than libseccomp — one syscall, one arg,
// no cgo; revisit if the deny list ever grows past a handful of rules.
func denyUnixSockets() error {
	if auditArch == 0 {
		return fmt.Errorf("no audit arch for GOARCH %s", runtime.GOARCH)
	}
	const (
		offNr   = 0  // seccomp_data.nr
		offArch = 4  // seccomp_data.arch
		offArg0 = 16 // seccomp_data.args[0], low word (little-endian)
		// x32SyscallBit marks x32-ABI syscalls, which arrive with arch ==
		// AUDIT_ARCH_X86_64 but renumbered (socket = 0x40000029 ≠ 41): without
		// this deny, an x32 binary walks straight past the SYS_SOCKET match on
		// any CONFIG_X86_X32_ABI=y kernel. No legit syscall nr on any supported
		// arch reaches this bit, so the deny is unconditional, not amd64-only.
		x32SyscallBit = 0x40000000
	)
	deny := uint32(unix.SECCOMP_RET_ERRNO) | uint32(unix.EACCES)
	filter := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: offArch},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: auditArch, Jt: 0, Jf: 6}, // wrong arch ⇒ deny
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: offNr},
		{Code: unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K, K: x32SyscallBit, Jt: 4, Jf: 0}, // x32 nr ⇒ deny
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: uint32(unix.SYS_SOCKET), Jt: 0, Jf: 2},
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: offArg0},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: unix.AF_UNIX, Jt: 1, Jf: 0},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
		{Code: unix.BPF_RET | unix.BPF_K, K: deny},
	}
	prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	// NO_NEW_PRIVS is a precondition of an unprivileged seccomp filter (and is
	// set again by applyLandlock — idempotent).
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("no_new_privs: %v", err)
	}
	if err := unix.Prctl(unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER, uintptr(unsafe.Pointer(&prog)), 0, 0); err != nil {
		return fmt.Errorf("set_seccomp: %v", err)
	}
	return nil
}

// applyLandlock confines writes to the given directories: handled access =
// mask (write-type only), allow rules beneath each writable root, then
// restrict self. x/sys ships the types and syscall numbers but no wrappers,
// hence the raw syscalls.
func applyLandlock(mask uint64, writable []string) error {
	attr := unix.LandlockRulesetAttr{Access_fs: mask}
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET,
		uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if errno != 0 {
		return fmt.Errorf("create_ruleset: %v", errno)
	}
	defer unix.Close(int(fd))
	for _, dir := range writable {
		dfd, err := unix.Open(dir, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("open %s: %v", dir, err)
		}
		rule := unix.LandlockPathBeneathAttr{Allowed_access: mask, Parent_fd: int32(dfd)}
		_, _, errno = unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE,
			fd, unix.LANDLOCK_RULE_PATH_BENEATH, uintptr(unsafe.Pointer(&rule)), 0, 0, 0)
		unix.Close(dfd)
		if errno != 0 {
			return fmt.Errorf("add_rule %s: %v", dir, errno)
		}
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("no_new_privs: %v", err)
	}
	if _, _, errno = unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, fd, 0, 0); errno != 0 {
		return fmt.Errorf("restrict_self: %v", errno)
	}
	return nil
}
