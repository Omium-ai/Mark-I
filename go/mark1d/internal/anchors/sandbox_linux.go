//go:build linux

package anchors

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// landlockWriteV1 is the ABI-v1 write-type access set — everything that
// mutates the filesystem. Reads and execute stay unhandled: "read-only
// outside the worktree" allows reads everywhere (doc.go).
const landlockWriteV1 = unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
	unix.LANDLOCK_ACCESS_FS_REMOVE_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
	unix.LANDLOCK_ACCESS_FS_MAKE_CHAR | unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
	unix.LANDLOCK_ACCESS_FS_MAKE_REG | unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
	unix.LANDLOCK_ACCESS_FS_MAKE_FIFO | unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
	unix.LANDLOCK_ACCESS_FS_MAKE_SYM

// LinuxSandbox implements Sandbox with unprivileged user+net namespaces,
// rlimits, and Landlock write confinement. See doc.go for the exact enforced
// / not-enforced statement.
type LinuxSandbox struct {
	scratchRoot  string // per-run HOME dirs are created beneath this
	landlockMask uint64 // 0 when the kernel has no Landlock
	mu           sync.Mutex
	floor        string // the last userns refusal Run saw; "" once a run was admitted
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

// Status reports the floor as the last Run found it (the kernel is only asked at clone time, so before any run it reads available) plus the Landlock regime.
func (s *LinuxSandbox) Status() SandboxStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.floor != "" {
		return SandboxStatus{Available: false, Reason: "unprivileged user namespaces refused: " + s.floor}
	}
	if s.landlockMask == 0 {
		return SandboxStatus{Available: true, Reason: "write confinement (Landlock) unavailable: test-class and repo-code anchors refuse"}
	}
	return SandboxStatus{Available: true}
}

func (s *LinuxSandbox) noteFloor(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.floor = ""
	if err != nil {
		s.floor = err.Error()
	}
}

// Run executes spec per the doc.go contract. Network denial is the floor: a
// kernel that refuses unprivileged CLONE_NEWUSER|CLONE_NEWNET refuses the
// run — there is no unsandboxed fallback (CON-009).
func (s *LinuxSandbox) Run(ctx context.Context, spec RunSpec) (RunResult, error) {
	scratch, env, lim, err := prepare(s.scratchRoot, spec)
	if err != nil {
		return RunResult{}, err
	}
	defer func() { _ = os.RemoveAll(scratch) }()
	if spec.RequireFSConfined && !s.FSConfined() {
		// FR-VERIFY-003: test-class anchors refuse rather than run without
		// kernel-enforced write confinement.
		return RunResult{}, fmt.Errorf("%w: write confinement (Landlock) unavailable", ErrSandboxUnavailable)
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
		Writable:     writableRoots(spec, scratch),
	}
	attr := &syscall.SysProcAttr{
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
	// EPERM/EINVAL at start is the kernel refusing unprivileged userns — the sandbox floor cannot be established; Status remembers it.
	start := func(cmd *exec.Cmd) error {
		err := startDumpable(cmd)
		s.noteFloor(err)
		return err
	}
	return runHelper(ctx, hs, lim, attr, start, nil)
}

var startMu sync.Mutex

// startDumpable clones the helper with this process momentarily dumpable: harden.Apply's PR_SET_DUMPABLE=0 is inherited by the forked child, and the kernel refuses the parent's uid_map write to a non-dumpable child (PTRACE_MODE_READ), so under the shipped main() every anchor died at Start with EPERM — VERDICT_ERROR sandbox_unavailable on every install.
func startDumpable(cmd *exec.Cmd) error {
	startMu.Lock()
	defer startMu.Unlock()
	was, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err == nil && was == 0 {
		if err := unix.Prctl(unix.PR_SET_DUMPABLE, 1, 0, 0, 0); err != nil {
			return err
		}
		defer func() { _ = unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0) }()
	}
	return cmd.Start()
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
	spec := helperSpecFromEnv(specJSON)
	helperRlimit(unix.RLIMIT_CPU, spec.CPUSeconds)
	helperRlimit(unix.RLIMIT_DATA, spec.MemoryBytes)
	helperRlimit(unix.RLIMIT_NOFILE, spec.NoFile)
	helperRlimit(unix.RLIMIT_FSIZE, spec.FSizeBytes)
	helperNoCore()

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
	prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]} //nolint:gosec // G115: filter is the fixed literal program above
	// NO_NEW_PRIVS is a precondition of an unprivileged seccomp filter (and is
	// set again by applyLandlock — idempotent).
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("no_new_privs: %v", err)
	}
	//nolint:gosec // G103: seccomp takes the program by pointer; x/sys ships no wrapper (see the applyLandlock note)
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
		uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0) //nolint:gosec // G103: raw syscall, no wrapper exists
	if errno != 0 {
		return fmt.Errorf("create_ruleset: %v", errno)
	}
	defer func() { _ = unix.Close(int(fd)) }()
	allow := func(path string, access uint64, required bool) error {
		dfd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			if !required {
				return nil
			}
			return fmt.Errorf("open %s: %v", path, err)
		}
		rule := unix.LandlockPathBeneathAttr{Allowed_access: access, Parent_fd: int32(dfd)} //nolint:gosec // G115: dfd is a Linux fd, which is int32 by definition
		_, _, errno := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE,
			fd, unix.LANDLOCK_RULE_PATH_BENEATH, uintptr(unsafe.Pointer(&rule)), 0, 0, 0) //nolint:gosec // G103: raw syscall, no wrapper exists
		_ = unix.Close(dfd)
		if errno != 0 {
			return fmt.Errorf("add_rule %s: %v", path, errno)
		}
		return nil
	}
	for _, dir := range writable {
		if err := allow(dir, mask, true); err != nil {
			return err
		}
	}
	// The write-side device files every toolchain opens: git opens /dev/null O_RDWR at start and died with "could not open '/dev/null'" (the diff facts were empty on every real Linux run, so the baseline boundary and the suppression audit never existed). Writes to these reach no file.
	for _, dev := range []string{"/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom", "/dev/tty"} {
		if err := allow(dev, mask&unix.LANDLOCK_ACCESS_FS_WRITE_FILE, false); err != nil {
			return err
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
