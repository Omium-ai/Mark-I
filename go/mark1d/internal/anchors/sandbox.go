package anchors

import (
	"context"
	"errors"
	"time"
)

// ErrSandboxUnavailable means the platform cannot establish the sandbox's
// non-negotiable floor (network denial). Per CON-009 no anchor of ANY class
// runs unsandboxed, so this refuses the run — VERDICT_ERROR upstream, never
// a fallback exec.
var ErrSandboxUnavailable = errors.New("anchors: sandbox unavailable on this platform/kernel; anchor refused (CON-009)")

// ErrOutputCap means the anchor exceeded the combined stdout+stderr cap and
// was killed: its counts would be measured over truncated output, so the run
// is an error, not a diagnostic result.
var ErrOutputCap = errors.New("anchors: output cap exceeded; run killed")

// Sandbox is the security boundary, not a convenience wrapper (04 §2.2).
type Sandbox interface {
	// Run executes spec inside the sandbox; ctx cancel ⇒ SIGKILL the process
	// group (the kill switch — `mark1 off` cancels all running anchors).
	Run(ctx context.Context, spec RunSpec) (RunResult, error)
	// FSConfined reports whether write confinement (read-only outside the
	// worktree) is kernel-enforced for runs — the FR-VERIFY-003 test-anchor
	// precondition. It never overclaims: false means "chdir + env scrub
	// only", exactly as doc.go states.
	FSConfined() bool
	// Status is the candidates.json honesty field: can this platform admit a run at all, and why not.
	Status() SandboxStatus
}

// SandboxStatus is published in candidates.json so `mark1 doctor` and the app can say WHY nothing derives: Available is false when no run can be admitted, Reason is non-empty whenever something is refused or degraded.
type SandboxStatus struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason"`
}

// Limits are the per-run resource caps (04 §1.4 row "anchors").
type Limits struct {
	CPUSeconds uint64 // RLIMIT_CPU, soft=hard ⇒ kill at the cap
	// RLIMIT_DATA — committed private anonymous memory, the cgroup memory.max
	// stand-in (doc.go). NOT RLIMIT_AS: address space is not memory, and a
	// thread-per-core allocator reserves it in proportion to the core count, so
	// an AS cap kills real toolchains on big hosts without them using the memory.
	// On darwin the kernel enforces neither: a mark1d RSS watchdog over the process group kills it past the cap (sandbox_darwin.go).
	// On windows it is the job's JOB_MEMORY commit limit, CPUSeconds its JOB_TIME; NoFile and FSizeBytes have no job twin and are not enforced there (sandbox_windows.go).
	MemoryBytes uint64
	NoFile      uint64        // RLIMIT_NOFILE
	FSizeBytes  uint64        // RLIMIT_FSIZE — bounds any single file written
	Wall        time.Duration // wall-clock SIGKILL of the process group
	OutputCap   int64         // combined stdout+stderr byte cap
}

// DefaultLimits returns the 04 §1.4 defaults per cost class: 60 s fast /
// 600 s slow wall (CPU capped likewise), memory.max 512 MiB.
func DefaultLimits(c Class) Limits {
	// 1 GiB, not 512 MiB: node 24 reserves its V8 cage under RLIMIT_DATA and traps below ~1 GiB on `tsc --version` (founder's box, 2026-09-20); ruff and go vet never notice
	wall, mem := 60*time.Second, uint64(1<<30)
	if c == ClassSlow {
		wall, mem = 600*time.Second, 4<<30 // compilers: rustc alone passes 512 MiB of data on a mid-size crate
	}
	return Limits{
		CPUSeconds:  uint64(wall / time.Second), //nolint:gosec // G115: wall is one of the two constants above
		MemoryBytes: mem,
		NoFile:      1024,
		FSizeBytes:  512 << 20,
		Wall:        wall,
		OutputCap:   4 << 20,
	}
}

// RunSpec is one sandboxed execution (04 §2.2).
type RunSpec struct {
	Argv       []string          // argv[0] absolute — the consented BinaryPath
	WorktreeRO string            // cwd; writes confined to here + scratch (doc.go)
	CacheDir   string            // daemon-owned build cache the tool may also write (GOCACHE); "" ⇒ none
	ReadOnly   []string          // extra roots the run reads (git's repository top and git dirs); only Windows confines reads, so only it grants these
	Env        map[string]string // the allow-list, nothing inherited; HOME added by the sandbox
	Limits     Limits
	// RequireFSConfined refuses the run (ErrSandboxUnavailable) when write
	// confinement is not kernel-enforced — set for test-class anchors
	// (FR-VERIFY-003: refuse rather than run unsandboxed).
	RequireFSConfined bool
}

// RunResult reports what actually happened; Stdout/Stderr are capped copies.
type RunResult struct {
	ExitCode     int    // -1 when killed by signal
	Signal       string // non-empty when signal-killed ("killed", "CPU time limit exceeded", …)
	Stdout       []byte
	Stderr       []byte
	TimedOut     bool     // wall clock or ctx kill fired
	Truncated    bool     // output cap fired (run killed, see ErrOutputCap)
	EffectiveEnv []string // exact "K=V" env the child ran under, sorted — the
	// env_scrub_attestation input (proto verify.proto: "the exact env map
	// passed to RunSpec", plus the sandbox-owned HOME)
	Duration time.Duration
	// Touched is the set of worktree-relative paths git reports as changed or untracked when the run began (nil = unknown, every finding counts), and Worktree the root they are relative to. A static anchor's verdict is about the change, not the repo's history: a finding in an untouched file is the baseline the repo already carried, never the agent's doing.
	Touched  map[string]bool
	Worktree string
}
