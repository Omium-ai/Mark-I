//go:build linux || darwin

package anchors

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

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

type helperSpec struct {
	Argv         []string `json:"argv"`
	Dir          string   `json:"dir"`
	Env          []string `json:"env"` // final K=V set, sorted
	CPUSeconds   uint64   `json:"cpu_seconds"`
	MemoryBytes  uint64   `json:"memory_bytes"`
	NoFile       uint64   `json:"nofile"`
	FSizeBytes   uint64   `json:"fsize_bytes"`
	LandlockMask uint64   `json:"landlock_mask"`     // linux: 0 ⇒ kernel lacks Landlock; skip
	Writable     []string `json:"writable"`          // linux: worktree + scratch
	Profile      string   `json:"profile,omitempty"` // darwin: the per-run seatbelt profile path
}

// prepare is the platform-neutral front of Run: argv validation, the per-run scratch HOME, the exact sorted child env (spec.Env + HOME, the EffectiveEnv attestation input) and the defaulted caps.
func prepare(scratchRoot string, spec RunSpec) (scratch string, env []string, lim Limits, err error) {
	if len(spec.Argv) == 0 || !strings.HasPrefix(spec.Argv[0], "/") {
		return "", nil, Limits{}, errors.New("anchors: RunSpec.Argv[0] must be the absolute consented binary path")
	}
	scratch, err = os.MkdirTemp(scratchRoot, "anchor-scratch-")
	if err != nil {
		return "", nil, Limits{}, err
	}
	envMap := make(map[string]string, len(spec.Env)+1)
	for k, v := range spec.Env {
		envMap[k] = v
	}
	if _, ok := envMap["HOME"]; !ok {
		envMap["HOME"] = scratch
	}
	env = make([]string, 0, len(envMap))
	for k, v := range envMap {
		env = append(env, k+"="+v)
	}
	sort.Strings(env)
	return scratch, env, defaultedLimits(spec.Limits), nil
}

// defaultedLimits fills every zero cap from the slow-class defaults: the helper treats a zero rlimit as "skip", and doc.go states the caps as ENFORCED per run, so unset ⇒ default, never unbounded.
func defaultedLimits(l Limits) Limits {
	def := DefaultLimits(ClassSlow)
	if l.CPUSeconds == 0 {
		l.CPUSeconds = def.CPUSeconds
	}
	if l.MemoryBytes == 0 {
		l.MemoryBytes = def.MemoryBytes
	}
	if l.NoFile == 0 {
		l.NoFile = def.NoFile
	}
	if l.FSizeBytes == 0 {
		l.FSizeBytes = def.FSizeBytes
	}
	if l.Wall <= 0 {
		l.Wall = def.Wall
	}
	if l.OutputCap <= 0 {
		l.OutputCap = def.OutputCap
	}
	return l
}

// runHelper re-execs this binary as the helper described by hs and waits it out under lim: the output cap, the wall clock and ctx (the kill switch) all SIGKILL the process group. attr is the platform's clone/pgid setup, start launches cmd (a failure is the sandbox floor refusing: ErrSandboxUnavailable), and watch, when non-nil, runs beside the group with a kill until done closes.
func runHelper(ctx context.Context, hs helperSpec, lim Limits, attr *syscall.SysProcAttr, start func(*exec.Cmd) error, watch func(done <-chan struct{}, pgid int, kill func())) (RunResult, error) {
	specJSON, err := json.Marshal(hs)
	if err != nil {
		return RunResult{}, err
	}
	self, err := os.Executable()
	if err != nil {
		return RunResult{}, err
	}
	budget := &outputBudget{remaining: lim.OutputCap}
	var stdout, stderr capWriter
	stdout.budget, stderr.budget = budget, budget

	cmd := exec.Command(self) //nolint:gosec // G204: self is os.Executable() — this is the re-exec helper, not a caller-named binary
	cmd.Env = []string{helperSpecEnv + "=" + string(specJSON)}
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.SysProcAttr = attr

	began := time.Now()
	if err := start(cmd); err != nil {
		return RunResult{}, fmt.Errorf("%w: %v", ErrSandboxUnavailable, err)
	}
	pgid := cmd.Process.Pid
	gk := &groupKill{sig: func() { _ = syscall.Kill(-pgid, syscall.SIGKILL) }}
	budget.onExceed(func() { gk.kill(false) }) // output cap breach kills the whole group

	watchDone := make(chan struct{})
	go func() {
		t := time.NewTimer(lim.Wall)
		defer t.Stop()
		select {
		case <-ctx.Done(): // the kill switch: `mark1 off` cancels all anchors
		case <-t.C:
		case <-watchDone:
			return
		}
		gk.kill(true)
	}()
	if watch != nil {
		go watch(watchDone, pgid, func() { gk.kill(false) })
	}

	waitErr := cmd.Wait()
	timedOut := gk.markReaped()
	close(watchDone)
	res := RunResult{
		Stdout:       stdout.buf,
		Stderr:       stderr.buf,
		TimedOut:     timedOut,
		Truncated:    budget.exceeded(),
		EffectiveEnv: hs.Env,
		Duration:     time.Since(began),
	}
	res.ExitCode, res.Signal = exitStatus(waitErr, cmd.ProcessState)

	if res.Truncated {
		return res, ErrOutputCap
	}
	if res.ExitCode == helperSetupExit && strings.Contains(string(res.Stderr), helperStderrPrefix) {
		return res, fmt.Errorf("anchors: sandbox setup failed: %s", strings.TrimSpace(string(res.Stderr)))
	}
	return res, nil
}

// exitStatus maps the reaped state to (ExitCode, Signal): 0 on a clean exit, -1 plus the signal name when signaled, the tool's own code otherwise.
func exitStatus(waitErr error, ps *os.ProcessState) (int, string) {
	var ws syscall.WaitStatus
	if ps != nil {
		ws, _ = ps.Sys().(syscall.WaitStatus)
	}
	switch {
	case waitErr == nil:
		return 0, ""
	case ws.Signaled():
		return -1, ws.Signal().String()
	default:
		return ws.ExitStatus(), ""
	}
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

// helperSpecFromEnv is the helper's first act: decode the spec the parent passed in its one env var, or die with the setup code.
func helperSpecFromEnv(specJSON string) helperSpec {
	var spec helperSpec
	if err := json.Unmarshal([]byte(specJSON), &spec); err != nil {
		helperDie("bad spec: " + err.Error())
	}
	return spec
}

// helperRlimit sets soft=hard=v; zero skips, which Run never passes for a real limit (defaultedLimits).
func helperRlimit(resource int, v uint64) {
	if v == 0 {
		return
	}
	if err := unix.Setrlimit(resource, &unix.Rlimit{Cur: v, Max: v}); err != nil {
		helperDie(fmt.Sprintf("setrlimit(%d): %v", resource, err))
	}
}

// helperNoCore is {0,0} rather than helperRlimit(…,1): the hardened parent's hard limit is 0 and cannot be raised.
func helperNoCore() {
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}); err != nil {
		helperDie(fmt.Sprintf("setrlimit(RLIMIT_CORE): %v", err))
	}
}

func helperDie(msg string) {
	fmt.Fprintln(os.Stderr, helperStderrPrefix+msg)
	os.Exit(helperSetupExit)
}
