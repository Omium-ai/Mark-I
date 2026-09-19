//go:build linux || darwin

package anchors

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

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
