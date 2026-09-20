package anchors

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// helperSpecEnv carries the run spec into the re-exec'd helper. It is the
// helper process's ENTIRE environment, so the anchor cannot see it: the
// helper replaces the env wholesale at exec with spec.Env. Tag-free so the
// env-scrub probe can assert its absence on every platform.
const helperSpecEnv = "MARK1_ANCHOR_HELPER_SPEC"

// prepare is the platform-neutral front of Run: argv validation, the per-run scratch HOME, the exact sorted child env (spec.Env + HOME, the EffectiveEnv attestation input) and the defaulted caps.
func prepare(scratchRoot string, spec RunSpec) (scratch string, env []string, lim Limits, err error) {
	if len(spec.Argv) == 0 || !filepath.IsAbs(spec.Argv[0]) {
		return "", nil, Limits{}, errors.New("anchors: RunSpec.Argv[0] must be the absolute consented binary path")
	}
	scratch, err = os.MkdirTemp(scratchRoot, "anchor-scratch-")
	if err != nil {
		return "", nil, Limits{}, err
	}
	env = make([]string, 0, len(spec.Env)+1)
	for k, v := range spec.Env {
		env = append(env, k+"="+v)
	}
	sort.Strings(env)
	// TMPDIR too: go's work dir and rustc's temps land in the one place the sandbox lets them write
	return scratch, withDefault(withDefault(env, "HOME", scratch), "TMPDIR", scratch), defaultedLimits(spec.Limits), nil
}

// SweepScratch removes per-run scratch dirs a previous daemon left behind (a run in flight when it was stopped never reached its RemoveAll): every anchor-scratch-* under root older than an hour. Boot-time; the count is returned for the log.
func SweepScratch(root string) int {
	entries, err := os.ReadDir(root)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "anchor-scratch-") {
			continue
		}
		if info, err := e.Info(); err != nil || time.Since(info.ModTime()) < time.Hour {
			continue
		}
		dir := filepath.Join(root, e.Name())
		// a test suite run as an anchor leaves mode-000 dirs behind when it is stopped mid-test; RemoveAll cannot enter those
		_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err == nil && d.IsDir() {
				_ = os.Chmod(p, 0o700)
			}
			return nil
		})
		if os.RemoveAll(dir) == nil {
			n++
		}
	}
	return n
}

// writableRoots is the write set every sandbox grants: the worktree, the per-run scratch and, when the anchor has one, its daemon-owned build cache.
func writableRoots(spec RunSpec, scratch string) []string {
	roots := []string{spec.WorktreeRO, scratch}
	if spec.CacheDir != "" {
		roots = append(roots, spec.CacheDir)
	}
	return roots
}

// withDefault adds k=v to the sorted env unless the caller set k.
func withDefault(env []string, k, v string) []string {
	for _, kv := range env {
		if strings.HasPrefix(kv, k+"=") {
			return env
		}
	}
	env = append(env, k+"="+v)
	sort.Strings(env)
	return env
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
