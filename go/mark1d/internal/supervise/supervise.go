// Package supervise is 04 §2.8's child supervisor: the row that turns
// `mark1-proxy` from a binary that exists into a process that runs.
//
// One goroutine per child, and every mutable thing a child needs — its backoff
// state, its breaker window, its restart count — lives as a value inside that
// goroutine's own copy of the Child. There is no map keyed by name, no mutex,
// and nothing a second child's crash can reach: a supervisor whose own
// bookkeeping is shared is a supervisor that can corrupt the restart decision
// for a process it is not even talking about.
//
// Crash isolation is directional (04 §1.2): nothing here can stop capture. The
// worst outcome the breaker can produce is a child marked FAILED, and FAILED is
// a state with an announced consequence (OnFailed), never a silent stop.
package supervise

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"os"
	"os/exec"
	"sync"
	"time"
)

// The four constants 04 §1.2's restart-policy table fixes for both supervised
// children, transcribed rather than tuned. They are the same for cortexd and
// mark1-proxy ("same backoff as cortexd", 04 :81), so they are package-level
// and a Child overrides them only in a test.
const (
	BackoffBase   = 500 * time.Millisecond
	BackoffCap    = 60 * time.Second
	BreakerMax    = 5
	BreakerWindow = 60 * time.Second
)

// Child is 04 §2.8's declared shape. Every field it names is here with the
// meaning it names.
type Child struct {
	Name  string
	Start func(ctx context.Context) (*exec.Cmd, error)

	Backoff Backoff
	Breaker Breaker

	// OnFailed is called once, from the child's own goroutine, at the moment
	// the breaker trips — and never again, because the goroutine returns
	// immediately after. 04 :81 makes this the place where crash isolation
	// becomes user-visible truth rather than a silent absence of a process.
	OnFailed func()

	Adopt AdoptSpec

	// OnExit is the one field 04 §2.8 does not name, and it exists for a
	// failure that document does not model: `proxy.port` outliving the process
	// it describes. The supervisor is the only party that knows the exact
	// instant a child stopped, and between that instant and the next spawn
	// there is a backoff of up to a minute in which a file naming a freed
	// ephemeral port would still be on disk. err is nil for a clean exit.
	OnExit func(err error)
}

func (c Child) exited(err error) {
	if c.OnExit != nil {
		c.OnExit(err)
	}
}

// Supervisor holds children, not child state: everything mutable moves into the
// per-child goroutine at Run.
type Supervisor struct {
	log      *slog.Logger
	children []Child
}

func New(log *slog.Logger) *Supervisor {
	if log == nil {
		log = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	return &Supervisor{log: log}
}

func (s *Supervisor) Add(c Child) { s.children = append(s.children, c) }

// Run blocks until ctx is cancelled AND every child has been reaped. The join
// is not politeness: mark1d's shutdown drain closes the spool underneath these
// goroutines, and a child still running its OnExit against a closed session is
// how a teardown becomes a crash.
func (s *Supervisor) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, c := range s.children {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.supervise(ctx, c)
		}()
	}
	wg.Wait()
}

func (s *Supervisor) supervise(ctx context.Context, c Child) {
	log := s.log.With("child", c.Name)
	if c.Adopt.PidFile != "" {
		// 04 :674's adoption path. It refuses today (see AdoptSpec.Adopt), and
		// the refusal is logged rather than swallowed: a supervisor that
		// respawns where the document says it adopts is a behaviour difference
		// an operator should be able to see in the log, not infer from source.
		if err := c.Adopt.Adopt(); err != nil {
			log.Warn("supervise: not adopting; spawning a fresh child", "err", err)
		}
	}
	for {
		started := time.Now()
		err := runOnce(ctx, c)
		up := time.Since(started)

		if ctx.Err() != nil {
			// The exit reason here is the signal we sent, so it is not a crash
			// and must not reach the breaker: counting a shutdown as a restart
			// would let a daemon that stops six times in a minute mark its own
			// proxy FAILED and revert a fragment nobody asked it to revert.
			log.Info("supervise: child stopped for shutdown", "up", up, "err", err)
			c.exited(err)
			return
		}
		if err == nil {
			// A sidecar that returns 0 has still stopped serving. It is
			// restarted like any other exit and counted like any other exit;
			// only the log distinguishes them, because the two have different
			// causes and an operator reading "crashed" for a clean exit will
			// look for the wrong thing.
			log.Warn("supervise: child exited cleanly; restarting", "up", up)
		} else {
			log.Error("supervise: child crashed", "up", up, "err", err)
		}
		c.exited(err)

		if up > c.Breaker.window() {
			// A run that outlived the breaker's own window is not part of a
			// crash loop by the breaker's own definition, so carrying its
			// backoff forward would make a once-an-hour blip sleep like a flap.
			c.Backoff.Reset()
		}
		if c.Breaker.Trip(time.Now()) {
			log.Error("supervise: child FAILED — crash-loop breaker tripped; no further restarts",
				"restarts", c.Breaker.max(), "window", c.Breaker.window())
			if c.OnFailed != nil {
				c.OnFailed()
			}
			return
		}

		d := c.Backoff.Next()
		log.Info("supervise: restarting after backoff", "in", d)
		select {
		case <-time.After(d):
		case <-ctx.Done():
			return
		}
	}
}

// runOnce owns exactly one process lifetime. Start builds the command and this
// function starts it, so the supervisor — not the caller — holds the handle it
// must Wait on: a caller that both built and started would leave two parties
// able to reap, and the loser of that race reports a lost child as a clean exit.
func runOnce(ctx context.Context, c Child) error {
	cmd, err := c.Start(ctx)
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Wait()
}

// Backoff is 04 :80's "base 500 ms, ×2, cap 60 s, decorrelated jitter".
//
// Decorrelated rather than plain exponential because the event that killed one
// child (a machine wake, a full disk, an OOM) is usually the event that killed
// the others: undithered doubling has every survivor retry in lockstep on every
// attempt, so the thundering herd repeats at 1 s, 2 s, 4 s instead of once.
// The zero value is the 04 policy; the fields exist so a test does not sleep.
type Backoff struct {
	Base time.Duration
	Cap  time.Duration

	prev time.Duration
}

func (b *Backoff) base() time.Duration {
	if b.Base > 0 {
		return b.Base
	}
	return BackoffBase
}

func (b *Backoff) ceiling() time.Duration {
	if b.Cap > 0 {
		return b.Cap
	}
	return BackoffCap
}

// Next draws the next delay from [base, 2×previous], clamped to the cap.
func (b *Backoff) Next() time.Duration {
	base, ceiling := b.base(), b.ceiling()
	if b.prev < base {
		b.prev = base
	}
	hi := b.prev * 2
	if hi > ceiling {
		hi = ceiling
	}
	if hi < base {
		// A cap below the base is a misconfiguration, not a licence to return
		// a delay shorter than the floor 04 :80 sets.
		hi = base
	}
	d := base + time.Duration(rand.Int64N(int64(hi-base)+1)) //nolint:gosec // G404: retry dither, not a secret; math/rand is the correct tool
	b.prev = d
	return d
}

func (b *Backoff) Reset() { b.prev = 0 }

// Breaker is 04 :80/:81's ">5 restarts in 60 s ⇒ FAILED". Strictly greater: the
// fifth restart inside the window still gets a sixth attempt, the sixth does
// not — that is what the ">" in the document buys, and off-by-one here is the
// difference between a proxy that recovers from a flap and one that FAILs and
// reverts a fragment on it.
type Breaker struct {
	Max    int
	Window time.Duration

	at []time.Time
}

func (b *Breaker) max() int {
	if b.Max > 0 {
		return b.Max
	}
	return BreakerMax
}

func (b *Breaker) window() time.Duration {
	if b.Window > 0 {
		return b.Window
	}
	return BreakerWindow
}

// Trip records a restart at now and reports whether the child is FAILED. now is
// a parameter rather than a clock read so the window is testable without
// sleeping through it.
func (b *Breaker) Trip(now time.Time) bool {
	cut := now.Add(-b.window())
	kept := b.at[:0]
	for _, t := range b.at {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	b.at = append(kept, now)
	return len(b.at) > b.max()
}

// ErrNoAdoption is what every adoption attempt returns today. See AdoptSpec.
var ErrNoAdoption = errors.New("supervise: adoption not available")

// AdoptSpec is 04 §2.8's restart-survivable adoption input: the pidfile a
// running child left behind, plus the BLAKE3 of the binary that pidfile must
// name.
//
// It does not adopt, and saying so is the point. 04 :674 requires verifying the
// process's binary hash AND its start time before adopting — the start time is
// what stops a recycled PID being adopted as the child it replaced, and Go's
// standard library exposes no portable way to read either fact for an arbitrary
// PID. The only child wired today (mark1-proxy) also writes no pidfile at all:
// rust/mark1-proxy/src/main.rs publishes proxy.port and nothing else. So the
// honest answer is a refusal that names its reason and a respawn, not a
// pid-liveness check dressed up as adoption — and emphatically not the "kill
// and respawn on mismatch" arm, which without the verification would be this
// daemon killing whatever process happens to hold a recycled PID.
type AdoptSpec struct {
	PidFile    string
	BinaryHash []byte // BLAKE3-256 of the binary the pidfile must name
}

func (a AdoptSpec) Adopt() error {
	if a.PidFile == "" {
		return fmt.Errorf("%w: no pidfile configured", ErrNoAdoption)
	}
	if _, err := os.Stat(a.PidFile); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrNoAdoption, a.PidFile, err)
	}
	return fmt.Errorf("%w: %s exists, but 04 :674's binary-hash + start-time verification has no portable implementation, and an unverified adopt would adopt a recycled PID", ErrNoAdoption, a.PidFile)
}
