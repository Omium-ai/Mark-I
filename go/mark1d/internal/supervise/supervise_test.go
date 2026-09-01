package supervise

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The fake child is this test binary re-exec'ing itself. Deliberately not the
// real mark1-proxy: a Go suite that shells out to a Cargo artifact fails for
// reasons that have nothing to do with supervision, and then gets skipped.
const childEnvVar = "SUPERVISE_TEST_CHILD"

func TestMain(m *testing.M) {
	switch os.Getenv(childEnvVar) {
	case "":
		os.Exit(m.Run())
	case "clean":
		os.Exit(0)
	case "crash":
		os.Exit(3)
	case "sleep":
		// Not select{}: an empty select is a deadlock the runtime kills with a
		// panic, which this suite would read as a crashing child.
		time.Sleep(time.Hour)
		os.Exit(0)
	case "port":
		writePortFile()
		time.Sleep(time.Hour)
		os.Exit(0)
	case "port-then-crash":
		writePortFile()
		os.Exit(3)
	}
	os.Exit(0)
}

// writePortFile stands in for rust/mark1-proxy's `write_port`. It derives the
// path from $HOME exactly as the real proxy does (config() in main.rs), so this
// also proves ProxyChild's HOME override actually lands the file where the
// provisioner reads it.
func writePortFile() {
	home, err := os.UserHomeDir()
	if err != nil {
		os.Exit(9)
	}
	if err := os.WriteFile(home+"/.omium/mark1/proxy.port", []byte("41337"), 0o600); err != nil {
		os.Exit(9)
	}
}

func childStart(mode string) func(context.Context) (*exec.Cmd, error) {
	return func(ctx context.Context) (*exec.Cmd, error) {
		cmd := exec.CommandContext(ctx, os.Args[0])
		cmd.Env = append(os.Environ(), childEnvVar+"="+mode)
		return cmd, nil
	}
}

// fastBackoff keeps the restart loop off the wall clock. The constants under
// test are asserted directly in TestBackoff*; nothing here depends on them.
func fastBackoff() Backoff { return Backoff{Base: time.Millisecond, Cap: 2 * time.Millisecond} }

// logCapture is the observability assertion surface: Part 4's missing coverage
// receipt is only visible at runtime as a log line, so a test that cannot read
// the log cannot prove the gap is announced.
type logCapture struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *logCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}

func (c *logCapture) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

func (c *logCapture) logger() *slog.Logger { return slog.New(slog.NewTextHandler(c, nil)) }

func TestBackoffStaysInsideTheDocumentedEnvelope(t *testing.T) {
	for _, tc := range []struct {
		name string
		b    Backoff
	}{
		{"04 :80 defaults", Backoff{}},
		{"cap reached quickly", Backoff{Base: time.Millisecond, Cap: 4 * time.Millisecond}},
		{"cap below base is clamped to base", Backoff{Base: time.Second, Cap: time.Millisecond}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := tc.b
			base, ceiling := b.base(), b.ceiling()
			prev := base
			for i := range 500 {
				d := b.Next()
				hi := min(prev*2, ceiling)
				if hi < base {
					hi = base
				}
				if d < base || d > hi {
					t.Fatalf("draw %d = %v, want within [%v, %v] (decorrelated jitter over 2x previous %v)", i, d, base, hi, prev)
				}
				if d > ceiling && ceiling >= base {
					t.Fatalf("draw %d = %v exceeds the cap %v", i, d, ceiling)
				}
				prev = d
			}
		})
	}
}

// The default envelope, stated as the document states it, so a changed constant
// fails here and not only in an envelope check that would follow it.
func TestBackoffDefaultsAreTheDocumentedConstants(t *testing.T) {
	var b Backoff
	if b.base() != 500*time.Millisecond || b.ceiling() != 60*time.Second {
		t.Fatalf("base/cap = %v/%v, want 500ms/60s (04 :80)", b.base(), b.ceiling())
	}
	first := b.Next()
	if first < 500*time.Millisecond || first > time.Second {
		t.Errorf("first delay = %v, want within [500ms, 1s]", first)
	}
	b.Reset()
	again := b.Next()
	if again > time.Second {
		t.Errorf("delay after Reset = %v, want the first-draw envelope again", again)
	}
}

func TestBreakerWindow(t *testing.T) {
	for _, tc := range []struct {
		name     string
		restarts int
		gap      time.Duration
		wantTrip bool
	}{
		{"five in a minute is a flap, not a failure", 5, time.Second, false},
		{"six in a minute is FAILED", 6, time.Second, true},
		{"five spread beyond the window", 5, 20 * time.Second, false},
		{"six spread beyond the window", 6, 20 * time.Second, false},
		{"twenty spread beyond the window", 20, 61 * time.Second, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var b Breaker
			now := time.Now()
			tripped := false
			for range tc.restarts {
				if b.Trip(now) {
					tripped = true
				}
				now = now.Add(tc.gap)
			}
			if tripped != tc.wantTrip {
				t.Fatalf("tripped = %v after %d restarts %v apart, want %v", tripped, tc.restarts, tc.gap, tc.wantTrip)
			}
		})
	}
}

func TestBreakerTripCallsOnFailedExactlyOnce(t *testing.T) {
	var failed, exits atomic.Int64
	logs := &logCapture{}
	s := New(logs.logger())
	s.Add(Child{
		Name:     "crasher",
		Start:    childStart("crash"),
		Backoff:  fastBackoff(),
		Breaker:  Breaker{Max: 5, Window: time.Minute},
		OnExit:   func(error) { exits.Add(1) },
		OnFailed: func() { failed.Add(1) },
	})

	done := make(chan struct{})
	go func() {
		s.Run(t.Context())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("supervisor never gave up; the breaker did not trip")
	}

	if got := failed.Load(); got != 1 {
		t.Errorf("OnFailed called %d times, want exactly 1", got)
	}
	// Six exits: five restarts are inside the budget, the sixth is over it.
	if got := exits.Load(); got != 6 {
		t.Errorf("child ran %d times, want 6 (>5 restarts in the window, 04 :81)", got)
	}
	if !bytes.Contains([]byte(logs.String()), []byte("FAILED")) {
		t.Errorf("the FAILED state was never logged:\n%s", logs.String())
	}
}

// A child that keeps exiting cleanly is still restarted and still counted — but
// it must not be reported as a crash, because an operator reading "crashed" for
// an exit code of 0 goes looking for the wrong thing.
func TestCleanExitIsDistinguishableFromACrash(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mode    string
		wantErr bool
		wantLog string
	}{
		{"exit 0", "clean", false, "exited cleanly"},
		{"exit 3", "crash", true, "crashed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exits := make(chan error, 8)
			logs := &logCapture{}
			s := New(logs.logger())
			s.Add(Child{
				Name:    tc.name,
				Start:   childStart(tc.mode),
				Backoff: fastBackoff(),
				OnExit: func(err error) {
					select {
					case exits <- err:
					default:
					}
				},
			})
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan struct{})
			go func() {
				s.Run(ctx)
				close(done)
			}()

			var err error
			select {
			case err = <-exits:
			case <-time.After(30 * time.Second):
				t.Fatal("child never exited")
			}
			cancel()
			<-done

			if (err != nil) != tc.wantErr {
				t.Fatalf("exit err = %v, wantErr = %v", err, tc.wantErr)
			}
			var ee *exec.ExitError
			if tc.wantErr && (!errors.As(err, &ee) || ee.ExitCode() != 3) {
				t.Errorf("exit err = %v, want an ExitError carrying code 3", err)
			}
			if !bytes.Contains([]byte(logs.String()), []byte(tc.wantLog)) {
				t.Errorf("log does not say %q:\n%s", tc.wantLog, logs.String())
			}
		})
	}
}

func TestCancellationStopsEveryChildAndLeavesNoGoroutines(t *testing.T) {
	before := runtime.NumGoroutine()
	var stopped atomic.Int64
	s := New(slog.New(slog.NewTextHandler(&logCapture{}, nil)))
	for range 3 {
		s.Add(Child{
			Name:    "sleeper",
			Start:   childStart("sleep"),
			Backoff: fastBackoff(),
			OnExit:  func(error) { stopped.Add(1) },
		})
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		s.Run(ctx)
		close(done)
	}()
	// Let all three actually get running, so cancellation has something to stop.
	for stopped.Load() == 0 && runtime.NumGoroutine() < before+3 {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("Run did not return after cancellation; a child goroutine is stuck")
	}
	if got := stopped.Load(); got != 3 {
		t.Errorf("%d of 3 children reported an exit; the rest were never reaped", got)
	}
	// Run's WaitGroup is the guarantee; this is the check that the guarantee is
	// real and that nothing was started outside it.
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > before+2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if after := runtime.NumGoroutine(); after > before+2 {
		t.Errorf("goroutines %d -> %d after a cancelled Run", before, after)
	}
}

func TestAdoptRefusesRatherThanPretending(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec AdoptSpec
	}{
		{"unconfigured", AdoptSpec{}},
		{"pidfile absent", AdoptSpec{PidFile: t.TempDir() + "/nope.pid"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.spec.Adopt(); !errors.Is(err, ErrNoAdoption) {
				t.Fatalf("Adopt() = %v, want ErrNoAdoption", err)
			}
		})
	}
	// The arm that matters: a pidfile that DOES exist must still refuse, because
	// 04 :674's binary-hash + start-time verification is not implemented and an
	// unverified adopt would adopt a recycled PID.
	pid := t.TempDir() + "/proxy.pid"
	if err := os.WriteFile(pid, []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := AdoptSpec{PidFile: pid}.Adopt()
	if !errors.Is(err, ErrNoAdoption) {
		t.Fatalf("Adopt() on an existing pidfile = %v, want ErrNoAdoption", err)
	}
}
