package anchors

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

// fakeEmitter records what the vote path admitted. It lives in the tag-free
// file for the reason stated below about extraProbes, inverted: it came from
// runner_test.go back when that file was //go:build unix, while votes_test.go
// — which never was — uses it, so the anchors package did not compile on
// Windows at all. Nothing about an in-memory slice is platform-specific.
type fakeEmitter struct {
	mu     sync.Mutex
	events []*m1pv1.Event
}

func (f *fakeEmitter) Admit(_ context.Context, ev *m1pv1.Event) error {
	f.mu.Lock()
	f.events = append(f.events, ev)
	f.mu.Unlock()
	return nil
}

func (f *fakeEmitter) all() []*m1pv1.Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*m1pv1.Event(nil), f.events...)
}

// probeEnv selects a probe behavior when THIS test binary is exec'd inside the
// sandbox: the sandbox negatives run the real sandbox against the test binary
// itself, so the "anchor" is a process we fully control. The variable arrives
// via RunSpec.Env — the scrubbed allow-list — which doubles as proof the env
// path works.
const probeEnv = "MARK1_ANCHOR_TEST_PROBE"

// versionSidecar is the fakeBin contract on windows: this binary, copied under a tool's name, prints the sidecar beside it and exits — no batch file, which an AppContainer refuses to run.
const versionSidecar = ".version"

func printVersionSidecar() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	for _, p := range []string{exe + versionSidecar, func() string { r, _ := filepath.EvalSymlinks(exe); return r + versionSidecar }()} {
		if b, err := os.ReadFile(p); err == nil {
			_, _ = os.Stdout.Write(b)
			os.Exit(0)
		}
	}
}

// extraProbes lets platform-specific test files register probes this file
// cannot host: main_test.go builds on every GOOS, while a probe like the
// raw x32 socket syscall only exists on linux (sandbox_linux_test.go).
var extraProbes = map[string]func() int{}

func TestMain(m *testing.M) {
	// Helper stage first: the sandbox parent re-execs this binary with the
	// helper spec env var; MaybeRunHelper never returns in that mode.
	MaybeRunHelper()
	printVersionSidecar()
	if mode := os.Getenv(probeEnv); mode != "" {
		runProbe(mode)
	}
	os.Exit(m.Run())
}

// runProbe exits 0 iff the probed operation SUCCEEDED — so a sandbox test
// asserting denial asserts a NONZERO exit.
func runProbe(mode string) {
	switch mode {
	case "dial":
		// Network probe: the test parent listens on this addr; unsandboxed the
		// dial succeeds, in a loopback-less netns it cannot.
		conn, err := net.DialTimeout("tcp", os.Getenv("MARK1_ANCHOR_TEST_ADDR"), 2*time.Second)
		if err != nil {
			os.Exit(1)
		}
		_ = conn.Close()
		os.Exit(0)
	case "uds":
		// AF_UNIX probe: a netns denies IP but not pathname unix sockets, so
		// this is the mark1d-m1p.sock reachability question asked directly.
		conn, err := net.DialTimeout("unix", os.Getenv("MARK1_ANCHOR_TEST_ADDR"), 2*time.Second)
		if err != nil {
			os.Exit(1)
		}
		_ = conn.Close()
		os.Exit(0)
	case "write":
		if err := os.WriteFile(os.Getenv("MARK1_ANCHOR_TEST_PATH"), []byte("escaped"), 0o600); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	case "exfil":
		// The one-way valve, exercised end to end: read a same-uid file OUTSIDE
		// the worktree and copy it INSIDE. doc.go documents this as NOT ENFORCED
		// BY CONSTRUCTION; the test that drives this probe asserts the docs and
		// the sandbox still agree about it.
		b, err := os.ReadFile(os.Getenv("MARK1_ANCHOR_TEST_SRC"))
		if err != nil {
			os.Exit(1)
		}
		if err := os.WriteFile(os.Getenv("MARK1_ANCHOR_TEST_PATH"), b, 0o600); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	case "sleep":
		time.Sleep(time.Minute)
		os.Exit(0)
	case "memhog":
		// Memory-cap probe: allocate AND TOUCH far past any sane cap, so the
		// pages are really committed rather than lazily reserved. Exit 0 iff
		// every allocation succeeded — the cap test asserts a nonzero exit.
		var held [][]byte
		for i := 0; i < 64; i++ {
			b := make([]byte, 32<<20)
			for j := 0; j < len(b); j += 4096 {
				b[j] = 1
			}
			held = append(held, b)
		}
		time.Sleep(time.Second) // hold it resident long enough for a polling watchdog (darwin) to see it
		os.Exit(len(held) - 64)
	case "flood":
		// Output-cap probe: 8 MiB to stdout, far past any test cap.
		chunk := strings.Repeat("x", 64<<10)
		for i := 0; i < 128; i++ {
			_, _ = os.Stdout.WriteString(chunk)
		}
		os.Exit(0)
	case "env":
		// Env-scrub probe: print the entire environment, sorted, one per line.
		env := os.Environ()
		sort.Strings(env)
		_, _ = os.Stdout.WriteString(strings.Join(env, "\n"))
		os.Exit(0)
	default:
		if f, ok := extraProbes[mode]; ok {
			os.Exit(f())
		}
		os.Exit(2)
	}
}
