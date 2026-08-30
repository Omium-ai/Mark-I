package anchors

import (
	"net"
	"os"
	"sort"
	"strings"
	"testing"
	"time"
)

// probeEnv selects a probe behavior when THIS test binary is exec'd inside the
// sandbox: the sandbox negatives run the real sandbox against the test binary
// itself, so the "anchor" is a process we fully control. The variable arrives
// via RunSpec.Env — the scrubbed allow-list — which doubles as proof the env
// path works.
const probeEnv = "MARK1_ANCHOR_TEST_PROBE"

// extraProbes lets platform-specific test files register probes this file
// cannot host: main_test.go builds on every GOOS, while a probe like the
// raw x32 socket syscall only exists on linux (sandbox_linux_test.go).
var extraProbes = map[string]func() int{}

// testSandbox is the REAL sandbox, used wherever a test derives a catalog:
// derivation's version sniff execs an unconsented binary and must go through
// it (catalog.go Derive).
func testSandbox(t *testing.T) Sandbox {
	t.Helper()
	return NewSandbox(t.TempDir())
}

func TestMain(m *testing.M) {
	// Helper stage first: the sandbox parent re-execs this binary with the
	// helper spec env var; MaybeRunHelper never returns in that mode.
	MaybeRunHelper()
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
		conn.Close()
		os.Exit(0)
	case "uds":
		// AF_UNIX probe: a netns denies IP but not pathname unix sockets, so
		// this is the mark1d-m1p.sock reachability question asked directly.
		conn, err := net.DialTimeout("unix", os.Getenv("MARK1_ANCHOR_TEST_ADDR"), 2*time.Second)
		if err != nil {
			os.Exit(1)
		}
		conn.Close()
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
	case "spin":
		// CPU burn for the RLIMIT_CPU kill test; never exits on its own.
		for {
			_ = time.Now()
		}
	case "sleep":
		time.Sleep(time.Minute)
		os.Exit(0)
	case "flood":
		// Output-cap probe: 8 MiB to stdout, far past any test cap.
		chunk := strings.Repeat("x", 64<<10)
		for i := 0; i < 128; i++ {
			os.Stdout.WriteString(chunk)
		}
		os.Exit(0)
	case "env":
		// Env-scrub probe: print the entire environment, sorted, one per line.
		env := os.Environ()
		sort.Strings(env)
		os.Stdout.WriteString(strings.Join(env, "\n"))
		os.Exit(0)
	default:
		if f, ok := extraProbes[mode]; ok {
			os.Exit(f())
		}
		os.Exit(2)
	}
}
