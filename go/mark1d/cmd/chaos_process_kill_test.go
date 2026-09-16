//go:build chaos && linux

// chaos_process_kill — NFR-AVAILABILITY-001 ("no single point of failure"),
// the process-kill half of the chaos set justfile:120-121 documented as
// unbuilt. internal/spool's chaos_kill9 kills a spool writer and grades
// recovery; nothing before this killed the ASSEMBLED daemon, or its sidecar,
// under a live agent session and asked whether the agent noticed.
//
// Same discipline as chaos_kill9_test.go: the victims are real processes —
// the mark1d binary `go build` produces from this package, the mark1-hookshim
// and mark1-proxy binaries `cargo build --locked` produces — and the fault is
// a real SIGKILL, so the flock, the stale socket file, the orphaned
// proxy.port and the un-run shutdown drain are all the kernel's problem and
// then the next boot's, exactly as in production. No fake daemon: the shim
// tests already have one, and a fake cannot be killed in a way that matters.
//
// "The agent task completes" is asserted per hook invocation: while the
// daemon is dead, every hook the agent fires must exit 0, emit no decision,
// and return inside the 08 §4.4 budget the shim states for that hook — the
// same ceilings rust/mark1-hookshim/tests/shim_e2e.rs holds the shim to
// against its own fakes, now held against a daemon that actually died. What
// the outage cost is then read off the wire after restart: every event that
// hit the dead window reaches ingest exactly once via the spill ring, the
// session's Usage still arrives via the tailer, and the Dropped{} ledger is
// empty of anything the ring could have lost.
//
// Linux-only, not unix: the proxy leg finds the sidecar's pid by scanning
// /proc for the daemon's children, because the proxy publishes a port and no
// pidfile (supervise.AdoptSpec explains why nothing else can either).
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"

	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/claudecode"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/cortex"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/coverage"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/fabric/fabrictest"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/spool"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/supervise"
)

const (
	// chaosSession is the session every committed hook fixture carries.
	chaosSession = "3f9c2e71-58d4-4b6a-9e2f-7a1c0d8b4e55"
	// fixtureToolUseID is the tool_use_id in the PostToolUse fixture; each
	// invocation below swaps it for a unique one so the wire can be graded
	// per event rather than by count.
	fixtureToolUseID = "toolu_01SynthFixtureTTTTTTTT"

	// The 08 §4.4 budgets the shim states, transcribed from shim_e2e.rs so a
	// silent map edit cannot move them: the observer abandon timer
	// (main.rs FABRIC_ABANDON_MS), the Stop gate's 250 ms minus the 10 ms
	// margin, and the SessionEnd drain barrier's 1.5 s minus the margin.
	observerBudget   = 45 * time.Millisecond
	stopBudget       = 240 * time.Millisecond
	sessionEndBudget = 1490 * time.Millisecond
	// failOpenOverhead is shim_e2e.rs's FAIL_OPEN_OVERHEAD: what a fail-open
	// costs that is NOT waiting on the fabric — spawn, map load, the
	// debug-build redact ruleset compile, the sealed spill write. A fixed
	// cost added to the budget, never a multiple of it.
	failOpenOverhead = 900 * time.Millisecond

	// A hook with a live daemon has no spill and no ruleset compile: the
	// cold-start bound is 50 ms (04 §5) and shim_e2e.rs holds a warm run to
	// it, but this harness measures under a Go test binary that is also
	// running a daemon, so it takes 10× and calls the 50 ms number the
	// shim's to defend, not this file's.
	liveHookCeiling = 500 * time.Millisecond
)

// chaosBins builds the three real binaries. `cargo build --locked` so the
// bytes are the committed dependency set; `go build` of THIS package so the
// daemon under test is main(), flags and signal set included — not run()
// re-entered from a test binary that has already parsed its own flags.
type chaosBins struct{ root, mark1d, shim, proxy string }

func chaosBuild(t *testing.T) chaosBins {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	build := exec.Command("go", "build", "-o", filepath.Join(out, "mark1d"), ".")
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build mark1d: %v\n%s", err, b)
	}
	cargo := exec.Command("cargo", "build", "-p", "mark1-hookshim", "-p", "mark1-proxy", "--locked")
	cargo.Dir = root
	if b, err := cargo.CombinedOutput(); err != nil {
		// Not a skip: this lane's whole content is the real binaries, and a
		// harness that skips when it cannot build them is green-by-absence.
		t.Fatalf("cargo build: %v\n%s", err, b)
	}
	return chaosBins{
		root:   root,
		mark1d: filepath.Join(out, "mark1d"),
		shim:   filepath.Join(root, "target", "debug", "mark1-hookshim"),
		proxy:  filepath.Join(root, "target", "debug", "mark1-proxy"),
	}
}

// chaosRig is one machine: a HOME whose .omium/mark1 is the daemon's state
// dir (the shim and the proxy both derive that path from HOME and have no
// flag to move it), and an XDG_RUNTIME_DIR the shim and daemon agree on for
// the socket. env is what every child — daemon, shim, proxy — inherits.
type chaosRig struct {
	t                             *testing.T
	bins                          chaosBins
	home, state, socket, fixtures string
	env                           []string
	daemon                        *exec.Cmd
}

func newChaosRig(t *testing.T, bins chaosBins) *chaosRig {
	t.Helper()
	home := t.TempDir()
	xdg := fabrictest.SocketDir(t)
	r := &chaosRig{
		t:        t,
		bins:     bins,
		home:     home,
		state:    filepath.Join(home, ".omium", "mark1"),
		socket:   filepath.Join(xdg, "omium-mark1", "m1p.sock"),
		fixtures: filepath.Join(bins.root, "conformance", "hooks", "claudecode", "v2.1.251", "hooks"),
	}
	if err := os.MkdirAll(r.state, 0o700); err != nil {
		t.Fatal(err)
	}
	// The child environment is built, not inherited: a developer's own
	// ANTHROPIC_API_KEY would flip the daemon into the API-key regime and
	// spawn a proxy the mark1d leg does not want, and MARK1_DISABLE=1 in a
	// shell would make every shim a silent no-op and this test vacuous.
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		switch k {
		case "HOME", "USERPROFILE", "XDG_RUNTIME_DIR", "ANTHROPIC_API_KEY", "MARK1_DISABLE", "MARK1_PROXY":
			continue
		}
		r.env = append(r.env, kv)
	}
	r.env = append(r.env, "HOME="+home, "XDG_RUNTIME_DIR="+xdg, "ANTHROPIC_API_KEY=", "MARK1_DISABLE=")
	// A pinned `claude` first on every child's PATH. Every start below passes
	// --tenant-salt (see startDaemon), which arms the tailer, and the tailer
	// refuses any other version with a device-wide unsupported_agent_version
	// bypass transition — which the proxy leg's "exactly one transition"
	// would then count.
	fakeBin := t.TempDir()
	if err := os.WriteFile(filepath.Join(fakeBin, "claude"), []byte("#!/bin/sh\necho '"+pinnedAgentVersion(t)+" (Claude Code)'\n"), 0o755); err != nil { //nolint:gosec // G306: it must be executable
		t.Fatal(err)
	}
	r.env = append(r.env, "PATH="+fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Cleanup(r.reap)
	return r
}

// reap is the failure-path cleanup: a daemon left running past the test
// would hold the spool flock and a socket in a directory about to be deleted.
func (r *chaosRig) reap() {
	if r.daemon == nil || r.daemon.ProcessState != nil {
		return
	}
	_ = r.daemon.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() { _ = r.daemon.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		_ = r.daemon.Process.Kill()
		<-done
	}
}

// startDaemon runs the real binary. --tenant-salt on every start: it is the
// dev seam that arms transcript tailing (leg 1's Usage), and an unenrolled
// daemon with none of the enrollment dev seams refuses to boot (`mark1
// enroll`), so a bare start is not a daemon that can be killed.
func (r *chaosRig) startDaemon(extra ...string) {
	r.t.Helper()
	args := append([]string{"--state-dir", r.state, "--socket", r.socket, "--tenant-salt", "aa"}, extra...)
	cmd := exec.Command(r.bins.mark1d, args...)
	cmd.Env = r.env
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		r.t.Fatal(err)
	}
	r.daemon = cmd
	// A stat of the socket cannot mean "up" here: after a SIGKILL the stale
	// file is still there. Only a connect that succeeds does.
	waitUpTo(r.t, 30*time.Second, "mark1d listening on the fabric", func() bool {
		c, err := net.DialTimeout("unix", r.socket, 100*time.Millisecond)
		if err != nil {
			return false
		}
		_ = c.Close()
		return true
	})
}

// kill9 is the fault. Reaped before returning: the spool flock (D-CJ) is
// released by the kernel only once the process is actually gone, and the
// next boot must find it released.
func (r *chaosRig) kill9() {
	r.t.Helper()
	if err := r.daemon.Process.Kill(); err != nil {
		r.t.Fatal(err)
	}
	_ = r.daemon.Wait()
}

// stop is the clean exit: SIGTERM, then main()'s signal set runs the full
// 07 §6 shutdown drain and exits 0.
func (r *chaosRig) stop() {
	r.t.Helper()
	if err := r.daemon.Process.Signal(syscall.SIGTERM); err != nil {
		r.t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- r.daemon.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			r.t.Fatalf("mark1d exited %v on SIGTERM, want a clean 0", err)
		}
	case <-time.After(30 * time.Second):
		r.t.Fatal("mark1d did not exit on SIGTERM")
	}
}

func (r *chaosRig) fixture(name string) []byte {
	r.t.Helper()
	b, err := os.ReadFile(filepath.Join(r.fixtures, name+".json"))
	if err != nil {
		r.t.Fatalf("pinned %s fixture: %v", name, err)
	}
	return b
}

// hook runs the REAL shim exactly as Claude Code would: hook JSON on stdin,
// HOME/XDG from the environment, and reads back the three things the agent
// can observe — exit status, stdout, wall.
func (r *chaosRig) hook(name string, stdin []byte) shimRun {
	r.t.Helper()
	cmd := exec.Command(r.bins.shim)
	cmd.Env = r.env
	var out, errb strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errb
	cmd.Stdin = bytes.NewReader(stdin)
	started := time.Now()
	err := cmd.Run()
	run := shimRun{ok: err == nil, stdout: out.String(), stderr: errb.String(), wall: time.Since(started)}
	if !run.ok {
		r.t.Fatalf("%s: shim exited %v, want 0 on every path (08 §5.1): stderr=%q", name, err, run.stderr)
	}
	if strings.Contains(run.stdout, `"decision"`) {
		r.t.Fatalf("%s: the shim emitted a decision the agent acts on: %q", name, run.stdout)
	}
	return run
}

// shimRun mirrors adapters/claudecode's shim_e2e_test.go shape; that package's
// helper is not importable from here.
type shimRun struct {
	ok             bool
	stdout, stderr string
	wall           time.Duration
}

func (r *chaosRig) assertWall(name string, run shimRun, budget time.Duration) {
	r.t.Helper()
	if ceiling := budget + failOpenOverhead; run.wall > ceiling {
		r.t.Fatalf("%s took %v against a dead daemon, over the %v budget + %v overhead (08 §4.4) — the agent stalled",
			name, run.wall, budget, failOpenOverhead)
	}
	r.t.Logf("chaos: %s against a dead daemon: exit 0, no decision, %v (budget %v + %v)", name, run.wall, budget, failOpenOverhead)
}

func (r *chaosRig) postToolUse(id string) []byte {
	r.t.Helper()
	body := bytes.Replace(r.fixture("PostToolUse"), []byte(fixtureToolUseID), []byte(id), 1)
	if bytes.Equal(body, r.fixture("PostToolUse")) {
		r.t.Fatal("the PostToolUse fixture no longer carries the tool_use_id this harness rewrites")
	}
	return body
}

// events flattens every batch the tap received, in wire order.
func (w *wireTap) events() []*m1pv1.Event {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []*m1pv1.Event
	for _, b := range w.batches {
		out = append(out, b.GetEvents()...)
	}
	return out
}

// droppedRows is every Dropped row across every batch, for the ledger audit.
func (w *wireTap) droppedRows() []*m1pv1.Dropped {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []*m1pv1.Dropped
	for _, b := range w.batches {
		out = append(out, b.GetDropped()...)
	}
	return out
}

func (w *wireTap) count(pred func(*m1pv1.Event) bool) int {
	n := 0
	for _, ev := range w.events() {
		if pred(ev) {
			n++
		}
	}
	return n
}

func toolUse(id string) func(*m1pv1.Event) bool {
	return func(ev *m1pv1.Event) bool { return ev.GetToolUse().GetToolUseId() == id }
}

// TestChaosMark1dKill9MidSession is leg 1: the daemon dies between two hook
// invocations of a live session and comes back on the same state dir.
func TestChaosMark1dKill9MidSession(t *testing.T) {
	bins := chaosBuild(t)
	r := newChaosRig(t, bins)
	tap := newWireTap(t)

	// The transcript surface, so the session's Usage has a path to arrive
	// by: an enabled workspace (the rig supplies the pinned `claude` and the
	// tenant salt that arm the tailer).
	root := filepath.Join(r.home, "ws")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	canonRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	ws := `{"version":1,"workspaces":[{"path":"` + canonRoot + `","enabled_at":"2026-09-15T00:00:00Z"}]}`
	if err := os.WriteFile(filepath.Join(r.state, "workspaces.json"), []byte(ws), 0o600); err != nil {
		t.Fatal(err)
	}
	vendorDir, err := (&claudecode.Adapter{Home: r.home}).TranscriptDir(canonRoot)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(vendorDir, 0o700); err != nil {
		t.Fatal(err)
	}

	// ---- life 1: the session starts against a healthy daemon ----
	r.startDaemon()
	live := []string{"toolu_chaos_live_1", "toolu_chaos_live_2", "toolu_chaos_live_3"}
	var liveMax time.Duration
	if run := r.hook("SessionStart", r.fixture("SessionStart")); run.wall > liveHookCeiling {
		t.Fatalf("SessionStart took %v with a live daemon", run.wall)
	} else {
		liveMax = run.wall
	}
	for _, id := range live {
		run := r.hook("PostToolUse", r.postToolUse(id))
		if run.wall > liveHookCeiling {
			t.Fatalf("PostToolUse %s took %v with a live daemon", id, run.wall)
		}
		liveMax = max(liveMax, run.wall)
	}
	t.Logf("chaos: 4 hooks against the live daemon, slowest %v", liveMax)
	// The observer path is fire-and-forget past the HelloAck (08 §4.3 step
	// 4): a shim that has exited has its bytes in the kernel socket buffer,
	// and the daemon's reader admits them microseconds later. One fsync
	// cadence of slack so the kill below lands on an idle daemon, which is
	// what makes "every live event survives" a claim about durability rather
	// than about a race this row does not model.
	time.Sleep(300 * time.Millisecond)

	// ---- the fault ----
	r.kill9()
	if _, err := os.Lstat(r.socket); err != nil {
		t.Fatalf("the socket file should outlive a SIGKILLed daemon (its unlink never ran): %v", err)
	}

	// ---- the dead window: the agent keeps working ----
	dead := []string{"toolu_chaos_dead_1", "toolu_chaos_dead_2", "toolu_chaos_dead_3"}
	for _, id := range dead {
		r.assertWall("PostToolUse", r.hook("PostToolUse", r.postToolUse(id)), observerBudget)
	}
	r.assertWall("Stop", r.hook("Stop", r.fixture("Stop")), stopBudget)
	r.assertWall("SessionEnd", r.hook("SessionEnd", r.fixture("SessionEnd")), sessionEndBudget)
	// The agent's API call during the outage: the transcript line is on disk,
	// nobody is tailing it.
	line := `{"type":"assistant","cwd":"` + canonRoot + `","requestId":"req_chaos","sessionId":"` + chaosSession + `","message":{"id":"msg_chaos","model":"claude-fable-5","usage":{"input_tokens":1,"output_tokens":9,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"service_tier":"standard"}}}` + "\n"
	if err := os.WriteFile(filepath.Join(vendorDir, chaosSession+".jsonl"), []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}

	// The precondition the restart assertions rest on: the dead-window hooks
	// SPILLED. Without this, "the ring was drained" is satisfied by a ring
	// that was never written, and the exactly-once grade below would be
	// grading the live window twice.
	spillDir := filepath.Join(r.state, "spill")
	ring := filepath.Join(spillDir, "hookshim.ring")
	if fi, err := os.Stat(ring); err != nil || fi.Size() == 0 {
		t.Fatalf("the shim did not spill while the daemon was dead (ring: %v) — every dead-window event is lost and nothing below can be asserted", err)
	}
	// The shim's own outage ledger (04 §5.4 sidecars): one Stop allowed by
	// timeout, one SessionEnd whose drain was never receipted. Asserted here
	// because it is the only accounting those two fail-opens have — the
	// daemon's drain converts hookshim.ring.shed to Dropped{RING_EVICTED}
	// and nothing converts these (see the report).
	for name, want := range map[string]int64{"hookshim.gate_timeout": 1, "hookshim.flush_timeout": 1} {
		fi, err := os.Stat(filepath.Join(spillDir, name))
		if err != nil || fi.Size() != want {
			t.Fatalf("%s = %v (err %v), want %d byte(s): the fail-open was not counted", name, fi, err, want)
		}
	}

	// ---- life 2: restart on the same state dir, uplink on ----
	restarted := time.Now()
	r.startDaemon("--ingest-url", tap.url, "--device-token", "tok-test")
	// Inside spillDrainEvery, so a pass is the drain AT ENTRY (04 §5's
	// restart scan) and not the first periodic tick.
	waitUpTo(t, spillDrainEvery/2, "the startup drain to truncate the ring", func() bool {
		_, err := os.Stat(ring)
		return os.IsNotExist(err)
	})
	t.Logf("chaos: ring drained %v after restart", time.Since(restarted))
	all := append(append([]string{}, live...), dead...)
	waitUpTo(t, 30*time.Second, "every hook event and the Usage to reach the wire", func() bool {
		for _, id := range all {
			if tap.count(toolUse(id)) == 0 {
				return false
			}
		}
		return tap.usage() >= 1 &&
			tap.count(func(ev *m1pv1.Event) bool { return ev.GetSessionEnd() != nil }) >= 1
	})
	t.Logf("chaos: every dead-window event and the Usage on the wire %v after restart", time.Since(restarted))
	r.stop()

	// ---- grade ----
	for _, id := range all {
		if n := tap.count(toolUse(id)); n != 1 {
			t.Errorf("%s reached the wire %d times, want exactly once", id, n)
		}
	}
	if n := tap.count(func(ev *m1pv1.Event) bool { return ev.GetSessionStart() != nil }); n != 1 {
		t.Errorf("SessionStart on the wire %d times, want 1", n)
	}
	if n := tap.count(func(ev *m1pv1.Event) bool {
		return ev.GetTurn().GetInitiator() == m1pv1.Initiator_INITIATOR_AGENT
	}); n != 1 {
		t.Errorf("the dead-window Stop's Turn{AGENT} on the wire %d times, want 1 (fail-open allow must still spill the observer event)", n)
	}
	if n := tap.count(func(ev *m1pv1.Event) bool { return ev.GetSessionEnd() != nil }); n != 1 {
		t.Errorf("the dead-window SessionEnd on the wire %d times, want 1 (an unreceipted drain barrier must spill)", n)
	}
	if n := tap.count(func(ev *m1pv1.Event) bool { return ev.GetUsage().GetOutputTokens() == 9 }); n != 1 {
		t.Errorf("the session's Usage on the wire %d times, want 1 — daemon-down transcript capture is late, not lost", n)
	}
	// The ledger: nothing the ring could lose was lost. CRC_LOSS is the one
	// row a SIGKILL may legitimately raise — the single append in flight at
	// the signal, torn at a page boundary (chaos_kill9's finding) — and the
	// daemon was idle, so it is logged rather than expected.
	for _, d := range tap.droppedRows() {
		switch d.GetReason() {
		case m1pv1.DropReason_DROP_REASON_CRC_LOSS:
			if d.GetQuantity() > 1 {
				t.Errorf("recovery accounted %d CRC losses; at most one append can be in flight", d.GetQuantity())
			}
			t.Logf("chaos: recovery of the killed spool accounted %v", d)
		default:
			t.Errorf("Dropped%v on the wire — the ring lost something, or the outage was accounted as a loss it was not", d)
		}
	}
}

// TestChaosProxyKill9MidStream is leg 2: the supervised sidecar dies under
// a client that is mid-request. The client must see an error rather than a
// hang; the supervisor must bring the proxy back (backoff, new port); and
// once the crash-loop breaker trips, D-CM's FAILED arm must revert the
// base-URL fragment and receipt the bypass window (04 :81).
//
// Mid-request, not mid-response: supervise.ProxyChild spawns the proxy with a
// fixed `--mode sidecar` argv and no `--upstream` passthrough, so the
// daemon-supervised proxy can only forward to api.anthropic.com. A response
// stream from a local fake upstream is therefore unreachable through the
// real daemon; what IS reachable is a request the proxy is still reading
// when it dies, which exercises the same client-side property.
func TestChaosProxyKill9MidStream(t *testing.T) {
	bins := chaosBuild(t)
	r := newChaosRig(t, bins)
	// The API-key regime, which is the only regime that spawns a proxy
	// (04 §1.2), and the sidecar binary the daemon should find.
	r.env = append(r.env, "ANTHROPIC_API_KEY=sk-ant-chaos", "MARK1_PROXY="+bins.proxy)
	settings := filepath.Join(r.home, ".claude", "settings.json")
	const userSettings = "{\n  \"model\": \"opus\"\n}\n"
	if err := os.MkdirAll(filepath.Dir(settings), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settings, []byte(userSettings), 0o600); err != nil {
		t.Fatal(err)
	}

	r.startDaemon()
	portFile := claudecode.ProxyPortPath(r.state)
	pid, port := r.waitProxy(0)

	// `mark1 enable`'s forward half, so there is a fragment for FAILED to
	// revert: the provisioner probes the live proxy and writes the pointer.
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-chaos")
	if _, err := (&claudecode.Adapter{Home: r.home, StateDir: r.state}).ApplyProxyPointer(); err != nil {
		t.Fatalf("ApplyProxyPointer against the supervised proxy: %v", err)
	}
	if b, err := os.ReadFile(settings); err != nil || !bytes.Contains(b, []byte("ANTHROPIC_BASE_URL")) {
		t.Fatalf("setup: the base-URL fragment was not provisioned (%v):\n%s", err, b)
	}

	// supervise.BreakerMax crashes are restarted; the next one trips.
	for i := 1; i <= supervise.BreakerMax+1; i++ {
		// A client mid-request: headers half-sent, the proxy waiting for the
		// rest. hyper answers the moment the head is complete, so this is the
		// longest a request can be "in flight" without an upstream.
		conn, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port))
		if err != nil {
			t.Fatalf("kill %d: dial proxy: %v", i, err)
		}
		if _, err := fmt.Fprintf(conn, "POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n", port); err != nil {
			t.Fatalf("kill %d: write: %v", i, err)
		}
		if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
			t.Fatalf("kill %d: SIGKILL %d: %v", i, pid, err)
		}
		// Clean error, not a hang: the kernel closes the dead process's
		// sockets, so the client's read must fail promptly — and with a
		// connection error, not the deadline this harness sets as a backstop.
		if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		started := time.Now()
		var buf [1]byte
		switch _, err := conn.Read(buf[:]); {
		case err == nil:
			t.Fatalf("kill %d: the dead proxy answered %#x", i, buf[0])
		case errors.Is(err, os.ErrDeadlineExceeded):
			t.Fatalf("kill %d: the client hung on a dead proxy for %v", i, time.Since(started))
		}
		_ = conn.Close()
		if i <= supervise.BreakerMax {
			// Availability: the supervisor reaps, backs off, respawns — a new
			// pid, a new port file. The wait spans 04 :80's backoff (base
			// 500 ms, ×2, cap 60 s, jittered), so it is generous.
			pid, port = r.waitProxy(pid)
		}
	}

	// FAILED: 04 :81's two obligations.
	waitUpTo(t, 30*time.Second, "the base-URL fragment to be reverted on FAILED (D-CM)", func() bool {
		b, err := os.ReadFile(settings)
		return err == nil && string(b) == userSettings
	})
	if _, err := os.Stat(portFile); !os.IsNotExist(err) {
		t.Errorf("proxy.port survived FAILED (%v): it names a freed port for as long as the daemon runs", err)
	}
	if pids := childrenNamed(t, r.daemon.Process.Pid, "mark1-proxy"); len(pids) != 0 {
		t.Errorf("a proxy is still running after FAILED: pids %v", pids)
	}
	r.stop()

	// The receipt, read cold off the spool the daemon just drained.
	sp, err := spool.Open(spool.Config{Dir: filepath.Join(r.state, "spool")})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sp.Close() }()
	got := spooledCoverage(t, sp)
	if len(got) != 1 {
		t.Fatalf("coverage transitions = %d, want exactly 1 — FAILED opened an unreceipted bypass window", len(got))
	}
	if got[0].GetReasonCode() != coverage.ReasonProxyFailed || got[0].GetKind() != m1pv1.CoverageKind_COVERAGE_KIND_BYPASS {
		t.Errorf("transition = %v/%q, want BYPASS/%s", got[0].GetKind(), got[0].GetReasonCode(), coverage.ReasonProxyFailed)
	}
	if got[0].GetDurationMs() != 0 {
		t.Errorf("duration_ms = %d, want 0: FAILED is terminal, the window is a bypass_start", got[0].GetDurationMs())
	}
}

// waitProxy waits for a supervised proxy whose pid is not `prev` and whose
// port file names it, returning both. The port file is written by the proxy
// after it binds, so its presence is also the "listening" signal.
func (r *chaosRig) waitProxy(prev int) (pid, port int) {
	r.t.Helper()
	pid = r.waitChild("mark1-proxy", prev)
	waitUpTo(r.t, 10*time.Second, "the respawned mark1-proxy to publish its port", func() bool {
		b, err := os.ReadFile(claudecode.ProxyPortPath(r.state))
		if err != nil {
			return false
		}
		p, err := strconv.Atoi(strings.TrimSpace(string(b)))
		if err != nil || p == 0 {
			return false
		}
		port = p
		return true
	})
	return pid, port
}

// childrenNamed lists ppid's live children with the given comm, from
// /proc/<pid>/stat ("pid (comm) state ppid ..."). stat is world-readable even
// for a non-dumpable process, which the hardened proxy is.
func childrenNamed(t *testing.T, ppid int, comm string) []int {
	t.Helper()
	ents, err := os.ReadDir("/proc")
	if err != nil {
		t.Fatal(err)
	}
	var out []int
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join("/proc", e.Name(), "stat"))
		if err != nil {
			continue
		}
		// comm may contain spaces; it is bracketed, so split on the last ')'.
		i := bytes.LastIndexByte(b, ')')
		if i < 0 {
			continue
		}
		name := string(b[bytes.IndexByte(b, '(')+1 : i])
		f := strings.Fields(string(b[i+1:]))
		// f[0] = state, f[1] = ppid. A zombie is a reaped-but-not-waited
		// child: not live, not ours to count.
		if name == comm && len(f) > 1 && f[1] == strconv.Itoa(ppid) && f[0] != "Z" {
			out = append(out, pid)
		}
	}
	return out
}

// TestChaosCortexdKill9 is leg 3: the per-workspace cortexd (04 §6.7, the
// other child 04 §1.2 names) dies under the daemon's supervision. Its death
// costs ranked maps and nothing else, so what must come back is the MCP wall:
// a fresh child, a fresh port in the store's mcp.json, the token-less and the
// stale-token requests refused and the tokened one served — after 04 :80's
// backoff, not before it. A daemon that stops spawning cortexd for an enabled
// root fails this leg at the first wait, never skips it.
func TestChaosCortexdKill9(t *testing.T) {
	bins := chaosBuild(t)
	cargo := exec.Command("cargo", "build", "-p", "cortexd", "--locked")
	cargo.Dir = bins.root
	if b, err := cargo.CombinedOutput(); err != nil {
		t.Fatalf("cargo build cortexd: %v\n%s", err, b)
	}
	r := newChaosRig(t, bins)
	r.env = append(r.env, "MARK1_CORTEXD="+filepath.Join(bins.root, "target", "debug", "cortexd"))
	// An enabled workspace with something in it to index.
	root := filepath.Join(r.home, "ws")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\n\nfunc main() {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	canonRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	ws := `{"version":1,"workspaces":[{"path":"` + canonRoot + `","enabled_at":"2026-09-15T00:00:00Z"}]}`
	if err := os.WriteFile(filepath.Join(r.state, "workspaces.json"), []byte(ws), 0o600); err != nil {
		t.Fatal(err)
	}
	store := filepath.Join(r.state, "cortex", cortex.WorkspaceID(canonRoot))

	r.startDaemon()
	pid := r.waitChild("cortexd", 0)
	port, token := waitMCP(t, store, 0)
	mcpWall(t, port, token, "")

	killed := time.Now()
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	// Restarted, with backoff: Backoff.Next never draws below the base
	// (04 :80), so a respawn faster than that is a supervisor that is not
	// backing off — the crash-loop shape the breaker exists for.
	pid2 := r.waitChild("cortexd", pid)
	if since := time.Since(killed); since < supervise.BackoffBase {
		t.Errorf("cortexd respawned %v after the kill, under the %v backoff base", since, supervise.BackoffBase)
	}
	// A fresh per-boot token: the old one is a wall the new child never
	// built, so it must be refused like any other wrong bearer.
	port2, token2 := waitMCP(t, store, port)
	mcpWall(t, port2, token2, token)
	t.Logf("chaos: cortexd %d killed, %d serving MCP again on :%d %v later", pid, pid2, port2, time.Since(killed))
	r.stop()
}

// waitChild waits for a child of the daemon named comm whose pid is not prev.
// The deadline clears one backoff at 04 :80's constants — the fifth draw is
// bounded by 16 s (base 500 ms doubling, jittered) — with runner headroom.
func (r *chaosRig) waitChild(comm string, prev int) (pid int) {
	r.t.Helper()
	waitUpTo(r.t, 30*time.Second, "a (re)spawned "+comm, func() bool {
		pids := childrenNamed(r.t, r.daemon.Process.Pid, comm)
		if len(pids) != 1 || pids[0] == prev {
			return false
		}
		pid = pids[0]
		return true
	})
	return pid
}

// waitMCP waits for the store's mcp.json to name a port other than prev —
// cortexd binds :0 and rewrites the discovery file on every boot.
func waitMCP(t *testing.T, store string, prev int) (port int, token string) {
	t.Helper()
	waitUpTo(t, 45*time.Second, "cortexd to publish mcp.json", func() bool {
		b, err := os.ReadFile(filepath.Join(store, "mcp.json"))
		if err != nil {
			return false
		}
		var d struct {
			Port  int    `json:"port"`
			Token string `json:"token"`
		}
		if json.Unmarshal(b, &d) != nil || d.Port == 0 || d.Port == prev || d.Token == "" {
			return false
		}
		port, token = d.Port, d.Token
		return true
	})
	return port, token
}

// mcpWall is the loopback wall as 08 §4.5 lists it: no bearer ⇒ 401
// M1E-1002, a stale bearer (from before a restart) ⇒ the same; the per-boot
// bearer ⇒ served (a JSON-RPC ping).
func mcpWall(t *testing.T, port int, token, stale string) {
	t.Helper()
	post := func(bearer string) (int, string) {
		req, err := http.NewRequest(http.MethodPost, "http://127.0.0.1:"+strconv.Itoa(port)+"/mcp",
			strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		res, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
		if err != nil {
			t.Fatalf("MCP on :%d: %v", port, err)
		}
		defer func() { _ = res.Body.Close() }()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b)
	}
	for _, bad := range []string{"", stale} {
		if code, body := post(bad); code != http.StatusUnauthorized || !strings.Contains(body, "M1E-1002") {
			t.Fatalf("MCP request with bearer %q: %d %s, want 401 M1E-1002 — the wall is down", bad, code, body)
		}
	}
	if code, body := post(token); code != http.StatusOK || !strings.Contains(body, `"result"`) {
		t.Fatalf("tokened MCP ping: %d %s, want a served result", code, body)
	}
}
