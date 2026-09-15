//go:build unix

package claudecode

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"google.golang.org/protobuf/proto"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/fabric"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/fabric/fabrictest"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/verdict"
)

// The cross-language half of the C8 acceptance: the REAL mark1-hookshim binary
// driven by the pinned Stop-hook fixture against a Go daemon, so the
// vendor-facing contract (what lands on the agent's stdin/stdout) and the
// fabric contract (what mark1d receives) are asserted against the shipping
// bytes, not a Go re-implementation of them. Same discipline as
// internal/spill's TestDrainRustSealedFixture, live-socket instead of frozen.

var (
	shimOnce sync.Once
	shimPath string
	shimErr  error
)

func repoRoot(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("..", "..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

// buildShim builds the shipping binary once per test binary. --locked so the
// bytes under test are the committed dependency set, matching the CI gate.
func buildShim(t *testing.T) string {
	t.Helper()
	shimOnce.Do(func() {
		if _, err := exec.LookPath("cargo"); err != nil {
			shimErr = err
			return
		}
		root := repoRoot(t)
		cmd := exec.Command("cargo", "build", "-p", "mark1-hookshim", "--locked")
		cmd.Dir = root
		if out, err := cmd.CombinedOutput(); err != nil {
			shimErr = errors.New(string(out))
			return
		}
		shimPath = filepath.Join(root, "target", "debug", "mark1-hookshim")
	})
	if shimErr != nil {
		t.Skipf("cannot build mark1-hookshim (this suite asserts the real binary, so it cannot stand in for it): %v", shimErr)
	}
	return shimPath
}

func hookFixture(t *testing.T, event string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "conformance", "hooks", "claudecode", "v2.1.251", "hooks", event+".json"))
	if err != nil {
		t.Fatalf("pinned %s fixture (a vacuous pass proves nothing): %v", event, err)
	}
	return b
}

// stopDeadlineMs is D-AU's 250 ms gate budget minus 08 §4.4's 10 ms shim
// margin — the number the shim must put on the wire, spelled out here so a
// silent map edit cannot move it. It is NOT the agent's 30 s hook timeout,
// which 08 §4.4 bounds only from above: spending the whole ceiling makes a
// wedged daemon cost 31.4 s per turn against 217 ms for an absent one, and
// 250 ms is already 50× the ≤5 ms cache read 04 §2.3 specifies this gate to be.
const stopDeadlineMs = 250 - 10

// blockRow is 08 §5.1's Stop row, transcribed byte for byte. The shim's stdout
// is compared against this template with the placeholder replaced by the
// JSON-encoded reason — key order, absence of whitespace, absence of a
// `continue` key and absence of a trailing newline are all part of the
// contract, and a paraphrase asserts none of them.
const blockRow = `{"decision":"block","reason":"<verdict + failure evidence as continuation reason>"}`

const blockPlaceholder = `"<verdict + failure evidence as continuation reason>"`

// daemon is the fake mark1d. It decodes with the SHIPPING framing decoder and
// holds the same FabricFrame dialect session.frame does: every payload is one
// m1p.v1.FabricFrame (D-U), the first frame on a connection MUST be Hello
// (08 §4.3 step 2), and an undecodable or unexpected arm is a protocol error
// reported to the test. The tolerance a fake may afford is exactly the
// tolerance the real daemon has, which is none — a fallback here would hide
// the cross-language drift this suite exists to catch.
type daemon struct {
	sock    string
	events  chan *m1pv1.Event
	queries chan *m1pv1.GateQuery
	errs    chan error
	verdict *m1pv1.GateVerdict // the answer to every GateQuery
}

func newDaemon(t *testing.T, xdg string, v *m1pv1.GateVerdict) *daemon {
	t.Helper()
	d := &daemon{
		sock:    filepath.Join(xdg, "omium-mark1", "m1p.sock"),
		events:  make(chan *m1pv1.Event, 8),
		queries: make(chan *m1pv1.GateQuery, 8),
		errs:    make(chan error, 8),
		verdict: v,
	}
	ln := listen(t, d.sock)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go d.serve(conn)
		}
	}()
	return d
}

func listen(t *testing.T, sock string) net.Listener {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(sock), 0o700); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

func (d *daemon) fail(err error) {
	select {
	case d.errs <- err:
	default:
	}
}

func (d *daemon) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	var dec fabric.Decoder
	buf := make([]byte, 4096)
	helloed := false
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			dec.Push(buf[:n])
			for {
				payload, _, derr := dec.Next()
				if derr != nil {
					d.fail(derr)
					return
				}
				if payload == nil {
					break
				}
				var f m1pv1.FabricFrame
				if uerr := proto.Unmarshal(payload, &f); uerr != nil {
					d.fail(fmt.Errorf("payload is not a m1p.v1.FabricFrame (D-U): %w", uerr))
					return
				}
				switch arm := f.GetKind().(type) {
				case *m1pv1.FabricFrame_Hello:
					if helloed {
						d.fail(errors.New("a second Hello on one connection"))
						return
					}
					helloed = true
					if arm.Hello.GetComponent() != "mark1-hookshim" {
						d.fail(fmt.Errorf("Hello.component = %q", arm.Hello.GetComponent()))
					}
					d.reply(conn, &m1pv1.FabricFrame{Kind: &m1pv1.FabricFrame_HelloAck{
						HelloAck: &m1pv1.HelloAck{Accepted: true, MaxFrame: fabric.MaxFrame},
					}})
				case *m1pv1.FabricFrame_Event:
					if !helloed {
						d.fail(errors.New("M1E-4003: first frame is not Hello (08 §4.3)"))
						return
					}
					d.events <- arm.Event
				case *m1pv1.FabricFrame_GateQuery:
					if !helloed {
						d.fail(errors.New("M1E-4003: first frame is not Hello (08 §4.3)"))
						return
					}
					d.queries <- arm.GateQuery
					d.reply(conn, &m1pv1.FabricFrame{Kind: &m1pv1.FabricFrame_GateVerdict{GateVerdict: d.verdict}})
				default:
					d.fail(fmt.Errorf("unexpected FabricFrame arm %T from a writer", arm))
					return
				}
			}
		}
		if err != nil {
			return
		}
	}
}

func (d *daemon) reply(conn net.Conn, f *m1pv1.FabricFrame) {
	b, err := proto.Marshal(f)
	if err != nil {
		d.fail(err)
		return
	}
	if err := fabric.WriteFrame(conn, b); err != nil {
		d.fail(err)
	}
}

// query / event block for one arm, failing on any dialect error the daemon saw
// — a shim that spoke the wrong dialect never delivers, so the error channel
// is what turns a hang into a diagnosis.
func (d *daemon) query(t *testing.T) *m1pv1.GateQuery {
	t.Helper()
	select {
	case q := <-d.queries:
		return q
	case err := <-d.errs:
		t.Fatalf("the daemon refused what the shim wrote: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("no GateQuery reached the daemon")
	}
	return nil
}

func (d *daemon) event(t *testing.T) *m1pv1.Event {
	t.Helper()
	select {
	case e := <-d.events:
		return e
	case err := <-d.errs:
		t.Fatalf("the daemon refused what the shim wrote: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("no Event reached the daemon")
	}
	return nil
}

type shimRun struct {
	ok     bool
	stdout string
	stderr string
	wall   time.Duration
}

func runShim(t *testing.T, home, xdg string, stdin []byte) shimRun {
	t.Helper()
	cmd := exec.Command(buildShim(t))
	cmd.Env = append(os.Environ(), "HOME="+home, "XDG_RUNTIME_DIR="+xdg)
	cmd.Env = append(cmd.Env, "MARK1_DISABLE=")
	var out, errb strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errb
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// The shim's off/fail-closed paths exit before reading stdin, so EPIPE
	// here is a behavior under test, not a harness fault.
	if _, err := in.Write(stdin); err != nil && !errors.Is(err, io.ErrClosedPipe) {
		_ = in.Close()
		t.Fatalf("stdin write: %v", err)
	}
	_ = in.Close()
	waitErr := cmd.Wait()
	return shimRun{ok: waitErr == nil, stdout: out.String(), stderr: errb.String(), wall: time.Since(started)}
}

// TestShimStopGateBlocksTheAgent is 08 §5.1's below-the-knee branch end to
// end: the real shim asks the gate, and a BLOCK verdict comes back to Claude
// Code as the row's exact JSON. The comparison is byte-for-byte against the
// transcribed row because every character of it is contract — Claude Code
// discards stdout it cannot parse, which is silently an allow.
func TestShimStopGateBlocksTheAgent(t *testing.T) {
	home, xdg := t.TempDir(), fabrictest.SocketDir(t)
	d := newDaemon(t, xdg, &m1pv1.GateVerdict{
		Decision:    m1pv1.GateDecision_GATE_DECISION_BLOCK,
		Verdict:     m1pv1.Verdict_VERDICT_VIOLATED,
		Posterior:   []float64{0.02, 0.95, 0.02, 0.01},
		Reason:      "two anchors report the build is broken",
		EvidenceRef: "ev/9f2c",
	})

	run := runShim(t, home, xdg, hookFixture(t, "Stop"))
	if !run.ok {
		t.Fatalf("shim must exit 0 on every path (08 §5.1: exit 2 is never used): stderr=%q", run.stderr)
	}

	q := d.query(t)
	if q.GetGate() != m1pv1.GateKind_GATE_KIND_STOP {
		t.Fatalf("gate kind %v, want STOP", q.GetGate())
	}
	if q.GetDeadlineMs() != stopDeadlineMs {
		t.Fatalf("deadline_ms = %d, want %d (D-AU's 250 ms budget − 08 §4.4's 10 ms)", q.GetDeadlineMs(), stopDeadlineMs)
	}

	reason, err := json.Marshal("two anchors report the build is broken [evidence: ev/9f2c]")
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(blockRow, blockPlaceholder, string(reason), 1)
	if run.stdout != want {
		t.Fatalf("stdout is not 08 §5.1's block row\n got: %s\nwant: %s", run.stdout, want)
	}

	// The gate path also delivers the observer event on the same connection
	// (08 §4.3 step 4) — gating a turn must not cost the ledger the turn.
	ev := d.event(t)
	if got := ev.GetTurn().GetInitiator(); got != m1pv1.Initiator_INITIATOR_AGENT {
		t.Fatalf("Stop delivered %v, want the observer Turn{AGENT} (maps/claudecode.json)", got)
	}
	if len(ev.GetEventId()) != 16 || ev.GetEventId()[6]>>4 != 7 {
		t.Fatalf("event_id is not a UUIDv7: %x", ev.GetEventId())
	}
}

// TestShimStopGateAllowsSilently is the row's other branch: an ALLOW verdict
// means "exit 0 with no decision", byte-identical to Mark 1 being absent.
//
// The assertion is the absence of a `decision`, not the absence of all output:
// 08 §5.1's at-the-knee branch also promises a `systemMessage` surfacing
// verdict + evidence to the human, and m1p.v1.GateVerdict has no field that
// could carry it and no way to say "at the knee" (GateDecision is ALLOW|BLOCK).
// That sub-row is BLOCKED on a lead ruling; pinning stdout == "" here would
// quietly bless its absence as the contract.
func TestShimStopGateAllowsSilently(t *testing.T) {
	home, xdg := t.TempDir(), fabrictest.SocketDir(t)
	d := newDaemon(t, xdg, &m1pv1.GateVerdict{
		Decision: m1pv1.GateDecision_GATE_DECISION_ALLOW,
		Verdict:  m1pv1.Verdict_VERDICT_SATISFIED,
		Reason:   "knee governor: stop at attempt 3",
	})

	run := runShim(t, home, xdg, hookFixture(t, "Stop"))
	if !run.ok {
		t.Fatalf("allow must exit 0: stderr=%q", run.stderr)
	}
	if strings.Contains(run.stdout, `"decision"`) {
		t.Fatalf("allow emitted a decision Claude Code acts on: %q", run.stdout)
	}
	if run.wall > 5*time.Second {
		t.Fatalf("allow took %v — the 30 s fragment budget is the agent's stall, not a target", run.wall)
	}
	if q := d.query(t); q.GetDeadlineMs() != stopDeadlineMs {
		t.Fatalf("deadline_ms = %d, want %d", q.GetDeadlineMs(), stopDeadlineMs)
	}
}

// TestShimStopGateAgainstTheRealServer removes the last re-implementation from
// the loop: the shipping fabric.Server (handshake, unwrap, dispatch) answering
// the shipping fabric.Gate over a live socket, driven by the shipping shim. If
// either language's dialect drifts, this is where it surfaces — nothing here
// is a Go restatement of what the daemon does.
func TestShimStopGateAgainstTheRealServer(t *testing.T) {
	home, xdg := t.TempDir(), fabrictest.SocketDir(t)
	events := make(chan []byte, 8)
	srv := fabric.NewServer(func(_ context.Context, inner []byte) error {
		events <- inner
		return nil
	}, nil)
	// A violated verdict below the knee: the one cache state that blocks.
	task := verdict.TaskID{0xa5}
	g := fabric.NewGate(stopReader{task: verdict.Cached{
		Verdict: &m1pv1.VerdictEvent{
			Stage:     m1pv1.VerdictStage_VERDICT_STAGE_PROVISIONAL,
			Verdict:   m1pv1.Verdict_VERDICT_VIOLATED,
			Posterior: []float64{0.02, 0.95, 0.02, 0.01},
		},
		Knee: verdict.KneeState{N: 2, PLCB: 0.4, VTask: 10, CostN: 1, CostBasis: "usd"},
	}}, verdict.NewBlocks(), t.TempDir())
	// The daemon's segmenter stands in as a constant: this test is about the two
	// languages agreeing on the wire, and D-AA makes an unresolved task a miss,
	// so without a resolver the gate would answer ALLOW and prove nothing.
	g.TaskFor = func(session, _ [16]byte) ([16]byte, bool) { return task, session != [16]byte{} }
	srv.SetGate(g)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, listen(t, filepath.Join(xdg, "omium-mark1", "m1p.sock"))) }()
	t.Cleanup(srv.Close)

	run := runShim(t, home, xdg, hookFixture(t, "Stop"))
	if !run.ok {
		t.Fatalf("shim must exit 0: stderr=%q", run.stderr)
	}
	var got struct {
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
		Continue *bool  `json:"continue"`
	}
	if err := json.Unmarshal([]byte(run.stdout), &got); err != nil {
		t.Fatalf("the real server's BLOCK did not reach the agent as JSON (%v): %q", err, run.stdout)
	}
	if got.Decision != "block" || got.Continue != nil {
		t.Fatalf("08 §5.1: block is `decision`, never `continue:false`: %q", run.stdout)
	}
	if !strings.Contains(got.Reason, "knee") {
		t.Fatalf("the reason does not carry the gate's evidence: %q", got.Reason)
	}
	select {
	case inner := <-events:
		ev := &m1pv1.Event{}
		if err := proto.Unmarshal(inner, ev); err != nil {
			t.Fatalf("the server admitted bytes that are not an Event: %v", err)
		}
		if ev.GetTurn().GetInitiator() != m1pv1.Initiator_INITIATOR_AGENT {
			t.Fatalf("Stop admitted as %v", ev.GetTurn().GetInitiator())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the gate answered but the turn never reached admission")
	}
}

// stopReader is the gate's whole verdict surface: one task's cached entry. The
// shim sends an EMPTY task_id (it has no way to learn one), so the key is
// whatever the gate's TaskFor resolves that connection's session to — never the
// zero TaskID, which D-AA reserves as the "unresolved" sentinel.
type stopReader map[verdict.TaskID]verdict.Cached

func (r stopReader) Get(id verdict.TaskID) (verdict.Cached, bool) { e, ok := r[id]; return e, ok }

// TestFakeDaemonIsAsStrictAsTheRealOne guards the harness itself. This suite's
// whole value is that a dialect drift between the two languages shows up here;
// a fake that tolerates what session.frame refuses converts that signal into a
// green run. So the two refusals the real daemon makes are asserted on the fake
// directly: a payload that is not a FabricFrame (the pre-D-U dialect, where the
// payload was a bare Event), and any first frame that is not Hello (M1E-4003,
// 08 §4.3 step 2).
func TestFakeDaemonIsAsStrictAsTheRealOne(t *testing.T) {
	xdg := fabrictest.SocketDir(t)
	d := newDaemon(t, xdg, nil)

	ev, err := proto.Marshal(&m1pv1.FabricFrame{Kind: &m1pv1.FabricFrame_Event{Event: &m1pv1.Event{}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		payload []byte
	}{
		// field 1, length-delimited, claiming 5 bytes and carrying 2.
		{"not a FabricFrame", []byte{0x0a, 0x05, 0x01, 0x02}},
		{"first frame is not Hello", ev},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := net.Dial("unix", d.sock)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			if err := fabric.WriteFrame(conn, tc.payload); err != nil {
				t.Fatal(err)
			}
			select {
			case <-d.errs:
			case e := <-d.events:
				t.Fatalf("the fake daemon accepted what mark1d closes on: %v", e)
			case <-time.After(5 * time.Second):
				t.Fatal("the fake daemon neither refused nor delivered")
			}
		})
	}
}

// TestShimStopHookFailsOpenWhenDaemonUnreachable is 04 §5 step 5's other half:
// with no daemon at all the Stop hook still exits 0 with no decision, well
// inside the fragment's 30 s Stop budget. A shim that emitted a block here
// would wedge a session whenever mark1d is down.
func TestShimStopHookFailsOpenWhenDaemonUnreachable(t *testing.T) {
	home, xdg := t.TempDir(), t.TempDir()
	run := runShim(t, home, xdg, hookFixture(t, "Stop"))
	if !run.ok {
		t.Fatalf("unreachable daemon must still exit 0: stderr=%q", run.stderr)
	}
	if strings.Contains(run.stdout, `"decision"`) {
		t.Fatalf("unreachable daemon produced a decision: %q", run.stdout)
	}
	if run.wall > 5*time.Second {
		t.Fatalf("Stop took %v — the 30 s fragment budget is the agent's stall, not a target", run.wall)
	}
}

// TestShimSessionStartInjectsNothing pins the honest state of the map seam:
// the fragment registers SessionStart for injection, but no m1p.v1 message
// carries cortexd's budgeted ranked map (04 §6.4) to the shim — fabric.proto
// defines Hello/Gate/Flush and nothing else. So the shim injects NOTHING and
// emits the SessionStart lifecycle event instead of fabricating a map. This
// asserts the accounting that DOES exist; it goes red the day a map reaches
// the hook, which is when additionalContext must start being asserted.
func TestShimSessionStartInjectsNothing(t *testing.T) {
	home, xdg := t.TempDir(), fabrictest.SocketDir(t)
	d := newDaemon(t, xdg, nil)

	run := runShim(t, home, xdg, hookFixture(t, "SessionStart"))
	if !run.ok {
		t.Fatalf("SessionStart must exit 0: stderr=%q", run.stderr)
	}
	if run.stdout != "" {
		t.Fatalf("a map reached the hook (%q) — assert its budget and CortexInjection accounting here", run.stdout)
	}
	ss := d.event(t).GetSessionStart()
	if ss.GetAgent() != "claudecode" || ss.GetAgentVersion() != "2.1.251" {
		t.Fatalf("SessionStart accounting is not the pinned agent: %+v", ss)
	}
}
