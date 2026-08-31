//go:build unix

// Unix-tagged with the rest of this package: run() binds the fabric, and
// fabric.Listen refuses on Windows until 07 §5's named pipe lands (main_test.go).
package main

import (
	"context"
	"log/slog"
	"math"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/fabric"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/spool"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/verdict"
	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

// proofAnchor is the one verifier the proof bundle lists. A vote from any
// other id would contribute no likelihood at all (D-X), which is exactly the
// property that makes this test sensitive to the FromBundle mapping.
const proofAnchor = "ruff@cat-1"

// The posterior a single VIOLATED vote from proofAnchor produces under
// proofMatrices, computed by hand from the same numbers the code fuses:
// prior × the reject column, normalized. Written out rather than recomputed in
// the test so a change to either half is caught by the other.
var wantPosterior = [4]float64{
	0.55 * 0.02 / 0.3385,
	0.30 * 0.95 / 0.3385,
	0.10 * 0.30 / 0.3385,
	0.05 * 0.25 / 0.3385,
}

// proofMatrices is the applied-bundle slice the daemon boots on for this
// proof. kneeStops picks between the two economics the whole feature turns on:
//
//	false — p̂_LCB(n)·V(task) = 9.0 > c(n) = 0.5: another attempt is still
//	        worth paying for, so a VIOLATED verdict BLOCKS the agent's Stop
//	        and forces the retry (08 §5.1 "below the knee").
//	true  — 1.0 ≤ 5.0: the knee is reached, the retry loop is arrested and
//	        the agent is ALLOWED to stop.
//
// The rows carry an explicit PLCB, built here rather than decoded so these two
// tests pin the fusion+knee arithmetic alone; the bundle-decode path that feeds
// the same seam in production is what TestPhase2RetryLoopArrestedAtTheKnee
// exercises, through verdict.FromBundle.
func proofMatrices(kneeStops bool) verdict.BundleMatrices {
	plcb := 0.9
	cost := 0.5
	if kneeStops {
		plcb, cost = 0.1, 5.0
	}
	return verdict.BundleMatrices{
		Seq:    7,
		Priors: verdict.DefaultPriors,
		Verifiers: map[string]verdict.VerifierParams{
			proofAnchor: {Confusion: verdict.Confusion{
				{0.96, 0.02, 0.02}, // satisfied: accept, reject, abstain
				{0.04, 0.95, 0.01}, // violated
				{0.40, 0.30, 0.30}, // refused
				{0.35, 0.25, 0.40}, // error
			}},
		},
		Knee:      []verdict.KneeRow{{N: 1, CostN: cost, PLCB: &plcb}},
		VTask:     10.0,
		CostBasis: "usd",
	}
}

// startProofDaemon runs the real daemon (run → session: the assembled
// listener, capture, spool, verdict Engine and Gate) and returns its socket
// plus a stopper. The stopper cancels this daemon's own context: main() owns
// the signal set, so stopping one daemon never signals the test process and
// these tests stay safe to run in parallel with anything.
// m == nil is the no-bundle boot.
func startProofDaemon(t *testing.T, m *verdict.BundleMatrices) (string, func()) {
	t.Helper()
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	socket := filepath.Join(dir, "sock", "m1p.sock")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, slog.New(slog.NewTextHandler(os.Stderr, nil)), config{
			stateDir: stateDir,
			spoolDir: filepath.Join(dir, "spool"),
			socket:   socket,
			offPoll:  10 * time.Millisecond,
			matrices: m,
		})
	}()
	waitFor(t, "fabric socket", func() bool {
		_, err := os.Stat(socket)
		return err == nil
	})
	return socket, func() {
		t.Helper()
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("run returned %v, want clean exit", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("daemon did not exit on cancellation")
		}
	}
}

// fabricConn is the writer half of M1PL as a real writer speaks it: the
// shipping framing codec, the D-U FabricFrame envelope, the 08 §4.3 handshake.
// No daemon internals are reachable from here — everything below travels over
// the socket.
type fabricConn struct {
	t   *testing.T
	c   net.Conn
	dec fabric.Decoder
}

func dialFabric(t *testing.T, socket string, session [16]byte) *fabricConn {
	t.Helper()
	c, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	f := &fabricConn{t: t, c: c}
	f.send(&m1pv1.FabricFrame{Kind: &m1pv1.FabricFrame_Hello{Hello: &m1pv1.Hello{
		Component: "tests", Pid: uint32(os.Getpid()), Version: version, SessionId: session[:], // #nosec G115 -- pid fits
	}}})
	if ack := f.recv().GetHelloAck(); !ack.GetAccepted() {
		t.Fatalf("HelloAck accepted=false (max_frame %d)", ack.GetMaxFrame())
	}
	return f
}

func (f *fabricConn) send(fr *m1pv1.FabricFrame) {
	f.t.Helper()
	b, err := proto.Marshal(fr)
	if err != nil {
		f.t.Fatal(err)
	}
	if err := fabric.WriteFrame(f.c, b); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fabricConn) recv() *m1pv1.FabricFrame {
	f.t.Helper()
	if err := f.c.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		f.t.Fatal(err)
	}
	buf := make([]byte, 4096)
	for {
		payload, _, err := f.dec.Next()
		if err != nil {
			f.t.Fatal(err)
		}
		if payload != nil {
			fr := &m1pv1.FabricFrame{}
			if err := proto.Unmarshal(payload, fr); err != nil {
				f.t.Fatal(err)
			}
			return fr
		}
		n, err := f.c.Read(buf)
		if n > 0 {
			f.dec.Push(buf[:n])
			continue
		}
		f.t.Fatalf("fabric read: %v", err)
	}
}

// event stamps ev with a fresh UUIDv7 and the connection's session, then
// frames it. Body is the caller's — the oneof wrapper interface is unexported
// in the generated package and cannot be named from here.
func (f *fabricConn) event(session [16]byte, ev *m1pv1.Event) {
	f.t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		f.t.Fatal(err)
	}
	ev.EventId, ev.SessionId = id[:], session[:]
	f.send(&m1pv1.FabricFrame{Kind: &m1pv1.FabricFrame_Event{Event: ev}})
}

// prompt is the user turn that opens a task (ADR-0002 R1). Nothing in a
// session is gateable until one has arrived: D-AA makes an unresolved task a
// miss, so this is the event the whole verdict plane hangs off.
func (f *fabricConn) prompt(session [16]byte) {
	f.t.Helper()
	f.event(session, &m1pv1.Event{Body: &m1pv1.Event_Turn{
		Turn: &m1pv1.Turn{Initiator: m1pv1.Initiator_INITIATOR_HUMAN},
	}})
}

// vote sends one AnchorVote event — the shape the sandboxed anchor runner
// emits through the same capture door (anchors.Runner's Emitter). Its task_id
// is empty, exactly as a real anchor's is: the daemon's segmenter is the only
// party that knows which task the vote belongs to.
func (f *fabricConn) vote(session [16]byte, anchor string, v m1pv1.Verdict) {
	f.t.Helper()
	f.event(session, &m1pv1.Event{Body: &m1pv1.Event_AnchorVote{
		AnchorVote: &m1pv1.AnchorVote{AnchorId: anchor, Vote: v},
	}})
}

// gate sends a real GateQuery and returns the daemon's GateVerdict, under the
// deadline the shipping shim actually uses: the agent map's gate.budget_ms 250
// minus SHIM_MARGIN_MS 10 (D-AU). The previous 29_990 came from reading 08
// §5.1's 30 s as the shim's budget, which D-AU retired — and a 30 s deadline
// would have hidden the one failure that matters here, a daemon too slow to
// answer inside the real budget, because in production that times out and the
// gate fails open. The gate is a cache read; 240 ms is ~3 orders of magnitude
// of headroom.
func (f *fabricConn) gate() *m1pv1.GateVerdict {
	f.t.Helper()
	f.send(&m1pv1.FabricFrame{Kind: &m1pv1.FabricFrame_GateQuery{GateQuery: &m1pv1.GateQuery{
		Gate:       m1pv1.GateKind_GATE_KIND_STOP,
		DeadlineMs: 240,
	}}})
	v := f.recv().GetGateVerdict()
	if v == nil {
		f.t.Fatal("reply frame is not a GateVerdict")
	}
	return v
}

func assertPosterior(t *testing.T, got []float64) {
	t.Helper()
	if len(got) != 4 {
		t.Fatalf("posterior has %d classes, want 4", len(got))
	}
	for i, want := range wantPosterior {
		if math.Abs(got[i]-want) > 1e-9 {
			t.Fatalf("posterior[%d] = %.17g, want %.17g", i, got[i], want)
		}
	}
}

// TestStopGateBlocksBelowTheKnee is the Phase 2 gate reduced to a test, first
// half: the assembled daemon, one synthetic anchor result over the real
// fabric, one real GateQuery over the same connection, and a BLOCK back with
// the fused posterior and the knee arithmetic in its reason. Every link in the
// chain — FabricFrame unwrap, capture admission, the anchor→votes tee, the
// fusion Engine, the knee evaluation at publish, the cache, the gate handler —
// is the shipping one.
func TestStopGateBlocksBelowTheKnee(t *testing.T) {
	m := proofMatrices(false)
	socket, stop := startProofDaemon(t, &m)
	defer stop()

	session := uuid.New()
	c := dialFabric(t, socket, session)
	c.prompt(session)
	c.vote(session, proofAnchor, m1pv1.Verdict_VERDICT_VIOLATED)

	// Fusion is asynchronous by design (the recompute goroutine is the cache's
	// only writer), so the gate is polled: before the publish it answers the
	// M1E-5001 cache miss, which is a correct answer, not a failure.
	var v *m1pv1.GateVerdict
	waitFor(t, "the stop gate to BLOCK on the fused verdict", func() bool {
		v = c.gate()
		return v.GetDecision() == m1pv1.GateDecision_GATE_DECISION_BLOCK
	})
	if v.GetVerdict() != m1pv1.Verdict_VERDICT_VIOLATED {
		t.Fatalf("BLOCK carries verdict %v, want VIOLATED", v.GetVerdict())
	}
	assertPosterior(t, v.GetPosterior())
	if !strings.Contains(v.GetReason(), "below the knee") {
		t.Fatalf("BLOCK reason %q does not state the knee economics", v.GetReason())
	}
}

// TestStopGateAllowsAtTheKnee is the second half: identical setup, identical
// vote, identical fused verdict — only the knee row's economics differ, and
// the retry loop is arrested. The agent is allowed to stop.
func TestStopGateAllowsAtTheKnee(t *testing.T) {
	m := proofMatrices(true)
	socket, stop := startProofDaemon(t, &m)
	defer stop()

	session := uuid.New()
	c := dialFabric(t, socket, session)
	c.prompt(session)
	c.vote(session, proofAnchor, m1pv1.Verdict_VERDICT_VIOLATED)

	var v *m1pv1.GateVerdict
	waitFor(t, "the fused verdict to reach the gate", func() bool {
		v = c.gate()
		return v.GetVerdict() == m1pv1.Verdict_VERDICT_VIOLATED
	})
	if v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_ALLOW {
		t.Fatalf("decision %v at the knee, want ALLOW — the retry loop is not arrested", v.GetDecision())
	}
	assertPosterior(t, v.GetPosterior())
	if !strings.Contains(v.GetReason(), "knee governor") {
		t.Fatalf("allow reason %q does not name the knee governor", v.GetReason())
	}
}

// TestGateAllowsWithNoBundleNoVotesNoCache pins the three states 04 §2.3 calls
// normal: no bundle (fail-static built-ins), no anchor consented (no votes)
// and no cache entry. The daemon must boot and answer allow, never error.
func TestGateAllowsWithNoBundleNoVotesNoCache(t *testing.T) {
	socket, stop := startProofDaemon(t, nil)
	defer stop()

	v := dialFabric(t, socket, uuid.New()).gate()
	if v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_ALLOW {
		t.Fatalf("decision %v with no bundle and no votes, want ALLOW", v.GetDecision())
	}
	if !strings.Contains(v.GetReason(), fabric.CodeGateTimeout) {
		t.Fatalf("cache-miss reason %q, want the %s posture", v.GetReason(), fabric.CodeGateTimeout)
	}
	// The wiring must also be live, not absent: the M1E-5001 the shim would
	// have seen from an unwired listener is a different sentence entirely.
	if strings.Contains(v.GetReason(), "no verdict subsystem") {
		t.Fatal("the fabric listener has no gate wired — session.go's fail-open stub answered")
	}
}

// TestTwoSessionsDoNotShareAVerdict is the defect S1 reduced to a test, against
// the assembled daemon: two developers, two connections, two authenticated
// sessions. A votes VIOLATED under matrices that block; B votes NOTHING. Before
// D-AA both sessions' empty task_id collapsed to the all-zero TaskID, so B was
// answered BLOCK carrying A's posterior and A's evidence — one developer's
// failing task stopping another developer's unrelated one.
func TestTwoSessionsDoNotShareAVerdict(t *testing.T) {
	m := proofMatrices(false)
	socket, stop := startProofDaemon(t, &m)
	defer stop()

	sessionA, sessionB := uuid.New(), uuid.New()
	a := dialFabric(t, socket, sessionA)
	b := dialFabric(t, socket, sessionB)
	a.prompt(sessionA)
	b.prompt(sessionB) // B has a task of its own; what it does not have is evidence
	a.vote(sessionA, proofAnchor, m1pv1.Verdict_VERDICT_VIOLATED)

	waitFor(t, "session A to BLOCK on its own vote", func() bool {
		return a.gate().GetDecision() == m1pv1.GateDecision_GATE_DECISION_BLOCK
	})
	// A is blocking NOW, so any leak into B is live at this instant.
	v := b.gate()
	if v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_ALLOW {
		t.Fatalf("session B answered %v %q with zero votes of its own — session A's evidence crossed", v.GetDecision(), v.GetReason())
	}
	if len(v.GetPosterior()) != 0 {
		t.Fatalf("session B's allow carries a posterior %v — it can only be session A's", v.GetPosterior())
	}
	if !strings.Contains(v.GetReason(), fabric.CodeGateTimeout) {
		t.Fatalf("session B's reason %q, want the %s cache-miss posture", v.GetReason(), fabric.CodeGateTimeout)
	}
}

// sessionEnd closes the session, which is what forces every still-open task
// through closeOpen — the seam D-AS lives on.
func (f *fabricConn) sessionEnd(session [16]byte) {
	f.t.Helper()
	f.event(session, &m1pv1.Event{Body: &m1pv1.Event_SessionEnd{SessionEnd: &m1pv1.SessionEnd{}}})
}

// TestAssembledDaemonResolvesItsDenominator is D-AS at the only level that can
// observe it. internal/taskseg's TestFastAnchorOnlySessionResolvesItsDenominator
// assigns s.Verdict itself, so it proves the state machine and is structurally
// blind to cmd/main.go leaving the hook nil — which it did, shipping a daemon
// whose every close was RESOLUTION_UNRESOLVED_SESSION_END while that unit test
// stayed green. Nothing between the two levels asserted the wire existed.
//
// Unresolved is the one denominator value indistinguishable from "Mark 1 was
// not there", so a daemon that reports 100% unresolved does not report a weak
// TVO — it reports no TVO, and every number derived from it is vacuous.
//
// Everything here crosses the socket: the daemon is the assembled run(), and
// the only thing the test writes is one human Turn, one ToolUse and one vote.
func TestAssembledDaemonResolvesItsDenominator(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	spoolDir := filepath.Join(dir, "spool")
	socket := filepath.Join(dir, "sock", "m1p.sock")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", filepath.Join(dir, "home")) // keep the tailer off the real ~/.claude

	m := proofMatrices(false)
	stop := runDaemon(t, config{
		stateDir: stateDir,
		spoolDir: spoolDir,
		socket:   socket,
		offPoll:  10 * time.Millisecond,
		matrices: &m,
	})
	waitFor(t, "fabric socket", func() bool {
		_, err := os.Stat(socket)
		return err == nil
	})

	session := uuid.New()
	c := dialFabric(t, socket, session)
	c.prompt(session) // the human turn that opens the task (ADR-0002 R1)
	c.toolUse(session, 1)
	c.vote(session, proofAnchor, m1pv1.Verdict_VERDICT_VIOLATED)

	// A BLOCK is the cheapest proof the verdict actually reached the cache: the
	// gate reads that cache and never computes, so it cannot BLOCK on a verdict
	// the cache does not hold. Sending SessionEnd before this point would race
	// the fusion and close the task honestly unresolved.
	waitFor(t, "the fused verdict to reach the gate cache", func() bool {
		return c.gate().GetDecision() == m1pv1.GateDecision_GATE_DECISION_BLOCK
	})

	c.sessionEnd(session)
	// SessionEnd travels the socket asynchronously: cancelling the daemon here
	// races its teardown against the close it is supposed to emit, which made an
	// earlier draft of this test pass 12 times in 20. The session's disappearance
	// is the observable — once the segmenter has dropped it, there is no task for
	// the gate to answer for, and the TaskClose is already written.
	waitFor(t, "the segmenter to process SessionEnd", func() bool {
		return strings.Contains(c.gate().GetReason(), "no open task for this session")
	})
	stop() // drains the spool

	sp, err := spool.Open(spool.Config{Dir: spoolDir})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sp.Close() }()
	ack, _ := sp.Cursors()
	recs, _, err := sp.Records(ack)
	if err != nil {
		t.Fatal(err)
	}

	verdicts := map[string]*m1pv1.VerdictEvent{}
	var closes []*m1pv1.TaskClose
	for _, r := range recs {
		var ev m1pv1.Event
		if err := proto.Unmarshal(r.Payload, &ev); err != nil {
			continue
		}
		switch b := ev.Body.(type) {
		case *m1pv1.Event_VerdictEvent:
			verdicts[string(ev.GetEventId())] = b.VerdictEvent
		case *m1pv1.Event_TaskClose:
			closes = append(closes, b.TaskClose)
		}
	}
	if len(closes) != 1 {
		t.Fatalf("spool holds %d TaskClose events, want exactly 1", len(closes))
	}
	got := closes[0]
	if got.GetResolution() != m1pv1.Resolution_RESOLUTION_VERDICT {
		t.Fatalf("resolution %v — the daemon reports this task as no outcome at all, "+
			"which is the whole TVO denominator on any install with no consented SLOW anchor (D-AS)",
			got.GetResolution())
	}
	// 07 §3 / events.proto: final_verdict_id is empty iff UNRESOLVED. A resolved
	// close naming nothing is a denominator entry no receipt can support.
	ve, ok := verdicts[string(got.GetFinalVerdictId())]
	if !ok {
		t.Fatalf("final_verdict_id %x names no VerdictEvent in the spool (07 §3)", got.GetFinalVerdictId())
	}
	if ve.GetVerdict() != m1pv1.Verdict_VERDICT_VIOLATED {
		t.Fatalf("the close resolved on verdict %v, want the VIOLATED one the gate blocked on", ve.GetVerdict())
	}
	if ve.GetStage() != m1pv1.VerdictStage_VERDICT_STAGE_PROVISIONAL {
		t.Fatalf("stage %v: a fast-anchor-only session resolves PROVISIONAL, and the coverage "+
			"band is what reports that weakness — not suppression to unresolved", ve.GetStage())
	}
}
