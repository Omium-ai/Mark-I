// The M1PL session state machine: handshake, framing, per-connection accounting
// and the fail-open gate reply. Every assertion here is about bytes on a stream,
// so this file carries no build tag and runs on all three CI platforms — see
// harness_test.go for why it used to, and what NFR-PORTABILITY-002 still lacks.
package fabric

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/spool"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/verdict"
)

// startStub serves with a recording handle instead of the real admitter, so
// tests can assert on the exact bytes the fabric hands to capture.
func startStub(t *testing.T, gate *Gate) (addr string, got *[][]byte) {
	t.Helper()
	l := listenLoopback(t)
	var payloads [][]byte
	errSkip := errors.New("per-event")
	srv := NewServer(func(_ context.Context, p []byte) error {
		if len(p) > 0 && p[0] == 0xff {
			return errSkip // stands in for shed/quarantine: accounted, connection lives
		}
		payloads = append(payloads, append([]byte(nil), p...))
		return nil
	}, func(err error) bool { return errors.Is(err, errSkip) })
	if gate != nil {
		srv.SetGate(gate)
	}
	go func() { _ = srv.Serve(context.Background(), l) }()
	t.Cleanup(func() { _ = l.Close(); srv.Close() })
	return l.Addr().String(), &payloads
}

// TestHandshakeFirstFrameMustBeHello pins 08 §4.3 step 2: any other first
// frame closes the connection (M1E-4003) with no reply.
func TestHandshakeFirstFrameMustBeHello(t *testing.T) {
	addr, got := startStub(t, nil)
	c := dial(t, addr)
	writeEvent(t, c, 1, 5)
	readClosed(t, c)
	if len(*got) != 0 {
		t.Fatal("pre-handshake event reached the admission handle")
	}
	// A control frame that isn't Hello is equally a violation.
	c2 := dial(t, addr)
	frameFabric(t, c2, &m1pv1.FabricFrame{Kind: &m1pv1.FabricFrame_Flush{Flush: &m1pv1.Flush{}}})
	readClosed(t, c2)
}

// TestHelloAckCarriesMaxFrame: the ack is accepted:true with M1PL_MAX_FRAME
// the symbol (08 §4.3 step 3).
func TestHelloAckCarriesMaxFrame(t *testing.T) {
	addr, _ := startStub(t, nil)
	c := dial(t, addr)
	frameFabric(t, c, &m1pv1.FabricFrame{Kind: &m1pv1.FabricFrame_Hello{
		Hello: &m1pv1.Hello{Component: "mark1-hookshim", Pid: 42, Version: "1.0.0", SessionId: testSession[:]},
	}})
	ack := readFrame(t, c).GetHelloAck()
	if ack == nil || !ack.GetAccepted() || ack.GetMaxFrame() != MaxFrame {
		t.Fatalf("HelloAck %+v, want accepted with max_frame=%d", ack, MaxFrame)
	}
}

// TestHelloWithoutASessionIsRejected is D-AT. D-AL closed the all-zero session
// at every CONSUMER, so a Hello carrying no session was accepted and then had
// everything it sent silently dropped — the handshake was lying. Entry is the
// producer axis, and it is now closed too.
func TestHelloWithoutASessionIsRejected(t *testing.T) {
	for _, tc := range []struct {
		name string
		sid  []byte
	}{
		{"absent", nil},
		{"wrong length", bytes.Repeat([]byte{3}, 8)},
		{"explicitly all-zero", make([]byte, 16)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, got := startStub(t, nil)
			c := dial(t, addr)
			frameFabric(t, c, &m1pv1.FabricFrame{Kind: &m1pv1.FabricFrame_Hello{
				Hello: &m1pv1.Hello{Component: "tests", Version: "1.0.0", SessionId: tc.sid},
			}})
			readClosed(t, c)
			if len(*got) != 0 {
				t.Fatal("a session-less connection reached admission")
			}
		})
	}
}

// TestFabricFrameUnwrapRoundTrip pins D-U: the bytes handed to admission are
// the writer's exact INNER Event bytes — built here with protowire so no
// re-marshal can accidentally make the assertion vacuous.
func TestFabricFrameUnwrapRoundTrip(t *testing.T) {
	addr, got := startStub(t, nil)
	c := dial(t, addr)
	hello(t, c)

	inner, err := proto.Marshal(&m1pv1.Event{
		SessionId: bytes.Repeat([]byte{7}, 16),
		Body:      &m1pv1.Event_Usage{Usage: &m1pv1.Usage{IdemKey: make([]byte, 32), OutputTokens: 1234}},
	})
	if err != nil {
		t.Fatal(err)
	}
	frame := protowire.AppendBytes(protowire.AppendTag(nil, frameEvent, protowire.BytesType), inner)
	if err := WriteFrame(c, frame); err != nil {
		t.Fatal(err)
	}
	// Flush is the read barrier: its ack proves the event was handled.
	frameFabric(t, c, &m1pv1.FabricFrame{Kind: &m1pv1.FabricFrame_Flush{Flush: &m1pv1.Flush{}}})
	if d := readFrame(t, c).GetFlushAck().GetDrained(); d != 1 {
		t.Fatalf("drained %d, want 1", d)
	}
	if len(*got) != 1 || !bytes.Equal((*got)[0], inner) {
		t.Fatalf("admission received %d payloads; inner bytes differ from what the writer framed", len(*got))
	}
}

// TestFlushAckCountsOnlyAdmitted: the drained counter is "events the daemon
// admitted since this connection's Hello" — per-event losses do not count.
func TestFlushAckCountsOnlyAdmitted(t *testing.T) {
	addr, _ := startStub(t, nil)
	c := dial(t, addr)
	hello(t, c)
	writeEvent(t, c, 1, 1)
	writeEvent(t, c, 1, 2)
	// The 0xff lead byte makes the stub handle refuse per-event.
	frame := protowire.AppendBytes(protowire.AppendTag(nil, frameEvent, protowire.BytesType), []byte{0xff, 0xff})
	if err := WriteFrame(c, frame); err != nil {
		t.Fatal(err)
	}
	writeEvent(t, c, 1, 3)
	frameFabric(t, c, &m1pv1.FabricFrame{Kind: &m1pv1.FabricFrame_Flush{Flush: &m1pv1.Flush{}}})
	if d := readFrame(t, c).GetFlushAck().GetDrained(); d != 3 {
		t.Fatalf("drained %d, want 3 (the refused event is a loss, not a drain)", d)
	}
}

// TestFlushAckFollowsTheSpoolFsync is NFR-DURABILITY-004's daemon half. The
// shim sends Flush after SessionEnd and treats FlushAck as its only delivery
// evidence (mark1-hookshim/src/fabric.rs flush), so the ack must be written
// only once the spool's durable cursor covers what this connection admitted.
// The spool here is real with its fsync cadence PARKED: nothing but the
// Flush arm can make a record durable, so a durable cursor that covers the
// records is proof of which side of the ack the sync ran on.
func TestFlushAckFollowsTheSpoolFsync(t *testing.T) {
	sp, err := spool.Open(spool.Config{Dir: t.TempDir(), After: func(time.Duration) <-chan time.Time { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sp.Close() })
	var seq atomic.Uint64
	var failSync atomic.Bool
	l := listenLoopback(t)
	srv := NewServer(func(ctx context.Context, p []byte) error {
		var id [16]byte
		binary.LittleEndian.PutUint64(id[:], seq.Add(1))
		return sp.Append(ctx, id, spool.ClassBilling, p)
	}, nil)
	srv.Sync = func() error {
		if failSync.Load() {
			return errors.New("injected fsync failure")
		}
		return sp.Sync()
	}
	go func() { _ = srv.Serve(context.Background(), l) }()
	t.Cleanup(func() { _ = l.Close(); srv.Close() })
	addr := l.Addr().String()
	ackCur, _ := sp.Cursors()

	// Admit N, Flush: the ack must find every one of them below the durable
	// cursor — the spool's own observable, and with the cadence parked the
	// Flush arm is the only thing that could have put them there.
	const n = 3
	c := dial(t, addr)
	hello(t, c)
	for i := uint64(1); i <= n; i++ {
		writeEvent(t, c, 1, i)
	}
	frameFabric(t, c, &m1pv1.FabricFrame{Kind: &m1pv1.FabricFrame_Flush{Flush: &m1pv1.Flush{}}})
	if d := readFrame(t, c).GetFlushAck().GetDrained(); d != n {
		t.Fatalf("drained %d, want %d", d, n)
	}
	recs, _, err := sp.Records(ackCur)
	if err != nil || len(recs) != n {
		t.Fatalf("FlushAck arrived with %d of %d records below the durable cursor (err %v): the ack attests to bytes that are not on disk", len(recs), n, err)
	}

	// The ordering half, timing-free: with the sync failing, a correct daemon
	// writes NO ack and closes (the shim's cue to spill), so the stream holds
	// nothing but EOF. An ack written before the sync would be the first byte
	// read here.
	failSync.Store(true)
	c2 := dial(t, addr)
	hello(t, c2)
	writeEvent(t, c2, 1, n+1)
	frameFabric(t, c2, &m1pv1.FabricFrame{Kind: &m1pv1.FabricFrame_Flush{Flush: &m1pv1.Flush{}}})
	readClosed(t, c2)
	if recs, _, err := sp.Records(ackCur); err != nil || len(recs) != n {
		t.Fatalf("%d records durable after a failed sync (err %v), want the %d the earlier ack covered", len(recs), err, n)
	}
}

// TestGateQueryOverFabric is the request-reply round trip: GateQuery in,
// GateVerdict out, on a connection that also streams events.
func TestGateQueryOverFabric(t *testing.T) {
	entry := violatedEntry(false, false)
	g := NewGate(stubReader{{1}: entry}, verdict.NewBlocks(), t.TempDir())
	g.TaskFor = ownAll
	addr, _ := startStub(t, g)
	c := dial(t, addr)
	hello(t, c)
	frameFabric(t, c, &m1pv1.FabricFrame{Kind: &m1pv1.FabricFrame_GateQuery{GateQuery: query(1, 5000)}})
	v := readFrame(t, c).GetGateVerdict()
	if v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_BLOCK {
		t.Fatalf("verdict over fabric: %v %q, want BLOCK", v.GetDecision(), v.GetReason())
	}
	// And with no gate wired, the posture is fail-open M1E-5001, never a hang.
	addr2, _ := startStub(t, nil)
	c2 := dial(t, addr2)
	hello(t, c2)
	frameFabric(t, c2, &m1pv1.FabricFrame{Kind: &m1pv1.FabricFrame_GateQuery{GateQuery: query(1, 5000)}})
	if err := c2.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	v2 := readFrame(t, c2).GetGateVerdict()
	if v2.GetDecision() != m1pv1.GateDecision_GATE_DECISION_ALLOW {
		t.Fatalf("gateless daemon answered %v, want fail-open ALLOW", v2.GetDecision())
	}
}

// TestDuplicatedOneofArmIsMalformed is a parser differential, not a style
// point: proto3 in Go takes the LAST occurrence and prost on the Rust end of
// this same socket MERGES them, so a duplicating frame means two different
// things at the two ends. The daemon refuses it — for a repeated arm and for
// two different arms alike — and closes the connection.
func TestDuplicatedOneofArmIsMalformed(t *testing.T) {
	inner, err := proto.Marshal(&m1pv1.Hello{Component: "dup", Version: "1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	arm := func(num protowire.Number) []byte {
		return protowire.AppendBytes(protowire.AppendTag(nil, num, protowire.BytesType), inner)
	}
	for _, tc := range []struct {
		name  string
		frame []byte
	}{
		{"same arm twice", append(arm(frameHello), arm(frameHello)...)},
		{"two different arms", append(arm(frameHello), arm(frameFlush)...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := unwrap(tc.frame); err == nil {
				t.Fatal("unwrap accepted a duplicated oneof arm — Go would take the last, prost would merge")
			}
			// And over the wire it closes the connection rather than guessing.
			addr, got := startStub(t, nil)
			c := dial(t, addr)
			if err := WriteFrame(c, tc.frame); err != nil {
				t.Fatal(err)
			}
			readClosed(t, c)
			if len(*got) != 0 {
				t.Fatal("a malformed frame reached admission")
			}
		})
	}
}

// TestVersionMismatchIsToldNotJustDropped pins 08 §4.3 step 3's second
// outcome. A bare EOF is indistinguishable from a dead daemon, so a
// mid-upgrade writer learned nothing; want_ver is the whole diagnostic.
func TestVersionMismatchIsToldNotJustDropped(t *testing.T) {
	addr, got := startStub(t, nil)
	c := dial(t, addr)
	// A well-formed Hello framed at an M1PL version this daemon does not speak.
	inner, err := proto.Marshal(&m1pv1.FabricFrame{Kind: &m1pv1.FabricFrame_Hello{
		Hello: &m1pv1.Hello{Component: "mark1-hookshim", Version: "9.9.9"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	frame := append([]byte("M1PL"), 0x02)
	frame = binary.LittleEndian.AppendUint32(frame, uint32(len(inner))) // #nosec G115 -- test sizes
	if _, err := c.Write(append(frame, inner...)); err != nil {
		t.Fatal(err)
	}
	ack := readFrame(t, c).GetHelloAck()
	if ack == nil || ack.GetAccepted() {
		t.Fatalf("version mismatch answered %v, want HelloAck{accepted:false}", ack)
	}
	if ack.GetWantVer() != version {
		t.Fatalf("want_ver = %d, want the %d this daemon speaks", ack.GetWantVer(), version)
	}
	readClosed(t, c)
	if len(*got) != 0 {
		t.Fatal("a rejected-version connection reached admission")
	}
}
