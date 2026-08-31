package fabric

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"google.golang.org/protobuf/proto"
)

// The transport and framing helpers shared by every fabric test, deliberately
// NOT build-tagged.
//
// These lived in listener_test.go, which is //go:build unix because it asserts
// socket modes — so the framing and single-writer suites that merely borrowed
// its helpers inherited a unix tag they had no reason to carry, and the
// windows-2022 CI leg ran none of them. NFR-PORTABILITY-002 asks for
// "equivalent perms/framing/single-writer semantics" on Windows; perms cannot
// pass until 07 §5's named pipe lands (listener_windows.go refuses), but
// framing and single-writer are pure net.Conn and always could have.
//
// listenLoopback is a TCP socket, and that is not a stand-in for the fabric's
// transport — mark1d still refuses to serve on Windows, and the perms boundary
// is still tested only where it exists. It is available because serveConn
// (server.go) reads a net.Conn and nothing else, so a loopback conn runs the
// identical code, and the half of the suite that is about bytes on a stream
// stops being unix-only for filing reasons.
//
// Read that as a fact about the code, not as an endorsement of it. The reason
// serveConn is transport-agnostic is that the fabric's ONLY admission control
// is the socket's 0600/0700 mode at Listen: 04 §11.1 also specifies a peer
// verification row (SO_PEERCRED uid == daemon uid on Linux, LOCAL_PEERCRED on
// macOS) and nothing in this repo implements it — D-CE. If it is ever added,
// these tests must move back behind a real UDS rather than have the new check
// weakened to keep a TCP harness working.
func listenLoopback(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func dial(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// hello performs the 08 §4.3 handshake and consumes the HelloAck.
func hello(t *testing.T, c net.Conn) {
	t.Helper()
	frameFabric(t, c, &m1pv1.FabricFrame{Kind: &m1pv1.FabricFrame_Hello{
		Hello: &m1pv1.Hello{Component: "test-writer", Pid: 1, Version: "0.0.0", SessionId: testSession[:]},
	}})
	ack := readFrame(t, c)
	if ack.GetHelloAck() == nil || !ack.GetHelloAck().GetAccepted() {
		t.Fatalf("no accepting HelloAck: %v", ack)
	}
}

func frameFabric(t *testing.T, w io.Writer, f *m1pv1.FabricFrame) {
	t.Helper()
	b, err := proto.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteFrame(w, b); err != nil {
		t.Fatal(err)
	}
}

// readFrame reads exactly one M1PL frame off c and decodes the FabricFrame.
func readFrame(t *testing.T, c net.Conn) *m1pv1.FabricFrame {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	hdr := make([]byte, 9)
	if _, err := io.ReadFull(c, hdr); err != nil {
		t.Fatalf("reading reply header: %v", err)
	}
	n := int(uint32(hdr[5]) | uint32(hdr[6])<<8 | uint32(hdr[7])<<16 | uint32(hdr[8])<<24)
	payload := make([]byte, n)
	if _, err := io.ReadFull(c, payload); err != nil {
		t.Fatalf("reading reply payload: %v", err)
	}
	f := &m1pv1.FabricFrame{}
	if err := proto.Unmarshal(payload, f); err != nil {
		t.Fatal(err)
	}
	return f
}

func writeEvent(t *testing.T, w io.Writer, session byte, out uint64) {
	t.Helper()
	sid := make([]byte, 16)
	sid[0] = session
	frameFabric(t, w, &m1pv1.FabricFrame{Kind: &m1pv1.FabricFrame_Event{Event: &m1pv1.Event{
		SessionId: sid,
		Body:      &m1pv1.Event_Usage{Usage: &m1pv1.Usage{IdemKey: make([]byte, 32), OutputTokens: out}},
	}}})
}

// readClosed asserts the daemon hung up. It tests for "a read that fails and is
// not a timeout" rather than for io.EOF specifically: the subject is that the
// connection is gone, and a peer that closes with bytes still in flight is
// reported as a reset, not an EOF — on TCP, and on Windows especially. Pinning
// io.EOF would make the assertion a statement about which shutdown path the
// kernel took, which is neither what 08 §4.3 promises nor portable.
func readClosed(t *testing.T, c net.Conn) {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	n, err := c.Read(make([]byte, 1))
	if err == nil {
		t.Fatalf("connection still open: read %d byte(s), want the daemon to have closed it", n)
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("connection still open after 5s: %v", err)
	}
}
