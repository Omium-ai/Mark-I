// D-AI's ContaminationAlert arm — all decode-side, no filesystem, so no build
// tag (harness_test.go). Tag forward-compatibility moved to context_test.go.
package fabric

import (
	"context"
	"testing"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"google.golang.org/protobuf/encoding/protowire"
)

type recordingHandler struct {
	got chan [3]string
}

func (r *recordingHandler) OnContamination(session [16]byte, credRef, reason string) {
	r.got <- [3]string{string(session[:]), credRef, reason}
}

// startContaminationStub is startStub's sibling with the D-AI handler seam.
// h may be nil — that is the unwired daemon, and the frame must still decode.
func startContaminationStub(t *testing.T, h ContaminationHandler) string {
	t.Helper()
	l := listenLoopback(t)
	srv := NewServer(func(context.Context, []byte) error { return nil }, nil)
	if h != nil {
		srv.SetContaminationHandler(h)
	}
	go srv.Serve(context.Background(), l) //nolint:errcheck // closed by cleanup
	t.Cleanup(func() { _ = l.Close(); srv.Close() })
	return l.Addr().String()
}

// TestContaminationAlertReachesTheHandler is the hole D-AI names, closed: a
// FabricFrame carrying oneof arm 10 used to be skipped as unknown and then
// rejected as "carries no oneof arm", so the single most severe action the
// proxy can take had no wire. The credRef is what resolves to the fragment
// that must be reverted, so it has to survive the trip verbatim.
func TestContaminationAlertReachesTheHandler(t *testing.T) {
	h := &recordingHandler{got: make(chan [3]string, 1)}
	c := dial(t, startContaminationStub(t, h))
	frameFabric(t, c, &m1pv1.FabricFrame{Kind: &m1pv1.FabricFrame_Hello{
		Hello: &m1pv1.Hello{Component: "mark1-proxy", Pid: 7, Version: "0.1.0", SessionId: testSession[:]},
	}})
	readFrame(t, c) // HelloAck

	frameFabric(t, c, &m1pv1.FabricFrame{Kind: &m1pv1.FabricFrame_ContaminationAlert{
		ContaminationAlert: &m1pv1.ContaminationAlert{
			SessionId: testSession[:], CredRef: "ref-abc", ReasonCode: "oauth_marker",
		},
	}})

	select {
	case got := <-h.got:
		if got[0] != string(testSession[:]) {
			t.Fatalf("session %q, want the connection's authenticated Hello id", got[0])
		}
		if got[1] != "ref-abc" || got[2] != "oauth_marker" {
			t.Fatalf("cred_ref/reason_code %q/%q", got[1], got[2])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ContaminationAlert never reached the handler")
	}

	// One-way (D-AI): the proxy never awaits a reply, so the daemon must not
	// send one — a frame here would desynchronize a writer that is already
	// closing the session.
	if err := c.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buf := make([]byte, 1)
	if n, err := c.Read(buf); err == nil {
		t.Fatalf("daemon answered a one-way alert with %d byte(s)", n)
	}
}

// TestContaminationAlertWithNoHandlerIsAccepted: an unwired daemon (nil
// handler, which is main.go today) must still decode and accept the frame.
// Closing the connection instead would make the proxy's P0 notification look
// like a dialect breach and cost it its Hello on every retry.
func TestContaminationAlertWithNoHandlerIsAccepted(t *testing.T) {
	c := dial(t, startContaminationStub(t, nil))
	frameFabric(t, c, &m1pv1.FabricFrame{Kind: &m1pv1.FabricFrame_Hello{
		Hello: &m1pv1.Hello{Component: "mark1-proxy", Pid: 7, Version: "0.1.0", SessionId: testSession[:]},
	}})
	readFrame(t, c)
	frameFabric(t, c, &m1pv1.FabricFrame{Kind: &m1pv1.FabricFrame_ContaminationAlert{
		ContaminationAlert: &m1pv1.ContaminationAlert{SessionId: testSession[:], ReasonCode: "oauth_marker"},
	}})
	// The connection is still live: a Flush still round-trips.
	frameFabric(t, c, &m1pv1.FabricFrame{Kind: &m1pv1.FabricFrame_Flush{Flush: &m1pv1.Flush{}}})
	if err := c.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	if f := readFrame(t, c); f.GetFlushAck() == nil {
		t.Fatalf("connection died after an unhandled alert: %v", f)
	}
}

func appendBytesField(b []byte, num protowire.Number, v []byte) []byte {
	b = protowire.AppendTag(b, num, protowire.BytesType)
	return protowire.AppendBytes(b, v)
}
