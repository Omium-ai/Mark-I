package fabric

import (
	"bytes"
	"context"
	"testing"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

// TestPushReachesTheBoundExtConnection is ADR-0015's fabric path: a
// recommendation pushed for a session lands on the ext: connection bound to
// it as the one unsolicited daemon→writer frame, and on nothing else — a
// first-party connection with the same session id receives nothing, and an
// unbound session counts zero deliveries.
func TestPushReachesTheBoundExtConnection(t *testing.T) {
	l := listenLoopback(t)
	srv := NewServer(func(context.Context, []byte) error { return nil }, nil)
	go func() { _ = srv.Serve(context.Background(), l) }()
	t.Cleanup(func() { _ = l.Close(); srv.Close() })

	ext := dial(t, l.Addr().String())
	frameFabric(t, ext, extHello(nil))
	sid := readFrame(t, ext).GetHelloAck().GetSessionId()
	if len(sid) != 16 {
		t.Fatal("no minted session")
	}
	var session [16]byte
	copy(session[:], sid)

	// A first-party writer that happens to use the same session id (as the
	// hookshim does for its own sessions) is never a push target.
	first := dial(t, l.Addr().String())
	frameFabric(t, first, &m1pv1.FabricFrame{Kind: &m1pv1.FabricFrame_Hello{Hello: &m1pv1.Hello{Component: "mark1-hookshim", Pid: 1, Version: "1", SessionId: sid}}})
	if !readFrame(t, first).GetHelloAck().GetAccepted() {
		t.Fatal("first-party Hello refused")
	}

	rec := &m1pv1.ArrestRecommendation{Kind: "knee_arrest", Reason: "p̂_LCB too low", KStarEstimate: 3, ProjectedCost: 4200, SessionId: sid}
	if n := srv.Push(session, &m1pv1.FabricFrame{Kind: &m1pv1.FabricFrame_ArrestRecommendation{ArrestRecommendation: rec}}); n != 1 {
		t.Fatalf("Push delivered to %d connection(s), want exactly the ext: one", n)
	}
	got := readFrame(t, ext).GetArrestRecommendation()
	if got == nil || got.GetKind() != "knee_arrest" || got.GetProjectedCost() != 4200 || !bytes.Equal(got.GetSessionId(), sid) {
		t.Fatalf("ext connection received %v, want the recommendation", got)
	}
	if n := srv.Push([16]byte{0xde, 0xad}, &m1pv1.FabricFrame{Kind: &m1pv1.FabricFrame_ArrestRecommendation{ArrestRecommendation: rec}}); n != 0 {
		t.Fatalf("Push for an unbound session delivered to %d", n)
	}
	// The ext: connection is still a working writer after the push: a Flush
	// round-trips, proving the push did not desynchronize the stream.
	frameFabric(t, ext, &m1pv1.FabricFrame{Kind: &m1pv1.FabricFrame_Flush{Flush: &m1pv1.Flush{}}})
	if readFrame(t, ext).GetFlushAck() == nil {
		t.Fatal("no FlushAck after a push")
	}
}
