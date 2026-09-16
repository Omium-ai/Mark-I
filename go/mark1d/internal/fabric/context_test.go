package fabric

import (
	"context"
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

// The byte contract, shared verbatim with rust/mark1-hookshim/src/context.rs (D-AE arms 8/9).
const (
	ctxQueryHex     = "421f08041204426173681a124578697420636f646520310a4641494c207820d20b"
	ctxQueryFlagHex = "4207080220f0012801"
	ctxReplyHex     = "4a1e0a1c5b6d61726b31206d656d6f72795d2072656d6564793a207265747279"
	ctxReplyEmpty   = "4a00"
	ctxReplyText    = "[mark1 memory] remedy: retry"
	// The CORRECTION channel (08 §5.1 PostToolUse row): the shim's pull and one rendered correction.
	ctxCorrectionQueryHex = "4205080520f001"
	ctxCorrectionReplyHex = "4a670a655b6d61726b3120636f7272656374696f6e5d206120736c6f772076657269666965722066696e697368656420616674657220746865206c61737420766572646963743a2076696f6c6174656420776173207265766973656420746f20736174697366696564"
	ctxCorrectionText     = "[mark1 correction] a slow verifier finished after the last verdict: violated was revised to satisfied"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestContextFrameBytesAgreeWithTheShim(t *testing.T) {
	field, inner, err := unwrap(mustHex(t, ctxQueryHex))
	if err != nil || field != frameContextQuery {
		t.Fatalf("unwrap: field %d err %v", field, err)
	}
	q, err := decodeContextQuery(inner)
	if err != nil {
		t.Fatal(err)
	}
	want := ContextQuery{Channel: 4, ToolName: "Bash", Error: "Exit code 1\nFAIL x", DeadlineMs: 1490}
	if q != want {
		t.Fatalf("decoded %+v, want %+v", q, want)
	}
	_, inner, err = unwrap(mustHex(t, ctxQueryFlagHex))
	if err != nil {
		t.Fatal(err)
	}
	if q, err = decodeContextQuery(inner); err != nil || q != (ContextQuery{Channel: 2, DeadlineMs: 240, IsInterrupt: true}) {
		t.Fatalf("flag vector decoded %+v err %v", q, err)
	}
	if got := hex.EncodeToString(encodeContextReply(ctxReplyText)); got != ctxReplyHex {
		t.Fatalf("reply bytes %s, want %s", got, ctxReplyHex)
	}
	if got := hex.EncodeToString(encodeContextReply("")); got != ctxReplyEmpty {
		t.Fatalf("empty reply bytes %s, want %s", got, ctxReplyEmpty)
	}
	field, _, err = unwrap(mustHex(t, ctxReplyEmpty))
	if err != nil || field != frameContextReply {
		t.Fatalf("an empty reply must still carry arm 9: field %d err %v", field, err)
	}
	// The CORRECTION arm: channel 5 under the pack's 240 ms deadline, nothing else set.
	field, inner, err = unwrap(mustHex(t, ctxCorrectionQueryHex))
	if err != nil || field != frameContextQuery {
		t.Fatalf("unwrap correction: field %d err %v", field, err)
	}
	if q, err = decodeContextQuery(inner); err != nil || q != (ContextQuery{Channel: uint32(m1pv1.InjectionChannel_INJECTION_CHANNEL_CORRECTION), DeadlineMs: 240}) {
		t.Fatalf("correction vector decoded %+v err %v", q, err)
	}
	if got := hex.EncodeToString(encodeContextReply(ctxCorrectionText)); got != ctxCorrectionReplyHex {
		t.Fatalf("correction reply bytes %s, want %s", got, ctxCorrectionReplyHex)
	}
}

func TestContextQueryDecodeRefusesWrongWireTypes(t *testing.T) {
	bad := protowire.AppendTag(nil, 3, protowire.VarintType)
	bad = protowire.AppendVarint(bad, 7)
	if _, err := decodeContextQuery(bad); err == nil {
		t.Fatal("varint in the error field decoded")
	}
	bad = protowire.AppendTag(nil, 1, protowire.BytesType)
	bad = protowire.AppendString(bad, "x")
	if _, err := decodeContextQuery(bad); err == nil {
		t.Fatal("bytes in the channel field decoded")
	}
	future := protowire.AppendTag(nil, 9, protowire.BytesType)
	future = protowire.AppendString(future, "a later field")
	future = protowire.AppendTag(future, 1, protowire.VarintType)
	future = protowire.AppendVarint(future, 2)
	if q, err := decodeContextQuery(future); err != nil || q.Channel != 2 {
		t.Fatalf("unknown field must be skipped: %+v %v", q, err)
	}
}

// TestContextArmsAreArmsNow replaces the reserved-tag guard: 8 and 9 are oneof
// arms, so a frame carrying 8 beside Flush is a two-arm frame and refused;
// tag 11 stays forward-compatible.
func TestContextArmsAreArmsNow(t *testing.T) {
	flush, err := proto.Marshal(&m1pv1.Flush{})
	if err != nil {
		t.Fatal(err)
	}
	payload := appendBytesField(nil, frameContextQuery, nil)
	payload = appendBytesField(payload, frameFlush, flush)
	if _, _, err := unwrap(payload); err == nil {
		t.Fatal("ContextQuery beside Flush decoded as one arm")
	}
	payload = appendBytesField(nil, 11, []byte("future"))
	payload = appendBytesField(payload, frameFlush, flush)
	if field, _, err := unwrap(payload); err != nil || field != frameFlush {
		t.Fatalf("tag 11 must be skipped: field %d err %v", field, err)
	}
}

type recordingContext struct {
	got     chan ContextQuery
	session chan [16]byte
	text    string
}

// Context answers the pitfall channel only, as memory.Cache does; anything else is a recorded miss.
func (r *recordingContext) Context(_ context.Context, q ContextQuery, session [16]byte) string {
	r.got <- q
	r.session <- session
	if q.Channel != uint32(m1pv1.InjectionChannel_INJECTION_CHANNEL_REACTIVE_PITFALL) {
		return ""
	}
	return r.text
}

func readRawFrame(t *testing.T, c net.Conn) []byte {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
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
	return payload
}

func TestContextQueryRoundTripsThroughTheSession(t *testing.T) {
	h := &recordingContext{got: make(chan ContextQuery, 1), session: make(chan [16]byte, 1), text: ctxReplyText}
	l := listenLoopback(t)
	srv := NewServer(func(context.Context, []byte) error { return nil }, nil)
	srv.SetContextHandler(h)
	go srv.Serve(context.Background(), l) //nolint:errcheck // closed by cleanup
	t.Cleanup(func() { _ = l.Close(); srv.Close() })
	c := dial(t, l.Addr().String())
	hello(t, c)
	if err := WriteFrame(c, mustHex(t, ctxQueryHex)); err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(readRawFrame(t, c)); got != ctxReplyHex {
		t.Fatalf("reply %s, want %s", got, ctxReplyHex)
	}
	if q := <-h.got; q.Error != "Exit code 1\nFAIL x" || q.Channel != 4 {
		t.Fatalf("handler saw %+v", q)
	}
	if s := <-h.session; s != testSession {
		t.Fatalf("handler saw session %x, want the Hello's", s)
	}
	// The connection is still an event stream afterwards.
	frameFabric(t, c, &m1pv1.FabricFrame{Kind: &m1pv1.FabricFrame_Flush{Flush: &m1pv1.Flush{}}})
	if f := readFrame(t, c); f.GetFlushAck() == nil {
		t.Fatalf("connection died after a context round trip: %v", f)
	}
}

func TestContextQueryWithNoHandlerIsAnEmptyReply(t *testing.T) {
	l := listenLoopback(t)
	srv := NewServer(func(context.Context, []byte) error { return nil }, nil)
	go srv.Serve(context.Background(), l) //nolint:errcheck // closed by cleanup
	t.Cleanup(func() { _ = l.Close(); srv.Close() })
	c := dial(t, l.Addr().String())
	hello(t, c)
	if err := WriteFrame(c, mustHex(t, ctxQueryHex)); err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(readRawFrame(t, c)); got != ctxReplyEmpty {
		t.Fatalf("unwired daemon replied %s, want %s", got, ctxReplyEmpty)
	}
}

func TestContextQueryBeforeHelloIsRefused(t *testing.T) {
	l := listenLoopback(t)
	srv := NewServer(func(context.Context, []byte) error { return nil }, nil)
	go srv.Serve(context.Background(), l) //nolint:errcheck // closed by cleanup
	t.Cleanup(func() { _ = l.Close(); srv.Close() })
	c := dial(t, l.Addr().String())
	if err := WriteFrame(c, mustHex(t, ctxQueryHex)); err != nil {
		t.Fatal(err)
	}
	readClosed(t, c)
}
