package main

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"google.golang.org/protobuf/proto"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/spool"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/tailers"
)

// TestSocketExtSessionGetsDaemonIdemKey is ADR-0012 §4 on the socket
// transport, through the assembled daemon: an ext: writer Hellos without a
// session, is minted one, sends a Usage carrying its own idem_key, and the
// spool holds that Usage under the daemon's key — the same stamp the file
// transport gets in TestPartnerFileStreamMatchesSocketGolden.
func TestSocketExtSessionGetsDaemonIdemKey(t *testing.T) {
	state := t.TempDir()
	endpoint := testEndpoint(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, slog.New(slog.NewTextHandler(os.Stderr, nil)), config{
			stateDir:  state,
			spoolDir:  filepath.Join(state, "spool"),
			socket:    endpoint,
			saltHex:   "aa",
			offPoll:   10 * time.Millisecond,
			diskUsage: func(string) (float64, error) { return 0.10, nil },
		})
	}()
	w := &goldenWriter{t: t, c: dialEndpoint(t, endpoint)}
	w.frame(&m1pv1.FabricFrame{Kind: &m1pv1.FabricFrame_Hello{Hello: &m1pv1.Hello{
		Component: "ext:acme/runner@1.2.3", Pid: 1, Version: "1.2.3", HostCorrelationId: "run-7781",
	}}})
	sid := w.reply().GetHelloAck().GetSessionId()
	if len(sid) != 16 {
		t.Fatalf("no minted session: %x", sid)
	}
	w.frame(&m1pv1.FabricFrame{Kind: &m1pv1.FabricFrame_Event{Event: &m1pv1.Event{
		EventId: bytes.Repeat([]byte{0xe7}, 16), SessionId: sid,
		Body: &m1pv1.Event_Usage{Usage: &m1pv1.Usage{IdemKey: bytes.Repeat([]byte{0x1d}, 32), MessageId: "msg_01", RequestId: "req_01", Model: "m", OutputTokens: 1}},
	}}})
	w.frame(&m1pv1.FabricFrame{Kind: &m1pv1.FabricFrame_Flush{Flush: &m1pv1.Flush{}}})
	if d := w.reply().GetFlushAck().GetDrained(); d != 1 {
		t.Fatalf("drained %d, want 1", d)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	sp, err := spool.Open(spool.Config{Dir: filepath.Join(state, "spool")})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sp.Close() }()
	ack, _ := sp.Cursors()
	recs, _, err := sp.Records(ack)
	if err != nil {
		t.Fatal(err)
	}
	want := tailers.IdemKey(mustIdemKey(t, "aa"), [16]byte(sid), "msg_01", "req_01")
	for _, r := range recs {
		ev := &m1pv1.Event{}
		if err := proto.Unmarshal(r.Payload, ev); err != nil {
			t.Fatal(err)
		}
		if u := ev.GetUsage(); u != nil && bytes.Equal(ev.GetSessionId(), sid) {
			if !bytes.Equal(u.GetIdemKey(), want) {
				t.Fatalf("Usage.idem_key = %x, want the daemon-stamped %x", u.GetIdemKey(), want)
			}
			return
		}
	}
	t.Fatal("the ext session's Usage never reached the spool")
}
