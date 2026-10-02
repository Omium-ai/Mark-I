package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/fabric"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/spool"
)

var updateGolden = flag.Bool("update", false, "rewrite testdata goldens from the current build")

// TestSocketStreamGolden pins the INTERNAL STREAM the socket path produces for
// one scripted session: every spool record the assembled daemon (run()) wrote
// for that session, in spool order, with the fields the daemon mints
// (session_epoch, UUIDv7 event/task ids) masked so the pin is about shape and
// sequence, not clocks.
//
// It exists for the admit refactor (ADR-0012 wave): the fabric handler closure
// in run() became a named admission path shared by the socket, the loopback
// door and the JSONL tailer, and "pure refactor" is only a claim until the
// stream before and after is byte-identical. testdata/socket_stream.golden was
// recorded BEFORE the lift and must never need -update for a transport change.
//
// Deliberately NOT unix-tagged: the daemon's endpoint is the platform's
// (dial_unix_test.go / dial_windows_test.go), and the stream is the same bytes
// on both.
func TestSocketStreamGolden(t *testing.T) {
	state := t.TempDir()
	endpoint := testEndpoint(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, slog.New(slog.NewTextHandler(os.Stderr, nil)), config{
			stateDir: state,
			spoolDir: filepath.Join(state, "spool"),
			socket:   endpoint,
			saltHex:  "aa",
			offPoll:  10 * time.Millisecond,
			// The 95 % disk hard stop (07 §6) is a real posture, not a test condition: a full developer disk would block billing-grade admission here forever.
			diskUsage: func(string) (float64, error) { return 0.10, nil },
		})
	}()
	stop := func() {
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

	sid := [16]byte{0x5e, 0x55, 0x10, 0x0a, 0x5e, 0x55, 0x10, 0x0a, 0x5e, 0x55, 0x10, 0x0a, 0x5e, 0x55, 0x10, 0x0a}
	c := dialEndpoint(t, endpoint)
	w := &goldenWriter{t: t, c: c}
	w.frame(&m1pv1.FabricFrame{Kind: &m1pv1.FabricFrame_Hello{Hello: &m1pv1.Hello{
		Component: "tests", Pid: 1, Version: version, SessionId: sid[:],
	}}})
	if ack := w.reply().GetHelloAck(); !ack.GetAccepted() {
		t.Fatalf("HelloAck not accepted: %+v", ack)
	}
	// The scripted session: the five-event minimum an external host emits
	// (08 §4) plus the lifecycle pair around it, with writer-stamped ids.
	at := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	bodies := []func(*m1pv1.Event){
		func(e *m1pv1.Event) {
			e.Body = &m1pv1.Event_SessionStart{SessionStart: &m1pv1.SessionStart{Agent: "claudecode", AgentVersion: "2.1.251", CapturePaths: []m1pv1.CapturePath{m1pv1.CapturePath_CAPTURE_PATH_HOOKS}}}
		},
		func(e *m1pv1.Event) {
			e.Body = &m1pv1.Event_Turn{Turn: &m1pv1.Turn{TurnIndex: 0, Initiator: m1pv1.Initiator_INITIATOR_HUMAN}}
		},
		func(e *m1pv1.Event) {
			e.Body = &m1pv1.Event_ToolUse{ToolUse: &m1pv1.ToolUse{ToolName: "Bash", ToolUseId: "toolu_01", DurationMs: 42, Status: m1pv1.ToolStatus_TOOL_STATUS_OK}}
		},
		func(e *m1pv1.Event) {
			e.Body = &m1pv1.Event_Usage{Usage: &m1pv1.Usage{IdemKey: bytes.Repeat([]byte{0x1d}, 32), MessageId: "msg_01", RequestId: "req_01", Model: "claude-fable-5-1", InputTokens: 120, OutputTokens: 30, Source: m1pv1.UsageSource_USAGE_SOURCE_TRANSCRIPT}}
		},
		func(e *m1pv1.Event) {
			e.Body = &m1pv1.Event_ArtifactOutcome{ArtifactOutcome: &m1pv1.ArtifactOutcome{ArtifactId: bytes.Repeat([]byte{0xa7}, 16), TaskVerdict: m1pv1.Verdict_VERDICT_SATISFIED, ArtifactFollowed: true}}
		},
		func(e *m1pv1.Event) {
			e.Body = &m1pv1.Event_SessionEnd{SessionEnd: &m1pv1.SessionEnd{Reason: m1pv1.EndReason_END_REASON_EXIT, DurationMs: 5000, Drained: true}}
		},
	}
	writerIDs := map[[16]byte]bool{}
	for i, body := range bodies {
		id := [16]byte{0xe0, byte(i)}
		writerIDs[id] = true
		ev := &m1pv1.Event{EventId: id[:], SessionId: sid[:], OccurredAt: timestamppb.New(at.Add(time.Duration(i) * time.Second))}
		body(ev)
		w.frame(&m1pv1.FabricFrame{Kind: &m1pv1.FabricFrame_Event{Event: ev}})
	}
	w.frame(&m1pv1.FabricFrame{Kind: &m1pv1.FabricFrame_Flush{Flush: &m1pv1.Flush{}}})
	if d := w.reply().GetFlushAck().GetDrained(); d != uint64(len(bodies)) {
		t.Fatalf("FlushAck drained %d, want %d", d, len(bodies))
	}
	// The segmenter closes the session's task on SessionEnd and the spool
	// syncs on shutdown; stop() is the drain barrier that makes both durable.
	stop()

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
	var got bytes.Buffer
	for _, r := range recs {
		ev := &m1pv1.Event{}
		if err := proto.Unmarshal(r.Payload, ev); err != nil {
			t.Fatalf("spool record does not decode: %v", err)
		}
		if !bytes.Equal(ev.GetSessionId(), sid[:]) {
			continue // device-wide boot events (coverage, health) are not this session's stream
		}
		got.WriteString(normalizeEvent(t, ev, writerIDs))
		got.WriteByte('\n')
	}

	golden := filepath.Join("testdata", "socket_stream.golden")
	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, got.Bytes(), 0o644); err != nil { //nolint:gosec // G306: a checked-in fixture
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("%v (run with -update to record)", err)
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatalf("socket-path internal stream drifted from %s\n--- got ---\n%s--- want ---\n%s", golden, got.String(), string(want))
	}
}

// normalizeEvent is one spooled event as a deterministic JSON line: the
// daemon-minted fields are masked (session_epoch → 0, a non-writer event_id and its occurred_at →
// 0xee…, any task_id → 0x7a…, a TaskClose.final_verdict_id → 0x7f…) and the
// keys are sorted by a round trip through encoding/json, because protojson's
// own output is deliberately unstable.
func normalizeEvent(t *testing.T, ev *m1pv1.Event, writerIDs map[[16]byte]bool) string {
	t.Helper()
	ev.SessionEpoch = 0
	var id [16]byte
	copy(id[:], ev.GetEventId())
	if !writerIDs[id] {
		// Daemon-minted (TaskOpen, TaskClose): its id and its occurred_at are the
		// daemon clock, masked so the pin is the shape and sequence.
		ev.EventId = bytes.Repeat([]byte{0xee}, 16)
		ev.OccurredAt = nil
	}
	if len(ev.GetTaskId()) == 16 {
		ev.TaskId = bytes.Repeat([]byte{0x7a}, 16)
	}
	if tc := ev.GetTaskClose(); tc != nil && len(tc.GetFinalVerdictId()) == 16 {
		tc.FinalVerdictId = bytes.Repeat([]byte{0x7f}, 16)
	}
	raw, err := protojson.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	var tree any
	if err := json.Unmarshal(raw, &tree); err != nil {
		t.Fatal(err)
	}
	line, err := json.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	return string(line)
}

// goldenWriter is the writer half of M1PL as a real writer speaks it, over
// whichever net.Conn the platform's endpoint gave us. gate_e2e_test.go's
// fabricConn is the same thing behind a unix tag.
type goldenWriter struct {
	t   *testing.T
	c   net.Conn
	dec fabric.Decoder
}

func (w *goldenWriter) frame(f *m1pv1.FabricFrame) {
	w.t.Helper()
	b, err := proto.Marshal(f)
	if err != nil {
		w.t.Fatal(err)
	}
	if err := fabric.WriteFrame(w.c, b); err != nil {
		w.t.Fatal(err)
	}
}

func (w *goldenWriter) reply() *m1pv1.FabricFrame {
	w.t.Helper()
	if err := w.c.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		w.t.Fatal(err)
	}
	buf := make([]byte, 4096)
	for {
		payload, _, err := w.dec.Next()
		if err != nil {
			w.t.Fatal(err)
		}
		if payload != nil {
			f := &m1pv1.FabricFrame{}
			if err := proto.Unmarshal(payload, f); err != nil {
				w.t.Fatal(err)
			}
			return f
		}
		n, err := w.c.Read(buf)
		if n > 0 {
			w.dec.Push(buf[:n])
			continue
		}
		w.t.Fatalf("fabric read: %v", err)
	}
}
