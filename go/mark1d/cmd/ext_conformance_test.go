package main

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"google.golang.org/protobuf/proto"

	"github.com/Omium-ai/omium-mark1/conformance/emitter"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/spool"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/tailers"
)

// The ext conformance family (conformance/vectors/ext/README.md), Go lane.
// Both tests carry the ConfVectors token the cross-language gate filters on.

const extVectors = "../../../conformance/vectors/ext"

// TestConfVectorsExtEmitterIsPinned: the Go reference emitter reproduces the
// frozen sample.jsonl and sidecar byte for byte.
func TestConfVectorsExtEmitterIsPinned(t *testing.T) {
	got, err := emitter.JSONL()
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join(extVectors, "sample.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("emitter.JSONL drifted from the frozen vector\n--- got ---\n%s--- want ---\n%s", got, want)
	}
	wantM, err := os.ReadFile(filepath.Join(extVectors, "sample.manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(emitter.Manifest(), wantM) {
		t.Fatalf("emitter.Manifest drifted: %s", emitter.Manifest())
	}
}

// TestConfVectorsExtTransportsAgree is FR-SPINE-031's equality clause: the
// sample session pushed over the socket into one assembled daemon and tailed
// from the frozen file by a second daemon produce identical internal streams
// — every spool record of the session, in order, with the daemon-minted
// fields masked — and identical receipt leaves, the writer-stamped event_id
// sequence a checkpoint's Merkle root is computed over.
func TestConfVectorsExtTransportsAgree(t *testing.T) {
	// Daemon A: the socket.
	socketState := t.TempDir()
	stopA := bootDaemon(t, socketState, "")
	c := dialEndpoint(t, lastEndpoint)
	sidA, err := emitter.Push(c)
	if err != nil {
		t.Fatal(err)
	}
	stopA()

	// Daemon B: the file, straight from the vector directory copied into a
	// drop dir (the tailer writes a cursor; the vector itself stays frozen).
	drop := t.TempDir()
	for _, name := range []string{"sample.manifest.json", "sample.jsonl"} {
		b, err := os.ReadFile(filepath.Join(extVectors, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(drop, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fileState := t.TempDir()
	stopB := bootDaemon(t, fileState, filepath.Join(drop, "sample.jsonl"))
	size := func() int64 {
		fi, err := os.Stat(filepath.Join(drop, "sample.jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		return fi.Size()
	}()
	deadline := time.Now().Add(20 * time.Second)
	for cursorAt(t, filepath.Join(fileState, "cursors"), filepath.Join(drop, "sample.jsonl")) != size {
		if time.Now().After(deadline) {
			t.Fatal("partner file never fully tailed")
		}
		time.Sleep(20 * time.Millisecond)
	}
	stopB()

	writerIDs := map[[16]byte]bool{}
	for _, ev := range emitter.Session() {
		var id [16]byte
		copy(id[:], ev.GetEventId())
		writerIDs[id] = true
	}
	streamA, leavesA := sessionStream(t, socketState, sidA[:], writerIDs)
	streamB, leavesB := sessionStream(t, fileState, nil, writerIDs)
	if streamA != streamB {
		t.Fatalf("socket and file-tail streams differ\n--- socket ---\n%s\n--- file ---\n%s", streamA, streamB)
	}
	if leavesA != leavesB {
		t.Fatalf("receipt leaves differ\n--- socket ---\n%s\n--- file ---\n%s", leavesA, leavesB)
	}
	if !strings.Contains(streamA, `"usage"`) || !strings.Contains(streamA, `"taskClose"`) || !strings.Contains(streamA, `"artifactOutcome"`) {
		t.Fatalf("the stream lost part of the minimum set: %s", streamA)
	}
}

// lastEndpoint is the endpoint bootDaemon last bound, for the socket half.
var lastEndpoint string

// bootDaemon runs the assembled daemon over a fresh state dir; partner is
// the --partner-events file or "".
func bootDaemon(t *testing.T, state, partner string) (stop func()) {
	t.Helper()
	endpoint := testEndpoint(t)
	lastEndpoint = endpoint
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, slog.New(slog.NewTextHandler(os.Stderr, nil)), config{
			stateDir:      state,
			spoolDir:      filepath.Join(state, "spool"),
			socket:        endpoint,
			saltHex:       "aa",
			offPoll:       10 * time.Millisecond,
			partnerEvents: partner,
			diskUsage:     func(string) (float64, error) { return 0.10, nil },
		})
	}()
	return func() {
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

// sessionStream reads a stopped daemon's spool and returns the session's
// normalized stream (session masked, as the two transports' sessions
// legitimately differ) and its receipt leaves: the writer-stamped event_ids
// in spool order, which is what a checkpoint seals. sid selects the session;
// nil means "the session the first writer id appears under".
func sessionStream(t *testing.T, state string, sid []byte, writerIDs map[[16]byte]bool) (stream, leaves string) {
	t.Helper()
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
	var lines, ids []string
	for _, r := range recs {
		ev := &m1pv1.Event{}
		if err := proto.Unmarshal(r.Payload, ev); err != nil {
			t.Fatal(err)
		}
		var id [16]byte
		copy(id[:], ev.GetEventId())
		if sid == nil && writerIDs[id] {
			sid = ev.GetSessionId()
		}
		if sid == nil || !bytes.Equal(ev.GetSessionId(), sid) {
			continue
		}
		if writerIDs[id] {
			ids = append(ids, string(r.ID[:16]))
		}
		if u := ev.GetUsage(); u != nil {
			// idem_key is HMAC-keyed by the session (events.proto), so it differs
			// between two minted sessions BY CONTRACT: assert each daemon stamped
			// its own correctly (ADR-0012 §4), then mask it like the session.
			if want := tailers.IdemKey(mustIdemKey(t, "aa"), [16]byte(sid), u.GetMessageId(), u.GetRequestId()); !bytes.Equal(u.GetIdemKey(), want) {
				t.Fatalf("Usage.idem_key = %x, want the daemon-stamped %x", u.GetIdemKey(), want)
			}
			u.IdemKey = bytes.Repeat([]byte{0x1d}, 32)
		}
		lines = append(lines, withoutSession(t, normalizeEvent(t, ev, writerIDs)))
	}
	return strings.Join(lines, "\n"), strings.Join(ids, "|")
}
