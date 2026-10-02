package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/spool"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/tailers"
)

// TestPartnerFileStreamMatchesSocketGolden is FR-SPINE-029's equivalence
// clause at the daemon level: the same six events the socket golden was
// recorded from, written as protojson lines to a partner JSONL file with its
// sidecar, tailed by the assembled daemon through admitPath, produce the
// same internal stream — testdata/socket_stream.golden with the session
// masked, because the file's session is minted rather than sent.
func TestPartnerFileStreamMatchesSocketGolden(t *testing.T) {
	state := t.TempDir()
	drop := t.TempDir()
	if err := os.WriteFile(filepath.Join(drop, "run.manifest.json"),
		[]byte(`{"component":"ext:acme/runner@1.2.3","host_correlation_id":"run-7781","schema_version":"m1p.v1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// The socket golden's writer events, as a host would write them: no
	// session_id, no seq, no epoch — only the body, the id and the clock.
	at := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	events := []*m1pv1.Event{
		{Body: &m1pv1.Event_SessionStart{SessionStart: &m1pv1.SessionStart{Agent: "claudecode", AgentVersion: "2.1.251", CapturePaths: []m1pv1.CapturePath{m1pv1.CapturePath_CAPTURE_PATH_HOOKS}}}},
		{Body: &m1pv1.Event_Turn{Turn: &m1pv1.Turn{TurnIndex: 0, Initiator: m1pv1.Initiator_INITIATOR_HUMAN}}},
		{Body: &m1pv1.Event_ToolUse{ToolUse: &m1pv1.ToolUse{ToolName: "Bash", ToolUseId: "toolu_01", DurationMs: 42, Status: m1pv1.ToolStatus_TOOL_STATUS_OK}}},
		{Body: &m1pv1.Event_Usage{Usage: &m1pv1.Usage{IdemKey: bytes.Repeat([]byte{0x1d}, 32), MessageId: "msg_01", RequestId: "req_01", Model: "claude-fable-5-1", InputTokens: 120, OutputTokens: 30, Source: m1pv1.UsageSource_USAGE_SOURCE_TRANSCRIPT}}},
		{Body: &m1pv1.Event_ArtifactOutcome{ArtifactOutcome: &m1pv1.ArtifactOutcome{ArtifactId: bytes.Repeat([]byte{0xa7}, 16), TaskVerdict: m1pv1.Verdict_VERDICT_SATISFIED, ArtifactFollowed: true}}},
		{Body: &m1pv1.Event_SessionEnd{SessionEnd: &m1pv1.SessionEnd{Reason: m1pv1.EndReason_END_REASON_EXIT, DurationMs: 5000, Drained: true}}},
	}
	var file bytes.Buffer
	writerIDs := map[[16]byte]bool{}
	for i, ev := range events {
		id := [16]byte{0xe0, byte(i)}
		writerIDs[id] = true
		ev.EventId = id[:]
		ev.OccurredAt = timestamppb.New(at.Add(time.Duration(i) * time.Second))
		line, err := protojson.Marshal(ev)
		if err != nil {
			t.Fatal(err)
		}
		file.Write(line)
		file.WriteByte('\n')
	}
	path := filepath.Join(drop, "run.jsonl")
	if err := os.WriteFile(path, file.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, slog.New(slog.NewTextHandler(os.Stderr, nil)), config{
			stateDir:      state,
			spoolDir:      filepath.Join(state, "spool"),
			socket:        testEndpoint(t),
			saltHex:       "aa",
			offPoll:       10 * time.Millisecond,
			partnerEvents: path,
			diskUsage:     func(string) (float64, error) { return 0.10, nil },
		})
	}()
	// The partner tailer persists its cursor after every emitted line, so the
	// file is fully admitted once a cursor for it reaches the file's size.
	deadline := time.Now().Add(20 * time.Second)
	for cursorAt(t, filepath.Join(state, "cursors"), path) != int64(file.Len()) {
		if time.Now().After(deadline) {
			t.Fatal("partner file never fully tailed")
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned %v, want clean exit", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("daemon did not exit on cancellation")
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
	// The file's session is whatever the daemon minted: read it off the
	// first record that carries one of the writer's ids.
	var sid []byte
	var got []string
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
		if u := ev.GetUsage(); u != nil {
			// ADR-0012 §4: the daemon's idem_key, never the writer's 0x1d…
			want := tailers.IdemKey(mustIdemKey(t, "aa"), [16]byte(sid), "msg_01", "req_01")
			if !bytes.Equal(u.GetIdemKey(), want) {
				t.Fatalf("Usage.idem_key = %x, want the daemon-stamped key %x", u.GetIdemKey(), want)
			}
			u.IdemKey = bytes.Repeat([]byte{0x1d}, 32) // the socket golden's writer value, for the shape comparison below
		}
		got = append(got, withoutSession(t, normalizeEvent(t, ev, writerIDs)))
	}
	want, err := os.ReadFile(filepath.Join("testdata", "socket_stream.golden"))
	if err != nil {
		t.Fatal(err)
	}
	var wantLines []string
	for _, l := range strings.Split(strings.TrimSpace(string(want)), "\n") {
		wantLines = append(wantLines, withoutSession(t, l))
	}
	if strings.Join(got, "\n") != strings.Join(wantLines, "\n") {
		t.Fatalf("file-tail stream differs from the socket golden\n--- file ---\n%s\n--- socket ---\n%s", strings.Join(got, "\n"), strings.Join(wantLines, "\n"))
	}
}

// withoutSession drops sessionId from one normalized JSON line: the socket's
// session is the writer's, the file's is minted, and everything else must match.
func withoutSession(t *testing.T, line string) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatal(err)
	}
	delete(m, "sessionId")
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// cursorAt returns the saved offset of the cursor whose path is p, or -1.
func cursorAt(t *testing.T, dir, p string) int64 {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return -1
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var c struct {
			Path   string `json:"path"`
			Offset int64  `json:"offset"`
		}
		if json.Unmarshal(b, &c) == nil && c.Path == p {
			return c.Offset
		}
	}
	return -1
}

func mustIdemKey(t *testing.T, saltHex string) []byte {
	t.Helper()
	root, err := hex.DecodeString(saltHex)
	if err != nil {
		t.Fatal(err)
	}
	k, err := tailers.DeriveUsageIdemKey(root)
	if err != nil {
		t.Fatal(err)
	}
	return k
}
