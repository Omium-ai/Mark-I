// Package emitter is the reference external writer (08 §4.6): one realistic
// sample session a partner can produce without an account, as the JSONL
// file-tail format and as a socket push. It depends on nothing but the
// generated m1p.v1 bindings — no mark1d internals, by design: a partner's
// integration must be reproducible from this package and the contract alone.
//
// The JSONL bytes are pinned in conformance/vectors/ext/ and the Python copy
// (emit.py) reproduces them byte for byte; the Go and Python emitters are
// therefore one artifact, not two opinions.
package emitter

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Component is the Hello.component / sidecar component this emitter declares
// (08 §4.6.1's ext:<vendor>/<product>@<version> convention).
const Component = "ext:omium/reference-emitter@0.1.0"

// HostCorrelationID is the host's own reference for the sample run.
const HostCorrelationID = "sample-run-0001"

// SchemaVersion is the sidecar's schema_version (07 "Partner event files").
const SchemaVersion = "m1p.v1"

// M1PL framing (07 §5), the nine bytes a socket writer needs and nothing else.
const (
	maxFrame  = 4_194_304
	headerLen = 9
)

var magic = [4]byte{'M', '1', 'P', 'L'}

// eventID is a fixed UUIDv7-shaped id (version 7, RFC 9562 variant) per
// line, so the sample is deterministic and a re-scan is idempotent at ingest.
func eventID(i byte) []byte {
	return []byte{0x01, 0x99, 0x9f, 0xc4, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, i}
}

// Session is the sample: the five-event minimum (TaskOpen, TaskClose, Turn,
// Usage, ArtifactOutcome) with the recommended lifecycle pair and one
// ToolUse, in 08 §4.6.3 order, one second apart from a fixed instant. No
// session_id: the daemon mints it (socket: HelloAck; file: the sidecar bind).
func Session() []*m1pv1.Event {
	at := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	bodies := []func(*m1pv1.Event){
		func(e *m1pv1.Event) {
			e.Body = &m1pv1.Event_SessionStart{SessionStart: &m1pv1.SessionStart{Agent: "acme-runner", AgentVersion: "1.2.3"}}
		},
		func(e *m1pv1.Event) {
			e.Body = &m1pv1.Event_TaskOpen{TaskOpen: &m1pv1.TaskOpen{TaskSegVersion: "ext:acme/runner.v1", TaskClass: "*"}}
		},
		func(e *m1pv1.Event) {
			e.Body = &m1pv1.Event_Turn{Turn: &m1pv1.Turn{TurnIndex: 0, Initiator: m1pv1.Initiator_INITIATOR_HUMAN}}
		},
		func(e *m1pv1.Event) {
			e.Body = &m1pv1.Event_Turn{Turn: &m1pv1.Turn{TurnIndex: 1, Initiator: m1pv1.Initiator_INITIATOR_AGENT}}
		},
		func(e *m1pv1.Event) {
			e.Body = &m1pv1.Event_ToolUse{ToolUse: &m1pv1.ToolUse{ToolName: "Bash", ToolUseId: "toolu_01", DurationMs: 42, Status: m1pv1.ToolStatus_TOOL_STATUS_OK}}
		},
		func(e *m1pv1.Event) {
			e.Body = &m1pv1.Event_Usage{Usage: &m1pv1.Usage{MessageId: "msg_01", RequestId: "req_01", Model: "claude-fable-5-1", InputTokens: 120, OutputTokens: 30}}
		},
		func(e *m1pv1.Event) {
			e.Body = &m1pv1.Event_ArtifactOutcome{ArtifactOutcome: &m1pv1.ArtifactOutcome{ArtifactId: bytes.Repeat([]byte{0xa7}, 16), TaskVerdict: m1pv1.Verdict_VERDICT_SATISFIED, ArtifactFollowed: true}}
		},
		func(e *m1pv1.Event) {
			e.Body = &m1pv1.Event_TaskClose{TaskClose: &m1pv1.TaskClose{Resolution: m1pv1.Resolution_RESOLUTION_VERDICT, TurnCount: 2}}
		},
		func(e *m1pv1.Event) {
			e.Body = &m1pv1.Event_SessionEnd{SessionEnd: &m1pv1.SessionEnd{Reason: m1pv1.EndReason_END_REASON_EXIT, DurationMs: 8000, Drained: true}}
		},
	}
	out := make([]*m1pv1.Event, 0, len(bodies))
	for i, body := range bodies {
		ev := &m1pv1.Event{EventId: eventID(byte(i)), OccurredAt: timestamppb.New(at.Add(time.Duration(i) * time.Second))}
		body(ev)
		out = append(out, ev)
	}
	return out
}

// JSONL renders Session as the file-tail format: one protojson Event per
// line, keys sorted and compact so the bytes are deterministic (protojson's
// own spacing is deliberately unstable).
func JSONL() ([]byte, error) {
	var out bytes.Buffer
	for _, ev := range Session() {
		raw, err := protojson.Marshal(ev)
		if err != nil {
			return nil, err
		}
		var tree any
		if err := json.Unmarshal(raw, &tree); err != nil {
			return nil, err
		}
		line, err := json.Marshal(tree)
		if err != nil {
			return nil, err
		}
		out.Write(line)
		out.WriteByte('\n')
	}
	return out.Bytes(), nil
}

// Manifest is the sidecar <name>.manifest.json, the file's Hello.
func Manifest() []byte {
	return []byte(fmt.Sprintf("{\"component\":%q,\"host_correlation_id\":%q,\"schema_version\":%q}\n", Component, HostCorrelationID, SchemaVersion))
}

// Push plays the sample over an open fabric connection as a socket writer
// (08 §4.6.1): Hello without a session, the minted id echoed on every
// Event, then Flush and its ack. Returns the minted session.
func Push(conn io.ReadWriter) ([16]byte, error) {
	var sid [16]byte
	if err := writeFrame(conn, &m1pv1.FabricFrame{Kind: &m1pv1.FabricFrame_Hello{Hello: &m1pv1.Hello{
		Component: Component, Pid: 1, Version: "0.1.0", HostCorrelationId: HostCorrelationID,
	}}}); err != nil {
		return sid, err
	}
	ack, err := readFrame(conn)
	if err != nil {
		return sid, err
	}
	ha := ack.GetHelloAck()
	if ha == nil || !ha.GetAccepted() {
		return sid, errors.New("emitter: Hello not accepted")
	}
	if len(ha.GetSessionId()) != 16 {
		return sid, errors.New("emitter: HelloAck carries no minted session (is the daemon ADR-0012 aware?)")
	}
	copy(sid[:], ha.GetSessionId())
	events := Session()
	for _, ev := range events {
		ev.SessionId = sid[:]
		if err := writeFrame(conn, &m1pv1.FabricFrame{Kind: &m1pv1.FabricFrame_Event{Event: ev}}); err != nil {
			return sid, err
		}
	}
	if err := writeFrame(conn, &m1pv1.FabricFrame{Kind: &m1pv1.FabricFrame_Flush{Flush: &m1pv1.Flush{}}}); err != nil {
		return sid, err
	}
	fa, err := readFrame(conn)
	if err != nil {
		return sid, err
	}
	if d := fa.GetFlushAck().GetDrained(); d != uint64(len(events)) {
		return sid, fmt.Errorf("emitter: FlushAck drained %d, want %d", d, len(events))
	}
	return sid, nil
}

func writeFrame(w io.Writer, f *m1pv1.FabricFrame) error {
	payload, err := proto.Marshal(f)
	if err != nil {
		return err
	}
	if len(payload) == 0 || len(payload) > maxFrame {
		return fmt.Errorf("emitter: payload of %d bytes unframeable", len(payload))
	}
	var hdr [headerLen]byte
	copy(hdr[:4], magic[:])
	hdr[4] = 0x01
	binary.LittleEndian.PutUint32(hdr[5:], uint32(len(payload))) //nolint:gosec // G115: bounded above
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(payload)
	return err
}

func readFrame(r io.Reader) (*m1pv1.FabricFrame, error) {
	var hdr [headerLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	if string(hdr[:4]) != string(magic[:]) || hdr[4] != 0x01 {
		return nil, errors.New("emitter: not an M1PL/1 frame")
	}
	n := binary.LittleEndian.Uint32(hdr[5:])
	if n == 0 || n > maxFrame {
		return nil, fmt.Errorf("emitter: frame len %d out of bound", n)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	f := &m1pv1.FabricFrame{}
	return f, proto.Unmarshal(payload, f)
}
