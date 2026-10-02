// Package validateevents is `mark1 validate-events` (08 §7.8): a host checks a
// JSONL file of m1p.v1 Events against the external-writer contract (08 §4.6)
// before it ever connects. Pure: no daemon, no network, no state dir. It
// checks what the daemon would check at admission plus the ordering rules a
// host owns — causal order and non-decreasing timestamps — and deliberately
// NOT seq, which is the daemon's to assign.
package validateevents

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/Omium-ai/omium-mark1/go/mark1/internal/cli"
)

// CodeInvalid is the M1E row for a file that fails validation (08 §9).
const CodeInvalid = "M1E-4006"

// maxLine mirrors the daemon's 1 MiB admission bound (07 §6) with headroom
// for protojson's expansion; a line past it is a finding, never a stall.
const maxLine = 4 << 20

type Options struct {
	Path string // JSONL file; "" or "-" reads stdin
}

// Finding is one line's verdict. Line is 1-based.
type Finding struct {
	Line    int    `json:"line"`
	Message string `json:"message"`
}

// Report is the --json contract: ok iff errors is empty.
type Report struct {
	OK       bool      `json:"ok"`
	Lines    int       `json:"lines"`
	Errors   []Finding `json:"errors"`
	Warnings []Finding `json:"warnings"`
}

// Run validates and prints. Non-zero exit (ExitVerify) on any error; usage
// exit on an unreadable input.
func Run(_ context.Context, env *cli.Env, opts Options) error {
	var in io.Reader = os.Stdin
	if opts.Path != "" && opts.Path != "-" {
		f, err := os.Open(opts.Path)
		if err != nil {
			return cli.Failf(cli.ExitUsage, "", "%v", err)
		}
		defer func() { _ = f.Close() }()
		in = f
	}
	rep, err := Validate(in)
	if err != nil {
		return cli.Failf(cli.ExitRuntime, "", "reading input: %v", err)
	}
	if env.JSON {
		if err := json.NewEncoder(env.Stdout).Encode(rep); err != nil {
			return cli.Failf(cli.ExitRuntime, "", "writing report: %v", err)
		}
	} else {
		for _, f := range rep.Errors {
			_, _ = fmt.Fprintf(env.Stdout, "line %d: error: %s\n", f.Line, f.Message)
		}
		for _, f := range rep.Warnings {
			_, _ = fmt.Fprintf(env.Stdout, "line %d: warning: %s\n", f.Line, f.Message)
		}
		_, _ = fmt.Fprintf(env.Stdout, "%d line(s), %d error(s), %d warning(s): %s\n", rep.Lines, len(rep.Errors), len(rep.Warnings), map[bool]string{true: "OK", false: "INVALID"}[rep.OK])
	}
	if !rep.OK {
		ee := cli.Failf(cli.ExitVerify, "M1E-4006", "%d error(s) — see report", len(rep.Errors)) // the literal: the exit-code taxonomy test reads it
		ee.Emitted = true
		return ee
	}
	return nil
}

// session is the per-session ordering state (08 §4.6.3). Sessions are keyed
// by session_id; a file-tail host leaves it empty, which is one session.
type session struct {
	open   bool // a host-declared task is open
	turns  int  // Turns inside the open task
	lastAt time.Time
	hasAt  bool
}

// Validate reads JSONL from r and returns the report; the only error is I/O.
func Validate(r io.Reader) (*Report, error) {
	rep := &Report{Errors: []Finding{}, Warnings: []Finding{}}
	sessions := map[string]*session{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), maxLine)
	strict := protojson.UnmarshalOptions{}
	lenient := protojson.UnmarshalOptions{DiscardUnknown: true}
	n := 0
	for sc.Scan() {
		n++
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		errf := func(format string, a ...any) { rep.Errors = append(rep.Errors, Finding{n, fmt.Sprintf(format, a...)}) }
		warnf := func(format string, a ...any) {
			rep.Warnings = append(rep.Warnings, Finding{n, fmt.Sprintf(format, a...)})
		}

		ev := &m1pv1.Event{}
		if err := strict.Unmarshal(line, ev); err != nil {
			if !strings.Contains(err.Error(), "unknown field") {
				errf("not an m1p.v1.Event: %v", trimProto(err))
				continue
			}
			// Unknown fields are additive within the major (08 §1.1 external
			// writer): a warning, and the line is re-read without them.
			warnf("unknown field ignored: %v", trimProto(err))
			ev = &m1pv1.Event{}
			if err := lenient.Unmarshal(line, ev); err != nil {
				errf("not an m1p.v1.Event: %v", trimProto(err))
				continue
			}
		}

		// Required fields and the envelope rules a host owns.
		if ev.GetBody() == nil {
			errf("no body: exactly one of the Event body arms is required")
			continue
		}
		if l := len(ev.GetEventId()); l != 0 && l != 16 {
			errf("event_id is %d bytes, want 16 (UUIDv7) or empty", l)
		} else if l == 0 {
			warnf("event_id empty: the daemon mints one, but a re-scan then duplicates this line at ingest (08 §4.6.2)")
		}
		if l := len(ev.GetSessionId()); l != 0 && l != 16 {
			errf("session_id is %d bytes, want 16 or empty", l)
		}
		if ev.GetSeq() != 0 || ev.GetSessionEpoch() != 0 {
			errf("seq/session_epoch must be zero: the daemon assigns them (07 §2)")
		}
		if len(ev.GetTenantId()) != 0 || len(ev.GetDeviceId()) != 0 || ev.GetReceivedAt() != nil || ev.GetClockSkewMs() != 0 {
			errf("server-stamped band set (tenant_id/device_id/received_at/clock_skew_ms must be unset)")
		}
		if u := ev.GetUsage(); u != nil {
			if u.GetMessageId() == "" || u.GetRequestId() == "" {
				errf("Usage needs message_id and request_id: the daemon derives idem_key from them")
			}
			if len(u.GetIdemKey()) != 0 {
				warnf("Usage.idem_key set: the daemon overwrites it for an ext session (ADR-0012 §4)")
			}
		}

		ss := sessions[string(ev.GetSessionId())]
		if ss == nil {
			ss = &session{}
			sessions[string(ev.GetSessionId())] = ss
		}
		if ev.GetOccurredAt() == nil {
			errf("occurred_at missing")
		} else {
			at := ev.GetOccurredAt().AsTime()
			if ss.hasAt && at.Before(ss.lastAt) {
				errf("occurred_at %s is before the previous event's %s", at.Format(time.RFC3339Nano), ss.lastAt.Format(time.RFC3339Nano))
			}
			ss.lastAt, ss.hasAt = at, true
		}

		// Causal order (08 §4.6.3): TaskOpen → Turn… → Usage/ArtifactOutcome → TaskClose.
		switch ev.GetBody().(type) {
		case *m1pv1.Event_TaskOpen:
			if ss.open {
				errf("TaskOpen while a task is already open (close it first)")
			}
			ss.open, ss.turns = true, 0
		case *m1pv1.Event_TaskClose:
			if !ss.open {
				errf("TaskClose before its TaskOpen")
			}
			ss.open, ss.turns = false, 0
		case *m1pv1.Event_Turn:
			if !ss.open {
				errf("Turn outside an open task (emit TaskOpen first)")
			}
			ss.turns++
		case *m1pv1.Event_ArtifactOutcome:
			if ss.turns == 0 {
				errf("ArtifactOutcome before any Turn in this task")
			}
		case *m1pv1.Event_Usage:
			if ss.turns == 0 {
				errf("Usage before any Turn in this task")
			}
		case *m1pv1.Event_SessionEnd:
			if ss.open {
				warnf("SessionEnd with a task still open")
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	rep.Lines = n
	rep.OK = len(rep.Errors) == 0
	return rep, nil
}

// trimProto drops protojson's "proto: " prefix and newlines from an error.
func trimProto(err error) string {
	return strings.ReplaceAll(strings.TrimPrefix(err.Error(), "proto: "), "\n", " ")
}
