package copilot

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/tailers"
)

// eventsFormat is the DIAGNOSTIC reader over $COPILOT_HOME/session-state/
// <session-uuid>/events.jsonl (schema/session-events.subset.schema.json at the
// pin): `session.start` opens a session (cwd is its containment evidence) and
// `session.shutdown` closes it. Nothing else on this surface is read — per-request
// usage is `ephemeral` and never persisted, and the shutdown rollup carries no
// per-request id, so this reader can never produce a Usage (08 §2 idem_key).
// ponytail: tailers.stream is Usage-only, so the two bodies ride the parser's
// own Observe+Emit and every line reports "not usage"; lift into a
// Format.Diagnostic seam in tailers when a second adapter needs one.
func eventsFormat(cfg TailConfig) tailers.Format {
	return tailers.Format{Discover: discoverSessions, Cwd: startCwd, NewParser: func() func([]byte) (tailers.Line, bool) {
		return newEventsParser(cfg)
	}}
}

func discoverSessions(dir string, open func(path string, role tailers.Role, session uuid.UUID)) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		session, err := uuid.Parse(e.Name())
		if !e.IsDir() || err != nil {
			continue
		}
		open(filepath.Join(dir, e.Name(), "events.jsonl"), tailers.RoleParent, session)
	}
}

type eventLine struct {
	Type      string `json:"type"`
	Timestamp string `json:"timestamp"`
	Data      struct {
		SessionID      string `json:"sessionId"`
		CopilotVersion string `json:"copilotVersion"`
		Context        struct {
			Cwd string `json:"cwd"`
		} `json:"context"`
		ShutdownType     string  `json:"shutdownType"`
		SessionStartTime float64 `json:"sessionStartTime"`
	} `json:"data"`
}

// startCwd is session.start's context.cwd — the head of every stream.
func startCwd(line []byte) string {
	var l eventLine
	if json.Unmarshal(line, &l) != nil || l.Type != "session.start" {
		return ""
	}
	return l.Data.Context.Cwd
}

func newEventsParser(cfg TailConfig) func(line []byte) (tailers.Line, bool) {
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	emit := func(ev *m1pv1.Event, at time.Time) {
		if !at.IsZero() {
			ev.OccurredAt = timestamppb.New(at)
		}
		if cfg.Observe != nil {
			cfg.Observe(ev)
		}
		if cfg.Emit != nil {
			if err := cfg.Emit(context.Background(), ev); err != nil {
				log.Error("copilot: diagnostic emit failed", "err", err)
			}
		}
	}
	var session uuid.UUID
	started := false
	return func(line []byte) (tailers.Line, bool) {
		var l eventLine
		if json.Unmarshal(line, &l) != nil {
			return tailers.Line{}, false
		}
		at, _ := time.Parse(time.RFC3339Nano, l.Timestamp)
		switch l.Type {
		case "session.start":
			id, err := uuid.Parse(l.Data.SessionID)
			if err != nil || started {
				return tailers.Line{}, false
			}
			session, started = id, true
			emit(&m1pv1.Event{SessionId: session[:], Body: &m1pv1.Event_SessionStart{SessionStart: &m1pv1.SessionStart{
				Agent: "copilot", AgentVersion: l.Data.CopilotVersion,
				CapturePaths: []m1pv1.CapturePath{m1pv1.CapturePath_CAPTURE_PATH_TRANSCRIPT},
			}}}, at)
		case "session.shutdown":
			if !started {
				return tailers.Line{}, false
			}
			end := &m1pv1.SessionEnd{Reason: m1pv1.EndReason_END_REASON_EXIT}
			if l.Data.ShutdownType == "error" {
				end.Reason = m1pv1.EndReason_END_REASON_CRASH_DETECTED
			}
			if startMs := int64(l.Data.SessionStartTime); startMs > 0 && !at.IsZero() && at.UnixMilli() > startMs {
				end.DurationMs = uint64(at.UnixMilli() - startMs) //nolint:gosec // G115: the guard above makes the difference positive
			}
			emit(&m1pv1.Event{SessionId: session[:], Body: &m1pv1.Event_SessionEnd{SessionEnd: end}}, at)
		}
		return tailers.Line{}, false
	}
}
