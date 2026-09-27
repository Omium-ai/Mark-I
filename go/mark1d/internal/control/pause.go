package control

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"

	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/provision"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/coverage"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/off"
)

// AgentFor is fabric.Gate.AgentFor's source: the agent the session's SessionStart named, "" when the hub never saw one.
func (h *Hub) AgentFor(sid [16]byte) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if s := h.sessions[sid]; s != nil {
		return s.Agent
	}
	return ""
}

type liveRow struct {
	LiveSession
	Paused bool `json:"paused"`
}

// markPaused stamps each live session with its agent's pause marker; the global switch is /v1/status's own `paused`.
func (s *Server) markPaused(live []LiveSession) []liveRow {
	out := make([]liveRow, len(live))
	for i, l := range live {
		out[i] = liveRow{l, off.AgentOff(s.cfg.StateDir, l.Agent)}
	}
	return out
}

// setAgentOff is setOff for one agent (desktop spec §5.9): the per-agent marker every reader checks after the global OFF, journalled with the agent-scoped reason on each transition; a repeated pause or resume journals nothing.
func (s *Server) setAgentOff(w http.ResponseWriter, r *http.Request, paused bool) {
	name, ok := agentName(w, r)
	if !ok {
		return
	}
	marker := off.AgentMarker(s.cfg.StateDir, name)
	ts := now()
	var err error
	switch was := off.AgentOff(s.cfg.StateDir, name); {
	case paused && !was:
		b, _ := json.Marshal(map[string]string{"agent": name, "written_at": ts})
		if err = writeAtomic(marker, b); err == nil {
			err = appendJSONL(coverage.JournalPath(s.cfg.StateDir), map[string]any{"ts": ts, "kind": "disable", "reason": coverage.ReasonAgentPause, "scope": "all", "agent": name})
		}
	case !paused && was:
		if err = os.Remove(marker); errors.Is(err, os.ErrNotExist) {
			err = nil
		}
		if err == nil {
			err = appendJSONL(coverage.JournalPath(s.cfg.StateDir), map[string]any{"ts": ts, "kind": "enable", "reason": coverage.ReasonAgentResume, "scope": "all", "agent": name})
		}
	}
	if err != nil {
		internal(w, err)
		return
	}
	if !paused {
		s.Reprovision(name) // the daemon-start upgrade skipped this agent while it was paused
	}
	writeJSON(w, map[string]any{"agent": name, "paused": off.AgentOff(s.cfg.StateDir, name), "receipted_transition_id": nil})
}

// Reprovision is provision.Reconcile under the lock the enable and repair routes hold, logged: an upgraded fragment at Info, one left alone for a human at Warn.
func (s *Server) Reprovision(only ...string) []provision.Outcome {
	s.files.Lock()
	out := provision.Reconcile(s.cfg.StateDir, s.cfg.Version, only...)
	s.files.Unlock()
	for _, o := range out {
		switch o.Action {
		case "current":
		case "upgraded", "paused":
			s.cfg.Log.Info("mark1d: agent integration reprovision", "agent", o.Agent, "action", o.Action, "version", s.cfg.Version, "detail", o.Detail)
		default:
			s.cfg.Log.Warn("mark1d: agent integration reprovision", "agent", o.Agent, "action", o.Action, "code", o.Code, "detail", o.Detail)
		}
	}
	return out
}
