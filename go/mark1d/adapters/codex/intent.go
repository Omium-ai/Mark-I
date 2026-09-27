package codex

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/intent"
)

// IntentSource reads the person's prompts from the rollout under sessionsDir ($CODEX_HOME/sessions): the event_msg user_message, or a user response_item that is not context Codex injected.
func IntentSource(sessionsDir string) intent.Source {
	return intent.Source{
		Find: func(session uuid.UUID) (string, string, bool) {
			m, _ := filepath.Glob(filepath.Join(sessionsDir, "*", "*", "*", "rollout-*"+session.String()+"*.jsonl"))
			for _, p := range m {
				if id, ok := threadFromName(filepath.Base(p)); ok && id == session {
					return p, "", true
				}
			}
			return "", "", false
		},
		Line: rolloutPrompt,
	}
}

func rolloutPrompt(line []byte) (cwd, prompt string, at time.Time) {
	var l struct {
		Timestamp time.Time `json:"timestamp"`
		Type      string    `json:"type"`
		Payload   struct {
			Type    string          `json:"type"`
			Role    string          `json:"role"`
			Cwd     string          `json:"cwd"`
			Message json.RawMessage `json:"message"`
			Content json.RawMessage `json:"content"`
		} `json:"payload"`
	}
	if json.Unmarshal(line, &l) != nil {
		return "", "", time.Time{}
	}
	p := l.Payload
	switch {
	case l.Type == "session_meta" || l.Type == "turn_context":
		return p.Cwd, "", l.Timestamp
	case l.Type == "event_msg" && p.Type == "user_message":
		var s string
		_ = json.Unmarshal(p.Message, &s)
		return "", s, l.Timestamp
	case l.Type == "response_item" && p.Type == "message" && p.Role == "user":
		var blocks []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}
		if json.Unmarshal(p.Content, &blocks) != nil {
			return "", "", l.Timestamp
		}
		parts := make([]string, 0, len(blocks))
		for _, b := range blocks {
			if b.Type == "input_text" && !injected(b.Text) {
				parts = append(parts, b.Text)
			}
		}
		return "", strings.Join(parts, "\n"), l.Timestamp
	}
	return "", "", l.Timestamp
}

// injected is the context Codex writes as a user turn: tag-wrapped blocks (<environment_context>, <user_instructions>, <turn_aborted>) and the AGENTS.md preamble.
func injected(s string) bool {
	t := strings.TrimSpace(s)
	return strings.HasPrefix(t, "# AGENTS.md instructions") || (strings.HasPrefix(t, "<") && strings.HasSuffix(t, ">"))
}
