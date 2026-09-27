package copilot

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/intent"
)

// IntentSource reads the person's prompts from <session-state>/<session>/events.jsonl: user.message's own content (never transformedContent, which carries injected context); session.start names the cwd.
func IntentSource(sessionStateDir string) intent.Source {
	return intent.Source{
		Find: func(session uuid.UUID) (string, string, bool) {
			p := filepath.Join(sessionStateDir, session.String(), "events.jsonl")
			if _, err := os.Stat(p); err != nil {
				return "", "", false
			}
			return p, "", true
		},
		Line: func(line []byte) (string, string, time.Time) {
			var l struct {
				Type      string    `json:"type"`
				Timestamp time.Time `json:"timestamp"`
				Data      struct {
					Content string `json:"content"`
				} `json:"data"`
			}
			if json.Unmarshal(line, &l) != nil {
				return "", "", time.Time{}
			}
			if l.Type == "user.message" {
				return "", l.Data.Content, l.Timestamp
			}
			return startCwd(line), "", l.Timestamp
		},
	}
}
