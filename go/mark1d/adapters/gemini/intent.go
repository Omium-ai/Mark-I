package gemini

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/intent"
)

// IntentSource reads the person's prompts from the main chat recording under tmpDir (~/.gemini/tmp): a `user` record whose parts are all text. The cwd is the slug's .project_root marker, admitted only when the head's projectHash is that marker's hash.
func IntentSource(tmpDir string) intent.Source {
	return intent.Source{
		Find: func(session uuid.UUID) (string, string, bool) {
			m, _ := filepath.Glob(filepath.Join(tmpDir, "*", "chats", "session-*-"+session.String()[:8]+".jsonl"))
			for _, p := range m {
				raw, err := os.ReadFile(filepath.Join(filepath.Dir(filepath.Dir(p)), ".project_root"))
				if err != nil {
					continue
				}
				marker := strings.TrimSpace(string(raw))
				if id, hash, ok := chatHead(p); ok && id == session && hash == projectHash(marker) {
					return p, marker, true
				}
			}
			return "", "", false
		},
		Line: chatPrompt,
	}
}

func chatHead(path string) (uuid.UUID, string, bool) {
	f, err := os.Open(path) //nolint:gosec // G304: a chat recording under the gemini tmp tree
	if err != nil {
		return uuid.UUID{}, "", false
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 4<<10), headMaxLine)
	if !sc.Scan() {
		return uuid.UUID{}, "", false
	}
	var meta struct {
		SessionID   string `json:"sessionId"`
		ProjectHash string `json:"projectHash"`
	}
	if json.Unmarshal(sc.Bytes(), &meta) != nil {
		return uuid.UUID{}, "", false
	}
	id, err := uuid.Parse(meta.SessionID)
	return id, meta.ProjectHash, err == nil
}

func chatPrompt(line []byte) (string, string, time.Time) {
	var l struct {
		Type      string          `json:"type"`
		Timestamp time.Time       `json:"timestamp"`
		Content   json.RawMessage `json:"content"`
	}
	if json.Unmarshal(line, &l) != nil || l.Type != "user" {
		return "", "", l.Timestamp
	}
	var s string
	if json.Unmarshal(l.Content, &s) == nil {
		return "", s, l.Timestamp
	}
	var parts []map[string]json.RawMessage
	if json.Unmarshal(l.Content, &parts) != nil {
		return "", "", l.Timestamp
	}
	texts := make([]string, 0, len(parts))
	for _, p := range parts {
		var t string
		if len(p) != 1 || json.Unmarshal(p["text"], &t) != nil {
			return "", "", l.Timestamp // a functionResponse or file part: a tool turn, never the person's prompt
		}
		texts = append(texts, t)
	}
	return "", strings.Join(texts, "\n"), l.Timestamp
}
