package opencode

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/intent"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/tailers"
)

// IntentSource reads the person's prompts from mark1.js's <captureDir>/intent/ses_*.jsonl: the plugin notes each chat.message's own text parts with its directory, since opencode keeps its transcript in SQLite.
func IntentSource(captureDir string) intent.Source {
	return intent.Source{
		Find: func(session uuid.UUID) (string, string, bool) {
			m, _ := filepath.Glob(filepath.Join(captureDir, "intent", "ses_*.jsonl"))
			for _, p := range m {
				if SessionUUID(strings.TrimSuffix(filepath.Base(p), ".jsonl")) == session {
					return p, "", true
				}
			}
			return "", "", false
		},
		Line: func(line []byte) (string, string, time.Time) {
			var l struct {
				Type       string `json:"type"`
				Properties struct {
					Cwd  string    `json:"cwd"`
					Text string    `json:"text"`
					Time time.Time `json:"timestamp"`
				} `json:"properties"`
			}
			if json.Unmarshal(line, &l) != nil || l.Type != "chat.message" {
				return "", "", time.Time{}
			}
			return l.Properties.Cwd, l.Properties.Text, l.Properties.Time
		},
	}
}

// NotesDir is where mark1.js notes prompts: <home>/.omium/mark1/capture/opencode/intent, which is <state>/capture/opencode/intent for the default state dir.
// ponytail: a daemon on a non-default --state-dir purges its own tree, not the plugin's fixed one; the plugin reads the default tree's OFF and workspaces.json too, so that setup is dev-only.
func NotesDir(stateDir string) string {
	return filepath.Join(stateDir, "capture", "opencode", "intent")
}

// PurgeNotes removes every prompt mark1.js noted (`mark1 off`, and the agent's revert).
func PurgeNotes(stateDir string) error { return os.RemoveAll(NotesDir(stateDir)) }

// PruneNotes removes each noted session whose prompts name a directory outside roots (the enabled workspaces, .mark1ignore honoured) or no directory at all: a disabled workspace's prompts do not outlive it.
func PruneNotes(stateDir string, roots []string) error {
	ws, err := tailers.NewWorkspaceSet(roots...)
	if err != nil {
		return err
	}
	src := IntentSource(filepath.Dir(NotesDir(stateDir)))
	m, _ := filepath.Glob(filepath.Join(NotesDir(stateDir), "*.jsonl"))
	var errs []error
	for _, p := range m {
		b, err := os.ReadFile(p) //nolint:gosec // G304: a file under mark1's own capture dir
		keep := err == nil
		for _, line := range bytes.Split(b, []byte("\n")) {
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}
			if cwd, _, _ := src.Line(line); cwd == "" || !ws.Allowed(cwd) {
				keep = false
			}
		}
		if !keep {
			if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}
