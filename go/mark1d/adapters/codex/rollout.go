package codex

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/tailers"
)

// rolloutFormat is reader (a): the on-disk rollout JSONL
// ($CODEX_HOME/sessions/YYYY/MM/DD/rollout-<ts>-<thread_id>.jsonl, one
// `{timestamp, ordinal, type, payload}` line per RolloutItem). Usage is the
// `token_usage_record` line — one per completed API response — keyed
// (thread_id, turn_id, response_id). `event_msg`/`token_count` snapshots are
// never read, which is what defeats openai/codex#14489 by construction.
func rolloutFormat() tailers.Format {
	return tailers.Format{Discover: discoverRollouts, Cwd: sessionMetaCwd, NewParser: newRolloutParser}
}

// discoverRollouts walks every dated directory: a resumed session appends to
// the file its first day created, so no date window is safe to skip.
// ponytail: one Glob over the whole tree per sweep; bound by year/month
// dirs if a sessions tree ever grows large enough to measure.
func discoverRollouts(dir string, open func(path string, role tailers.Role, session uuid.UUID)) {
	paths, _ := filepath.Glob(filepath.Join(dir, "*", "*", "*", "rollout-*.jsonl"))
	for _, p := range paths {
		if id, ok := threadFromName(filepath.Base(p)); ok {
			open(p, tailers.RoleParent, id)
		}
	}
}

// threadFromName parses rollout_file_name.rs's `rollout-<19-char ts>-<thread>[_<rollout>].jsonl`.
func threadFromName(name string) (uuid.UUID, bool) {
	core, ok := strings.CutSuffix(strings.TrimPrefix(name, "rollout-"), ".jsonl")
	if !ok || len(core) < 21 || core[19] != '-' {
		return uuid.UUID{}, false
	}
	thread, _, _ := strings.Cut(core[20:], "_")
	id, err := uuid.Parse(thread)
	if err != nil {
		return uuid.UUID{}, false
	}
	return id, true
}

// sessionMetaCwd reads the head line's `session_meta.payload.cwd` (SessionMeta.cwd).
func sessionMetaCwd(line []byte) string {
	var l struct {
		Type    string `json:"type"`
		Payload struct {
			Cwd string `json:"cwd"`
		} `json:"payload"`
	}
	if json.Unmarshal(line, &l) != nil || l.Type != "session_meta" {
		return ""
	}
	return l.Payload.Cwd
}

type rolloutLine struct {
	Timestamp string `json:"timestamp"`
	Type      string `json:"type"`
	Payload   struct {
		Model      string `json:"model"` // turn_context
		TurnID     string `json:"turn_id"`
		ResponseID string `json:"response_id"`
		Usage      *struct {
			InputTokens           uint64 `json:"input_tokens"`
			CachedInputTokens     uint64 `json:"cached_input_tokens"`
			CacheWriteInputTokens uint64 `json:"cache_write_input_tokens"`
			OutputTokens          uint64 `json:"output_tokens"`
		} `json:"usage"`
	} `json:"payload"`
}

// newRolloutParser keeps the last turn_context model: the record carries none.
func newRolloutParser() func(line []byte) (tailers.Line, bool) {
	model := ""
	return func(line []byte) (tailers.Line, bool) {
		var l rolloutLine
		if json.Unmarshal(line, &l) != nil {
			return tailers.Line{}, false
		}
		switch l.Type {
		case "turn_context":
			if l.Payload.Model != "" {
				model = l.Payload.Model
			}
		case "token_usage_record":
			if u := l.Payload.Usage; u != nil {
				return tailers.Line{
					MessageID: l.Payload.TurnID, RequestID: l.Payload.ResponseID,
					Model: model, Timestamp: l.Timestamp,
					InputTokens: u.InputTokens, OutputTokens: u.OutputTokens,
					CacheCreationTokens: u.CacheWriteInputTokens, CacheReadTokens: u.CachedInputTokens,
				}, true
			}
		}
		return tailers.Line{}, false
	}
}

// hasUsageRecord reports whether any of the newest few rollouts under dir
// carries a token_usage_record line — DetectUsage's "which reader is live".
func hasUsageRecord(dir string) bool {
	paths, _ := filepath.Glob(filepath.Join(dir, "*", "*", "*", "rollout-*.jsonl"))
	const newest, chunk = 16, 1 << 20
	for i := len(paths) - 1; i >= 0 && i >= len(paths)-newest; i-- {
		f, err := os.Open(paths[i])
		if err != nil {
			continue
		}
		buf, carry := make([]byte, chunk), []byte(nil)
		for {
			n, rerr := f.Read(buf)
			window := append(carry, buf[:n]...)
			if bytes.Contains(window, []byte(`"type":"token_usage_record"`)) {
				_ = f.Close()
				return true
			}
			if rerr != nil {
				break
			}
			carry = append([]byte(nil), window[max(0, len(window)-64):]...)
		}
		_ = f.Close()
	}
	return false
}
