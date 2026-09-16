package opencode

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/tailers"
)

// captureFormat is the Usage reader over mark1.js's per-session JSONL: one
// vendor bus event per line, `{type, properties}` as the plugin `event` hook
// received it (plugin/index.ts), restricted to assistant `message.updated`
// (Assistant info: path.cwd, providerID/modelID) and `message.part.updated`
// whose part is a `step-finish` (StepFinishPart: per-LLM-call tokens + cost,
// schema/src/v1/session.ts). Usage is keyed (messageID, partID): a step-finish
// part is one API round-trip, and its id is unique where assistantMessageID
// is reused across a tool-loop turn. Files are <sessionID>.jsonl, flat.
func captureFormat() tailers.Format {
	return tailers.Format{Discover: discoverCaptures, Cwd: assistantCwd, NewParser: newCaptureParser}
}

func discoverCaptures(dir string, open func(path string, role tailers.Role, session uuid.UUID)) {
	paths, _ := filepath.Glob(filepath.Join(dir, "ses_*.jsonl"))
	for _, p := range paths {
		open(p, tailers.RoleParent, SessionUUID(strings.TrimSuffix(filepath.Base(p), ".jsonl")))
	}
}

// assistantCwd is Assistant.path.cwd on a message.updated line — the head of
// every stream, since session.updateMessage runs before any step-finish part.
func assistantCwd(line []byte) string {
	var l struct {
		Type       string `json:"type"`
		Properties struct {
			Info struct {
				Role string `json:"role"`
				Path struct {
					Cwd string `json:"cwd"`
				} `json:"path"`
			} `json:"info"`
		} `json:"properties"`
	}
	if json.Unmarshal(line, &l) != nil || l.Type != "message.updated" || l.Properties.Info.Role != "assistant" {
		return ""
	}
	return l.Properties.Info.Path.Cwd
}

type tokens struct {
	Input     float64 `json:"input"`
	Output    float64 `json:"output"`
	Reasoning float64 `json:"reasoning"`
	Cache     struct {
		Read  float64 `json:"read"`
		Write float64 `json:"write"`
	} `json:"cache"`
}

type captureLine struct {
	Type       string `json:"type"`
	Properties struct {
		Info struct {
			ID         string `json:"id"`
			Role       string `json:"role"`
			ProviderID string `json:"providerID"`
			ModelID    string `json:"modelID"`
		} `json:"info"`
		Part struct {
			ID        string  `json:"id"`
			MessageID string  `json:"messageID"`
			Type      string  `json:"type"`
			Tokens    *tokens `json:"tokens"`
		} `json:"part"`
		Time float64 `json:"time"`
	} `json:"properties"`
}

func count(f float64) uint64 {
	if f < 0 {
		return 0
	}
	return uint64(f)
}

// newCaptureParser keeps providerID/modelID per assistant message: the part
// carries none. opencode's tokens.input EXCLUDES cache reads/writes
// (session.ts getUsage subtracts them) and tokens.output EXCLUDES reasoning,
// which is billed as output and folded back in.
func newCaptureParser() func(line []byte) (tailers.Line, bool) {
	models := map[string]string{}
	return func(line []byte) (tailers.Line, bool) {
		var l captureLine
		if json.Unmarshal(line, &l) != nil {
			return tailers.Line{}, false
		}
		switch l.Type {
		case "message.updated":
			if i := l.Properties.Info; i.Role == "assistant" && i.ID != "" {
				models[i.ID] = i.ProviderID + "/" + i.ModelID
			}
		case "message.part.updated":
			p := l.Properties.Part
			if p.Type != "step-finish" || p.Tokens == nil || p.ID == "" || p.MessageID == "" {
				return tailers.Line{}, false
			}
			ts := ""
			if l.Properties.Time > 0 {
				ts = time.UnixMilli(int64(l.Properties.Time)).UTC().Format(time.RFC3339Nano)
			}
			return tailers.Line{
				MessageID: p.MessageID, RequestID: p.ID,
				Model: models[p.MessageID], Timestamp: ts,
				InputTokens: count(p.Tokens.Input), OutputTokens: count(p.Tokens.Output + p.Tokens.Reasoning),
				CacheCreationTokens: count(p.Tokens.Cache.Write), CacheReadTokens: count(p.Tokens.Cache.Read),
			}, true
		}
		return tailers.Line{}, false
	}
}
