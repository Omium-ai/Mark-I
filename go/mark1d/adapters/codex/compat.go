package codex

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters"
)

var errUnprobed = errors.New("no rollout at this version yet")

// probeRecord is every token_usage_record field newRolloutParser reads, as pointers so absence and a wrong type both surface.
type probeRecord struct {
	Timestamp *string `json:"timestamp"`
	Payload   *struct {
		TurnID     *string `json:"turn_id"`
		ResponseID *string `json:"response_id"`
		Usage      *struct {
			InputTokens           *uint64 `json:"input_tokens"`
			CachedInputTokens     *uint64 `json:"cached_input_tokens"`
			CacheWriteInputTokens *uint64 `json:"cache_write_input_tokens"`
			OutputTokens          *uint64 `json:"output_tokens"`
		} `json:"usage"`
	} `json:"payload"`
}

func (r *probeRecord) missing() string {
	p := r.Payload != nil
	u := p && r.Payload.Usage != nil
	var m []string
	for _, c := range []struct {
		name string
		ok   bool
	}{
		{"timestamp", r.Timestamp != nil},
		{"payload.turn_id", p && r.Payload.TurnID != nil},
		{"payload.response_id", p && r.Payload.ResponseID != nil},
		{"usage.input_tokens", u && r.Payload.Usage.InputTokens != nil},
		{"usage.cached_input_tokens", u && r.Payload.Usage.CachedInputTokens != nil},
		{"usage.cache_write_input_tokens", u && r.Payload.Usage.CacheWriteInputTokens != nil},
		{"usage.output_tokens", u && r.Payload.Usage.OutputTokens != nil},
	} {
		if !c.ok {
			m = append(m, c.name)
		}
	}
	return strings.Join(m, ", ")
}

// Compatibility is the admission: version ∈ SupportedVersions ⇒ Pinned; else the shim's hook shape is
// checked, then the newest rollout whose session_meta stamps this cli_version is probed for every field rollout.go reads.
func (a *Adapter) Compatibility(version string) (adapters.Compat, error) {
	if Supported(version) {
		return adapters.Pinned, nil
	}
	if version == "" {
		return adapters.Incompatible, errors.New("codex version unsniffable")
	}
	if _, state, err := a.paths(); err == nil {
		if err := adapters.HookShape(state, a.Name()); err != nil {
			return adapters.Incompatible, err
		}
	}
	dir, err := a.SessionsDir()
	if err != nil {
		return adapters.Incompatible, err
	}
	if err := probe(dir, version); err != nil {
		if errors.Is(err, errUnprobed) {
			return adapters.Unprobed, err
		}
		return adapters.Incompatible, err
	}
	return adapters.CompatibleUnpinned, nil
}

// probe scans rollouts newest-first; the first one at this version with a completed API response decides.
// ponytail: unbounded newest-first scan, same as claudecode's; cap the file count if boot gets slow.
func probe(dir, version string) error {
	type file struct {
		path string
		mod  int64
	}
	paths, _ := filepath.Glob(filepath.Join(dir, "*", "*", "*", "rollout-*.jsonl"))
	files := make([]file, 0, len(paths))
	for _, p := range paths {
		if info, err := os.Stat(p); err == nil {
			files = append(files, file{p, info.ModTime().UnixNano()})
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].mod > files[j].mod })
	for _, f := range files {
		decided, err := probeRollout(f.path, version)
		if decided {
			return err
		}
	}
	return fmt.Errorf("%w: no codex %s rollout with a completed turn under %s; run one session, then restart mark1d", errUnprobed, version, dir)
}

// probeRollout returns decided=false when the file is another version or has no completed response yet.
func probeRollout(path, version string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, nil
	}
	defer func() { _ = f.Close() }()
	r := bufio.NewReader(f)
	head, _ := r.ReadBytes('\n')
	var meta struct {
		Type    string `json:"type"`
		Payload struct {
			Cwd        *string `json:"cwd"`
			CliVersion string  `json:"cli_version"`
		} `json:"payload"`
	}
	if json.Unmarshal(head, &meta) != nil || meta.Type != "session_meta" || meta.Payload.CliVersion != version {
		return false, nil
	}
	if meta.Payload.Cwd == nil {
		return true, fmt.Errorf("codex %s rollout session_meta lacks payload.cwd", version)
	}
	model, responded := false, false
	for {
		line, err := r.ReadBytes('\n')
		var l struct {
			Type    string `json:"type"`
			Payload struct {
				Type  string  `json:"type"`
				Role  string  `json:"role"`
				Model *string `json:"model"`
			} `json:"payload"`
		}
		if json.Unmarshal(line, &l) == nil {
			switch l.Type {
			case "turn_context":
				model = model || l.Payload.Model != nil
			case "event_msg":
				responded = responded || l.Payload.Type == "token_count"
			case "response_item":
				responded = responded || (l.Payload.Type == "message" && l.Payload.Role == "assistant")
			case "token_usage_record":
				var rec probeRecord
				if err := json.Unmarshal(line, &rec); err != nil {
					return true, fmt.Errorf("codex %s token_usage_record mistyped: %w", version, err)
				}
				if m := rec.missing(); m != "" {
					return true, fmt.Errorf("codex %s token_usage_record lacks %s", version, m)
				}
				if !model {
					return true, fmt.Errorf("codex %s rollout has no turn_context.payload.model before its first usage record", version)
				}
				return true, nil
			}
		}
		if err != nil {
			break
		}
	}
	if responded {
		return true, fmt.Errorf("codex %s persists no token_usage_record after an API response (usage records landed in 0.15x); update codex: npm i -g @openai/codex@latest", version)
	}
	return false, nil
}
