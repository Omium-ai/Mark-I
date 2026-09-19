package opencode

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

var errUnprobed = errors.New("no opencode capture at this version yet")

// probeLine is every field newCaptureParser and assistantCwd read, as pointers so absence and a wrong type both surface.
type probeLine struct {
	Type       *string `json:"type"`
	Properties *struct {
		Info *struct {
			ID         *string `json:"id"`
			Role       *string `json:"role"`
			ProviderID *string `json:"providerID"`
			ModelID    *string `json:"modelID"`
			Finish     *string `json:"finish"`
			Path       *struct {
				Cwd *string `json:"cwd"`
			} `json:"path"`
		} `json:"info"`
		Part *struct {
			ID        *string `json:"id"`
			MessageID *string `json:"messageID"`
			Type      *string `json:"type"`
			Tokens    *struct {
				Input     *float64 `json:"input"`
				Output    *float64 `json:"output"`
				Reasoning *float64 `json:"reasoning"`
				Cache     *struct {
					Read  *float64 `json:"read"`
					Write *float64 `json:"write"`
				} `json:"cache"`
			} `json:"tokens"`
		} `json:"part"`
		Time *float64 `json:"time"`
	} `json:"properties"`
}

func (l *probeLine) missingAssistant() string {
	i := l.Properties.Info
	var m []string
	for _, c := range []struct {
		name string
		ok   bool
	}{
		{"info.id", i.ID != nil},
		{"info.providerID", i.ProviderID != nil},
		{"info.modelID", i.ModelID != nil},
		{"info.path.cwd", i.Path != nil && i.Path.Cwd != nil},
	} {
		if !c.ok {
			m = append(m, c.name)
		}
	}
	return strings.Join(m, ", ")
}

func (l *probeLine) missingStep() string {
	p := l.Properties.Part
	tk := p.Tokens != nil
	ca := tk && p.Tokens.Cache != nil
	var m []string
	for _, c := range []struct {
		name string
		ok   bool
	}{
		{"part.id", p.ID != nil},
		{"part.messageID", p.MessageID != nil},
		{"part.tokens.input", tk && p.Tokens.Input != nil},
		{"part.tokens.output", tk && p.Tokens.Output != nil},
		{"part.tokens.reasoning", tk && p.Tokens.Reasoning != nil},
		{"part.tokens.cache.read", ca && p.Tokens.Cache.Read != nil},
		{"part.tokens.cache.write", ca && p.Tokens.Cache.Write != nil},
		{"time", l.Properties.Time != nil},
	} {
		if !c.ok {
			m = append(m, c.name)
		}
	}
	return strings.Join(m, ", ")
}

// Compatibility is the admission: version ∈ SupportedVersions ⇒ Pinned; else the shim's hook
// shape is checked, then the newest capture mark1.js wrote is probed for every field capture.go reads.
func (a *Adapter) Compatibility(version string) (adapters.Compat, error) {
	if Supported(version) {
		return adapters.Pinned, nil
	}
	if version == "" {
		return adapters.Incompatible, errors.New("opencode version unsniffable")
	}
	_, state, err := a.paths()
	if err != nil {
		return adapters.Incompatible, err
	}
	if err := adapters.HookShape(state, a.Name()); err != nil {
		return adapters.Incompatible, err
	}
	dir, err := a.CaptureDir()
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

// probe scans captures newest-first; the first with a finished assistant message decides.
// ponytail: the capture carries no opencode version, so recency attributes the newest file to the sniffed build.
func probe(dir, version string) error {
	type file struct {
		path string
		mod  int64
	}
	paths, _ := filepath.Glob(filepath.Join(dir, "ses_*.jsonl"))
	files := make([]file, 0, len(paths))
	for _, p := range paths {
		if info, err := os.Stat(p); err == nil {
			files = append(files, file{p, info.ModTime().UnixNano()})
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].mod > files[j].mod })
	for _, f := range files {
		decided, err := probeCapture(f.path, version)
		if decided {
			return err
		}
	}
	return fmt.Errorf("%w: no opencode %s capture with a finished assistant message under %s; run one session, then restart mark1d", errUnprobed, version, dir)
}

// probeCapture returns decided=false while no assistant message has finished in this capture.
func probeCapture(path, version string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, nil
	}
	defer func() { _ = f.Close() }()
	r := bufio.NewReader(f)
	assistant, step := false, false
	for {
		line, rerr := r.ReadBytes('\n')
		var l probeLine
		if uerr := json.Unmarshal(line, &l); uerr != nil && len(strings.TrimSpace(string(line))) > 0 {
			return true, fmt.Errorf("opencode %s capture line mistyped: %w", version, uerr)
		}
		if l.Type != nil && l.Properties != nil {
			switch *l.Type {
			case "message.updated":
				if i := l.Properties.Info; i != nil && i.Role != nil && *i.Role == "assistant" {
					if m := l.missingAssistant(); m != "" {
						return true, fmt.Errorf("opencode %s assistant message.updated lacks %s", version, m)
					}
					assistant = true
					if i.Finish != nil && !step {
						return true, fmt.Errorf("opencode %s assistant message finished with no step-finish part recorded before it", version)
					}
				}
			case "message.part.updated":
				if p := l.Properties.Part; p != nil && p.Type != nil && *p.Type == "step-finish" {
					if m := l.missingStep(); m != "" {
						return true, fmt.Errorf("opencode %s step-finish part lacks %s", version, m)
					}
					if !assistant {
						return true, fmt.Errorf("opencode %s step-finish part precedes any assistant message.updated", version)
					}
					step = true
				}
			}
		}
		if rerr != nil {
			return step, nil
		}
	}
}
