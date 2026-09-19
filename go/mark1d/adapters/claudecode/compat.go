package claudecode

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters"
)

// Compat is adapters.Compat; the names stay in this package for its callers.
type Compat = adapters.Compat

const (
	Incompatible       = adapters.Incompatible
	Unprobed           = adapters.Unprobed
	Pinned             = adapters.Pinned
	CompatibleUnpinned = adapters.CompatibleUnpinned
)

// probeLine is every field the pinned corpus's selfcheck.py and
// expectations.json rely on, as pointers so absence and a wrong type are both
// distinguishable from a zero value.
type probeLine struct {
	Type      *string `json:"type"`
	Cwd       *string `json:"cwd"`
	SessionID *string `json:"sessionId"`
	Version   *string `json:"version"`
	RequestID *string `json:"requestId"`
	Message   *struct {
		ID    *string `json:"id"`
		Usage *struct {
			InputTokens              *uint64 `json:"input_tokens"`
			OutputTokens             *uint64 `json:"output_tokens"`
			CacheCreationInputTokens *uint64 `json:"cache_creation_input_tokens"`
			CacheReadInputTokens     *uint64 `json:"cache_read_input_tokens"`
		} `json:"usage"`
	} `json:"message"`
}

func (l *probeLine) missing() string {
	u := l.Message != nil && l.Message.Usage != nil
	var m []string
	for _, c := range []struct {
		name string
		ok   bool
	}{
		{"type", l.Type != nil},
		{"message.id", l.Message != nil && l.Message.ID != nil},
		{"requestId", l.RequestID != nil},
		{"usage.input_tokens", u && l.Message.Usage.InputTokens != nil},
		{"usage.output_tokens", u && l.Message.Usage.OutputTokens != nil},
		{"usage.cache_creation_input_tokens", u && l.Message.Usage.CacheCreationInputTokens != nil},
		{"usage.cache_read_input_tokens", u && l.Message.Usage.CacheReadInputTokens != nil},
		{"cwd", l.Cwd != nil},
		{"sessionId", l.SessionID != nil},
		{"version", l.Version != nil},
	} {
		if !c.ok {
			m = append(m, c.name)
		}
	}
	return strings.Join(m, ", ")
}

// Compatibility is the admission: version ∈ SupportedVersions ⇒ Pinned; else
// the newest transcript line this version wrote under ~/.claude/projects is
// probed for the required fields, present and typed. The error names what failed.
func (a *Adapter) Compatibility(version string) (Compat, error) {
	if Supported(version) {
		return Pinned, nil
	}
	if version == "" {
		return Incompatible, errors.New("claude version unsniffable")
	}
	if _, state, err := a.paths(); err == nil {
		if err := adapters.HookShape(state, a.Name()); err != nil {
			return Incompatible, err
		}
	}
	home, err := a.home()
	if err != nil {
		return Incompatible, err
	}
	if err := probe(filepath.Join(home, ".claude", "projects"), version); err != nil {
		if errors.Is(err, errUnprobed) {
			return Unprobed, err
		}
		return Incompatible, err
	}
	return CompatibleUnpinned, nil
}

var errUnprobed = errors.New("no transcript at this version yet")

// probe scans transcripts newest-first for the first assistant usage line
// stamped with version and checks it against probeLine.
// ponytail: unbounded newest-first scan; cap the file count if boot gets slow.
func probe(projects, version string) error {
	type file struct {
		path string
		mod  int64
	}
	var files []file
	_ = filepath.WalkDir(projects, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".jsonl") {
			return nil
		}
		if info, ierr := d.Info(); ierr == nil {
			files = append(files, file{p, info.ModTime().UnixNano()})
		}
		return nil
	})
	sort.Slice(files, func(i, j int) bool { return files[i].mod > files[j].mod })
	for _, f := range files {
		line, found, err := candidate(f.path, version)
		if err != nil || !found {
			continue
		}
		var l probeLine
		if err := json.Unmarshal(line, &l); err != nil {
			return fmt.Errorf("claude %s transcript line mistyped: %w", version, err)
		}
		if m := l.missing(); m != "" {
			return fmt.Errorf("claude %s transcript line lacks %s", version, m)
		}
		return nil
	}
	return fmt.Errorf("%w: no claude %s transcript under %s; run one session, then restart mark1d", errUnprobed, version, projects)
}

// candidate returns the first assistant line carrying usage and this version.
func candidate(path, version string) ([]byte, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = f.Close() }()
	r := bufio.NewReader(f)
	for {
		line, err := r.ReadBytes('\n')
		var l struct {
			Type    string `json:"type"`
			Version string `json:"version"`
			Message *struct {
				Usage json.RawMessage `json:"usage"`
			} `json:"message"`
		}
		if json.Unmarshal(line, &l) == nil && l.Type == "assistant" && l.Version == version && l.Message != nil && l.Message.Usage != nil {
			return line, true, nil
		}
		if err != nil {
			return nil, false, nil
		}
	}
}
