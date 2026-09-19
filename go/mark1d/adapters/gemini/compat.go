package gemini

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters"
)

var errUnprobed = errors.New("no gemini chat at this version yet")

// probeRecord is every field newChatParser reads off a `gemini` MessageRecord, as pointers so absence and a wrong type both surface.
type probeRecord struct {
	ID        *string `json:"id"`
	Type      *string `json:"type"`
	Timestamp *string `json:"timestamp"`
	Model     *string `json:"model"`
	Tokens    *struct {
		Input    *uint64 `json:"input"`
		Output   *uint64 `json:"output"`
		Cached   *uint64 `json:"cached"`
		Thoughts *uint64 `json:"thoughts"`
	} `json:"tokens"`
}

func (r *probeRecord) missing() string {
	tk := r.Tokens != nil
	var m []string
	for _, c := range []struct {
		name string
		ok   bool
	}{
		{"id", r.ID != nil},
		{"timestamp", r.Timestamp != nil},
		{"model", r.Model != nil},
		{"tokens.input", tk && r.Tokens.Input != nil},
		{"tokens.output", tk && r.Tokens.Output != nil},
		{"tokens.cached", tk && r.Tokens.Cached != nil},
		{"tokens.thoughts", tk && r.Tokens.Thoughts != nil},
	} {
		if !c.ok {
			m = append(m, c.name)
		}
	}
	return strings.Join(m, ", ")
}

// Compatibility is the admission: version ∈ SupportedVersions ⇒ Pinned; else the shim's hook
// shape is checked, then the newest chat recording is probed for every field chats.go reads.
func (a *Adapter) Compatibility(version string) (adapters.Compat, error) {
	if Supported(version) {
		return adapters.Pinned, nil
	}
	if version == "" {
		return adapters.Incompatible, errors.New("gemini version unsniffable")
	}
	_, state, err := a.paths()
	if err != nil {
		return adapters.Incompatible, err
	}
	if err := adapters.HookShape(state, a.Name()); err != nil {
		return adapters.Incompatible, err
	}
	tmp, err := a.TmpDir()
	if err != nil {
		return adapters.Incompatible, err
	}
	if err := probe(tmp, version); err != nil {
		if errors.Is(err, errUnprobed) {
			return adapters.Unprobed, err
		}
		return adapters.Incompatible, err
	}
	return adapters.CompatibleUnpinned, nil
}

// probe scans main chat recordings newest-first; the first carrying a completed gemini message decides.
// A recording whose gemini records all lack tokens is an aborted turn, not a verdict, unless no recording carries them at all.
// ponytail: gemini stamps no version into its recordings, so recency attributes the newest chat to the sniffed build; filter on the binary's mtime if a stale post-upgrade verdict ever bites.
func probe(tmp, version string) error {
	type file struct {
		path string
		mod  int64
	}
	paths, _ := filepath.Glob(filepath.Join(tmp, "*", "chats", "session-*.jsonl"))
	files := make([]file, 0, len(paths))
	for _, p := range paths {
		if info, err := os.Stat(p); err == nil {
			files = append(files, file{p, info.ModTime().UnixNano()})
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].mod > files[j].mod })
	untokened := false
	for _, f := range files {
		decided, seen, err := probeChat(f.path, version)
		if decided {
			return err
		}
		untokened = untokened || seen
	}
	if untokened {
		return fmt.Errorf("gemini %s recordings have gemini records but none carries tokens (chatRecordingService writes tokens on the response line)", version)
	}
	return fmt.Errorf("%w: no gemini %s chat with a completed response under %s; run one session, then restart mark1d", errUnprobed, version, tmp)
}

// probeChat returns decided=false when the recording has no tokened gemini message yet; seen says whether it has any gemini record.
func probeChat(path, version string) (decided, seen bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		return false, false, nil
	}
	defer func() { _ = f.Close() }()
	r := bufio.NewReader(f)
	head, _ := r.ReadBytes('\n')
	var meta struct {
		SessionID   *string `json:"sessionId"`
		ProjectHash *string `json:"projectHash"`
	}
	if json.Unmarshal(head, &meta) != nil {
		return false, false, nil
	}
	if meta.SessionID == nil || meta.ProjectHash == nil {
		return true, false, fmt.Errorf("gemini %s chat head lacks sessionId/projectHash", version)
	}
	if _, err := uuid.Parse(*meta.SessionID); err != nil {
		return true, false, fmt.Errorf("gemini %s chat head sessionId is not a UUID", version)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(filepath.Dir(path)), ".project_root")); err != nil {
		return true, false, fmt.Errorf("gemini %s chat slug lacks its .project_root marker", version)
	}
	for {
		line, rerr := r.ReadBytes('\n')
		var rec probeRecord
		if uerr := json.Unmarshal(line, &rec); uerr != nil && len(strings.TrimSpace(string(line))) > 0 {
			return true, seen, fmt.Errorf("gemini %s chat record mistyped: %w", version, uerr)
		}
		if rec.Type != nil && *rec.Type == "gemini" {
			seen = true
			if rec.Tokens != nil {
				if m := rec.missing(); m != "" {
					return true, seen, fmt.Errorf("gemini %s chat record lacks %s", version, m)
				}
				return true, seen, nil
			}
		}
		if rerr != nil {
			return false, seen, nil
		}
	}
}
