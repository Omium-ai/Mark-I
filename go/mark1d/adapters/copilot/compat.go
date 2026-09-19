package copilot

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

var errUnprobed = errors.New("no copilot session at this version yet")

// probeLine is every field newEventsParser and startCwd read, as pointers so absence and a wrong type both surface.
type probeLine struct {
	Type      *string `json:"type"`
	Timestamp *string `json:"timestamp"`
	Data      *struct {
		SessionID      *string `json:"sessionId"`
		CopilotVersion *string `json:"copilotVersion"`
		Context        *struct {
			Cwd *string `json:"cwd"`
		} `json:"context"`
		ShutdownType     *string  `json:"shutdownType"`
		SessionStartTime *float64 `json:"sessionStartTime"`
	} `json:"data"`
}

func (l *probeLine) missingStart() string {
	d := l.Data
	var m []string
	for _, c := range []struct {
		name string
		ok   bool
	}{
		{"timestamp", l.Timestamp != nil},
		{"data.sessionId", d.SessionID != nil},
		{"data.copilotVersion", d.CopilotVersion != nil},
		{"data.context.cwd", d.Context != nil && d.Context.Cwd != nil},
	} {
		if !c.ok {
			m = append(m, c.name)
		}
	}
	return strings.Join(m, ", ")
}

func (l *probeLine) missingShutdown() string {
	var m []string
	for _, c := range []struct {
		name string
		ok   bool
	}{
		{"timestamp", l.Timestamp != nil},
		{"data.shutdownType", l.Data.ShutdownType != nil},
		{"data.sessionStartTime", l.Data.SessionStartTime != nil},
	} {
		if !c.ok {
			m = append(m, c.name)
		}
	}
	return strings.Join(m, ", ")
}

// Compatibility is the admission: version ∈ SupportedVersions ⇒ Pinned; else the shim's hook
// shape is checked, then the newest events.jsonl stamped with this copilotVersion is probed for
// every field events.go reads.
func (a *Adapter) Compatibility(version string) (adapters.Compat, error) {
	if Supported(version) {
		return adapters.Pinned, nil
	}
	if version == "" {
		return adapters.Incompatible, errors.New("copilot version unsniffable")
	}
	_, state, err := a.paths()
	if err != nil {
		return adapters.Incompatible, err
	}
	if err := adapters.HookShape(state, a.Name()); err != nil {
		return adapters.Incompatible, err
	}
	dir, err := a.SessionStateDir()
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

// probe scans sessions newest-first; the first one this version wrote and shut down decides.
func probe(dir, version string) error {
	type file struct {
		path string
		mod  int64
	}
	paths, _ := filepath.Glob(filepath.Join(dir, "*", "events.jsonl"))
	files := make([]file, 0, len(paths))
	for _, p := range paths {
		if info, err := os.Stat(p); err == nil {
			files = append(files, file{p, info.ModTime().UnixNano()})
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].mod > files[j].mod })
	for _, f := range files {
		decided, err := probeEvents(f.path, version)
		if decided {
			return err
		}
	}
	return fmt.Errorf("%w: no copilot %s session-state with a session.shutdown under %s; run one session to completion, then restart mark1d", errUnprobed, version, dir)
}

// probeEvents returns decided=false when the session is another version's or has not shut down yet.
// A session.start with no copilotVersion at all cannot be attributed, so it is judged as this version's.
func probeEvents(path, version string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, nil
	}
	defer func() { _ = f.Close() }()
	r := bufio.NewReader(f)
	started := false
	for {
		line, rerr := r.ReadBytes('\n')
		var l probeLine
		if uerr := json.Unmarshal(line, &l); uerr != nil && len(strings.TrimSpace(string(line))) > 0 {
			return true, fmt.Errorf("copilot %s events line mistyped: %w", version, uerr)
		}
		if l.Type != nil && l.Data != nil {
			switch *l.Type {
			case "session.start":
				if l.Data.CopilotVersion != nil && *l.Data.CopilotVersion != version {
					return false, nil
				}
				if m := l.missingStart(); m != "" {
					return true, fmt.Errorf("copilot %s session.start lacks %s", version, m)
				}
				if _, err := uuid.Parse(*l.Data.SessionID); err != nil {
					return true, fmt.Errorf("copilot %s session.start sessionId is not a UUID", version)
				}
				started = true
			case "session.shutdown":
				if !started {
					return false, nil
				}
				if m := l.missingShutdown(); m != "" {
					return true, fmt.Errorf("copilot %s session.shutdown lacks %s", version, m)
				}
				return true, nil
			}
		}
		if rerr != nil {
			return false, nil
		}
	}
}
