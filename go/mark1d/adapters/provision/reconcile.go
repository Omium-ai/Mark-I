package provision

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/claudecode"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/codex"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/copilot"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/cursor"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/gemini"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/opencode"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/off"
)

// capture is one agent's §8 capture fragment: the manifest that proves Mark 1 owns it, the read-only classifier, and the non-forcing apply against the target the manifest recorded.
type capture struct {
	name     string
	manifest func(stateDir string) string
	inspect  func(stateDir string) (state, target string, err error)
	apply    func(target, stateDir string) (changed bool, checksum string, err error)
	refusal  func(error) string
}

var captures = []capture{
	{"claudecode", claudecode.ManifestPath,
		func(d string) (string, string, error) {
			s, err := claudecode.Inspect(d)
			return string(s.State), s.Target, err
		},
		func(t, d string) (bool, string, error) {
			r, err := claudecode.ApplyFragment(t, d, "")
			return r.Changed, r.Checksum, err
		},
		claudecode.RefusalCode},
	{"codex", codex.ManifestPath,
		func(d string) (string, string, error) {
			s, err := codex.Inspect(d)
			return string(s.State), s.Target, err
		},
		func(t, d string) (bool, string, error) {
			r, err := codex.ApplyFragment(t, d, "")
			return r.Changed, r.Checksum, err
		},
		codex.RefusalCode},
	{"gemini", gemini.ManifestPath,
		func(d string) (string, string, error) {
			s, err := gemini.Inspect(d)
			return string(s.State), s.Target, err
		},
		func(t, d string) (bool, string, error) {
			r, err := gemini.ApplyFragment(t, d, "")
			return r.Changed, r.Checksum, err
		},
		gemini.RefusalCode},
	{"opencode", opencode.ManifestPath,
		func(d string) (string, string, error) {
			s, err := opencode.Inspect(d)
			return string(s.State), s.Target, err
		},
		func(t, d string) (bool, string, error) {
			r, err := opencode.ApplyFragment(t, d, "")
			return r.Changed, r.Checksum, err
		},
		opencode.RefusalCode},
	{"copilot", copilot.ManifestPath,
		func(d string) (string, string, error) {
			s, err := copilot.Inspect(d)
			return string(s.State), s.Target, err
		},
		func(t, d string) (bool, string, error) {
			r, err := copilot.ApplyFragment(t, d, "")
			return r.Changed, r.Checksum, err
		},
		copilot.RefusalCode},
	{"cursor", cursor.ManifestPath,
		func(d string) (string, string, error) {
			s, err := cursor.Inspect(d)
			return string(s.State), s.Target, err
		},
		func(t, d string) (bool, string, error) {
			r, err := cursor.ApplyFragment(t, d, "")
			return r.Changed, r.Checksum, err
		},
		cursor.RefusalCode},
}

// Outcome is what Reconcile did to one agent's capture fragment.
type Outcome struct {
	Agent  string `json:"agent"`
	Action string `json:"action"` // upgraded | current | refused | missing | paused | failed
	Code   string `json:"code,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// Reconcile is the 08 §8.3(c) upgrade on every daemon start and `doctor --fix`: only a fragment whose manifest is on disk and whose fence is still exactly ours is re-applied; reverted, hand-edited, deleted, paused and off are left as they are.
func Reconcile(stateDir, version string, only ...string) []Outcome {
	if off.Off(stateDir) {
		return nil
	}
	var out []Outcome
	for _, c := range captures {
		if len(only) > 0 && !slices.Contains(only, c.name) {
			continue
		}
		if _, err := os.Stat(c.manifest(stateDir)); err != nil {
			continue
		}
		o := Outcome{Agent: c.name}
		state, target, err := c.inspect(stateDir)
		switch {
		case off.AgentOff(stateDir, c.name):
			o.Action = "paused"
		case err != nil:
			o.Action, o.Code, o.Detail = "refused", c.refusal(err), err.Error()
		case state == string(claudecode.StateDamaged):
			o.Action, o.Code, o.Detail = "refused", claudecode.CodeDamaged, "our fence was edited by hand; left untouched — `mark1 doctor --fix` rewrites it"
		case state != string(claudecode.StateOK) && state != string(claudecode.StateUserEdited):
			o.Action, o.Detail = "missing", "fragment removed from "+target+"; not re-added — `mark1 enable` provisions it again"
		default:
			changed, checksum, aerr := c.apply(target, stateDir)
			switch {
			case aerr != nil && c.refusal(aerr) != "":
				o.Action, o.Code, o.Detail = "refused", c.refusal(aerr), aerr.Error()
			case aerr != nil:
				o.Action, o.Detail = "failed", aerr.Error()
			case changed:
				o.Action = "upgraded"
			default:
				o.Action = "current"
			}
			if aerr == nil {
				if err := WriteStamp(stateDir, c.name, version, checksum); err != nil {
					o.Detail = "release stamp not written: " + err.Error()
				}
			}
		}
		out = append(out, o)
	}
	return out
}

// Stamp is <state>/provisioned/<agent>/release.json: the Mark 1 release whose capture fragment is on disk, which `mark1 doctor` prints per agent.
type Stamp struct {
	Version          string `json:"version"`
	FragmentChecksum string `json:"fragment_checksum"`
	At               string `json:"at"`
}

func StampPath(stateDir, agent string) string {
	return filepath.Join(stateDir, "provisioned", agent, "release.json")
}

func ReadStamp(stateDir, agent string) (Stamp, error) {
	var s Stamp
	b, err := os.ReadFile(StampPath(stateDir, agent))
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(b, &s); err != nil || s.Version == "" {
		return Stamp{}, errors.New(StampPath(stateDir, agent) + ": unreadable release stamp")
	}
	return s, nil
}

// WriteStamp records that the fragment on disk is what version ships; a no-op when that is already the record, and when version is unknown.
func WriteStamp(stateDir, agent, version, checksum string) error {
	if version == "" || checksum == "" {
		return nil
	}
	if s, err := ReadStamp(stateDir, agent); err == nil && s.Version == version && s.FragmentChecksum == checksum {
		return nil
	}
	b, err := json.MarshalIndent(Stamp{version, checksum, time.Now().UTC().Format(time.RFC3339)}, "", "  ")
	if err != nil {
		return err
	}
	p := StampPath(stateDir, agent)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// dropStamps removes the release stamp of every agent whose capture manifest is gone, so a reverted agent never reports a provisioned version.
func dropStamps(stateDir string) {
	for _, c := range captures {
		if _, err := os.Stat(c.manifest(stateDir)); errors.Is(err, os.ErrNotExist) {
			_ = os.Remove(StampPath(stateDir, c.name))
		}
	}
}
