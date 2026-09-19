package adapters

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// HookShape is the hook half of the structural probe: the shim spills
// <stateDir>/shape/<agent>/<event>.json (key → type, plus the field map's
// vendor names the live payload lacked); the first non-empty `missing` is the
// verdict, naming the renamed key. No shape files ⇒ nil: the hook path has
// nothing to refuse until a payload of this build has been seen.
func HookShape(stateDir, agent string) error {
	paths, _ := filepath.Glob(filepath.Join(stateDir, "shape", agent, "*.json"))
	sort.Strings(paths)
	for _, p := range paths {
		var s struct {
			Missing []string `json:"missing"`
		}
		b, err := os.ReadFile(p)
		if err != nil || json.Unmarshal(b, &s) != nil || len(s.Missing) == 0 {
			continue
		}
		event := strings.TrimSuffix(filepath.Base(p), ".json")
		return fmt.Errorf("%s hook %s payload lacks %s (vendor rename; a field-map push fixes it without a release)", agent, event, strings.Join(s.Missing, ", "))
	}
	return nil
}

// WriteShape is the shim's file, written by tests and recorders: keys with their JSON types and the missing vendor names.
func WriteShape(stateDir, agent, event string, keys map[string]string, missing []string) error {
	dir := filepath.Join(stateDir, "shape", agent)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if missing == nil {
		missing = []string{}
	}
	b, err := json.Marshal(map[string]any{"keys": keys, "missing": missing})
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, event+".json"), b, 0o600)
}
