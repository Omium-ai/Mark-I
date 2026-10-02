package cursor

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/fence"
)

// State is 08 §7.4's vocabulary, verbatim.
type State string

const (
	StateOK         State = "OK"
	StateUserEdited State = "USER-EDITED"
	StateDamaged    State = "FRAGMENT-DAMAGED"
	StateMissing    State = "MISSING"
)

type Line struct {
	Pointer string `json:"pointer"`
	Value   string `json:"value"`
}

type Status struct {
	Agent     string `json:"agent"`
	Fragment  string `json:"fragment"`
	Mechanism string `json:"mechanism"`
	Manifest  string `json:"manifest"`
	Target    string `json:"target"`
	State     State  `json:"state"`
	Detail    string `json:"detail,omitempty"`
	Lines     []Line `json:"lines,omitempty"`
}

type RevertResult struct {
	Target       string   `json:"target"`
	Kind         string   `json:"kind"` // verbatim | surgical | target-absent | not-provisioned
	ByteEquality bool     `json:"byte_equality"`
	Retained     []string `json:"retained,omitempty"`
}

func LoadManifest(stateDir string) (Manifest, error) { return loadManifest(stateDir) }

func loadManifest(stateDir string) (Manifest, error) {
	b, err := os.ReadFile(ManifestPath(stateDir))
	if err != nil {
		return Manifest{}, err
	}
	var m Manifest
	if json.Unmarshal(b, &m) != nil || m.PostImageHash == "" || !validTarget(m.TargetPath) ||
		(m.Mechanism != "A" && m.Mechanism != "B") || (m.Mechanism == "B" && (m.PreImage == "" || m.PreImageHash == "")) {
		return Manifest{}, ErrManifestCorrupt
	}
	return m, nil
}

// validTarget: the one value that reaches a write without being derived here must be absolute and canonical.
func validTarget(p string) bool {
	return p != "" && filepath.IsAbs(p) && filepath.Clean(p) == p
}

// RefusalCode maps a provisioning refusal to its M1E code; "" for a genuine failure.
func RefusalCode(err error) string {
	switch {
	case errors.Is(err, ErrNoTarget):
		return CodeNoTarget
	case errors.Is(err, ErrDamaged):
		return CodeDamaged
	case errors.Is(err, ErrDuplicateKey):
		return CodeDuplicateKey
	case errors.Is(err, ErrManifestCorrupt):
		return CodeManifestCorrupt
	case errors.Is(err, ErrWireNoGo):
		return CodeNotEligible
	}
	return ""
}

// Inspect classifies the fragment without writing anything (the read half of `mark1 doctor`).
func Inspect(stateDir string) (Status, error) {
	st := Status{Agent: "cursor", Fragment: "hooks", Manifest: ManifestPath(stateDir), State: StateMissing}
	m, err := LoadManifest(stateDir)
	if errors.Is(err, os.ErrNotExist) {
		st.Detail = "not provisioned"
		return st, nil
	}
	if err != nil {
		return st, err
	}
	st.Target, st.Mechanism = m.TargetPath, m.Mechanism
	cur, err := os.ReadFile(m.TargetPath)
	if os.IsNotExist(err) {
		st.Detail = "target file no longer exists"
		return st, nil
	}
	if err != nil {
		return st, err
	}
	_, hooks, err := openTarget(cur)
	if err != nil {
		st.State, st.Detail = StateDamaged, err.Error()
		return st, nil
	}
	tagged := taggedPointers(hooks)
	if len(tagged) == 0 {
		st.Detail = "fragment absent from the target"
		return st, nil
	}
	curSum, cerr := checksumAt(hooks, m.Pointers)
	st.Lines = linesAt(hooks, m.Pointers)
	switch {
	case cerr != nil || curSum != m.FragmentChecksum:
		st.State = StateDamaged
		st.Detail = CodeDamaged + ": values at the recorded pointers no longer match their checksum"
		if len(st.Lines) == 0 {
			st.Lines = linesAt(hooks, tagged)
		}
	case sum(cur) == m.PostImageHash:
		st.State = StateOK
	default:
		st.State = StateUserEdited
		st.Detail = "fragment intact; the rest of the file changed since apply"
	}
	return st, nil
}

// Revert is 08 §8.4: idempotent, crash-re-runnable, manifest deleted LAST.
func Revert(stateDir string) (RevertResult, error) {
	m, err := LoadManifest(stateDir)
	if errors.Is(err, os.ErrNotExist) {
		return RevertResult{Kind: "not-provisioned", ByteEquality: true}, nil
	}
	if err != nil {
		return RevertResult{}, err
	}
	res := RevertResult{Target: m.TargetPath}
	cur, rerr := os.ReadFile(m.TargetPath)
	switch {
	case os.IsNotExist(rerr):
		res.Kind, res.ByteEquality = "target-absent", true
	case rerr != nil:
		return res, rerr
	case sum(cur) == m.PostImageHash && m.Mechanism == "A":
		if err := os.Remove(m.TargetPath); err != nil && !os.IsNotExist(err) {
			return res, err
		}
		res.Kind, res.ByteEquality = "verbatim", true
	case sum(cur) == m.PostImageHash:
		pre, err := RestorePreImage(m)
		if err != nil {
			return res, err
		}
		if err := writeAtomic(m.TargetPath, pre, 0o600); err != nil {
			return res, err
		}
		res.Kind, res.ByteEquality = "verbatim", true
	case m.Mechanism == "B" && sum(cur) == m.PreImageHash:
		res.Kind, res.ByteEquality = "verbatim", true
	default:
		// ADR-0014: classify drift against the recorded post-apply image. A
		// reformat-only change (DriftNone by structure: CRLF, indentation, a
		// trailing newline) is not an edit, so the original bytes go back
		// verbatim; outside-fence, inside-fence and missing take the path they
		// always took. A pre-ADR manifest has no post_image and skips this.
		if post, perr := RestorePostImage(m); perr == nil {
			if d, _ := fence.Classify(nil, post, cur); d == fence.DriftNone {
				pre, err := RestorePreImage(m)
				if err != nil {
					return res, err
				}
				if err := writeAtomic(m.TargetPath, pre, 0o600); err != nil {
					return res, err
				}
				res.Kind, res.ByteEquality = "verbatim", true
				break
			}
		}
		if err := surgical(m, cur); err != nil {
			return res, err
		}
		res.Kind = "surgical"
	}
	if err := os.Remove(ManifestPath(stateDir)); err != nil && !os.IsNotExist(err) {
		return res, err
	}
	return res, nil
}

// surgical removes exactly our tagged entries from a file the user edited after apply.
func surgical(m Manifest, cur []byte) error {
	root, hooks, err := openTarget(cur)
	if err != nil {
		return err
	}
	preEvents, preHadHooks := preHooks(m)
	changed := false
	for _, event := range append([]string(nil), hooks.keys...) {
		var list []json.RawMessage
		if json.Unmarshal(hooks.vals[event], &list) != nil {
			continue
		}
		keep := list[:0:0]
		for _, e := range list {
			if !isOurs(e) {
				keep = append(keep, e)
			}
		}
		if len(keep) == len(list) {
			continue
		}
		changed = true
		if len(keep) == 0 && !preEvents[event] {
			hooks.del(event)
			continue
		}
		b, err := json.Marshal(keep)
		if err != nil {
			return err
		}
		hooks.set(event, b)
	}
	if !changed {
		return nil
	}
	if len(hooks.keys) == 0 && !preHadHooks {
		root.del("hooks")
	} else {
		root.set("hooks", rawOrdered(hooks))
	}
	post, err := root.encode()
	if err != nil {
		return err
	}
	return writeAtomic(m.TargetPath, post, 0o600)
}

// preHooks reports which hook-event keys existed BEFORE Mark 1 touched the file (none for mechanism A).
func preHooks(m Manifest) (map[string]bool, bool) {
	out := map[string]bool{}
	if m.Mechanism == "A" {
		return out, false
	}
	pre, err := RestorePreImage(m)
	if err != nil {
		return out, false
	}
	root, err := decodeObject(pre)
	if err != nil {
		return out, false
	}
	raw, ok := root.get("hooks")
	if !ok {
		return out, false
	}
	hooks, err := decodeObject(raw)
	if err != nil {
		return out, false
	}
	for _, k := range hooks.keys {
		out[k] = true
	}
	return out, true
}

func openTarget(b []byte) (root, hooks *object, err error) {
	root, err = decodeObject(b)
	if err != nil {
		return nil, nil, err
	}
	raw, ok := root.get("hooks")
	if !ok || len(raw) == 0 {
		raw = json.RawMessage("{}")
	}
	hooks, err = decodeObject(raw)
	if err != nil {
		return nil, nil, err
	}
	return root, hooks, nil
}

func isOurs(e json.RawMessage) bool {
	var probe struct {
		Mark1 string `json:"_mark1"`
	}
	return json.Unmarshal(e, &probe) == nil && probe.Mark1 != ""
}

func taggedPointers(hooks *object) []string {
	var out []string
	for _, event := range hooks.keys {
		var list []json.RawMessage
		if json.Unmarshal(hooks.vals[event], &list) != nil {
			continue
		}
		for i, e := range list {
			if isOurs(e) {
				out = append(out, fmt.Sprintf("/hooks/%s/%d", event, i))
			}
		}
	}
	return out
}

func linesAt(hooks *object, pointers []string) []Line {
	vals, err := resolve(hooks, pointers)
	if err != nil {
		return nil
	}
	out := make([]Line, 0, len(pointers))
	for i, p := range pointers {
		out = append(out, Line{Pointer: p, Value: string(vals[i])})
	}
	return out
}
