package claudecode

// 08 §8.4 (revert) and §7.4 (the four fenced-config states `mark1 doctor`
// reports). Both live beside ApplyFragment on purpose: the fence is one
// definition, and a revert that re-derived what a fence looks like would drift
// from the apply that wrote it — with each side's own tests still green.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/fence"
)

// State is 08 §7.4's vocabulary, verbatim. There is no fifth value: anything
// we cannot verify is FRAGMENT-DAMAGED, because the only safe reading of "I
// cannot tell what is in there" is the one that refuses to write.
type State string

const (
	StateOK         State = "OK"               // post-image matches; nothing has moved
	StateUserEdited State = "USER-EDITED"      // fragment intact, rest of the file changed
	StateDamaged    State = "FRAGMENT-DAMAGED" // checksum mismatch inside our markers
	StateMissing    State = "MISSING"          // never applied, or removed from under us
)

// Line is one provisioned line as it exists ON DISK — pointer plus the exact
// bytes at it. FR-AGENT-003: every line Mark 1 wrote must be visible in
// `mark1 doctor` and byte-for-byte diffable, which a state word alone is not.
type Line struct {
	Pointer string `json:"pointer"`
	Value   string `json:"value"`
}

// Status is one fragment's row in `mark1 doctor` (08 §7.4).
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

// RevertResult is what `mark1 off` reports per fragment (08 §7.6, §8.4).
// ByteEquality is the doc's bool; Kind keeps §8.4's "surgical" distinction the
// bool flattens away, so a user who edited their settings after we provisioned
// learns why their file is not byte-identical instead of seeing a bare false.
//
// Retained names what of ours is STILL IN the file — the one thing a false
// ByteEquality does not distinguish (D-CR). "Their bytes differ from the
// pre-image" and "our proxy pointer is still live" are the same `false`, and
// only the second is an unfinished revert. A non-empty Retained is that second
// case, and it is why `Kind` has a fifth value.
type RevertResult struct {
	Target       string   `json:"target"`
	Kind         string   `json:"kind"` // verbatim | surgical | target-absent | not-provisioned | fragment-damaged
	ByteEquality bool     `json:"byte_equality"`
	Retained     []string `json:"retained,omitempty"`
}

// LoadManifest reads 08 §8.2's record. A missing manifest surfaces as
// os.ErrNotExist so callers can say "not provisioned" without a stat race; an
// unparseable one is ErrManifestCorrupt rather than a zero Manifest, because a
// zero Manifest quietly means "the target path is the empty string".
func LoadManifest(stateDir string) (Manifest, error) { return loadManifest(stateDir, "hooks") }

func loadManifest(stateDir, fragment string) (Manifest, error) {
	b, err := os.ReadFile(manifestPath(stateDir, fragment))
	if err != nil {
		return Manifest{}, err
	}
	var m Manifest
	if json.Unmarshal(b, &m) != nil || m.PostImageHash == "" || !validTarget(m.TargetPath) {
		return Manifest{}, ErrManifestCorrupt
	}
	return m, nil
}

// validTarget gates the ONE value in this package that reaches a write without
// being derived here: target_path, read back off disk. Revert and
// `doctor --fix` both write to it, so it must still be absolute and already
// canonical on the way in. Rejecting is the whole point — filepath.Clean would
// resolve a `..` and then write wherever it landed, which IS the traversal
// rather than a defense against it. The manifest lives 0600 under the user's
// own state root, so nobody able to forge one lacks the rights to edit
// settings.json directly; this turns that reasoning into a checked invariant
// that fails closed on M1E-7104.
func validTarget(p string) bool {
	return p != "" && filepath.IsAbs(p) && filepath.Clean(p) == p
}

// RefusalCode maps a provisioning refusal to its M1E code, and returns "" for
// anything that is a genuine failure. The distinction is load-bearing at the
// CLI: "you have no ~/.claude/settings.json yet" and "someone hand-edited our
// block" are STATES a user can see and act on, and turning either into a
// non-zero `mark1 enable` would fail the command for a user whose only sin is
// never having customized their agent.
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
	case errors.Is(err, ErrEnvConflict):
		return CodeEnvConflict
	case errors.Is(err, ErrNotEligible):
		return CodeNotEligible
	}
	return ""
}

// Inspect classifies the fragment without writing anything, ever. It is the
// read half of `mark1 doctor`; `--fix` is RepairFragment and is a separate
// call, so no diagnostic path can mutate a user's file by accident.
func Inspect(stateDir string) (Status, error) {
	st := Status{Agent: "claudecode", Fragment: "hooks", Mechanism: "B",
		Manifest: ManifestPath(stateDir), State: StateMissing}
	m, err := LoadManifest(stateDir)
	if errors.Is(err, os.ErrNotExist) {
		st.Detail = "not provisioned"
		return st, nil
	}
	if err != nil {
		return st, err
	}
	st.Target = m.TargetPath

	cur, err := os.ReadFile(m.TargetPath)
	if os.IsNotExist(err) {
		st.Detail = "target file no longer exists"
		return st, nil
	}
	if err != nil {
		return st, err
	}
	root, hooks, err := openTarget(cur)
	if err != nil {
		// Unparseable (or duplicate-keyed) settings: our fragment may be
		// perfectly intact in there, but we cannot prove it, and DAMAGED is the
		// state whose repair path requires a human to say --fix.
		st.State, st.Detail = StateDamaged, err.Error()
		return st, nil
	}

	if raw, ok := root.get(managedKey); ok {
		mg, curSum, cerr := currentChecksum(raw, root, hooks)
		st.Lines = linesAt(root, hooks, mg.Pointers)
		switch {
		case cerr != nil || curSum != mg.Checksum:
			st.State = StateDamaged
			st.Detail = CodeDamaged + ": values at the recorded pointers no longer match their checksum"
			if len(st.Lines) == 0 {
				st.Lines = linesAt(root, hooks, taggedPointers(root, hooks))
			}
		case sum(cur) == m.PostImageHash:
			st.State = StateOK
		default:
			st.State = StateUserEdited
			st.Detail = "fragment intact; the rest of the file changed since apply"
		}
		return st, nil
	}

	// No `_mark1_managed`, but tagged entries survive: the checksum object was
	// deleted while our entries stayed. That is damage, not absence — reporting
	// MISSING would make the next apply append a SECOND copy of every handler.
	if ptrs := taggedPointers(root, hooks); len(ptrs) > 0 {
		st.State, st.Lines = StateDamaged, linesAt(root, hooks, ptrs)
		st.Detail = CodeDamaged + ": " + managedKey + " was removed but managed entries remain"
		return st, nil
	}
	st.Detail = "fragment absent from the target"
	return st, nil
}

// Revert is 08 §8.4. It is idempotent and crash-re-runnable: the manifest is
// deleted LAST, so an interruption anywhere leaves a state a second run
// finishes from.
func Revert(stateDir string) (RevertResult, error) {
	m, err := LoadManifest(stateDir)
	if errors.Is(err, os.ErrNotExist) {
		// Nothing provisioned ⇒ nothing to undo. `mark1 off` twice must
		// succeed twice; a second run that errors is a run an operator learns
		// to skip.
		return RevertResult{Kind: "not-provisioned", ByteEquality: true}, nil
	}
	if err != nil {
		return RevertResult{}, err
	}
	res := RevertResult{Target: m.TargetPath}

	cur, rerr := os.ReadFile(m.TargetPath)
	switch {
	case os.IsNotExist(rerr):
		// The user deleted their own settings file. Writing the pre-image back
		// would be Mark 1 creating a user file — the same thing §8.3 refuses in
		// the other direction, and no more welcome here.
		res.Kind, res.ByteEquality = "target-absent", true
	case rerr != nil:
		return res, rerr
	case sum(cur) == m.PostImageHash:
		// §8.4 step 2: untouched since our write ⇒ restore the ORIGINAL bytes.
		// This is the path that makes byte-equality a guarantee.
		pre, err := RestorePreImage(m)
		if err != nil {
			return res, err
		}
		if err := writeAtomic(m.TargetPath, pre); err != nil {
			return res, err
		}
		res.Kind, res.ByteEquality = "verbatim", true
	case sum(cur) == m.PreImageHash:
		// A previous run restored the pre-image and then died before deleting
		// the manifest. Still byte-equal — calling it surgical here would
		// report a downgrade that never happened.
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
				if err := writeAtomic(m.TargetPath, pre); err != nil {
					return res, err
				}
				res.Kind, res.ByteEquality = "verbatim", true
				break
			}
		}
		// §8.4 step 3: the user edited the file after we did, so the pre-image
		// is stale. Remove exactly our entries and nothing else.
		if err := surgical(m, cur, stateDir); err != nil {
			return res, err
		}
		res.Kind = "surgical"
	}
	// The slot is theirs again on every path above, so the shim must stop chaining; before the manifest for the same re-run reason.
	if err := os.Remove(StatusLinePrevPath(stateDir)); err != nil && !os.IsNotExist(err) {
		return res, err
	}

	// §8.4 step 4, and the reason it is step 4: a crash between the write above
	// and this line leaves a manifest whose post_image no longer matches, so the
	// re-run takes the surgical (or already-reverted) path and still completes.
	// Deleting it first would strand the fragment with nothing that knows how
	// to find it.
	if err := os.Remove(ManifestPath(stateDir)); err != nil && !os.IsNotExist(err) {
		return res, err
	}
	return res, nil
}

// surgical removes our entries from a file the user has edited since apply.
// Identity is the `_mark1` tag, never the manifest's recorded index: an index
// goes stale the moment the user inserts a handler above ours, and deleting
// what a stale index points at destroys THEIR config — the single failure this
// whole design exists to prevent.
func surgical(m Manifest, cur []byte, stateDir string) error {
	root, hooks, err := openTarget(cur)
	if err != nil {
		return err
	}
	changed := false
	if _, ok := root.get(managedKey); ok {
		root.del(managedKey)
		changed = true
	}
	if sl, ok := root.get(statusLineKey); ok && isOurs(sl) {
		changed = true
		if prev, err := os.ReadFile(StatusLinePrevPath(stateDir)); err == nil && json.Valid(prev) {
			root.set(statusLineKey, prev)
			root.owned[statusLineKey] = false // their bytes go back verbatim, not re-indented
		} else {
			root.del(statusLineKey) // the slot was empty when we took it
		}
	}
	preEvents, preHadHooks := preHooks(m)
	for _, event := range append([]string(nil), hooks.keys...) {
		var list []json.RawMessage
		if json.Unmarshal(hooks.vals[event], &list) != nil {
			continue // not an array we ever wrote into, so not ours to touch
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
			hooks.del(event) // the key is one we created; leave nothing behind
			continue
		}
		b, err := json.Marshal(keep)
		if err != nil {
			return err
		}
		hooks.set(event, b)
	}
	if !changed {
		return nil // already clean; do not rewrite a file for nothing
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
	return writeAtomic(m.TargetPath, post)
}

// preHooks reports the hook-event keys the file had BEFORE Mark 1 touched it,
// and whether it had a `hooks` key at all. Surgical removal needs it for
// exactly one decision: when our entry was the only one in an array, does the
// emptied key stay? Deleting a key the user wrote breaks "we never touch what
// we do not own"; keeping one we created breaks "we leave nothing behind".
// The pre-image is the only thing that knows which case this is. If it is
// unreadable we delete, because a stray key of OURS is the failure that is
// ours to answer for.
func preHooks(m Manifest) (map[string]bool, bool) {
	out := map[string]bool{}
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

// openTarget decodes the settings root and its `hooks` object. A file with no
// `hooks` key yields an empty object rather than nil so every caller reads the
// same shape.
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

// isOurs identifies a hook entry by the per-entry `_mark1` tag 08 §8.1 puts on
// every one precisely so it stays identifiable when `_mark1_managed` is
// damaged or the array has been reordered under us — or, when Claude Code has
// rewritten settings.json and dropped the tag as an unknown key (it does on
// every settings change), by the shim it invokes.
func isOurs(e json.RawMessage) bool {
	var probe struct {
		Mark1   string `json:"_mark1"`
		Command string `json:"command"`
		Hooks   []struct {
			Command string `json:"command"`
		} `json:"hooks"`
	}
	if json.Unmarshal(e, &probe) != nil {
		return false
	}
	if probe.Mark1 != "" || strings.Contains(probe.Command, shimName) {
		return true
	}
	for _, h := range probe.Hooks {
		if strings.Contains(h.Command, shimName) {
			return true
		}
	}
	return false
}

// taggedPointers finds every managed entry by tag, wherever it now sits. This
// is the fallback identity for the damaged states, where the recorded pointer
// list is absent or provably wrong.
func taggedPointers(root, hooks *object) []string {
	var out []string
	if sl, ok := root.get(statusLineKey); ok && isOurs(sl) {
		out = append(out, statusLinePointer)
	}
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

// linesAt reads the bytes actually sitting at each pointer. A pointer that no
// longer resolves yields no lines rather than a fabricated one — doctor shows
// what is there, not what should be.
func linesAt(root, hooks *object, pointers []string) []Line {
	vals, err := resolve(root, hooks, pointers)
	if err != nil {
		return nil
	}
	out := make([]Line, 0, len(pointers))
	for i, p := range pointers {
		out = append(out, Line{Pointer: p, Value: string(vals[i])})
	}
	return out
}
