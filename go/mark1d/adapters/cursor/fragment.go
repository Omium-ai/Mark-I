package cursor

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
	"lukechampine.com/blake3"
)

// hookRegistrations: the 8 events Mark 1 registers, in the vendor's own
// vocabulary (schema/hooks-module.js `r` at the pin) — an unknown name
// invalidates the whole hooks.json. Timeouts are in SECONDS. `stop` is the
// stop-gate: Cursor's z() turns the shim's `decision:"block"` + reason into
// `followup_message`, which it auto-submits as the next user message; the
// runaway cap is the vendor's per-script loop_limit (default 5).
// sessionStart/sessionEnd are IDE-only at the pin (the CLI dispatches ten
// steps, not these two); afterAgentResponse/afterAgentThought are not
// registered — a subprocess per assistant message that nothing here reads.
var hookRegistrations = []struct {
	Event   string
	Timeout int
}{
	{"sessionStart", 10},
	{"beforeSubmitPrompt", 5},
	{"preToolUse", 5},
	{"postToolUse", 5},
	{"postToolUseFailure", 5},
	{"stop", 30},
	{"subagentStop", 5},
	{"sessionEnd", 3},
}

// DefaultShimPath is 08 §8.1's command string; Cursor runs the command through the shell, which expands the `~`.
const DefaultShimPath = "~/.omium/mark1/bin/mark1-hookshim"

const (
	entryTag = "_mark1"
	tagValue = "v1"
	// agentArg is argv[1] to the shim: which agent_maps entry this payload is (maps.rs). Cursor has no commandWindows key and `env` is not a cmd.exe builtin, so the agent rides the command line on every OS.
	agentArg = "cursor"

	CodeNoTarget        = "M1E-7101"
	CodeDamaged         = "M1E-7102"
	CodeDuplicateKey    = "M1E-7103"
	CodeManifestCorrupt = "M1E-7104"
)

var (
	ErrNoTarget        = errors.New(CodeNoTarget + ": ~/.cursor does not exist; Mark 1 never creates the vendor's config directory (08 §8.3)")
	ErrDamaged         = errors.New(CodeDamaged + ": MARK1 hook entries no longer match their recorded checksum (edited by hand); repair via `mark1 doctor --fix` (08 §8.3)")
	ErrDuplicateKey    = errors.New(CodeDuplicateKey + ": hooks.json contains a duplicate key; Mark 1 will not rewrite a file whose keys it would silently collapse (08 §8.1)")
	ErrManifestCorrupt = errors.New(CodeManifestCorrupt + ": provisioning manifest is unreadable; its pre_image is the only byte-equality revert target, so apply refuses rather than re-snapshot (08 §8.2)")
)

// entry is one flat hooks.json script (docs "Per-Script Configuration Options"):
// no matcher (empty matches everything), vendor defaults for loop_limit and failClosed.
type entry struct {
	Command string `json:"command"`
	Timeout int    `json:"timeout"`
	Mark1   string `json:"_mark1"`
}

// Manifest is 08 §8.2 plus the pointer list: the validator (schema/hooks-module.js
// te()) checks only version and hooks at the root, but a sibling object is one
// more key to explain in a user's file, so the manifest is the checksum record.
type Manifest struct {
	TargetPath       string   `json:"target_path"`
	Mechanism        string   `json:"mechanism"`
	PreImageHash     string   `json:"pre_image_hash"`
	PreImage         string   `json:"pre_image"`
	PostImageHash    string   `json:"post_image_hash"`
	PostImage        string   `json:"post_image,omitempty"` // ADR-0014: the bytes we wrote, zstd+base64; absent in pre-ADR manifests
	FragmentChecksum string   `json:"fragment_checksum"`
	Pointers         []string `json:"pointers"`
	AppliedAt        string   `json:"applied_at"`
	AppliedBy        string   `json:"applied_by"`
}

type ApplyResult struct {
	Changed   bool
	Mechanism string
	Checksum  string
	Pointers  []string
}

func sum(b []byte) string { s := blake3.Sum256(b); return "blake3:" + hex.EncodeToString(s[:]) }

func canonical(vals []json.RawMessage) ([]byte, error) {
	out := make([]any, 0, len(vals))
	for _, v := range vals {
		var a any
		if err := json.Unmarshal(v, &a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return json.Marshal(out)
}

// object keeps a JSON object's key order and every untouched value's exact bytes.
type object struct {
	keys  []string
	vals  map[string]json.RawMessage
	owned map[string]bool
}

func decodeObject(b []byte) (*object, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	tok, err := d.Token()
	if err != nil {
		return nil, err
	}
	if tok != json.Delim('{') {
		return nil, fmt.Errorf("hooks.json root is %v, want a JSON object", tok)
	}
	o := &object{vals: map[string]json.RawMessage{}, owned: map[string]bool{}}
	for d.More() {
		k, err := d.Token()
		if err != nil {
			return nil, err
		}
		var raw json.RawMessage
		if err := d.Decode(&raw); err != nil {
			return nil, err
		}
		key, _ := k.(string)
		if _, dup := o.vals[key]; dup {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateKey, key)
		}
		o.keys = append(o.keys, key)
		o.vals[key] = raw
	}
	return o, nil
}

func (o *object) get(k string) (json.RawMessage, bool) { v, ok := o.vals[k]; return v, ok }

func (o *object) del(k string) {
	if _, ok := o.vals[k]; !ok {
		return
	}
	delete(o.vals, k)
	delete(o.owned, k)
	for i, key := range o.keys {
		if key == k {
			o.keys = append(o.keys[:i], o.keys[i+1:]...)
			return
		}
	}
}

func (o *object) set(k string, v json.RawMessage) {
	if _, ok := o.vals[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.vals[k] = v
	o.owned[k] = true
}

func (o *object) encode() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("{\n")
	for i, k := range o.keys {
		key, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		buf.WriteString("  ")
		buf.Write(key)
		buf.WriteString(": ")
		if o.owned[k] {
			var indented bytes.Buffer
			if err := json.Indent(&indented, o.vals[k], "  ", "  "); err != nil {
				return nil, err
			}
			buf.Write(indented.Bytes())
		} else {
			buf.Write(o.vals[k])
		}
		if i < len(o.keys)-1 {
			buf.WriteString(",")
		}
		buf.WriteString("\n")
	}
	buf.WriteString("}\n")
	return buf.Bytes(), nil
}

func rawOrdered(o *object) json.RawMessage {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range o.keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		key, _ := json.Marshal(k)
		buf.Write(key)
		buf.WriteByte(':')
		buf.Write(o.vals[k])
	}
	buf.WriteByte('}')
	return buf.Bytes()
}

func desiredEntries(shim string) ([]json.RawMessage, error) {
	out := make([]json.RawMessage, 0, len(hookRegistrations))
	for _, r := range hookRegistrations {
		b, err := json.Marshal(entry{shim + " " + agentArg, r.Timeout, tagValue})
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

// ApplyFragment is 08 §8.3 for ~/.cursor/hooks.json: mechanism A (owned file)
// when it does not exist, mechanism B (fenced entries) when it does.
func ApplyFragment(hooksPath, stateDir, shim string) (ApplyResult, error) {
	return apply(hooksPath, stateDir, shim, false)
}

// RepairFragment is `mark1 doctor --fix`: the same write, damaged entries rewritten instead of refused.
func RepairFragment(hooksPath, stateDir, shim string) (ApplyResult, error) {
	return apply(hooksPath, stateDir, shim, true)
}

func apply(hooksPath, stateDir, shim string, force bool) (ApplyResult, error) {
	if shim == "" {
		shim = DefaultShimPath
	}
	if fi, err := os.Stat(filepath.Dir(hooksPath)); err != nil || !fi.IsDir() {
		return ApplyResult{}, ErrNoTarget
	}
	pre, err := os.ReadFile(hooksPath)
	mechanism := "B"
	if os.IsNotExist(err) {
		// The validator requires a numeric version at the root (te()).
		pre, mechanism = []byte(`{"version":1}`), "A"
	} else if err != nil {
		return ApplyResult{}, err
	}
	root, hooks, err := openTarget(pre)
	if err != nil {
		return ApplyResult{}, err
	}
	want, err := desiredEntries(shim)
	if err != nil {
		return ApplyResult{}, err
	}
	arrays := make([][]json.RawMessage, len(hookRegistrations))
	pointers := make([]string, len(hookRegistrations))
	for i, r := range hookRegistrations {
		var list []json.RawMessage
		if raw, ok := hooks.get(r.Event); ok {
			if err := json.Unmarshal(raw, &list); err != nil {
				return ApplyResult{}, fmt.Errorf("hooks.json /hooks/%s: %w", r.Event, err)
			}
		}
		idx := -1
		for j, e := range list {
			if isOurs(e) {
				idx = j
				break
			}
		}
		if idx < 0 {
			idx = len(list)
			list = append(list, want[i])
		} else {
			list[idx] = want[i]
		}
		arrays[i] = list
		pointers[i] = fmt.Sprintf("/hooks/%s/%d", r.Event, idx)
	}
	canonWant, err := canonical(want)
	if err != nil {
		return ApplyResult{}, err
	}
	desired := sum(canonWant)

	prior, perr := loadManifest(stateDir)
	switch {
	case perr == nil:
		mechanism = prior.Mechanism
	case errors.Is(perr, os.ErrNotExist):
	default:
		return ApplyResult{}, perr
	}
	if tagged := taggedPointers(hooks); len(tagged) > 0 {
		cur, cerr := checksumAt(hooks, prior.Pointers)
		switch {
		case perr != nil || cerr != nil || cur != prior.FragmentChecksum:
			if !force {
				return ApplyResult{}, ErrDamaged
			}
		case prior.FragmentChecksum == desired && equalStrings(prior.Pointers, pointers):
			return ApplyResult{Changed: false, Mechanism: mechanism, Checksum: desired, Pointers: pointers}, nil
		}
	}

	for i, r := range hookRegistrations {
		b, err := json.Marshal(arrays[i])
		if err != nil {
			return ApplyResult{}, err
		}
		hooks.set(r.Event, b)
	}
	root.set("hooks", rawOrdered(hooks))
	post, err := root.encode()
	if err != nil {
		return ApplyResult{}, err
	}
	postImage, err := encodeImage(post)
	if err != nil {
		return ApplyResult{}, err
	}
	m := Manifest{
		TargetPath: hooksPath, Mechanism: mechanism, PostImageHash: sum(post),
		PostImage:        postImage,
		FragmentChecksum: desired, Pointers: pointers,
		AppliedAt: time.Now().UTC().Format(time.RFC3339), AppliedBy: "mark1d",
	}
	switch {
	case perr == nil && prior.Mechanism == "B":
		m.PreImage, m.PreImageHash = prior.PreImage, prior.PreImageHash
	case mechanism == "B":
		z, err := zstdCompress(pre)
		if err != nil {
			return ApplyResult{}, err
		}
		m.PreImage, m.PreImageHash = base64.StdEncoding.EncodeToString(z), sum(pre)
	}
	// Manifest FIRST (08 §8.3 D-BK): the manifest brackets the mutation.
	if err := writeManifest(stateDir, m); err != nil {
		return ApplyResult{}, err
	}
	if err := writeAtomic(hooksPath, post, 0o600); err != nil {
		return ApplyResult{}, err
	}
	return ApplyResult{Changed: true, Mechanism: mechanism, Checksum: desired, Pointers: pointers}, nil
}

func checksumAt(hooks *object, pointers []string) (string, error) {
	found, err := resolve(hooks, pointers)
	if err != nil {
		return "", err
	}
	c, err := canonical(found)
	if err != nil {
		return "", err
	}
	return sum(c), nil
}

func resolve(hooks *object, pointers []string) ([]json.RawMessage, error) {
	out := make([]json.RawMessage, 0, len(pointers))
	for _, p := range pointers {
		rest, ok := strings.CutPrefix(p, "/hooks/")
		if !ok {
			return nil, fmt.Errorf("unownable pointer %q", p)
		}
		event, idxs, ok := strings.Cut(rest, "/")
		if !ok {
			return nil, fmt.Errorf("unownable pointer %q", p)
		}
		idx, err := strconv.Atoi(idxs)
		if err != nil {
			return nil, err
		}
		raw, ok := hooks.get(event)
		if !ok {
			return nil, fmt.Errorf("pointer %q: no such hook event", p)
		}
		var list []json.RawMessage
		if err := json.Unmarshal(raw, &list); err != nil {
			return nil, err
		}
		if idx < 0 || idx >= len(list) {
			return nil, fmt.Errorf("pointer %q: index out of range", p)
		}
		out = append(out, list[idx])
	}
	return out, nil
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	tmp := path + ".mark1.tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func ManifestPath(stateDir string) string {
	return filepath.Join(stateDir, "provisioned", "cursor", "hooks.manifest.json")
}

func writeManifest(stateDir string, m Manifest) error {
	if err := os.MkdirAll(filepath.Dir(ManifestPath(stateDir)), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := ManifestPath(stateDir) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, ManifestPath(stateDir)); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func zstdCompress(b []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := zstd.NewWriter(&buf)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(b); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// RestorePreImage decodes the manifest's original bytes and checks them against pre_image_hash.
func RestorePreImage(m Manifest) ([]byte, error) {
	z, err := base64.StdEncoding.DecodeString(m.PreImage)
	if err != nil {
		return nil, err
	}
	r, err := zstd.NewReader(bytes.NewReader(z))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if sum(out) != m.PreImageHash {
		return nil, errors.New("pre_image does not match pre_image_hash")
	}
	return out, nil
}
