package claudecode

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

// The 08 §5.1 registration table, transcribed verbatim: hook event, matcher
// ("" where the table says n/a — the §8.1 example writes Stop that way), and
// the deadline the fragment sets. Stop's 30 s is the gate budget the shim
// subtracts 10 ms from (08 §4.4); SessionStart's 10 s is a read of an
// already-assembled map (04 §6.4).
var hookRegistrations = []struct {
	Event   string
	Matcher string
	Timeout int
}{
	{"SessionStart", "*", 10},
	{"UserPromptSubmit", "", 5},
	{"PreToolUse", "*", 5},
	{"PostToolUse", "*", 5},
	{"PostToolUseFailure", "*", 5},
	{"Stop", "", 30},
	{"SubagentStop", "*", 5},
	{"PreCompact", "manual,auto", 5},
	{"SessionEnd", "*", 30},
}

// DefaultShimPath is 08 §8.1's command string, transcribed exactly — the
// vendor expands the leading `~`; an absolute path would make the fragment
// machine-specific and its checksum unshareable.
const DefaultShimPath = "~/.omium/mark1/bin/mark1-hookshim"

const (
	managedKey = "_mark1_managed" // 08 §8.1 sibling checksum object
	entryTag   = "_mark1"         // per-entry tag: survives a damaged manifest
	tagValue   = "v1"

	// 08 §8.3: mechanism B refuses to create a user file it would then own.
	CodeNoTarget = "M1E-7101"
	// 08 §8.3(d): a human edited inside our pointers — stop, never overwrite.
	CodeDamaged = "M1E-7102"
	// The provisioning family's two other refusals. Neither is in 08 §9's
	// table yet (both name states the algorithm implies but the table does not
	// enumerate) — they take the next codes in the family, not a code from
	// another one.
	CodeDuplicateKey    = "M1E-7103"
	CodeManifestCorrupt = "M1E-7104"
)

// The provisioning refusals. All are states doctor reports, not crashes.
var (
	ErrNoTarget = errors.New(CodeNoTarget + ": settings file does not exist; mechanism B never creates a user file (08 §8.3)")
	ErrDamaged  = errors.New(CodeDamaged + ": MARK1 pointers no longer match their recorded checksum (edited by hand); repair via `mark1 doctor --fix` (08 §8.3)")
	// A duplicate key is legal JSON that every decoder collapses differently.
	// Rewriting the file would silently delete one of the user's values — and
	// 08 §8.1 promises we never touch what we do not list in `pointers`, so
	// the posture is refusal, not normalization.
	ErrDuplicateKey = errors.New(CodeDuplicateKey + ": settings object contains a duplicate key; Mark 1 will not rewrite a file whose keys it would silently collapse (08 §8.1)")
	// A manifest that exists but does not parse cannot be re-snapshotted: the
	// bytes on disk are POST-Mark1, so re-snapshotting would overwrite the
	// pre-Mark1 image `mark1 off` restores from (08 §8.4 step 2).
	ErrManifestCorrupt = errors.New(CodeManifestCorrupt + ": provisioning manifest is unreadable; its pre_image is the only byte-equality revert target, so apply refuses rather than re-snapshot (08 §8.2)")
)

type hookSpec struct {
	Type    string `json:"type"`
	Command string `json:"command"`
	Timeout int    `json:"timeout"`
}

// managed is 08 §8.1's `_mark1_managed` object.
type managed struct {
	Version  int      `json:"version"`
	Agent    string   `json:"agent"`
	Fragment string   `json:"fragment"`
	Pointers []string `json:"pointers"`
	Checksum string   `json:"checksum"`
}

// Manifest is 08 §8.2, written on every apply. pre_image holds the ORIGINAL
// bytes (not just their hash) because that is what makes `mark1 off`'s
// byte-equality restore a guarantee rather than a hope.
type Manifest struct {
	TargetPath       string `json:"target_path"`
	Mechanism        string `json:"mechanism"`
	PreImageHash     string `json:"pre_image_hash"`
	PreImage         string `json:"pre_image"`
	PostImageHash    string `json:"post_image_hash"`
	FragmentChecksum string `json:"fragment_checksum"`
	AppliedAt        string `json:"applied_at"`
	AppliedBy        string `json:"applied_by"`
}

// ApplyResult reports what §8.3 did. Changed=false is the idempotent no-op
// (case b): the target was not opened for write at all.
type ApplyResult struct {
	Changed  bool
	Checksum string
	Pointers []string
}

func sum(b []byte) string { s := blake3.Sum256(b); return "blake3:" + hex.EncodeToString(s[:]) }

// canonical is the checksum input for a pointed-to value set: JSON with map
// keys sorted and no whitespace. Round-tripping through `any` is what makes
// the desired fragment and the on-disk one comparable — the file's spacing
// and key order must not change the checksum.
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

// object keeps a JSON object's key order and every untouched value's exact
// bytes: we own the pointers we record and nothing else (08 §8.1), so a
// re-marshal that reorders or reformats a user's keys is out of contract.
type object struct {
	keys []string
	vals map[string]json.RawMessage
	// owned marks the keys this process wrote. Only those are re-formatted on
	// encode; every other value goes back out as the exact bytes it came in as.
	owned map[string]bool
}

func decodeObject(b []byte) (*object, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	tok, err := d.Token()
	if err != nil {
		return nil, err
	}
	if tok != json.Delim('{') {
		return nil, fmt.Errorf("settings root is %v, want a JSON object", tok)
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

// del drops a key, keeping the surviving keys in their original order. Only
// ever called on keys Mark 1 owns (`_mark1_managed`, and a hook-event key we
// emptied) — 08 §8.1's "never sets, merges, or reorders any key it does not
// list in pointers" cuts both ways.
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
		// Only a value we wrote is re-formatted. Everything else is copied
		// byte for byte — the file's top-level line framing is ours to
		// normalize on first apply (revert restores the pre_image verbatim,
		// 08 §8.4 step 2), the user's values are not.
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

// desiredEntries renders the nine managed handlers in registration order.
func desiredEntries(shim string) ([]json.RawMessage, error) {
	out := make([]json.RawMessage, 0, len(hookRegistrations))
	for _, r := range hookRegistrations {
		b, err := json.Marshal(struct {
			Matcher string     `json:"matcher"`
			Hooks   []hookSpec `json:"hooks"`
			Mark1   string     `json:"_mark1"`
		}{r.Matcher, []hookSpec{{"command", shim, r.Timeout}}, tagValue})
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

// ApplyFragment is 08 §8.3's idempotent apply for the strict-JSON fence:
// registers the nine 08 §5.1 hooks into an EXISTING settings file, owning
// exactly the JSON Pointers it records. stateDir is the `mark1` state root —
// the manifest lands under provisioned/claudecode/hooks.manifest.json (§8.2).
func ApplyFragment(settingsPath, stateDir, shim string) (ApplyResult, error) {
	return apply(settingsPath, stateDir, shim, false)
}

// RepairFragment is 08 §8.3(d)'s ONLY repair path — `mark1 doctor --fix` — and
// the single difference from ApplyFragment is that a damaged fragment is
// rewritten instead of refused. It is the same write, not a second fence
// implementation: a repair that re-derived what a fence looks like could drift
// from apply, and the drift would be invisible to both sides' own tests.
//
// It is still bounded by §8.1: only the pointers we record are touched, and a
// pre-image already on file is never re-snapshotted, so `mark1 off` still
// restores the file the user had before Mark 1 existed.
func RepairFragment(settingsPath, stateDir, shim string) (ApplyResult, error) {
	return apply(settingsPath, stateDir, shim, true)
}

func apply(settingsPath, stateDir, shim string, force bool) (ApplyResult, error) {
	if shim == "" {
		shim = DefaultShimPath
	}
	pre, err := os.ReadFile(settingsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return ApplyResult{}, ErrNoTarget
		}
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
	// Place each managed entry, reusing the slot the `_mark1` tag marks so a
	// re-apply replaces in place and a user's own handlers keep their index.
	arrays := make([][]json.RawMessage, len(hookRegistrations))
	pointers := make([]string, len(hookRegistrations))
	for i, r := range hookRegistrations {
		var list []json.RawMessage
		if raw, ok := hooks.get(r.Event); ok {
			if err := json.Unmarshal(raw, &list); err != nil {
				return ApplyResult{}, fmt.Errorf("settings /hooks/%s: %w", r.Event, err)
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

	// §8.3 step 2: classify against what the file itself claims.
	if raw, ok := root.get(managedKey); ok {
		m, cur, err := currentChecksum(raw, hooks)
		switch {
		case err != nil || cur != m.Checksum:
			// (d) a human edited inside our pointers. Stop — never overwrite.
			// force is `mark1 doctor --fix`, the one sanctioned repair.
			if !force {
				return ApplyResult{}, ErrDamaged
			}
		case m.Checksum == desired && equalStrings(m.Pointers, pointers):
			// (b) present and current ⇒ exit unchanged, no write at all.
			return ApplyResult{Changed: false, Checksum: desired, Pointers: pointers}, nil
		}
	}

	// Resolved BEFORE the target is opened for write: a manifest we cannot
	// read is a refusal, and refusing after writeAtomic would leave the file
	// changed with no manifest describing it.
	preImage, preHash, err := priorPreImage(stateDir)
	if err != nil {
		return ApplyResult{}, err
	}

	for i, r := range hookRegistrations {
		b, err := json.Marshal(arrays[i])
		if err != nil {
			return ApplyResult{}, err
		}
		hooks.set(r.Event, b)
	}
	newHooks, err := json.Marshal(hooksRawOrdered(hooks))
	if err != nil {
		return ApplyResult{}, err
	}
	root.set("hooks", newHooks)
	mb, err := json.Marshal(managed{
		Version: 1, Agent: "claudecode", Fragment: "hooks",
		Pointers: pointers, Checksum: desired,
	})
	if err != nil {
		return ApplyResult{}, err
	}
	root.set(managedKey, mb)

	post, err := root.encode()
	if err != nil {
		return ApplyResult{}, err
	}
	// Manifest FIRST, mirroring §8.4 step 4's "deleted LAST": the manifest
	// brackets the mutation, so the target file is never carrying our entries
	// while nothing on disk knows how to remove them. Revert keys off the
	// manifest alone — an absent one is reported "not-provisioned" and returns
	// before it ever opens the target — so the other order strands nine
	// `_mark1` handlers in a user's settings.json permanently if the process
	// dies in between. The inverse crash is benign: a manifest whose
	// post_image matches nothing takes Revert's surgical path, which is
	// tag-driven and a no-op when none of our entries are there.
	if err := writeManifest(settingsPath, stateDir, pre, post, desired, preImage, preHash); err != nil {
		return ApplyResult{}, err
	}
	if err := writeAtomic(settingsPath, post); err != nil {
		return ApplyResult{}, err
	}
	return ApplyResult{Changed: true, Checksum: desired, Pointers: pointers}, nil
}

// currentChecksum reads the fragment the FILE claims to have: the values at
// the `_mark1_managed` object's OWN recorded pointers, canonicalized. §8.3(d)
// compares against that payload, not the desired one — checking the desired
// set instead would call every fragment revision damaged and jam the (c)
// upgrade path.
func currentChecksum(raw json.RawMessage, hooks *object) (managed, string, error) {
	var m managed
	if err := json.Unmarshal(raw, &m); err != nil {
		return m, "", err
	}
	found, err := resolve(hooks, m.Pointers)
	if err != nil {
		return m, "", err
	}
	canonFound, err := canonical(found)
	if err != nil {
		return m, "", err
	}
	return m, sum(canonFound), nil
}

// resolve reads the values a recorded pointer set points at. Only the
// `/hooks/<Event>/<index>` shape this fragment records is understood — a
// pointer we never write is not a pointer we own.
func resolve(hooks *object, pointers []string) ([]json.RawMessage, error) {
	out := make([]json.RawMessage, 0, len(pointers))
	for _, p := range pointers {
		var event string
		var idx int
		if _, err := fmt.Sscanf(p, "/hooks/%s", &event); err != nil {
			return nil, err
		}
		slash := strings.LastIndexByte(event, '/')
		if slash < 0 {
			return nil, fmt.Errorf("unownable pointer %q", p)
		}
		idx, err := strconv.Atoi(event[slash+1:])
		if err != nil {
			return nil, err
		}
		raw, ok := hooks.get(event[:slash])
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

// hooksRawOrdered re-emits the hooks object preserving the user's key order.
func hooksRawOrdered(o *object) json.RawMessage {
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

// writeAtomic preserves the target's mode: settings.json is the user's file
// and its permissions are theirs, not ours.
func writeAtomic(path string, data []byte) error {
	mode := os.FileMode(0o600)
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
	return filepath.Join(stateDir, "provisioned", "claudecode", "hooks.manifest.json")
}

// priorPreImage returns the pre-Mark1 bytes an earlier apply recorded, or
// ("", "") when there is no earlier apply. §8.3(c) keeps the ORIGINAL bytes so
// revert restores the file the user had before Mark 1 ever touched it.
//
// A manifest that exists but cannot be read for its pre_image is REFUSED. The
// file on disk is post-Mark1 by then, so treating an unreadable manifest as
// "no earlier apply" re-snapshots our own output as the pre-image and silently
// destroys the byte-equality target `mark1 off` restores from (08 §8.4).
func priorPreImage(stateDir string) (image, hash string, err error) {
	if stateDir == "" {
		return "", "", nil
	}
	old, err := os.ReadFile(ManifestPath(stateDir))
	if os.IsNotExist(err) {
		return "", "", nil
	}
	if err != nil {
		return "", "", err
	}
	var m Manifest
	if json.Unmarshal(old, &m) != nil || m.PreImage == "" || m.PreImageHash == "" {
		return "", "", ErrManifestCorrupt
	}
	return m.PreImage, m.PreImageHash, nil
}

func writeManifest(target, stateDir string, pre, post []byte, fragmentChecksum, preImage, preHash string) error {
	if stateDir == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(ManifestPath(stateDir)), 0o700); err != nil {
		return err
	}
	if preImage == "" {
		z, err := zstdCompress(pre)
		if err != nil {
			return err
		}
		preImage, preHash = base64.StdEncoding.EncodeToString(z), sum(pre)
	}
	b, err := json.MarshalIndent(Manifest{
		TargetPath:       target,
		Mechanism:        "B",
		PreImageHash:     preHash,
		PreImage:         preImage,
		PostImageHash:    sum(post),
		FragmentChecksum: fragmentChecksum,
		AppliedAt:        time.Now().UTC().Format(time.RFC3339),
		AppliedBy:        "mark1d",
	}, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomicMode(ManifestPath(stateDir), b, 0o600)
}

func writeAtomicMode(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
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

// RestorePreImage is the revert half of §8.2 — exposed because storing the
// original bytes is worthless without the one function that puts them back.
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
