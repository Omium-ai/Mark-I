package opencode

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"lukechampine.com/blake3"
)

// DefaultShimPath is 08 §8.1's command string; mark1.js expands the `~` itself (os.homedir).
const DefaultShimPath = "~/.omium/mark1/bin/mark1-hookshim"

//go:embed mark1.js
var pluginSource string

const (
	CodeNoTarget        = "M1E-7101"
	CodeDamaged         = "M1E-7102"
	CodeManifestCorrupt = "M1E-7104"
)

var (
	ErrNoTarget        = errors.New(CodeNoTarget + ": opencode's config directory does not exist; Mark 1 never creates the vendor's config directory (08 §8.3)")
	ErrDamaged         = errors.New(CodeDamaged + ": plugins/mark1.js no longer matches the bytes Mark 1 wrote (edited by hand); repair via `mark1 doctor --fix` (08 §8.3)")
	ErrManifestCorrupt = errors.New(CodeManifestCorrupt + ": provisioning manifest is unreadable; apply refuses rather than re-own a file it cannot account for (08 §8.2)")
)

// Plugin is the owned file's bytes for one shim path.
func Plugin(shim string) []byte {
	if shim == "" {
		shim = DefaultShimPath
	}
	return []byte(strings.ReplaceAll(pluginSource, "__MARK1_SHIM__", shim))
}

// Manifest is 08 §8.2 for a mechanism-A file: no pre-image, because the
// user's files are never opened for write.
type Manifest struct {
	TargetPath       string `json:"target_path"`
	Mechanism        string `json:"mechanism"`
	PostImageHash    string `json:"post_image_hash"`
	FragmentChecksum string `json:"fragment_checksum"`
	AppliedAt        string `json:"applied_at"`
	AppliedBy        string `json:"applied_by"`
}

type ApplyResult struct {
	Changed   bool
	Mechanism string
	Checksum  string
}

func sum(b []byte) string { s := blake3.Sum256(b); return "blake3:" + hex.EncodeToString(s[:]) }

// ApplyFragment is 08 §8.3 for <config>/plugins/mark1.js: mechanism A — write
// the owned file, refuse if the vendor's config directory is absent.
func ApplyFragment(pluginPath, stateDir, shim string) (ApplyResult, error) {
	return apply(pluginPath, stateDir, shim, false)
}

// RepairFragment is `mark1 doctor --fix`: the same write, a damaged file rewritten instead of refused.
func RepairFragment(pluginPath, stateDir, shim string) (ApplyResult, error) {
	return apply(pluginPath, stateDir, shim, true)
}

func apply(pluginPath, stateDir, shim string, force bool) (ApplyResult, error) {
	if fi, err := os.Stat(filepath.Dir(filepath.Dir(pluginPath))); err != nil || !fi.IsDir() {
		return ApplyResult{}, ErrNoTarget
	}
	want := Plugin(shim)
	desired := sum(want)
	prior, perr := loadManifest(stateDir)
	if perr != nil && !errors.Is(perr, os.ErrNotExist) {
		return ApplyResult{}, perr
	}
	cur, rerr := os.ReadFile(pluginPath)
	switch {
	case rerr != nil && !os.IsNotExist(rerr):
		return ApplyResult{}, rerr
	case rerr == nil && perr == nil && sum(cur) == prior.PostImageHash && prior.FragmentChecksum == desired:
		return ApplyResult{Changed: false, Mechanism: "A", Checksum: desired}, nil
	case rerr == nil && !force && (perr != nil || sum(cur) != prior.PostImageHash) && sum(cur) != desired:
		// A file at our path that we did not write, or ours edited by hand (08 §8.3 d).
		return ApplyResult{}, ErrDamaged
	}
	m := Manifest{TargetPath: pluginPath, Mechanism: "A", PostImageHash: desired, FragmentChecksum: desired,
		AppliedAt: time.Now().UTC().Format(time.RFC3339), AppliedBy: "mark1d"}
	// Manifest FIRST (08 §8.3 D-BK): the manifest brackets the mutation.
	if err := writeManifest(stateDir, m); err != nil {
		return ApplyResult{}, err
	}
	if err := os.MkdirAll(filepath.Dir(pluginPath), 0o700); err != nil {
		return ApplyResult{}, err
	}
	if err := writeAtomic(pluginPath, want, 0o600); err != nil {
		return ApplyResult{}, err
	}
	return ApplyResult{Changed: true, Mechanism: "A", Checksum: desired}, nil
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
	return filepath.Join(stateDir, "provisioned", "opencode", "plugin.manifest.json")
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

// State is 08 §7.4's vocabulary, verbatim; USER-EDITED cannot arise on an owned file.
type State string

const (
	StateOK      State = "OK"
	StateDamaged State = "FRAGMENT-DAMAGED"
	StateMissing State = "MISSING"
)

type Status struct {
	Agent     string `json:"agent"`
	Fragment  string `json:"fragment"`
	Mechanism string `json:"mechanism"`
	Manifest  string `json:"manifest"`
	Target    string `json:"target"`
	State     State  `json:"state"`
	Detail    string `json:"detail,omitempty"`
}

type RevertResult struct {
	Target       string   `json:"target"`
	Kind         string   `json:"kind"` // verbatim | target-absent | not-provisioned | fragment-damaged
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
	if json.Unmarshal(b, &m) != nil || m.PostImageHash == "" || m.Mechanism != "A" ||
		m.TargetPath == "" || !filepath.IsAbs(m.TargetPath) || filepath.Clean(m.TargetPath) != m.TargetPath {
		return Manifest{}, ErrManifestCorrupt
	}
	return m, nil
}

// RefusalCode maps a provisioning refusal to its M1E code; "" for a genuine failure.
func RefusalCode(err error) string {
	switch {
	case errors.Is(err, ErrNoTarget):
		return CodeNoTarget
	case errors.Is(err, ErrDamaged):
		return CodeDamaged
	case errors.Is(err, ErrManifestCorrupt):
		return CodeManifestCorrupt
	}
	return ""
}

// Inspect classifies the owned file without writing anything (the read half of `mark1 doctor`).
func Inspect(stateDir string) (Status, error) {
	st := Status{Agent: "opencode", Fragment: "plugin", Manifest: ManifestPath(stateDir), State: StateMissing}
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
	if sum(cur) != m.PostImageHash {
		st.State, st.Detail = StateDamaged, CodeDamaged+": the owned file no longer matches its recorded checksum"
		return st, nil
	}
	st.State = StateOK
	return st, nil
}

// Revert is 08 §8.4 mechanism A: delete the owned file, manifest LAST, unless its bytes aren't ours any more (3b) — then nothing is written and the manifest stays so `mark1 off` still sees it; mark1.js's noted prompts go too, regardless of plugin state.
func Revert(stateDir string) (RevertResult, error) {
	r, err := revert(stateDir)
	if perr := PurgeNotes(stateDir); err == nil {
		err = perr
	}
	return r, err
}

func revert(stateDir string) (RevertResult, error) {
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
	case sum(cur) != m.PostImageHash:
		res.Kind, res.Retained = "fragment-damaged", []string{m.TargetPath}
		return res, nil
	default:
		if err := os.Remove(m.TargetPath); err != nil && !os.IsNotExist(err) {
			return res, err
		}
		res.Kind, res.ByteEquality = "verbatim", true
	}
	if err := os.Remove(ManifestPath(stateDir)); err != nil && !os.IsNotExist(err) {
		return res, err
	}
	return res, nil
}
