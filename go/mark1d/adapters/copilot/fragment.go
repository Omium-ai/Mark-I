package copilot

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"lukechampine.com/blake3"
)

// hookRegistrations: the 7 events the pinned corpus recorded, by their
// PascalCase names — the spelling that selects the Claude-compatible stdin
// body (hook_event_name + session_id) the shim keys on. Timeouts are in
// SECONDS (timeoutSec). Stop is the stop-gate: `decision:"block"` + reason
// enqueues the reason as the next prompt and re-fires Stop with
// stop_hook_active set, exactly Claude Code's Stop.
var hookRegistrations = []struct {
	Event   string
	Timeout int
}{
	{"SessionStart", 10},
	{"UserPromptSubmit", 5},
	{"PreToolUse", 5},
	{"PostToolUse", 5},
	{"PostToolUseFailure", 5},
	{"Stop", 30},
	{"SessionEnd", 3},
}

// DefaultShimPath is 08 §8.1's command string; the CLI runs `bash` entries
// through bash, which expands the `~`.
const DefaultShimPath = "~/.omium/mark1/bin/mark1-hookshim"

const (
	// agentEnv tells the shim which agent_maps entry this payload is (maps.rs);
	// the entry's `env` is merged into the hook's environment (hooks-reference).
	agentEnv = "copilot"

	CodeNoTarget        = "M1E-7101"
	CodeDamaged         = "M1E-7102"
	CodeManifestCorrupt = "M1E-7104"
)

var (
	ErrNoTarget        = errors.New(CodeNoTarget + ": $COPILOT_HOME (~/.copilot) does not exist; Mark 1 never creates the vendor's config directory (08 §8.3)")
	ErrDamaged         = errors.New(CodeDamaged + ": hooks/mark1.json no longer matches the bytes Mark 1 wrote (edited by hand); repair via `mark1 doctor --fix` (08 §8.3)")
	ErrManifestCorrupt = errors.New(CodeManifestCorrupt + ": provisioning manifest is unreadable; apply refuses rather than re-own a file it cannot account for (08 §8.2)")
)

type hookEntry struct {
	Type       string            `json:"type"`
	Bash       string            `json:"bash"`
	Env        map[string]string `json:"env"`
	TimeoutSec int               `json:"timeoutSec"`
}

// HooksFile is the owned file's bytes for one shim path. `|| true` is
// load-bearing: PreToolUse command hooks fail CLOSED on a non-zero exit at the
// pin (a missing shim denied every tool call on the recording), and 08 §5
// rule 5 says Mark 1's absence must never block a developer.
func HooksFile(shim string) []byte {
	if shim == "" {
		shim = DefaultShimPath
	}
	hooks := make(map[string][]hookEntry, len(hookRegistrations))
	for _, r := range hookRegistrations {
		hooks[r.Event] = []hookEntry{{"command", shim + " || true", map[string]string{"MARK1_AGENT": agentEnv}, r.Timeout}}
	}
	b, err := json.MarshalIndent(struct {
		Version int                    `json:"version"`
		Hooks   map[string][]hookEntry `json:"hooks"`
	}{1, hooks}, "", "  ")
	if err != nil {
		panic(err) // a fixed struct of strings and ints cannot fail to marshal
	}
	return append(b, '\n')
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

// ApplyFragment is 08 §8.3 for <copilotHome>/hooks/mark1.json: mechanism A —
// write the owned file, refuse if the vendor's config directory is absent.
func ApplyFragment(hooksPath, stateDir, shim string) (ApplyResult, error) {
	return apply(hooksPath, stateDir, shim, false)
}

// RepairFragment is `mark1 doctor --fix`: the same write, a damaged file rewritten instead of refused.
func RepairFragment(hooksPath, stateDir, shim string) (ApplyResult, error) {
	return apply(hooksPath, stateDir, shim, true)
}

func apply(hooksPath, stateDir, shim string, force bool) (ApplyResult, error) {
	if fi, err := os.Stat(filepath.Dir(filepath.Dir(hooksPath))); err != nil || !fi.IsDir() {
		return ApplyResult{}, ErrNoTarget
	}
	want := HooksFile(shim)
	desired := sum(want)
	prior, perr := loadManifest(stateDir)
	if perr != nil && !errors.Is(perr, os.ErrNotExist) {
		return ApplyResult{}, perr
	}
	cur, rerr := os.ReadFile(hooksPath)
	switch {
	case rerr != nil && !os.IsNotExist(rerr):
		return ApplyResult{}, rerr
	case rerr == nil && perr == nil && sum(cur) == prior.PostImageHash && prior.FragmentChecksum == desired:
		return ApplyResult{Changed: false, Mechanism: "A", Checksum: desired}, nil
	case rerr == nil && !force && (perr != nil || sum(cur) != prior.PostImageHash) && sum(cur) != desired:
		// A file at our path that we did not write, or ours edited by hand (08 §8.3 d).
		return ApplyResult{}, ErrDamaged
	}
	m := Manifest{TargetPath: hooksPath, Mechanism: "A", PostImageHash: desired, FragmentChecksum: desired,
		AppliedAt: time.Now().UTC().Format(time.RFC3339), AppliedBy: "mark1d"}
	// Manifest FIRST (08 §8.3 D-BK): the manifest brackets the mutation.
	if err := writeManifest(stateDir, m); err != nil {
		return ApplyResult{}, err
	}
	if err := os.MkdirAll(filepath.Dir(hooksPath), 0o700); err != nil {
		return ApplyResult{}, err
	}
	if err := writeAtomic(hooksPath, want, 0o600); err != nil {
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
	return filepath.Join(stateDir, "provisioned", "copilot", "hooks.manifest.json")
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
	case errors.Is(err, ErrNotEligible):
		return CodeNotEligible
	}
	return ""
}

// Inspect classifies the owned file without writing anything (the read half of `mark1 doctor`).
func Inspect(stateDir string) (Status, error) {
	st := Status{Agent: "copilot", Fragment: "hooks", Manifest: ManifestPath(stateDir), State: StateMissing}
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

// Revert is 08 §8.4 for mechanism A: delete the owned file, manifest LAST —
// unless its bytes are not ours any more (3b), in which case nothing is
// written and the manifest stays so `mark1 off` keeps seeing it.
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
