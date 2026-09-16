package cursor

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters"
)

// cursor -> adapters -> mark1d -> go -> repo root.
const fixtureRoot = "../../../../conformance/hooks/cursor/v2026.09.10-fd3934a"

type expectations struct {
	AgentVersion string `json:"agent_version"`
	UsageClass   string `json:"usage_class"`
	Hooks        struct {
		Registered []string `json:"registered"`
		IDEOnly    []string `json:"ide_only_at_pin"`
	} `json:"hooks"`
	NoGo map[string]string `json:"no_go"`
}

func loadExpectations(t *testing.T) expectations {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtureRoot, "expectations.json"))
	if err != nil {
		t.Fatal(err)
	}
	var exp expectations
	if err := json.Unmarshal(b, &exp); err != nil {
		t.Fatal(err)
	}
	return exp
}

func TestSupportedVersionsMatchTheFixtureTree(t *testing.T) {
	ents, err := os.ReadDir(filepath.Dir(fixtureRoot))
	if err != nil {
		t.Fatalf("fixture tree unreadable: %v", err)
	}
	fixtures := map[string]struct{}{}
	for _, e := range ents {
		if e.IsDir() {
			fixtures[strings.TrimPrefix(e.Name(), "v")] = struct{}{}
		}
	}
	if len(fixtures) == 0 {
		t.Fatal("no version directories under conformance/hooks/cursor")
	}
	for v := range SupportedVersions {
		if _, ok := fixtures[v]; !ok {
			t.Errorf("SupportedVersions has %q with no fixture directory", v)
		}
	}
	for v := range fixtures {
		if _, ok := SupportedVersions[v]; !ok {
			t.Errorf("conformance/hooks/cursor/v%s exists but is not in SupportedVersions", v)
		}
	}
}

func TestVersionSniffReadsBothSurfaces(t *testing.T) {
	if v := versionRe.FindString("2026.09.10-fd3934a\n"); v != "2026.09.10-fd3934a" || !Supported(v) {
		t.Fatalf("CLI build read as %q (supported=%v)", v, Supported(v))
	}
	if v := versionRe.FindString("3.20.21\nf09fca384ceca23f7bf21f9c23655b162641d740\nx64\n"); v != "3.20.21" || Supported(v) {
		t.Fatalf("IDE build read as %q (supported=%v) — no IDE-recorded corpus exists", v, Supported(v))
	}
	if Supported("") || Supported("99.0.0") {
		t.Fatal("an unpinned version is supported; FR-AGENT-002 requires the opposite")
	}
}

// TestWirePathIsAPermanentNoGo: no credential state on the machine makes Cursor
// proxy-eligible, and the refusal carries the CON-001 code.
func TestWirePathIsAPermanentNoGo(t *testing.T) {
	exp := loadExpectations(t)
	if !strings.HasPrefix(exp.NoGo["wire_proxy"], "permanent") || !strings.HasPrefix(exp.NoGo["model_rewrite"], "permanent") {
		t.Fatalf("expectations no longer close the wire column: %v", exp.NoGo)
	}
	t.Setenv("OPENAI_API_KEY", "sk-synth")
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-synth")
	t.Setenv("PATH", t.TempDir()) // no vendor binary: Detect must still answer, not error
	d, err := (&Adapter{Home: t.TempDir()}).Detect()
	if err != nil || d.Installed || d.Regime != adapters.RegimeSubscription {
		t.Fatalf("Detect = %+v, %v — subscription regardless of any key in the environment", d, err)
	}
	if RefusalCode(ErrWireNoGo) != CodeNotEligible || !errors.Is(ErrWireNoGo, ErrWireNoGo) {
		t.Fatal("the wire refusal must carry M1E-7105")
	}
	for _, s := range (&Adapter{}).Surfaces() {
		if s.Kind != "hooks" {
			t.Fatalf("a %s surface is offered; the spike closes every other column", s.Kind)
		}
	}
	if exp.UsageClass != "none" {
		t.Fatal("expectations claim a usage class")
	}
}

// TestRegistrationsMatchPinnedFixtures: the events the fragment registers are
// exactly the bodies the pinned corpus carries, every name is in the vendor's
// vocabulary (an unknown name invalidates the user's whole file), and the
// IDE-only pair is registered knowingly.
func TestRegistrationsMatchPinnedFixtures(t *testing.T) {
	exp := loadExpectations(t)
	ents, err := os.ReadDir(filepath.Join(fixtureRoot, "hooks"))
	if err != nil {
		t.Fatal(err)
	}
	onDisk := map[string]bool{}
	for _, e := range ents {
		onDisk[strings.TrimSuffix(e.Name(), ".json")] = true
	}
	module, err := os.ReadFile(filepath.Join(fixtureRoot, "schema", "hooks-module.js"))
	if err != nil {
		t.Fatal(err)
	}
	registered := map[string]bool{}
	for _, r := range hookRegistrations {
		registered[r.Event] = true
		if !onDisk[r.Event] {
			t.Errorf("registers %s with no fixture body", r.Event)
		}
		if !bytes.Contains(module, []byte(r.Event+`: "`+r.Event+`",`)) {
			t.Errorf("%s is not in the vendor's event vocabulary (hooks-module.js r)", r.Event)
		}
	}
	for ev := range onDisk {
		if !registered[ev] {
			t.Errorf("fixture body %s exists but is not registered", ev)
		}
	}
	if len(exp.Hooks.Registered) != len(hookRegistrations) {
		t.Errorf("expectations register %d, fragment %d", len(exp.Hooks.Registered), len(hookRegistrations))
	}
	for _, ev := range exp.Hooks.IDEOnly {
		if !registered[ev] {
			t.Errorf("%s is IDE-only and must still be registered for the IDE surface", ev)
		}
	}
}

// TestFragmentParsesAsCursorHooksFile pins the on-disk shape to the vendor
// validator (te/X in hooks-module.js): version 1, flat entries, known keys.
func TestFragmentParsesAsCursorHooksFile(t *testing.T) {
	ch := t.TempDir()
	res, err := ApplyFragment(filepath.Join(ch, "hooks.json"), t.TempDir(), "")
	if err != nil || !res.Changed || res.Mechanism != "A" {
		t.Fatalf("apply: %+v %v", res, err)
	}
	b, err := os.ReadFile(filepath.Join(ch, "hooks.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Version int `json:"version"`
		Hooks   map[string][]struct {
			Command string `json:"command"`
			Timeout int    `json:"timeout"`
			Mark1   string `json:"_mark1"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(b, &file); err != nil {
		t.Fatal(err)
	}
	if file.Version != 1 {
		t.Fatalf("version %d: the validator requires a positive integer version", file.Version)
	}
	if len(file.Hooks) != len(hookRegistrations) {
		t.Fatalf("%d events, want %d", len(file.Hooks), len(hookRegistrations))
	}
	for ev, entries := range file.Hooks {
		if len(entries) != 1 || entries[0].Mark1 != tagValue || entries[0].Timeout <= 0 {
			t.Fatalf("%s: %+v", ev, entries)
		}
		if entries[0].Command != "env MARK1_AGENT=cursor "+DefaultShimPath {
			t.Fatalf("%s command: %q", ev, entries[0].Command)
		}
	}
	if file.Hooks["stop"][0].Timeout != 30 || file.Hooks["sessionEnd"][0].Timeout != 3 {
		t.Fatal("stop keeps the 30 s gate budget; sessionEnd is fire-and-forget at 3 s")
	}
	var raw map[string]json.RawMessage
	_ = json.Unmarshal(b, &raw)
	for k := range raw {
		if k != "version" && k != "hooks" {
			t.Fatalf("root key %q is not one the vendor validator knows", k)
		}
	}
}

func TestOwnedFileApplyIsIdempotentAndOffDeletesIt(t *testing.T) {
	ch, state := t.TempDir(), t.TempDir()
	target := filepath.Join(ch, "hooks.json")
	first, err := ApplyFragment(target, state, "")
	if err != nil || !first.Changed {
		t.Fatalf("first apply: %+v %v", first, err)
	}
	after1, _ := os.ReadFile(target)
	second, err := ApplyFragment(target, state, "")
	if err != nil || second.Changed {
		t.Fatalf("re-apply must be a no-op: %+v %v", second, err)
	}
	after2, _ := os.ReadFile(target)
	if !bytes.Equal(after1, after2) {
		t.Fatal("apply ∘ apply changed bytes")
	}
	st, err := Inspect(state)
	if err != nil || st.State != StateOK || st.Mechanism != "A" || len(st.Lines) != len(hookRegistrations) {
		t.Fatalf("inspect: %+v %v", st, err)
	}
	res, err := Revert(state)
	if err != nil || res.Kind != "verbatim" || !res.ByteEquality {
		t.Fatalf("revert: %+v %v", res, err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatal("mechanism A revert must delete the owned file")
	}
	if _, err := os.Stat(ManifestPath(state)); !os.IsNotExist(err) {
		t.Fatal("manifest must be deleted last")
	}
	if res, err := Revert(state); err != nil || res.Kind != "not-provisioned" {
		t.Fatalf("second off must succeed as a no-op: %+v %v", res, err)
	}
	a := &Adapter{Home: t.TempDir(), CursorDir: ch, StateDir: state}
	if _, err := a.Apply(); err != nil {
		t.Fatal(err)
	}
	if st, _ := Inspect(state); st.State != StateOK || st.Target != target {
		t.Fatalf("adapter paths: %+v", st)
	}
}

// TestFencedApplyKeepsUserBytesAndOffIsByteEqual: mechanism B — the user's own
// stop hook (with its loop_limit) survives byte-for-byte, JSONC comments and
// all, and `mark1 off` restores the original.
func TestFencedApplyKeepsUserBytesAndOffIsByteEqual(t *testing.T) {
	ch, state := t.TempDir(), t.TempDir()
	target := filepath.Join(ch, "hooks.json")
	original := []byte("{\n  \"version\": 1,\n  \"hooks\": {\"stop\": [ {\"command\": \"./audit.sh\", \"loop_limit\": 10} ]}\n}\n")
	if err := os.WriteFile(target, original, 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := ApplyFragment(target, state, "")
	if err != nil || !res.Changed || res.Mechanism != "B" {
		t.Fatalf("apply: %+v %v", res, err)
	}
	for _, p := range res.Pointers {
		if strings.HasPrefix(p, "/hooks/stop/") && p != "/hooks/stop/1" {
			t.Fatalf("our stop entry must append after the user's: %s", p)
		}
	}
	post, _ := os.ReadFile(target)
	var file struct {
		Version int                          `json:"version"`
		Hooks   map[string][]json.RawMessage `json:"hooks"`
	}
	if err := json.Unmarshal(post, &file); err != nil || file.Version != 1 || len(file.Hooks["stop"]) != 2 {
		t.Fatalf("user's file lost content: %v\n%s", err, post)
	}
	if user := string(file.Hooks["stop"][0]); !strings.Contains(user, `"./audit.sh"`) || !strings.Contains(user, `"loop_limit": 10`) {
		t.Fatalf("user's handler changed:\n%s", user)
	}
	if fi, _ := os.Stat(target); fi.Mode().Perm() != 0o644 {
		t.Fatal("target mode not preserved")
	}
	if st, _ := Inspect(state); st.State != StateOK {
		t.Fatalf("inspect: %+v", st)
	}
	rev, err := Revert(state)
	if err != nil || rev.Kind != "verbatim" || !rev.ByteEquality {
		t.Fatalf("revert: %+v %v", rev, err)
	}
	if got, _ := os.ReadFile(target); !bytes.Equal(got, original) {
		t.Fatalf("off is not byte-equal:\n%s", got)
	}
}

func TestUserEditAfterApplyRevertsSurgically(t *testing.T) {
	ch, state := t.TempDir(), t.TempDir()
	target := filepath.Join(ch, "hooks.json")
	if _, err := ApplyFragment(target, state, ""); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(target)
	var root map[string]json.RawMessage
	_ = json.Unmarshal(b, &root)
	var hooks map[string]json.RawMessage
	_ = json.Unmarshal(root["hooks"], &hooks)
	hooks["preToolUse"] = json.RawMessage(string(hooks["preToolUse"][:len(hooks["preToolUse"])-1]) + `,{"command":"echo user","matcher":"Shell"}]`)
	root["hooks"], _ = json.Marshal(hooks)
	edited, _ := json.MarshalIndent(root, "", " ")
	if err := os.WriteFile(target, edited, 0o600); err != nil {
		t.Fatal(err)
	}
	if st, _ := Inspect(state); st.State != StateUserEdited {
		t.Fatalf("inspect: %+v", st)
	}
	rev, err := Revert(state)
	if err != nil || rev.Kind != "surgical" || rev.ByteEquality {
		t.Fatalf("revert: %+v %v", rev, err)
	}
	after, _ := os.ReadFile(target)
	if bytes.Contains(after, []byte(entryTag)) || !bytes.Contains(after, []byte("echo user")) {
		t.Fatalf("surgical revert wrong:\n%s", after)
	}
	var check struct {
		Version int                          `json:"version"`
		Hooks   map[string][]json.RawMessage `json:"hooks"`
	}
	_ = json.Unmarshal(after, &check)
	if check.Version != 1 || len(check.Hooks) != 1 || len(check.Hooks["preToolUse"]) != 1 {
		t.Fatalf("events we created must vanish, the user's stay, version stays valid: %v", check.Hooks)
	}
}

func TestHandEditInsideOurEntriesRefusesUntilRepair(t *testing.T) {
	ch, state := t.TempDir(), t.TempDir()
	target := filepath.Join(ch, "hooks.json")
	if _, err := ApplyFragment(target, state, ""); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(target)
	tampered := bytes.Replace(b, []byte(`"timeout": 30`), []byte(`"timeout": 600`), 1)
	if bytes.Equal(tampered, b) {
		t.Fatal("fixture drift: stop's timeout not found")
	}
	if err := os.WriteFile(target, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyFragment(target, state, ""); !errors.Is(err, ErrDamaged) || RefusalCode(err) != CodeDamaged {
		t.Fatalf("apply over a hand-edited entry: %v", err)
	}
	if st, _ := Inspect(state); st.State != StateDamaged {
		t.Fatalf("inspect: %+v", st)
	}
	if res, err := RepairFragment(target, state, ""); err != nil || !res.Changed {
		t.Fatalf("repair: %+v %v", res, err)
	}
	if st, _ := Inspect(state); st.State != StateOK {
		t.Fatalf("after repair: %+v", st)
	}
}

func TestRefusals(t *testing.T) {
	if _, err := ApplyFragment(filepath.Join(t.TempDir(), "nope", "hooks.json"), t.TempDir(), ""); !errors.Is(err, ErrNoTarget) || RefusalCode(err) != CodeNoTarget {
		t.Fatalf("missing ~/.cursor must refuse: %v", err)
	}
	ch := t.TempDir()
	if err := os.WriteFile(filepath.Join(ch, "hooks.json"), []byte(`{"version":1,"hooks":{},"hooks":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyFragment(filepath.Join(ch, "hooks.json"), t.TempDir(), ""); !errors.Is(err, ErrDuplicateKey) {
		t.Fatalf("duplicate key must refuse: %v", err)
	}
	state := t.TempDir()
	if err := os.MkdirAll(filepath.Dir(ManifestPath(state)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ManifestPath(state), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyFragment(filepath.Join(t.TempDir(), "hooks.json"), state, ""); !errors.Is(err, ErrManifestCorrupt) {
		t.Fatalf("corrupt manifest must refuse: %v", err)
	}
}
