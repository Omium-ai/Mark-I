package claudecode

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters"
)

// userSettings is a settings.json shaped like a real one: keys Mark 1 does
// not own, and the user's OWN Stop handler, which must survive untouched.
const userSettings = `{
  "model": "opus",
  "hooks": {
    "Stop": [
      { "matcher": "", "hooks": [ { "type": "command", "command": "/usr/bin/mine.sh" } ] }
    ]
  },
  "permissions": { "allow": ["Bash(ls:*)"] }
}
`

// fenceLines is every pointer the fence records: the nine handlers plus the status-line slot.
var fenceLines = len(hookRegistrations) + 1

func writeSettings(t *testing.T, body string) (path, stateDir string) {
	t.Helper()
	dir := t.TempDir()
	path = filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, filepath.Join(dir, "state")
}

func readJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("apply produced invalid JSON: %v\n%s", err, b)
	}
	return m
}

// entry digs out /hooks/<event>/<idx>.
func entry(t *testing.T, m map[string]any, event string, idx int) map[string]any {
	t.Helper()
	hooks, ok := m["hooks"].(map[string]any)
	if !ok {
		t.Fatalf("no hooks object: %#v", m)
	}
	list, ok := hooks[event].([]any)
	if !ok || idx >= len(list) {
		t.Fatalf("/hooks/%s/%d absent: %#v", event, idx, hooks[event])
	}
	e, _ := list[idx].(map[string]any)
	return e
}

// TestFragmentRegistersStopAndSessionStart is the deliverable's core claim:
// the Stop gate and the SessionStart injection are registered with 08 §5.1's
// exact matchers and deadlines, through the shim, without disturbing the
// user's own keys or their own Stop handler.
func TestFragmentRegistersStopAndSessionStart(t *testing.T) {
	path, state := writeSettings(t, userSettings)
	res, err := ApplyFragment(path, state, "")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed {
		t.Fatal("first apply reported no change")
	}
	m := readJSON(t, path)

	// The user's handler kept its index; ours was appended after it.
	if got := entry(t, m, "Stop", 0)["hooks"].([]any)[0].(map[string]any)["command"]; got != "/usr/bin/mine.sh" {
		t.Fatalf("user's own Stop handler moved or was overwritten: %v", got)
	}
	stop := entry(t, m, "Stop", 1)
	if stop["_mark1"] != "v1" || stop["matcher"] != "" {
		t.Fatalf("Stop registration shape: %#v", stop)
	}
	sh := stop["hooks"].([]any)[0].(map[string]any)
	if sh["type"] != "command" || sh["command"] != DefaultShimPath || sh["timeout"].(float64) != 30 {
		t.Fatalf("Stop gate row (08 §5.1: command shim, 30 s): %#v", sh)
	}
	ss := entry(t, m, "SessionStart", 0)
	if ss["matcher"] != "*" {
		t.Fatalf("SessionStart matcher = %v, want * (08 §5.1)", ss["matcher"])
	}
	if to := ss["hooks"].([]any)[0].(map[string]any)["timeout"].(float64); to != 10 {
		t.Fatalf("SessionStart timeout = %v, want 10 (08 §5.1)", to)
	}

	// Untouched user keys survive verbatim.
	if m["model"] != "opus" {
		t.Fatalf("user key mutated: %#v", m["model"])
	}
	if _, ok := m["permissions"]; !ok {
		t.Fatal("user key dropped")
	}

	// 08 §8.1: pointers + a checksum that actually describes the values at
	// those pointers.
	mg, ok := m[managedKey].(map[string]any)
	if !ok {
		t.Fatalf("no %s object", managedKey)
	}
	if mg["agent"] != "claudecode" || mg["fragment"] != "hooks" || mg["version"].(float64) != 1 {
		t.Fatalf("managed header: %#v", mg)
	}
	if !strings.HasPrefix(mg["checksum"].(string), "blake3:") {
		t.Fatalf("checksum is not blake3: %v", mg["checksum"])
	}
	ptrs := mg["pointers"].([]any)
	if len(ptrs) != fenceLines {
		t.Fatalf("%d pointers, want %d", len(ptrs), fenceLines)
	}
	if !contains(ptrs, "/hooks/Stop/1") || !contains(ptrs, "/hooks/SessionStart/0") || !contains(ptrs, "/statusLine") {
		t.Fatalf("pointers do not record where our entries landed: %v", ptrs)
	}

	// The manifest (§8.2) exists where doctor and `mark1 off` glob for it.
	if _, err := os.Stat(filepath.Join(state, "provisioned", "claudecode", "hooks.manifest.json")); err != nil {
		t.Fatalf("manifest: %v", err)
	}
}

func contains(vals []any, want string) bool {
	for _, v := range vals {
		if v == want {
			return true
		}
	}
	return false
}

// TestFragmentApplyIsIdempotent: §8.3(b) — a second apply is a no-op that
// does not open the target for write. Byte-equality is the assertion because
// "no change" measured any other way is a claim, not a fact.
func TestFragmentApplyIsIdempotent(t *testing.T) {
	path, state := writeSettings(t, userSettings)
	if _, err := ApplyFragment(path, state, ""); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	res, err := ApplyFragment(path, state, "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed {
		t.Fatal("re-apply of an identical fragment reported a change (§8.3 b)")
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatalf("re-apply rewrote the file:\n%s\n---\n%s", first, second)
	}
}

// TestFragmentReapplyReplacesStaleFragmentOnly: §8.3(c) — a fragment revision
// (here: a different shim path) replaces the payload between our pointers and
// nothing else, and the manifest keeps the ORIGINAL pre-Mark1 bytes so revert
// still restores the file the user had before Mark 1 existed.
func TestFragmentReapplyReplacesStaleFragmentOnly(t *testing.T) {
	path, state := writeSettings(t, userSettings)
	if _, err := ApplyFragment(path, state, ""); err != nil {
		t.Fatal(err)
	}
	res, err := ApplyFragment(path, state, "/opt/mark1/bin/mark1-hookshim")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed {
		t.Fatal("a changed fragment was treated as current")
	}
	m := readJSON(t, path)
	if got := entry(t, m, "Stop", 0)["hooks"].([]any)[0].(map[string]any)["command"]; got != "/usr/bin/mine.sh" {
		t.Fatalf("user's handler was rewritten by the replace path: %v", got)
	}
	if got := entry(t, m, "Stop", 1)["hooks"].([]any)[0].(map[string]any)["command"]; got != "/opt/mark1/bin/mark1-hookshim" {
		t.Fatalf("our entry was not replaced: %v", got)
	}
	if n := len(m["hooks"].(map[string]any)["Stop"].([]any)); n != 2 {
		t.Fatalf("replace appended instead of replacing: %d Stop entries", n)
	}

	b, err := os.ReadFile(filepath.Join(state, "provisioned", "claudecode", "hooks.manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var man Manifest
	if err := json.Unmarshal(b, &man); err != nil {
		t.Fatal(err)
	}
	pre, err := RestorePreImage(man)
	if err != nil {
		t.Fatal(err)
	}
	if string(pre) != userSettings {
		t.Fatalf("pre_image is not the pre-Mark1 bytes:\n%s", pre)
	}
}

// TestFragmentDamagedRefusesWrite: §8.3(d) — a human edit inside our pointers
// stops the apply cold. Silently overwriting it is the one outcome the
// algorithm forbids.
func TestFragmentDamagedRefusesWrite(t *testing.T) {
	path, state := writeSettings(t, userSettings)
	if _, err := ApplyFragment(path, state, ""); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(b), `"timeout": 30`, `"timeout": 90`, 1)
	if edited == string(b) {
		t.Fatal("fixture drift: no 30 s timeout to hand-edit")
	}
	if err := os.WriteFile(path, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyFragment(path, state, ""); err != ErrDamaged {
		t.Fatalf("apply over a hand-edited fragment: %v, want %v", err, ErrDamaged)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != edited {
		t.Fatal("damaged fragment was overwritten")
	}
}

// TestFragmentSurvivesClaudeCodeRewrite: Claude Code rewrites settings.json on
// every settings change and drops `_mark1` as an unknown key. That is not a
// human edit: the next apply reconciles the managed block in place, with no
// second copy of the hooks and no refusal.
func TestFragmentSurvivesClaudeCodeRewrite(t *testing.T) {
	path, state := writeSettings(t, userSettings)
	if _, err := ApplyFragment(path, state, ""); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	strip := func(v any) {
		if o, ok := v.(map[string]any); ok {
			delete(o, entryTag)
		}
	}
	strip(doc[statusLineKey])
	for _, list := range doc["hooks"].(map[string]any) {
		for _, e := range list.([]any) {
			strip(e)
		}
	}
	// and the managed block as a release that hashed the tags recorded it
	doc[managedKey].(map[string]any)["checksum"] = "blake3:" + strings.Repeat("0", 64)
	rewritten, _ := json.MarshalIndent(doc, "", "  ")
	if strings.Contains(string(rewritten), entryTag+`"`) {
		t.Fatal("fixture drift: a tag survived the strip")
	}
	if err := os.WriteFile(path, rewritten, 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := ApplyFragment(path, state, "")
	if err != nil {
		t.Fatalf("apply after Claude Code stripped the tags: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(after), `"Stop"`); n != 1 {
		t.Fatalf("Stop registered %d times after the reconcile", n)
	}
	if n := strings.Count(string(after), DefaultShimPath+`"`); n != len(hookRegistrations) {
		t.Fatalf("%d shim hook entries after the reconcile, want %d:\n%s", n, len(hookRegistrations), after)
	}
	if !res.Changed {
		t.Fatal("the managed block was not refreshed")
	}
	if res2, err := ApplyFragment(path, state, ""); err != nil || res2.Changed {
		t.Fatalf("third apply: changed=%v err=%v, want a no-op", res2.Changed, err)
	}
}

// TestFragmentRefusesDuplicateKeys: a settings object with the same key twice
// is legal JSON that every decoder collapses differently. 08 §8.1 promises we
// never touch a key we do not list in `pointers`, and rewriting this file
// deletes one of the user's two values — so the posture is refusal, not a
// silent last-wins normalization.
func TestFragmentRefusesDuplicateKeys(t *testing.T) {
	const dup = `{
  "model": "opus",
  "hooks": {},
  "model": "sonnet"
}
`
	path, state := writeSettings(t, dup)
	if _, err := ApplyFragment(path, state, ""); !errors.Is(err, ErrDuplicateKey) {
		t.Fatalf("duplicate key: %v, want %v", err, ErrDuplicateKey)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != dup {
		t.Fatalf("a refused apply still rewrote the file:\n%s", b)
	}
}

// TestFragmentPreservesUntouchedValueBytes pins exactly how much of 08 §8.1's
// "never sets, merges, or reorders any key it does not list in pointers" this
// implementation delivers, and where it stops:
//
//   - a top-level value we do not own goes back out BYTE FOR BYTE, interior
//     whitespace and all;
//   - the file's top-level line framing (one "key": value per line, two-space
//     indent, trailing newline) IS normalized on first apply, as is the
//     /hooks subtree we must re-emit to place our entries in it. Untouched
//     entries inside /hooks keep their JSON value, not their spacing.
//
// A byte-preserving splice of arbitrary nested regions needs an
// offset-tracking JSON editor; it is not built, because 08 §8.4 step 2 already
// makes revert restore the pre_image verbatim, so the cost of this
// normalization is a cosmetic diff that `mark1 off` undoes exactly.
func TestFragmentPreservesUntouchedValueBytes(t *testing.T) {
	const oddSpacing = `{"permissions":{"allow":["Bash(ls:*)"],
        "deny":    []},
 "hooks": {"Stop": [{"matcher":"","hooks":[{"type":"command","command":"/usr/bin/mine.sh"}]}]}}
`
	const untouched = `{"allow":["Bash(ls:*)"],
        "deny":    []}`
	path, state := writeSettings(t, oddSpacing)
	if _, err := ApplyFragment(path, state, ""); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), untouched) {
		t.Fatalf("a value we do not own was re-formatted; want the original bytes\n%s", b)
	}
	// The pinned half: our own subtree is re-indented, and the user's handler
	// inside it survives as a value.
	m := readJSON(t, path)
	if got := entry(t, m, "Stop", 0)["hooks"].([]any)[0].(map[string]any)["command"]; got != "/usr/bin/mine.sh" {
		t.Fatalf("user's own Stop handler did not survive: %v", got)
	}
	if !strings.Contains(string(b), `"command": "`+DefaultShimPath+`"`) {
		t.Fatalf("our own entries are expected to be indented, not compact:\n%s", b)
	}
}

// TestFragmentRefusesCorruptManifest is F10(b): the manifest's pre_image is the
// only byte-equality revert target `mark1 off` has (08 §8.4 step 2). When the
// manifest cannot be read, the bytes on disk are already POST-Mark1, so
// re-snapshotting them would record our own output as "the file the user had".
// Apply refuses instead — and refuses before touching the settings file.
func TestFragmentRefusesCorruptManifest(t *testing.T) {
	path, state := writeSettings(t, userSettings)
	if _, err := ApplyFragment(path, state, ""); err != nil {
		t.Fatal(err)
	}
	applied, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	man := filepath.Join(state, "provisioned", "claudecode", "hooks.manifest.json")
	if err := os.WriteFile(man, []byte(`{"target_path": tru`), 0o600); err != nil {
		t.Fatal(err)
	}
	// A changed fragment, so the apply would otherwise take the §8.3(c) write path.
	if _, err := ApplyFragment(path, state, "/opt/mark1/bin/mark1-hookshim"); !errors.Is(err, ErrManifestCorrupt) {
		t.Fatalf("corrupt manifest: %v, want %v", err, ErrManifestCorrupt)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(applied) {
		t.Fatal("a refused apply rewrote the settings file")
	}
	b, err := os.ReadFile(man)
	if err != nil {
		t.Fatal(err)
	}
	var m Manifest
	if json.Unmarshal(b, &m) == nil {
		t.Fatalf("the corrupt manifest was overwritten — the pre-Mark1 image is gone:\n%s", b)
	}
}

// TestFragmentRefusesMissingTarget: §8.3(1) — mechanism B never invents a
// user file to fence into.
func TestFragmentRefusesMissingTarget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if _, err := ApplyFragment(path, filepath.Join(dir, "state"), ""); err != ErrNoTarget {
		t.Fatalf("missing target: %v, want %v", err, ErrNoTarget)
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("mechanism B created the user's file")
	}
}

// TestFragmentManifestPrecedesTheTargetWrite pins the ordering that makes
// `mark1 off` total. Revert keys off the manifest alone — no manifest means it
// returns "not-provisioned" before it ever opens settings.json — so a target
// carrying our entries with no manifest beside it is unremovable by any
// supported command. Writing the manifest first makes that state unreachable:
// the only crash window left leaves a manifest with no fragment, which Revert
// resolves through its tag-driven surgical path.
func TestFragmentManifestPrecedesTheTargetWrite(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the directory mode this test writes through")
	}
	if runtime.GOOS == "windows" {
		// The read-only attribute on a directory does not deny file creation
		// in it, so the fault cannot be constructed; the manifest-first
		// ordering is the same platform-neutral code path — FR-AGENT-*
		// (08 §8.2 manifest-before-target) unproven on windows only.
		t.Skip("windows: a read-only directory attribute does not block the target write")
	}
	dir := t.TempDir()
	settings := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(settings, []byte(userSettings), 0o600); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(t.TempDir(), "mark1")

	// Deny the target write only — the state root is a separate temp dir, so
	// the manifest leg is untouched.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	if _, err := ApplyFragment(settings, state, "/usr/bin/mark1-hookshim"); err == nil {
		t.Fatal("target write should have failed against a read-only directory")
	}
	if _, err := os.Stat(ManifestPath(state)); err != nil {
		t.Fatalf("manifest must already exist when the target write fails, "+
			"or a crash here strands our entries with no way to remove them: %v", err)
	}
}

// TestProvisionAppliesFragmentToVendorSettings is the last mile: the daemon
// calls Adapter.Provision, and the Stop gate + SessionStart injection actually
// land in the vendor's own ~/.claude/settings.json (the path Surfaces()
// advertises), with the §8.2 manifest under the daemon's state root — not a
// second, divergent one.
func TestProvisionAppliesFragmentToVendorSettings(t *testing.T) {
	home := t.TempDir()
	state := filepath.Join(t.TempDir(), "mark1")
	settings := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settings), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settings, []byte(userSettings), 0o600); err != nil {
		t.Fatal(err)
	}
	a := &Adapter{Home: home, StateDir: state}
	if err := a.Provision(adapters.Workspace{Root: t.TempDir()}, nil); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	m := readJSON(t, settings)
	stop := entry(t, m, "Stop", 1)["hooks"].([]any)[0].(map[string]any)
	if stop["command"] != DefaultShimPath || stop["timeout"].(float64) != 30 {
		t.Fatalf("Stop gate not registered by Provision: %#v", stop)
	}
	ss := entry(t, m, "SessionStart", 0)["hooks"].([]any)[0].(map[string]any)
	if ss["command"] != DefaultShimPath || ss["timeout"].(float64) != 10 {
		t.Fatalf("SessionStart injection not registered by Provision: %#v", ss)
	}
	if _, err := os.Stat(filepath.Join(state, "provisioned", "claudecode", "hooks.manifest.json")); err != nil {
		t.Fatalf("manifest did not land under the daemon's state root: %v", err)
	}
	// Re-provisioning is the same no-op the fragment guarantees — the daemon
	// may call this on every start.
	if err := a.Provision(adapters.Workspace{Root: t.TempDir()}, nil); err != nil {
		t.Fatalf("re-Provision: %v", err)
	}
}

// TestProvisionRefusesMissingSettings: §8.3(1) survives the Provision seam —
// no vendor settings file, no invention of one.
func TestProvisionRefusesMissingSettings(t *testing.T) {
	home := t.TempDir()
	a := &Adapter{Home: home, StateDir: filepath.Join(home, "state")}
	if err := a.Provision(adapters.Workspace{Root: home}, nil); err != ErrNoTarget {
		t.Fatalf("Provision with no settings.json: %v, want %v", err, ErrNoTarget)
	}
	if _, err := os.Stat(filepath.Join(home, ".claude")); err == nil {
		t.Fatal("Provision created the vendor's config dir")
	}
}

// TestRegistrationsMatchPinnedFixtures ties the fragment to the recorded
// corpus: we register exactly the events conformance/hooks/claudecode has
// bodies for. A registration with no fixture is a hook nobody ever replayed;
// a fixture with no registration is an event we will never receive.
func TestRegistrationsMatchPinnedFixtures(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "..", "conformance", "hooks", "claudecode", "v2.1.251", "hooks")
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("pinned fixture dir (a vacuous pass proves nothing): %v", err)
	}
	var fixtures []string
	for _, e := range ents {
		fixtures = append(fixtures, strings.TrimSuffix(e.Name(), ".json"))
	}
	var registered []string
	for _, r := range hookRegistrations {
		registered = append(registered, r.Event)
	}
	sort.Strings(fixtures)
	sort.Strings(registered)
	if strings.Join(fixtures, ",") != strings.Join(registered, ",") {
		t.Fatalf("registrations %v != pinned fixtures %v", registered, fixtures)
	}
}
