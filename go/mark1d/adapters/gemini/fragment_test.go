package gemini

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestRegistrationsMatchPinnedFixtures: the events the fragment registers are
// exactly the hook bodies the pinned corpus proves (08 §5 rule 3).
func TestRegistrationsMatchPinnedFixtures(t *testing.T) {
	ents, err := os.ReadDir(filepath.Join(fixtureRoot, "hooks"))
	if err != nil {
		t.Fatal(err)
	}
	onDisk := map[string]bool{}
	for _, e := range ents {
		onDisk[strings.TrimSuffix(e.Name(), ".json")] = true
	}
	registered := map[string]bool{}
	for _, r := range hookRegistrations {
		registered[r.Event] = true
		if !onDisk[r.Event] {
			t.Errorf("registers %s with no fixture body under conformance/hooks/gemini/v0.59.0/hooks", r.Event)
		}
		if r.Timeout < 1000 {
			t.Errorf("%s timeout %d reads as seconds; CommandHookConfig.timeout is milliseconds", r.Event, r.Timeout)
		}
	}
	for ev := range onDisk {
		if !registered[ev] {
			t.Errorf("fixture body %s exists but is not registered", ev)
		}
	}
}

func seedSettings(t *testing.T, body string) (target, state string) {
	t.Helper()
	target = filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(target, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return target, t.TempDir()
}

// TestFragmentParsesAsGeminiHookDefinitions pins the on-disk shape to
// types.ts HookDefinition{matcher, hooks: CommandHookConfig[]} with the env
// carrying MARK1_AGENT and ms timeouts.
func TestFragmentParsesAsGeminiHookDefinitions(t *testing.T) {
	target, state := seedSettings(t, "{\n  \"security\": {\"auth\": {\"selectedType\": \"oauth-personal\"}}\n}\n")
	res, err := ApplyFragment(target, state, "")
	if err != nil || !res.Changed || res.Mechanism != "B" {
		t.Fatalf("apply: %+v %v", res, err)
	}
	b, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Security json.RawMessage `json:"security"`
		Hooks    map[string][]struct {
			Matcher string `json:"matcher"`
			Hooks   []struct {
				Type    string            `json:"type"`
				Command string            `json:"command"`
				Timeout int               `json:"timeout"`
				Env     map[string]string `json:"env"`
			} `json:"hooks"`
			Mark1 string `json:"_mark1"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(b, &file); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(file.Security, []byte(`"oauth-personal"`)) {
		t.Fatal("user's security block lost")
	}
	if len(file.Hooks) != len(hookRegistrations) {
		t.Fatalf("%d events, want %d", len(file.Hooks), len(hookRegistrations))
	}
	for ev, groups := range file.Hooks {
		if len(groups) != 1 || groups[0].Mark1 != tagValue || len(groups[0].Hooks) != 1 {
			t.Fatalf("%s: %+v", ev, groups)
		}
		h := groups[0].Hooks[0]
		if h.Type != "command" || h.Command != DefaultShimPath || h.Timeout < 1000 || h.Env["MARK1_AGENT"] != "gemini" {
			t.Fatalf("%s handler: %+v", ev, h)
		}
	}
	if file.Hooks["AfterAgent"][0].Hooks[0].Timeout != 30000 || file.Hooks["SessionEnd"][0].Hooks[0].Timeout != 3000 {
		t.Fatal("AfterAgent keeps the 30 s gate budget; SessionEnd sits at 3 s")
	}
	if file.Hooks["BeforeTool"][0].Matcher != "*" || file.Hooks["AfterAgent"][0].Matcher != "" {
		t.Fatal("tool events match every tool; lifecycle events carry no matcher")
	}
}

func TestMissingSettingsRefuses(t *testing.T) {
	if _, err := ApplyFragment(filepath.Join(t.TempDir(), "settings.json"), t.TempDir(), ""); !errors.Is(err, ErrNoTarget) || RefusalCode(err) != CodeNoTarget {
		t.Fatalf("mechanism B must never create the user's settings.json: %v", err)
	}
}

// TestFencedApplyKeepsUserBytesAndOffIsByteEqual: the user's own handler and
// formatting survive byte-for-byte and `mark1 off` restores the original.
func TestFencedApplyKeepsUserBytesAndOffIsByteEqual(t *testing.T) {
	original := []byte("{\n  \"theme\": \"Default\",\n  \"hooks\": {\"BeforeTool\": [ {\"matcher\":\"run_shell_command\", \"hooks\": [ {\"type\":\"command\",\"command\":\"echo hi\"} ] } ]}\n}\n")
	target, state := seedSettings(t, string(original))
	res, err := ApplyFragment(target, state, "")
	if err != nil || !res.Changed || res.Mechanism != "B" {
		t.Fatalf("apply: %+v %v", res, err)
	}
	for _, p := range res.Pointers {
		if strings.HasPrefix(p, "/hooks/BeforeTool/") && p != "/hooks/BeforeTool/1" {
			t.Fatalf("our BeforeTool entry must append after the user's: %s", p)
		}
	}
	second, err := ApplyFragment(target, state, "")
	if err != nil || second.Changed {
		t.Fatalf("re-apply must be a no-op: %+v %v", second, err)
	}
	post, _ := os.ReadFile(target)
	var file struct {
		Theme string                       `json:"theme"`
		Hooks map[string][]json.RawMessage `json:"hooks"`
	}
	if err := json.Unmarshal(post, &file); err != nil || file.Theme != "Default" || len(file.Hooks["BeforeTool"]) != 2 {
		t.Fatalf("user's file lost content: %v\n%s", err, post)
	}
	user := string(file.Hooks["BeforeTool"][0])
	if !strings.Contains(user, `"echo hi"`) || strings.Index(user, `"matcher"`) > strings.Index(user, `"hooks"`) {
		t.Fatalf("user's handler moved or reordered:\n%s", user)
	}
	if fi, _ := os.Stat(target); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o644 {
		t.Fatal("target mode not preserved") // no POSIX mode bits on windows
	}
	st, err := Inspect(state)
	if err != nil || st.State != StateOK || st.Mechanism != "B" || len(st.Lines) != len(hookRegistrations) {
		t.Fatalf("inspect: %+v %v", st, err)
	}
	rev, err := Revert(state)
	if err != nil || rev.Kind != "verbatim" || !rev.ByteEquality {
		t.Fatalf("revert: %+v %v", rev, err)
	}
	got, _ := os.ReadFile(target)
	if !bytes.Equal(got, original) {
		t.Fatalf("off is not byte-equal:\n%s", got)
	}
	if _, err := os.Stat(ManifestPath(state)); !os.IsNotExist(err) {
		t.Fatal("manifest must be deleted last")
	}
	if res, err := Revert(state); err != nil || res.Kind != "not-provisioned" {
		t.Fatalf("second off must succeed as a no-op: %+v %v", res, err)
	}
}

func TestUserEditAfterApplyRevertsSurgically(t *testing.T) {
	target, state := seedSettings(t, "{\"theme\":\"Default\"}\n")
	if _, err := ApplyFragment(target, state, ""); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(target)
	var root map[string]json.RawMessage
	_ = json.Unmarshal(b, &root)
	var hooks map[string]json.RawMessage
	_ = json.Unmarshal(root["hooks"], &hooks)
	hooks["BeforeTool"] = json.RawMessage(string(hooks["BeforeTool"][:len(hooks["BeforeTool"])-1]) + `,{"matcher":"write_file","hooks":[{"type":"command","command":"echo user"}]}]`)
	root["hooks"], _ = json.Marshal(hooks)
	root["theme"] = json.RawMessage(`"edited by the user"`)
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
	if bytes.Contains(after, []byte(entryTag)) || !bytes.Contains(after, []byte("echo user")) || !bytes.Contains(after, []byte("edited by the user")) {
		t.Fatalf("surgical revert wrong:\n%s", after)
	}
	var check struct {
		Hooks map[string][]json.RawMessage `json:"hooks"`
	}
	_ = json.Unmarshal(after, &check)
	if len(check.Hooks) != 1 || len(check.Hooks["BeforeTool"]) != 1 {
		t.Fatalf("events we created must vanish, the user's stay: %v", check.Hooks)
	}
}

func TestHandEditInsideOurEntriesRefusesUntilRepair(t *testing.T) {
	target, state := seedSettings(t, "{}\n")
	if _, err := ApplyFragment(target, state, ""); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(target)
	tampered := bytes.Replace(b, []byte(`"timeout": 30000`), []byte(`"timeout": 600000`), 1)
	if bytes.Equal(tampered, b) {
		t.Fatal("fixture drift: AfterAgent's timeout not found")
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
	target, _ := seedSettings(t, `{"hooks":{},"hooks":{}}`)
	if _, err := ApplyFragment(target, t.TempDir(), ""); !errors.Is(err, ErrDuplicateKey) {
		t.Fatalf("duplicate key must refuse: %v", err)
	}
	target, _ = seedSettings(t, "// gemini tolerates comments; we do not rewrite what we cannot parse\n{}\n")
	if _, err := ApplyFragment(target, t.TempDir(), ""); err == nil || RefusalCode(err) != "" {
		t.Fatalf("a JSONC settings file must fail apply as a plain parse error: %v", err)
	}
	target, state := seedSettings(t, "{}\n")
	if err := os.MkdirAll(filepath.Dir(ManifestPath(state)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ManifestPath(state), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyFragment(target, state, ""); !errors.Is(err, ErrManifestCorrupt) {
		t.Fatalf("corrupt manifest must refuse: %v", err)
	}
}
