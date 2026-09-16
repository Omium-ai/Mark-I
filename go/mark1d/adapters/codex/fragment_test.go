package codex

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
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
			t.Errorf("registers %s with no fixture body under conformance/hooks/codex/v0.154.0/hooks", r.Event)
		}
		if (r.Event == "SessionEnd" || r.Event == "Interrupt") && r.Timeout > 3 {
			t.Errorf("%s timeout %d exceeds the vendor's 3 s clamp (discovery.rs normalize_command_hook)", r.Event, r.Timeout)
		}
	}
	for ev := range onDisk {
		if !registered[ev] {
			t.Errorf("fixture body %s exists but is not registered", ev)
		}
	}
}

// TestFragmentParsesAsCodexHooksFile pins the on-disk shape to codex_config's
// HooksFile (deny_unknown_fields at the root) and HookHandlerConfig::Command.
func TestFragmentParsesAsCodexHooksFile(t *testing.T) {
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
		Description *string `json:"description"`
		Hooks       map[string][]struct {
			Matcher string `json:"matcher"`
			Hooks   []struct {
				Type           string `json:"type"`
				Command        string `json:"command"`
				CommandWindows string `json:"commandWindows"`
				Timeout        int    `json:"timeout"`
			} `json:"hooks"`
			Mark1 string `json:"_mark1"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(b, &file); err != nil {
		t.Fatal(err)
	}
	var root map[string]json.RawMessage
	_ = json.Unmarshal(b, &root)
	for k := range root {
		if k != "description" && k != "hooks" {
			t.Fatalf("root key %q would be rejected by HooksFile's deny_unknown_fields", k)
		}
	}
	if len(file.Hooks) != len(hookRegistrations) {
		t.Fatalf("%d events, want %d", len(file.Hooks), len(hookRegistrations))
	}
	for ev, groups := range file.Hooks {
		if len(groups) != 1 || groups[0].Mark1 != tagValue || len(groups[0].Hooks) != 1 {
			t.Fatalf("%s: %+v", ev, groups)
		}
		h := groups[0].Hooks[0]
		if h.Type != "command" || h.Command != "env MARK1_AGENT=codex "+DefaultShimPath || h.Timeout <= 0 {
			t.Fatalf("%s handler: %+v", ev, h)
		}
		if !strings.HasPrefix(h.CommandWindows, "set MARK1_AGENT=codex&& ") || !strings.Contains(h.CommandWindows, `%USERPROFILE%\.omium\mark1\bin\mark1-hookshim`) {
			t.Fatalf("%s commandWindows: %q", ev, h.CommandWindows)
		}
	}
	if file.Hooks["Stop"][0].Hooks[0].Timeout != 30 || file.Hooks["SessionEnd"][0].Hooks[0].Timeout != 3 {
		t.Fatal("Stop keeps the 30 s gate budget; SessionEnd sits at the vendor's 3 s cap")
	}
}

// TestOwnedFileApplyIsIdempotentAndOffDeletesIt: mechanism A end to end —
// apply ∘ apply ≡ apply, then `mark1 off` leaves ~/.codex byte-equal (no file).
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
}

// TestFencedApplyKeepsUserBytesAndOffIsByteEqual: mechanism B — the user's
// own handler survives byte-for-byte and `mark1 off` restores the original.
func TestFencedApplyKeepsUserBytesAndOffIsByteEqual(t *testing.T) {
	ch, state := t.TempDir(), t.TempDir()
	target := filepath.Join(ch, "hooks.json")
	original := []byte("{\n  \"description\": \"mine\",\n  \"hooks\": {\"PreToolUse\": [ {\"matcher\":\"shell\", \"hooks\": [ {\"type\":\"command\",\"command\":\"echo hi\"} ] } ]}\n}\n")
	if err := os.WriteFile(target, original, 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := ApplyFragment(target, state, "")
	if err != nil || !res.Changed || res.Mechanism != "B" {
		t.Fatalf("apply: %+v %v", res, err)
	}
	for _, p := range res.Pointers {
		if strings.HasPrefix(p, "/hooks/PreToolUse/") && p != "/hooks/PreToolUse/1" {
			t.Fatalf("our PreToolUse entry must append after the user's: %s", p)
		}
	}
	post, _ := os.ReadFile(target)
	var file struct {
		Description string                       `json:"description"`
		Hooks       map[string][]json.RawMessage `json:"hooks"`
	}
	if err := json.Unmarshal(post, &file); err != nil || file.Description != "mine" || len(file.Hooks["PreToolUse"]) != 2 {
		t.Fatalf("user's file lost content: %v\n%s", err, post)
	}
	user := string(file.Hooks["PreToolUse"][0])
	if !strings.Contains(user, `"echo hi"`) || strings.Index(user, `"matcher"`) > strings.Index(user, `"hooks"`) {
		t.Fatalf("user's handler moved or reordered:\n%s", user)
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
	got, _ := os.ReadFile(target)
	if !bytes.Equal(got, original) {
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
	hooks["PreToolUse"] = json.RawMessage(string(hooks["PreToolUse"][:len(hooks["PreToolUse"])-1]) + `,{"matcher":"shell","hooks":[{"type":"command","command":"echo user"}]}]`)
	root["hooks"], _ = json.Marshal(hooks)
	root["description"] = json.RawMessage(`"edited by the user"`)
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
	if len(check.Hooks) != 1 || len(check.Hooks["PreToolUse"]) != 1 {
		t.Fatalf("events we created must vanish, the user's stay: %v", check.Hooks)
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
		t.Fatal("fixture drift: Stop's timeout not found")
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
	if _, err := ApplyFragment(filepath.Join(t.TempDir(), "nope", "hooks.json"), t.TempDir(), ""); !errors.Is(err, ErrNoTarget) {
		t.Fatalf("missing ~/.codex must refuse: %v", err)
	}
	ch := t.TempDir()
	if err := os.WriteFile(filepath.Join(ch, "hooks.json"), []byte(`{"hooks":{},"hooks":{}}`), 0o600); err != nil {
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
