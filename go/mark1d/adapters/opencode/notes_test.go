package opencode

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

func chatCall(session, text string) map[string]any {
	return map[string]any{
		"hook":   "chat.message",
		"input":  map[string]any{"sessionID": session},
		"output": map[string]any{"parts": []any{map[string]any{"type": "text", "text": text}}},
	}
}

func writeWorkspaces(t *testing.T, home string, mode os.FileMode, roots ...string) {
	t.Helper()
	var ws []map[string]any
	for _, r := range roots {
		ws = append(ws, map[string]any{"path": r, "enabled_at": "2026-09-26T00:00:00Z"})
	}
	b, _ := json.Marshal(map[string]any{"version": 1, "workspaces": ws})
	dir := filepath.Join(home, ".omium", "mark1")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "workspaces.json")
	if err := os.WriteFile(p, b, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

func runPlugin(t *testing.T, home string, dirs map[string]string) []string {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not on PATH: the plugin cannot run")
	}
	var inst []any
	for session, dir := range dirs {
		inst = append(inst, map[string]any{"directory": dir, "worktree": dir, "calls": []any{chatCall(session, "the person's words for "+session)}})
	}
	b, _ := json.Marshal(map[string]any{"instances": inst})
	in := filepath.Join(t.TempDir(), "inputs.json")
	if err := os.WriteFile(in, b, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(node, filepath.Join(fixtureRoot, "harness.mjs"), in, "mark1.js", home) //nolint:gosec // G204: the repo's own harness
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("harness: %v %s", err, out)
	}
	m, _ := filepath.Glob(filepath.Join(home, ".omium", "mark1", "capture", "opencode", "intent", "*.jsonl"))
	var got []string
	for _, p := range m {
		got = append(got, filepath.Base(p))
	}
	slices.Sort(got)
	return got
}

func TestPluginNotesPromptsOnlyInsideEnabledWorkspaces(t *testing.T) {
	base := t.TempDir()
	proj, sub, sibling, other := filepath.Join(base, "proj"), filepath.Join(base, "proj", "pkg"), filepath.Join(base, "proj2"), filepath.Join(base, "other")
	for _, d := range []string{sub, sibling, other} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	dirs := map[string]string{"ses_root": proj, "ses_sub": sub, "ses_sibling": sibling, "ses_other": other, "ses_gone": filepath.Join(base, "missing")}

	home := t.TempDir()
	writeWorkspaces(t, home, 0o600, proj)
	if got := runPlugin(t, home, dirs); !slices.Equal(got, []string{"ses_root.jsonl", "ses_sub.jsonl"}) {
		t.Fatalf("noted %v, want only the enabled workspace's sessions", got)
	}

	if got := runPlugin(t, t.TempDir(), dirs); len(got) != 0 {
		t.Fatalf("no workspaces.json, yet noted %v", got)
	}

	if runtime.GOOS != "windows" {
		loose := t.TempDir()
		writeWorkspaces(t, loose, 0o644, proj)
		if got := runPlugin(t, loose, dirs); len(got) != 0 {
			t.Fatalf("a group-readable workspaces.json is refused as mark1d refuses it, yet noted %v", got)
		}
	}
}

func seedNote(t *testing.T, dir, session, cwd string) string {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"type": "chat.message", "properties": map[string]any{"sessionID": session, "cwd": cwd, "timestamp": "2026-09-26T00:00:00Z", "text": "secret prompt"}})
	p := filepath.Join(dir, session+".jsonl")
	if err := os.WriteFile(p, append(b, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDisableAndOffPurgeNotedPrompts(t *testing.T) {
	state := t.TempDir()
	notes := NotesDir(state)
	if err := os.MkdirAll(notes, 0o700); err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	kept, gone := filepath.Join(base, "kept"), filepath.Join(base, "gone")
	for _, d := range []string{kept, gone} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keep := seedNote(t, notes, "ses_kept", kept)
	drop := seedNote(t, notes, "ses_gone", gone)
	noCwd := seedNote(t, notes, "ses_nocwd", "")

	if err := PruneNotes(state, []string{kept}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("an enabled workspace's prompts were pruned: %v", err)
	}
	for _, p := range []string{drop, noCwd} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("%s outlived its workspace's disable: %v", p, err)
		}
	}

	if r, err := Revert(state); err != nil || r.Kind != "not-provisioned" {
		t.Fatalf("revert: %+v %v", r, err)
	}
	if _, err := os.Stat(notes); !os.IsNotExist(err) {
		t.Fatalf("`mark1 off` left the noted prompts on disk: %v", err)
	}
}
