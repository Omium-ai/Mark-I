package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLogFileRotatesOncePastEightMiB(t *testing.T) {
	state := t.TempDir()
	f, err := openLogFile(state)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	// grown on disk, not via Truncate on the append handle (Windows refuses that)
	if err := os.WriteFile(filepath.Join(state, "logs", "mark1d.log"), make([]byte, 9<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openLogFile(state); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(state, "logs", "mark1d.log.1")); err != nil {
		t.Fatal("the full log was not rotated aside:", err)
	}
	if st, _ := os.Stat(filepath.Join(state, "logs", "mark1d.log")); st.Size() != 0 {
		t.Fatalf("fresh log has %d bytes", st.Size())
	}
}

// A hook's cwd attributes the session to the deepest enabled root it sits in; outside every root it stays unattributed.
func TestEnabledRootForPicksTheDeepestEnabledRoot(t *testing.T) {
	state := t.TempDir()
	outer := filepath.Join(t.TempDir(), "repo")
	inner := filepath.Join(outer, "packages", "web")
	if err := os.MkdirAll(filepath.Join(inner, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "workspaces.json"), []byte(`{"version":1,"workspaces":[{"path":"`+filepath.ToSlash(outer)+`"},{"path":"`+filepath.ToSlash(inner)+`"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if root, ok := enabledRootFor(state, "", filepath.Join(inner, "src")); !ok || root != mustReal(t, inner) {
		t.Fatalf("inner cwd → %q (%v), want %q", root, ok, inner)
	}
	if root, ok := enabledRootFor(state, "", filepath.Join(outer, "docs")); !ok || root != mustReal(t, outer) {
		t.Fatalf("outer cwd → %q (%v), want %q", root, ok, outer)
	}
	if root, ok := enabledRootFor(state, "", t.TempDir()); ok {
		t.Fatalf("a cwd outside every root attributed to %q", root)
	}
}

func mustReal(t *testing.T, p string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
