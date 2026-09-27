package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDiffRepoIsTheSessionsRepository (FR-VERIFY-021): in an enabled folder of repositories a session diffs the one it works in; a root inside a repository, or a cwd in no repository, diffs the enabled root.
func TestDiffRepoIsTheSessionsRepository(t *testing.T) {
	folder := realPath(t.TempDir())
	svc := filepath.Join(folder, "svc")
	for _, d := range []string{filepath.Join(svc, ".git"), filepath.Join(svc, "pkg"), filepath.Join(folder, "notes")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for cwd, want := range map[string]string{
		filepath.Join(svc, "pkg"):      svc,
		svc:                            svc,
		filepath.Join(folder, "notes"): folder,
		folder:                         folder,
	} {
		if got := diffRepo(folder, cwd); got != want {
			t.Errorf("diffRepo(%s) = %s, want %s", cwd, got, want)
		}
	}
	if got := diffRepo(filepath.Join(svc, "pkg"), filepath.Join(svc, "pkg")); got != filepath.Join(svc, "pkg") {
		t.Errorf("a root inside a repository diffs %s, want the root", got)
	}
}
