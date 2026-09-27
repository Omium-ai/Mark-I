package doctor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTaskDiffCheck(t *testing.T) {
	dir := t.TempDir()
	if c := taskDiffCheck(dir); !c.OK || c.Name != "task_diff" {
		t.Fatalf("no status file is not a failure: %+v", c)
	}
	write := func(body string) {
		if err := os.MkdirAll(filepath.Join(dir, "anchors"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "anchors", "diff_status.json"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"version":1,"worktrees":{"/w/a":{"via":"sandbox"},"/w/b":{"via":"direct","detail":"sandbox unavailable"},"/w/c":{"via":"sandbox","abstain":"no_change"}}}`)
	if c := taskDiffCheck(dir); !c.OK || !strings.Contains(c.Detail, "/w/b: read outside the sandbox (sandbox unavailable)") || !strings.Contains(c.Detail, "/w/c: no_change") {
		t.Fatalf("healthy and fallback reads: %+v", c)
	}
	write(`{"version":1,"worktrees":{"/w/a":{"via":"","abstain":"not_a_repository"}}}`)
	if c := taskDiffCheck(dir); c.OK || !strings.Contains(c.Detail, "not_a_repository") {
		t.Fatalf("a worktree with no readable diff must fail doctor: %+v", c)
	}
	write(`{"version":1,"worktrees":{"/w/a":{"via":"","abstain":"unsafe_git_dir","detail":"gitdir outside a repository"}}}`)
	if c := taskDiffCheck(dir); c.OK || !strings.Contains(c.Detail, "unsafe_git_dir") {
		t.Fatalf("a refused gitfile must fail doctor: %+v", c)
	}
}
