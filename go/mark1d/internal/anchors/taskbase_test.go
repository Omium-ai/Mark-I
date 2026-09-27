package anchors

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

func openedRunner(t *testing.T, repo string, task [16]byte, state string) *Runner {
	t.Helper()
	r := NewRunner(NewSandbox(t.TempDir()), &fakeEmitter{}, nil, false)
	r.StateDir = state
	r.OpenTask(task, repo)
	if _, ok := r.baseFor(context.Background(), task); !ok {
		t.Fatal("the open-time HEAD was not recorded")
	}
	return r
}

// TestTaskDiffForCoversWhatTheAgentCommitted (FR-VERIFY-021): a task whose agent commits its own work still diffs from the HEAD it opened at — committed, staged, unstaged and untracked alike — and a daemon restart keeps that base.
func TestTaskDiffForCoversWhatTheAgentCommitted(t *testing.T) {
	ctx := context.Background()
	repo := fixtureRepo(t)
	task := [16]byte{1}
	state := t.TempDir()
	r := openedRunner(t, repo, task, state)
	write(t, filepath.Join(repo, "app.py"), "def f():\n    return 2  # noqa\n")
	realGit(t, repo, "commit", "-q", "-am", "agent commit")
	r.OpenTask(task, repo) // an R3 reopen keeps the first base
	write(t, filepath.Join(repo, "staged.py"), "s = 1\n")
	realGit(t, repo, "add", "staged.py")
	write(t, filepath.Join(repo, "loose.py"), "l = 1\n")
	if got := string(r.TaskDiff(ctx, repo)); strings.Contains(got, "return 2") {
		t.Fatalf("HEAD-based diff unexpectedly carries the committed change:\n%s", got)
	}
	for _, rr := range []*Runner{r, NewRunner(NewSandbox(t.TempDir()), &fakeEmitter{}, nil, false)} {
		rr.StateDir = state
		got := string(rr.TaskDiffFor(ctx, task, repo))
		for _, want := range []string{"+    return 2  # noqa", "diff --git a/staged.py b/staged.py", "diff --git a/loose.py b/loose.py"} {
			if !strings.Contains(got, want) {
				t.Fatalf("task diff lacks %q:\n%s", want, got)
			}
		}
	}
	d := r.diff(ctx, repo, task)
	if d.delta != 1 || !d.touchedSet()["app.py"] {
		t.Fatalf("anchor facts from the base: delta %d touched %v", d.delta, d.touchedSet())
	}
}

// TestTaskDiffForMovedHead (FR-VERIFY-021): a reset to an older commit diffs from the merge-base; an orphan history, a garbage-collected base, a base from another repository and a base whose HEAD is gone all abstain as base_unreachable — never a silently wrong diff.
func TestTaskDiffForMovedHead(t *testing.T) {
	ctx := context.Background()
	unreachable := func(name string, r *Runner, task [16]byte, wt string) {
		t.Helper()
		if got := r.TaskDiffFor(ctx, task, wt); got != nil {
			t.Fatalf("%s: diff %q, want nil", name, got)
		}
		if st := diffStatus(t, r.StateDir, wt); st.Abstain != DiffBaseUnreachable {
			t.Fatalf("%s: status %+v, want base_unreachable", name, st)
		}
	}

	reset := fixtureRepo(t)
	write(t, filepath.Join(reset, "app.py"), "def f():\n    return 5\n")
	realGit(t, reset, "commit", "-q", "-am", "second")
	r := openedRunner(t, reset, [16]byte{2}, t.TempDir())
	realGit(t, reset, "reset", "-q", "--hard", "HEAD~1")
	write(t, filepath.Join(reset, "note.md"), "after reset\n")
	if got := string(r.TaskDiffFor(ctx, [16]byte{2}, reset)); !strings.Contains(got, "diff --git a/note.md b/note.md") {
		t.Fatalf("reset: no diff from the merge-base:\n%s", got)
	}

	orphan := fixtureRepo(t)
	r = openedRunner(t, orphan, [16]byte{3}, t.TempDir())
	realGit(t, orphan, "checkout", "-q", "--orphan", "other")
	realGit(t, orphan, "commit", "-q", "-m", "unrelated")
	unreachable("orphan history", r, [16]byte{3}, orphan)

	gcd := fixtureRepo(t)
	write(t, filepath.Join(gcd, "app.py"), "def f():\n    return 7\n")
	realGit(t, gcd, "commit", "-q", "-am", "doomed")
	r = openedRunner(t, gcd, [16]byte{4}, t.TempDir())
	realGit(t, gcd, "reset", "-q", "--hard", "HEAD~1")
	realGit(t, gcd, "reflog", "expire", "--expire=now", "--all")
	realGit(t, gcd, "gc", "-q", "--prune=now")
	unreachable("garbage-collected base", r, [16]byte{4}, gcd)

	other := fixtureRepo(t)
	unreachable("another repository", r, [16]byte{4}, other)

	unbornNow := fixtureRepo(t)
	r = openedRunner(t, unbornNow, [16]byte{5}, t.TempDir())
	realGit(t, unbornNow, "checkout", "-q", "--orphan", "empty")
	unreachable("HEAD gone unborn", r, [16]byte{5}, unbornNow)
}

// TestTaskDiffForFirstCommit (FR-VERIFY-021): a task opened in a repository with no commit, whose agent makes the first one, shows every file as new against the empty tree.
func TestTaskDiffForFirstCommit(t *testing.T) {
	repo := canonTemp(t)
	realGit(t, repo, "init", "-q", "-b", "main", ".")
	r := openedRunner(t, repo, [16]byte{6}, t.TempDir())
	if b, _ := r.baseFor(context.Background(), [16]byte{6}); b.Head != "" {
		t.Fatalf("an unborn repository recorded HEAD %q", b.Head)
	}
	write(t, filepath.Join(repo, "first.py"), "a = 1\n")
	realGit(t, repo, "add", "first.py")
	realGit(t, repo, "commit", "-q", "-m", "first")
	write(t, filepath.Join(repo, "later.py"), "b = 2\n")
	got := string(r.TaskDiffFor(context.Background(), [16]byte{6}, repo))
	if !strings.Contains(got, "diff --git a/first.py b/first.py\nnew file mode 100644\n") || !strings.Contains(got, "diff --git a/later.py b/later.py\nnew file mode 100644\n") {
		t.Fatalf("first-commit task diff:\n%s", got)
	}
}

// TestObserveRecordsTheBaseAtTaskOpen (FR-VERIFY-021): a TaskOpen on the event tap records its base in the session's repository; other events record nothing.
func TestObserveRecordsTheBaseAtTaskOpen(t *testing.T) {
	repo := fixtureRepo(t)
	r := NewRunner(NewSandbox(t.TempDir()), &fakeEmitter{}, nil, false)
	session, task := [16]byte{9}, [16]byte{7}
	r.RepoFor = func(s [16]byte) string {
		if s == session {
			return repo
		}
		return ""
	}
	r.Observe(&m1pv1.Event{SessionId: session[:], TaskId: task[:], Body: &m1pv1.Event_TaskClose{TaskClose: &m1pv1.TaskClose{}}})
	if _, ok := r.baseFor(context.Background(), task); ok {
		t.Fatal("a TaskClose recorded a base")
	}
	r.Observe(&m1pv1.Event{SessionId: session[:], TaskId: task[:], Body: &m1pv1.Event_TaskOpen{TaskOpen: &m1pv1.TaskOpen{}}})
	if b, ok := r.baseFor(context.Background(), task); !ok || b.Top != repo || len(b.Head) != 40 {
		t.Fatalf("base %+v ok=%v", b, ok)
	}
}
