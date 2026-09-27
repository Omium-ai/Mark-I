package anchors

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// realGit runs the host's git for fixture setup and oracles, with no system or user config in play; skips without git.
func realGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("no git on PATH")
	}
	home := t.TempDir()
	cmd := exec.Command(git, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "HOME="+home, "XDG_CONFIG_HOME="+home, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, stderr.Bytes())
	}
	return string(out)
}

func write(t *testing.T, p, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

// fixtureRepo is a committed repository with one tracked file.
func fixtureRepo(t *testing.T) string {
	t.Helper()
	repo := canonTemp(t)
	realGit(t, repo, "init", "-q", "-b", "main", ".")
	write(t, filepath.Join(repo, "app.py"), "def f():\n    return 1\n")
	realGit(t, repo, "add", "app.py")
	realGit(t, repo, "commit", "-q", "-m", "init")
	return repo
}

// TestNewFileSectionMatchesGit (FR-VERIFY-004): an untracked file renders byte for byte as `git diff` shows it once intent-to-add, for every content shape git distinguishes.
func TestNewFileSectionMatchesGit(t *testing.T) {
	repo := fixtureRepo(t)
	files := map[string]string{
		"multi.py":       "a = 1\nb = 2\nc = 3\n",
		"one.txt":        "single\n",
		"no_eol.txt":     "first\nlast",
		"empty.txt":      "",
		"blob.bin":       "PK\x00\x03binary",
		"dir/nested.go":  "package x\n",
		"sp ace.md":      "# t\n",
		"quo\"te.txt":    "q\n",
		"caf\u00e9.txt":  "accent\n",
		"crlf.txt":       "one\r\ntwo\r\n",
		"tab\there.json": "{}\n",
	}
	if runtime.GOOS == "windows" {
		delete(files, "quo\"te.txt")
		delete(files, "tab\there.json")
	}
	var names []string
	for n, c := range files {
		write(t, filepath.Join(repo, filepath.FromSlash(n)), c)
		names = append(names, n)
	}
	if runtime.GOOS != "windows" {
		write(t, filepath.Join(repo, "run.sh"), "#!/bin/sh\necho hi\n")
		if err := os.Chmod(filepath.Join(repo, "run.sh"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("multi.py", filepath.Join(repo, "link.py")); err != nil {
			t.Fatal(err)
		}
		names = append(names, "run.sh", "link.py")
	}
	slices.Sort(names)
	root, err := os.OpenRoot(repo)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	var got []byte
	for _, n := range names {
		got = append(got, newFileSection(root, filepath.FromSlash(n), n)...)
	}
	realGit(t, repo, "add", "-N", ".")
	want := realGit(t, repo, append(slices.Clone(gitHardening[1:]), "diff", "--no-color", "--no-ext-diff", "--no-textconv")...)
	if string(got) != want {
		t.Fatalf("rendered:\n%s\ngit:\n%s", got, want)
	}
}

// TestFilterOverrides (FR-VERIFY-004): every filter driver the config names is emptied, dotted subsections survive, and a name `-c` would misparse refuses the read.
func TestFilterOverrides(t *testing.T) {
	list := "core.bare=false\x00filter.lfs.clean\ngit-lfs clean -- %f\x00filter.lfs.process\ngit-lfs filter-process\x00filter.a.b.smudge\nx\x00filter.lfs.required\x00user.name\nme\x00"
	got, ok := filterOverrides([]byte(list))
	want := []string{"-c", "filter.lfs.clean=", "-c", "filter.lfs.smudge=", "-c", "filter.lfs.process=", "-c", "filter.lfs.required=false",
		"-c", "filter.a.b.clean=", "-c", "filter.a.b.smudge=", "-c", "filter.a.b.process=", "-c", "filter.a.b.required=false"}
	if !ok || !slices.Equal(got, want) {
		t.Fatalf("overrides %q ok=%v", got, ok)
	}
	if got, ok := filterOverrides([]byte("core.bare=false\x00")); !ok || got != nil {
		t.Fatalf("no drivers: %q ok=%v", got, ok)
	}
	if _, ok := filterOverrides([]byte("filter.a=b.clean\nevil\x00")); ok {
		t.Fatal("a driver name with '=' was accepted; -c would read a different key")
	}
	for _, flag := range []string{"--no-optional-locks", "core.fsmonitor=false", "core.hooksPath=/dev/null", "protocol.allow=never", "log.showSignature=false", "diff.relative=false", "diff.noprefix=false"} {
		if !slices.Contains(gitHardening, flag) {
			t.Errorf("gitHardening lost %s", flag)
		}
	}
	if env := gitEnv("/usr/bin/git"); env["GIT_CONFIG_NOSYSTEM"] != "1" || env["GIT_NO_LAZY_FETCH"] != "1" || env["GIT_ALLOW_PROTOCOL"] != "mark1-none" || len(env) != 6 {
		t.Errorf("gitEnv %v", env)
	}
}

func diffStatus(t *testing.T, state, worktree string) DiffState {
	t.Helper()
	b, err := os.ReadFile(DiffStatusPath(state))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Worktrees map[string]DiffState `json:"worktrees"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return f.Worktrees[worktree]
}

func indexHash(t *testing.T, repo string) [32]byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repo, ".git", "index"))
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(b)
}

// TestTaskDiffUntrackedAndHardened (FR-VERIFY-004): the real sandbox on this OS answers the task diff with the tracked change AND the new files, honours .gitignore and .mark1ignore, runs no repository-planted filter or fsmonitor, and leaves the user's index untouched.
func TestTaskDiffUntrackedAndHardened(t *testing.T) {
	repo := fixtureRepo(t)
	pwned := filepath.Join(t.TempDir(), "PWNED")
	write(t, filepath.Join(repo, ".gitignore"), "build/\n")
	realGit(t, repo, "add", ".gitignore")
	realGit(t, repo, "commit", "-q", "-m", "ignore")
	write(t, filepath.Join(repo, ".git", "info", "attributes"), "* filter=evil\n")
	realGit(t, repo, "config", "filter.evil.clean", "sh -c 'touch "+filepath.ToSlash(pwned)+"; echo FORGED'")
	realGit(t, repo, "config", "filter.evil.required", "true")
	realGit(t, repo, "config", "core.fsmonitor", "sh -c 'touch "+filepath.ToSlash(pwned)+"'")
	write(t, filepath.Join(repo, ".mark1ignore"), "private/\n")
	write(t, filepath.Join(repo, "app.py"), "def f():\n    return 2\n")
	write(t, filepath.Join(repo, "new_mod.py"), "def g():\n    return 3\n")
	write(t, filepath.Join(repo, "build", "out.o"), "ignored by git\n")
	write(t, filepath.Join(repo, "private", "keys.txt"), "ignored by mark1\n")
	before := indexHash(t, repo)

	r := NewRunner(NewSandbox(t.TempDir()), &fakeEmitter{}, nil, false)
	r.StateDir = t.TempDir()
	got := string(r.TaskDiff(context.Background(), repo))
	st := diffStatus(t, r.StateDir, repo)
	t.Logf("via=%s detail=%s", st.Via, st.Detail)
	for _, want := range []string{"diff --git a/app.py b/app.py", "+    return 2", "diff --git a/new_mod.py b/new_mod.py\nnew file mode 100644\n", "+def g():", "diff --git a/.mark1ignore b/.mark1ignore"} {
		if !strings.Contains(got, want) {
			t.Fatalf("task diff lacks %q:\n%s", want, got)
		}
	}
	for _, not := range []string{"build/out.o", "private/keys.txt", "FORGED"} {
		if strings.Contains(got, not) {
			t.Fatalf("task diff carries %q:\n%s", not, got)
		}
	}
	if _, err := os.Stat(pwned); err == nil {
		t.Fatal("a repository-planted filter/fsmonitor command ran during the read")
	}
	if indexHash(t, repo) != before {
		t.Fatal("the read rewrote the user's index")
	}
	if st.Abstain != "" {
		t.Fatalf("status %+v", st)
	}
	if st.Via != "sandbox" {
		if os.Getenv("M1_REQUIRE_SANDBOX") == "1" {
			t.Fatalf("git was not hosted by the sandbox on %s (M1_REQUIRE_SANDBOX=1): %s", runtime.GOOS, st.Detail)
		}
		t.Logf("git answered via %s: %s", st.Via, st.Detail)
	}
}

// TestTaskDiffSubdirAndLinkedWorktree (FR-VERIFY-004): a worktree below the repository top and a `git worktree add` checkout both read, which on Windows needs the git dirs granted (gitReadRoots).
func TestTaskDiffSubdirAndLinkedWorktree(t *testing.T) {
	repo := fixtureRepo(t)
	write(t, filepath.Join(repo, "svc", "main.go"), "package main\n")
	realGit(t, repo, "add", ".")
	realGit(t, repo, "commit", "-q", "-m", "svc")
	linked := filepath.Join(canonTemp(t), "wt")
	realGit(t, repo, "worktree", "add", "-q", linked)
	write(t, filepath.Join(repo, "svc", "extra.go"), "package main\n\nfunc extra() {}\n")
	write(t, filepath.Join(repo, "outside.txt"), "not under svc\n")
	write(t, filepath.Join(linked, "app.py"), "def f():\n    return 9\n")

	r := NewRunner(NewSandbox(t.TempDir()), &fakeEmitter{}, nil, false)
	r.StateDir = t.TempDir()
	sub := filepath.Join(repo, "svc")
	got := string(r.TaskDiff(context.Background(), sub))
	if !strings.Contains(got, "diff --git a/svc/extra.go b/svc/extra.go") || strings.Contains(got, "outside.txt") {
		t.Fatalf("subdir worktree diff (%+v):\n%s", diffStatus(t, r.StateDir, sub), got)
	}
	if got := string(r.TaskDiff(context.Background(), linked)); !strings.Contains(got, "+    return 9") {
		t.Fatalf("linked worktree diff (%+v):\n%s", diffStatus(t, r.StateDir, linked), got)
	}
	if roots, _, ok := gitReadRoots(linked); !ok || len(roots) != 2 || !strings.HasSuffix(filepath.ToSlash(roots[1]), ".git") {
		t.Fatalf("linked worktree read roots %v, want its git dir and the common dir", roots)
	}
	for _, wt := range []string{sub, linked} {
		if st := diffStatus(t, r.StateDir, wt); st.Via != "sandbox" && os.Getenv("M1_REQUIRE_SANDBOX") == "1" {
			t.Fatalf("%s read via %q (M1_REQUIRE_SANDBOX=1): %s", wt, st.Via, st.Detail)
		}
	}
}

// TestTaskDiffFallsBackOutsideARefusingSandbox (FR-VERIFY-004): a sandbox that cannot host git (no userns, no sandbox-exec, a refused AppContainer) or whose git cannot read the repository still yields the diff, through the 10 §7.5 direct read, and says so.
func TestTaskDiffFallsBackOutsideARefusingSandbox(t *testing.T) {
	repo := fixtureRepo(t)
	write(t, filepath.Join(repo, "new.py"), "x = 1\n")
	for name, sb := range map[string]*fakeSandbox{
		"refused":       {err: ErrSandboxUnavailable},
		"cannot read":   {res: RunResult{ExitCode: 128, Stderr: []byte("fatal: not a git repository")}},
		"setup refused": {err: errors.New("anchors: sandbox setup failed: landlock")},
	} {
		r := NewRunner(sb, &fakeEmitter{}, nil, false)
		r.StateDir = t.TempDir()
		if got := r.TaskDiff(context.Background(), repo); !bytes.Contains(got, []byte("diff --git a/new.py b/new.py")) {
			t.Fatalf("%s: no diff through the fallback: %q", name, got)
		}
		if st := diffStatus(t, r.StateDir, repo); st.Via != "direct" || st.Detail == "" || st.Abstain != "" {
			t.Fatalf("%s: status %+v, want via=direct with the sandbox's reason", name, st)
		}
		if len(sb.specs) != 3 || sb.specs[0].RequireFSConfined {
			t.Fatalf("%s: %d sandbox attempts, want config/status/diff each tried in the sandbox first, unconfined-write allowed", name, len(sb.specs))
		}
	}
}

// TestTaskDiffAbstainsWithAReason (FR-VERIFY-004): every empty answer names its cause in diff_status.json — never a silent nil.
func TestTaskDiffAbstainsWithAReason(t *testing.T) {
	ctx := context.Background()
	check := func(name, wt string, want DiffAbstain) {
		t.Helper()
		r := NewRunner(NewSandbox(t.TempDir()), &fakeEmitter{}, nil, false)
		r.StateDir = t.TempDir()
		if got := r.TaskDiff(ctx, wt); got != nil {
			t.Fatalf("%s: diff %q, want nil", name, got)
		}
		if st := diffStatus(t, r.StateDir, wt); st.Abstain != want {
			t.Fatalf("%s: status %+v, want abstain %s", name, st, want)
		}
	}
	clean := fixtureRepo(t)
	check("clean tree", clean, DiffNoChange)
	check("not a repository", canonTemp(t), DiffNoRepo)
	flood := fixtureRepo(t)
	for i := range maxNewFiles + 1 {
		write(t, filepath.Join(flood, "gen", "f"+strconv.Itoa(i)), "x\n")
	}
	check("vendored flood", flood, DiffTooLarge)
	t.Setenv("PATH", t.TempDir())
	check("no git", clean, DiffNoGit)
}

// TestTaskDiffUnbornHead (FR-VERIFY-004): a repository with no commit yet shows every staged and untracked file as new.
func TestTaskDiffUnbornHead(t *testing.T) {
	repo := canonTemp(t)
	realGit(t, repo, "init", "-q", "-b", "main", ".")
	write(t, filepath.Join(repo, "staged.py"), "a = 1\n")
	realGit(t, repo, "add", "staged.py")
	write(t, filepath.Join(repo, "loose.py"), "b = 2\n")
	r := NewRunner(NewSandbox(t.TempDir()), &fakeEmitter{}, nil, false)
	got := string(r.TaskDiff(context.Background(), repo))
	if !strings.Contains(got, "diff --git a/loose.py b/loose.py\nnew file mode 100644\n") || !strings.Contains(got, "diff --git a/staged.py b/staged.py\nnew file mode 100644\n") {
		t.Fatalf("unborn HEAD diff:\n%s", got)
	}
}
