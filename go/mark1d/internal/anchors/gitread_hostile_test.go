package anchors

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// submoduleExploitRepo is the review's H7 reproduction: a repository whose submodule's own config names a clean filter every file in it uses, and a stat-dirty file in that submodule, so a git read that recurses runs the filter.
func submoduleExploitRepo(t *testing.T) (repo, pwned string) {
	t.Helper()
	src := fixtureRepo(t)
	repo = fixtureRepo(t)
	realGit(t, repo, "-c", "protocol.file.allow=always", "submodule", "add", "-q", src, "sub")
	realGit(t, repo, "commit", "-q", "-m", "sub")
	pwned = filepath.Join(repo, "PWNED") // inside the worktree: the one place a sandboxed run may write
	realGit(t, filepath.Join(repo, "sub"), "config", "filter.evil.clean", "sh -c 'touch "+filepath.ToSlash(pwned)+"; cat'")
	write(t, filepath.Join(repo, "sub", ".gitattributes"), "* filter=evil\n")
	later := time.Now().Add(time.Hour)
	if err := os.Chtimes(filepath.Join(repo, "sub", "app.py"), later, later); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(repo, "app.py"), "def f():\n    return 2\n")
	return repo, pwned
}

// TestSubmoduleFilterNeverRuns (H7): the submodule's filter command never runs during the hardened read, hosted by the platform sandbox or by the direct fallback.
func TestSubmoduleFilterNeverRuns(t *testing.T) {
	for name, sb := range bothModes(t) {
		t.Run(name, func(t *testing.T) {
			repo, pwned := submoduleExploitRepo(t)
			r := NewRunner(sb, &fakeEmitter{}, nil, false)
			r.StateDir = t.TempDir()
			got := r.TaskDiff(context.Background(), repo)
			st := diffStatus(t, r.StateDir, repo)
			t.Logf("via=%s abstain=%s detail=%s", st.Via, st.Abstain, st.Detail)
			for _, args := range [][]string{{"status", "--porcelain"}, {"log", "-p", "-1", "HEAD"}, {"diff", "HEAD"}} {
				_, _ = r.Git(context.Background(), repo, args...)
			}
			if _, err := os.Stat(pwned); err == nil {
				t.Fatal("the submodule's filter command ran during the read")
			}
			if len(got) == 0 {
				t.Fatalf("no diff: %+v", st)
			}
		})
	}
}

// bothModes is the platform sandbox and a refusing one that forces the 10 §7.5 direct read.
func bothModes(t *testing.T) map[string]Sandbox {
	return map[string]Sandbox{"sandbox": NewSandbox(t.TempDir()), "direct": &fakeSandbox{err: ErrSandboxUnavailable}}
}

// TestRepoConfigNeverRunsAProgram (H7): every repository-settable key that names a program git could run is planted in .git/config; a full task read, status, log -p and blame run none of them, sandboxed or direct.
func TestRepoConfigNeverRunsAProgram(t *testing.T) {
	for mode, sb := range bothModes(t) {
		t.Run(mode, func(t *testing.T) {
			repo := fixtureRepo(t)
			pwned := filepath.Join(repo, "PWNED")
			touch := "sh -c 'touch " + filepath.ToSlash(pwned) + "; cat'"
			hooks := filepath.Join(repo, "hooks")
			for _, h := range []string{"post-index-change", "reference-transaction", "fsmonitor-watchman"} {
				write(t, filepath.Join(hooks, h), "#!/bin/sh\ntouch "+filepath.ToSlash(pwned)+"\n")
				if err := os.Chmod(filepath.Join(hooks, h), 0o755); err != nil { //nolint:gosec // G302: a hook must be executable to be a threat
					t.Fatal(err)
				}
			}
			include := filepath.Join(repo, "inc.cfg")
			write(t, include, "[filter \"inc\"]\n\tclean = "+touch+"\n\tsmudge = "+touch+"\n\trequired = true\n")
			write(t, filepath.Join(repo, ".git", "info", "attributes"), "* filter=evil diff=evil\n*.py filter=inc\n")
			for k, v := range map[string]string{
				"core.fsmonitor": touch, "core.hooksPath": filepath.ToSlash(hooks), "core.pager": touch, "pager.diff": touch, "pager.log": touch, "pager.blame": touch, "pager.status": "true",
				"diff.external": touch, "diff.evil.command": touch, "diff.evil.textconv": touch, "diff.evil.cachetextconv": "true",
				"filter.evil.clean": touch, "filter.evil.smudge": touch, "filter.evil.process": touch, "filter.evil.required": "true",
				"include.path": filepath.ToSlash(include), "core.attributesFile": filepath.ToSlash(filepath.Join(repo, ".git", "info", "attributes")),
				"core.sshCommand": touch, "core.askPass": touch, "credential.helper": "!" + touch, "core.alternateRefsCommand": touch, "uploadpack.packObjectsHook": touch,
				"gpg.program": touch, "log.showSignature": "true", "core.editor": touch, "sequence.editor": touch, "diff.noprefix": "true", "diff.mnemonicPrefix": "true",
				"color.ui": "always", "status.submoduleSummary": "true", "submodule.recurse": "true", "protocol.allow": "always", "protocol.ext.allow": "always",
			} {
				realGit(t, repo, "config", k, v)
			}
			realGit(t, repo, "-c", "filter.evil.clean=cat", "-c", "filter.evil.smudge=cat", "-c", "filter.inc.clean=cat", "-c", "filter.inc.smudge=cat", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "commit", "-q", "--allow-empty", "-m", "second")
			write(t, filepath.Join(repo, "app.py"), "def f():\n    return 7\n")
			r := NewRunner(sb, &fakeEmitter{}, nil, false)
			r.StateDir = t.TempDir()
			got := string(r.TaskDiff(context.Background(), repo))
			if !strings.Contains(got, "diff --git a/app.py b/app.py") || strings.Contains(got, "\x1b[") {
				t.Fatalf("task diff (%+v):\n%s", diffStatus(t, r.StateDir, repo), got)
			}
			for _, args := range [][]string{{"status", "--porcelain"}, {"log", "-p", "-2", "HEAD"}, {"blame", "--line-porcelain", "HEAD", "--", "app.py"}, {"rev-parse", "HEAD"}} {
				if _, ok := r.Git(context.Background(), repo, args...); !ok {
					t.Fatalf("git %v failed", args)
				}
			}
			if _, err := os.Stat(pwned); err == nil {
				t.Fatal("a program the repository's config names ran during the read")
			}
		})
	}
}

// partialCloneRepo is a partial clone missing the blob a task diff needs, whose promisor remote is an ext:: command the repository itself allowed.
func partialCloneRepo(t *testing.T) (repo, pwned string) {
	t.Helper()
	repo = fixtureRepo(t)
	pwned = filepath.Join(repo, "PWNED")
	blob := strings.TrimSpace(realGit(t, repo, "rev-parse", "HEAD:app.py"))
	if err := os.Remove(filepath.Join(repo, ".git", "objects", blob[:2], blob[2:])); err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{
		"core.repositoryFormatVersion": "1", "extensions.partialClone": "origin", "remote.origin.promisor": "true",
		"remote.origin.url": "ext::sh -c touch% " + filepath.ToSlash(pwned), "protocol.ext.allow": "always",
	} {
		realGit(t, repo, "config", k, v)
	}
	write(t, filepath.Join(repo, "app.py"), "changed\n")
	return repo, pwned
}

// TestLazyFetchTransportRefused (H7): a partial clone's lazy fetch through a repository-allowed ext:: remote (protocol.ext.allow=always outranks -c protocol.allow=never) never runs, sandboxed or direct; and GIT_ALLOW_PROTOCOL alone refuses it on a git that predates GIT_NO_LAZY_FETCH.
func TestLazyFetchTransportRefused(t *testing.T) {
	for mode, sb := range bothModes(t) {
		t.Run(mode, func(t *testing.T) {
			repo, pwned := partialCloneRepo(t)
			r := NewRunner(sb, &fakeEmitter{}, nil, false)
			r.StateDir = t.TempDir()
			_ = r.TaskDiff(context.Background(), repo)
			if _, err := os.Stat(pwned); err == nil {
				t.Fatal("the promisor remote's ext:: command ran")
			}
		})
	}
	t.Run("without GIT_NO_LAZY_FETCH", func(t *testing.T) {
		repo, pwned := partialCloneRepo(t)
		git, err := gitBinary()
		if err != nil {
			t.Skip(err)
		}
		env := gitEnv(git)
		delete(env, "GIT_NO_LAZY_FETCH")
		g := gitDirect(context.Background(), append(append([]string{git}, gitHardening...), gitSubcommand([]string{"diff", "HEAD"})...), env, repo)
		if _, err := os.Stat(pwned); err == nil || g.abstain == "" {
			t.Fatalf("the ext:: command ran or the read answered: %+v", g)
		}
	})
}

// TestCoreWorktreeCannotRedirectTheRead (H7): core.worktree in the repository's config does not move the read to another directory's files.
func TestCoreWorktreeCannotRedirectTheRead(t *testing.T) {
	for mode, sb := range bothModes(t) {
		t.Run(mode, func(t *testing.T) {
			repo := fixtureRepo(t)
			elsewhere := canonTemp(t)
			write(t, filepath.Join(elsewhere, "app.py"), "SECRET-ELSEWHERE\n")
			realGit(t, repo, "config", "core.worktree", elsewhere)
			write(t, filepath.Join(repo, "app.py"), "def f():\n    return 3\n")
			r := NewRunner(sb, &fakeEmitter{}, nil, false)
			r.StateDir = t.TempDir()
			got := string(r.TaskDiff(context.Background(), repo))
			if strings.Contains(got, "SECRET-ELSEWHERE") || !strings.Contains(got, "+    return 3") {
				t.Fatalf("read left the repository (%+v):\n%s", diffStatus(t, r.StateDir, repo), got)
			}
		})
	}
}

// TestHostileGitfileIsNeverRead (H7/M8): a .git file naming another repository's git dir, a .git dir with a commondir of its own, or a worktree dir whose back-link names someone else abstains unsafe_git_dir in both modes and grants nothing.
func TestHostileGitfileIsNeverRead(t *testing.T) {
	private := fixtureRepo(t)
	write(t, filepath.Join(private, "secret.txt"), "PRIVATE-CONTENT\n")
	realGit(t, private, "add", "secret.txt")
	realGit(t, private, "commit", "-q", "-m", "secret")
	other := fixtureRepo(t)
	linked := filepath.Join(canonTemp(t), "wt")
	realGit(t, other, "worktree", "add", "-q", linked)
	cases := map[string]func(t *testing.T) string{
		"gitfile to another repo": func(t *testing.T) string {
			d := canonTemp(t)
			write(t, filepath.Join(d, ".git"), "gitdir: "+filepath.Join(private, ".git")+"\n")
			return d
		},
		"commondir in a .git dir": func(t *testing.T) string {
			d := fixtureRepo(t)
			write(t, filepath.Join(d, ".git", "commondir"), filepath.Join(private, ".git")+"\n")
			return d
		},
		"stolen worktree dir": func(t *testing.T) string {
			d := canonTemp(t)
			wts, _ := filepath.Glob(filepath.Join(other, ".git", "worktrees", "*"))
			write(t, filepath.Join(d, ".git"), "gitdir: "+wts[0]+"\n")
			return d
		},
		"modules dir of a repo that is not an ancestor": func(t *testing.T) string {
			d := canonTemp(t)
			mod := filepath.Join(private, ".git", "modules", "x")
			if err := os.MkdirAll(mod, 0o700); err != nil {
				t.Fatal(err)
			}
			write(t, filepath.Join(d, ".git"), "gitdir: "+mod+"\n")
			return d
		},
	}
	for name, mk := range cases {
		for mode, sb := range bothModes(t) {
			t.Run(name+"/"+mode, func(t *testing.T) {
				wt := mk(t)
				if _, _, ok := gitReadRoots(wt); ok {
					t.Fatal("hostile git dir validated")
				}
				r := NewRunner(sb, &fakeEmitter{}, nil, false)
				r.StateDir = t.TempDir()
				if got := r.TaskDiff(context.Background(), wt); got != nil {
					t.Fatalf("read through a hostile git dir:\n%s", got)
				}
				if st := diffStatus(t, r.StateDir, wt); st.Abstain != DiffUnsafeGitDir {
					t.Fatalf("status %+v", st)
				}
			})
		}
	}
	if roots, _, ok := gitReadRoots(linked); !ok || len(roots) != 2 {
		t.Fatalf("a real linked worktree: %v %v", roots, ok)
	}
	repo, _ := submoduleExploitRepo(t)
	if roots, _, ok := gitReadRoots(filepath.Join(repo, "sub")); !ok || len(roots) != 1 || filepath.Base(roots[0]) != "sub" {
		t.Fatalf("a real submodule: %v %v", roots, ok)
	}
}

// TestEmbeddedBareRepoCannotHijackDiscovery (review M3): a bare repository committed inside the tree, read with the worktree set to it, never becomes the git dir: the read stays on the top's own .git, so the bare repo's HEAD cannot fabricate the diff.
func TestEmbeddedBareRepoCannotHijackDiscovery(t *testing.T) {
	for mode, sb := range bothModes(t) {
		t.Run(mode, func(t *testing.T) {
			top := fixtureRepo(t)
			sub := filepath.Join(top, "sub")
			realGit(t, top, "init", "-q", "--bare", "sub")
			forge := canonTemp(t)
			write(t, filepath.Join(forge, "app.py"), "FORGED-BASE\n")
			realGit(t, forge, "--git-dir="+sub, "--work-tree="+forge, "add", "app.py")
			realGit(t, forge, "--git-dir="+sub, "--work-tree="+forge, "commit", "-q", "-m", "forged")
			write(t, filepath.Join(top, "app.py"), "def f():\n    return 9\n")
			r := NewRunner(sb, &fakeEmitter{}, nil, false)
			r.StateDir = t.TempDir()
			got := string(r.TaskDiff(context.Background(), sub))
			if strings.Contains(got, "FORGED-BASE") || !strings.Contains(got, "+    return 9") {
				t.Fatalf("the embedded bare repo became the git dir (%+v):\n%s", diffStatus(t, r.StateDir, sub), got)
			}
			if gd, ok := r.Git(context.Background(), sub, "rev-parse", "--absolute-git-dir"); !ok || strings.TrimSpace(string(gd)) != filepath.ToSlash(filepath.Join(top, ".git")) {
				t.Fatalf("git dir %q ok=%v", gd, ok)
			}
		})
	}
}

// TestAlternatesOutsideTheGitDirRefused (review M3): objects/info/alternates naming another repository's objects abstains unsafe_git_dir, so a planted alternate can neither read nor forge through someone else's object store; one inside the git dir still reads.
func TestAlternatesOutsideTheGitDirRefused(t *testing.T) {
	private := fixtureRepo(t)
	repo := fixtureRepo(t)
	alt := filepath.Join(repo, ".git", "objects", "info", "alternates")
	write(t, alt, filepath.Join(private, ".git", "objects")+"\n")
	for mode, sb := range bothModes(t) {
		t.Run(mode, func(t *testing.T) {
			r := NewRunner(sb, &fakeEmitter{}, nil, false)
			r.StateDir = t.TempDir()
			if got := r.TaskDiff(context.Background(), repo); got != nil {
				t.Fatalf("read through a foreign alternate:\n%s", got)
			}
			if st := diffStatus(t, r.StateDir, repo); st.Abstain != DiffUnsafeGitDir {
				t.Fatalf("status %+v", st)
			}
		})
	}
	inside := filepath.Join(repo, ".git", "extra", "objects")
	if err := os.MkdirAll(inside, 0o700); err != nil {
		t.Fatal(err)
	}
	write(t, alt, "# a comment\n../extra/objects\n")
	if _, _, ok := gitReadRoots(repo); !ok {
		t.Fatal("an alternate inside the git dir refused")
	}
	write(t, filepath.Join(inside, "info", "alternates"), filepath.Join(private, ".git", "objects")+"\n")
	if _, _, ok := gitReadRoots(repo); ok {
		t.Fatal("a chained alternate leaving the git dir validated")
	}
}

// TestGlobalIgnoresStayOnTheMachine (review HIGH-4): what the person's own git ignores globally (core.excludesFile from their global config, else git's default ignore file) and what .git/info/exclude ignores never reads as a new file, so a globally ignored .venv/ neither leaves the machine nor blows the new-file cap.
func TestGlobalIgnoresStayOnTheMachine(t *testing.T) {
	cases := map[string]func(t *testing.T, home string){
		"default ignore file": func(t *testing.T, home string) {
			write(t, filepath.Join(home, ".config", "git", "ignore"), ".venv/\n*.secret\n")
		},
		"excludesFile in ~/.gitconfig": func(t *testing.T, home string) {
			write(t, filepath.Join(home, ".config", "git", "ignore"), "nothing-here\n")
			write(t, filepath.Join(home, ".gitconfig"), "[user]\n\tname = x\n[Core]\n\texcludesFile = \"~/my ignores\" ; the person's own\n")
			write(t, filepath.Join(home, "my ignores"), ".venv/\n*.secret\n")
		},
		"XDG_CONFIG_HOME": func(t *testing.T, _ string) {
			xdg := canonTemp(t)
			t.Setenv("XDG_CONFIG_HOME", xdg)
			write(t, filepath.Join(xdg, "git", "ignore"), ".venv/\n*.secret\n")
		},
		"GIT_CONFIG_GLOBAL": func(t *testing.T, home string) {
			cfg := filepath.Join(canonTemp(t), "cfg")
			t.Setenv("GIT_CONFIG_GLOBAL", cfg)
			write(t, cfg, "[core]\n\texcludesfile = "+filepath.ToSlash(filepath.Join(home, "ign"))+"\n")
			write(t, filepath.Join(home, "ign"), ".venv/\n*.secret\n")
		},
	}
	for name, setup := range cases {
		for mode, sb := range bothModes(t) {
			t.Run(name+"/"+mode, func(t *testing.T) {
				home := canonTemp(t)
				t.Setenv("HOME", home)
				t.Setenv("USERPROFILE", home)
				t.Setenv("XDG_CONFIG_HOME", "")
				t.Setenv("GIT_CONFIG_GLOBAL", "")
				setup(t, home)
				repo := fixtureRepo(t)
				for i := range maxNewFiles + 1 {
					write(t, filepath.Join(repo, ".venv", "lib", strconv.Itoa(i)+".py"), "x\n")
				}
				write(t, filepath.Join(repo, "api.secret"), "TOKEN\n")
				write(t, filepath.Join(repo, "notes.local"), "LOCAL\n")
				write(t, filepath.Join(repo, ".git", "info", "exclude"), "*.local\n")
				write(t, filepath.Join(repo, "new_mod.py"), "def g():\n    return 3\n")
				r := NewRunner(sb, &fakeEmitter{}, nil, false)
				r.StateDir = t.TempDir()
				got := string(r.TaskDiff(context.Background(), repo))
				if !strings.Contains(got, "b/new_mod.py") || strings.Contains(got, ".venv") || strings.Contains(got, "TOKEN") || strings.Contains(got, "LOCAL") {
					t.Fatalf("(%+v)\n%s", diffStatus(t, r.StateDir, repo), got)
				}
			})
		}
	}
}

func TestCoreExcludesFileParse(t *testing.T) {
	for in, want := range map[string]string{
		"[core]\n\texcludesfile = /a/b\n":                            "/a/b",
		"[core]\nexcludesFile=/a/b # c\n":                            "/a/b",
		"[CORE]\n  ExcludesFile = \"/a b\" ; c\n":                    "/a b",
		"[core] excludesfile = /x\n":                                 "/x",
		"[core]\nexcludesfile = /a\\\n/b\n":                          "/a/b",
		"[core]\nexcludesfile = \"/a\\\\b\\\"c\"\n":                  "/a\\b\"c",
		"[core]\nexcludesfile = /a\n[core]\nexcludesfile = /b\n":     "/b",
		"[core]\nexcludesfile = /a\nexcludesfile =\n":                "",
		"[core \"sub\"]\nexcludesfile = /no\n[core]\nfoo = bar\n":    "!",
		"[include]\npath = x\n# excludesfile = /no\n":                "!",
		"[core.x]\nexcludesfile = /no\n":                             "!",
		"[core]\n\texcludesfile = ~/g\n[user]\nexcludesfile = /no\n": "~/g",
	} {
		got, ok := coreExcludesFile([]byte(in))
		if !ok {
			got = "!"
		}
		if got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}

// TestBlameIgnoresNoRevsTheRepositoryNames (review LOW): a repository's blame.ignoreRevsFile cannot hide a commit from the outcome labels' blame; every line is attributed to the commit that wrote it.
func TestBlameIgnoresNoRevsTheRepositoryNames(t *testing.T) {
	repo := fixtureRepo(t)
	write(t, filepath.Join(repo, "app.py"), "def f():\n    return 7\n")
	realGit(t, repo, "commit", "-q", "-am", "task")
	task := strings.TrimSpace(realGit(t, repo, "rev-parse", "HEAD"))
	write(t, filepath.Join(repo, ".git-blame-ignore-revs"), task+"\n")
	realGit(t, repo, "config", "blame.ignoreRevsFile", ".git-blame-ignore-revs")
	for mode, sb := range bothModes(t) {
		t.Run(mode, func(t *testing.T) {
			r := NewRunner(sb, &fakeEmitter{}, nil, false)
			out, ok := r.Git(context.Background(), repo, "blame", "--line-porcelain", "-L", "2,2", "HEAD", "--", "app.py")
			if !ok || !strings.HasPrefix(string(out), task) {
				t.Fatalf("blame of the task's line names %q, want %s", strings.SplitN(string(out), " ", 2)[0], task)
			}
		})
	}
}
