package anchors

import (
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // G505: git's blob id, not a security hash
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/tailers"
)

// DiffAbstain is why a worktree read produced no diff; "" when it produced one.
type DiffAbstain string

const (
	DiffNoGit           DiffAbstain = "no_git"            // no git on the daemon's PATH
	DiffNoRepo          DiffAbstain = "not_a_repository"  // no .git at or above the worktree
	DiffGitFailed       DiffAbstain = "git_failed"        // git failed in the sandbox and outside it
	DiffTooLarge        DiffAbstain = "diff_too_large"    // past the output cap or the new-file count cap
	DiffUnsafeConfig    DiffAbstain = "unsafe_git_config" // a filter driver name `-c` cannot neutralise
	DiffNoChange        DiffAbstain = "no_change"         // the worktree matches the task's base, untracked files included
	DiffBaseUnreachable DiffAbstain = "base_unreachable"  // the task's open-time HEAD shares no history with HEAD now (orphan checkout, gc'd, another repository)
	DiffUnsafeGitDir    DiffAbstain = "unsafe_git_dir"    // the .git file or commondir points anywhere but this repository's own git dir, a linked worktree's or a submodule's
)

const (
	maxNewFiles     = 1000    // untracked files in one diff; past it the change is a vendoring, not a task
	maxNewFileBytes = 1 << 20 // one new file's text; larger reads as binary, as git's bigFileThreshold does
	binarySniff     = 8000    // git's FIRST_FEW_BYTES: a NUL among them is binary
)

// gitHardening leads every git mark1d runs: no program the repository, the agent or the user's config names runs (fsmonitor, hooks, pager, attributes file, submodule recursion, signature checks; transports are gitEnv's), nothing is locked or written, and the output shape is pinned (10 §7.5). Audited and left to config: include.path/includeIf only read files (and `config --list` follows them, so a filter an include names is still emptied); diff.<driver>.command/textconv and diff.external are off by the --no-ext-diff/--no-textconv gitSubcommand adds; core.sshCommand, credential helpers, remote.*.vcs, core.alternateRefsCommand and uploadpack.packObjectsHook run only inside a transport, which GIT_ALLOW_PROTOCOL refuses; core.worktree is overridden by --work-tree, discovery by --git-dir.
var gitHardening = []string{
	"--no-pager", "--no-optional-locks", "--no-replace-objects",
	"-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", "-c", "core.hooksPath=/dev/null", "-c", "core.attributesFile=/dev/null",
	"-c", "protocol.allow=never", "-c", "log.showSignature=false", "-c", "core.quotePath=true", "-c", "color.ui=never",
	"-c", "diff.noprefix=false", "-c", "diff.mnemonicPrefix=false", "-c", "diff.srcPrefix=a/", "-c", "diff.dstPrefix=b/", "-c", "diff.relative=false",
	"-c", "diff.interHunkContext=0", "-c", "diff.algorithm=myers", "-c", "diff.submodule=short", "-c", "diff.renames=true", "-c", "diff.orderFile=/dev/null",
	"-c", "diff.ignoreSubmodules=all", "-c", "status.submoduleSummary=false", "-c", "submodule.recurse=false",
	"-c", "safe.bareRepository=explicit",
}

// gitEnv is the whole environment git gets besides the sandbox's HOME/TMPDIR: no system config, no prompt, no lazy fetch, and no transport at all (GIT_ALLOW_PROTOCOL outranks every protocol.<name>.allow a repository sets, which `-c protocol.allow=never` does not; GIT_NO_LAZY_FETCH exists only from git 2.44).
func gitEnv(git string) map[string]string {
	return map[string]string{"PATH": filepath.Dir(git), "LANG": "C", "GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0", "GIT_NO_LAZY_FETCH": "1", "GIT_ALLOW_PROTOCOL": "mark1-none"}
}

// gitSubcommand pins what each subcommand we run must never do whatever its caller passed: recurse into a submodule (whose own config git reads and whose filters -c never reaches), run an external diff or a textconv driver.
func gitSubcommand(args []string) []string {
	if len(args) == 0 {
		return args
	}
	var pin []string
	switch args[0] {
	case "status":
		pin = []string{"--ignore-submodules=all"}
	case "diff", "log", "show":
		pin = []string{"--ignore-submodules=all", "--no-ext-diff", "--no-textconv"}
	case "blame":
		pin = []string{"--no-textconv", "--no-ignore-revs-file"} // a repository's blame.ignoreRevsFile would hide commits from the outcome labels
	}
	return append(append([]string{args[0]}, pin...), args[1:]...)
}

func gitBinary() (string, error) {
	git, err := exec.LookPath("git")
	if err != nil {
		return "", err
	}
	if git, err = filepath.Abs(git); err != nil {
		return "", err
	}
	if resolved, rerr := filepath.EvalSymlinks(git); rerr == nil {
		git = resolved
	}
	return git, nil
}

// gitResult is one hardened git run.
type gitResult struct {
	out     []byte
	abstain DiffAbstain // "" = git answered with exit 0
	direct  bool        // answered outside the sandbox
	detail  string      // why the sandbox did not answer, or git's stderr head
	code    int         // git's exit code when it ran and failed
}

// gitRun runs git hardened in the sandbox, and the same argv directly when the sandbox refuses or its git cannot read the repository (10 §7.5); overrides are filterOverrides' output.
func (r *Runner) gitRun(ctx context.Context, worktree string, overrides []string, args ...string) gitResult {
	git, err := gitBinary()
	if err != nil {
		return gitResult{abstain: DiffNoGit, detail: err.Error()}
	}
	top := GitTop(worktree)
	if !isRepo(top) {
		return gitResult{abstain: DiffNoRepo}
	}
	roots, gd, ok := gitReadRoots(worktree)
	if !ok {
		return gitResult{abstain: DiffUnsafeGitDir, detail: "the .git at " + top + " points outside a repository's own git dir, or its object store borrows another's"}
	}
	argv := append([]string{git}, gitHardening...)
	if x := globalExcludes(); x != "" { // the scratch HOME hides the person's own global ignores; without them a globally ignored .venv/ reads as new files
		argv, roots = append(argv, "-c", "core.excludesFile="+x), append(roots, x)
	}
	argv = append(append(argv, overrides...), "--git-dir="+gd, "--work-tree="+top) // explicit: no bare repository inside the tree is ever discovered as this one's
	argv = append(argv, gitSubcommand(args)...)
	env := gitEnv(git)
	res, err := r.sb.Run(ctx, RunSpec{Argv: argv, WorktreeRO: worktree, ReadOnly: roots, Env: env, Limits: DefaultLimits(ClassFast)})
	switch {
	case errors.Is(err, ErrOutputCap):
		return gitResult{abstain: DiffTooLarge}
	case err == nil && res.TimedOut:
		return gitResult{abstain: DiffGitFailed, detail: "timed out in the sandbox"}
	case err == nil && res.ExitCode == 0:
		return gitResult{out: res.Stdout}
	case err == nil && res.ExitCode == 1:
		return gitResult{abstain: DiffGitFailed, code: 1, detail: head(res.Stderr)} // git's "no" (merge-base, rev-parse -q), never a sandbox refusal: those are fatal 128s
	}
	why := "sandboxed git exited " + strconv.Itoa(res.ExitCode) + ": " + head(res.Stderr)
	if err != nil {
		why = err.Error()
	}
	g := gitDirect(ctx, argv, env, worktree)
	g.direct, g.detail = true, strings.TrimSuffix(why+"; "+g.detail, "; ")
	return g
}

// gitDirect is the documented fallback (10 §7.5): the same hardened argv outside the sandbox, a scrubbed env with a throwaway HOME, the fast-class wall clock and output cap.
// ponytail: kills git alone on timeout, not a process group; hardened git spawns nothing but Git for Windows' cmd\git.exe shim child.
func gitDirect(ctx context.Context, argv []string, env map[string]string, dir string) gitResult {
	home, err := os.MkdirTemp("", "mark1-git-")
	if err != nil {
		return gitResult{abstain: DiffGitFailed, detail: err.Error()}
	}
	defer func() { _ = os.RemoveAll(home) }()
	lim := DefaultLimits(ClassFast)
	ctx, cancel := context.WithTimeout(ctx, lim.Wall)
	defer cancel()
	budget := &outputBudget{remaining: lim.OutputCap}
	stdout, stderr := &capWriter{budget: budget}, &capWriter{budget: budget}
	budget.onExceed(cancel)
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec // G204: argv[0] is the resolved git, the rest is gitHardening plus our own subcommand
	cmd.Dir = dir
	cmd.Env = []string{"HOME=" + home, "TMPDIR=" + home}
	if v := os.Getenv("SystemRoot"); v != "" {
		cmd.Env = append(cmd.Env, "SystemRoot="+v) // a Win32 process cannot load without it
	}
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	cmd.Stdout, cmd.Stderr, cmd.WaitDelay = stdout, stderr, time.Second
	err = cmd.Run()
	switch {
	case budget.exceeded():
		return gitResult{abstain: DiffTooLarge}
	case err != nil:
		code := -1
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		}
		return gitResult{abstain: DiffGitFailed, code: code, detail: "git: " + err.Error() + ": " + head(stderr.buf)}
	}
	return gitResult{out: stdout.buf}
}

// globalExcludes is the person's effective global ignore file as their own git would find it: core.excludesFile from their global config (GIT_CONFIG_GLOBAL, else $XDG_CONFIG_HOME/git/config then ~/.gitconfig, the later winning; that one key parsed, nothing followed or run), else $XDG_CONFIG_HOME/git/ignore or ~/.config/git/ignore; "" when that is not a regular file.
// ponytail: an excludesFile set only in an include.path/includeIf file is missed; parse includes if anyone keeps it there.
func globalExcludes() string {
	home := os.Getenv("HOME")
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	if !filepath.IsAbs(home) {
		home = ""
	}
	xdg := os.Getenv("XDG_CONFIG_HOME")
	if !filepath.IsAbs(xdg) {
		xdg = ""
		if home != "" {
			xdg = filepath.Join(home, ".config")
		}
	}
	var cfgs []string
	switch g := os.Getenv("GIT_CONFIG_GLOBAL"); {
	case g != "":
		cfgs = []string{g}
	default:
		if xdg != "" {
			cfgs = append(cfgs, filepath.Join(xdg, "git", "config"))
		}
		if home != "" {
			cfgs = append(cfgs, filepath.Join(home, ".gitconfig"))
		}
	}
	p, set := "", false
	for _, c := range cfgs {
		if b, err := os.ReadFile(c); err == nil { //nolint:gosec // G304: the person's own global git config
			if v, ok := coreExcludesFile(b); ok {
				p, set = v, true
			}
		}
	}
	switch {
	case !set && xdg != "":
		p = filepath.Join(xdg, "git", "ignore")
	case strings.HasPrefix(p, "~/") && home != "":
		p = filepath.Join(home, p[2:])
	}
	if !filepath.IsAbs(p) {
		return ""
	}
	if fi, err := os.Stat(p); err != nil || !fi.Mode().IsRegular() {
		return ""
	}
	return filepath.Clean(p)
}

// coreExcludesFile is the last core.excludesFile a git config file sets, parsed as git does (case-insensitive section and key, quotes, escapes, comments, line continuations); ok is false when the file never sets it.
func coreExcludesFile(b []byte) (string, bool) {
	text := strings.NewReplacer("\\\r\n", "", "\\\n", "").Replace(string(b))
	val, ok, core := "", false, false
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			end := strings.IndexByte(line, ']')
			if end < 0 {
				continue
			}
			core = strings.EqualFold(strings.TrimSpace(line[1:end]), "core")
			line = strings.TrimSpace(line[end+1:])
		}
		k, v, hasEq := strings.Cut(line, "=")
		if !core || !strings.EqualFold(strings.TrimSpace(k), "excludesfile") {
			continue
		}
		val, ok = "", true
		if hasEq {
			val = configValue(v)
		}
	}
	return val, ok
}

// configValue is git's parse_value: leading/trailing unquoted blanks dropped, "…" quoting, \\ \" \n \t \b escapes, an unquoted # or ; starts a comment.
func configValue(raw string) string {
	var b []byte
	quoted, keep := false, 0
	raw = strings.TrimLeft(raw, " \t")
	for i := 0; i < len(raw); i++ {
		switch c := raw[i]; {
		case c == '"':
			quoted = !quoted
		case c == '\\' && i+1 < len(raw):
			i++
			switch raw[i] {
			case 'n':
				b = append(b, '\n')
			case 't':
				b = append(b, '\t')
			case 'b':
				b = append(b, '\b')
			default:
				b = append(b, raw[i])
			}
			keep = len(b)
		case !quoted && (c == '#' || c == ';'):
			return string(b[:keep])
		default:
			b = append(b, c)
			if quoted || (c != ' ' && c != '\t') {
				keep = len(b)
			}
		}
	}
	return string(b[:keep])
}

func head(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// gitReadRoots is what git reads outside the worktree: the repository top when the worktree is a subdirectory, and a linked worktree's or submodule's git dir plus its common dir; gd is the git dir every run names explicitly; false when the .git there is anything but a real repository's own (gitDirs) or its objects borrow from outside it.
func gitReadRoots(worktree string) (roots []string, gd string, ok bool) {
	top := GitTop(worktree)
	gd, common, ok := gitDirs(top)
	if !ok || !localAlternates(filepath.Join(common, "objects"), resolvedPath(common, common), 0) {
		return nil, "", false
	}
	var out []string
	if top != worktree {
		out = append(out, top)
	}
	if gd != filepath.Join(top, ".git") {
		out = append(out, gd)
		if common != gd {
			out = append(out, common)
		}
	}
	return out, gd, true
}

// localAlternates: every objects/info/alternates entry, followed as git follows them (five deep), stays inside gitDir; an alternate elsewhere would have git read, and diff against, another repository's objects as this one's.
func localAlternates(objects, gitDir string, depth int) bool {
	b, err := os.ReadFile(filepath.Join(objects, "info", "alternates")) //nolint:gosec // G304: the repository's own alternates list
	if errors.Is(err, fs.ErrNotExist) {
		return true
	}
	if err != nil || depth >= 5 {
		return false
	}
	for _, l := range strings.Split(strings.ReplaceAll(string(b), "\r", ""), "\n") {
		if l == "" || l[0] == '#' {
			continue
		}
		p := resolvedPath(objects, l)
		if l[0] == '"' || !Within(gitDir, p) || !localAlternates(p, gitDir, depth+1) {
			return false
		}
	}
	return true
}

// gitDirs validates top/.git before git reads through it: a directory with no commondir of its own, or a gitfile naming a linked worktree's dir (R/.git/worktrees/x, whose gitdir file points back here and whose commondir is R/.git) or a submodule's (R/.git/modules/…, R a proper ancestor of top). A gitfile or commondir naming any other directory would have git read another repository, or anything, as this one's.
func gitDirs(top string) (gitDir, common string, ok bool) {
	dotgit := filepath.Join(top, ".git")
	fi, err := os.Lstat(dotgit)
	switch {
	case err != nil:
		return "", "", false
	case fi.IsDir():
		if _, err := os.Lstat(filepath.Join(dotgit, "commondir")); err == nil {
			return "", "", false
		}
		return dotgit, dotgit, true
	case !fi.Mode().IsRegular():
		return "", "", false
	}
	b, err := os.ReadFile(dotgit) //nolint:gosec // G304: the repository's own gitfile
	if err != nil {
		return "", "", false
	}
	gd, found := strings.CutPrefix(strings.TrimSpace(string(b)), "gitdir: ")
	if !found || gd == "" {
		return "", "", false
	}
	if gd = resolvedDir(top, gd); gd == "" {
		return "", "", false
	}
	if parent := filepath.Dir(gd); filepath.Base(parent) == "worktrees" && realGitDir(filepath.Dir(parent)) {
		back, err := os.ReadFile(filepath.Join(gd, "gitdir")) //nolint:gosec // G304: git's own back-link
		if err != nil || !sameFile(resolvedPath(gd, strings.TrimSpace(string(back))), dotgit) {
			return "", "", false
		}
		c, err := os.ReadFile(filepath.Join(gd, "commondir")) //nolint:gosec // G304: as above
		if err != nil || !sameFile(resolvedPath(gd, strings.TrimSpace(string(c))), filepath.Dir(parent)) {
			return "", "", false
		}
		return gd, filepath.Dir(parent), true
	}
	if _, err := os.Lstat(filepath.Join(gd, "commondir")); err == nil {
		return "", "", false
	}
	for d := filepath.Dir(gd); d != filepath.Dir(d); d = filepath.Dir(d) {
		if filepath.Base(d) != "modules" || !realGitDir(filepath.Dir(d)) {
			continue
		}
		if r, t := filepath.Dir(filepath.Dir(d)), resolvedPath(top, top); r != t && Within(r, t) {
			return gd, gd, true
		}
		return "", "", false
	}
	return "", "", false
}

// realGitDir: p is named .git and is a directory, not a link to one.
func realGitDir(p string) bool {
	fi, err := os.Lstat(p)
	return err == nil && fi.IsDir() && filepath.Base(p) == ".git"
}

// resolvedPath is p (relative to base when not absolute) cleaned, with symlinks resolved where it exists.
func resolvedPath(base, p string) string {
	if !filepath.IsAbs(p) {
		p = filepath.Join(base, p)
	}
	p = filepath.Clean(p)
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return p
}

// resolvedDir is resolvedPath for a directory that must exist; "" otherwise.
func resolvedDir(base, p string) string {
	p = resolvedPath(base, p)
	if fi, err := os.Stat(p); err != nil || !fi.IsDir() {
		return ""
	}
	return p
}

func sameFile(a, b string) bool {
	fa, err := os.Stat(a)
	if err != nil {
		return false
	}
	fb, err := os.Stat(b)
	return err == nil && os.SameFile(fa, fb)
}

// filterOverrides empties every filter driver `git config --list -z` names: a clean/smudge/process command is repository-controlled code git runs on every worktree read, and it can rewrite what the diff shows. ponytail: listed one git run before the read, so a driver planted in between runs once, inside the sandbox where it hosts git.
func filterOverrides(list []byte) ([]string, bool) {
	var out []string
	seen := map[string]bool{}
	for _, kv := range bytes.Split(list, []byte{0}) {
		k, _, _ := strings.Cut(string(kv), "\n")
		i := strings.LastIndex(k, ".")
		if !strings.HasPrefix(k, "filter.") || i < len("filter.") {
			continue
		}
		name := k[len("filter."):i]
		if name == "" || strings.ContainsAny(name, "=\x00") {
			return nil, false
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		for _, v := range []string{"clean=", "smudge=", "process=", "required=false"} {
			out = append(out, "-c", "filter."+name+"."+v)
		}
	}
	return out, true
}

// gitOverrides lists the repository's config once and neutralises its filter drivers for the reads that follow.
func (r *Runner) gitOverrides(ctx context.Context, worktree string) ([]string, gitResult) {
	g := r.gitRun(ctx, worktree, nil, "config", "--list", "-z")
	if g.abstain != "" {
		return nil, g
	}
	ov, ok := filterOverrides(g.out)
	if !ok {
		return nil, gitResult{abstain: DiffUnsafeConfig, direct: g.direct, detail: "a filter driver name git -c cannot override"}
	}
	return ov, g
}

// treeRead is one read of a worktree against the task's base (HEAD without one): git status paths, and the tracked diff followed by every untracked file under the worktree as a new-file section.
type treeRead struct {
	paths []string
	raw   []byte
	known bool // git status answered
	gitResult
}

// emptyTree is the object id of the empty tree in the repository's hash (a HEAD of 64 hex digits is SHA-256).
func emptyTree(head string) string {
	if len(head) == 64 {
		return "6ef19b41225c5369f1c104d45d8d85efa9b057b53b14b4b9b939dd74decc5321"
	}
	return "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
}

// readTree answers diff() and TaskDiff alike; unified is the context width, task (zero = none) selects the base recorded at its open.
func (r *Runner) readTree(ctx context.Context, worktree string, unified int, task [16]byte) (t treeRead) {
	defer func() {
		if ctx.Err() == nil { // a cancelled read (`mark1 off`, shutdown) says nothing about the tree
			r.noteDiff(worktree, t.gitResult)
		}
	}()
	top := GitTop(worktree)
	if !isRepo(top) {
		t.abstain = DiffNoRepo
		return t
	}
	base, has := r.baseFor(ctx, task)
	if has && base.Top != top {
		t.abstain, t.detail = DiffBaseUnreachable, "the task opened in "+base.Top
		return t
	}
	ov, g := r.gitOverrides(ctx, worktree)
	if t.gitResult = g; g.abstain != "" {
		return t
	}
	st := r.gitRun(ctx, worktree, ov, "status", "--porcelain=v2", "-z", "--branch", "--no-renames", "--untracked-files=all")
	if t.gitResult = mergeHow(g, st); st.abstain != "" {
		return t
	}
	t.known = true
	cur, fresh, tracked := "", []string(nil), []string(nil)
	for _, ent := range bytes.Split(st.out, []byte{0}) {
		s := string(ent)
		switch {
		case strings.HasPrefix(s, "# branch.oid "):
			cur = strings.TrimPrefix(s, "# branch.oid ")
		case strings.HasPrefix(s, "? "):
			fresh = append(fresh, s[2:])
		case strings.HasPrefix(s, "1 "):
			if f := strings.SplitN(s, " ", 9); len(f) == 9 {
				tracked = append(tracked, f[8])
			}
		case strings.HasPrefix(s, "u "):
			if f := strings.SplitN(s, " ", 11); len(f) == 11 {
				tracked = append(tracked, f[10])
			}
		}
	}
	t.paths = append(append(t.paths, tracked...), fresh...)
	unborn := cur == "(initial)"
	from := "HEAD"
	switch {
	case unborn && has && base.Head != "":
		t.abstain, t.detail = DiffBaseUnreachable, "HEAD has no commit now; the task opened at "+base.Head
		return t
	case unborn:
		from, fresh = "", append(fresh, tracked...) // with no HEAD every path is new; a deleted one fails its Lstat and drops
	case !has || base.Head == cur:
	case base.Head == "":
		from = emptyTree(cur) // the task made the repository's first commit
	default:
		mb := r.gitRun(ctx, worktree, nil, "merge-base", base.Head, cur)
		if t.gitResult = mergeHow(t.gitResult, mb); mb.abstain != "" {
			t.abstain, t.detail = DiffBaseUnreachable, "the task opened at "+base.Head+": "+mb.detail
			return t
		}
		from = strings.TrimSpace(string(mb.out)) // the open-time HEAD itself when it is an ancestor, else the fork point
	}
	if from != "" {
		d := r.gitRun(ctx, worktree, ov, "diff", from, "--unified="+strconv.Itoa(unified), "--no-color", "--no-ext-diff", "--no-textconv", "--")
		if t.gitResult = mergeHow(t.gitResult, d); d.abstain != "" {
			return t
		}
		t.raw = d.out
		if from != "HEAD" && from != cur { // committed during the task: those files are touched too
			n := r.gitRun(ctx, worktree, ov, "diff", "--name-only", "-z", "--no-renames", from, "--")
			if t.gitResult = mergeHow(t.gitResult, n); n.abstain != "" {
				return t
			}
			for _, p := range bytes.Split(n.out, []byte{0}) {
				if len(p) > 0 && !slices.Contains(t.paths, string(p)) {
					t.paths = append(t.paths, string(p))
				}
			}
		}
	}
	nf, ok := newFiles(worktree, top, fresh, DefaultLimits(ClassFast).OutputCap-int64(len(t.raw)))
	if !ok {
		t.abstain, t.raw = DiffTooLarge, nil
		return t
	}
	if t.raw = append(t.raw, nf...); len(t.raw) == 0 {
		t.abstain = DiffNoChange
	}
	return t
}

// mergeHow carries the later run's outcome with "direct" sticky: one fallback makes the whole read a direct one.
func mergeHow(prev, next gitResult) gitResult {
	if prev.direct && !next.direct {
		next.direct, next.detail = true, prev.detail
	}
	return next
}

// newFiles renders untracked paths (repository-relative) that sit under worktree and that .mark1ignore leaves in, sorted, as git's own new-file sections; false when they exceed maxNewFiles or budget bytes.
func newFiles(worktree, top string, paths []string, budget int64) ([]byte, bool) {
	var keep []string
	ws, err := tailers.NewWorkspaceSet(worktree)
	if err != nil {
		return nil, true
	}
	for _, p := range paths {
		if strings.HasSuffix(p, "/") {
			continue // a nested repository git will not look into
		}
		abs := filepath.Join(top, filepath.FromSlash(p))
		if rel, err := filepath.Rel(worktree, abs); err == nil && filepath.IsLocal(rel) && ws.Allowed(abs) {
			keep = append(keep, p)
		}
	}
	if len(keep) > maxNewFiles {
		return nil, false
	}
	if len(keep) == 0 {
		return nil, true
	}
	root, err := os.OpenRoot(worktree)
	if err != nil {
		return nil, true
	}
	defer func() { _ = root.Close() }()
	sort.Strings(keep)
	var out []byte
	for _, p := range keep {
		rel, _ := filepath.Rel(worktree, filepath.Join(top, filepath.FromSlash(p)))
		out = append(out, newFileSection(root, rel, p)...)
		if int64(len(out)) > budget {
			return nil, false
		}
	}
	return out, true
}

// newFileSection is `git diff` of one intent-to-add path, byte for byte: mode, blob id, the whole file as one added hunk; binary, oversize and symlink content as git shows them. Nothing is followed out of root.
func newFileSection(root *os.Root, rel, name string) []byte {
	fi, err := root.Lstat(rel)
	if err != nil {
		return nil
	}
	var mode string
	var content []byte
	switch {
	case fi.Mode()&fs.ModeSymlink != 0:
		target, err := root.Readlink(rel)
		if err != nil {
			return nil
		}
		mode, content = "120000", []byte(filepath.ToSlash(target))
	case fi.Mode().IsRegular():
		mode = "100644"
		if fi.Mode()&0o111 != 0 {
			mode = "100755"
		}
		if fi.Size() > maxNewFileBytes {
			return fmt.Appendf(nil, "diff --git %s %s\nnew file mode %s\nBinary files /dev/null and %s differ\n", gitQuote("a/"+name), gitQuote("b/"+name), mode, gitQuote("b/"+name))
		}
		if content, err = readRegular(root, rel); err != nil {
			return nil
		}
		if len(content) > maxNewFileBytes { // grew past the cap since the Lstat
			return fmt.Appendf(nil, "diff --git %s %s\nnew file mode %s\nBinary files /dev/null and %s differ\n", gitQuote("a/"+name), gitQuote("b/"+name), mode, gitQuote("b/"+name))
		}
	default:
		return nil
	}
	h := sha1.New() //nolint:gosec // G401: git's blob id
	_, _ = fmt.Fprintf(h, "blob %d\x00", len(content))
	_, _ = h.Write(content)
	b := gitQuote("b/" + name)
	out := fmt.Appendf(nil, "diff --git %s %s\nnew file mode %s\nindex 0000000..%s\n", gitQuote("a/"+name), b, mode, hex.EncodeToString(h.Sum(nil))[:7])
	if len(content) == 0 {
		return out
	}
	if bytes.IndexByte(content[:min(len(content), binarySniff)], 0) >= 0 {
		return fmt.Appendf(out, "Binary files /dev/null and %s differ\n", b)
	}
	lines := strings.SplitAfter(string(content), "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	tab := ""
	if strings.Contains(name, " ") {
		tab = "\t" // git's own disambiguation for GNU patch
	}
	out = fmt.Appendf(out, "--- /dev/null\n+++ %s%s\n@@ -0,0 +1", b, tab)
	if len(lines) != 1 {
		out = fmt.Appendf(out, ",%d", len(lines))
	}
	out = append(out, " @@\n"...)
	for _, l := range lines {
		out = append(append(out, '+'), l...)
	}
	if !strings.HasSuffix(string(content), "\n") {
		out = append(out, "\n\\ No newline at end of file\n"...)
	}
	return out
}

// readRegular reads rel only while it is a regular file: opened non-blocking so a FIFO swapped in after the Lstat never hangs the read, and one byte past the cap at most so a growing file never reads unbounded.
func readRegular(root *os.Root, rel string) ([]byte, error) {
	f, err := root.OpenFile(rel, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	return io.ReadAll(io.LimitReader(f, maxNewFileBytes+1))
}

// gitQuote is git's quote_c_style under core.quotePath=true: control bytes, '"', '\' and every byte past 0x7e are escaped, and then the whole name is quoted.
func gitQuote(s string) string {
	if !strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == '"' || r == '\\' || r >= 0x7f }) {
		return s
	}
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '\a':
			b.WriteString(`\a`)
		case '\b':
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\v':
			b.WriteString(`\v`)
		case '\f':
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		default:
			if c < 0x20 || c >= 0x7f {
				fmt.Fprintf(&b, `\%03o`, c)
			} else {
				b.WriteByte(c)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

// DiffStatusPath is where mark1d says, per worktree, how its last read of the tree went; `mark1 doctor` reads it (task_diff).
func DiffStatusPath(stateDir string) string {
	return filepath.Join(stateDir, "anchors", "diff_status.json")
}

// DiffState is one worktree's row in diff_status.json.
type DiffState struct {
	Via     string      `json:"via"` // "sandbox", "direct" (the 10 §7.5 fallback) or "" when nothing answered
	Abstain DiffAbstain `json:"abstain,omitempty"`
	Detail  string      `json:"detail,omitempty"`
	Since   time.Time   `json:"since"`
}

// noteDiff records a worktree's read outcome, rewriting the file only when that worktree's state changes.
func (r *Runner) noteDiff(worktree string, g gitResult) {
	if r.StateDir == "" {
		return
	}
	via := "sandbox"
	switch {
	case g.direct:
		via = "direct"
	case g.abstain != "" && g.abstain != DiffNoChange && g.abstain != DiffTooLarge:
		via = ""
	}
	st := DiffState{Via: via, Abstain: g.abstain, Detail: g.detail}
	r.mu.Lock()
	defer r.mu.Unlock()
	if prev, ok := r.diffStates[worktree]; ok && prev.Via == st.Via && prev.Abstain == st.Abstain && prev.Detail == st.Detail {
		return
	}
	if r.diffStates == nil {
		r.diffStates = map[string]DiffState{}
	}
	st.Since = time.Now().UTC()
	r.diffStates[worktree] = st
	b, err := json.MarshalIndent(map[string]any{"version": 1, "worktrees": r.diffStates}, "", "  ")
	if err == nil {
		_ = writePrivate(DiffStatusPath(r.StateDir), b)
	}
}
