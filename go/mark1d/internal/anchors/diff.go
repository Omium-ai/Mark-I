package anchors

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

// diffFacts is AnchorIntegrity's touched-file input (06 §2.4), read with git inside the sandbox since CortexInjection carries only root_hash.
type diffFacts struct {
	class m1pv1.DiffClassification
	delta int32
	raw   []byte
	paths []string // git status paths, worktree-relative, slash-separated
	known bool     // git status answered; false = no git/no repo, so nothing is known about what was touched
}

var (
	testPathRe = regexp.MustCompile(`(^|/)(tests?|__tests__|spec|testdata)/|_test\.(go|rs|py)$|(^|/)test_[^/]*\.py$|\.(test|spec)\.[cm]?[jt]sx?$`)
	// suppressionRe is 06 §2.4's directive set; one match = one directive.
	suppressionRe = regexp.MustCompile(`#\s*noqa|#\s*type:\s*ignore|//\s*nolint|#!?\[allow\(|eslint-disable|@ts-ignore|@ts-expect-error|#\s*pylint:\s*disable`)
	// configNames: files that change what the catalog tools answer; ponytail: a name set, per-tool discovery if gaming moves elsewhere.
	configNames = map[string]bool{
		"ruff.toml": true, ".ruff.toml": true, "pyproject.toml": true, "setup.cfg": true, "tox.ini": true,
		"pytest.ini": true, "mypy.ini": true, ".flake8": true, "tsconfig.json": true, "package.json": true,
		"Cargo.toml": true, "clippy.toml": true, "rustfmt.toml": true, "go.mod": true, ".golangci.yml": true,
		".golangci.yaml": true, ".golangci.toml": true, "eslint.config.js": true, "eslint.config.mjs": true,
		"eslint.config.cjs": true, ".editorconfig": true, ".prettierrc": true,
	}
)

func pathRole(p string) m1pv1.PathRole {
	base := path.Base(p)
	switch {
	case configNames[base] || strings.HasPrefix(base, ".eslintrc"):
		return m1pv1.PathRole_PATH_ROLE_CONFIG
	case testPathRe.MatchString(p):
		return m1pv1.PathRole_PATH_ROLE_TEST
	default:
		return m1pv1.PathRole_PATH_ROLE_SRC
	}
}

// classifyDiff: CONFIG > TEST > SUPPRESSION > SRC_ONLY — the delta has its own field, config/test touches do not.
func classifyDiff(paths []string, delta int32) m1pv1.DiffClassification {
	if len(paths) == 0 {
		return m1pv1.DiffClassification_DIFF_CLASSIFICATION_NONE
	}
	test := false
	for _, p := range paths {
		switch pathRole(p) {
		case m1pv1.PathRole_PATH_ROLE_CONFIG:
			return m1pv1.DiffClassification_DIFF_CLASSIFICATION_CONFIG_TOUCHED
		case m1pv1.PathRole_PATH_ROLE_TEST:
			test = true
		}
	}
	switch {
	case test:
		return m1pv1.DiffClassification_DIFF_CLASSIFICATION_TEST_TOUCHED
	case delta != 0:
		return m1pv1.DiffClassification_DIFF_CLASSIFICATION_SUPPRESSION_TOUCHED
	default:
		return m1pv1.DiffClassification_DIFF_CLASSIFICATION_SRC_ONLY
	}
}

// suppressionDelta counts directives on added minus removed unified-diff lines.
func suppressionDelta(diff []byte) int32 {
	var n int32
	for _, l := range bytes.Split(diff, []byte("\n")) {
		switch {
		case bytes.HasPrefix(l, []byte("+++")), bytes.HasPrefix(l, []byte("---")):
		case bytes.HasPrefix(l, []byte("+")):
			n += int32(len(suppressionRe.FindAllIndex(l, -1))) //nolint:gosec // G115: directives per line
		case bytes.HasPrefix(l, []byte("-")):
			n -= int32(len(suppressionRe.FindAllIndex(l, -1))) //nolint:gosec // G115: directives per line
		}
	}
	return n
}

// diff runs git status/diff in the sandbox; no git, no confinement or a failing git ⇒ UNSPECIFIED, never a guess.
func (r *Runner) diff(ctx context.Context, worktree string) diffFacts {
	git, err := exec.LookPath("git")
	if err != nil {
		return diffFacts{}
	}
	if git, err = filepath.Abs(git); err != nil {
		return diffFacts{}
	}
	if resolved, rerr := filepath.EvalSymlinks(git); rerr == nil {
		git = resolved
	}
	run := func(args ...string) ([]byte, bool) {
		res, err := r.sb.Run(ctx, RunSpec{
			Argv:              append([]string{git, "-c", "core.fsmonitor=false", "--no-pager"}, args...),
			WorktreeRO:        worktree,
			Env:               map[string]string{"PATH": filepath.Dir(git), "LANG": "C"},
			Limits:            DefaultLimits(ClassFast),
			RequireFSConfined: true,
		})
		if err != nil || res.ExitCode != 0 {
			return nil, false
		}
		return res.Stdout, true
	}
	status, ok := run("status", "--porcelain", "-z", "--no-renames", "--untracked-files=all")
	if !ok {
		return diffFacts{}
	}
	var paths []string
	for _, ent := range bytes.Split(status, []byte{0}) {
		if len(ent) > 3 {
			paths = append(paths, string(ent[3:]))
		}
	}
	raw, _ := run("diff", "HEAD", "--unified=0", "--no-color", "--no-ext-diff", "--no-textconv")
	delta := suppressionDelta(raw)
	return diffFacts{class: classifyDiff(paths, delta), delta: delta, raw: raw, paths: paths, known: true}
}

// fingerprint names the state of the tree these facts describe: the status paths plus the diff against HEAD; empty when git could not answer. Content edits inside an untracked file do not move it — the vote tee ORs it with the evidence fingerprint for that case.
func (d diffFacts) fingerprint() string {
	if !d.known {
		return ""
	}
	h := sha256.New()
	for _, p := range d.paths {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	h.Write(d.raw)
	return hex.EncodeToString(h.Sum(nil))
}

// touchedSet is diffFacts.paths as the RunResult.Touched map; nil when git could not answer (no repo, no git): then every finding counts. A clean tree is an empty set, not nil: nothing was touched, so every finding is baseline.
func (d diffFacts) touchedSet() map[string]bool {
	if !d.known {
		return nil
	}
	out := map[string]bool{}
	for _, p := range d.paths {
		out[filepath.ToSlash(filepath.Clean(p))] = true
	}
	return out
}

// touched reports whether a tool's path token names a touched file: tools print worktree-relative paths (ruff, tsc, cargo, go vet's ./pkg/f.go, eslint's absolute filePath); anything under a touched directory counts too (an untracked directory lists as "dir/").
func touched(set map[string]bool, worktree, file string) bool {
	if set == nil {
		return true
	}
	p := file
	if filepath.IsAbs(p) {
		if rel, err := filepath.Rel(worktree, p); err == nil {
			p = rel
		}
	}
	p = filepath.ToSlash(filepath.Clean(p))
	if set[p] {
		return true
	}
	for dir := path.Dir(p); dir != "." && dir != "/"; dir = path.Dir(dir) {
		if set[dir+"/"] || set[dir] {
			return true
		}
	}
	return false
}
