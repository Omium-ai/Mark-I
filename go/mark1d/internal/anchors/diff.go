package anchors

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

// diffFacts is AnchorIntegrity's touched-file input (06 §2.4), read with hardened git (gitread.go) since CortexInjection carries only root_hash.
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

// git runs one hardened git command (gitread.go), in the sandbox or through the 10 §7.5 fallback; no git or a failing git ⇒ false, never a guess.
func (r *Runner) git(ctx context.Context, worktree string, args ...string) ([]byte, bool) {
	ov, g := r.gitOverrides(ctx, worktree)
	if g.abstain != "" {
		return nil, false
	}
	g = r.gitRun(ctx, worktree, ov, args...)
	return g.out, g.abstain == ""
}

// Git is git for callers outside the package (16 L8's outcome labels): the same hardened read.
func (r *Runner) Git(ctx context.Context, worktree string, args ...string) ([]byte, bool) {
	return r.git(ctx, worktree, args...)
}

// TaskDiff is the task diff without a task (TaskDiffFor has one): the worktree against HEAD with 3 lines of context, the shape its training patches carry, then every untracked file as a new-file section; nil when there is nothing to show, and diff_status.json says why.
func (r *Runner) TaskDiff(ctx context.Context, worktree string) []byte {
	t := r.readTree(ctx, worktree, 3, [16]byte{})
	if t.abstain != "" {
		return nil
	}
	return t.raw
}

// diff reads git status and the task's diff (from its open-time base) in one readTree; no git, no repository or a failing status ⇒ UNSPECIFIED, never a guess.
func (r *Runner) diff(ctx context.Context, worktree string, task [16]byte) diffFacts {
	t := r.readTree(ctx, worktree, 0, task)
	if !t.known {
		return diffFacts{}
	}
	delta := suppressionDelta(t.raw)
	return diffFacts{class: classifyDiff(t.paths, delta), delta: delta, raw: t.raw, paths: t.paths, known: true}
}

// fingerprint names the state of the tree these facts describe: the status paths plus the diff against HEAD, untracked files' content included; empty when git could not answer.
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
