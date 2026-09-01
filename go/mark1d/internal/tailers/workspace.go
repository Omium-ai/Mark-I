package tailers

import (
	"os"
	"path/filepath"
	"strings"
)

// WorkspaceSet answers "may I read this path?" — the 04 §0.3 invariant-3
// oracle, consulted on every file DISCOVERY, not just once. A transcript
// whose cwd resolves outside an enabled root is not opened, full stop.
type WorkspaceSet interface {
	Allowed(absPath string) bool
	Roots() []string
}

// NewWorkspaceSet canonicalizes the enabled roots and attaches each root's
// .mark1ignore (mark1ignore.go) — together the two halves of the oracle
// 04 §2.1 specifies: "canonicalized enabled roots + .mark1ignore (gitignore
// syntax, evaluated at the workspace root)". The daemon reads the file off
// disk itself; nothing has to be written at enable time for it to take
// effect, and a file written mid-session takes effect on the next consult.
func NewWorkspaceSet(roots ...string) (WorkspaceSet, error) {
	rs, err := newRootSet(roots)
	if err != nil {
		return nil, err
	}
	return rs, nil
}

// root is one enabled workspace: its canonical path plus the live view of its
// exclusion file.
type root struct {
	path   string
	ignore *ignoreCache
}

type rootSet []root

func newRootSet(roots []string) (rootSet, error) {
	rs := make(rootSet, 0, len(roots))
	for _, r := range roots {
		abs, err := filepath.Abs(r)
		if err != nil {
			return nil, err
		}
		if resolved, err := filepath.EvalSymlinks(abs); err == nil {
			abs = resolved
		}
		rs = append(rs, root{path: abs, ignore: &ignoreCache{dir: abs}})
	}
	return rs, nil
}

func (rs rootSet) Roots() []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.path)
	}
	return out
}

func (rs rootSet) Allowed(absPath string) bool {
	// Symlinks resolve BEFORE the containment check — a link inside a root
	// pointing outside it must not widen the oracle. The ignore check then
	// runs on the RESOLVED path, so a symlink cannot launder an excluded
	// subtree into an allowed name either.
	if resolved, err := filepath.EvalSymlinks(absPath); err == nil {
		absPath = resolved
	}
	allowed := false
	for _, r := range rs {
		if absPath != r.path && !strings.HasPrefix(absPath, r.path+string(filepath.Separator)) {
			continue
		}
		ig, err := r.ignore.current()
		if err != nil {
			return false // fail-closed: an unreadable consent record excludes
		}
		if ig != nil {
			rel, rerr := filepath.Rel(r.path, absPath)
			if rerr != nil {
				return false
			}
			if ig.match(filepath.ToSlash(rel), isDirOrUnknown(absPath)) {
				return false
			}
		}
		// Enrolled roots can nest; any enclosing root that excludes the path
		// wins, so the loop runs to the end rather than returning early.
		allowed = true
	}
	return allowed
}

// isDirOrUnknown supplies the dirness that `dir/` rules need. A path that
// cannot be stat'ed counts as a directory: that is the answer that lets a
// `dir/` rule MATCH, i.e. the read-less direction.
func isDirOrUnknown(p string) bool {
	fi, err := os.Stat(p)
	return err != nil || fi.IsDir()
}
