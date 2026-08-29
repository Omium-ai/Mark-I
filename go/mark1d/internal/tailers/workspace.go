package tailers

import (
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

// NewWorkspaceSet canonicalizes the enabled roots. The .mark1ignore layer
// (gitignore syntax at the workspace root, 04 §2.1) rides the enable-flow
// row that writes the file; until a workspace can have one, roots are the
// whole oracle.
func NewWorkspaceSet(roots ...string) (WorkspaceSet, error) {
	ws := rootSet{}
	for _, r := range roots {
		abs, err := filepath.Abs(r)
		if err != nil {
			return nil, err
		}
		if resolved, err := filepath.EvalSymlinks(abs); err == nil {
			abs = resolved
		}
		ws = append(ws, abs)
	}
	return ws, nil
}

type rootSet []string

func (rs rootSet) Roots() []string { return append([]string(nil), rs...) }

func (rs rootSet) Allowed(absPath string) bool {
	// Symlinks resolve BEFORE the containment check — a link inside a root
	// pointing outside it must not widen the oracle.
	if resolved, err := filepath.EvalSymlinks(absPath); err == nil {
		absPath = resolved
	}
	for _, root := range rs {
		if absPath == root || strings.HasPrefix(absPath, root+string(filepath.Separator)) {
			return true
		}
	}
	return false
}
