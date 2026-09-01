// The on-disk workspace allow-list seam. <state>/workspaces.json is WRITTEN
// by `mark1 enable` (go/mark1/internal/cli — that file DEFINES the format and
// its canonicalization; this reader consumes it byte-compatibly and never
// writes it: the CLI and the daemon talk via files, never imports, 13 §1).
// LiveSet is the runtime half: the same WorkspaceSet oracle (04 §0.3
// invariant 3), but with roots the daemon can swap when the file changes —
// enable/disable while running must move the oracle without a restart.
package tailers

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"
)

// workspacesFile mirrors go/mark1/internal/cli.Workspaces field for field —
// the CLI's format wins; only Path is consumed here.
type workspacesFile struct {
	Version    int `json:"version"`
	Workspaces []struct {
		Path      string    `json:"path"`
		EnabledAt time.Time `json:"enabled_at"`
	} `json:"workspaces"`
}

// LoadWorkspacesFile reads the enable-list's roots. A missing file is an
// empty allow-list (nothing enabled yet), not an error; a group/world-
// accessible file is refused like every credential-class state file (the
// identity.FileCustody discipline) — a loosely-writable allow-list would let
// another user widen what capture reads. Windows permission bits are
// decoration; the check is unix-only there too.
func LoadWorkspacesFile(path string) ([]string, error) {
	fi, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s has mode %o; must be 0600 — refusing to read it", path, fi.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var ws workspacesFile
	if err := json.Unmarshal(data, &ws); err != nil {
		return nil, fmt.Errorf("%s is corrupt: %w", path, err)
	}
	roots := make([]string, 0, len(ws.Workspaces))
	for _, w := range ws.Workspaces {
		if w.Path != "" {
			roots = append(roots, w.Path)
		}
	}
	return roots, nil
}

// LiveSet is a WorkspaceSet whose root set can be replaced at runtime — the
// oracle every running Manager holds, so a disable narrows discovery for ALL
// tailers the instant the daemon reloads the file, and an enable widens it
// without restarting anything.
type LiveSet struct {
	mu sync.RWMutex
	rs rootSet
}

func NewLiveSet() *LiveSet { return &LiveSet{} }

// SetRoots swaps the whole set through the SAME constructor NewWorkspaceSet
// uses (abs + symlinks resolved — 04 §11's canonicalize-then-check — and each
// root's .mark1ignore attached), so the long-running daemon's oracle is never
// the weaker of the two. A root that fails to resolve is dropped from the
// set, never kept stale.
func (l *LiveSet) SetRoots(roots []string) error {
	rs, err := newRootSet(roots)
	if err != nil {
		return err
	}
	l.mu.Lock()
	l.rs = rs
	l.mu.Unlock()
	return nil
}

func (l *LiveSet) Allowed(absPath string) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.rs.Allowed(absPath)
}

func (l *LiveSet) Roots() []string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.rs.Roots()
}
