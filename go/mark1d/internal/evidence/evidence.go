// Package evidence is the raw local evidence store (NFR-PRIVACY-005): <state>/evidence/ (0700), device-local, never on an Event.
package evidence

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// Store writes under one 0700 directory; a nil *Store stores nothing.
type Store struct{ dir, state string }

// Dir is the store's location under the daemon state root.
func Dir(stateDir string) string { return filepath.Join(stateDir, "evidence") }

// Open creates (or re-tightens) the directory at 0700.
func Open(stateDir string) (*Store, error) {
	dir := Dir(stateDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: a directory needs x; 0700 is the NFR-PRIVACY-005 mode
		return nil, err
	}
	return &Store{dir: dir, state: stateDir}, nil
}

// Retention is the founder's 30 d ruling (2026-09-16): a run older than that is swept at boot, and a task dir left empty with it.
const Retention = 30 * 24 * time.Hour

// Sweep removes runs older than Retention and the task dirs they empty; the count of runs removed is returned for the log.
func (s *Store) Sweep(now time.Time) int {
	if s == nil {
		return 0
	}
	tasks, err := os.ReadDir(s.dir)
	if err != nil {
		return 0
	}
	n := 0
	for _, t := range tasks {
		if !t.IsDir() {
			continue
		}
		dir := filepath.Join(s.dir, t.Name())
		runs, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		left := 0
		for _, r := range runs {
			info, err := r.Info()
			if err != nil {
				left++
				continue
			}
			if now.Sub(info.ModTime()) > Retention && os.RemoveAll(filepath.Join(dir, r.Name())) == nil {
				n++
				continue
			}
			left++
		}
		if left == 0 {
			_ = os.Remove(dir)
		}
	}
	return n
}

// Put files one run as <dir>/<task hex>/<anchor id>-<ns>/{stdout,stderr,diff} (0600, empty parts skipped).
func (s *Store) Put(task [16]byte, anchorID string, stdout, stderr, diff []byte) (string, error) {
	if s == nil {
		return "", nil
	}
	parent := filepath.Join(s.dir, hex.EncodeToString(task[:]))
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return "", err
	}
	// MkdirTemp, not the nanosecond clock alone: two runs of one anchor inside a Windows clock tick (≈1 ms) named the same dir and the second overwrote the first
	run, err := os.MkdirTemp(parent, anchorID+"-"+strconv.FormatInt(time.Now().UnixNano(), 10)+"-")
	if err != nil {
		return "", err
	}
	for name, b := range map[string][]byte{"stdout": stdout, "stderr": stderr, "diff": diff} {
		if len(b) == 0 {
			continue
		}
		if err := os.WriteFile(filepath.Join(run, name), b, 0o600); err != nil {
			return "", err
		}
	}
	return run, nil
}
