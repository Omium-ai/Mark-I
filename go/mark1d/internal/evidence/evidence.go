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
type Store struct{ dir string }

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
	return &Store{dir: dir}, nil
}

// Put files one run as <dir>/<task hex>/<anchor id>-<ns>/{stdout,stderr,diff} (0600, empty parts skipped); ponytail: no retention, age out by mtime when disk notices.
func (s *Store) Put(task [16]byte, anchorID string, stdout, stderr, diff []byte) (string, error) {
	if s == nil {
		return "", nil
	}
	run := filepath.Join(s.dir, hex.EncodeToString(task[:]), anchorID+"-"+strconv.FormatInt(time.Now().UnixNano(), 10))
	if err := os.MkdirAll(run, 0o700); err != nil {
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
