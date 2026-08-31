//go:build unix

// The M1PL transport ENDPOINT on unix (07 §5): socket-path resolution and the
// 0600/0700 permission boundary. The accept loop that consumes the listener is
// platform-independent and lives in server.go; only what follows is genuinely
// tied to a filesystem with mode bits and a uid. Windows named pipes
// (\\.\pipe\omium-mark1-<user-SID>, 07 §5) are their own row — listener_windows.go
// refuses until it lands, so the surface is missing rather than approximated.
package fabric

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

// SocketPath resolves 07 §5's transport endpoint: $XDG_RUNTIME_DIR/omium-mark1/m1p.sock,
// falling back to ~/.omium/mark1/m1p.sock. (08 §4.1's older mark1d.sock name
// lost the R-2 reconciliation, 04 §0.4 — 07 is authoritative.)
func SocketPath() (string, error) {
	if rd := os.Getenv("XDG_RUNTIME_DIR"); rd != "" {
		return filepath.Join(rd, "omium-mark1", "m1p.sock"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".omium", "mark1", "m1p.sock"), nil
}

// Listen creates the UDS with 07 §5's boundary: parent directory 0700 owned
// by this user, socket 0600, and a hard refusal — not a chmod-and-continue —
// when an existing parent grants group/world anything or belongs to someone
// else. The fabric's threat model is other users; a permissive parent is the
// one hole the mode bits exist to close.
func Listen(path string) (net.Listener, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("fabric: %s is not a directory", dir)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("fabric: refusing socket dir %s with mode %o — 07 §5 requires 0700, no group or world grant, ever", dir, fi.Mode().Perm())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		return nil, fmt.Errorf("fabric: socket dir %s owned by uid %d, not this user", dir, st.Uid)
	}
	// A stale socket from a dead daemon blocks bind; anything else at the
	// path is not ours to delete.
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("fabric: %s exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = l.Close()
		return nil, err
	}
	return l, nil
}
