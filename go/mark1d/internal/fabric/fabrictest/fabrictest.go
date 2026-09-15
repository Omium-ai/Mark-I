// Package fabrictest is test support for code that binds the M1PL unix socket:
// the net/http/httptest shape, a sibling package so internal/fabric's own
// tests can use it without a cycle. It imports nothing from fabric.
package fabrictest

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// sunPathMax is the shortest sun_path capacity across supported unixes: 104 on
// Darwin/BSD (108 on Linux), minus the NUL terminator. Pinned as a literal
// rather than read from syscall so the helper is portable and dependency-free;
// fabric.Listen carries the per-platform check.
const sunPathMax = 103

// SocketDir returns a scratch directory short enough that <dir>/run/m1p.sock
// fits sun_path on every platform. t.TempDir() is fine on Linux (/tmp/<Test>...)
// but on macOS lives under /var/folders/<xx>/<long>/T/<Test>.../NNN, which
// overflows the 104-byte Darwin limit and makes bind fail with EINVAL — so on
// darwin it uses /tmp explicitly (user-writable, a symlink to /private/tmp).
// Only the socket needs this root; state, spool and HOME can stay in t.TempDir().
func SocketDir(t testing.TB) string {
	t.Helper()
	dir := ""
	if runtime.GOOS == "darwin" {
		var err error
		if dir, err = os.MkdirTemp("/tmp", "m1-"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
	} else {
		dir = t.TempDir()
	}
	if p := filepath.Join(dir, "run", "m1p.sock"); len(p) > sunPathMax {
		t.Fatalf("fabrictest: socket path %q is %d bytes, over the %d-byte sun_path limit — set TMPDIR shorter", p, len(p), sunPathMax)
	}
	return dir
}
