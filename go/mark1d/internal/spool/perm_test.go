package spool

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// wantPerm is the whole point of this file: the spool sets four modes
// (spool.go:190 dir, spool.go:229 lock, spool.go:626 segment, recovery.go:15
// ledger) and until now nothing ever read one back, so a regression to 0644
// would have been completely silent.
func wantPerm(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := fi.Mode().Perm(); got != want {
		t.Errorf("%s mode %04o, want %04o — NFR-SECURITY-007 requires spool artifacts owner-only (0700 dirs, 0600 files)", path, got, want)
	}
}

// TestSpoolDirAndSegmentsAreOwnerOnly pins NFR-SECURITY-007 for the spool.
// cfg.Dir is a SUBDIRECTORY of the temp dir on purpose: MkdirAll on a path that
// already exists returns nil without touching the mode, so pointing it at
// t.TempDir() (itself 0700) would make the directory assertion vacuous.
func TestSpoolDirAndSegmentsAreOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permission bits only")
	}
	dir := filepath.Join(t.TempDir(), "spool")
	s, err := Open(testConfig(dir, 1<<16, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	// A real record + Sync, so the segment under test is one that was written
	// through, not just an empty file Open happened to mint.
	mustAppend(t, s, 1, ClassBilling, []byte("owner-only"))
	if err := s.Sync(); err != nil {
		t.Fatal(err)
	}

	// Positive control: an artifact this test creates AT the required mode must
	// pass, so a failure below is a real mode regression and not a stat that
	// cannot see the file or a path that never existed.
	control := filepath.Join(dir, "control")
	if err := os.WriteFile(control, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	wantPerm(t, control, 0o600)

	wantPerm(t, dir, 0o700)                                // spool.go:190
	wantPerm(t, segPath(dir, 1), 0o600)                    // spool.go:626
	wantPerm(t, filepath.Join(dir, "spool.ledger"), 0o600) // recovery.go:15
	wantPerm(t, filepath.Join(dir, lockName), 0o600)       // spool.go:229
}
