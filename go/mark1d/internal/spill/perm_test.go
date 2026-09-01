package spill

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// wantPerm reads a mode back. Open sets two (spill.go:111 dir, spill.go:120
// pubkey) and delegates a third to identity.FileCustody; nothing asserted any
// of them, so a regression to 0644 on the key the shim seals to would have been
// silent.
func wantPerm(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := fi.Mode().Perm(); got != want {
		t.Errorf("%s mode %04o, want %04o — NFR-SECURITY-007 requires spill artifacts owner-only (0700 dirs, 0600 files)", path, got, want)
	}
}

// TestSpillRingAndPubAreOwnerOnly pins NFR-SECURITY-007 for the spill side.
// newRig's stateDir is a fresh t.TempDir, so <stateDir>/spill is genuinely
// created by Open's MkdirAll rather than pre-existing — a pre-existing path
// makes MkdirAll a no-op and the directory assertion vacuous.
func TestSpillRingAndPubAreOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permission bits only")
	}
	_, _, _, stateDir := newRig(t)
	dir := filepath.Join(stateDir, "spill")

	// Positive control: an artifact created AT the required mode must pass, so
	// a failure below is a real mode regression and not a broken stat or path.
	control := filepath.Join(dir, "control")
	if err := os.WriteFile(control, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	wantPerm(t, control, 0o600)

	wantPerm(t, dir, 0o700)                             // spill.go:111
	wantPerm(t, filepath.Join(dir, "spill.pub"), 0o600) // spill.go:120
	// The private half is minted through identity.FileCustody (04 §2.9's 0600
	// floor); its mode constant lives outside this package but the artifact is
	// the spill's, and a loose key here is the same breach.
	wantPerm(t, filepath.Join(stateDir, "spill.key"), 0o600)
}
