//go:build linux

package anchors

import (
	"context"
	"testing"

	"golang.org/x/sys/unix"
)

// TestSandboxRunsUnderAHardenedParent: harden.Apply (cmd/main.go) leaves the daemon non-dumpable; the helper must still clone (the kernel refuses a non-dumpable parent's uid_map write) and the hardened posture must be back afterwards.
func TestSandboxRunsUnderAHardenedParent(t *testing.T) {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	sb := NewSandbox(t.TempDir())
	if _, err := sb.Run(context.Background(), RunSpec{Argv: []string{"/bin/true"}, WorktreeRO: t.TempDir()}); err != nil {
		t.Fatalf("non-dumpable parent: %v", err)
	}
	if got, _ := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0); got != 0 {
		t.Fatalf("dumpable=%d after the run, want the hardened 0 restored", got)
	}
}
