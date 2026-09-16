//go:build unix

package harden

import (
	"testing"

	"golang.org/x/sys/unix"
)

// TestApplyReadsBack is the daemon half of 12 §9 row 2 (NFR-SECURITY-002):
// the limits the kernel consults before writing a core, read back through a
// second, independent path so the assertion does not rest on the code that
// set them. Calling Apply twice is the shape every supervised child sees —
// mark1d hardens, the child inherits {0,0}, then applies its own. The Linux
// dumpable half is TestApplyClearsDumpable.
func TestApplyReadsBack(t *testing.T) {
	if err := Apply(); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := Apply(); err != nil {
		t.Fatalf("Apply is not idempotent: %v", err)
	}
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &lim); err != nil {
		t.Fatal(err)
	}
	if lim.Cur != 0 {
		t.Errorf("soft RLIMIT_CORE = %d, want 0", lim.Cur)
	}
	if lim.Max != 0 {
		t.Errorf("hard RLIMIT_CORE = %d, want 0 — a raisable hard limit is not a control", lim.Max)
	}
}
