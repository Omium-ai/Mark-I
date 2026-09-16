//go:build unix

// Package harden is mark1d's own NFR-SECURITY-002 arm: RLIMIT_CORE=0 and, on
// Linux, PR_SET_DUMPABLE=0, applied before any spool, socket or key is opened
// (04 §11.6, 10 §4.1). The daemon holds no upstream credential, but a core of
// it is the device signing key, the spill-unseal key and every spooled event
// in the clear. Twin of rust/mark1-harden; the anchor CHILD's own cap lives in
// anchors/sandbox_linux.go.
//
// The limits are inherited by everything mark1d spawns — cortexd, the proxy,
// the anchor sandbox helper. Each re-applies {0,0} for itself, which is a
// no-op on an inherited {0,0}; what NO child may do afterwards is raise the
// hard limit, because that is EPERM without CAP_SYS_RESOURCE.
package harden

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// Apply sets the limits and reads them back through independent syscalls: a
// container runtime or LSM can accept setrlimit/prctl and not honour them,
// so the return codes alone are not the proof.
func Apply() error {
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		return fmt.Errorf("harden: setrlimit(RLIMIT_CORE): %w", err)
	}
	var got unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &got); err != nil {
		return fmt.Errorf("harden: getrlimit(RLIMIT_CORE): %w", err)
	}
	if got.Cur != 0 || got.Max != 0 {
		return errors.New("harden: RLIMIT_CORE did not stick at 0")
	}
	return notDumpable()
}
