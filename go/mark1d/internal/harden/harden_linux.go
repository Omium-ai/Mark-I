package harden

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// notDumpable clears the dumpable flag and reads it back as the kernel
// reports it. Non-dumpable also defeats same-user ptrace and turns
// /proc/<pid>/{mem,maps,environ,fd} root-only (10 §4.1).
func notDumpable() error {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("harden: prctl(PR_SET_DUMPABLE): %w", err)
	}
	got, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil {
		return fmt.Errorf("harden: prctl(PR_GET_DUMPABLE): %w", err)
	}
	if got != 0 {
		return errors.New("harden: PR_SET_DUMPABLE did not stick at 0")
	}
	return nil
}
