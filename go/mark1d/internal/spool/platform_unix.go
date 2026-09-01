//go:build unix

// The two syscalls 07 §6 needs and the standard library does not portably
// offer: an inter-process file lock and free-space accounting. Split by
// platform on the pattern fabric/listener_windows.go already sets, so the
// windows-2022 CI leg keeps compiling this package.
package spool

import (
	"os"

	"golang.org/x/sys/unix"
)

// lockExclusive is non-blocking on purpose: a second daemon must refuse to
// boot with a diagnostic, not queue behind the first and start writing the
// moment it exits. flock rather than a pidfile because the kernel drops it
// when the holder dies by ANY means, kill -9 included — a lock needing manual
// cleanup after every crash is its own outage, and 04 §11.4 says crashes are
// routine here (launchd kills mark1d during sleep).
func lockExclusive(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
}

// diskUsedRatio reports the fraction of dir's filesystem unavailable to this
// process. Bavail, not Bfree: the root-reserved blocks are not ours to spend,
// so counting them as free would let the spool run the disk down to the
// reserve — stricter than df's Use%, in the direction NFR-FOOTPRINT-002 wants.
func diskUsedRatio(dir string) (float64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, err
	}
	if st.Blocks == 0 {
		return 0, nil
	}
	return 1 - float64(st.Bavail)/float64(st.Blocks), nil
}
