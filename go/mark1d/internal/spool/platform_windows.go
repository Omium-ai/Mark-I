package spool

import (
	"os"

	"golang.org/x/sys/windows"
)

// lockExclusive: see the unix twin. LockFileEx on a byte range the daemon
// never reads, released by the OS when the handle closes — including on an
// abrupt process death, so no stale lock survives a crash. os.OpenFile shares
// the file for read and write on Windows, so the open itself excludes nothing.
//
// The locked byte sits past the pid text lockDir writes at offset 0. Windows
// byte-range locks are mandatory and per handle, so a lock over byte 0 would
// make the loser's ReadFile of the pid fail with ERROR_LOCK_VIOLATION and
// every refusal would read "holder pid unrecorded". A byte beyond EOF is a
// legal lock target.
func lockExclusive(f *os.File) error {
	ov := windows.Overlapped{Offset: 1 << 20}
	return windows.LockFileEx(windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &ov)
}

// diskUsedRatio: freeBytesAvailableToCaller, not totalNumberOfFreeBytes — a
// per-user quota makes them differ, and only the former is space the spool may
// actually spend (the unix twin's Bavail choice, same reason).
func diskUsedRatio(dir string) (float64, error) {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return 0, err
	}
	var freeToCaller, total, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(p, &freeToCaller, &total, &totalFree); err != nil {
		return 0, err
	}
	if total == 0 {
		return 0, nil
	}
	return 1 - float64(freeToCaller)/float64(total), nil
}
