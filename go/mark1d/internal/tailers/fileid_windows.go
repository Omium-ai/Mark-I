package tailers

import (
	"os"
	"syscall"
)

// FileID's Windows form is (volume serial, file index) — 07 §5's counterpart to
// the unix (dev, inode). It comes from GetFileInformationByHandle against an
// OPEN HANDLE, which is why fileID takes the *os.File and not an fs.FileInfo:
// os.Stat's Sys() here is a *Win32FileAttributeData carrying timestamps and
// attributes and no identity at all, and os.SameFile compares identities
// without ever handing one back — this type is both a JSON field on the
// persisted cursor and a component of the cursor's filename.
type FileID struct {
	Dev uint64
	Ino uint64
}

func fileID(f *os.File) (FileID, bool) {
	var d syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(syscall.Handle(f.Fd()), &d); err != nil {
		return FileID{}, false
	}
	return FileID{Dev: uint64(d.VolumeSerialNumber), Ino: uint64(d.FileIndexHigh)<<32 | uint64(d.FileIndexLow)}, true
}
