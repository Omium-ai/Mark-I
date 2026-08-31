package tailers

import "io/fs"

// FileID's Windows form is (volume serial, file index) — 07 §5's counterpart to
// the unix (dev, inode) — and it is NOT derivable from an fs.FileInfo. Go's
// os.Stat fills Sys() with a *syscall.Win32FileAttributeData, which carries
// timestamps and attributes and no identity at all; the volume serial and file
// index come from GetFileInformationByHandle against an OPEN HANDLE, which is a
// different call with a different lifetime than this signature has.
//
// os.SameFile does compare Windows identity internally, but it compares — it
// cannot hand back a value, and this type is both a JSON field on the persisted
// cursor and a component of the cursor's filename. A comparison does not
// serialize.
//
// So the honest answer is (zero, false), which is not a stub: NewTailer already
// treats !ok as "no file identity on this platform" and refuses to construct a
// tailer at all. Nothing here degrades into following a file it cannot identify
// across a rotation — the one failure mode the ID exists to prevent.
type FileID struct {
	Dev uint64
	Ino uint64
}

func fileID(fs.FileInfo) (FileID, bool) { return FileID{}, false }
