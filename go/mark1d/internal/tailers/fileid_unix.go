//go:build unix

package tailers

import (
	"io/fs"
	"syscall"
)

// FileID is file identity — (dev, inode) on unix (04 §2.1) — so cursors
// survive renames and rotation is detectable when a path's identity changes
// under a held handle. fileid_windows.go declares the same type and refuses to
// produce a value, for the reason given there.
type FileID struct {
	Dev uint64
	Ino uint64
}

func fileID(fi fs.FileInfo) (FileID, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return FileID{}, false
	}
	return FileID{Dev: uint64(st.Dev), Ino: uint64(st.Ino)}, true
}
