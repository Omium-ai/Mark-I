//go:build unix

package tailers

import (
	"os"
	"syscall"
)

// FileID is file identity — (dev, inode) on unix (04 §2.1) — so cursors
// survive renames and rotation is detectable when a path's identity changes
// under a held handle. fileid_windows.go declares the same type over
// (volume serial, file index); both are read off an OPEN HANDLE, the one
// lifetime the two platforms share.
type FileID struct {
	Dev uint64
	Ino uint64
}

func fileID(f *os.File) (FileID, bool) {
	fi, err := f.Stat()
	if err != nil {
		return FileID{}, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return FileID{}, false
	}
	// dev_t is uint64 on linux but int32 on darwin, so this widening is only
	// flagged on darwin. Narrowing through uint32 to silence it would truncate a
	// genuinely 64-bit linux dev_t and collide file identities in the tailer,
	// which is the one thing FileID exists to keep apart.
	//nolint:gosec // G115: dev_t is an opaque non-negative device id; darwin cannot sign-extend it
	return FileID{Dev: uint64(st.Dev), Ino: uint64(st.Ino)}, true
}
