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
	// dev_t is uint64 on linux but int32 on darwin, so this widening is only
	// flagged on darwin. Narrowing through uint32 to silence it would truncate a
	// genuinely 64-bit linux dev_t and collide file identities in the tailer,
	// which is the one thing FileID exists to keep apart.
	//nolint:gosec // G115: dev_t is an opaque non-negative device id; darwin cannot sign-extend it
	return FileID{Dev: uint64(st.Dev), Ino: uint64(st.Ino)}, true
}
