package tailers

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Cursor is persisted after every emitted Usage flush (atomic write+rename,
// fsync'd), keyed by file identity — not path — so rotation is detectable
// (04 §2.1). Offset always sits at a fully-emitted line boundary with nothing
// pending, so a crash between flushes only ever replays — and replays are
// free: idem_key upserts at ingest (07 §7).
type Cursor struct {
	Path    string    `json:"path"`
	FileID  FileID    `json:"file_id"`
	Offset  int64     `json:"offset"`
	SavedAt time.Time `json:"saved_at"`
}

func cursorPath(stateDir string, id FileID) string {
	return filepath.Join(stateDir, fmt.Sprintf("cur-%x-%x.json", id.Dev, id.Ino))
}

func loadCursor(stateDir string, id FileID) (Cursor, bool) {
	b, err := os.ReadFile(cursorPath(stateDir, id))
	if err != nil {
		return Cursor{}, false
	}
	var c Cursor
	if json.Unmarshal(b, &c) != nil || c.FileID != id {
		// A corrupt or mismatched cursor costs a re-scan from 0, never data
		// (04 §2.1 resume rule) — discard rather than trust.
		return Cursor{}, false
	}
	return c, true
}

func saveCursor(stateDir string, c Cursor) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	path := cursorPath(stateDir, c.FileID)
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
