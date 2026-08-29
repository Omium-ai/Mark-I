package tailers

import (
	"bufio"
	"errors"
	"io"
	"os"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

// maxLine bounds one transcript line's accumulation. Usage lines are tiny;
// only pathological content lines approach this, and they carry nothing the
// tailer reads — skipped whole rather than ballooning memory.
// ponytail: 16 MiB flat cap, no accounting per skipped line; a Dropped{}
// reason if a real transcript ever ships usage on a line this large.
const maxLine = 16 << 20

// Tailer follows one transcript stream — a session's main transcript or one
// subagent transcript, each its own stream under the parent session_id
// (04 §2.1). It owns the file handle, the cursor and the dedupe state.
type Tailer struct {
	path     string
	stateDir string
	str      stream

	f    *os.File
	id   FileID
	off  int64 // first unconsumed byte: always a fully-emitted line boundary
	gone bool  // path vanished (vendor retention sweep); drained and done
}

func newTailer(path, stateDir string, str stream) (*Tailer, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	id, ok := fileID(fi)
	if !ok {
		f.Close()
		return nil, errors.New("tailers: no file identity on this platform")
	}
	t := &Tailer{path: path, stateDir: stateDir, str: str, f: f, id: id}
	// Resume-after-restart (04 §2.1): a matching-identity cursor resumes;
	// a shrunken file re-scans from 0 — replays are safe, so the cheap
	// response is the correct one.
	if c, ok := loadCursor(stateDir, id); ok && c.Offset <= fi.Size() {
		t.off = c.Offset
	}
	return t, nil
}

// poll advances the stream: rotation and truncation checks first, then every
// complete new line through the dedupe core, quiesce last. Emissions go
// through emit in order; the cursor is persisted only when a flush left
// nothing pending, so the saved offset never points past an unemitted key.
func (t *Tailer) poll(now time.Time, emit func([]*m1pv1.Event) error) error {
	if t.gone {
		return nil
	}
	fi, statErr := os.Stat(t.path)
	switch {
	case statErr != nil:
		if !errors.Is(statErr, os.ErrNotExist) {
			return statErr
		}
		// Vendor retention sweep (08 §5.1): drain what the held inode still
		// serves, flush, done. The coverage-gap CoverageTransition for
		// tailer-downtime gaps rides the coverage package's row (04 §2.7).
		if err := t.readLines(now, emit); err != nil {
			return err
		}
		t.gone = true
		return t.flushAndSave(emit)
	default:
		id, ok := fileID(fi)
		if ok && id != t.id {
			// Rotation: drain the old handle to EOF — the old inode stays
			// readable while held, so nothing is lost — then follow the new
			// identity from offset 0 (04 §2.1).
			if err := t.readLines(now, emit); err != nil {
				return err
			}
			f, err := os.Open(t.path)
			if err != nil {
				return err
			}
			t.f.Close()
			t.f, t.id, t.off = f, id, 0
		} else if fi.Size() < t.off {
			// Truncation: same identity, shorter file ⇒ rewritten in place.
			// Re-scan from 0; idem_key makes the replay billing-safe.
			t.off = 0
		}
	}
	if err := t.readLines(now, emit); err != nil {
		return err
	}
	if evs := t.str.quiet(now); len(evs) > 0 {
		if err := emit(evs); err != nil {
			return err
		}
		return t.save(now)
	}
	return nil
}

// flushAndSave is the Stop/shutdown drain: everything pending emits now
// (04 §2.1 emission trigger 3), then the cursor lands at the drained offset.
func (t *Tailer) flushAndSave(emit func([]*m1pv1.Event) error) error {
	if evs := t.str.flush(); len(evs) > 0 {
		if err := emit(evs); err != nil {
			return err
		}
	}
	return t.save(time.Now())
}

func (t *Tailer) save(now time.Time) error {
	return saveCursor(t.stateDir, Cursor{Path: t.path, FileID: t.id, Offset: t.off, SavedAt: now})
}

func (t *Tailer) close() {
	t.f.Close()
}

// readLines consumes every complete ('\n'-terminated) line past the cursor.
// A partial tail line is left unconsumed for the next poll — the offset only
// ever advances over whole lines. When a batch of emissions ends with nothing
// pending, the cursor is persisted (04 §2.1: after every emitted Usage flush).
func (t *Tailer) readLines(now time.Time, emit func([]*m1pv1.Event) error) error {
	if _, err := t.f.Seek(t.off, io.SeekStart); err != nil {
		return err
	}
	rd := bufio.NewReaderSize(t.f, 64<<10)
	var (
		line    = make([]byte, 0, 4<<10)
		lineLen int64 // bytes of the current line consumed so far, discarded overflow included
		emitted bool
	)
scan:
	for {
		chunk, err := rd.ReadSlice('\n')
		lineLen += int64(len(chunk))
		if len(line) <= maxLine {
			// Accumulate only under the cap; an oversize line is still
			// CONSUMED in full (the bound caps memory, never stalls the
			// stream) but is never parsed from a truncation.
			line = append(line, chunk...)
		}
		switch {
		case err == nil: // complete line
			t.off += lineLen
			if len(line) <= maxLine {
				if evs := t.str.consume(line, now); len(evs) > 0 {
					if err := emit(evs); err != nil {
						return err
					}
					emitted = true
				}
			}
			line, lineLen = line[:0], 0
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF):
			// The partial tail line stays unconsumed for the next poll.
			break scan
		default:
			return err
		}
	}
	if emitted && len(t.str.pending) == 0 {
		return t.save(now)
	}
	return nil
}
