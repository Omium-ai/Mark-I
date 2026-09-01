package coverage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

// JournalPath is the CLI's local transition journal, restated here because
// go/mark1 and go/mark1d are separate modules and neither imports the other's
// internal/ — the STRING is the contract, exactly as it is for the OFF marker
// and the fabric socket. Must equal cli.Env.CoveragePath().
func JournalPath(stateDir string) string {
	return filepath.Join(stateDir, "coverage", "transitions.jsonl")
}

// cursorPath is how much of the journal this daemon has already receipted.
// A byte offset rather than a rename-and-consume, because the CLI appends with
// O_APPEND while the daemon reads: renaming out from under an already-open CLI
// fd silently loses the line it is mid-write on, and `mark1 off` losing its
// disable row is the exact failure this plane exists to prevent.
func cursorPath(stateDir string) string {
	return filepath.Join(stateDir, "coverage", "drain.cursor")
}

// journalLine is what go/mark1's three writers put on disk (cli.go's
// AppendCoverageTransition, fed by enable.Run, off.Run and off.On).
type journalLine struct {
	TS        string `json:"ts"`
	Kind      string `json:"kind"`
	Reason    string `json:"reason"`
	Workspace string `json:"workspace"`
	Scope     string `json:"scope"`
}

// DrainJournal receipts everything `mark1 enable`/`off`/`on` journalled since
// the last call, and returns how many transitions it emitted.
//
// Why a journal at all, rather than the CLI talking to the daemon: 08 §7.6 is
// categorical that `off` works with the daemon down and the network down —
// "there is no server round-trip on the critical path" — so the CLI cannot be
// the thing that signs. It writes an attributable local line; mark1d, which is
// where the device key lives, turns that line into a receipted event.
//
// The residual, stated rather than papered over: between the CLI's write and
// this drain the line is a 0600 file its owner can edit. The receipt chain
// makes every DRAINED transition tamper-evident, so the window is bounded by
// the drain interval — it does not close it. Closing it needs the CLI to hold
// a signing key, which 08 §7.6's daemon-down requirement and the keychain's
// custody model both argue against; it is a lead call, not a code cleanup.
func (e *Emitter) DrainJournal(ctx context.Context, stateDir string) (int, error) {
	if e == nil {
		return 0, ErrNotWired
	}
	path := JournalPath(stateDir)
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return 0, nil // nobody has ever run enable/off on this box
	}
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()

	off := readCursor(stateDir)
	if st, serr := f.Stat(); serr == nil && st.Size() < off {
		// The journal shrank: somebody truncated or replaced it. Re-reading
		// from zero re-emits transitions we already receipted, which the band
		// query absorbs (a repeated state is a zero-length interval) — whereas
		// trusting a stale cursor skips every line of the NEW file forever.
		off = 0
	}
	if _, err := f.Seek(off, 0); err != nil {
		return 0, err
	}
	tail, err := io.ReadAll(f)
	if err != nil {
		return 0, err
	}

	n := 0
	for {
		// Only NEWLINE-TERMINATED lines are complete. A trailing fragment is
		// the CLI mid-append: leave the cursor before it and read it whole on
		// the next tick, rather than receipting half a transition.
		i := bytes.IndexByte(tail, '\n')
		if i < 0 {
			break
		}
		raw, advance := tail[:i], int64(i)+1
		tail = tail[i+1:]

		kind, ws, reason, at, perr := e.parseLine(raw)
		if perr != nil {
			// Skipped, not retried: a line we cannot parse will not parse on
			// the next tick either, and wedging here would cost every LATER
			// transition too. Loud at the call site, never silent.
			off += advance
			_ = writeCursor(stateDir, off)
			return n, perr
		}
		if err := e.emit(ctx, kind, ws, reason, 0, at); err != nil {
			// Cursor NOT advanced: a shed or a parked spool is transient, and
			// this row is the evidence for a window the customer is billed on.
			_ = writeCursor(stateDir, off)
			return n, err
		}
		off += advance
		n++
	}
	return n, writeCursor(stateDir, off)
}

func (e *Emitter) parseLine(raw []byte) (m1pv1.CoverageKind, []byte, string, time.Time, error) {
	var l journalLine
	if err := json.Unmarshal(raw, &l); err != nil {
		return 0, nil, "", time.Time{}, fmt.Errorf("coverage: unparseable journal line: %w", err)
	}
	reason := l.Reason
	if reason == "" {
		// Journals written before the CLI stamped a reason. Recovered rather
		// than discarded: the two kinds the CLI can write map 1:1 onto the two
		// reason codes 04 §2.7 assigns it, so nothing is guessed.
		switch l.Kind {
		case "enable":
			reason = ReasonUserEnable
		case "disable":
			reason = ReasonMark1Off
		}
	}
	kind, ok := reasonKind[reason]
	if !ok {
		return 0, nil, "", time.Time{}, fmt.Errorf("coverage: journal line has no usable reason (kind %q, reason %q)", l.Kind, l.Reason)
	}
	at, err := time.Parse(time.RFC3339, l.TS)
	if err != nil {
		// The CLI's timestamp is the transition's REAL time; the daemon may
		// drain hours later. Falling back to now() would silently move a
		// window, so an unusable ts is a refusal.
		return 0, nil, "", time.Time{}, fmt.Errorf("coverage: journal line has an unusable ts %q: %w", l.TS, err)
	}
	surface := l.Workspace
	if surface == "" {
		surface = l.Scope
	}
	ws := DeviceWide()
	if surface != "" && surface != "all" {
		ws = e.WorkspaceID(surface)
	}
	return kind, ws, reason, at, nil
}

func readCursor(stateDir string) int64 {
	b, err := os.ReadFile(cursorPath(stateDir))
	if err != nil {
		return 0
	}
	n, err := strconv.ParseInt(string(bytes.TrimSpace(b)), 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

func writeCursor(stateDir string, off int64) error {
	if err := os.MkdirAll(filepath.Dir(cursorPath(stateDir)), 0o700); err != nil {
		return err
	}
	// ponytail: plain write, no atomic rename. A torn cursor parses as 0 and
	// re-emits the journal, which the band query absorbs; the rename dance
	// buys nothing this file's failure mode does not already survive.
	return os.WriteFile(cursorPath(stateDir), []byte(strconv.FormatInt(off, 10)), 0o600)
}
