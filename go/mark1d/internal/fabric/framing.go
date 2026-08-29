// Package fabric carries M1PL/1 framing — 07 §5's byte layout under 08 §4.2's
// bound, the Go half of the two-language codec the m1pl conformance vectors
// freeze (12 §3.4) — plus the unix listener (listener.go) whose read loop
// wraps the Decoder exactly as shaped: Push what Read returned, drain Next
// until incomplete, close the connection on any reject. The Windows named
// pipe and the 08 §4.3 Hello handshake stay later rows (Hello has no
// m1p.v1 message in the frozen proto yet — nothing to implement against).
package fabric

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	// MaxFrame is 08 §4.2's M1PL_MAX_FRAME — the symbol, not a re-typed
	// literal elsewhere; 07 §6 derives the spool record bound from it.
	MaxFrame  = 4_194_304
	headerLen = 9
	version   = 0x01
)

var magic = [4]byte{'M', '1', 'P', 'L'}

// Reject codes per the vector manifest and 08 §7: only a version mismatch is
// M1E-4003; every other framing violation is the M1E-4002 protocol error.
const (
	CodeProtocol = "M1E-4002"
	CodeVersion  = "M1E-4003"
)

// RejectError is the third decoder outcome. Receiving one means the stream is
// desynchronized or hostile: the caller closes the connection (07 §5) — the
// decoder never resynchronizes on attacker-chosen bytes (12 §3.4 row 1).
type RejectError struct {
	Code   string // the refusal identity Rust and Go agree on (12 §3.4)
	detail string
}

func (e *RejectError) Error() string { return e.Code + ": " + e.detail }

// Decoder is the incremental three-outcome frame reader
// (conformance/vectors/m1pl/README.md §Decoder model): accept consumes exactly
// 9+len, incomplete consumes 0, reject consumes 0 and is sticky-by-buffer —
// re-polling re-rejects identically, matching "reject means close" without a
// poison flag. The buffer holds only bytes actually received; nothing is ever
// allocated from the claimed len, so a hostile length prefix cannot demand
// memory past MaxFrame (08 §4.2).
type Decoder struct {
	buf []byte
}

func (d *Decoder) Push(p []byte) {
	d.buf = append(d.buf, p...)
}

// Next returns one decoder step over the unconsumed buffer:
//
//	accept     — payload != nil, consumed == 9 + len(payload)
//	incomplete — (nil, 0, nil): need more bytes
//	reject     — (nil, 0, *RejectError): close the connection
//
// payload is a copy; the caller owns it.
func (d *Decoder) Next() (payload []byte, consumed int, err error) {
	// A <9-byte buffer is incomplete WITHOUT inspecting content — eager
	// prefix rejection is a conformance failure (README §Decoder model
	// rule 1: both implementations must buffer the full header).
	if len(d.buf) < headerLen {
		return nil, 0, nil
	}
	// Full 4-byte compare: reject_bad_magic.bin flips only the last byte.
	if !bytes.Equal(d.buf[:4], magic[:]) {
		return nil, 0, &RejectError{CodeProtocol, fmt.Sprintf("bad magic % x", d.buf[:4])}
	}
	if d.buf[4] != version {
		return nil, 0, &RejectError{CodeVersion, fmt.Sprintf("M1PL version %#02x not in the shipped set {0x01}", d.buf[4])}
	}
	n := binary.LittleEndian.Uint32(d.buf[5:9])
	// Both halves of the bound, from the 9-byte header BEFORE any payload
	// allocation (07 §5, 08 §4.2): len == 0 is a desynchronized stream, not
	// an empty Event; len > max caps hostile allocation at 4 MiB.
	if n == 0 || n > MaxFrame {
		return nil, 0, &RejectError{CodeProtocol, fmt.Sprintf("frame len %d outside 0 < len <= %d", n, MaxFrame)}
	}
	total := headerLen + int(n)
	if len(d.buf) < total {
		return nil, 0, nil
	}
	payload = make([]byte, n)
	copy(payload, d.buf[headerLen:total])
	// ponytail: memmove-compaction per accepted frame — O(buffered), so one
	// Push holding many small frames degrades quadratically, same ceiling as
	// the Rust reference's drain. A read cursor + amortized compaction if the
	// fabric ever batches like that.
	rest := copy(d.buf, d.buf[total:])
	d.buf = d.buf[:rest]
	return payload, total, nil
}

// WriteFrame frames one encoded m1p.v1.Event onto w. The writer enforces the
// same bound as the decoder, so an unframeable payload fails here rather than
// as a peer's connection close (mirrors the Rust encoder's refusal).
// Two writes are safe because a fabric connection has exactly one writing
// goroutine (04 §8.1); nothing interleaves a header with a foreign payload.
func WriteFrame(w io.Writer, payload []byte) error {
	n := len(payload)
	if n == 0 || n > MaxFrame {
		return &RejectError{CodeProtocol, fmt.Sprintf("payload of %d bytes unframeable under 0 < len <= %d", n, MaxFrame)}
	}
	var hdr [headerLen]byte
	copy(hdr[:4], magic[:])
	hdr[4] = version
	binary.LittleEndian.PutUint32(hdr[5:9], uint32(n))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}
