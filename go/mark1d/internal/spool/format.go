// On-disk byte layouts for 07 §6, kept apart from the writer so the fuzz
// target and the recovery scan exercise exactly the codepaths the writer uses
// — one encoding, one decoding, no test-only mirror to drift.
package spool

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"math"
)

const (
	segHeaderLen = 64
	segVersion   = 0x01

	recordIDLen  = 20
	recHeaderLen = 4 + 4 + recordIDLen // len + crc32c + record_id
	// 07 §6: record len = 20 + payload, bound 20 < len <= 4_194_324 —
	// derived from 08 §4.2's M1PL_MAX_FRAME (4_194_304) + record_id.
	minRecordLen = recordIDLen + 1
	maxRecordLen = 4_194_324
	classOff     = 4 + 4 + 16 // class byte [16] of record_id, from record start

	ledgerLen  = 128
	slotLen    = 64
	slotCRCEnd = 40 // slot crc32c covers bytes 0..40
)

var (
	segMagic = [4]byte{'M', '1', 'S', 'G'}
	// crc32c (Castagnoli) — same polynomial as the estate's vector-disk-v2
	// shape; stdlib table, no external dep.
	castagnoli = crc32.MakeTable(crc32.Castagnoli)
)

// RecordID is the 20-byte spool identity: [0..16) the event's UUIDv7 (the
// spool cursor IS the wire idempotency key), [16] the durability class carried
// outside the payload so full-spool policy and loss accounting never decode
// protobuf, [17..20) reserved zero.
type RecordID [recordIDLen]byte

func makeRecordID(eventID [16]byte, class Class) RecordID {
	var id RecordID
	copy(id[:16], eventID[:])
	id[16] = byte(class)
	return id
}

func (id RecordID) Class() Class { return Class(id[16]) }

// Integer-domain bridges: spool arithmetic is uint64 (07 §6's fields are u64),
// the os.File API is int64. Offsets are bounded by SegmentSize and sizes by
// the filesystem, so a trip here is corruption-scale internal-state damage —
// and a silent wrap would corrupt the write head, hence the hard stop.
func toI64(x uint64) int64 {
	if x > math.MaxInt64 {
		panic(fmt.Sprintf("spool: offset %d overflows int64", x))
	}
	return int64(x) // #nosec G115 -- guarded above
}

func toU64(x int64) uint64 {
	if x < 0 {
		panic(fmt.Sprintf("spool: negative size %d", x))
	}
	return uint64(x) // #nosec G115 -- guarded above
}

func appendRecord(dst []byte, id RecordID, payload []byte) []byte {
	recLen := recordIDLen + len(payload)
	if recLen > maxRecordLen {
		panic(fmt.Sprintf("spool: record len %d past bound %d — Append validates first", recLen, maxRecordLen))
	}
	var hdr [recHeaderLen]byte
	binary.LittleEndian.PutUint32(hdr[0:4], uint32(recLen)) // #nosec G115 -- guarded above
	crc := crc32.Update(0, castagnoli, id[:])
	crc = crc32.Update(crc, castagnoli, payload)
	binary.LittleEndian.PutUint32(hdr[4:8], crc)
	copy(hdr[8:], id[:])
	return append(append(dst, hdr[:]...), payload...)
}

// decodeRecord walks one record off the front of b. ok=false means the tail
// is torn per recovery step 3 — too few bytes for len, len outside its bound,
// too few bytes for the record, or a crc32c mismatch; all four are the same
// outcome (truncate to the last good boundary) so they carry no distinction.
// The payload aliases b: callers copy if they keep it past b's lifetime.
func decodeRecord(b []byte) (id RecordID, payload []byte, consumed int, ok bool) {
	if len(b) < 4 {
		return id, nil, 0, false
	}
	recLen := binary.LittleEndian.Uint32(b[0:4])
	if recLen < minRecordLen || recLen > maxRecordLen {
		return id, nil, 0, false
	}
	// Step-3 arithmetic: after the len field, len + 4 bytes must remain —
	// the crc field plus the len-covered record_id||payload.
	total := 8 + int(recLen)
	if len(b) < total {
		return id, nil, 0, false
	}
	copy(id[:], b[8:8+recordIDLen])
	payload = b[8+recordIDLen : total]
	crc := crc32.Update(0, castagnoli, id[:])
	crc = crc32.Update(crc, castagnoli, payload)
	if crc != binary.LittleEndian.Uint32(b[4:8]) {
		return id, nil, 0, false
	}
	return id, payload, total, true
}

// tornClass reads the durability class of a discarded record from byte [16]
// of its record_id WITHOUT decoding (or even having) the payload — recovery
// step 4: the class rides before the payload precisely so it survives a torn
// or CRC-failing tail. Fewer than classOff+1 bytes means the record_id itself
// was torn: the class is honestly unknowable and reported as ClassUnknown
// (DURABILITY_CLASS_UNSPECIFIED), never guessed.
func tornClass(b []byte) Class {
	if len(b) <= classOff {
		return ClassUnknown
	}
	return Class(b[classOff])
}

func encodeSegHeader(seq, createdAtNs uint64) [segHeaderLen]byte {
	var h [segHeaderLen]byte
	copy(h[0:4], segMagic[:])
	h[4] = segVersion
	binary.LittleEndian.PutUint64(h[8:16], seq)
	binary.LittleEndian.PutUint64(h[16:24], createdAtNs)
	return h
}

func parseSegHeader(b []byte, wantSeq uint64) error {
	if len(b) < segHeaderLen {
		return fmt.Errorf("segment header truncated: %d bytes", len(b))
	}
	if [4]byte(b[0:4]) != segMagic {
		return fmt.Errorf("segment magic % x", b[0:4])
	}
	if b[4] != segVersion {
		return fmt.Errorf("segment version %#02x", b[4])
	}
	if got := binary.LittleEndian.Uint64(b[8:16]); got != wantSeq {
		return fmt.Errorf("segment_seq %d, filename says %d", got, wantSeq)
	}
	return nil
}

// Cursor is a spool position: a segment plus a byte offset inside it.
type Cursor struct {
	Seq uint64
	Off uint64
}

func (c Cursor) less(o Cursor) bool {
	return c.Seq < o.Seq || (c.Seq == o.Seq && c.Off < o.Off)
}

type ledgerState struct {
	generation uint64
	write, ack Cursor
}

func encodeSlot(st ledgerState) [slotLen]byte {
	var s [slotLen]byte
	binary.LittleEndian.PutUint64(s[0:8], st.generation)
	binary.LittleEndian.PutUint64(s[8:16], st.write.Seq)
	binary.LittleEndian.PutUint64(s[16:24], st.write.Off)
	binary.LittleEndian.PutUint64(s[24:32], st.ack.Seq)
	binary.LittleEndian.PutUint64(s[32:40], st.ack.Off)
	binary.LittleEndian.PutUint32(s[40:44], crc32.Checksum(s[:slotCRCEnd], castagnoli))
	return s
}

func parseSlot(b []byte) (ledgerState, bool) {
	if len(b) < slotLen {
		return ledgerState{}, false
	}
	if crc32.Checksum(b[:slotCRCEnd], castagnoli) != binary.LittleEndian.Uint32(b[40:44]) {
		return ledgerState{}, false
	}
	return ledgerState{
		generation: binary.LittleEndian.Uint64(b[0:8]),
		write:      Cursor{binary.LittleEndian.Uint64(b[8:16]), binary.LittleEndian.Uint64(b[16:24])},
		ack:        Cursor{binary.LittleEndian.Uint64(b[24:32]), binary.LittleEndian.Uint64(b[32:40])},
	}, true
}

// bestSlot implements recovery step 1: the highest-generation slot whose CRC
// verifies. A torn ledger write is harmless by construction — the older
// consistent slot survives, and a stale ledger only causes re-scanning.
func bestSlot(ledger []byte) (ledgerState, bool) {
	a, aok := parseSlot(ledger[0:slotLen])
	b, bok := parseSlot(ledger[slotLen:ledgerLen])
	switch {
	case aok && bok:
		if b.generation > a.generation {
			return b, true
		}
		return a, true
	case aok:
		return a, true
	case bok:
		return b, true
	default:
		return ledgerState{}, false
	}
}
