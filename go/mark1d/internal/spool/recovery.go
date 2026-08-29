// Recovery after unclean shutdown — 07 §6 steps 1–6, in order. The governing
// asymmetry: the ledger is only ever BEHIND the true durable end (it is
// written post-fsync), so scanning forward from its cursor finds records the
// ledger hasn't caught up to, and a stale ledger costs re-scanning, never data.
package spool

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

func (s *Spool) recover() error {
	ledger, err := os.OpenFile(filepath.Join(s.cfg.Dir, "spool.ledger"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	s.ledger = ledger
	if err := ledger.Truncate(ledgerLen); err != nil {
		return err
	}
	lbuf := make([]byte, ledgerLen)
	if _, err := ledger.ReadAt(lbuf, 0); err != nil {
		return err
	}

	segs, err := s.listSegments()
	if err != nil {
		return err
	}
	if len(segs) == 0 {
		// First boot: no history to recover; seed segment 1 and publish.
		if err := s.openSegmentLocked(1); err != nil {
			return err
		}
		s.ack = Cursor{1, segHeaderLen}
		return s.writeLedgerLocked()
	}

	// Step 1: highest-generation valid-CRC slot; both invalid ⇒ lowest
	// existing segment at offset 64 for both cursors.
	st, ok := bestSlot(lbuf)
	if !ok {
		st = ledgerState{write: Cursor{segs[0], segHeaderLen}, ack: Cursor{segs[0], segHeaderLen}}
	}
	s.gen = st.generation

	write := clampToSegments(st.write, segs)
	// Steps 2–4: scan forward from write across successive segments;
	// torn tail ⇒ truncate to the last good boundary, account by class byte.
	write, err = s.scanForward(write, segs)
	if err != nil {
		return err
	}

	// Step 5: resume upload from (ack_seq, ack_off); everything in
	// (ack, write] is re-sent, at-least-once — record_id[0..16) IS the
	// event_id the server dedupes on, so replay needs no state here.
	ack := clampToSegments(st.ack, segs)
	if write.less(ack) {
		ack = write
	}
	s.ack = ack

	// Segments strictly before ack are fully acked leftovers of a crash
	// between deletion and ledger publication — delete whole, as ever.
	for _, seq := range segs {
		if seq < s.ack.Seq {
			if err := os.Remove(segPath(s.cfg.Dir, seq)); err != nil {
				return err
			}
			continue
		}
		if seq < write.Seq {
			info, err := os.Stat(segPath(s.cfg.Dir, seq))
			if err != nil {
				return err
			}
			s.sealed[seq] = toU64(info.Size())
		}
	}

	f, err := os.OpenFile(segPath(s.cfg.Dir, write.Seq), os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	s.f = f
	s.writeSeq = write.Seq
	s.writeOff = write.Off
	// Bytes that survived the crash are on stable media by observation;
	// treating them as durable is what lets the ledger republish them now.
	s.durable = write

	// Step 6: publish the recovered (write, ack) pair and resume appends.
	return s.writeLedgerLocked()
}

// listSegments returns existing segment seqs ascending, headers validated.
// A bad header on the HIGHEST segment is the openSegmentLocked crash window
// (create → header WriteAt → fsync): kill -9 in it leaves a zero-byte or
// partial-header file — the routine crash class 07 §6 recovery exists for
// (04 §11.4), so it is discarded deterministically like every other torn
// artifact, never a boot-refusing error. Nothing durable can live there: the
// header fsync precedes every record write and every ledger publication.
// A bad header BELOW a durable successor cannot come from that window
// (rotation fsyncs a segment whole before minting its successor) — that is a
// segment lying about its own identity, an operator problem (refuse to run),
// not something to guess around.
func (s *Spool) listSegments() ([]uint64, error) {
	names, err := filepath.Glob(filepath.Join(s.cfg.Dir, "seg-*.m1s"))
	if err != nil {
		return nil, err
	}
	type seg struct {
		seq    uint64
		name   string
		hdrErr error
	}
	segs := make([]seg, 0, len(names))
	for _, name := range names {
		var seq uint64
		if _, err := fmt.Sscanf(filepath.Base(name), "seg-%016x.m1s", &seq); err != nil {
			return nil, fmt.Errorf("spool: alien file in spool dir: %s", name)
		}
		segs = append(segs, seg{seq: seq, name: name, hdrErr: checkSegHeader(name, seq)})
	}
	sort.Slice(segs, func(i, j int) bool { return segs[i].seq < segs[j].seq })
	out := make([]uint64, 0, len(segs))
	for i, sg := range segs {
		switch {
		case sg.hdrErr == nil:
			out = append(out, sg.seq)
		case i < len(segs)-1:
			return nil, fmt.Errorf("spool: %s: %w", sg.name, sg.hdrErr)
		default:
			// The file must go, not merely be skipped: the resumed writer
			// re-mints this seq at the next rotation, and O_EXCL would refuse
			// it. Any readable record bytes (data pages can outrun the header's
			// under no-fsync crashes) are accounted before removal — silence is
			// the one failure mode 07 §6 forbids.
			if err := s.discardSegment(sg.seq); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

func checkSegHeader(name string, seq uint64) error {
	hdr := make([]byte, segHeaderLen)
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	_, rerr := f.ReadAt(hdr, 0)
	if cerr := f.Close(); rerr == nil {
		rerr = cerr
	}
	if rerr != nil {
		return rerr
	}
	return parseSegHeader(hdr, seq)
}

// clampToSegments pins a ledger cursor onto a segment that still exists: a
// cursor into a deleted segment (crash between whole-segment delete and
// ledger publication) restarts at the lowest survivor — harmless, because
// replay is at-least-once and the server dedupes on event_id.
func clampToSegments(c Cursor, segs []uint64) Cursor {
	lowest, highest := segs[0], segs[len(segs)-1]
	if c.Seq < lowest {
		return Cursor{lowest, segHeaderLen}
	}
	if c.Seq > highest {
		return Cursor{highest, segHeaderLen}
	}
	if c.Off < segHeaderLen {
		c.Off = segHeaderLen
	}
	return c
}

// scanForward is steps 2–4: walk records from the write cursor to the true
// durable end. A torn record truncates its segment to the last good boundary
// and ends the scan; its durability class is read from record_id byte [16]
// without decoding the payload, and the loss lands in the Dropped ledger for
// the first batch after restart — bounded by the fsync cadence, never silent.
func (s *Spool) scanForward(write Cursor, segs []uint64) (Cursor, error) {
	cur := write
	for {
		f, err := os.OpenFile(segPath(s.cfg.Dir, cur.Seq), os.O_RDWR, 0o600)
		if err != nil {
			return Cursor{}, err
		}
		end, torn, err := s.scanSegment(f, cur)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return Cursor{}, err
		}
		cur.Off = end
		next := cur.Seq + 1
		hasNext := false
		for _, seq := range segs {
			hasNext = hasNext || seq == next
		}
		if torn {
			// Single-writer means nothing valid exists past a tear; any later
			// segment here is corruption-shaped, and leaving it would collide
			// with the seq this writer mints next. Account what is readable,
			// then delete whole.
			for _, seq := range segs {
				if seq > cur.Seq {
					if err := s.discardSegment(seq); err != nil {
						return Cursor{}, err
					}
				}
			}
			return cur, nil
		}
		if !hasNext {
			return cur, nil
		}
		cur = Cursor{next, segHeaderLen}
	}
}

// scanSegment validates records in f from c.Off to EOF, returning the last
// good record boundary and whether the tail was torn (in which case the file
// is already truncated to that boundary — step 3's deterministic discard).
func (s *Spool) scanSegment(f *os.File, c Cursor) (end uint64, torn bool, err error) {
	info, err := f.Stat()
	if err != nil {
		return 0, false, err
	}
	size := toU64(info.Size())
	off := c.Off
	if off > size {
		// Pathological (the ledger is never ahead of an fsync) — disk-level
		// damage. Rescan the whole segment rather than trust either number.
		off = segHeaderLen
	}
	// ponytail: whole-tail read — ≤ one segment (64 MiB default) transiently
	// in memory, once, at boot. Chunked scanning if that ever matters.
	buf := make([]byte, size-off)
	if _, err := f.ReadAt(buf, toI64(off)); err != nil {
		return 0, false, err
	}
	for len(buf) > 0 {
		_, _, consumed, ok := decodeRecord(buf)
		if !ok {
			// Step 4: the discarded record's class from byte [16], which sits
			// before the payload and survives a torn/CRC-failing tail.
			s.drops[dropKey{DropCRCLoss, tornClass(buf)}]++
			if err := f.Truncate(toI64(off)); err != nil {
				return 0, false, err
			}
			if err := f.Sync(); err != nil {
				return 0, false, err
			}
			return off, true, nil
		}
		off += toU64(int64(consumed))
		buf = buf[consumed:]
	}
	return off, false, nil
}

// discardSegment accounts every readable record in an orphaned segment as
// CRC_LOSS by class byte, then removes the file whole.
func (s *Spool) discardSegment(seq uint64) error {
	path := segPath(s.cfg.Dir, seq)
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(data) > segHeaderLen {
		buf := data[segHeaderLen:]
		for len(buf) > 0 {
			id, _, consumed, ok := decodeRecord(buf)
			if !ok {
				s.drops[dropKey{DropCRCLoss, tornClass(buf)}]++
				break
			}
			s.drops[dropKey{DropCRCLoss, id.Class()}]++
			buf = buf[consumed:]
		}
	}
	return os.Remove(path)
}
