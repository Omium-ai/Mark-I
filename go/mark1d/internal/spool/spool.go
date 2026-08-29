// Package spool is 07 §6 made code: the single durable buffer between capture
// and uplink. Append-only segments with crc32c-framed records, a 128-byte A/B
// ledger, adaptive fsync, per-class full policy (billing-grade blocks,
// diagnostics drop-newest), and the six-step recovery scan with torn-tail
// truncation and class-byte loss accounting.
//
// The package stores opaque payload bytes and never imports protobuf: the
// durability class rides in record_id byte [16] precisely so full-spool
// policy and loss accounting work without decoding (07 §6, §3). Dropped{}
// values here are the typed precursors the daemon translates to m1p.v1.Dropped
// at batch composition (04 §8.1: the counter table is drained by uplink).
//
// Not here, by row: the 95%-disk hard stop and its CoverageTransition, and
// SessionEnd's upload attempt — both are daemon wiring over this package's
// seams (07 §6 operational policy; 04 §2), landing with uplink/coverage.
package spool

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Class is the durability class byte, 07 §6 record_id[16]. Values 1 and 2 are
// deliberately identical to m1p.v1.DurabilityClass so the ledger and the disk
// name the class the same way with no mapping table.
type Class byte

const (
	// ClassUnknown is DURABILITY_CLASS_UNSPECIFIED: only ever reported for a
	// discarded record whose record_id itself was torn — never written.
	ClassUnknown Class = 0
	// ClassBilling is the closed set {usage, verdict_event,
	// receipt_checkpoint}: blocks on full, never silently shed. The CALLER
	// (capture's class-tag stage, 04 §2.0) owns membership; widening it is a
	// m1p.v2 conversation (07 §6).
	ClassBilling Class = 1
	// ClassDiagnostic is everything else, CoverageTransition included:
	// drop-newest on full, always accounted.
	ClassDiagnostic Class = 2
)

// DropReason values mirror m1p.v1.DropReason's numbering (envelope.proto) —
// the daemon's translation to the wire enum is a cast, not a table.
type DropReason int32

const (
	DropSpoolShed DropReason = 1 // DROP_REASON_SPOOL_SHED: diagnostic drop-newest on full
	DropCRCLoss   DropReason = 2 // DROP_REASON_CRC_LOSS: torn/corrupt record discarded at recovery
)

// Dropped is one row of the loss ledger: every shed and every CRC loss is
// accounted here and emitted in the next batch — silence is the one failure
// mode 07 §6 forbids.
type Dropped struct {
	Reason   DropReason
	Class    Class
	Quantity uint64
}

// ErrDiagnosticShed is the caller-visible half of drop-newest: the diagnostic
// was NOT appended, and the loss is already accounted (drain via DrainDropped).
var ErrDiagnosticShed = errors.New("spool: diagnostic dropped, spool full (accounted)")

// ErrClosed unblocks class-1 waiters at shutdown; the event stays with the
// caller (hookshim/tailer spill rings are the upstream buffer, 04 §8.2).
var ErrClosed = errors.New("spool: closed")

const (
	// 07 §6 operational policy. billingSyncEvery is the loop tick; diagnostics
	// tolerate every other tick — see run().
	billingSyncEvery = 250 * time.Millisecond
	defaultSegSize   = 64 << 20
	defaultCap       = 2 << 30
)

// Config: sizes are operational policy (07 §6 names 64 MiB / ~2 GiB); tests
// shrink them — the on-disk byte format never varies with them. Now/After are
// the injectable clock for the fsync loop.
type Config struct {
	Dir         string
	SegmentSize int64
	SpoolCap    int64
	Now         func() time.Time
	After       func(d time.Duration) <-chan time.Time
}

// Record is one durable spool record as handed to uplink/recovery consumers.
type Record struct {
	ID      RecordID
	Payload []byte
	// Pos is the record's start cursor; the record ends at Pos.Off+28+len(Payload).
	Pos Cursor
}

type dropKey struct {
	reason DropReason
	class  Class
}

// Spool is the single writer (04 §8.1). All methods are safe for concurrent
// use; internally one mutex serializes writer, acker and syncer.
// ponytail: one lock across append/ack/sync — fsync holds it, so appends stall
// ~ms during a sync. A seal/handoff split if the 250 ms cadence ever shows up
// in the hook path's latency budget.
type Spool struct {
	cfg Config
	// Validated-at-Open uint64 copies of the int64 config sizes: all spool
	// arithmetic stays in 07 §6's u64 domain with one checked crossing.
	segSize  uint64
	spoolCap uint64

	mu       sync.Mutex
	f        *os.File // live segment
	writeSeq uint64
	writeOff uint64            // first unwritten byte (may be ahead of durable)
	durable  Cursor            // last fsync-covered write position — all the ledger may publish
	ack      Cursor            // first unacked record (uplink cursor)
	sealed   map[uint64]uint64 // sealed segment seq -> size in bytes
	gen      uint64
	ledger   *os.File

	billingPending bool // class-1 bytes appended since the last fsync
	dirty          bool
	skipTick       bool // diagnostics-only tick already deferred once
	syncErr        error
	drops          map[dropKey]uint64
	spaceCh        chan struct{} // closed+replaced when Ack frees space

	stop chan struct{}
	done chan struct{}
}

func segPath(dir string, seq uint64) string {
	return filepath.Join(dir, fmt.Sprintf("seg-%016x.m1s", seq))
}

// Open loads or creates the spool at cfg.Dir, running the full 07 §6 recovery
// (steps 1–6) before returning; the returned spool is ready for appends and
// its fsync loop is running.
func Open(cfg Config) (*Spool, error) {
	if cfg.SegmentSize == 0 {
		cfg.SegmentSize = defaultSegSize
	}
	if cfg.SpoolCap == 0 {
		cfg.SpoolCap = defaultCap
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.After == nil {
		cfg.After = time.After
	}
	if cfg.SegmentSize < segHeaderLen+recHeaderLen+1 {
		return nil, fmt.Errorf("spool: segment size %d cannot hold one record", cfg.SegmentSize)
	}
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return nil, err
	}
	s := &Spool{
		cfg:      cfg,
		segSize:  toU64(cfg.SegmentSize),
		spoolCap: toU64(cfg.SpoolCap),
		sealed:   map[uint64]uint64{},
		drops:    map[dropKey]uint64{},
		spaceCh:  make(chan struct{}),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	if err := s.recover(); err != nil {
		return nil, err
	}
	go s.run()
	return s, nil
}

// Append stores one record. Billing-grade appends block while the spool is
// full (caller-visible backpressure, released by Ack or ctx/Close); diagnostic
// appends at full return ErrDiagnosticShed after accounting the loss.
// Durability is the fsync cadence's, not Append's: return means written, not
// yet necessarily synced (07 §6 — the loss window is the cadence, and it is
// accounted, never silent).
func (s *Spool) Append(ctx context.Context, eventID [16]byte, class Class, payload []byte) error {
	if class != ClassBilling && class != ClassDiagnostic {
		// Trust boundary: an unknown class byte on disk would poison every
		// future recovery accounting pass — refuse it here, loudly.
		return fmt.Errorf("spool: invalid durability class %d", class)
	}
	if len(payload) == 0 || recordIDLen+len(payload) > maxRecordLen {
		return fmt.Errorf("spool: payload of %d bytes outside record bound %d < len <= %d", len(payload), minRecordLen-1, maxRecordLen)
	}
	recSize := toU64(int64(recHeaderLen + len(payload)))
	if segHeaderLen+recSize > s.segSize {
		return fmt.Errorf("spool: record of %d bytes cannot fit a %d-byte segment", recSize, s.cfg.SegmentSize)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.takeSyncErrLocked(); err != nil {
		return err
	}
	for s.totalLocked()+recSize > s.spoolCap {
		if class == ClassDiagnostic {
			s.drops[dropKey{DropSpoolShed, ClassDiagnostic}]++
			return ErrDiagnosticShed
		}
		ch := s.spaceCh
		s.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			s.mu.Lock()
			return ctx.Err()
		case <-s.stop:
			s.mu.Lock()
			return ErrClosed
		}
		s.mu.Lock()
	}
	if s.writeOff+recSize > s.segSize {
		if err := s.rotateLocked(); err != nil {
			return err
		}
	}
	rec := appendRecord(make([]byte, 0, recSize), makeRecordID(eventID, class), payload)
	if _, err := s.f.WriteAt(rec, toI64(s.writeOff)); err != nil {
		// writeOff not advanced: a partial record on disk is overwritten by
		// the next attempt, and recovery's CRC discards it if we crash first.
		return err
	}
	s.writeOff += recSize
	s.dirty = true
	if class == ClassBilling {
		s.billingPending = true
	}
	return nil
}

// Sync forces fsync + ledger publication now (SessionEnd/shutdown drain path;
// tests). The ledger is written only after the segment fsync (07 §6).
func (s *Spool) Sync() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.syncLocked()
}

// Ack advances the upload cursor to c (exclusive of everything before it) and
// deletes segments that are now fully acked, whole — no compaction (07 §6).
// The ledger write here publishes only the durable write cursor, preserving
// "ledger updated only after a segment fsync".
func (s *Spool) Ack(c Cursor) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c.less(s.ack) {
		return fmt.Errorf("spool: ack %v behind current ack %v", c, s.ack)
	}
	if s.durable.less(c) {
		return fmt.Errorf("spool: ack %v beyond durable write %v", c, s.durable)
	}
	s.ack = c
	if err := s.writeLedgerLocked(); err != nil {
		return err
	}
	freed := false
	for seq := range s.sealed {
		if seq < s.ack.Seq {
			if err := os.Remove(segPath(s.cfg.Dir, seq)); err != nil {
				return err
			}
			delete(s.sealed, seq)
			freed = true
		}
	}
	if freed {
		close(s.spaceCh)
		s.spaceCh = make(chan struct{})
	}
	return nil
}

// Records reads every durable record in (from, durable] order. from must be at
// or ahead of the ack cursor (older segments may already be deleted).
// ponytail: loads the whole backlog into memory — uplink's 04 §2.5 batching
// caps this when it lands; tests and recovery checks are the C3 consumers.
func (s *Spool) Records(from Cursor) ([]Record, Cursor, error) {
	s.mu.Lock()
	durable := s.durable
	s.mu.Unlock()

	var out []Record
	cur := from
	for {
		if cur.Seq > durable.Seq || (cur.Seq == durable.Seq && cur.Off >= durable.Off) {
			return out, durable, nil
		}
		end := durable.Off
		if cur.Seq < durable.Seq {
			s.mu.Lock()
			size, sealedOK := s.sealed[cur.Seq]
			s.mu.Unlock()
			if !sealedOK {
				return nil, from, fmt.Errorf("spool: segment %d not retained (cursor behind ack?)", cur.Seq)
			}
			end = size
		}
		if cur.Off < segHeaderLen {
			cur.Off = segHeaderLen
		}
		buf := make([]byte, end-cur.Off)
		f, err := os.Open(segPath(s.cfg.Dir, cur.Seq))
		if err != nil {
			return nil, from, err
		}
		_, err = f.ReadAt(buf, toI64(cur.Off))
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return nil, from, err
		}
		off := cur.Off
		for len(buf) > 0 {
			id, payload, consumed, ok := decodeRecord(buf)
			if !ok {
				// Below the durable cursor every record was CRC-verified at
				// write or recovery time; failure here is disk corruption.
				return nil, from, fmt.Errorf("spool: corrupt record below durable cursor at (%d,%d)", cur.Seq, off)
			}
			p := make([]byte, len(payload))
			copy(p, payload)
			out = append(out, Record{ID: id, Payload: p, Pos: Cursor{cur.Seq, off}})
			off += toU64(int64(consumed))
			buf = buf[consumed:]
		}
		cur = Cursor{cur.Seq + 1, segHeaderLen}
	}
}

// DrainDropped returns and resets the loss ledger (read-and-reset is the
// 04 §8.1 contract: uplink drains it at batch composition).
func (s *Spool) DrainDropped() []Dropped {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Dropped, 0, len(s.drops))
	for k, q := range s.drops {
		out = append(out, Dropped{Reason: k.reason, Class: k.class, Quantity: q})
	}
	s.drops = map[dropKey]uint64{}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Reason != out[j].Reason {
			return out[i].Reason < out[j].Reason
		}
		return out[i].Class < out[j].Class
	})
	return out
}

// Cursors returns (ack, durable write) — the replay window (ack, write] that
// recovery resumes and uplink re-sends, at-least-once by design (07 §6 step 5).
func (s *Spool) Cursors() (ack, write Cursor) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ack, s.durable
}

// Close stops the fsync loop, forces the full drain fsync (07 §6: shutdown
// forces a drain regardless of cadence) and releases files. Blocked billing
// appenders are unblocked with ErrClosed.
func (s *Spool) Close() error {
	s.mu.Lock()
	select {
	case <-s.stop:
		s.mu.Unlock()
		<-s.done
		return nil
	default:
		close(s.stop)
	}
	s.mu.Unlock()
	<-s.done
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.syncLocked()
	if cerr := s.f.Close(); err == nil {
		err = cerr
	}
	if cerr := s.ledger.Close(); err == nil {
		err = cerr
	}
	return err
}

// run is the adaptive fsync loop. A constant 250 ms tick implements 07 §6's
// two cadences exactly: billing-pending state syncs every tick (250 ms);
// diagnostics-only state defers one tick (500 ms). A tick-based loop rather
// than a re-armed 250/500 timer so billing arriving mid-sleep never waits a
// diagnostic interval — the 250 ms promise holds from the append, not from
// the next timer decision.
func (s *Spool) run() {
	defer close(s.done)
	for {
		select {
		case <-s.stop:
			return
		case <-s.cfg.After(billingSyncEvery):
			s.mu.Lock()
			if s.dirty && !s.billingPending && !s.skipTick {
				s.skipTick = true
			} else {
				if err := s.syncLocked(); err != nil && s.syncErr == nil {
					// Surfaced on the next Append/Sync — an fsync failure is
					// a durability breach the producer must see, not a log line.
					s.syncErr = err
				}
			}
			s.mu.Unlock()
		}
	}
}

func (s *Spool) takeSyncErrLocked() error {
	err := s.syncErr
	s.syncErr = nil
	return err
}

func (s *Spool) totalLocked() uint64 {
	t := s.writeOff
	for _, size := range s.sealed {
		t += size
	}
	return t
}

func (s *Spool) syncLocked() error {
	s.skipTick = false
	if !s.dirty {
		return nil
	}
	if err := s.f.Sync(); err != nil {
		return err
	}
	s.durable = Cursor{s.writeSeq, s.writeOff}
	s.dirty = false
	s.billingPending = false
	return s.writeLedgerLocked()
}

func (s *Spool) writeLedgerLocked() error {
	s.gen++
	slot := encodeSlot(ledgerState{generation: s.gen, write: s.durable, ack: s.ack})
	// Alternating A/B slots: a torn write can only damage the slot being
	// written, so the previous generation always survives with a valid CRC.
	if _, err := s.ledger.WriteAt(slot[:], toI64(s.gen%2)*slotLen); err != nil {
		return err
	}
	return s.ledger.Sync()
}

// rotateLocked seals the live segment (fsync + ledger, so the seal is durable
// before anything points past it) and opens the successor with a durable
// header — 07 §6: rotated when the next record would overflow.
func (s *Spool) rotateLocked() error {
	if err := s.syncLocked(); err != nil {
		return err
	}
	if err := s.f.Close(); err != nil {
		return err
	}
	s.sealed[s.writeSeq] = s.writeOff
	return s.openSegmentLocked(s.writeSeq + 1)
}

func (s *Spool) openSegmentLocked(seq uint64) error {
	f, err := os.OpenFile(segPath(s.cfg.Dir, seq), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	// created_at is u64 unix nanoseconds on disk (07 §6); a pre-1970 clock is
	// misconfiguration toU64 turns into a loud stop, not a wrapped timestamp.
	hdr := encodeSegHeader(seq, toU64(s.cfg.Now().UnixNano()))
	if _, err := f.WriteAt(hdr[:], 0); err != nil {
		return err
	}
	// Header fsync before any record: the ledger may point into this segment
	// on the next sync, and recovery validates the header it points at.
	if err := f.Sync(); err != nil {
		return err
	}
	s.f = f
	s.writeSeq = seq
	s.writeOff = segHeaderLen
	s.durable = Cursor{seq, segHeaderLen}
	return nil
}
