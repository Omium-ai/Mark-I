// The 07 §6 behavior suite: byte-exact formats, the kill -9 truncation sweep,
// per-class full policy, A/B ledger survival, and the fsync cadence. Tests
// shrink SegmentSize/SpoolCap (operational policy) — never the byte formats.
package spool

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var fixedNow = time.Unix(1_700_000_000, 424242)

// neverAfter parks the fsync loop on a nil channel so tests drive Sync
// deterministically.
func neverAfter(time.Duration) <-chan time.Time { return nil }

func testConfig(dir string, seg, spoolCap int64) Config {
	return Config{
		Dir:         dir,
		SegmentSize: seg,
		SpoolCap:    spoolCap,
		Now:         func() time.Time { return fixedNow },
		After:       neverAfter,
	}
}

func eid(i int) [16]byte {
	var id [16]byte
	binary.LittleEndian.PutUint64(id[:8], uint64(i))
	id[15] = 0x7E
	return id
}

func mustAppend(t *testing.T, s *Spool, i int, class Class, payload []byte) {
	t.Helper()
	if err := s.Append(context.Background(), eid(i), class, payload); err != nil {
		t.Fatalf("append %d: %v", i, err)
	}
}

func TestSpoolRoundTripAndOnDiskBytes(t *testing.T) {
	dir := t.TempDir()
	// 64-byte header + two 48-byte records per segment: forces rotation.
	s, err := Open(testConfig(dir, 160, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()

	payloads := make([][]byte, 5)
	for i := range payloads {
		payloads[i] = bytes.Repeat([]byte{byte('a' + i)}, 20)
		class := ClassBilling
		if i%2 == 1 {
			class = ClassDiagnostic
		}
		mustAppend(t, s, i, class, payloads[i])
	}
	if err := s.Sync(); err != nil {
		t.Fatal(err)
	}

	ack, write := s.Cursors()
	recs, next, err := s.Records(ack)
	if err != nil {
		t.Fatal(err)
	}
	if next != write || len(recs) != 5 {
		t.Fatalf("got %d records, next %v, write %v", len(recs), next, write)
	}
	for i, r := range recs {
		wantClass := ClassBilling
		if i%2 == 1 {
			wantClass = ClassDiagnostic
		}
		if r.ID != makeRecordID(eid(i), wantClass) || !bytes.Equal(r.Payload, payloads[i]) {
			t.Fatalf("record %d drifted: %+v", i, r)
		}
	}
	if write.Seq < 3 {
		t.Fatalf("expected rotation across >=3 segments, write %v", write)
	}

	// Segment header, byte-exact per 07 §6.
	seg1, err := os.ReadFile(segPath(dir, 1))
	if err != nil {
		t.Fatal(err)
	}
	if string(seg1[0:4]) != "M1SG" || seg1[4] != 0x01 {
		t.Fatalf("segment magic/ver: % x", seg1[0:5])
	}
	if !bytes.Equal(seg1[5:8], make([]byte, 3)) || !bytes.Equal(seg1[24:64], make([]byte, 40)) {
		t.Fatal("segment header reserved bytes not zero")
	}
	if binary.LittleEndian.Uint64(seg1[8:16]) != 1 {
		t.Fatal("segment_seq")
	}
	if binary.LittleEndian.Uint64(seg1[16:24]) != uint64(fixedNow.UnixNano()) {
		t.Fatal("created_at")
	}

	// First record, byte-exact: len | crc32c(record_id||payload) | record_id | payload.
	rec := seg1[64:]
	if binary.LittleEndian.Uint32(rec[0:4]) != 20+20 {
		t.Fatalf("record len field %d", binary.LittleEndian.Uint32(rec[0:4]))
	}
	table := crc32.MakeTable(crc32.Castagnoli)
	if binary.LittleEndian.Uint32(rec[4:8]) != crc32.Checksum(rec[8:8+20+20], table) {
		t.Fatal("record crc32c is not Castagnoli over record_id||payload")
	}
	wantEID := eid(0)
	if !bytes.Equal(rec[8:24], wantEID[:]) || rec[24] != 1 || !bytes.Equal(rec[25:28], make([]byte, 3)) {
		t.Fatal("record_id layout")
	}
	if !bytes.Equal(rec[28:48], payloads[0]) {
		t.Fatal("payload bytes")
	}

	// Ledger: 128 bytes, best slot carries the durable pair.
	lbuf, err := os.ReadFile(filepath.Join(dir, "spool.ledger"))
	if err != nil || len(lbuf) != 128 {
		t.Fatalf("ledger: len %d err %v", len(lbuf), err)
	}
	st, ok := bestSlot(lbuf)
	if !ok || st.write != write || st.ack != ack {
		t.Fatalf("ledger slot %+v, want write %v ack %v", st, write, ack)
	}

	// Clean reopen replays identically.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(testConfig(dir, 160, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s2.Close() }()
	recs2, _, err := s2.Records(ack)
	if err != nil || len(recs2) != 5 {
		t.Fatalf("reopen: %d records, err %v", len(recs2), err)
	}
	for i := range recs {
		if recs2[i].ID != recs[i].ID || !bytes.Equal(recs2[i].Payload, recs[i].Payload) {
			t.Fatalf("reopen record %d drifted", i)
		}
	}
	if drops := s2.DrainDropped(); len(drops) != 0 {
		t.Fatalf("clean reopen accounted losses: %v", drops)
	}
}

// The kill -9 test (13 §11 row C3): records are written, the directory is
// copied with the live segment truncated at EVERY byte position of the
// un-fsynced tail, and recovery must (a) truncate to a record boundary,
// (b) lose zero billing-grade records from before the fsync, and (c) account
// every discarded record via the class byte — without decoding any payload.
func TestCrashRecoveryTruncationSweep(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(testConfig(dir, 1<<20, 1<<30))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()

	// Durable prefix: three billing records, fsynced.
	for i := 0; i < 3; i++ {
		mustAppend(t, s, i, ClassBilling, bytes.Repeat([]byte{0xB0}, 40))
	}
	if err := s.Sync(); err != nil {
		t.Fatal(err)
	}
	_, durable := s.Cursors()

	// Un-fsynced tail: the fsync-cadence loss window.
	type tailRec struct {
		class      Class
		payloadLen int
		start, end uint64
	}
	tail := []tailRec{
		{ClassBilling, 10, 0, 0},
		{ClassDiagnostic, 25, 0, 0},
		{ClassBilling, 100, 0, 0},
	}
	off := durable.Off
	for i := range tail {
		tail[i].start = off
		tail[i].end = off + uint64(recHeaderLen+tail[i].payloadLen)
		off = tail[i].end
		mustAppend(t, s, 100+i, tail[i].class, bytes.Repeat([]byte{0xD0}, tail[i].payloadLen))
	}
	fileEnd := off

	liveSeg := segPath(dir, durable.Seq)
	src, err := os.ReadFile(liveSeg)
	if err != nil {
		t.Fatal(err)
	}
	if uint64(len(src)) != fileEnd {
		t.Fatalf("live segment %d bytes, want %d", len(src), fileEnd)
	}
	ledgerBytes, err := os.ReadFile(filepath.Join(dir, "spool.ledger"))
	if err != nil {
		t.Fatal(err)
	}

	for cut := durable.Off; cut <= fileEnd; cut++ {
		cdir := t.TempDir()
		if err := os.WriteFile(filepath.Join(cdir, "spool.ledger"), ledgerBytes, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(segPath(cdir, durable.Seq), src[:cut], 0o600); err != nil {
			t.Fatal(err)
		}

		r, err := Open(testConfig(cdir, 1<<20, 1<<30))
		if err != nil {
			t.Fatalf("cut %d: %v", cut, err)
		}

		// Expected surviving tail prefix + the torn record's class.
		survivors := 0
		torn := false
		var wantClass Class
		for _, tr := range tail {
			if tr.end <= cut {
				survivors++
				continue
			}
			if tr.start < cut {
				torn = true
				// class byte readable iff record_id byte [16] made it to disk
				if cut-tr.start > classOff {
					wantClass = tr.class
				} else {
					wantClass = ClassUnknown
				}
			}
			break
		}
		boundary := durable.Off
		if survivors > 0 {
			boundary = tail[survivors-1].end
		}

		ack, write := r.Cursors()
		if write != (Cursor{durable.Seq, boundary}) {
			t.Fatalf("cut %d: recovered write %v, want boundary %d", cut, write, boundary)
		}
		if info, err := os.Stat(segPath(cdir, durable.Seq)); err != nil || uint64(info.Size()) != boundary {
			t.Fatalf("cut %d: file not truncated to boundary: %v %v", cut, info.Size(), err)
		}

		recs, _, err := r.Records(ack)
		if err != nil {
			t.Fatalf("cut %d: %v", cut, err)
		}
		if len(recs) != 3+survivors {
			t.Fatalf("cut %d: %d records, want %d", cut, len(recs), 3+survivors)
		}
		for i := 0; i < 3; i++ {
			if recs[i].ID != makeRecordID(eid(i), ClassBilling) {
				t.Fatalf("cut %d: durable billing record %d lost — loss beyond the un-fsynced tail must be zero", cut, i)
			}
		}
		for i := 0; i < survivors; i++ {
			if recs[3+i].ID != makeRecordID(eid(100+i), tail[i].class) {
				t.Fatalf("cut %d: tail survivor %d drifted", cut, i)
			}
		}

		drops := r.DrainDropped()
		switch {
		case !torn && len(drops) != 0:
			t.Fatalf("cut %d: clean boundary but drops %v", cut, drops)
		case torn && (len(drops) != 1 || drops[0] != (Dropped{DropCRCLoss, wantClass, 1})):
			t.Fatalf("cut %d: drops %v, want CRC_LOSS class %d qty 1", cut, drops, wantClass)
		}
		if err := r.Close(); err != nil {
			t.Fatalf("cut %d: close: %v", cut, err)
		}
	}
}

func TestFullSpoolPolicyPerClass(t *testing.T) {
	dir := t.TempDir()
	// 2 records of payload 20 per segment; cap = 3 segments' worth.
	s, err := Open(testConfig(dir, 160, 480))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()

	payload := bytes.Repeat([]byte{0xF0}, 20)
	n := 0
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		err := s.Append(ctx, eid(n), ClassBilling, payload)
		cancel()
		if errors.Is(err, context.DeadlineExceeded) {
			break // full: billing-grade blocked, backpressure is caller-visible
		}
		if err != nil {
			t.Fatal(err)
		}
		n++
		if n > 100 {
			t.Fatal("spool never filled")
		}
	}

	// Class 2 at full: drop-newest, sentinel returned, loss accounted.
	if err := s.Append(context.Background(), eid(200), ClassDiagnostic, payload); !errors.Is(err, ErrDiagnosticShed) {
		t.Fatalf("diagnostic at full: %v", err)
	}
	if err := s.Append(context.Background(), eid(201), ClassDiagnostic, payload); !errors.Is(err, ErrDiagnosticShed) {
		t.Fatalf("diagnostic at full: %v", err)
	}
	drops := s.DrainDropped()
	if len(drops) != 1 || drops[0] != (Dropped{DropSpoolShed, ClassDiagnostic, 2}) {
		t.Fatalf("shed accounting: %v", drops)
	}

	// Class 1 at full: blocks until Ack frees a whole sealed segment.
	if err := s.Sync(); err != nil {
		t.Fatal(err)
	}
	unblocked := make(chan error, 1)
	go func() {
		unblocked <- s.Append(context.Background(), eid(300), ClassBilling, payload)
	}()
	select {
	case err := <-unblocked:
		t.Fatalf("billing append did not block at full: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if err := s.Ack(Cursor{2, segHeaderLen}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-unblocked:
		if err != nil {
			t.Fatalf("billing append after Ack: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("billing append still blocked after Ack freed a segment")
	}
	// Fully-acked segments are deleted whole (ack-then-delete, no compaction).
	if _, err := os.Stat(segPath(dir, 1)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("segment 1 not deleted after ack: %v", err)
	}
}

func TestLedgerTornWriteSurvivesOnOtherSlot(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(testConfig(dir, 1<<20, 1<<30))
	if err != nil {
		t.Fatal(err)
	}
	mustAppend(t, s, 1, ClassBilling, []byte("first"))
	if err := s.Sync(); err != nil {
		t.Fatal(err)
	}
	mustAppend(t, s, 2, ClassBilling, []byte("second"))
	if err := s.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	ledgerPath := filepath.Join(dir, "spool.ledger")
	pristine, err := os.ReadFile(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	a, aok := parseSlot(pristine[0:64])
	b, bok := parseSlot(pristine[64:128])
	if !aok || !bok {
		t.Fatal("expected two valid slots after two syncs")
	}
	newest := 0
	if b.generation > a.generation {
		newest = 64
	}

	// Torn write on the newest slot: the reader must take the other, and the
	// forward scan recovers everything the stale cursor missed — re-scanning,
	// never loss.
	torn := bytes.Clone(pristine)
	torn[newest+41] ^= 0xFF
	if err := os.WriteFile(ledgerPath, torn, 0o600); err != nil {
		t.Fatal(err)
	}
	assertBothRecords := func(label string) {
		t.Helper()
		r, err := Open(testConfig(dir, 1<<20, 1<<30))
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		defer func() { _ = r.Close() }()
		ack, _ := r.Cursors()
		recs, _, err := r.Records(ack)
		if err != nil || len(recs) != 2 {
			t.Fatalf("%s: %d records, err %v", label, len(recs), err)
		}
		if !bytes.Equal(recs[0].Payload, []byte("first")) || !bytes.Equal(recs[1].Payload, []byte("second")) {
			t.Fatalf("%s: payloads drifted", label)
		}
		if drops := r.DrainDropped(); len(drops) != 0 {
			t.Fatalf("%s: durable records misaccounted as lost: %v", label, drops)
		}
	}
	assertBothRecords("one torn slot")

	// Both slots invalid: step-1 fallback — lowest existing segment, offset 64.
	garbage := bytes.Clone(pristine)
	garbage[41] ^= 0xFF
	garbage[64+41] ^= 0xFF
	if err := os.WriteFile(ledgerPath, garbage, 0o600); err != nil {
		t.Fatal(err)
	}
	assertBothRecords("both slots torn")
}

// A kill -9 inside openSegmentLocked's create→fsync window leaves the newest
// segment with a zero-byte, partial or garbage header. 07 §6 recovery treats
// every torn artifact of a routine crash as a deterministic discard, never a
// refusal to boot (04 §11.4: launchd kills mark1d during sleep) — only a bad
// header BELOW a durable successor stays fatal, because rotation's
// fsync-before-mint ordering means no crash can produce that shape.
func TestRecoveryDiscardsTornUnbornSegment(t *testing.T) {
	seed := func(t *testing.T) string {
		t.Helper()
		dir := t.TempDir()
		s, err := Open(testConfig(dir, 160, 1<<20))
		if err != nil {
			t.Fatal(err)
		}
		mustAppend(t, s, 1, ClassBilling, []byte("durable"))
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	reopen := func(t *testing.T, dir string, wantDrops []Dropped) {
		t.Helper()
		r, err := Open(testConfig(dir, 160, 1<<20))
		if err != nil {
			t.Fatalf("torn unborn segment must not refuse boot: %v", err)
		}
		defer func() { _ = r.Close() }()
		if _, err := os.Stat(segPath(dir, 2)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("torn segment not removed: %v", err)
		}
		ack, _ := r.Cursors()
		recs, _, err := r.Records(ack)
		if err != nil || len(recs) != 1 || !bytes.Equal(recs[0].Payload, []byte("durable")) {
			t.Fatalf("durable record lost across torn-segment discard: %d recs, err %v", len(recs), err)
		}
		drops := r.DrainDropped()
		if len(drops) != len(wantDrops) {
			t.Fatalf("drops %v, want %v", drops, wantDrops)
		}
		for i := range drops {
			if drops[i] != wantDrops[i] {
				t.Fatalf("drops %v, want %v", drops, wantDrops)
			}
		}
		// The discard must free the seq for re-mint: rotation re-creates
		// seg 2 with O_EXCL, which a skipped-but-present file would refuse.
		for i := 0; i < 3; i++ {
			mustAppend(t, r, 10+i, ClassBilling, bytes.Repeat([]byte{0xAA}, 40))
		}
		if err := r.Sync(); err != nil {
			t.Fatal(err)
		}
		if _, write := r.Cursors(); write.Seq < 2 {
			t.Fatalf("expected rotation past the discarded seq, write %v", write)
		}
	}

	t.Run("zero_byte", func(t *testing.T) {
		dir := seed(t)
		if err := os.WriteFile(segPath(dir, 2), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		reopen(t, dir, nil)
	})
	t.Run("partial_header", func(t *testing.T) {
		dir := seed(t)
		hdr := encodeSegHeader(2, uint64(fixedNow.UnixNano()))
		if err := os.WriteFile(segPath(dir, 2), hdr[:30], 0o600); err != nil {
			t.Fatal(err)
		}
		reopen(t, dir, nil)
	})
	t.Run("garbage_header_readable_records", func(t *testing.T) {
		// Data pages can outrun the header's under a no-fsync crash: record
		// bytes readable behind a garbage header are accounted CRC_LOSS by
		// class byte before removal — never silently discarded (07 §6 step 4).
		dir := seed(t)
		file := append(make([]byte, segHeaderLen), appendRecord(nil, makeRecordID(eid(9), ClassBilling), []byte("unborn"))...)
		if err := os.WriteFile(segPath(dir, 2), file, 0o600); err != nil {
			t.Fatal(err)
		}
		reopen(t, dir, []Dropped{{DropCRCLoss, ClassBilling, 1}})
	})
	t.Run("bad_header_below_successor_refuses", func(t *testing.T) {
		dir := seed(t)
		hdr := encodeSegHeader(2, uint64(fixedNow.UnixNano()))
		if err := os.WriteFile(segPath(dir, 2), hdr[:], 0o600); err != nil {
			t.Fatal(err)
		}
		seg1 := segPath(dir, 1)
		data, err := os.ReadFile(seg1)
		if err != nil {
			t.Fatal(err)
		}
		data[0] ^= 0xFF
		if err := os.WriteFile(seg1, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(testConfig(dir, 160, 1<<20)); err == nil {
			t.Fatal("bad header below a durable successor is corruption: Open must refuse")
		}
	})
	t.Run("sole_torn_segment_is_first_boot", func(t *testing.T) {
		// Crash inside the very first openSegmentLocked(1): the next boot must
		// take the first-boot path, and the removed file must not O_EXCL-block
		// re-seeding seg 1.
		dir := t.TempDir()
		if err := os.WriteFile(segPath(dir, 1), make([]byte, 17), 0o600); err != nil {
			t.Fatal(err)
		}
		s, err := Open(testConfig(dir, 160, 1<<20))
		if err != nil {
			t.Fatalf("sole torn segment must re-seed, not boot-loop: %v", err)
		}
		defer func() { _ = s.Close() }()
		mustAppend(t, s, 1, ClassBilling, []byte("reborn"))
		if err := s.Sync(); err != nil {
			t.Fatal(err)
		}
		ack, _ := s.Cursors()
		recs, _, err := s.Records(ack)
		if err != nil || len(recs) != 1 {
			t.Fatalf("%d records, err %v", len(recs), err)
		}
	})
}

// The 07 §6 cadence as tick behavior: billing-grade pending syncs on the next
// 250 ms tick; diagnostics-only defers exactly one tick (500 ms).
func TestAdaptiveFsyncCadence(t *testing.T) {
	dir := t.TempDir()
	ticks := make(chan time.Time)
	intervals := make(chan time.Duration, 16)
	cfg := testConfig(dir, 1<<20, 1<<30)
	cfg.After = func(d time.Duration) <-chan time.Time {
		intervals <- d
		return ticks
	}
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()

	waitInterval := func() time.Duration {
		t.Helper()
		select {
		case d := <-intervals:
			return d
		case <-time.After(2 * time.Second):
			t.Fatal("fsync loop stalled")
			return 0
		}
	}
	if d := waitInterval(); d != 250*time.Millisecond {
		t.Fatalf("tick interval %v", d)
	}

	// Diagnostics only: first tick defers, second syncs — 500 ms cadence.
	mustAppend(t, s, 1, ClassDiagnostic, []byte("diag"))
	_, before := s.Cursors()
	ticks <- fixedNow
	waitInterval()
	if _, w := s.Cursors(); w != before {
		t.Fatal("diagnostics-only synced on the first tick (250 ms), want deferred (500 ms)")
	}
	ticks <- fixedNow
	waitInterval()
	if _, w := s.Cursors(); w == before {
		t.Fatal("diagnostics not durable after the second tick")
	}

	// Billing pending: the very next tick syncs — 250 ms cadence.
	mustAppend(t, s, 2, ClassBilling, []byte("bill"))
	_, before = s.Cursors()
	ticks <- fixedNow
	waitInterval()
	if _, w := s.Cursors(); w == before {
		t.Fatal("billing-grade not durable after one tick (250 ms promise)")
	}
}

func TestAppendRefusesBounds(t *testing.T) {
	s, err := Open(testConfig(t.TempDir(), 1<<20, 1<<30))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	ctx := context.Background()
	if err := s.Append(ctx, eid(1), Class(9), []byte("x")); err == nil {
		t.Fatal("unknown class must be refused — it would poison recovery accounting")
	}
	if err := s.Append(ctx, eid(1), ClassBilling, nil); err == nil {
		t.Fatal("empty payload violates 20 < len")
	}
	if err := s.Append(ctx, eid(1), ClassBilling, make([]byte, maxRecordLen-recordIDLen+1)); err == nil {
		t.Fatal("payload past the record bound must be refused")
	}
}

// FuzzSpoolRecordDecode: decodeRecord/tornClass over arbitrary bytes — never
// panic, never over-consume, and every accept re-encodes byte-identically
// (the same walk recovery trusts after a crash).
func FuzzSpoolRecordDecode(f *testing.F) {
	valid := appendRecord(nil, makeRecordID(eid(7), ClassBilling), []byte("payload bytes"))
	f.Add(valid)
	f.Add(valid[:len(valid)-3]) // torn payload
	f.Add(valid[:9])            // torn record_id — class byte lost
	corrupt := bytes.Clone(valid)
	corrupt[5] ^= 0x01 // crc mismatch
	f.Add(corrupt)
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x00, 0x00, 0x00}) // len 0 < minRecordLen
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF}) // len past maxRecordLen
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = tornClass(data)
		id, payload, consumed, ok := decodeRecord(data)
		if !ok {
			return
		}
		if consumed < 8+minRecordLen || consumed > len(data) || consumed > 8+maxRecordLen {
			t.Fatalf("consumed %d outside bounds (input %d)", consumed, len(data))
		}
		back := appendRecord(nil, id, payload)
		if !bytes.Equal(back, data[:consumed]) {
			t.Fatal("accepted record does not re-encode byte-identically")
		}
	})
}

// Guard for the deliberate mirror of m1p.v1 numbering — the daemon's future
// translation to the wire enums is a cast, not a table (07 §6, envelope.proto).
func TestClassAndReasonNumbersMirrorProto(t *testing.T) {
	if ClassBilling != 1 || ClassDiagnostic != 2 || ClassUnknown != 0 {
		t.Fatal("DurabilityClass drift against envelope.proto")
	}
	if DropSpoolShed != 1 || DropCRCLoss != 2 {
		t.Fatal("DropReason drift against envelope.proto")
	}
}
