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
	"strconv"
	"strings"
	"sync/atomic"
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
	// Slot fields read by offset rather than through parseSlot: bestSlot above
	// shares its encoder with the writer, so a transposed pair (write against
	// ack, seq against off) round-trips perfectly here and only surfaces after a
	// crash, as a replay window pointing at the wrong bytes. 07 §6's table is
	// the contract, so the bytes are what gets asserted.
	slot := lbuf[int(st.generation%2)*slotLen:]
	if binary.LittleEndian.Uint64(slot[0:8]) != st.generation ||
		binary.LittleEndian.Uint64(slot[8:16]) != write.Seq ||
		binary.LittleEndian.Uint64(slot[16:24]) != write.Off ||
		binary.LittleEndian.Uint64(slot[24:32]) != ack.Seq ||
		binary.LittleEndian.Uint64(slot[32:40]) != ack.Off {
		t.Fatalf("ledger slot fields off 07 §6's layout: % x", slot[0:40])
	}
	if binary.LittleEndian.Uint32(slot[40:44]) != crc32.Checksum(slot[0:40], table) {
		t.Fatal("ledger slot crc32c is not Castagnoli over bytes 0..40")
	}
	if !bytes.Equal(slot[44:64], make([]byte, 20)) {
		t.Fatal("ledger slot reserved bytes not zero")
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

// TestSegmentWithAnUnackedRecordSurvivesGC is the direction the test above never
// exercises. That one proves a FULLY acked segment is deleted; NFR-DURABILITY-005
// is the converse — "a segment with any unacked record must not be deleted" — and
// a citation that only ever ran the delete case vouches for nothing here. The
// distinction lives in one comparison (`seq < s.ack.Seq`, Ack); relaxing it to
// `<=` passes every other test in this file and silently deletes acknowledged-plus-
// pending segments, which is unrecoverable data loss rather than a re-send.
func TestSegmentWithAnUnackedRecordSurvivesGC(t *testing.T) {
	dir := t.TempDir()
	// 64-byte header + two 48-byte records per segment, so records 1 and 2 fill
	// and seal segment 1 and record 3 opens segment 2.
	s, err := Open(testConfig(dir, 160, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()

	payload := bytes.Repeat([]byte{0xA1}, 20)
	for i := 1; i <= 3; i++ {
		mustAppend(t, s, i, ClassBilling, payload)
	}
	if err := s.Sync(); err != nil {
		t.Fatal(err)
	}
	recs, _, err := s.Records(Cursor{1, segHeaderLen})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 3 || recs[1].Pos.Seq != 1 || recs[2].Pos.Seq != 2 {
		t.Fatalf("layout = %d records at %v; want 3 with records 1-2 in segment 1 and record 3 in segment 2",
			len(recs), func() []Cursor {
				p := make([]Cursor, len(recs))
				for i, r := range recs {
					p[i] = r.Pos
				}
				return p
			}())
	}

	// Ack the first record only. Segment 1 is sealed AND still holds record 2.
	if err := s.Ack(recs[1].Pos); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(segPath(dir, 1)); err != nil {
		t.Fatalf("segment 1 was deleted while it still held unacked record 2: %v", err)
	}
	back, _, err := s.Records(recs[1].Pos)
	if err != nil {
		t.Fatal(err)
	}
	if want := eid(2); len(back) != 2 || string(back[0].ID[:16]) != string(want[:]) {
		t.Fatalf("re-read from the ack cursor gave %d records starting %v; want 2 starting at record 2",
			len(back), back[0].ID)
	}

	// Acking past it is what earns the delete.
	if err := s.Ack(recs[2].Pos); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(segPath(dir, 1)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("segment 1 survived an ack that covers all of it: %v", err)
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

// The 04 §8.1 single-writer claim is inter-PROCESS, not merely inter-goroutine:
// a second daemon on the same directory recovers to the same tail offset and
// appends into the same open segment. Nothing downstream can detect that — each
// interleaved record is individually well-formed with a valid CRC — so the loss
// is silent and billing-grade. Refusing to boot is the cheap failure.
func TestSecondOpenIsRefusedNotInterleaved(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(testConfig(dir, 1<<20, 1<<30))
	if err != nil {
		t.Fatal(err)
	}
	mustAppend(t, s, 1, ClassBilling, []byte("first writer"))

	second, err := Open(testConfig(dir, 1<<20, 1<<30))
	if err == nil {
		_ = second.Close()
		t.Fatal("second Open on a live spool dir succeeded — two writers interleave into one segment")
	}
	if !strings.Contains(err.Error(), strconv.Itoa(os.Getpid())) {
		t.Fatalf("refusal must name the holder, not just fail: %v", err)
	}

	// Released by Close, so a clean restart is never locked out. A kill -9
	// needs no test and no cleanup path: the kernel drops the lock with the
	// process, which is why this is an OS lock and not a pidfile.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(testConfig(dir, 1<<20, 1<<30))
	if err != nil {
		t.Fatalf("restart after clean shutdown must acquire the lock: %v", err)
	}
	defer func() { _ = s2.Close() }()
	ack, _ := s2.Cursors()
	recs, _, err := s2.Records(ack)
	if err != nil || len(recs) != 1 {
		t.Fatalf("%d records after restart, err %v", len(recs), err)
	}
}

// NFR-FOOTPRINT-002 / F-19: the 95%-disk stop is the second, independent limit
// — the spool stops before the HOST fills, whatever its own ~2 GiB cap says.
// 02 §8.2 puts billing-grade under it too, so the policy is exactly
// FR-SPINE-007's: billing blocks, diagnostics shed and are accounted.
func TestDiskHardStop(t *testing.T) {
	dir := t.TempDir()
	ticks := make(chan time.Time)
	var usedPct atomic.Uint64
	usedPct.Store(99)
	cfg := testConfig(dir, 1<<20, 1<<30)
	cfg.After = func(time.Duration) <-chan time.Time { return ticks }
	cfg.DiskUsage = func(string) (float64, error) { return float64(usedPct.Load()) / 100, nil }

	// Booting onto a full disk must still work: a spool that refuses to open
	// can never drain its backlog, which is one of the ways the disk empties.
	s, err := Open(cfg)
	if err != nil {
		t.Fatalf("Open past the hard stop must still recover and boot: %v", err)
	}
	defer func() { _ = s.Close() }()

	payload := bytes.Repeat([]byte{0xD5}, 20)
	if err := s.Append(context.Background(), eid(1), ClassDiagnostic, payload); !errors.Is(err, ErrDiagnosticShed) {
		t.Fatalf("diagnostic past the hard stop: %v, want shed", err)
	}
	if drops := s.DrainDropped(); len(drops) != 1 || drops[0] != (Dropped{DropSpoolShed, ClassDiagnostic, 1}) {
		t.Fatalf("hard-stop shed accounting: %v", drops)
	}

	blocked := make(chan error, 1)
	go func() { blocked <- s.Append(context.Background(), eid(2), ClassBilling, payload) }()
	select {
	case err := <-blocked:
		t.Fatalf("billing-grade append proceeded past the hard stop (%v) — 02 §8.2 applies it to every class", err)
	case <-time.After(50 * time.Millisecond):
	}

	// Space returns — from anything, the spool is not the only writer on the
	// volume — and the next cadence tick clears the stop and wakes the waiter.
	usedPct.Store(50)
	ticks <- fixedNow
	select {
	case err := <-blocked:
		if err != nil {
			t.Fatalf("billing append once the disk drained: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("billing append still blocked after the disk fell below 95% — capture never resumes")
	}
	if err := s.Sync(); err != nil {
		t.Fatal(err)
	}
	ack, _ := s.Cursors()
	recs, _, err := s.Records(ack)
	if err != nil || len(recs) != 1 || recs[0].ID != makeRecordID(eid(2), ClassBilling) {
		t.Fatalf("resumed capture: %d records, err %v", len(recs), err)
	}
}

// 07 §6 step 3 names four ways a record fails to decode, and a crc32c mismatch
// is the only one truncation cannot produce: a short file trips the length
// checks first, so TestCrashRecoveryTruncationSweep's several hundred cut
// positions never once reach the CRC branch. FuzzSpoolRecordDecode does feed it
// a corrupt seed, but returns on every rejection and asserts nothing about it.
// So 02 §9's "corrupt crc32c detected" had no test that would fail if the
// compare in decodeRecord were deleted — and with it gone, bit-rotted billing
// bytes replay to ingest as genuine, which is worse than the loss the checksum
// exists to report.
//
// The flip is planted in the UN-fsynced tail deliberately. Below the durable
// cursor every record was verified at write time, so damage there is a
// different fault that Records() refuses outright (spool.go:428); the recovery
// scan is the path that must both detect and account this one, and it only ever
// runs above the ledger's write cursor.
func TestCorruptRecordIsDetectedAndAccounted(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(testConfig(dir, 1<<20, 1<<30))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()

	for i := 0; i < 3; i++ {
		mustAppend(t, s, i, ClassBilling, bytes.Repeat([]byte{0xB0}, 40))
	}
	if err := s.Sync(); err != nil {
		t.Fatal(err)
	}
	_, durable := s.Cursors()

	// The middle tail record is diagnostic among billing neighbours, so the
	// accounting has to read ITS byte [16] rather than carry a class over from
	// the records either side of it.
	tailPayloads := [][]byte{
		bytes.Repeat([]byte{0xD1}, 24),
		bytes.Repeat([]byte{0xD2}, 32),
		bytes.Repeat([]byte{0xD3}, 16),
	}
	tailClasses := []Class{ClassBilling, ClassDiagnostic, ClassBilling}
	starts := make([]uint64, len(tailPayloads))
	end := durable.Off
	for i, p := range tailPayloads {
		starts[i] = end
		end += uint64(recHeaderLen + len(p))
		mustAppend(t, s, 100+i, tailClasses[i], p)
	}
	src, err := os.ReadFile(segPath(dir, durable.Seq))
	if err != nil {
		t.Fatal(err)
	}
	if uint64(len(src)) != end {
		t.Fatalf("live segment %d bytes, want %d", len(src), end)
	}
	ledgerBytes, err := os.ReadFile(filepath.Join(dir, "spool.ledger"))
	if err != nil {
		t.Fatal(err)
	}

	// Each case recovers its own copy of the crashed directory: the ledger as it
	// stood at the last fsync, plus the segment with one byte changed.
	replay := func(t *testing.T, flip func([]byte)) (*Spool, string) {
		t.Helper()
		cdir := t.TempDir()
		seg := bytes.Clone(src)
		flip(seg)
		if err := os.WriteFile(filepath.Join(cdir, "spool.ledger"), ledgerBytes, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(segPath(cdir, durable.Seq), seg, 0o600); err != nil {
			t.Fatal(err)
		}
		r, err := Open(testConfig(cdir, 1<<20, 1<<30))
		if err != nil {
			t.Fatalf("corruption in the un-fsynced tail must recover, not refuse boot: %v", err)
		}
		t.Cleanup(func() { _ = r.Close() })
		return r, cdir
	}

	// Positive control, and the anti-vacuity floor under every case below: the
	// same bytes with nothing flipped recover all six records and account
	// nothing. "The records after the corruption are gone" is otherwise exactly
	// what a harness recovering an empty spool would also report.
	t.Run("uncorrupted_control", func(t *testing.T) {
		r, _ := replay(t, func([]byte) {})
		ack, write := r.Cursors()
		if write != (Cursor{durable.Seq, end}) {
			t.Fatalf("clean replay stops at %v, want the whole tail at (%d,%d)", write, durable.Seq, end)
		}
		recs, _, err := r.Records(ack)
		if err != nil || len(recs) != 6 {
			t.Fatalf("clean replay: %d records, err %v; want all 6", len(recs), err)
		}
		if !bytes.Equal(recs[4].Payload, tailPayloads[1]) {
			t.Fatal("clean replay: the record the corrupted cases target is not the one recovered here")
		}
		if drops := r.DrainDropped(); len(drops) != 0 {
			t.Fatalf("clean replay accounted losses: %v", drops)
		}
	})

	// One flipped bit in each region the crc32c is supposed to protect. The
	// event_id case is the one that would hurt most silently: those 16 bytes ARE
	// the wire idempotency key (07 §6), so a flip there re-keys the record and
	// walks straight past the server's dedupe.
	for _, tc := range []struct {
		name string
		at   uint64 // byte offset from the start of the corrupted record
	}{
		{"crc_field", 4},
		{"event_id", 8},
		{"payload", recHeaderLen + 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, cdir := replay(t, func(seg []byte) { seg[starts[1]+tc.at] ^= 0x01 })

			ack, write := r.Cursors()
			if write != (Cursor{durable.Seq, starts[1]}) {
				t.Fatalf("recovered write %v, want the last good boundary %d: a failing crc32c is a torn tail (07 §6 step 3)", write, starts[1])
			}
			info, err := os.Stat(segPath(cdir, durable.Seq))
			if err != nil {
				t.Fatal(err)
			}
			if uint64(info.Size()) != starts[1] {
				t.Fatalf("segment left at %d bytes, want truncated to %d — a corrupt record left in place poisons every future scan", info.Size(), starts[1])
			}
			recs, _, err := r.Records(ack)
			if err != nil {
				t.Fatal(err)
			}
			if len(recs) != 4 {
				t.Fatalf("%d records survive, want the 3 fsynced plus the one clean tail record ahead of the corruption", len(recs))
			}
			for i := 0; i < 3; i++ {
				if recs[i].ID != makeRecordID(eid(i), ClassBilling) {
					t.Fatalf("fsynced billing record %d lost to corruption in the un-fsynced tail", i)
				}
			}
			if recs[3].ID != makeRecordID(eid(100), ClassBilling) || !bytes.Equal(recs[3].Payload, tailPayloads[0]) {
				t.Fatalf("tail record ahead of the corruption drifted: %+v", recs[3])
			}
			drops := r.DrainDropped()
			if len(drops) != 1 || drops[0] != (Dropped{DropCRCLoss, ClassDiagnostic, 1}) {
				t.Fatalf("drops %v, want one CRC_LOSS charged to the corrupted record's own class byte", drops)
			}
		})
	}
}

// 07 §6: `SessionEnd` and daemon shutdown "force a full drain (fsync + upload
// attempt) regardless" of where the cadence stands. Every other test here calls
// Sync before it closes, and the ones that do not are covered anyway by
// recovery — scanForward walks past a stale ledger cursor and finds the records
// regardless, so a Close that skipped syncLocked outright still replays
// everything and no reopen-and-count assertion can tell the two apart.
//
// What the drain uniquely produces is a LEDGER that already covers the tail:
// the difference between durability the daemon can claim at exit (cmd/main.go's
// sp.Sync() before Flush uploads those bytes) and durability the next boot has
// to go looking for. So the assertion is on the published slot, and the
// pre-Close read is what stops it being vacuous — it proves the records were
// genuinely still pending when Close was called.
func TestCloseDrainsPendingAppends(t *testing.T) {
	dir := t.TempDir()
	// neverAfter parks the cadence loop: nothing but Close can do the drain's job.
	s, err := Open(testConfig(dir, 1<<20, 1<<30))
	if err != nil {
		t.Fatal(err)
	}
	_, before := s.Cursors()

	billing := []byte("billing-grade, pending at shutdown")
	// A diagnostics-only tail is the cadence's deferred case (skipTick): if
	// shutdown ever inherited that deferral it would leave 500 ms unpublished.
	diagnostic := []byte("diagnostic, pending at shutdown")
	mustAppend(t, s, 1, ClassBilling, billing)
	mustAppend(t, s, 2, ClassDiagnostic, diagnostic)
	want := Cursor{before.Seq, before.Off + uint64(2*recHeaderLen+len(billing)+len(diagnostic))}

	readSlot := func(label string) ledgerState {
		t.Helper()
		lbuf, err := os.ReadFile(filepath.Join(dir, "spool.ledger"))
		if err != nil {
			t.Fatal(err)
		}
		st, ok := bestSlot(lbuf)
		if !ok {
			t.Fatalf("%s: no ledger slot verifies", label)
		}
		return st
	}
	pre := readSlot("before Close")
	if pre.write != before {
		t.Fatalf("ledger already at %v before Close (want %v): the appends were durable without a drain, so the assertion below would pass on its own", pre.write, before)
	}

	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	post := readSlot("after Close")
	if post.write != want {
		t.Fatalf("ledger publishes %v after Close, want the whole pending tail at %v: shutdown forces a full drain regardless of cadence (07 §6)", post.write, want)
	}
	if post.generation <= pre.generation {
		t.Fatalf("ledger generation %d did not advance past %d — Close republished nothing", post.generation, pre.generation)
	}

	// And the drained bytes are real records, not just a cursor that moved.
	r, err := Open(testConfig(dir, 1<<20, 1<<30))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	ack, _ := r.Cursors()
	recs, _, err := r.Records(ack)
	if err != nil || len(recs) != 2 {
		t.Fatalf("%d records after a drained shutdown, err %v; want 2", len(recs), err)
	}
	if !bytes.Equal(recs[0].Payload, billing) || !bytes.Equal(recs[1].Payload, diagnostic) {
		t.Fatal("drained payloads drifted")
	}
	if drops := r.DrainDropped(); len(drops) != 0 {
		t.Fatalf("a clean drained shutdown accounted losses: %v", drops)
	}
}

// The 95% in "95%-disk hard stop" is a number the requirement states, and
// TestDiskHardStop only ever samples 99% — which a threshold wired at 0.99, or
// 0.999, or one that only fires when Bavail hits zero, passes identically. The
// margin left to the host IS the promise (NFR-FOOTPRINT-002), so the boundary
// is the thing worth pinning. No tick is needed to observe it: Open samples
// before the first Append (spool.go:211) precisely so booting onto a full disk
// gets no free cadence of writes.
func TestDiskHardStopBoundaryIsNinetyFivePercent(t *testing.T) {
	for _, tc := range []struct {
		name  string
		used  float64
		halts bool
	}{
		// Literals, never diskHardStopRatio: a case that reads the constant it
		// is meant to pin moves with it and asserts only that the spool agrees
		// with itself.
		{"just_below", 0.9499, false},
		{"exactly_at", 0.95, true},
		{"above", 0.9501, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(t.TempDir(), 1<<20, 1<<30)
			cfg.DiskUsage = func(string) (float64, error) { return tc.used, nil }
			s, err := Open(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = s.Close() }()

			err = s.Append(context.Background(), eid(1), ClassDiagnostic, bytes.Repeat([]byte{0xD5}, 20))
			if tc.halts {
				if !errors.Is(err, ErrDiagnosticShed) {
					t.Fatalf("append at %.4f disk used: %v, want the hard stop to shed it", tc.used, err)
				}
				return
			}
			// Positive control: below the stop this is an ordinary spool. A
			// stop wired at 0 refuses everything and would otherwise look
			// admirably strict.
			if err != nil {
				t.Fatalf("append at %.4f disk used: %v, want it accepted below the 95%% stop", tc.used, err)
			}
			if err := s.Sync(); err != nil {
				t.Fatal(err)
			}
			ack, _ := s.Cursors()
			recs, _, err := s.Records(ack)
			if err != nil || len(recs) != 1 {
				t.Fatalf("%d records below the stop, err %v; want 1", len(recs), err)
			}
		})
	}
}

// Config exists so tests can shrink the two sizes 07 §6 names, which means
// every other test in this file overrides them and nothing would notice 64 MiB
// segments silently becoming 16 MiB, or the ~2 GiB cap becoming 200 MiB. Both
// are felt by a user as churn and as disk, never as a failed assertion.
func TestDefaultSegmentAndCapSizes(t *testing.T) {
	s, err := Open(Config{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if s.segSize != 64<<20 || s.spoolCap != 2<<30 {
		t.Fatalf("defaults are %d-byte segments and a %d-byte cap; 07 §6 says 64 MiB and ~2 GiB", s.segSize, s.spoolCap)
	}
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

// TestHardStopHookFiresOnBothEdges is 04 §2.7's site 2: the hook is how the
// daemon receipts CoverageTransition{BYPASS,"disk_hard_stop"}, and a window
// with only one edge is not a window. It also pins the two properties the
// caller depends on for correctness rather than for style: the hook runs with
// NO spool lock held (it appends an event, and appending under s.mu deadlocks),
// and edges arrive in order (a `go` here could invert a coverage window).
func TestHardStopHookFiresOnBothEdges(t *testing.T) {
	dir := t.TempDir()
	ticks := make(chan time.Time)
	var usedPct atomic.Uint64
	usedPct.Store(50)
	cfg := testConfig(dir, 1<<20, 1<<30)
	cfg.After = func(time.Duration) <-chan time.Time { return ticks }
	cfg.DiskUsage = func(string) (float64, error) { return float64(usedPct.Load()) / 100, nil }

	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()

	edges := make(chan bool, 8)
	s.SetHardStopHook(func(entered bool) {
		// Proves no lock is held: this would deadlock under s.mu, and the
		// shed is the honest outcome while the stop is up.
		_ = s.Append(context.Background(), eid(99), ClassDiagnostic, []byte("coverage"))
		edges <- entered
	})
	// A spool below the stop must not claim a bypass window nobody is in.
	select {
	case e := <-edges:
		t.Fatalf("hook fired (entered=%v) on a spool that is not hard-stopped", e)
	default:
	}

	// Bounded: an edge that never arrives is a FAILURE, not a hang. A blocking
	// receive here would turn "the window never closes" into a CI timeout with
	// no test name on it, which is the one report nobody reads.
	nextEdge := func(what string) bool {
		t.Helper()
		select {
		case e := <-edges:
			return e
		case <-time.After(2 * time.Second):
			t.Fatalf("no hook call for %s", what)
			return false
		}
	}

	usedPct.Store(99)
	ticks <- fixedNow
	if !nextEdge("crossing the hard stop") {
		t.Fatal("crossing the hard stop delivered entered=false")
	}
	usedPct.Store(50)
	ticks <- fixedNow
	if nextEdge("draining below the hard stop") {
		t.Fatal("draining below the hard stop delivered entered=true — the window closes as a second open")
	}
	// Level, not edge: an unchanged sample must not re-announce the window.
	ticks <- fixedNow
	select {
	case e := <-edges:
		t.Fatalf("hook re-fired (entered=%v) with no edge; every tick would be a fresh window", e)
	case <-time.After(50 * time.Millisecond):
	}
}

// TestHardStopHookReplaysAnAlreadyStoppedSpool. The emitter is built on top of
// the spool Open returns, so it cannot be installed before Open samples the
// disk. Without this replay, a daemon booting onto a full disk reports the one
// window nobody would ever see.
func TestHardStopHookReplaysAnAlreadyStoppedSpool(t *testing.T) {
	cfg := testConfig(t.TempDir(), 1<<20, 1<<30)
	cfg.After = func(time.Duration) <-chan time.Time { return make(chan time.Time) }
	cfg.DiskUsage = func(string) (float64, error) { return 0.99, nil }
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()

	edges := make(chan bool, 4)
	s.SetHardStopHook(func(entered bool) { edges <- entered })
	select {
	case e := <-edges:
		if !e {
			t.Fatal("replay delivered entered=false on a hard-stopped spool")
		}
	case <-time.After(time.Second):
		t.Fatal("a spool already past the hard stop did not replay the window to a late hook")
	}
}
