//go:build chaos

// chaos_daemon_kill9 — FR-SPINE-024 / NFR-DURABILITY-002, the frozen plan's
// headline Phase-1 verification line ("deliberate kill -9 mid-batch loses
// nothing in the billing-grade classes") and 12 §6.2's ⚡ fast-set row.
//
// Every other spool test simulates the crash from inside the process that is
// supposed to have died: TestCrashRecoveryTruncationSweep corrupts bytes by
// hand, TestLedgerTornWriteSurvivesOnOtherSlot rewrites a ledger slot. Those
// model POWER LOSS, and they model it well. None of them models process
// death, and process death is the fault this row names — the one where the
// flock D-CJ added has to be released by the kernel, where the ledger is left
// wherever the 250 ms syncer happened to leave it, and where recovery runs in
// a genuinely fresh address space with nothing carried over.
//
// THE ASSERTION IS STRICTLY STRONGER THAN 12 §347 SPECIFIES, deliberately —
// but along a different axis than this comment first claimed, and the
// correction is worth keeping because the wrong version is the intuitive one.
// That row allows a torn tail record "bounded by the 250-500 ms fsync window".
// The bound is wrong for this fault: SIGKILL reaps a process, it does not drop
// the page cache, so bytes that reached the kernel are there for the next
// reader whether or not fsync ran and the fsync window bounds nothing here. A
// harness that tolerated "a torn tail" on that reasoning would equally
// tolerate the spool silently dropping its last two hundred records.
//
// What does NOT follow — and what this file asserted for a while — is that
// nothing can tear at all. Page-cache retention is not write atomicity. The
// kernel applies a write page by page and abandons the loop when a fatal
// signal is pending, so a record straddling a page boundary is left torn AT
// that boundary. Observed here: a 228-byte record at offset 3940 of a segment
// that ends at exactly 4096. Confirmed independently — a single WriteAt of
// 64 MiB, SIGKILLed, lands a page-aligned prefix 40 times out of 40.
//
// So the real bound is not the fsync window and not zero: it is THE SINGLE
// APPEND IN FLIGHT. The child keeps exactly one, and an Append that has
// returned has fully landed. One torn record is physics; a second one, or a
// torn record in a class the child never writes, is a returned Append that
// left torn bytes behind. Everything else stays zero-tolerance — the tear may
// cost only the record nobody was ever told was durable, and it may not be
// silent, which is why the drop is required to be ACCOUNTED rather than
// merely permitted.
//
// Loss is detected without a second durability channel, which matters because
// any side-file the child wrote to would need its own crash-consistency
// argument. The child appends billing records whose event_id encodes a
// monotone counter, one Append in flight at a time. So record N+1 existing
// proves record N's Append returned, and the recovered set must therefore be a
// GAP-FREE PREFIX. A hole is a record that was written, has a successor on
// disk, and is gone: loss, unambiguously, with no bookkeeping to disbelieve.
package spool

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

const (
	chaosChildEnv = "M1_CHAOS_KILL9_CHILD"
	chaosDirEnv   = "M1_CHAOS_KILL9_DIR"
	// The child announces itself only after this many records are durable, so
	// a kill that lands early cannot produce a vacuous pass on an empty spool.
	// The floor is asserted after recovery, not merely waited for.
	chaosReadyFloor = 64
	chaosIterations = 100
	// Small enough that a run of a few thousand records rotates segments many
	// times: rotation is where kill -9 has a header-sized window to land in
	// (recovery.go:99-109), and a single-segment harness would never open it.
	chaosSegSize  = 32 << 10
	chaosSpoolCap = 64 << 20
)

func TestChaosDaemonKill9(t *testing.T) {
	if os.Getenv(chaosChildEnv) == "1" {
		chaosChild()
		return
	}

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	var totalRecovered, maxRecovered, tornIters int
	for i := 0; i < chaosIterations; i++ {
		dir := t.TempDir()
		child := exec.Command(os.Args[0], "-test.run=^TestChaosDaemonKill9$")
		child.Env = append(os.Environ(), chaosChildEnv+"=1", chaosDirEnv+"="+dir)
		child.Stderr = os.Stderr
		stdout, err := child.StdoutPipe()
		if err != nil {
			t.Fatalf("iteration %d: stdout pipe: %v", i, err)
		}
		if err := child.Start(); err != nil {
			t.Fatalf("iteration %d: start: %v", i, err)
		}

		// Wait for the child to be genuinely mid-flight rather than mid-startup.
		ready := make(chan string, 1)
		go func() {
			sc := bufio.NewScanner(stdout)
			if sc.Scan() {
				ready <- sc.Text()
				return
			}
			ready <- ""
		}()
		select {
		case line := <-ready:
			if line != "ready" {
				_ = child.Process.Kill()
				_ = child.Wait()
				t.Fatalf("iteration %d: child never reached %d durable records (said %q)", i, chaosReadyFloor, line)
			}
		case <-time.After(30 * time.Second):
			_ = child.Process.Kill()
			_ = child.Wait()
			t.Fatalf("iteration %d: child did not signal ready within 30s", i)
		}

		// Land the signal at a random point in the write loop. The spread is
		// the whole point: a fixed delay tests one interleaving 100 times.
		time.Sleep(time.Duration(rng.Intn(25_000)+500) * time.Microsecond)
		if err := child.Process.Kill(); err != nil {
			t.Fatalf("iteration %d: kill: %v", i, err)
		}
		// Reaped before Open: the flock is released by the kernel on death, but
		// only once the process is actually gone.
		_ = child.Wait()

		// Read the raw bytes BEFORE recovery touches them: recovery truncates
		// torn tails and deletes orphaned segments, so afterwards the only
		// account of what was on disk is the one written by the code under
		// test. Deriving the expected set independently is what makes tail loss
		// visible at all — a gap-free prefix stays gap-free when recovery
		// simply stops scanning early (D-CG's lesson, applied to a test).
		onDisk := chaosScanRawSegments(t, i, dir)
		n, torn := chaosVerifyRecovered(t, i, dir, onDisk)
		totalRecovered += n
		if torn {
			tornIters++
		}
		if n > maxRecovered {
			maxRecovered = n
		}
	}
	// The torn count is logged rather than bounded: it is a property of where
	// the signal landed relative to a page boundary, so a run that happens to
	// tear zero times proves nothing extra and a threshold would be a flake.
	t.Logf("chaos_daemon_kill9: %d iterations, %d billing records recovered total, %d in the largest run — "+
		"zero holes, zero duplicates; %d iteration(s) tore the in-flight Append and accounted it",
		chaosIterations, totalRecovered, maxRecovered, tornIters)
}

// chaosScanRawSegments walks seg-*.m1s with the decoder alone — no cursors, no
// ledger, no recovery — and returns every valid-CRC billing counter it finds.
// This is the ground truth recovery is graded against.
func chaosScanRawSegments(t *testing.T, iter int, dir string) map[uint64]bool {
	t.Helper()
	names, err := filepath.Glob(filepath.Join(dir, "seg-*.m1s"))
	if err != nil {
		t.Fatalf("iteration %d: glob: %v", iter, err)
	}
	sort.Strings(names)
	out := make(map[uint64]bool)
	for _, name := range names {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("iteration %d: read %s: %v", iter, name, err)
		}
		if len(data) <= segHeaderLen {
			continue
		}
		// Stop this segment at the first undecodable record: single-writer
		// means nothing valid follows a tear, and counting past one would
		// invent records recovery is right to discard.
		for buf := data[segHeaderLen:]; len(buf) > 0; {
			id, _, consumed, ok := decodeRecord(buf)
			if !ok {
				break
			}
			if id.Class() == ClassBilling {
				out[binary.LittleEndian.Uint64(id[:8])] = true
			}
			buf = buf[consumed:]
		}
	}
	return out
}

// chaosVerifyRecovered opens the dead child's spool in a fresh Spool (the real
// 07 §6 recovery path) and returns how many billing records survived, and
// whether the in-flight Append was found torn.
func chaosVerifyRecovered(t *testing.T, iter int, dir string, onDisk map[uint64]bool) (int, bool) {
	t.Helper()
	s, err := Open(chaosConfig(dir))
	if err != nil {
		t.Fatalf("iteration %d: recovery Open: %v", iter, err)
	}
	defer func() {
		if err := s.Close(); err != nil {
			t.Fatalf("iteration %d: close: %v", iter, err)
		}
	}()

	ack, _ := s.Cursors()
	recs, _, err := s.Records(ack)
	if err != nil {
		t.Fatalf("iteration %d: Records: %v", iter, err)
	}

	seen := make(map[uint64]bool, len(recs))
	for _, r := range recs {
		if r.ID.Class() != ClassBilling {
			t.Fatalf("iteration %d: recovered a class-%d record; the child writes billing only, so this is a decode that landed on the wrong bytes", iter, r.ID.Class())
		}
		n := binary.LittleEndian.Uint64(r.ID[:8])
		if seen[n] {
			t.Fatalf("iteration %d: record %d recovered twice — the spool is the dedupe key's own source, so a duplicate here is not something ingest can absorb", iter, n)
		}
		seen[n] = true
	}

	// The property: a gap-free prefix. Record n+1 on disk proves record n's
	// Append returned, so a missing n with a present n+1 is durable loss.
	missing := make([]uint64, 0, 4)
	for n := uint64(1); n <= uint64(len(seen)); n++ {
		if !seen[n] {
			missing = append(missing, n)
		}
	}
	if len(missing) > 0 {
		highest := uint64(0)
		for n := range seen {
			if n > highest {
				highest = n
			}
		}
		sort.Slice(missing, func(a, b int) bool { return missing[a] < missing[b] })
		t.Fatalf("iteration %d: %d billing records LOST: %v missing while %d records up to %d survived. "+
			"Each missing record has a successor on disk, so its Append had returned. kill -9 does not "+
			"drop the page cache; there is no fault here that could legitimately lose these.",
			iter, len(missing), missing[:min(len(missing), 16)], len(seen), highest)
	}
	// Against the independent scan: every record that was on stable media must
	// come back, and recovery must not conjure one that was not.
	var lost, invented []uint64
	for n := range onDisk {
		if !seen[n] {
			lost = append(lost, n)
		}
	}
	for n := range seen {
		if !onDisk[n] {
			invented = append(invented, n)
		}
	}
	if len(lost) > 0 {
		sort.Slice(lost, func(a, b int) bool { return lost[a] < lost[b] })
		t.Fatalf("iteration %d: recovery returned %d of the %d valid-CRC billing records physically present in the "+
			"segment files. %d lost, lowest %v. These bytes survived the kill; recovery is what dropped them",
			iter, len(seen), len(onDisk), len(lost), lost[:min(len(lost), 16)])
	}
	if len(invented) > 0 {
		sort.Slice(invented, func(a, b int) bool { return invented[a] < invented[b] })
		t.Fatalf("iteration %d: recovery returned %d records that no segment file contains: %v",
			iter, len(invented), invented[:min(len(invented), 16)])
	}

	if len(seen) < chaosReadyFloor {
		t.Fatalf("iteration %d: recovered %d records but the child had already published %d durable before signalling ready — "+
			"recovery went BACKWARDS past an fsync", iter, len(seen), chaosReadyFloor)
	}

	// The one permitted casualty: the Append that was still inside WriteAt when
	// the signal landed, torn at a page boundary and correctly accounted. It is
	// permitted only because nothing was ever told it was durable — the checks
	// above have already proved every record with a successor came back.
	// Anything beyond it means an Append that RETURNED left torn bytes.
	drops := s.DrainDropped()
	for _, d := range drops {
		// ClassUnknown is honest, not sloppy: a tear can land before byte [16],
		// and tornClass refuses to guess a class it cannot read.
		wrongClass := d.Class != ClassBilling && d.Class != ClassUnknown
		if len(drops) > 1 || d.Reason != DropCRCLoss || d.Quantity != 1 || wrongClass {
			t.Fatalf("iteration %d: recovery accounted %v as dropped. At most ONE torn record is possible here — "+
				"the child holds one Append in flight and a returned Append has fully landed — and it can only be "+
				"CRC_LOSS in the class the child writes. This is a returned Append leaving torn bytes, a shed on a "+
				"spool that is nowhere near full, or the record format changing shape", iter, drops)
		}
	}
	return len(seen), len(drops) == 1
}

// chaosChild is the victim: a real process, doing real appends, that will be
// SIGKILLed at an arbitrary instruction. It never exits cleanly on the happy
// path — a clean shutdown drains, and a drained spool proves nothing.
func chaosChild() {
	dir := os.Getenv(chaosDirEnv)
	s, err := Open(chaosConfig(dir))
	if err != nil {
		fmt.Fprintf(os.Stderr, "chaos child: open: %v\n", err)
		os.Exit(1)
	}
	// 200 bytes: several records per 4 KiB page, so a segment spans many pages
	// and rotation lands often.
	payload := make([]byte, 200)
	for i := range payload {
		payload[i] = byte(i)
	}
	ctx := context.Background()
	for n := 1; ; n++ {
		if err := s.Append(ctx, eid(n), ClassBilling, payload); err != nil {
			fmt.Fprintf(os.Stderr, "chaos child: append %d: %v\n", n, err)
			os.Exit(1)
		}
		if n == chaosReadyFloor {
			// Sync before announcing so the floor asserted after recovery is a
			// claim about fsynced bytes, not about page cache.
			if err := s.Sync(); err != nil {
				fmt.Fprintf(os.Stderr, "chaos child: sync: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("ready")
		}
	}
}

func chaosConfig(dir string) Config {
	return Config{
		Dir:         dir,
		SegmentSize: chaosSegSize,
		SpoolCap:    chaosSpoolCap,
		Now:         time.Now,
		After:       time.After,
		// The host's real disk fullness is not part of this fault model, and a
		// CI runner past the 95% hard stop would block billing appends forever.
		DiskUsage: func(string) (float64, error) { return 0.10, nil },
	}
}
