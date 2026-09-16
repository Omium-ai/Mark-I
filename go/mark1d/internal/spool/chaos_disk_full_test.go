//go:build chaos

package spool

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fullProducers hammers one spool from both classes and remembers exactly what
// each Append promised: returned-nil ids are durable claims, sheds are counted.
type fullProducers struct {
	mu       sync.Mutex
	appended map[[16]byte]Class
	shed     uint64
	next     atomic.Int64
	wg       sync.WaitGroup
}

func (p *fullProducers) run(ctx context.Context, s *Spool, class Class, pace time.Duration) {
	defer p.wg.Done()
	payload := bytes.Repeat([]byte{byte(class)}, 100)
	for ctx.Err() == nil {
		id := eid(int(p.next.Add(1)))
		err := s.Append(ctx, id, class, payload)
		p.mu.Lock()
		switch {
		case err == nil:
			p.appended[id] = class
		case errors.Is(err, ErrDiagnosticShed):
			p.shed++
		}
		p.mu.Unlock()
		time.Sleep(pace)
	}
}

func (p *fullProducers) counts() (billing, diag int, shed uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.appended {
		if c == ClassBilling {
			billing++
		} else {
			diag++
		}
	}
	return billing, diag, p.shed
}

// billingParked proves a billing writer is BLOCKED, not failed: a fresh Append
// under its own short deadline must come back with that deadline and nothing else.
func billingParked(t *testing.T, s *Spool, what string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	err := s.Append(ctx, eid(1<<30), ClassBilling, bytes.Repeat([]byte{0xB1}, 100))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("%s: billing Append returned %v, want to block (deadline exceeded) — billing-grade must park, never shed or fail", what, err)
	}
}

// gradeRecovery reopens the spool cold and checks every promise the producers
// recorded against the bytes on disk: nothing lost, nothing invented, no
// corruption, and the shed ledger exact.
func gradeRecovery(t *testing.T, cfg Config, p *fullProducers, live *Spool, uploaded map[[16]byte]bool) {
	t.Helper()
	liveDrops := live.DrainDropped()
	if err := live.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(cfg)
	if err != nil {
		t.Fatalf("recovery Open: %v", err)
	}
	defer func() { _ = s.Close() }()
	if drops := s.DrainDropped(); len(drops) != 0 {
		t.Fatalf("recovery accounted %v on a spool that was never killed: a segment was corrupted by the full/hard-stop path", drops)
	}
	ack, _ := s.Cursors()
	recs, _, err := s.Records(ack)
	if err != nil {
		t.Fatalf("Records after recovery: %v", err)
	}
	seen := map[[16]byte]bool{}
	for id := range uploaded {
		seen[id] = true
	}
	for _, r := range recs {
		var id [16]byte
		copy(id[:], r.ID[:16])
		if seen[id] {
			t.Fatalf("record %x recovered twice", id)
		}
		seen[id] = true
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for id, class := range p.appended {
		if !seen[id] {
			t.Fatalf("class-%d record %x: Append returned nil and the record is not on disk after recovery", class, id)
		}
	}
	if len(seen) != len(p.appended) {
		t.Fatalf("%d records on disk, %d promised: recovery invented %d", len(seen), len(p.appended), len(seen)-len(p.appended))
	}
	var shedRows uint64
	for _, d := range liveDrops {
		if d.Reason != DropSpoolShed || d.Class != ClassDiagnostic {
			t.Fatalf("live ledger holds %v; a full spool may only shed diagnostics", d)
		}
		shedRows += d.Quantity
	}
	if shedRows != p.shed {
		t.Fatalf("Dropped{SPOOL_SHED,DIAGNOSTIC} = %d, producers saw %d sheds: the loss ledger is not exact", shedRows, p.shed)
	}
}

// TestChaosSpoolCapUnderLoad is 12 §6.2 spool_billing_blocks_on_full (F-17/F-18)
// with the uplink paused and both classes writing concurrently.
func TestChaosSpoolCapUnderLoad(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{Dir: dir, SegmentSize: 8 << 10, SpoolCap: 48 << 10,
		DiskUsage: func(string) (float64, error) { return 0.10, nil }}
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p := &fullProducers{appended: map[[16]byte]Class{}}
	ctx, stop := context.WithCancel(context.Background())
	p.wg.Add(2)
	go p.run(ctx, s, ClassBilling, 100*time.Microsecond)
	go p.run(ctx, s, ClassDiagnostic, 500*time.Microsecond)

	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, _, shed := p.counts(); shed >= 50 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the spool never filled under load")
		}
		time.Sleep(5 * time.Millisecond)
	}
	billingAtFull, _, _ := p.counts()
	time.Sleep(300 * time.Millisecond)
	if b, _, _ := p.counts(); b != billingAtFull {
		t.Fatalf("billing appends kept returning (%d→%d) on a full spool: a returned billing Append past the cap is a shed in disguise", billingAtFull, b)
	}
	billingParked(t, s, "at the ~cap")
	_, _, shedBefore := p.counts()
	if shedBefore == 0 {
		t.Fatal("no diagnostic shed at the cap")
	}

	// The uplink resumes: ack everything durable, whole segments delete, writers wake.
	if err := s.Sync(); err != nil {
		t.Fatal(err)
	}
	ack, durable := s.Cursors()
	recs, _, err := s.Records(ack)
	if err != nil {
		t.Fatal(err)
	}
	uploaded := map[[16]byte]bool{}
	for _, r := range recs {
		var id [16]byte
		copy(id[:], r.ID[:16])
		uploaded[id] = true
	}
	if err := s.Ack(durable); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for {
		if b, _, _ := p.counts(); b > billingAtFull {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("billing writers still parked after the uplink drained the spool")
		}
		time.Sleep(5 * time.Millisecond)
	}
	stop()
	p.wg.Wait()
	b, d, shed := p.counts()
	t.Logf("chaos_spool_cap: %d billing + %d diagnostic appended, %d diagnostics shed at the cap, writers parked then released by Ack", b, d, shed)
	gradeRecovery(t, cfg, p, s, uploaded)
}

// TestChaosDiskHardStopUnderLoad is 12 §6.2 spool_disk_hardstop (F-19) through
// the statfs seam: usage crosses 95 % mid-load, then space returns.
func TestChaosDiskHardStopUnderLoad(t *testing.T) {
	dir := t.TempDir()
	var usedPct atomic.Uint64
	usedPct.Store(50)
	cfg := Config{Dir: dir, SegmentSize: 8 << 10, SpoolCap: 64 << 20,
		DiskUsage: func(string) (float64, error) { return float64(usedPct.Load()) / 100, nil }}
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var edgesMu sync.Mutex
	var edges []bool
	s.SetHardStopHook(func(entered bool) {
		edgesMu.Lock()
		defer edgesMu.Unlock()
		edges = append(edges, entered)
	})
	p := &fullProducers{appended: map[[16]byte]Class{}}
	ctx, stop := context.WithCancel(context.Background())
	p.wg.Add(2)
	go p.run(ctx, s, ClassBilling, 200*time.Microsecond)
	go p.run(ctx, s, ClassDiagnostic, 500*time.Microsecond)
	time.Sleep(200 * time.Millisecond)
	if b, d, shed := p.counts(); b == 0 || d == 0 || shed != 0 {
		t.Fatalf("before the fault: billing=%d diag=%d shed=%d, want both flowing and nothing shed", b, d, shed)
	}

	usedPct.Store(96)
	deadline := time.Now().Add(5 * time.Second)
	for {
		edgesMu.Lock()
		n := len(edges)
		edgesMu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the hard-stop hook never fired entered=true after usage crossed 95 %")
		}
		time.Sleep(5 * time.Millisecond)
	}
	billingAtStop, _, shedAtStop := p.counts()
	time.Sleep(300 * time.Millisecond)
	if b, _, shed := p.counts(); b != billingAtStop || shed <= shedAtStop {
		t.Fatalf("under the hard stop billing went %d→%d and sheds %d→%d: billing must park and diagnostics must shed", billingAtStop, b, shedAtStop, shed)
	}
	billingParked(t, s, "under the hard stop")

	usedPct.Store(50)
	deadline = time.Now().Add(5 * time.Second)
	for {
		edgesMu.Lock()
		n := len(edges)
		edgesMu.Unlock()
		b, _, _ := p.counts()
		if n == 2 && b > billingAtStop {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("capture did not resume once space returned (edges=%d, billing %d→%d)", n, billingAtStop, b)
		}
		time.Sleep(5 * time.Millisecond)
	}
	stop()
	p.wg.Wait()
	edgesMu.Lock()
	got := append([]bool(nil), edges...)
	edgesMu.Unlock()
	if len(got) != 2 || !got[0] || got[1] {
		t.Fatalf("hard-stop edges = %v, want exactly [true false]", got)
	}
	b, d, shed := p.counts()
	t.Logf("chaos_disk_hardstop: %d billing + %d diagnostic appended, %d shed under the stop, edges %v", b, d, shed, got)
	gradeRecovery(t, cfg, p, s, nil)
}
