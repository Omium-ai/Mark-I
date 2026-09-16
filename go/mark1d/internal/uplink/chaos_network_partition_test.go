//go:build chaos

package uplink

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/spool"
)

// partitionIngest is a controld that can be black-holed: a swallowed request is
// read and never answered, so "received" and "landed" are different sets.
type partitionIngest struct {
	mu     sync.Mutex
	hole   bool
	holed  int
	landed [][]byte
}

func (p *partitionIngest) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return
		}
		p.mu.Lock()
		if p.hole {
			p.holed++
			p.mu.Unlock()
			<-r.Context().Done()
			return
		}
		p.landed = append(p.landed, body)
		p.mu.Unlock()
		writeAck(w, http.StatusOK, r.Header.Get("M1P-Batch-Id"), nil)
	}
}

func (p *partitionIngest) setHole(on bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.hole = on
}

func (p *partitionIngest) snapshot() (holed int, landed [][]byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.holed, append([][]byte(nil), p.landed...)
}

type ackCounter struct {
	*spool.Spool
	acks atomic.Int64
}

func (a *ackCounter) Ack(c spool.Cursor) error {
	a.acks.Add(1)
	return a.Spool.Ack(c)
}

// chaosEvent is makeEvent without *testing.T, for producer goroutines.
func chaosEvent(session uuid.UUID, seq uint64, class spool.Class) ([16]byte, []byte) {
	id := uuid.Must(uuid.NewV7())
	ev := &m1pv1.Event{EventId: id[:], Seq: seq, SessionId: session[:], SessionEpoch: 1}
	if class == spool.ClassBilling {
		ev.Body = &m1pv1.Event_Usage{Usage: &m1pv1.Usage{IdemKey: make([]byte, 32)}}
	} else {
		ev.Body = &m1pv1.Event_SessionStart{SessionStart: &m1pv1.SessionStart{Agent: "claudecode"}}
	}
	payload, err := proto.Marshal(ev)
	if err != nil {
		panic(err)
	}
	return [16]byte(id), payload
}

type producerLedger struct {
	mu       sync.Mutex
	appended map[[16]byte]spool.Class
	shed     uint64
}

func (l *producerLedger) run(ctx context.Context, sp *spool.Spool, class spool.Class, pace time.Duration) {
	session := uuid.Must(uuid.NewV7())
	for seq := uint64(1); ctx.Err() == nil; seq++ {
		id, payload := chaosEvent(session, seq, class)
		err := sp.Append(ctx, id, class, payload)
		l.mu.Lock()
		switch {
		case err == nil:
			l.appended[id] = class
		case errors.Is(err, spool.ErrDiagnosticShed):
			l.shed++
		}
		l.mu.Unlock()
		time.Sleep(pace)
	}
}

func TestChaosNetworkPartitionUplink(t *testing.T) {
	sp, err := spool.Open(spool.Config{
		Dir: t.TempDir(), SegmentSize: 8 << 10, SpoolCap: 64 << 10,
		DiskUsage: func(string) (float64, error) { return 0.10, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sp.Close() })
	store := &ackCounter{Spool: sp}

	ingest := &partitionIngest{}
	srv := httptest.NewServer(ingest.handler())
	t.Cleanup(srv.Close)
	dl := &delayLog{blockPark: true}
	netChange := make(chan struct{})
	u, err := New(Config{
		Store:         store,
		Drops:         []DropSource{sp},
		Tokens:        StaticToken("tok-chaos"),
		Endpoint:      srv.URL + "/m1p/v1/ingest",
		EdgeVersion:   "1.4.2",
		SDK:           &m1pv1.SdkInfo{Name: "mark1d", Version: "1.4.2", Os: "linux", Arch: "amd64", Agent: "claudecode"},
		QuarantineDir: filepath.Join(t.TempDir(), "quarantine"),
		Seal:          func(p []byte) ([]byte, error) { return p, nil },
		HTTPClient:    &http.Client{Timeout: 300 * time.Millisecond},
		After:         dl.After,
		Rand:          func() float64 { return 0.5 },
		NetworkChange: netChange,
		Poll:          5 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	runCtx, cancelRun := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- u.Run(runCtx) }()

	ledger := &producerLedger{appended: map[[16]byte]spool.Class{}}
	prodCtx, stopProducers := context.WithCancel(context.Background())
	var producers sync.WaitGroup
	producers.Add(2)
	go func() { defer producers.Done(); ledger.run(prodCtx, sp, spool.ClassBilling, 200*time.Microsecond) }()
	go func() { defer producers.Done(); ledger.run(prodCtx, sp, spool.ClassDiagnostic, time.Millisecond) }()

	waitFor(t, "two acked batches before the partition (positive control)", func() bool {
		_, landed := ingest.snapshot()
		return len(landed) >= 2
	})

	ingest.setHole(true)
	holeStart := time.Now()
	_, landedAtHole := ingest.snapshot()
	delaysBefore := len(dl.list())

	waitFor(t, "the automaton to reach PARKED behind the black hole", func() bool { return dl.parkEntries() == 1 })
	holed, landedAtPark := ingest.snapshot()
	if holed != maxAttempts {
		t.Fatalf("black hole swallowed %d requests before PARKED, want exactly %d (08 §2.5's budget)", holed, maxAttempts)
	}
	if len(landedAtPark) != len(landedAtHole) {
		t.Fatalf("ingest landed %d→%d batches inside the black hole", len(landedAtHole), len(landedAtPark))
	}
	if got := store.acks.Load(); got != int64(len(landedAtPark)) {
		t.Fatalf("%d spool acks at PARKED for %d landed batches: an ack without a landed object", got, len(landedAtPark))
	}
	var ladder []time.Duration
	for _, d := range dl.list()[delaysBefore:] {
		if d != parkRequeue && d != u.poll {
			ladder = append(ladder, d)
		}
	}
	if len(ladder) != maxAttempts-1 {
		t.Fatalf("observed %d backoff sleeps before PARKED, want %d: %v", len(ladder), maxAttempts-1, ladder)
	}
	for i, d := range ladder {
		if want := wantDelay(i+1) / 2; d != want {
			t.Fatalf("backoff sleep %d = %v, want %v (min(30m, 6s·2^%d)·U with U=0.5)", i+1, d, want, i)
		}
	}
	ledger.mu.Lock()
	shedAtPark := ledger.shed
	ledger.mu.Unlock()
	if shedAtPark == 0 {
		t.Fatal("no diagnostic was shed during the partition: the spool never filled, so block-on-full is unobserved")
	}
	t.Logf("chaos: parked after %d swallowed attempts in %v; ladder %v; %d diagnostics shed so far",
		holed, time.Since(holeStart), ladder, shedAtPark)

	ingest.setHole(false)
	netChange <- struct{}{}
	waitFor(t, "the first post-heal landing", func() bool {
		_, landed := ingest.snapshot()
		return len(landed) > len(landedAtPark)
	})
	stopProducers()
	producers.Wait()
	// One trailing billing record so the sheds after the last compose ride a batch (04 §2.4: rows drain at composition).
	tailID, tailPayload := chaosEvent(uuid.Must(uuid.NewV7()), 1, spool.ClassBilling)
	if err := sp.Append(context.Background(), tailID, spool.ClassBilling, tailPayload); err != nil {
		t.Fatal(err)
	}
	ledger.appended[tailID] = spool.ClassBilling
	if err := sp.Sync(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the spool to drain after the heal", func() bool {
		ack, write := sp.Cursors()
		return ack == write
	})
	cancelRun()
	if err := <-runDone; err != nil {
		t.Fatalf("Run = %v", err)
	}
	if left := sp.DrainDropped(); len(left) != 0 {
		t.Fatalf("loss ledger still holds %v after a full drain", left)
	}

	_, landed := ingest.snapshot()
	if got := store.acks.Load(); got != int64(len(landed)) {
		t.Fatalf("%d spool acks for %d landed batches: every ack must be licensed by one landing (08 §2.2)", got, len(landed))
	}
	seen := map[[16]byte]int{}
	var shedOnWire uint64
	for _, body := range landed {
		b, _ := decodeBody(t, body)
		for _, ev := range b.GetEvents() {
			seen[[16]byte(ev.GetEventId())]++
		}
		for _, d := range b.GetDropped() {
			if d.GetReason() != m1pv1.DropReason_DROP_REASON_SPOOL_SHED ||
				d.GetDurabilityClass() != m1pv1.DurabilityClass_DURABILITY_CLASS_DIAGNOSTIC {
				t.Fatalf("Dropped%v on the wire: the only loss a partition may cost is a shed diagnostic", d)
			}
			shedOnWire += d.GetQuantity()
		}
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	var billing, diag int
	for id, class := range ledger.appended {
		switch n := seen[id]; {
		case n == 0 && class == spool.ClassBilling:
			t.Fatalf("billing event %x appended and never landed: billing-grade loss across the partition", id)
		case n == 0:
			t.Fatalf("diagnostic %x was appended (not shed) and never landed", id)
		case n > 1:
			t.Fatalf("event %x landed %d times: a swallowed batch was acked, or a landed one re-sent", id, n)
		}
		if class == spool.ClassBilling {
			billing++
		} else {
			diag++
		}
	}
	if len(seen) != len(ledger.appended) {
		t.Fatalf("%d distinct events on the wire, %d appended: ingest received something the producers never wrote", len(seen), len(ledger.appended))
	}
	if shedOnWire != ledger.shed {
		t.Fatalf("Dropped{SPOOL_SHED,DIAGNOSTIC} on the wire = %d, producers saw %d sheds: the loss ledger is not exact", shedOnWire, ledger.shed)
	}
	t.Logf("chaos_network_partition: %d billing + %d diagnostic events exactly once across %d landed batches, %d requests swallowed, %d sheds accounted exactly",
		billing, diag, len(landed), holed, ledger.shed)
}
