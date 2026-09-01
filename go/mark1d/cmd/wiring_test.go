//go:build unix

// The two seams that are each proven on both sides and nowhere in the middle:
// the edge loss ledgers → Batch.dropped (FR-SPINE-007) and obs.Health → its
// consumers (NFR-OPERABILITY-002). Both are one line of cmd/main.go, both were
// deletable with the whole suite green, and neither is observable from below —
// internal/uplink's batch tests ride a stub DropSource and internal/obs's tests
// construct their own Health, so each proves its half against a wiring it
// supplies itself. Both tests here drive the assembled daemon and read the
// WIRE: the bytes controld would have received.
package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"
	"google.golang.org/protobuf/proto"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/spool"
	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

// wireTap is controld's ingest leg reduced to what the uplink demands of it: a
// JSON ack echoing M1P-Batch-Id, which is the only thing that licenses the
// spool cursor to advance (08 §2.2). Every decoded Batch is retained, so the
// assertions below read what left the machine rather than what a counter says.
type wireTap struct {
	t   *testing.T
	url string
	dec *zstd.Decoder

	mu      sync.Mutex
	batches []*m1pv1.Batch
}

func newWireTap(t *testing.T) *wireTap {
	t.Helper()
	dec, err := zstd.NewReader(nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dec.Close)
	w := &wireTap{t: t, dec: dec}
	srv := httptest.NewServer(http.HandlerFunc(w.serve))
	t.Cleanup(srv.Close)
	w.url = srv.URL + "/m1p/v1/ingest"
	return w
}

func (w *wireTap) serve(rw http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err == nil {
		var raw []byte
		if raw, err = w.dec.DecodeAll(body, nil); err == nil {
			b := &m1pv1.Batch{}
			if err = proto.Unmarshal(raw, b); err == nil {
				w.mu.Lock()
				w.batches = append(w.batches, b)
				w.mu.Unlock()
			}
		}
	}
	if err != nil {
		// Errorf, not Fatalf: this runs on the server's goroutine.
		w.t.Errorf("ingest could not decode the batch body: %v", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
	rw.Header().Set("Content-Type", "application/json")
	_, _ = rw.Write([]byte(`{"batch_id":"` + r.Header.Get("M1P-Batch-Id") + `"}`))
}

// dropped totals one (reason, class) row across every batch received. The
// ledgers are read-and-reset at composition, so a row rides whichever batch
// composes next and the union across batches is the only honest read.
func (w *wireTap) dropped(reason m1pv1.DropReason, class m1pv1.DurabilityClass) uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	var q uint64
	for _, b := range w.batches {
		for _, d := range b.GetDropped() {
			if d.GetReason() == reason && d.GetDurabilityClass() == class {
				q += d.GetQuantity()
			}
		}
	}
	return q
}

// usage counts Usage-bodied events on the wire. Counting ALL events would race
// the daemon's own EdgeHealth, which a successful cycle admits behind our back.
func (w *wireTap) usage() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := 0
	for _, b := range w.batches {
		for _, ev := range b.GetEvents() {
			if ev.GetUsage() != nil {
				n++
			}
		}
	}
	return n
}

func (w *wireTap) health() *m1pv1.EdgeHealth {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, b := range w.batches {
		for _, ev := range b.GetEvents() {
			if eh := ev.GetEdgeHealth(); eh != nil {
				return eh
			}
		}
	}
	return nil
}

// waitUpTo is waitFor with the deadline exposed. A full round trip here is the
// spool's 250 ms fsync cadence plus the uploader's 1 s poll, and the EdgeHealth
// a successful cycle admits needs a SECOND poll to ride a batch — past
// waitFor's 5 s on a loaded runner, and none of this is a latency test.
func waitUpTo(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// uplinkPaths lays out one daemon's directories and points HOME at a scratch
// dir so the tailer never reads the developer's real ~/.claude.
func uplinkPaths(t *testing.T) (stateDir, spoolDir, socket string) {
	t.Helper()
	dir := t.TempDir()
	stateDir = filepath.Join(dir, "state")
	spoolDir = filepath.Join(dir, "spool")
	// A fresh subdir so fabric.Listen creates it 0700 itself (main_test.go).
	socket = filepath.Join(dir, "sock", "m1p.sock")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", filepath.Join(dir, "home"))
	return stateDir, spoolDir, socket
}

// seedTornSpool leaves the spool dir holding one durable billing record
// followed by bytes that decode as no record — the crash tail recovery step 3
// discards and step 4 ACCOUNTS. The daemon's own spool.Open raises the row; the
// test never touches a loss ledger.
func seedTornSpool(t *testing.T, spoolDir string) {
	t.Helper()
	sp, err := spool.Open(spool.Config{Dir: spoolDir})
	if err != nil {
		t.Fatal(err)
	}
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	session := uuid.MustParse("3f9c2e71-58d4-4b6a-9e2f-7a1c0d8b4e55")
	payload, err := proto.Marshal(&m1pv1.Event{
		EventId: id[:], SessionId: session[:], Seq: 1, SessionEpoch: 1,
		Body: &m1pv1.Event_Usage{Usage: &m1pv1.Usage{IdemKey: make([]byte, 32)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sp.Append(context.Background(), [16]byte(id), spool.ClassBilling, payload); err != nil {
		t.Fatal(err)
	}
	if err := sp.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := sp.Close(); err != nil {
		t.Fatal(err)
	}

	segs, err := filepath.Glob(filepath.Join(spoolDir, "seg-*.m1s"))
	if err != nil || len(segs) != 1 {
		t.Fatalf("spool holds %v segments after one append, want exactly one (%v)", segs, err)
	}
	// 0xff… is unambiguously torn: the leading four bytes read as a record
	// length of 4294967295, past the format's bound, so no CRC accident can make
	// these decode. Offset 24 is record_id[16], the class byte, which sits ahead
	// of the payload precisely so a torn tail can still be accounted by class —
	// so this tear is readable as the billing-grade loss it claims to be.
	torn := bytes.Repeat([]byte{0xff}, 32)
	torn[24] = byte(spool.ClassBilling)
	f, err := os.OpenFile(segs[0], os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(torn); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestEdgeLossLedgersBothReachTheWire is FR-SPINE-007's spool→batch seam. It is
// one test rather than two because the defect it guards is one line —
// `Drops: []uplink.DropSource{sp, adm}`. Delete either element and the daemon
// keeps uploading, keeps capturing, logs nothing, and silently stops reporting
// that class of its own losses. Both halves are asserted here, so dropping
// either element is a red rather than a narrower green.
//
// Nothing below calls a loss ledger. The spool row is raised by the daemon's own
// recovery over a tail this test tore on disk; the capture row is raised by the
// daemon's own admission chokepoint refusing an event that crossed the real
// socket. Both are then read back off the wire.
func TestEdgeLossLedgersBothReachTheWire(t *testing.T) {
	tap := newWireTap(t)
	stateDir, spoolDir, socket := uplinkPaths(t)
	seedTornSpool(t, spoolDir)

	stop := runDaemon(t, config{
		stateDir:    stateDir,
		spoolDir:    spoolDir,
		socket:      socket,
		ingestURL:   tap.url,
		deviceToken: "tok-test",
		offPoll:     10 * time.Millisecond,
	})
	defer stop()
	waitFor(t, "fabric socket", func() bool {
		_, err := os.Stat(socket)
		return err == nil
	})

	// Half one — *spool.Spool as a DropSource. The surviving record is what
	// composes a batch at all; the tear rides it as a Dropped row.
	waitUpTo(t, 20*time.Second, "the recovered CRC loss to reach the wire", func() bool {
		return tap.dropped(m1pv1.DropReason_DROP_REASON_CRC_LOSS,
			m1pv1.DurabilityClass_DURABILITY_CLASS_BILLING_GRADE) == 1
	})
	// Anti-vacuity: that row rode a real upload of the record recovery kept, not
	// an empty envelope of accounting.
	if n := tap.usage(); n != 1 {
		t.Fatalf("the wire carried %d Usage events, want the one record recovery kept", n)
	}

	// Half two — *capture.Admitter as a DropSource. An event with a body and no
	// session_id is refused at admission (04 §2.0) and never reaches disk, so a
	// Dropped row is the ONLY trace it can leave anywhere.
	session := uuid.New()
	c := dialFabric(t, socket, session)
	c.send(&m1pv1.FabricFrame{Kind: &m1pv1.FabricFrame_Event{Event: &m1pv1.Event{
		Body: &m1pv1.Event_Turn{Turn: &m1pv1.Turn{Initiator: m1pv1.Initiator_INITIATOR_HUMAN}},
	}}})
	// A live record so a batch composes: dropped rows ride a batch, and compose
	// returns nothing for a drained spool — there is no rows-only batch.
	c.prompt(session)

	waitUpTo(t, 20*time.Second, "the refused event's local quarantine to reach the wire", func() bool {
		return tap.dropped(m1pv1.DropReason_DROP_REASON_LOCAL_QUARANTINE,
			m1pv1.DurabilityClass_DURABILITY_CLASS_DIAGNOSTIC) == 1
	})
}

// flush is the 07 §6 barrier frame. FlushAck.drained and obs.Health.Delivered()
// are incremented on adjacent lines of one switch arm in fabric/session.go, so
// an acked Flush is proof the delivery was already counted — which is what makes
// the health assertions below ordered rather than lucky.
func (f *fabricConn) flush() *m1pv1.FlushAck {
	f.t.Helper()
	f.send(&m1pv1.FabricFrame{Kind: &m1pv1.FabricFrame_Flush{Flush: &m1pv1.Flush{}}})
	ack := f.recv().GetFlushAck()
	if ack == nil {
		f.t.Fatal("reply frame is not a FlushAck")
	}
	return ack
}

// TestDaemonWiresItsHealthTable is NFR-OPERABILITY-002's wiring clause.
//
// internal/obs shipped complete and INERT: every consumer takes a nilable
// *obs.Health, cmd/main.go constructed none, and the daemon's whole
// self-monitoring surface was absent while obs's own tests stayed green —
// because they build a Health and never ask whether the daemon does (D-CP).
// TestNilHealthIsInert pins the very shape that hid it, and is right to: nil
// must stay inert, since a missing gauge may never become a missing gate
// answer. This is the other half, and only this half can fail when the wiring
// goes.
//
// The observable is an EdgeHealth that CROSSED THE WIRE carrying gauges only
// the daemon's own consumers can set, so it fails independently on the
// construction, on the emitter, and on either instrumented consumer.
func TestDaemonWiresItsHealthTable(t *testing.T) {
	tap := newWireTap(t)
	stateDir, spoolDir, socket := uplinkPaths(t)

	stop := runDaemon(t, config{
		stateDir:    stateDir,
		spoolDir:    spoolDir,
		socket:      socket,
		ingestURL:   tap.url,
		deviceToken: "tok-test",
		offPoll:     10 * time.Millisecond,
	})
	defer stop()
	waitFor(t, "fabric socket", func() bool {
		_, err := os.Stat(socket)
		return err == nil
	})

	session := uuid.New()
	c := dialFabric(t, socket, session)
	c.gate()          // fabric.Gate.Health: one GateQuery answered
	c.prompt(session) // fabric.Server.Health: one Event delivered — and the record a batch needs
	if n := c.flush().GetDrained(); n != 1 {
		t.Fatalf("FlushAck drained = %d, want the one delivered event", n)
	}

	var eh *m1pv1.EdgeHealth
	waitUpTo(t, 30*time.Second, "an EdgeHealth event to reach the wire", func() bool {
		eh = tap.health()
		return eh != nil
	})

	if eh.GetEdgeVersion() != version {
		t.Errorf("edge_version = %q, want %q — obs.Config.EdgeVersion is not the daemon's", eh.GetEdgeVersion(), version)
	}
	if eh.GetShim().GetDelivered() == 0 {
		t.Error("shim.delivered = 0 after an acked Flush — fabric.Server.Health is unwired, so every delivery counts nowhere")
	}
	if eh.GetGate().GetReads() == 0 {
		t.Error("gate.reads = 0 after a GateQuery was answered — fabric.Gate.Health is unwired, and SLO-7 is judged on a digest nothing feeds")
	}
	if eh.GetSpool().GetSegments() == 0 {
		t.Error("spool.segments = 0 with a live spool — obs.Config.SpoolDir is unwired, so the occupancy gauges read as an empty device")
	}
}
