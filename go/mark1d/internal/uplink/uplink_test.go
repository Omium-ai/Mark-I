// Tests drive the 08 §2.5 automaton against a fake ingest speaking controld's
// exact grammar (headers, JSON bodies, status table) over a real on-disk
// spool, with the clock, jitter and network-change signal injected.
package uplink

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/spool"
)

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

type testEvent struct {
	id      uuid.UUID
	payload []byte
	class   spool.Class
}

// makeEvent builds one encoded m1p.v1.Event exactly as capture spools it:
// billing = Usage, diagnostic = SessionStart (the closed class set, 07 §6).
func makeEvent(t *testing.T, session uuid.UUID, seq uint64, class spool.Class) testEvent {
	t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	ev := &m1pv1.Event{EventId: id[:], Seq: seq, SessionId: session[:], SessionEpoch: 1}
	if class == spool.ClassBilling {
		ev.Body = &m1pv1.Event_Usage{Usage: &m1pv1.Usage{IdemKey: make([]byte, 32)}}
	} else {
		ev.Body = &m1pv1.Event_SessionStart{SessionStart: &m1pv1.SessionStart{Agent: "claudecode"}}
	}
	payload, err := proto.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	return testEvent{id: id, payload: payload, class: class}
}

func openSpool(t *testing.T) *spool.Spool {
	t.Helper()
	sp, err := spool.Open(spool.Config{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sp.Close() })
	return sp
}

func appendAll(t *testing.T, sp *spool.Spool, evs ...testEvent) {
	t.Helper()
	for _, e := range evs {
		if err := sp.Append(context.Background(), [16]byte(e.id), e.class, e.payload); err != nil {
			t.Fatal(err)
		}
	}
	// Records are readable only below the durable cursor.
	if err := sp.Sync(); err != nil {
		t.Fatal(err)
	}
}

// fakeIngest records every request and answers via the per-test script,
// keyed by 1-based request index.
type fakeIngest struct {
	mu      sync.Mutex
	seen    []recordedReq
	respond func(n int, w http.ResponseWriter, bid string)
}

type recordedReq struct {
	header http.Header
	body   []byte
}

func (f *fakeIngest) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.seen = append(f.seen, recordedReq{header: r.Header.Clone(), body: body})
		n := len(f.seen)
		f.mu.Unlock()
		f.respond(n, w, r.Header.Get("M1P-Batch-Id"))
	}
}

func (f *fakeIngest) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.seen)
}

func (f *fakeIngest) req(i int) recordedReq {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.seen[i]
}

// writeAck mimics controld's ackBody — batch_id echoed from the request, the
// provenance the edge now demands before deleting spool (08 §2.2/§2.6);
// writeErr its 08 §9 error shape.
func writeAck(w http.ResponseWriter, status int, batchID string, quarantined []string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"batch_id": batchID, "accepted": 1, "quarantined": quarantined,
		"server_time": "2026-08-28T14:03:11.402Z",
	})
}

func writeErr(w http.ResponseWriter, status int, code string, detail any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	e := map[string]any{"code": code, "message": code}
	if detail != nil {
		e["detail"] = detail
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"error": e})
}

// delayLog is the injected clock: it records requested waits and fires them
// immediately, except the park re-queue timer when blockPark is set (so the
// network-change trigger is observable).
type delayLog struct {
	mu        sync.Mutex
	ds        []time.Duration
	blockPark bool
}

func (d *delayLog) After(dur time.Duration) <-chan time.Time {
	d.mu.Lock()
	d.ds = append(d.ds, dur)
	block := d.blockPark && dur == parkRequeue
	d.mu.Unlock()
	if block {
		return nil // a nil channel never fires
	}
	ch := make(chan time.Time, 1)
	ch <- time.Time{}
	return ch
}

func (d *delayLog) list() []time.Duration {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]time.Duration(nil), d.ds...)
}

// parkEntries counts observed entries into PARKED. park (uplink.go:449) is the
// only caller that ever asks for parkRequeue, so this is a POSITIVE sighting of
// the automaton in PARKED rather than an inference from "the cycle returned
// without an error" — which a cycle that never ran would also satisfy.
func (d *delayLog) parkEntries() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for _, dur := range d.ds {
		if dur == parkRequeue {
			n++
		}
	}
	return n
}

// stubDrops replays a fixed row set exactly once — DrainDropped's
// read-and-reset contract.
type stubDrops struct {
	mu   sync.Mutex
	rows []spool.Dropped
}

func (s *stubDrops) DrainDropped() []spool.Dropped {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.rows
	s.rows = nil
	return out
}

func newTestUplink(t *testing.T, store Store, ingest *fakeIngest, mod func(*Config)) (*Uplink, *delayLog, string) {
	t.Helper()
	srv := httptest.NewServer(ingest.handler())
	t.Cleanup(srv.Close)
	qdir := filepath.Join(t.TempDir(), "quarantine")
	dl := &delayLog{}
	cfg := Config{
		Store:       store,
		Tokens:      StaticToken("tok-abc"),
		Endpoint:    srv.URL + "/m1p/v1/ingest",
		EdgeVersion: "1.4.2",
		SDK:         &m1pv1.SdkInfo{Name: "mark1d", Version: "1.4.2", Os: "linux", Arch: "amd64", Agent: "claudecode"},

		QuarantineDir: qdir,
		Seal:          func(p []byte) ([]byte, error) { return p, nil }, // identity seal: tests inspect quarantined bytes
		Now:           func() time.Time { return time.Unix(1756400000, 0) },
		After:         dl.After,
		Rand:          func() float64 { return 1.0 },
		Poll:          time.Millisecond,
	}
	if mod != nil {
		mod(&cfg)
	}
	u, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return u, dl, qdir
}

// decodeBody unzstds one request body and splits it into the decoded Batch
// plus the raw field-5 event frames — the byte-level shape check: frames must
// be the spool payloads verbatim (opaque-payload rule).
func decodeBody(t *testing.T, body []byte) (*m1pv1.Batch, [][]byte) {
	t.Helper()
	dec, err := zstd.NewReader(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer dec.Close()
	raw, err := dec.DecodeAll(body, nil)
	if err != nil {
		t.Fatalf("body is not zstd: %v", err)
	}
	var batch m1pv1.Batch
	if err := proto.Unmarshal(raw, &batch); err != nil {
		t.Fatalf("body is not a m1p.v1.Batch: %v", err)
	}
	var frames [][]byte
	b := raw
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			t.Fatal("torn tag in batch bytes")
		}
		b = b[n:]
		if num == batchEventsField && typ == protowire.BytesType {
			v, m := protowire.ConsumeBytes(b)
			if m < 0 {
				t.Fatal("torn event frame")
			}
			frames = append(frames, v)
			b = b[m:]
			continue
		}
		if n = protowire.ConsumeFieldValue(num, typ, b); n < 0 {
			t.Fatal("torn field")
		}
		b = b[n:]
	}
	return &batch, frames
}

func sendOnce(t *testing.T, u *Uplink) cycleResult {
	t.Helper()
	b, err := u.compose()
	if err != nil {
		t.Fatal(err)
	}
	if b == nil {
		t.Fatal("compose returned nil, want a batch")
	}
	res, err := u.send(context.Background(), b, 0)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func assertDrained(t *testing.T, sp *spool.Spool) {
	t.Helper()
	ack, write := sp.Cursors()
	if ack != write {
		t.Fatalf("ack %v != durable write %v: cursor not advanced", ack, write)
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// ---------------------------------------------------------------------------
// 08 §2.1: the request, byte level
// ---------------------------------------------------------------------------

func TestIngestRequestShape(t *testing.T) {
	sp := openSpool(t)
	session, _ := uuid.NewV7()
	e1 := makeEvent(t, session, 1, spool.ClassBilling)
	e2 := makeEvent(t, session, 2, spool.ClassDiagnostic)
	appendAll(t, sp, e1, e2)

	drops := &stubDrops{rows: []spool.Dropped{{Reason: spool.DropSpoolShed, Class: spool.ClassDiagnostic, Quantity: 17}}}
	ingest := &fakeIngest{respond: func(int, http.ResponseWriter, string) {}}
	u, _, _ := newTestUplink(t, sp, ingest, func(c *Config) { c.Drops = []DropSource{drops} })
	ingest.respond = func(_ int, w http.ResponseWriter, bid string) { writeAck(w, http.StatusOK, bid, nil) }

	if res := sendOnce(t, u); res != cycleAdvanced {
		t.Fatalf("result = %v, want advanced", res)
	}
	if ingest.count() != 1 {
		t.Fatalf("requests = %d, want 1", ingest.count())
	}
	req := ingest.req(0)

	// Headers, 08 §2.1 verbatim.
	for k, want := range map[string]string{
		"Authorization":        "Bearer tok-abc",
		"Content-Type":         "application/x-m1p-protobuf",
		"Content-Encoding":     "zstd",
		"M1P-Schema":           "m1p.v1",
		"X-Mark1-Edge-Version": "1.4.2",
	} {
		if got := req.header.Get(k); got != want {
			t.Errorf("header %s = %q, want %q", k, got, want)
		}
	}
	headerBID, err := uuid.Parse(req.header.Get("M1P-Batch-Id"))
	if err != nil || headerBID.Version() != 7 {
		t.Fatalf("M1P-Batch-Id %q is not a uuidv7 (err=%v)", req.header.Get("M1P-Batch-Id"), err)
	}

	batch, frames := decodeBody(t, req.body)
	if !bytes.Equal(batch.GetBatchId(), headerBID[:]) {
		t.Error("Batch.batch_id != M1P-Batch-Id header (08 §2.1)")
	}
	if !bytes.Equal(batch.GetSessionId(), session[:]) {
		t.Error("Batch.session_id not stamped from the events' session")
	}
	if sdk := batch.GetSdk(); sdk.GetName() != "mark1d" || sdk.GetVersion() != "1.4.2" || sdk.GetAgent() != "claudecode" {
		t.Errorf("sdk = %v", sdk)
	}
	if batch.GetSentAt() == nil {
		t.Error("sent_at missing")
	}
	if len(batch.GetAdvisoryTenantId()) != 0 || len(batch.GetAdvisoryDeviceId()) != 0 {
		t.Error("identity asserted in envelope — M1E-8003 material (08 §2.1)")
	}
	// Payloads ride verbatim, in spool order (billing first here).
	if len(frames) != 2 || !bytes.Equal(frames[0], e1.payload) || !bytes.Equal(frames[1], e2.payload) {
		t.Fatal("event frames are not the spool payloads verbatim, in order")
	}
	if len(batch.GetDropped()) != 1 ||
		batch.GetDropped()[0].GetReason() != m1pv1.DropReason_DROP_REASON_SPOOL_SHED ||
		batch.GetDropped()[0].GetDurabilityClass() != m1pv1.DurabilityClass_DURABILITY_CLASS_DIAGNOSTIC ||
		batch.GetDropped()[0].GetQuantity() != 17 {
		t.Fatalf("dropped = %v, want the drained shed row", batch.GetDropped())
	}

	assertDrained(t, sp)
	if b, err := u.compose(); err != nil || b != nil {
		t.Fatalf("compose after ack = (%v, %v), want (nil, nil): batch must ack exactly once", b, err)
	}
}

// ---------------------------------------------------------------------------
// 08 §2.5: backoff, Retry-After, park, re-queue
// ---------------------------------------------------------------------------

func TestBackoffOn5xxThenSuccess(t *testing.T) {
	sp := openSpool(t)
	session, _ := uuid.NewV7()
	appendAll(t, sp, makeEvent(t, session, 1, spool.ClassBilling))

	ingest := &fakeIngest{respond: func(n int, w http.ResponseWriter, bid string) {
		if n <= 2 {
			writeErr(w, http.StatusServiceUnavailable, "M1E-9500", nil)
			return
		}
		writeAck(w, http.StatusOK, bid, nil)
	}}
	u, dl, _ := newTestUplink(t, sp, ingest, nil) // Rand = 1.0: delay = min(cap, 6s·2^(n−1)) exactly

	if res := sendOnce(t, u); res != cycleAdvanced {
		t.Fatalf("result = %v, want advanced", res)
	}
	if got, want := dl.list(), []time.Duration{6 * time.Second, 12 * time.Second}; len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("backoff delays = %v, want %v (base 6s, ×2 per attempt)", got, want)
	}
	// 08 §2.3: every re-POST is the SAME batch_id over byte-identical content.
	first := ingest.req(0)
	for i := 1; i < 3; i++ {
		r := ingest.req(i)
		if r.header.Get("M1P-Batch-Id") != first.header.Get("M1P-Batch-Id") || !bytes.Equal(r.body, first.body) {
			t.Fatal("retry mutated batch_id or bytes — would land Divergent (409) after a lost ack")
		}
	}
	assertDrained(t, sp)
}

func TestRetryAfterIsAFloor(t *testing.T) {
	sp := openSpool(t)
	session, _ := uuid.NewV7()
	appendAll(t, sp, makeEvent(t, session, 1, spool.ClassDiagnostic))

	ingest := &fakeIngest{respond: func(n int, w http.ResponseWriter, bid string) {
		if n == 1 {
			w.Header().Set("Retry-After", "7")
			w.Header().Set("M1P-Rate-Limits", "usage:10000:60;diagnostic:2000:60")
			writeErr(w, http.StatusTooManyRequests, "M1E-9001", nil)
			return
		}
		writeAck(w, http.StatusOK, bid, nil)
	}}
	u, dl, _ := newTestUplink(t, sp, ingest, func(c *Config) {
		c.Rand = func() float64 { return 0.0001 } // jitter would undercut the floor
	})
	if res := sendOnce(t, u); res != cycleAdvanced {
		t.Fatal("want advanced")
	}
	if ds := dl.list(); len(ds) != 1 || ds[0] != 7*time.Second {
		t.Fatalf("delay = %v, want [7s]: Retry-After is the floor (08 §2.5)", ds)
	}
}

func TestParkAfterBudgetThenRequeueSucceeds(t *testing.T) {
	sp := openSpool(t)
	session, _ := uuid.NewV7()
	appendAll(t, sp, makeEvent(t, session, 1, spool.ClassBilling))

	ingest := &fakeIngest{respond: func(n int, w http.ResponseWriter, bid string) {
		if n <= maxAttempts {
			writeErr(w, http.StatusServiceUnavailable, "M1E-9500", nil)
			return
		}
		writeAck(w, http.StatusOK, bid, nil)
	}}
	u, dl, _ := newTestUplink(t, sp, ingest, func(c *Config) {
		c.Rand = func() float64 { return 0.0001 }
	})
	if res := sendOnce(t, u); res != cycleParked {
		t.Fatalf("result = %v, want parked after the %dth failure", res, maxAttempts)
	}
	if ingest.count() != maxAttempts {
		t.Fatalf("attempts = %d, want exactly %d", ingest.count(), maxAttempts)
	}
	if len(dl.list()) != maxAttempts-1 {
		t.Fatalf("backoff sleeps = %d, want %d (no sleep after the final failure)", len(dl.list()), maxAttempts-1)
	}
	ack, _ := sp.Cursors()
	if ack != (spool.Cursor{Seq: 0, Off: 64}) && ack.Off != 64 {
		t.Fatalf("parked batch must stay in the spool; ack moved to %v", ack)
	}
	// Re-queue (restart / timer / network-change all recompose): now succeeds.
	if res := sendOnce(t, u); res != cycleAdvanced {
		t.Fatal("re-queued batch should land")
	}
	assertDrained(t, sp)
}

// wantDelay is 08 §2.5's ladder written from the DOC — min(30 min, 6 s·2^(n−1))
// — with literals rather than backoffBase/backoffCap, so a constant edited in
// uplink.go fails here instead of quietly re-deriving its own expectation.
func wantDelay(attempt int) time.Duration {
	if d := 6 * time.Second << (attempt - 1); d < 30*time.Minute {
		return d
	}
	return 30 * time.Minute
}

// TestBackoffLadderIsCappedAtThirtyMinutes measures how LONG the uploader asks
// to sleep, which no other test here does: the park test counts sleeps, so
// min(exp, cap) was unobserved. The clamp is load-bearing — the unclamped
// exponential is 51m12s by attempt 10 — and dropping it would leave every
// other test in this file green while a customer's daemon parked 20 minutes
// late.
func TestBackoffLadderIsCappedAtThirtyMinutes(t *testing.T) {
	sp := openSpool(t)
	session, _ := uuid.NewV7()
	appendAll(t, sp, makeEvent(t, session, 1, spool.ClassBilling))

	ingest := &fakeIngest{respond: func(_ int, w http.ResponseWriter, _ string) {
		writeErr(w, http.StatusServiceUnavailable, "M1E-9500", nil)
	}}
	// Rand = 1.0 (newTestUplink's default) draws the top of the jitter window,
	// the only setting where a clamp on that window is visible at all.
	u, dl, _ := newTestUplink(t, sp, ingest, nil)

	if res := sendOnce(t, u); res != cycleParked {
		t.Fatalf("result = %v, want parked after the retry budget", res)
	}
	// Positive capture first: the exact durations slept, in order. "Nothing
	// exceeded 30 min" is also what a test that recorded zero sleeps reports.
	got := dl.list()
	if len(got) != maxAttempts-1 {
		t.Fatalf("observed %d sleeps, want %d (one per failure but the last, which parks)", len(got), maxAttempts-1)
	}
	for i, d := range got {
		if want := wantDelay(i + 1); d != want {
			t.Fatalf("sleep %d = %v, want %v (base 6 s, doubling)", i+1, d, want)
		}
		if d > 30*time.Minute {
			t.Fatalf("sleep %d = %v exceeds the 30 min cap", i+1, d)
		}
	}
	// The budget stops the observed ladder at attempt 9 (25m36s), one rung
	// short of the cap — the 10th failure parks instead of sleeping — so the
	// clamp is asserted at the computation, the only place reachable. It is not
	// decoration: raise maxAttempts by one and attempt 10 sleeps 51m12s
	// without it.
	capped := 0
	for n := 1; n <= 12; n++ {
		unclamped := 6 * time.Second << (n - 1) // the doc's base, doubled, un-clamped
		if unclamped > 30*time.Minute {
			capped++
		}
		if d := u.backoff(n); d != wantDelay(n) {
			t.Fatalf("backoff(%d) = %v, want %v (unclamped this rung is %v)", n, d, wantDelay(n), unclamped)
		}
	}
	if capped < 3 {
		t.Fatalf("walked only %d rungs past the 30 min cap, want ≥3: the clamp went unexercised", capped)
	}
}

// TestBackoffDrawsFullJitterOverTheCappedExponential pins the U(0,1)·ceiling
// semantics of 08 §2.5's "full jitter": the draw scales the WHOLE window, so a
// zero draw waits zero and no draw can exceed the rung. Every other backoff
// test runs at one fixed draw, so an implementation that consulted the jitter
// source and discarded it — fleet-wide lockstep retries, the thundering herd
// the clause exists to prevent — would keep them all green.
func TestBackoffDrawsFullJitterOverTheCappedExponential(t *testing.T) {
	ingest := &fakeIngest{respond: func(int, http.ResponseWriter, string) {}}
	u, _, _ := newTestUplink(t, openSpool(t), ingest, nil)

	for _, draw := range []float64{0, 0.37, 0.5, 1} {
		u.rand = func() float64 { return draw }
		for n := 1; n <= 12; n++ {
			ceiling := wantDelay(n)
			d := u.backoff(n)
			if d < 0 || d > ceiling {
				t.Fatalf("backoff(%d) at draw %v = %v, outside the full-jitter window [0, %v]", n, draw, d, ceiling)
			}
			if want := time.Duration(float64(ceiling) * draw); d != want {
				t.Fatalf("backoff(%d) at draw %v = %v, want %v (delay = draw · min(30m, 6s·2^(n−1)))", n, draw, d, want)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// 08 §2.5, the network row: every retry test above drives a status code, but a
// torn connection or a dead route never produces one — and that is the failure
// a laptop on hotel wifi actually hits.
// ---------------------------------------------------------------------------

func TestTornConnectionIsRetriedNeverQuarantined(t *testing.T) {
	sp := openSpool(t)
	session, _ := uuid.NewV7()
	appendAll(t, sp, makeEvent(t, session, 1, spool.ClassBilling))

	ingest := &fakeIngest{respond: func(n int, w http.ResponseWriter, bid string) {
		if n == 1 {
			// Kill the connection with the request already on the wire and no
			// status line ever written: the client gets a transport error, the
			// one retry class no status code can express.
			panic(http.ErrAbortHandler)
		}
		writeAck(w, http.StatusOK, bid, nil)
	}}
	u, dl, qdir := newTestUplink(t, sp, ingest, nil)

	if res := sendOnce(t, u); res != cycleAdvanced {
		t.Fatalf("result = %v, want advanced once the retry landed", res)
	}
	if ingest.count() != 2 {
		t.Fatalf("requests = %d, want 2: a network failure is retried (08 §2.5)", ingest.count())
	}
	if ds := dl.list(); len(ds) != 1 || ds[0] != wantDelay(1) {
		t.Fatalf("backoff sleeps = %v, want exactly [%v] — the retry must back off, not spin", ds, wantDelay(1))
	}
	if ents, _ := os.ReadDir(qdir); len(ents) != 0 {
		t.Fatal("a torn connection quarantined the batch: network failures retry, they are not content verdicts (08 §2.5)")
	}
	assertDrained(t, sp)
}

func TestUnreachableEndpointExhaustsBudgetThenParks(t *testing.T) {
	sp := openSpool(t)
	session, _ := uuid.NewV7()
	appendAll(t, sp, makeEvent(t, session, 1, spool.ClassBilling))

	// A closed loopback port: the POST fails at dial, so nothing ever speaks
	// HTTP — the offline-device case, where quarantining would destroy
	// billing-grade bytes the spool was holding correctly.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}

	ingest := &fakeIngest{respond: func(int, http.ResponseWriter, string) {}}
	u, dl, qdir := newTestUplink(t, sp, ingest, func(c *Config) {
		c.Endpoint = "http://" + dead + "/m1p/v1/ingest"
	})

	if res := sendOnce(t, u); res != cycleParked {
		t.Fatalf("result = %v, want parked: an unreachable endpoint spends the budget (08 §2.5)", res)
	}
	if ingest.count() != 0 {
		t.Fatalf("the live fake ingest saw %d requests: the test never reached the dead endpoint", ingest.count())
	}
	if n := len(dl.list()); n != maxAttempts-1 {
		t.Fatalf("backoff sleeps = %d, want %d: all %d attempts must be spent before parking", n, maxAttempts-1, maxAttempts)
	}
	if ents, _ := os.ReadDir(qdir); len(ents) != 0 {
		t.Fatal("an offline device quarantined billing-grade data — a dial failure parks, leaving the bytes spooled (08 §2.5)")
	}
	if ack, write := sp.Cursors(); ack == write {
		t.Fatal("the parked batch was acked away; the spool must still hold it")
	}
}

func TestRunRequeuesParkedWorkOnNetworkChange(t *testing.T) {
	sp := openSpool(t)
	session, _ := uuid.NewV7()
	appendAll(t, sp, makeEvent(t, session, 1, spool.ClassBilling))

	ingest := &fakeIngest{respond: func(n int, w http.ResponseWriter, bid string) {
		if n <= maxAttempts {
			writeErr(w, http.StatusServiceUnavailable, "M1E-9500", nil)
			return
		}
		writeAck(w, http.StatusOK, bid, nil)
	}}
	netChange := make(chan struct{})
	u, dl, _ := newTestUplink(t, sp, ingest, func(c *Config) {
		c.Rand = func() float64 { return 0.0001 }
		c.NetworkChange = netChange
	})
	dl.blockPark = true // the 6 h timer never fires; only the signal can wake it

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- u.Run(ctx) }()

	waitFor(t, "park after retry budget", func() bool { return ingest.count() == maxAttempts })
	netChange <- struct{}{} // wake/network-change re-queues parked work (08 §2.5)
	waitFor(t, "re-queued batch to ack", func() bool {
		ack, write := sp.Cursors()
		return ingest.count() == maxAttempts+1 && ack == write
	})
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run = %v", err)
	}
}

// ---------------------------------------------------------------------------
// 08 §2.4/§2.5: the 4xx quarantine rule
// ---------------------------------------------------------------------------

func TestQuarantineOn4xxNeverRetried(t *testing.T) {
	sp := openSpool(t)
	session, _ := uuid.NewV7()
	e1 := makeEvent(t, session, 1, spool.ClassBilling)
	e2 := makeEvent(t, session, 2, spool.ClassDiagnostic)
	appendAll(t, sp, e1, e2)

	drops := &stubDrops{rows: []spool.Dropped{{Reason: spool.DropCRCLoss, Class: spool.ClassBilling, Quantity: 3}}}
	ingest := &fakeIngest{}
	u, _, qdir := newTestUplink(t, sp, ingest, func(c *Config) { c.Drops = []DropSource{drops} })
	ingest.respond = func(n int, w http.ResponseWriter, bid string) {
		if n == 1 {
			writeErr(w, http.StatusBadRequest, "M1E-2001", nil)
			return
		}
		writeAck(w, http.StatusOK, bid, nil)
	}

	if res := sendOnce(t, u); res != cycleAdvanced {
		t.Fatal("quarantine must advance the cursor (poison batch cannot block drainage)")
	}
	if ingest.count() != 1 {
		t.Fatalf("requests = %d: a 4xx is NEVER retried (08 §2.5)", ingest.count())
	}
	assertDrained(t, sp)

	// The batch moved aside on disk, sealed + manifest — never silently dropped.
	bid := ingest.req(0).header.Get("M1P-Batch-Id")
	sealed, err := os.ReadFile(filepath.Join(qdir, bid+".m1p.zst.sealed"))
	if err != nil {
		t.Fatalf("quarantined payload missing: %v", err)
	}
	_, frames := decodeBody(t, sealed) // identity seal ⇒ still the zstd batch
	if len(frames) != 2 || !bytes.Equal(frames[0], e1.payload) || !bytes.Equal(frames[1], e2.payload) {
		t.Fatal("quarantined bytes are not the refused batch")
	}
	manRaw, err := os.ReadFile(filepath.Join(qdir, bid+".manifest.json"))
	if err != nil {
		t.Fatalf("manifest missing: %v", err)
	}
	var man manifest
	if err := json.Unmarshal(manRaw, &man); err != nil {
		t.Fatal(err)
	}
	if man.Status != 400 || man.ErrCode != "M1E-2001" || man.EventCount != 2 || len(man.EventIDs) != 2 {
		t.Fatalf("manifest = %+v", man)
	}

	// The quarantine accounting AND the batch's own drained rows ride the
	// next successful batch, exactly once.
	e3 := makeEvent(t, session, 3, spool.ClassDiagnostic)
	appendAll(t, sp, e3)
	if res := sendOnce(t, u); res != cycleAdvanced {
		t.Fatal("next batch should land")
	}
	batch, _ := decodeBody(t, ingest.req(1).body)
	want := map[[2]int32]uint64{
		{int32(spool.DropCRCLoss), int32(spool.ClassBilling)}:  3, // re-credited: the 400 batch never landed
		{int32(dropQuarantined), int32(spool.ClassBilling)}:    1,
		{int32(dropQuarantined), int32(spool.ClassDiagnostic)}: 1,
	}
	got := map[[2]int32]uint64{}
	for _, d := range batch.GetDropped() {
		got[[2]int32{int32(d.GetReason()), int32(d.GetDurabilityClass())}] = d.GetQuantity()
	}
	if len(got) != len(want) {
		t.Fatalf("dropped rows = %v, want %v", got, want)
	}
	for k, q := range want {
		if got[k] != q {
			t.Fatalf("dropped rows = %v, want %v", got, want)
		}
	}

	// …and exactly once: the batch after carries none.
	appendAll(t, sp, makeEvent(t, session, 4, spool.ClassDiagnostic))
	if res := sendOnce(t, u); res != cycleAdvanced {
		t.Fatal("third batch should land")
	}
	if batch3, _ := decodeBody(t, ingest.req(2).body); len(batch3.GetDropped()) != 0 {
		t.Fatalf("dropped rows rode twice: %v", batch3.GetDropped())
	}
}

func Test401RefreshedOnceThenResent(t *testing.T) {
	sp := openSpool(t)
	session, _ := uuid.NewV7()
	appendAll(t, sp, makeEvent(t, session, 1, spool.ClassBilling))

	ingest := &fakeIngest{respond: func(n int, w http.ResponseWriter, bid string) {
		if n == 1 {
			writeErr(w, http.StatusUnauthorized, "M1E-1002", nil)
			return
		}
		writeAck(w, http.StatusOK, bid, nil)
	}}
	tok := &refreshableToken{cur: "tok-old", next: "tok-new"}
	u, _, _ := newTestUplink(t, sp, ingest, func(c *Config) { c.Tokens = tok })

	if res := sendOnce(t, u); res != cycleAdvanced {
		t.Fatal("401-with-refresh is the one retryable 4xx (08 §2.4)")
	}
	if got := ingest.req(0).header.Get("Authorization"); got != "Bearer tok-old" {
		t.Fatal(got)
	}
	if got := ingest.req(1).header.Get("Authorization"); got != "Bearer tok-new" {
		t.Fatalf("re-send did not carry the refreshed token: %s", got)
	}
	assertDrained(t, sp)
}

func Test401WithoutRefreshParks(t *testing.T) {
	sp := openSpool(t)
	session, _ := uuid.NewV7()
	appendAll(t, sp, makeEvent(t, session, 1, spool.ClassBilling))

	ingest := &fakeIngest{respond: func(_ int, w http.ResponseWriter, bid string) {
		writeErr(w, http.StatusUnauthorized, "M1E-1002", nil)
	}}
	u, _, qdir := newTestUplink(t, sp, ingest, nil) // StaticToken: no refresh path

	if res := sendOnce(t, u); res != cycleParked {
		t.Fatal("401 with no refresh path parks, never quarantines (08 §2.4)")
	}
	if ingest.count() != 1 {
		t.Fatalf("requests = %d, want 1", ingest.count())
	}
	if ents, _ := os.ReadDir(qdir); len(ents) != 0 {
		t.Fatal("auth failure must not quarantine data")
	}
}

// TestParkedOn401KeepsSpoolingThenReplaysBothSides is FR-ENROLL-002's
// keeps-spooling clause: a rejected device token is an UPLOAD problem and must
// never become a CAPTURE one (08 §2.5 — "PARKED is uploader state, not data
// state"). Neither neighbouring test can see it. Test401WithoutRefreshParks
// (line 780) stops at the park and never appends again, so it cannot observe
// whether capture survived; TestParkAfterBudgetThenRequeueSucceeds (line 429)
// asserts the ack cursor held, which proves the EXISTING batch was not lost,
// not that anything new was accepted. A daemon that went silent the moment the
// token expired keeps both of them green, and the resulting hole is permanent:
// it surfaces months later as an unexplained dip in a billing-grade metric,
// with no loss row to price it (07 §6 forbids silent loss above all).
//
// Phase 0 is the anti-vacuity control — the same appendAll, the same spool, the
// same uplink, un-parked. Without it every assertion below is equally satisfied
// by a harness whose appends never reached the spool at all.
func TestParkedOn401KeepsSpoolingThenReplaysBothSides(t *testing.T) {
	sp := openSpool(t)
	session, _ := uuid.NewV7()

	// The token ledger's two states, flipped from the test goroutine while Run
	// serves requests: atomic because the handler reads it concurrently.
	var authOK atomic.Bool
	authOK.Store(true)
	ingest := &fakeIngest{respond: func(_ int, w http.ResponseWriter, bid string) {
		if !authOK.Load() {
			writeErr(w, http.StatusUnauthorized, "M1E-1002", nil)
			return
		}
		writeAck(w, http.StatusOK, bid, nil)
	}}
	netChange := make(chan struct{})
	// StaticToken (newTestUplink's default) has no refresh path, so the first
	// 401 parks immediately — 08 §2.4's expired/revoked row, one request.
	u, dl, qdir := newTestUplink(t, sp, ingest, func(c *Config) { c.NetworkChange = netChange })
	dl.blockPark = true // the 6 h timer never fires; only the signal re-queues

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- u.Run(ctx) }()

	// Phase 0 — control: capture → spool → wire is live on this harness.
	ctrl := makeEvent(t, session, 1, spool.ClassBilling)
	appendAll(t, sp, ctrl)
	waitFor(t, "the control event to land", func() bool {
		ack, write := sp.Cursors()
		return ingest.count() == 1 && ack == write
	})

	// Phase 1 — the device token is rejected. The in-flight backlog parks.
	authOK.Store(false)
	pre := makeEvent(t, session, 2, spool.ClassBilling)
	appendAll(t, sp, pre)
	waitFor(t, "the uploader to enter PARKED", func() bool { return dl.parkEntries() == 1 })
	parkedAck, parkedWrite := sp.Cursors()
	reqsAtPark := ingest.count()

	// Phase 2 — THE CLAUSE: capture keeps recording through the park.
	// appendAll t.Fatals on any Append error, ErrDiagnosticShed included, so a
	// park that closed the write path fails here rather than silently no-opping.
	post1 := makeEvent(t, session, 3, spool.ClassBilling)
	post2 := makeEvent(t, session, 4, spool.ClassDiagnostic)
	appendAll(t, sp, post1, post2)

	// Ordered before the cursor check on purpose: a park that SHED rather than
	// stopped names its own cause here (reason + class), where growth alone
	// would only report bytes missing. Nothing may be shed for an upload
	// verdict, and billing-grade may not be shed for any reason — it blocks
	// (07 §6). Both losses are silent on the wire without this row.
	if rows := sp.DrainDropped(); len(rows) != 0 {
		t.Fatalf("loss ledger = %v while parked, want empty: a 401 is an upload verdict, nothing is shed for it — "+
			"least of all billing-grade, which blocks and is never shed (07 §6)", rows)
	}
	ack, write := sp.Cursors()
	grown := parkedWrite.Off + uint64(len(post1.payload)+len(post2.payload))
	if write.Seq != parkedWrite.Seq || write.Off < grown {
		t.Fatalf("durable write cursor %v -> %v, want at least (%d,%d): the parked daemon stopped spooling — "+
			"an expired token became a capture outage (08 §2.5)", parkedWrite, write, parkedWrite.Seq, grown)
	}
	if ack != parkedAck {
		t.Fatalf("ack cursor moved %v -> %v while parked: bytes were released with nothing landed (08 §2.2)", parkedAck, ack)
	}
	if ents, _ := os.ReadDir(qdir); len(ents) != 0 {
		t.Fatal("auth failure quarantined data: 401 parks, never quarantines (08 §2.4)")
	}
	if n := ingest.count(); n != reqsAtPark {
		t.Fatalf("requests = %d, want %d: PARKED must wait for a re-queue trigger, not hammer a rejected token", n, reqsAtPark)
	}

	// Phase 3 — the token is accepted again. One re-queue uploads BOTH sides of
	// the park in spool order: the customer's ledger is whole, not holed.
	authOK.Store(true)
	netChange <- struct{}{} // 08 §2.5's wake / network-change re-queue
	waitFor(t, "the re-queued backlog to land", func() bool {
		ack, write := sp.Cursors()
		return ingest.count() == reqsAtPark+1 && ack == write
	})
	_, frames := decodeBody(t, ingest.req(ingest.count()-1).body)
	if len(frames) != 3 ||
		!bytes.Equal(frames[0], pre.payload) ||
		!bytes.Equal(frames[1], post1.payload) ||
		!bytes.Equal(frames[2], post2.payload) {
		t.Fatalf("replayed batch carried %d frames, want the pre-park backlog then both post-park events, "+
			"in spool order — this is the only proof the post-park appends were real bytes", len(frames))
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run = %v", err)
	}
	// Exactly: the control, the 401, one replay. A fourth would mean the
	// backlog uploaded twice — at-least-once is the server's dedupe to absorb,
	// but a re-send here would mean the ack cursor never took.
	if n := ingest.count(); n != 3 {
		t.Fatalf("requests = %d, want 3 (control, the 401, one replay)", n)
	}
}

type refreshableToken struct {
	mu        sync.Mutex
	cur, next string
}

func (r *refreshableToken) Token(context.Context) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cur, nil
}

func (r *refreshableToken) Refresh(context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cur = r.next
	return nil
}

// ---------------------------------------------------------------------------
// 08 §2.4: the 422 remainder flow
// ---------------------------------------------------------------------------

func Test422QuarantinesNamedEventsAndResendsRemainderOnce(t *testing.T) {
	sp := openSpool(t)
	session, _ := uuid.NewV7()
	e0 := makeEvent(t, session, 1, spool.ClassBilling)
	e1 := makeEvent(t, session, 2, spool.ClassDiagnostic)
	e2 := makeEvent(t, session, 3, spool.ClassBilling)
	appendAll(t, sp, e0, e1, e2)

	ingest := &fakeIngest{respond: func(n int, w http.ResponseWriter, bid string) {
		if n == 1 {
			writeErr(w, http.StatusUnprocessableEntity, "M1E-2006",
				map[string]any{"event_ids": []string{e1.id.String()}, "kinds": []string{"seq"}})
			return
		}
		writeAck(w, http.StatusOK, bid, nil)
	}}
	u, _, qdir := newTestUplink(t, sp, ingest, nil)

	if res := sendOnce(t, u); res != cycleAdvanced {
		t.Fatal("remainder should land and advance")
	}
	if ingest.count() != 2 {
		t.Fatalf("requests = %d, want 2 (original + one remainder)", ingest.count())
	}
	if ingest.req(1).header.Get("M1P-Batch-Id") == ingest.req(0).header.Get("M1P-Batch-Id") {
		t.Fatal("remainder reused the batch_id over different bytes — the 409 corruption signal")
	}
	_, frames := decodeBody(t, ingest.req(1).body)
	if len(frames) != 2 || !bytes.Equal(frames[0], e0.payload) || !bytes.Equal(frames[1], e2.payload) {
		t.Fatal("remainder must carry exactly the un-named events, in order")
	}
	assertDrained(t, sp)

	// The named event is on disk with a manifest naming it.
	found := false
	ents, err := os.ReadDir(qdir)
	if err != nil {
		t.Fatal(err)
	}
	for _, ent := range ents {
		if !strings.HasSuffix(ent.Name(), ".manifest.json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(qdir, ent.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var man manifest
		if err := json.Unmarshal(raw, &man); err != nil {
			t.Fatal(err)
		}
		if man.Status == 422 && len(man.EventIDs) == 1 && man.EventIDs[0] == e1.id.String() {
			found = true
			sealed, err := os.ReadFile(filepath.Join(qdir, man.BatchID+".m1p.zst.sealed"))
			if err != nil {
				t.Fatal(err)
			}
			if _, qframes := decodeBody(t, sealed); len(qframes) != 1 || !bytes.Equal(qframes[0], e1.payload) {
				t.Fatal("quarantined mini-batch does not hold the named event verbatim")
			}
		}
	}
	if !found {
		t.Fatal("no quarantine manifest names the 422 event")
	}

	// Its Dropped{QUARANTINED} row rides the next batch.
	appendAll(t, sp, makeEvent(t, session, 4, spool.ClassDiagnostic))
	if res := sendOnce(t, u); res != cycleAdvanced {
		t.Fatal("next batch should land")
	}
	batch, _ := decodeBody(t, ingest.req(2).body)
	if len(batch.GetDropped()) != 1 ||
		batch.GetDropped()[0].GetReason() != m1pv1.DropReason_DROP_REASON_QUARANTINED ||
		batch.GetDropped()[0].GetDurabilityClass() != m1pv1.DurabilityClass_DURABILITY_CLASS_DIAGNOSTIC ||
		batch.GetDropped()[0].GetQuantity() != 1 {
		t.Fatalf("dropped = %v, want one Dropped{QUARANTINED, DIAGNOSTIC, 1}", batch.GetDropped())
	}
}

// Test422RemainderParkThenReplay pins the two remainder-accounting rules:
// (a) events the 422 flow quarantined-with-evidence are quarantined exactly
// once and NEVER re-sent, even when the remainder re-send fails to ack and
// the spool window replays (quarantine is never auto-retried, 08 §2.5);
// (b) Dropped counters — the quarantine rows AND the batch's own drained
// rows — ride exactly one successfully-acked batch, never two.
func Test422RemainderParkThenReplay(t *testing.T) {
	sp := openSpool(t)
	session, _ := uuid.NewV7()
	e0 := makeEvent(t, session, 1, spool.ClassBilling)
	e1 := makeEvent(t, session, 2, spool.ClassDiagnostic) // the 422-named event
	e2 := makeEvent(t, session, 3, spool.ClassBilling)
	appendAll(t, sp, e0, e1, e2)

	drops := &stubDrops{rows: []spool.Dropped{{Reason: spool.DropCRCLoss, Class: spool.ClassBilling, Quantity: 3}}}
	ingest := &fakeIngest{respond: func(n int, w http.ResponseWriter, bid string) {
		switch {
		case n == 1:
			writeErr(w, http.StatusUnprocessableEntity, "M1E-2006",
				map[string]any{"event_ids": []string{e1.id.String()}, "kinds": []string{"seq"}})
		case n <= 1+maxAttempts: // the remainder re-send exhausts its budget
			writeErr(w, http.StatusServiceUnavailable, "M1E-9500", nil)
		default:
			writeAck(w, http.StatusOK, bid, nil)
		}
	}}
	u, _, qdir := newTestUplink(t, sp, ingest, func(c *Config) {
		c.Drops = []DropSource{drops}
		c.Rand = func() float64 { return 0.0001 }
	})

	if res := sendOnce(t, u); res != cycleParked {
		t.Fatal("remainder exhausting its budget must park, not ack")
	}
	// Re-queue (wake / 6 h timer / network-change): the replayed window must
	// exclude the quarantined event and land.
	if res := sendOnce(t, u); res != cycleAdvanced {
		t.Fatal("replayed window should land")
	}
	assertDrained(t, sp)
	if got, want := ingest.count(), 2+maxAttempts; got != want {
		t.Fatalf("requests = %d, want %d (422 + %d remainder attempts + 1 replay)", got, want, maxAttempts)
	}
	// (a) after the quarantine write (request 1's verdict), e1 rides NO wire
	// request — not the remainder attempts, not the replay.
	for i := 1; i < ingest.count(); i++ {
		_, frames := decodeBody(t, ingest.req(i).body)
		for _, f := range frames {
			if bytes.Equal(f, e1.payload) {
				t.Fatalf("request %d re-sent the quarantined event (08 §2.5: never auto-retried)", i+1)
			}
		}
	}
	_, frames := decodeBody(t, ingest.req(ingest.count()-1).body)
	if len(frames) != 2 || !bytes.Equal(frames[0], e0.payload) || !bytes.Equal(frames[1], e2.payload) {
		t.Fatal("replayed batch must carry exactly the un-named events, in order")
	}
	// ...and its evidence landed exactly once: one sealed payload + one manifest.
	if ents, _ := os.ReadDir(qdir); len(ents) != 2 {
		t.Fatalf("quarantine holds %d files, want 2 — the named event quarantines exactly once", len(ents))
	}
	// (b) the acked replay carries each counter exactly once: the QUARANTINED
	// row from the 422 and the re-credited CRC row that never landed.
	batch, _ := decodeBody(t, ingest.req(ingest.count()-1).body)
	got := map[[2]int32]uint64{}
	for _, d := range batch.GetDropped() {
		got[[2]int32{int32(d.GetReason()), int32(d.GetDurabilityClass())}] = d.GetQuantity()
	}
	want := map[[2]int32]uint64{
		{int32(spool.DropCRCLoss), int32(spool.ClassBilling)}:  3,
		{int32(dropQuarantined), int32(spool.ClassDiagnostic)}: 1,
	}
	if len(got) != len(want) {
		t.Fatalf("dropped rows = %v, want %v", got, want)
	}
	for k, q := range want {
		if got[k] != q {
			t.Fatalf("dropped rows = %v, want %v (counters must ride exactly one acked batch)", got, want)
		}
	}
	// ...and exactly once: the batch after carries none.
	appendAll(t, sp, makeEvent(t, session, 4, spool.ClassDiagnostic))
	if res := sendOnce(t, u); res != cycleAdvanced {
		t.Fatal("follow-up batch should land")
	}
	if last, _ := decodeBody(t, ingest.req(ingest.count()-1).body); len(last.GetDropped()) != 0 {
		t.Fatalf("dropped rows rode twice: %v", last.GetDropped())
	}
}

// ---------------------------------------------------------------------------
// 202: server-side quarantine accounting
// ---------------------------------------------------------------------------

func Test202QuarantinedEventsRideNextBatchAsDropped(t *testing.T) {
	sp := openSpool(t)
	session, _ := uuid.NewV7()
	e0 := makeEvent(t, session, 1, spool.ClassBilling)
	appendAll(t, sp, e0)

	ingest := &fakeIngest{respond: func(n int, w http.ResponseWriter, bid string) {
		if n == 1 {
			writeAck(w, http.StatusAccepted, bid, []string{e0.id.String()})
			return
		}
		writeAck(w, http.StatusOK, bid, nil)
	}}
	u, _, _ := newTestUplink(t, sp, ingest, nil)

	if res := sendOnce(t, u); res != cycleAdvanced {
		t.Fatal("202 is an ack: delete acked segments (08 §2.4)")
	}
	assertDrained(t, sp)

	appendAll(t, sp, makeEvent(t, session, 2, spool.ClassDiagnostic))
	if res := sendOnce(t, u); res != cycleAdvanced {
		t.Fatal("next batch should land")
	}
	batch, _ := decodeBody(t, ingest.req(1).body)
	if len(batch.GetDropped()) != 1 ||
		batch.GetDropped()[0].GetReason() != m1pv1.DropReason_DROP_REASON_QUARANTINED ||
		batch.GetDropped()[0].GetDurabilityClass() != m1pv1.DurabilityClass_DURABILITY_CLASS_BILLING_GRADE ||
		batch.GetDropped()[0].GetQuantity() != 1 {
		t.Fatalf("dropped = %v, want Dropped{QUARANTINED, BILLING_GRADE, 1}", batch.GetDropped())
	}
}

// ---------------------------------------------------------------------------
// 07 §6 step 5: crash between 200 and Ack — at-least-once by design
// ---------------------------------------------------------------------------

// crashStore simulates dying between the server's 200 and the local Ack: the
// first Ack "crashes" without writing. The replay must re-send the same
// events (new batch_id, same event_ids — the server dedupes) and then land
// the cursor cleanly.
type crashStore struct {
	*spool.Spool
	crashed bool
}

func (c *crashStore) Ack(cur spool.Cursor) error {
	if !c.crashed {
		c.crashed = true
		return errors.New("simulated crash before ack")
	}
	return c.Spool.Ack(cur)
}

func TestCrashBetweenAckAndAckIsReplaySafe(t *testing.T) {
	sp := openSpool(t)
	session, _ := uuid.NewV7()
	e0 := makeEvent(t, session, 1, spool.ClassBilling)
	e1 := makeEvent(t, session, 2, spool.ClassBilling)
	appendAll(t, sp, e0, e1)
	store := &crashStore{Spool: sp}

	ingest := &fakeIngest{respond: func(_ int, w http.ResponseWriter, bid string) { writeAck(w, http.StatusOK, bid, nil) }}
	u, _, _ := newTestUplink(t, store, ingest, nil)

	b, err := u.compose()
	if err != nil || b == nil {
		t.Fatal(err)
	}
	if _, err := u.send(context.Background(), b, 0); err == nil {
		t.Fatal("ack failure must surface: it is local ledger damage the daemon restarts over")
	}
	ack, write := sp.Cursors()
	if ack == write {
		t.Fatal("cursor advanced despite the crashed Ack")
	}

	// "Restart": a fresh Uplink over the same spool state.
	u2, _, _ := newTestUplink(t, store, ingest, nil)
	if res := sendOnce(t, u2); res != cycleAdvanced {
		t.Fatal("replay should land")
	}
	if ingest.count() != 2 {
		t.Fatalf("requests = %d, want 2", ingest.count())
	}
	r1, r2 := ingest.req(0), ingest.req(1)
	if r1.header.Get("M1P-Batch-Id") == r2.header.Get("M1P-Batch-Id") {
		t.Fatal("replay after crash must mint a new batch_id (composition state died with the process)")
	}
	_, f1 := decodeBody(t, r1.body)
	_, f2 := decodeBody(t, r2.body)
	if len(f1) != 2 || len(f2) != 2 || !bytes.Equal(f1[0], f2[0]) || !bytes.Equal(f1[1], f2[1]) {
		t.Fatal("replay must re-send the identical event payloads — event_id is the dedupe key (07 §7)")
	}
	assertDrained(t, sp)
	if b, err := u2.compose(); err != nil || b != nil {
		t.Fatal("cursor corrupted: records remain after the replayed ack")
	}
}

// ---------------------------------------------------------------------------
// 08 §2.2: the ack license is controld's landing write, never a bare 2xx —
// middleboxes (TLS interception, captive portals) answer 2xx/3xx too.
// ---------------------------------------------------------------------------

func TestMiddlebox200WithoutBatchIDEchoIsRetriedNotAcked(t *testing.T) {
	sp := openSpool(t)
	session, _ := uuid.NewV7()
	appendAll(t, sp, makeEvent(t, session, 1, spool.ClassBilling))

	ingest := &fakeIngest{respond: func(n int, w http.ResponseWriter, bid string) {
		if n == 1 { // a portal's 200: HTML, no JSON ack, no batch_id echo
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html>corporate proxy says hello</html>"))
			return
		}
		writeAck(w, http.StatusOK, bid, nil)
	}}
	u, dl, qdir := newTestUplink(t, sp, ingest, nil)

	if res := sendOnce(t, u); res != cycleAdvanced {
		t.Fatalf("result = %v, want advanced after the real ack", res)
	}
	if ingest.count() != 2 {
		t.Fatalf("requests = %d, want 2: an unverifiable 2xx is network-class, retried (08 §2.2)", ingest.count())
	}
	if len(dl.list()) != 1 {
		t.Fatalf("backoff sleeps = %v, want exactly one (the retry)", dl.list())
	}
	if ents, _ := os.ReadDir(qdir); len(ents) != 0 {
		t.Fatal("a middlebox 2xx must never quarantine data")
	}
	assertDrained(t, sp)
}

func TestWrongBatchIDEchoIsNotAnAck(t *testing.T) {
	sp := openSpool(t)
	session, _ := uuid.NewV7()
	appendAll(t, sp, makeEvent(t, session, 1, spool.ClassBilling))

	other, _ := uuid.NewV7()
	ingest := &fakeIngest{respond: func(n int, w http.ResponseWriter, bid string) {
		if n == 1 { // valid JSON ack shape, but for a DIFFERENT batch
			writeAck(w, http.StatusOK, other.String(), nil)
			return
		}
		writeAck(w, http.StatusOK, bid, nil)
	}}
	u, _, _ := newTestUplink(t, sp, ingest, nil)

	if res := sendOnce(t, u); res != cycleAdvanced {
		t.Fatal("want advanced after the correctly-echoed ack")
	}
	if ingest.count() != 2 {
		t.Fatalf("requests = %d, want 2: a mis-echoed batch_id must not carry deletion authority", ingest.count())
	}
	assertDrained(t, sp)
}

func TestRedirectIsRefusedAndRetriedNeverAcked(t *testing.T) {
	sp := openSpool(t)
	session, _ := uuid.NewV7()
	appendAll(t, sp, makeEvent(t, session, 1, spool.ClassBilling))

	ingest := &fakeIngest{}
	u, _, qdir := newTestUplink(t, sp, ingest, nil)
	ingest.respond = func(n int, w http.ResponseWriter, bid string) {
		if n == 1 { // captive-portal 302; following it would find a 200 page
			w.Header().Set("Location", u.endpoint)
			w.WriteHeader(http.StatusFound)
			return
		}
		writeAck(w, http.StatusOK, bid, nil)
	}

	if res := sendOnce(t, u); res != cycleAdvanced {
		t.Fatal("want advanced after the real ack")
	}
	// Exactly 2 requests: the 302 was never followed (a follow would have
	// recorded a third request and acked off the portal page's 200).
	if ingest.count() != 2 {
		t.Fatalf("requests = %d, want 2 (redirects are network-class, never followed)", ingest.count())
	}
	if ents, _ := os.ReadDir(qdir); len(ents) != 0 {
		t.Fatal("a redirect must never quarantine data")
	}
	assertDrained(t, sp)
}

// ---------------------------------------------------------------------------
// 08 §2.4 403/426: quarantine the ONE offending batch, then halt — never
// grind the backlog into never-auto-retried quarantine files.
// ---------------------------------------------------------------------------

func TestRevoked403QuarantinesOffendingBatchThenHalts(t *testing.T) {
	sp := openSpool(t)
	session, _ := uuid.NewV7()
	// Two events too large to share a batch (compose's 4 MiB raw target), so
	// the spool holds a second batch BEHIND the offending one.
	big := func(seq uint64) testEvent {
		id, _ := uuid.NewV7()
		ev := &m1pv1.Event{EventId: id[:], Seq: seq, SessionId: session[:], SessionEpoch: 1,
			Body: &m1pv1.Event_Usage{Usage: &m1pv1.Usage{IdemKey: bytes.Repeat([]byte{0xaa}, 3<<20)}}}
		payload, err := proto.Marshal(ev)
		if err != nil {
			t.Fatal(err)
		}
		return testEvent{id: id, payload: payload, class: spool.ClassBilling}
	}
	appendAll(t, sp, big(1), big(2))

	ingest := &fakeIngest{respond: func(_ int, w http.ResponseWriter, _ string) {
		writeErr(w, http.StatusForbidden, "M1E-1003", nil)
	}}
	u, _, qdir := newTestUplink(t, sp, ingest, nil)

	if err := u.Run(context.Background()); err != nil {
		t.Fatalf("Run = %v, want nil (halt is not local damage)", err)
	}
	if ingest.count() != 1 {
		t.Fatalf("requests = %d, want 1: after the 403 the uplink must HALT, not grind batch after batch into quarantine", ingest.count())
	}
	ents, _ := os.ReadDir(qdir)
	if len(ents) != 2 { // one sealed payload + one manifest: the offending batch only
		t.Fatalf("quarantine holds %d files, want 2 (08 §2.4: quarantine-and-report the one refused batch)", len(ents))
	}
	// The backlog behind the refused batch stays in the spool, uploadable
	// after re-enrollment — parked, not quarantined (08 §2.5).
	ack, write := sp.Cursors()
	if ack == write {
		t.Fatal("the whole spool was acked away; the second batch must remain")
	}
}

func TestSchemaWindow426QuarantinesAndHalts(t *testing.T) {
	sp := openSpool(t)
	session, _ := uuid.NewV7()
	appendAll(t, sp, makeEvent(t, session, 1, spool.ClassBilling))

	ingest := &fakeIngest{respond: func(_ int, w http.ResponseWriter, _ string) {
		writeErr(w, http.StatusUpgradeRequired, "M1E-2007", nil)
	}}
	u, _, qdir := newTestUplink(t, sp, ingest, nil)

	if res := sendOnce(t, u); res != cycleHalt {
		t.Fatalf("result = %v, want halt (08 §2.4 426 row)", res)
	}
	if ingest.count() != 1 {
		t.Fatalf("requests = %d: 426 is never retried", ingest.count())
	}
	found := false
	ents, _ := os.ReadDir(qdir)
	for _, ent := range ents {
		if strings.HasSuffix(ent.Name(), ".manifest.json") {
			raw, err := os.ReadFile(filepath.Join(qdir, ent.Name()))
			if err != nil {
				t.Fatal(err)
			}
			var man manifest
			if err := json.Unmarshal(raw, &man); err != nil {
				t.Fatal(err)
			}
			if man.Status == http.StatusUpgradeRequired && man.ErrCode == "M1E-2007" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("426 must quarantine-and-report the offending batch")
	}
	assertDrained(t, sp) // the one refused batch is acked out of the upload path
}

// ---------------------------------------------------------------------------
// Checkpoint seal seam (07's checkpoint model)
// ---------------------------------------------------------------------------

type sealCall struct {
	leaves [][]byte
}

// TestCheckpointSealsExactlyTheAckedBatch binds the seal to the ONE landing
// that licenses it. A quarantine ack also advances the cursor, and sealing
// there would mint chain evidence for events controld refused.
func TestCheckpointSealsExactlyTheAckedBatch(t *testing.T) {
	sp := openSpool(t)
	session, _ := uuid.NewV7()
	e1 := makeEvent(t, session, 1, spool.ClassBilling)
	e2 := makeEvent(t, session, 2, spool.ClassDiagnostic)
	appendAll(t, sp, e1, e2)

	var calls []sealCall
	ingest := &fakeIngest{respond: func(n int, w http.ResponseWriter, bid string) {
		writeAck(w, http.StatusOK, bid, nil)
	}}
	u, _, _ := newTestUplink(t, sp, ingest, func(c *Config) {
		c.Checkpoint = func(_ context.Context, leaves [][]byte) {
			calls = append(calls, sealCall{leaves: leaves})
		}
	})

	if res := sendOnce(t, u); res != cycleAdvanced {
		t.Fatal("verified 2xx must advance")
	}
	if len(calls) != 1 {
		t.Fatalf("seals = %d after one acked batch, want 1", len(calls))
	}
	// Leaves are the batch's event_ids in spool order — the order controld's
	// EffectsFromBatch would rebuild the tree in.
	got := calls[0].leaves
	if len(got) != 2 || !bytes.Equal(got[0], e1.id[:]) || !bytes.Equal(got[1], e2.id[:]) {
		t.Fatalf("leaves = %x, want the batch's event_ids in spool order", got)
	}

	// A refused batch is acked out of the upload path but never landed: no seal.
	e3 := makeEvent(t, session, 3, spool.ClassBilling)
	appendAll(t, sp, e3)
	ingest.respond = func(n int, w http.ResponseWriter, bid string) {
		writeErr(w, http.StatusBadRequest, "M1E-2001", nil)
	}
	if res := sendOnce(t, u); res != cycleAdvanced {
		t.Fatal("quarantine must advance the cursor")
	}
	if len(calls) != 1 {
		t.Fatalf("seals = %d after a quarantined batch, want 1 — a refused batch is not chain evidence", len(calls))
	}
}

// TestFlushSealsItsAck: the shutdown drain lands billable events through its own
// ack path (07 §6). Unsealed, the last batch of every session would upload with
// no chain evidence and nothing would ever go back for it.
func TestFlushSealsItsAck(t *testing.T) {
	sp := openSpool(t)
	session, _ := uuid.NewV7()
	e1 := makeEvent(t, session, 1, spool.ClassBilling)
	appendAll(t, sp, e1)

	var calls []sealCall
	ingest := &fakeIngest{respond: func(n int, w http.ResponseWriter, bid string) {
		writeAck(w, http.StatusOK, bid, nil)
	}}
	u, _, _ := newTestUplink(t, sp, ingest, func(c *Config) {
		c.Checkpoint = func(_ context.Context, leaves [][]byte) {
			calls = append(calls, sealCall{leaves: leaves})
		}
	})

	u.Flush(context.Background())
	assertDrained(t, sp)
	if len(calls) != 1 || len(calls[0].leaves) != 1 || !bytes.Equal(calls[0].leaves[0], e1.id[:]) {
		t.Fatalf("Flush sealed %v, want one checkpoint over the flushed batch", calls)
	}
}

// makeCheckpoint builds one encoded ReceiptCheckpoint event as the sealer
// admits it: device-scoped (no session), billing class (07 §6).
func makeCheckpoint(t *testing.T, seq uint64) testEvent {
	t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	ev := &m1pv1.Event{EventId: id[:], Body: &m1pv1.Event_ReceiptCheckpoint{
		ReceiptCheckpoint: &m1pv1.ReceiptCheckpoint{CheckpointSeq: seq, LeafCount: 1},
	}}
	payload, err := proto.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	return testEvent{id: id, payload: payload, class: spool.ClassBilling}
}

// TestCheckpointRecordsAreNeverLeaves pins the leaf rule to the one controld
// enforces (ingest/sidefx/sidefx.go Apply: a checkpoint "is deliberately not
// a leaf of any tree"): the seal over a batch covers its OTHER events only.
// [cp, X, Y] → {X, Y}; [cp] → nothing; [cp, cp2] → nothing. Counting the
// checkpoint claimed one leaf more than the server held pending, was refused,
// and the orphaned leaf turned every later honest seal into merkle_mismatch.
func TestCheckpointRecordsAreNeverLeaves(t *testing.T) {
	sp := openSpool(t)
	session, _ := uuid.NewV7()
	var calls []sealCall
	ingest := &fakeIngest{respond: func(n int, w http.ResponseWriter, bid string) {
		writeAck(w, http.StatusOK, bid, nil)
	}}
	u, _, _ := newTestUplink(t, sp, ingest, func(c *Config) {
		c.Checkpoint = func(_ context.Context, leaves [][]byte) {
			calls = append(calls, sealCall{leaves: leaves})
		}
	})
	cp, x, y := makeCheckpoint(t, 1), makeEvent(t, session, 1, spool.ClassBilling), makeEvent(t, session, 2, spool.ClassDiagnostic)
	for i, batch := range [][]testEvent{
		{cp, x, y},
		{makeCheckpoint(t, 2)},
		{makeCheckpoint(t, 3), makeCheckpoint(t, 4)},
	} {
		appendAll(t, sp, batch...)
		if res := sendOnce(t, u); res != cycleAdvanced {
			t.Fatalf("batch %d: verified 2xx must advance", i)
		}
	}
	if len(calls) != 3 {
		t.Fatalf("seals = %d after three acked batches, want 3 (one per ack; the sealer decides over the leaves)", len(calls))
	}
	if got := calls[0].leaves; len(got) != 2 || !bytes.Equal(got[0], x.id[:]) || !bytes.Equal(got[1], y.id[:]) {
		t.Fatalf("[cp, X, Y] leaves = %x, want {X, Y} in spool order", got)
	}
	if got := calls[1].leaves; len(got) != 0 {
		t.Fatalf("[cp] leaves = %x, want none", got)
	}
	if got := calls[2].leaves; len(got) != 0 {
		t.Fatalf("[cp, cp2] leaves = %x, want none", got)
	}
}

// TestComposeStaysUnderTheRateLimitCapacities: controld debits a batch all-or-nothing against 05 §2.4's per-window capacities, so a batch no fresh bucket can afford is a 429 on every try (the founder's WSL spool, 2026-09-19). A backlog of 2,500 diagnostics composes as 2,000 then 500.
func TestComposeStaysUnderTheRateLimitCapacities(t *testing.T) {
	sp := openSpool(t)
	session, _ := uuid.NewV7()
	evs := make([]testEvent, 0, 2500)
	for i := range 2500 {
		evs = append(evs, makeEvent(t, session, uint64(i+1), spool.ClassDiagnostic))
	}
	appendAll(t, sp, evs...)
	u, _, _ := newTestUplink(t, sp, &fakeIngest{respond: func(_ int, w http.ResponseWriter, bid string) { writeAck(w, http.StatusOK, bid, nil) }}, nil)
	b, err := u.compose()
	if err != nil || b == nil {
		t.Fatalf("compose: %v %v", b, err)
	}
	if n := len(b.recs); n != categoryCap["diagnostic"] {
		t.Fatalf("first batch carries %d diagnostics, want the window capacity %d", n, categoryCap["diagnostic"])
	}
	if categoryOf(evs[0].payload) != "diagnostic" || categoryOf(makeEvent(t, session, 9999, spool.ClassBilling).payload) != "usage" {
		t.Fatal("categoryOf must read the body arm the server buckets by")
	}
}

// TestContributionTravelsAlone: controld refuses an OutcomeContribution batched with anything, dropped rows included (16 L8), so compose cuts before it and ships it as a batch of one.
func TestContributionTravelsAlone(t *testing.T) {
	sp := openSpool(t)
	session, _ := uuid.NewV7()
	id, _ := uuid.NewV7()
	payload, err := proto.Marshal(&m1pv1.Event{EventId: id[:], Seq: 2, SessionId: session[:], SessionEpoch: 1,
		Body: &m1pv1.Event_OutcomeContribution{OutcomeContribution: &m1pv1.OutcomeContribution{DiffRedacted: "d"}}})
	if err != nil {
		t.Fatal(err)
	}
	appendAll(t, sp, makeEvent(t, session, 1, spool.ClassDiagnostic), testEvent{id: id, payload: payload, class: spool.ClassDiagnostic}, makeEvent(t, session, 3, spool.ClassDiagnostic))
	u, _, _ := newTestUplink(t, sp, &fakeIngest{respond: func(_ int, w http.ResponseWriter, bid string) { writeAck(w, http.StatusOK, bid, nil) }}, nil)
	u.carry = []spool.Dropped{{Reason: 1, Class: spool.ClassDiagnostic, Quantity: 1}}
	var sizes []int
	for {
		b, err := u.compose()
		if err != nil {
			t.Fatal(err)
		}
		if b == nil {
			break
		}
		if isContribution(b.recs[0].Payload) && len(b.dropped) != 0 {
			t.Fatal("dropped rows rode the contribution batch")
		}
		sizes = append(sizes, len(b.recs))
		if err := sp.Ack(b.end); err != nil {
			t.Fatal(err)
		}
	}
	if len(sizes) != 3 || sizes[0] != 1 || sizes[1] != 1 || sizes[2] != 1 {
		t.Fatalf("batches %v, want [1 1 1]: the contribution alone between its neighbours", sizes)
	}
}
