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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
