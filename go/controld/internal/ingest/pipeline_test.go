package ingest

// Stage-boundary tests for the 05 §2.1 pipeline, against fakes for S3/CH/PG
// (13 §3.5 house style: stdlib testing, table tests against interfaces).
// Every trust-boundary behavior asserted here is a wire contract from 08 §2.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/klauspost/compress/zstd"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/chproj"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/s3land"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/sidefx"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

// ---------------------------------------------------------------------------
// fakes
// ---------------------------------------------------------------------------

type fakeObject struct {
	body   []byte
	device uuid.UUID
}

type fakeStore struct {
	mu      sync.Mutex
	objects map[string]fakeObject
	landErr error
	lands   int
}

func newFakeStore() *fakeStore { return &fakeStore{objects: map[string]fakeObject{}} }

func (f *fakeStore) Land(_ context.Context, key string, body []byte, _, device uuid.UUID) (s3land.Outcome, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lands++
	if f.landErr != nil {
		return 0, f.landErr
	}
	if existing, ok := f.objects[key]; ok {
		if bytes.Equal(existing.body, body) {
			return s3land.Duplicate, nil
		}
		return s3land.Divergent, nil
	}
	f.objects[key] = fakeObject{body: append([]byte(nil), body...), device: device}
	return s3land.Landed, nil
}

// Probe mirrors the AWS client's read-only duplicate check (no write, no
// landing count).
func (f *fakeStore) Probe(_ context.Context, key string, body []byte) (s3land.Outcome, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.landErr != nil {
		return 0, f.landErr
	}
	existing, ok := f.objects[key]
	if !ok {
		return s3land.NotLanded, nil
	}
	if bytes.Equal(existing.body, body) {
		return s3land.Duplicate, nil
	}
	return s3land.Divergent, nil
}

// seed plants an object as if a previous request had landed it — the flip
// tests use it to stand in for "landed under an older scanner ruleset".
func (f *fakeStore) seed(key string, body []byte, device uuid.UUID) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objects[key] = fakeObject{body: append([]byte(nil), body...), device: device}
}

func (f *fakeStore) Ready(context.Context) error { return nil }

func (f *fakeStore) List(_ context.Context, prefix string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var keys []string
	for k := range f.objects {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	return keys, nil
}

func (f *fakeStore) Get(_ context.Context, key string) ([]byte, uuid.UUID, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	o := f.objects[key]
	return o.body, o.device, nil
}

func (f *fakeStore) keys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var keys []string
	for k := range f.objects {
		keys = append(keys, k)
	}
	return keys
}

type fakeInserter struct {
	mu   sync.Mutex
	rows [][]any
}

func (f *fakeInserter) InsertRows(_ context.Context, _ string, _ []string, rows [][]any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rows = append(f.rows, rows...)
	return nil
}

func (f *fakeInserter) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.rows)
}

type fakeDB struct {
	mu    sync.Mutex
	calls int
}

func (f *fakeDB) WithTenant(context.Context, querychoke.TenantID, func(pgx.Tx) error) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return nil
}

type fakeSecurity struct {
	mu    sync.Mutex
	calls []string
}

func (f *fakeSecurity) RecordIdentityDisagreement(_, _, _ uuid.UUID, detail string, _ time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, detail)
}

func (f *fakeSecurity) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

type fakeReady struct{}

func (fakeReady) Ready(context.Context) error { return nil }

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

var testKey = []byte("c4-test-hmac-key")

type harness struct {
	mux      *http.ServeMux
	store    *fakeStore
	ins      *fakeInserter
	db       *fakeDB
	sec      *fakeSecurity
	proj     *chproj.Projector
	sfx      *sidefx.Sidefx
	tenant   uuid.UUID
	device   uuid.UUID
	token    string
	verifier *auth.HMACVerifier
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{
		mux:    http.NewServeMux(),
		store:  newFakeStore(),
		ins:    &fakeInserter{},
		db:     &fakeDB{},
		sec:    &fakeSecurity{},
		tenant: uuid.New(),
		device: uuid.New(),
	}
	h.proj = chproj.New(h.ins, 1, 100)
	h.sfx = sidefx.New(h.db, nil, nil, 1, 100)
	h.verifier = auth.NewHMACVerifier(testKey, auth.StaticRevocations{})
	h.token = auth.Mint(testKey, h.tenant, h.device, time.Hour)
	m := New(Deps{
		Verifier: h.verifier,
		ObsCfg:   obs.Config{ServiceName: "controld-test"},
		PG:       fakeReady{},
		Store:    h.store,
		Proj:     h.proj,
		Sidefx:   h.sfx,
		Security: h.sec,
		PoolSize: 4,
	})
	m.RegisterRoutes(h.mux)
	t.Cleanup(func() { h.proj.Close(); h.sfx.Close() })
	return h
}

// drain proves "no duplicate side effects" claims against the ASYNC pools:
// closing flushes both queues, so post-drain counts are final.
func (h *harness) drain() {
	h.proj.Close()
	h.sfx.Close()
}

func mustV7(t *testing.T) uuid.UUID {
	t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func usageEvent(t *testing.T, session uuid.UUID, seq uint64) *m1pv1.Event {
	t.Helper()
	eventID := mustV7(t)
	return &m1pv1.Event{
		EventId:    eventID[:],
		Seq:        seq,
		SessionId:  session[:],
		OccurredAt: timestamppb.New(time.Date(2026, 8, 29, 10, 0, 0, 0, time.UTC)),
		Body: &m1pv1.Event_Usage{Usage: &m1pv1.Usage{
			IdemKey:      bytes.Repeat([]byte{0xAB}, 32),
			MessageId:    "msg_test",
			RequestId:    "req_test",
			Model:        "claude-test-1",
			InputTokens:  100,
			OutputTokens: 50,
		}},
	}
}

func testBatch(t *testing.T, events ...*m1pv1.Event) (*m1pv1.Batch, uuid.UUID) {
	t.Helper()
	batchID := mustV7(t)
	session := mustV7(t)
	if len(events) == 0 {
		events = []*m1pv1.Event{usageEvent(t, session, 1)}
	}
	return &m1pv1.Batch{
		BatchId:   batchID[:],
		SessionId: session[:],
		Sdk:       &m1pv1.SdkInfo{Name: "mark1d", Version: "0.0.1-test", Agent: "claudecode"},
		SentAt:    timestamppb.New(time.Date(2026, 8, 29, 10, 0, 1, 0, time.UTC)),
		Events:    events,
	}, batchID
}

func compress(t *testing.T, raw []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zw.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func encodeBatch(t *testing.T, b *m1pv1.Batch) []byte {
	t.Helper()
	raw, err := proto.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return compress(t, raw)
}

func (h *harness) post(t *testing.T, batchID uuid.UUID, body []byte, mutate func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/m1p/v1/ingest", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+h.token)
	req.Header.Set("Content-Type", "application/x-m1p-protobuf")
	req.Header.Set("Content-Encoding", "zstd")
	req.Header.Set("M1P-Schema", "m1p.v1")
	req.Header.Set("M1P-Batch-Id", batchID.String())
	req.Header.Set("X-Mark1-Edge-Version", "0.0.1-test")
	req.ContentLength = int64(len(body))
	if mutate != nil {
		mutate(req)
	}
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)
	return rec
}

func errCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response not error JSON: %s", rec.Body.String())
	}
	return body.Error.Code
}

// ---------------------------------------------------------------------------
// happy path + ack ordering
// ---------------------------------------------------------------------------

func TestCleanBatchLandsAcksProjects(t *testing.T) {
	h := newHarness(t)
	b, id := testBatch(t)
	rec := h.post(t, id, encodeBatch(t, b), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var ack struct {
		BatchID  string `json:"batch_id"`
		Accepted int    `json:"accepted"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &ack); err != nil {
		t.Fatal(err)
	}
	if ack.BatchID != id.String() || ack.Accepted != 1 {
		t.Fatalf("bad ack: %+v", ack)
	}
	keys := h.store.keys()
	if len(keys) != 1 || !strings.Contains(keys[0], "/ingest/v1/") {
		t.Fatalf("expected one ingest-prefix landing, got %v", keys)
	}
	// The landed object is byte-identical to the request body (05 §2.1 stage 8).
	body, device, _ := h.store.Get(context.Background(), keys[0])
	if !bytes.Equal(body, encodeBatch(t, b)) {
		t.Fatal("landed object is not byte-identical to the received body")
	}
	if device != h.device {
		t.Fatalf("device stamp: want %s got %s", h.device, device)
	}
	h.drain()
	if h.ins.count() != 1 {
		t.Fatalf("want 1 projected row, got %d", h.ins.count())
	}
	if h.db.calls != 1 {
		t.Fatalf("want 1 sidefx write, got %d", h.db.calls)
	}
}

// The ack-ordering guarantee (05 §2.2): a failing S3 PUT MUST fail the
// request — the ack cannot precede the landing because the response is only
// computed from a successful Land outcome, and this test proves the failure
// path yields 503 + zero side effects, never a 2xx.
func TestS3FailureMeansNoAckNoSideEffects(t *testing.T) {
	h := newHarness(t)
	h.store.landErr = context.DeadlineExceeded
	b, id := testBatch(t)
	rec := h.post(t, id, encodeBatch(t, b), nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d", rec.Code)
	}
	if code := errCode(t, rec); code != "M1E-9500" {
		t.Fatalf("want M1E-9500, got %s", code)
	}
	h.drain()
	if h.ins.count() != 0 || h.db.calls != 0 {
		t.Fatalf("side effects ran without a landing: proj=%d sidefx=%d", h.ins.count(), h.db.calls)
	}
}

// Re-POST of an acked batch (08 §2.3): 200, cheap, all duplicates, and the
// side effects run exactly once (for the first landing).
func TestReplayedBatchAcks200WithoutDuplicateSideEffects(t *testing.T) {
	h := newHarness(t)
	b, id := testBatch(t)
	body := encodeBatch(t, b)
	if rec := h.post(t, id, body, nil); rec.Code != http.StatusOK {
		t.Fatalf("first post: want 200, got %d", rec.Code)
	}
	rec := h.post(t, id, body, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("replay: want 200, got %d", rec.Code)
	}
	var ack struct {
		Accepted   int `json:"accepted"`
		Duplicates int `json:"duplicates"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &ack); err != nil {
		t.Fatal(err)
	}
	if ack.Accepted != 0 || ack.Duplicates != 1 {
		t.Fatalf("replay ack: %+v", ack)
	}
	h.drain()
	if h.ins.count() != 1 {
		t.Fatalf("replay projected again: %d rows", h.ins.count())
	}
	if h.db.calls != 1 {
		t.Fatalf("replay re-ran sidefx: %d", h.db.calls)
	}
	if len(h.store.keys()) != 1 {
		t.Fatalf("replay landed a second object: %v", h.store.keys())
	}
}

func TestBatchIDReuseWithDifferentBytesIs409(t *testing.T) {
	h := newHarness(t)
	b, id := testBatch(t)
	if rec := h.post(t, id, encodeBatch(t, b), nil); rec.Code != http.StatusOK {
		t.Fatal("setup post failed")
	}
	b2, _ := testBatch(t) // different events
	b2.BatchId = id[:]
	rec := h.post(t, id, encodeBatch(t, b2), nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("want 409, got %d", rec.Code)
	}
	if code := errCode(t, rec); code != "M1E-2003" {
		t.Fatalf("want M1E-2003, got %s", code)
	}
}

// ---------------------------------------------------------------------------
// stage 2/3: identity
// ---------------------------------------------------------------------------

func TestIdentityDisagreementRejected403WithSecurityEvent(t *testing.T) {
	otherTenant := uuid.New()
	otherDevice := uuid.New()
	cases := []struct {
		name   string
		mutate func(b *m1pv1.Batch)
	}{
		{"advisory_tenant_mismatch", func(b *m1pv1.Batch) { b.AdvisoryTenantId = otherTenant[:] }},
		{"advisory_device_mismatch", func(b *m1pv1.Batch) { b.AdvisoryDeviceId = otherDevice[:] }},
		{"band_tenant_set", func(b *m1pv1.Batch) { b.Events[0].TenantId = otherTenant[:] }},
		{"band_device_set", func(b *m1pv1.Batch) { b.Events[0].DeviceId = otherDevice[:] }},
		{"band_received_at_set", func(b *m1pv1.Batch) { b.Events[0].ReceivedAt = timestamppb.Now() }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			b, id := testBatch(t)
			tc.mutate(b)
			rec := h.post(t, id, encodeBatch(t, b), nil)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("want 403, got %d: %s", rec.Code, rec.Body.String())
			}
			if code := errCode(t, rec); code != "M1E-8003" {
				t.Fatalf("want M1E-8003, got %s", code)
			}
			if h.sec.count() != 1 {
				t.Fatalf("security event not recorded: %d", h.sec.count())
			}
			if len(h.store.keys()) != 0 {
				t.Fatal("rejected batch must not land")
			}
		})
	}
}

// A band tenant_id EQUAL to the token's still rejects: the band must be unset
// on the client wire (envelope.proto; decision D-K).
func TestMatchingBandIdentityStillRejected(t *testing.T) {
	h := newHarness(t)
	b, id := testBatch(t)
	b.Events[0].TenantId = h.tenant[:]
	rec := h.post(t, id, encodeBatch(t, b), nil)
	if rec.Code != http.StatusForbidden || errCode(t, rec) != "M1E-8003" {
		t.Fatalf("want 403 M1E-8003, got %d %s", rec.Code, rec.Body.String())
	}
}

// Matching ADVISORY fields are the sanctioned cross-check: they must pass.
func TestMatchingAdvisoryFieldsAccepted(t *testing.T) {
	h := newHarness(t)
	b, id := testBatch(t)
	b.AdvisoryTenantId = h.tenant[:]
	b.AdvisoryDeviceId = h.device[:]
	rec := h.post(t, id, encodeBatch(t, b), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRevokedDeviceRejected403(t *testing.T) {
	h := newHarness(t)
	// Re-register the module with a verifier that knows the device is revoked.
	mux := http.NewServeMux()
	m := New(Deps{
		Verifier: auth.NewHMACVerifier(testKey, auth.StaticRevocations{h.device: true}),
		ObsCfg:   obs.Config{ServiceName: "controld-test"},
		PG:       fakeReady{}, Store: h.store, Proj: h.proj, Sidefx: h.sfx, Security: h.sec,
	})
	m.RegisterRoutes(mux)
	h.mux = mux
	b, id := testBatch(t)
	rec := h.post(t, id, encodeBatch(t, b), nil)
	if rec.Code != http.StatusForbidden || errCode(t, rec) != "M1E-1003" {
		t.Fatalf("want 403 M1E-1003, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestBadTokenRejected401(t *testing.T) {
	h := newHarness(t)
	b, id := testBatch(t)
	rec := h.post(t, id, encodeBatch(t, b), func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer not-a-token")
	})
	if rec.Code != http.StatusUnauthorized || errCode(t, rec) != "M1E-1002" {
		t.Fatalf("want 401 M1E-1002, got %d %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// stage 1: admission
// ---------------------------------------------------------------------------

func TestAdmissionRefusals(t *testing.T) {
	h := newHarness(t)
	b, id := testBatch(t)
	body := encodeBatch(t, b)
	cases := []struct {
		name       string
		mutate     func(*http.Request)
		wantStatus int
		wantCode   string
	}{
		{"wrong_content_type", func(r *http.Request) { r.Header.Set("Content-Type", "application/json") },
			http.StatusUnsupportedMediaType, "M1E-2005"},
		{"wrong_encoding", func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") },
			http.StatusUnsupportedMediaType, "M1E-2005"},
		{"schema_out_of_window", func(r *http.Request) { r.Header.Set("M1P-Schema", "m1p.v9") },
			http.StatusUpgradeRequired, "M1E-2007"},
		{"missing_batch_id", func(r *http.Request) { r.Header.Del("M1P-Batch-Id") },
			http.StatusBadRequest, "M1E-2001"},
		{"non_v7_batch_id", func(r *http.Request) { r.Header.Set("M1P-Batch-Id", uuid.New().String()) },
			http.StatusBadRequest, "M1E-2001"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := h.post(t, id, body, tc.mutate)
			if rec.Code != tc.wantStatus {
				t.Fatalf("want %d, got %d: %s", tc.wantStatus, rec.Code, rec.Body.String())
			}
			if code := errCode(t, rec); code != tc.wantCode {
				t.Fatalf("want %s, got %s", tc.wantCode, code)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// stage 4: zstd bounds
// ---------------------------------------------------------------------------

// A tiny body expanding past its 100:1 ratio is a bomb: 400 M1E-2001, refused
// mid-stream (05 §2.1 stage 4).
func TestZstdBombRefused(t *testing.T) {
	h := newHarness(t)
	bomb := compress(t, make([]byte, 33<<20)) // 33 MiB of zeros ⇒ tiny compressed
	if len(bomb) > 1<<20 {
		t.Fatalf("test setup: bomb should compress small, got %d", len(bomb))
	}
	id := mustV7(t)
	rec := h.post(t, id, bomb, nil)
	if rec.Code != http.StatusBadRequest || errCode(t, rec) != "M1E-2001" {
		t.Fatalf("want 400 M1E-2001, got %d %s", rec.Code, rec.Body.String())
	}
	if len(h.store.keys()) != 0 {
		t.Fatal("bomb landed")
	}
}

// A legitimately large batch (incompressible enough to pass the ratio bound)
// over 32 MiB decoded is 413 M1E-2004 (08 §2.4).
func TestDecodedSizeCapIs413(t *testing.T) {
	h := newHarness(t)
	// 400 KiB of random (defeats the ratio bound: 100 × 400 KiB > 32 MiB)
	// followed by 40 MiB of zeros to blow the size cap.
	payload := make([]byte, 400<<10, (400<<10)+(40<<20))
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	payload = append(payload, make([]byte, 40<<20)...)
	body := compress(t, payload)
	if len(body) > maxCompressed {
		t.Fatalf("test setup: compressed %d exceeds transport cap", len(body))
	}
	id := mustV7(t)
	rec := h.post(t, id, body, nil)
	if rec.Code != http.StatusRequestEntityTooLarge || errCode(t, rec) != "M1E-2004" {
		t.Fatalf("want 413 M1E-2004, got %d %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// stage 6: invariants
// ---------------------------------------------------------------------------

func TestUsageWithoutIdemKeyIs422NamingTheEvent(t *testing.T) {
	h := newHarness(t)
	b, id := testBatch(t)
	b.Events[0].GetUsage().IdemKey = nil // the ~2.5× overcount defense removed
	rec := h.post(t, id, encodeBatch(t, b), nil)
	if rec.Code != http.StatusUnprocessableEntity || errCode(t, rec) != "M1E-2006" {
		t.Fatalf("want 422 M1E-2006, got %d %s", rec.Code, rec.Body.String())
	}
	evID := uuid.Must(uuid.FromBytes(b.Events[0].EventId)).String()
	if !strings.Contains(rec.Body.String(), evID) {
		t.Fatalf("422 must name the offending event_id %s: %s", evID, rec.Body.String())
	}
	if len(h.store.keys()) != 0 {
		t.Fatal("invariant-violating batch landed (nothing lands on 422, 05 §2.2)")
	}
}

func TestBatchIDMismatchIs422(t *testing.T) {
	h := newHarness(t)
	b, _ := testBatch(t)
	otherID := mustV7(t) // header disagrees with Batch.batch_id
	rec := h.post(t, otherID, encodeBatch(t, b), nil)
	if rec.Code != http.StatusUnprocessableEntity || errCode(t, rec) != "M1E-2006" {
		t.Fatalf("want 422 M1E-2006, got %d %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// stage 7: scanner → quarantine
// ---------------------------------------------------------------------------

func TestScannerHitQuarantinesWholeBatchNeverStrips(t *testing.T) {
	h := newHarness(t)
	session := mustV7(t)
	leaky := usageEvent(t, session, 2)
	leaky.GetUsage().ServiceTier = "AKIAABCDEFGHIJKLMNOP" // aws_access_key_id class
	clean := usageEvent(t, session, 1)
	b, id := testBatch(t, clean, leaky)
	body := encodeBatch(t, b)

	rec := h.post(t, id, body, nil)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("want 202, got %d: %s", rec.Code, rec.Body.String())
	}
	var ack struct {
		Accepted    int      `json:"accepted"`
		Quarantined []string `json:"quarantined"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &ack); err != nil {
		t.Fatal(err)
	}
	leakyID := uuid.Must(uuid.FromBytes(leaky.EventId)).String()
	if len(ack.Quarantined) != 1 || ack.Quarantined[0] != leakyID {
		t.Fatalf("quarantined[] must name the flagged event: %+v", ack)
	}
	if ack.Accepted != 0 {
		t.Fatalf("nothing from a flagged batch is accepted for projection: %+v", ack)
	}

	keys := h.store.keys()
	if len(keys) != 1 || !strings.Contains(keys[0], "/quarantine/v1/") {
		t.Fatalf("flagged batch must land under the quarantine prefix: %v", keys)
	}
	// Never silently strip: the quarantine object is byte-identical.
	landed, _, _ := h.store.Get(context.Background(), keys[0])
	if !bytes.Equal(landed, body) {
		t.Fatal("quarantined object was modified — fail-closed means hold, not strip (05 §2.3)")
	}
	h.drain()
	if h.ins.count() != 0 || h.db.calls != 0 {
		t.Fatalf("quarantined batch was projected: proj=%d sidefx=%d", h.ins.count(), h.db.calls)
	}
}

// Re-POST of a quarantined batch (ack lost, same ruleset): the quarantine
// landing is detected as the duplicate it is, and the original 202 shape is
// reproduced — never a second object, never side effects.
func TestQuarantinedRePostReacks202WithoutSecondLanding(t *testing.T) {
	h := newHarness(t)
	session := mustV7(t)
	leaky := usageEvent(t, session, 1)
	leaky.GetUsage().ServiceTier = "AKIAABCDEFGHIJKLMNOP"
	b, id := testBatch(t, leaky)
	body := encodeBatch(t, b)
	if rec := h.post(t, id, body, nil); rec.Code != http.StatusAccepted {
		t.Fatal("setup post should quarantine")
	}
	rec := h.post(t, id, body, nil)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("re-POST of a quarantined batch: want 202, got %d: %s", rec.Code, rec.Body.String())
	}
	leakyID := uuid.Must(uuid.FromBytes(leaky.EventId)).String()
	if !strings.Contains(rec.Body.String(), leakyID) {
		t.Fatalf("replayed 202 must reproduce quarantined[]: %s", rec.Body.String())
	}
	if len(h.store.keys()) != 1 {
		t.Fatalf("re-POST landed a second object: %v", h.store.keys())
	}
	h.drain()
	if h.ins.count() != 0 || h.db.calls != 0 {
		t.Fatalf("quarantined re-POST ran side effects: proj=%d sidefx=%d", h.ins.count(), h.db.calls)
	}
}

// A scanner-ruleset change between attempts (clean at the first POST, flagged
// at the re-POST of the SAME bytes) must not double-land the batch: it is
// already in the replay log under the ingest prefix, so the retry re-acks as
// duplicates (08 §2.3 — the re-POST gets the original response class).
func TestFlaggedRePostOfCleanLandedBatchIsDuplicateNotQuarantine(t *testing.T) {
	h := newHarness(t)
	session := mustV7(t)
	leaky := usageEvent(t, session, 1)
	leaky.GetUsage().ServiceTier = "AKIAABCDEFGHIJKLMNOP"
	b, id := testBatch(t, leaky)
	body := encodeBatch(t, b)
	// First attempt landed clean under an OLDER ruleset; its ack was lost.
	h.store.seed(s3land.IngestKey(h.tenant, id), body, h.device)

	rec := h.post(t, id, body, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200 duplicate re-ack, got %d: %s", rec.Code, rec.Body.String())
	}
	var ack struct {
		Accepted   int `json:"accepted"`
		Duplicates int `json:"duplicates"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &ack); err != nil {
		t.Fatal(err)
	}
	if ack.Accepted != 0 || ack.Duplicates != 1 {
		t.Fatalf("flip re-ack: %+v", ack)
	}
	keys := h.store.keys()
	if len(keys) != 1 || !strings.Contains(keys[0], "/ingest/v1/") {
		t.Fatalf("flip re-POST must not land a quarantine twin: %v", keys)
	}
	h.drain()
	if h.ins.count() != 0 || h.db.calls != 0 {
		t.Fatalf("flip re-POST ran side effects: proj=%d sidefx=%d", h.ins.count(), h.db.calls)
	}
}

// Same flip, but the re-POST bytes DIFFER from the ingest-landed object: that
// is batch_id reuse over different content — spool corruption, 409 M1E-2003
// (08 §2.4), regardless of which prefix the retry would have landed under.
func TestFlaggedRePostDivergentFromIngestLandingIs409(t *testing.T) {
	h := newHarness(t)
	session := mustV7(t)
	leaky := usageEvent(t, session, 1)
	leaky.GetUsage().ServiceTier = "AKIAABCDEFGHIJKLMNOP"
	b, id := testBatch(t, leaky)
	h.store.seed(s3land.IngestKey(h.tenant, id), []byte("older clean bytes"), h.device)

	rec := h.post(t, id, encodeBatch(t, b), nil)
	if rec.Code != http.StatusConflict || errCode(t, rec) != "M1E-2003" {
		t.Fatalf("want 409 M1E-2003, got %d %s", rec.Code, rec.Body.String())
	}
	if len(h.store.keys()) != 1 {
		t.Fatalf("divergent re-POST landed anyway: %v", h.store.keys())
	}
}

// ---------------------------------------------------------------------------
// §2.4 backpressure
// ---------------------------------------------------------------------------

func TestRateLimit429CarriesRetryAfterAndCategories(t *testing.T) {
	h := newHarness(t)
	session := mustV7(t)
	mkBig := func() (*m1pv1.Batch, uuid.UUID) {
		events := make([]*m1pv1.Event, 6000)
		for i := range events {
			events[i] = usageEvent(t, session, uint64(i+1))
		}
		return testBatch(t, events...)
	}
	b1, id1 := mkBig()
	if rec := h.post(t, id1, encodeBatch(t, b1), nil); rec.Code != http.StatusOK {
		t.Fatalf("first 6000-usage batch should pass: %d", rec.Code)
	}
	b2, id2 := mkBig()
	rec := h.post(t, id2, encodeBatch(t, b2), nil)
	if rec.Code != http.StatusTooManyRequests || errCode(t, rec) != "M1E-9001" {
		t.Fatalf("want 429 M1E-9001, got %d %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("429 must carry Retry-After (08 §2.4)")
	}
	if !strings.Contains(rec.Header().Get("M1P-Rate-Limits"), "usage:10000:60") {
		t.Fatalf("429 must carry M1P-Rate-Limits: %q", rec.Header().Get("M1P-Rate-Limits"))
	}
	if len(h.store.keys()) != 1 {
		t.Fatal("rate-limited batch must not land")
	}
}

// ---------------------------------------------------------------------------
// §2.5 replay
// ---------------------------------------------------------------------------

func TestReplayReprojectsIdempotently(t *testing.T) {
	h := newHarness(t)
	b, id := testBatch(t)
	if rec := h.post(t, id, encodeBatch(t, b), nil); rec.Code != http.StatusOK {
		t.Fatal("setup post failed")
	}
	h.drain() // live projection done: 1 row

	claims := auth.Claims{TenantID: h.tenant, DeviceID: h.device}
	tenant, err := querychoke.FromClaims(claims)
	if err != nil {
		t.Fatal(err)
	}
	// The fake store keys carry the batch_id's uuidv7 date (minted just
	// above, so today); replay across a window that includes it.
	now := time.Now().UTC()
	n, err := Replay(context.Background(), h.store, h.ins, nil, tenant,
		now.AddDate(0, 0, -1), now.AddDate(0, 0, 1))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("want 1 replayed batch, got %d", n)
	}
	// Replay re-inserts the SAME event_id rows (dedup happens in CH's
	// ReplacingMergeTree); assert the derived identity matches exactly.
	if h.ins.count() != 2 {
		t.Fatalf("want 2 inserted rows (live + replay), got %d", h.ins.count())
	}
	liveID, replayID := h.ins.rows[0][3], h.ins.rows[1][3]
	if liveID != replayID {
		t.Fatalf("replayed row derived a different event_id: %v vs %v", liveID, replayID)
	}
	liveDevice, replayDevice := h.ins.rows[0][6], h.ins.rows[1][6]
	if liveDevice != replayDevice {
		t.Fatalf("replay lost the device stamp: %v vs %v", liveDevice, replayDevice)
	}
}
