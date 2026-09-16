package ingest

// Stage-boundary tests for the 05 §2.1 pipeline, against fakes for S3/CH/PG
// (13 §3.5 house style: stdlib testing, table tests against interfaces).
// Every trust-boundary behavior asserted here is a wire contract from 08 §2.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
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
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/registry"
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

func (f *fakeStore) Delete(_ context.Context, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.objects, key)
	return nil
}

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
	mu          sync.Mutex
	calls       []string
	quarantines []string
}

func (f *fakeSecurity) RecordIdentityDisagreement(_, _, _ uuid.UUID, detail string, _ time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, detail)
}

func (f *fakeSecurity) RecordQuarantine(_, _, _ uuid.UUID, classes []string, _ time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.quarantines = append(f.quarantines, strings.Join(classes, ","))
}

func (f *fakeSecurity) quarantineCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.quarantines)
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

const testServiceToken = "intel-service-token-test"

type harness struct {
	mux      *http.ServeMux
	store    *fakeStore
	ins      *fakeInserter
	db       *fakeDB // stage 11's seam (sidefx)
	tomb     *fakeDB // the quarantine tombstone seam (Deps.DB); separate so `db.calls == 0` still means "no stage 11"
	sec      *fakeSecurity
	proj     *chproj.Projector
	sfx      *sidefx.Sidefx
	tenant   uuid.UUID
	device   uuid.UUID
	token    string
	verifier *auth.HMACVerifier
}

func newHarness(t *testing.T) *harness { return newHarnessWithRegistry(t, nil) }

// newHarnessWithRegistry: reg nil ⇒ the compiled-in [m1p.v1] window (the
// module's own default); the FR-SPINE-023 tests inject windows and outages.
func newHarnessWithRegistry(t *testing.T, reg registry.Registry) *harness {
	return newHarnessFull(t, reg, nil)
}

// newHarnessFull additionally takes the FR-VERIFY-004 device-key lookup;
// nil ⇒ the module's own default (no lookup, non-empty signatures refuse).
func newHarnessFull(t *testing.T, reg registry.Registry, dk DeviceKeys) *harness {
	t.Helper()
	h := &harness{
		mux:    http.NewServeMux(),
		store:  newFakeStore(),
		ins:    &fakeInserter{},
		db:     &fakeDB{},
		tomb:   &fakeDB{},
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
		Registry: reg,
		PoolSize: 4,

		IntelServiceToken: testServiceToken,
		DeviceKeys:        dk,
		DB:                h.tomb,
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

// fakeDeviceKeys is the harness's FR-VERIFY-004 lookup: exactly one device's
// live key, mirroring what m1_device_keys would answer. A pointer so tests
// can set .device to the harness's randomly-generated one AFTER construction
// (New(Deps{DeviceKeys: dk}) only needs the interface value, not its fields
// filled in yet -- PublicKey isn't called until a request lands).
type fakeDeviceKeys struct {
	device uuid.UUID
	pub    ed25519.PublicKey
}

func (f *fakeDeviceKeys) PublicKey(_ context.Context, _ querychoke.TenantID, device uuid.UUID) (ed25519.PublicKey, bool, error) {
	if device != f.device {
		return nil, false, nil
	}
	return f.pub, true, nil
}

// signedAnchorVote builds a well-formed AnchorVote and signs verify.proto's
// canonical(anchor_id, vote, evidence, integrity) with priv -- the exact
// bytes Runner.signVote produces, reproduced independently so the test
// exercises the wire contract rather than any production helper. tamper, when
// non-nil, mutates the vote AFTER signing so the returned event's stale
// signature fails to verify.
func signedAnchorVote(t *testing.T, session uuid.UUID, seq uint64, priv ed25519.PrivateKey, tamper func(*m1pv1.AnchorVote)) *m1pv1.Event {
	t.Helper()
	eventID := mustV7(t)
	av := &m1pv1.AnchorVote{
		AnchorId: "ruff",
		Vote:     m1pv1.Verdict_VERDICT_VIOLATED,
		Evidence: &m1pv1.EvidenceRecord{
			Tool:           "ruff",
			DiagnosticCode: "E501",
			Category:       m1pv1.EvidenceCategory_EVIDENCE_CATEGORY_LINT,
			Counts:         &m1pv1.EvidenceCounts{Errors: 1, FilesAffected: 1},
		},
		Integrity: &m1pv1.AnchorIntegrity{
			ResolvedBinaryHashes: map[string][]byte{"ruff": bytes.Repeat([]byte{0xAA}, 32)},
			EnvScrubAttestation:  bytes.Repeat([]byte{0xBB}, 32),
			DiffClassification:   m1pv1.DiffClassification_DIFF_CLASSIFICATION_SRC_ONLY,
		},
	}
	if priv != nil {
		canon, err := proto.MarshalOptions{Deterministic: true}.Marshal(av)
		if err != nil {
			t.Fatal(err)
		}
		av.Signature = ed25519.Sign(priv, canon)
	}
	if tamper != nil {
		tamper(av)
	}
	return &m1pv1.Event{
		EventId:    eventID[:],
		Seq:        seq,
		SessionId:  session[:],
		OccurredAt: timestamppb.New(time.Date(2026, 8, 29, 10, 0, 0, 0, time.UTC)),
		Body:       &m1pv1.Event_AnchorVote{AnchorVote: av},
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
		{"schema_malformed_is_400_not_426", func(r *http.Request) { r.Header.Set("M1P-Schema", "m1p.v1; DROP") },
			http.StatusBadRequest, "M1E-2001"},
		{"schema_missing_is_400", func(r *http.Request) { r.Header.Del("M1P-Schema") },
			http.StatusBadRequest, "M1E-2001"},
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
// FR-VERIFY-004: per-vote signature verification (08 §9 ingest range)
// ---------------------------------------------------------------------------

func TestAnchorVoteSignedGoodAccepted(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dk := &fakeDeviceKeys{pub: pub}
	h := newHarnessFull(t, nil, dk)
	dk.device = h.device // the harness's randomly-generated device

	ev := signedAnchorVote(t, mustV7(t), 1, priv, nil)
	b, id := testBatch(t, ev)
	rec := h.post(t, id, encodeBatch(t, b), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200 for a correctly signed vote, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAnchorVoteTamperedSignatureRefusedM1E2010(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dk := &fakeDeviceKeys{pub: pub}
	h := newHarnessFull(t, nil, dk)
	dk.device = h.device

	// Content mutated AFTER signing: the stale signature must fail.
	ev := signedAnchorVote(t, mustV7(t), 1, priv, func(av *m1pv1.AnchorVote) {
		av.Evidence.Counts.Errors = 2
	})
	b, id := testBatch(t, ev)
	rec := h.post(t, id, encodeBatch(t, b), nil)
	if rec.Code != http.StatusUnprocessableEntity || errCode(t, rec) != "M1E-2010" {
		t.Fatalf("want 422 M1E-2010, got %d %s", rec.Code, rec.Body.String())
	}
	evID := uuid.Must(uuid.FromBytes(ev.EventId)).String()
	if body := rec.Body.String(); !strings.Contains(body, evID) || !strings.Contains(body, `"anchor_vote_signature"`) {
		t.Fatalf("422 must name event %s and kind anchor_vote_signature: %s", evID, body)
	}
	if len(h.store.keys()) != 0 {
		t.Fatal("tampered-signature batch must not land (05 §2.2)")
	}
}

func TestAnchorVoteUnknownKeyRefusedM1E2010(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// DeviceKeys knows a DIFFERENT device -- this device has no enrolled key.
	h := newHarnessFull(t, nil, &fakeDeviceKeys{device: uuid.New()})
	ev := signedAnchorVote(t, mustV7(t), 1, priv, nil)
	b, id := testBatch(t, ev)
	rec := h.post(t, id, encodeBatch(t, b), nil)
	if rec.Code != http.StatusUnprocessableEntity || errCode(t, rec) != "M1E-2010" {
		t.Fatalf("want 422 M1E-2010 for a signature with no resolvable key, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestAnchorVoteNilSignerDepsRefusesSignedVote(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t) // DeviceKeys nil: the safe default
	ev := signedAnchorVote(t, mustV7(t), 1, priv, nil)
	b, id := testBatch(t, ev)
	rec := h.post(t, id, encodeBatch(t, b), nil)
	if rec.Code != http.StatusUnprocessableEntity || errCode(t, rec) != "M1E-2010" {
		t.Fatalf("want 422 M1E-2010 with no DeviceKeys dependency wired, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestAnchorVoteEmptySignatureAdmittedAndMarkedUnsigned(t *testing.T) {
	h := newHarness(t)
	ev := signedAnchorVote(t, mustV7(t), 1, nil, nil) // priv nil ⇒ Signature stays empty
	b, id := testBatch(t, ev)
	rec := h.post(t, id, encodeBatch(t, b), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("an empty signature must be ADMITTED, not refused: %d %s", rec.Code, rec.Body.String())
	}
	h.drain()
	if h.ins.count() != 1 {
		t.Fatalf("want 1 projected row, got %d", h.ins.count())
	}
}

// verdictEvent is a well-formed VerdictEvent (verify.proto: 4-vector
// posterior, stage inside the enum); tests break one field at a time.
func verdictEvent(t *testing.T, session uuid.UUID, seq uint64) *m1pv1.Event {
	t.Helper()
	ev := usageEvent(t, session, seq)
	ev.Body = &m1pv1.Event_VerdictEvent{VerdictEvent: &m1pv1.VerdictEvent{
		Stage:     m1pv1.VerdictStage_VERDICT_STAGE_PROVISIONAL,
		Verdict:   m1pv1.Verdict_VERDICT_SATISFIED,
		Posterior: []float64{0.86, 0.09, 0.03, 0.02},
	}}
	return ev
}

// assertVerdictRefused is the FR-VERIFY-020 shape: 422 M1E-2006 naming the
// event and the kind, nothing landed, nothing projected — the same path a
// Usage without its idem_key takes, never a null projection.
func assertVerdictRefused(t *testing.T, h *harness, ev *m1pv1.Event, kind string) {
	t.Helper()
	b, id := testBatch(t, ev)
	rec := h.post(t, id, encodeBatch(t, b), nil)
	if rec.Code != http.StatusUnprocessableEntity || errCode(t, rec) != "M1E-2006" {
		t.Fatalf("want 422 M1E-2006, got %d %s", rec.Code, rec.Body.String())
	}
	evID := uuid.Must(uuid.FromBytes(ev.EventId)).String()
	if body := rec.Body.String(); !strings.Contains(body, evID) || !strings.Contains(body, `"`+kind+`"`) {
		t.Fatalf("422 must name event %s and kind %q: %s", evID, kind, body)
	}
	h.drain()
	if len(h.store.keys()) != 0 || h.ins.count() != 0 {
		t.Fatalf("refused verdict must neither land nor project: keys=%v rows=%d", h.store.keys(), h.ins.count())
	}
}

func TestVerdictEventWithBadPosteriorIsRefused(t *testing.T) {
	for _, n := range []int{0, 3, 5} {
		ev := verdictEvent(t, mustV7(t), 1)
		ev.GetVerdictEvent().Posterior = make([]float64, n)
		assertVerdictRefused(t, newHarness(t), ev, "verdict_posterior")
	}
}

func TestVerdictEventWithUnspecifiedStageIsRefused(t *testing.T) {
	// UNSPECIFIED (the proto zero) and a number the descriptor does not know
	// are both "outside the enum"; hand-listing the members would let a
	// regenerated enum drift past this check.
	for _, st := range []m1pv1.VerdictStage{m1pv1.VerdictStage_VERDICT_STAGE_UNSPECIFIED, m1pv1.VerdictStage(99)} {
		ev := verdictEvent(t, mustV7(t), 1)
		ev.GetVerdictEvent().Stage = st
		assertVerdictRefused(t, newHarness(t), ev, "verdict_stage")
	}
}

// Positive control: the refusals above must not be satisfiable by a pipeline
// that refuses every VerdictEvent.
func TestWellFormedVerdictEventProjectsAllFourColumns(t *testing.T) {
	h := newHarness(t)
	b, id := testBatch(t, verdictEvent(t, mustV7(t), 1))
	if rec := h.post(t, id, encodeBatch(t, b), nil); rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	h.drain()
	if h.ins.count() != 1 {
		t.Fatalf("want 1 projected row, got %d", h.ins.count())
	}
	row := h.ins.rows[0]
	if got := projCol(t, row, "verdict_stage"); got != "provisional" {
		t.Fatalf("verdict_stage: %v", got)
	}
	for c, want := range map[string]float32{"p_satisfied": 0.86, "p_violated": 0.09, "p_refused": 0.03, "p_error": 0.02} {
		if got := projCol(t, row, c); got != want {
			t.Fatalf("%s: want %v got %v (a null projection is the FR-VERIFY-020 failure)", c, want, got)
		}
	}
}

// routeDecision is the row mark1d's route.Emitter lands beside every Usage
// (ε = 0 ⇒ propensity 1.0, ADVISORY, the applied bundle's seq); tests break
// one field at a time.
func routeDecision(t *testing.T, session uuid.UUID, seq uint64) *m1pv1.Event {
	t.Helper()
	ev := usageEvent(t, session, seq)
	ev.Body = &m1pv1.Event_RouteDecision{RouteDecision: &m1pv1.RouteDecision{
		DecisionId: ev.EventId,
		Action:     "claude-test-1",
		Candidates: []string{"claude-test-1"},
		Propensity: 1,
		Fidelity:   m1pv1.RouteFidelity_ROUTE_FIDELITY_ADVISORY,
		BundleSeq:  7,
	}}
	return ev
}

func TestRouteDecisionWithBadPropensityIsRefused(t *testing.T) {
	// 0 is what a missing producer lands (FR-ROUTE-001's zero propensity);
	// NaN fails the same (0, 1] comparison rather than slipping past a
	// hand-written pair of inequalities.
	for _, p := range []float64{0, -0.1, 1.0001, math.NaN()} {
		ev := routeDecision(t, mustV7(t), 1)
		ev.GetRouteDecision().Propensity = p
		assertVerdictRefused(t, newHarness(t), ev, "route_propensity")
	}
}

func TestRouteDecisionWithUnspecifiedFidelityIsRefused(t *testing.T) {
	for _, f := range []m1pv1.RouteFidelity{m1pv1.RouteFidelity_ROUTE_FIDELITY_UNSPECIFIED, m1pv1.RouteFidelity(99)} {
		ev := routeDecision(t, mustV7(t), 1)
		ev.GetRouteDecision().Fidelity = f
		assertVerdictRefused(t, newHarness(t), ev, "route_fidelity")
	}
	ev := routeDecision(t, mustV7(t), 1)
	ev.GetRouteDecision().Action = ""
	assertVerdictRefused(t, newHarness(t), ev, "route_action")
}

// Positive control: the refusals above must not be satisfiable by a pipeline
// that refuses every RouteDecision — the honest ε = 0 row lands all three
// projected columns.
func TestWellFormedRouteDecisionProjects(t *testing.T) {
	h := newHarness(t)
	b, id := testBatch(t, routeDecision(t, mustV7(t), 1))
	if rec := h.post(t, id, encodeBatch(t, b), nil); rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	h.drain()
	if h.ins.count() != 1 {
		t.Fatalf("want 1 projected row, got %d", h.ins.count())
	}
	row := h.ins.rows[0]
	for c, want := range map[string]any{"propensity": float64(1), "fidelity": "advisory", "bundle_seq": uint64(7), "event_class": "route"} {
		if got := projCol(t, row, c); got != want {
			t.Fatalf("%s: want %#v got %#v (a null projection is the FR-ROUTE-001 failure)", c, want, got)
		}
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
	if h.sec.quarantineCount() != 1 {
		t.Fatalf("quarantine recorded no tenant-visible security event (CON-008): %d", h.sec.quarantineCount())
	}
	h.drain()
	if h.ins.count() != 0 || h.db.calls != 0 {
		t.Fatalf("quarantined batch was projected: proj=%d sidefx=%d", h.ins.count(), h.db.calls)
	}
	if h.tomb.calls != 1 {
		t.Fatalf("the never-replay marker must be written in the landing request path (07 §S3 layout): tombstone writes=%d", h.tomb.calls)
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
	// One landed quarantine, one tenant alert: the re-POST returns on the
	// Duplicate outcome above the recorder, so the alert cannot double-fire.
	if h.sec.quarantineCount() != 1 {
		t.Fatalf("re-POST recorded %d security events for one landed quarantine", h.sec.quarantineCount())
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
// CON-008: a quarantine must alert the TENANT, and must not leak what it caught
// ---------------------------------------------------------------------------

// The secrets planted below. Both are syntactically valid for their rule class
// and neither is a real credential.
const (
	plantedAWSKey   = "AKIAABCDEFGHIJKLMNOP"
	plantedGHToken  = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	plantedAWSClass = "aws_access_key_id"
	plantedGHClass  = "github_token"
)

// realSecurityHarness wires the PRODUCTION recorder (Deps.Security nil ⇒
// projectorSecurity), so the assertions run against the row that actually
// reaches ClickHouse rather than a fake's copy of the arguments it was handed.
func realSecurityHarness(t *testing.T) *harness {
	t.Helper()
	h := newHarness(t)
	mux := http.NewServeMux()
	m := New(Deps{
		Verifier: h.verifier,
		ObsCfg:   obs.Config{ServiceName: "controld-test"},
		PG:       fakeReady{}, Store: h.store, Proj: h.proj, Sidefx: h.sfx, DB: h.tomb,
		PoolSize: 4,
	})
	m.RegisterRoutes(mux)
	h.mux = mux
	return h
}

// projCol reads a projected column by NAME, so a column inserted into
// chproj.Columns moves these assertions instead of silently re-aiming them.
func projCol(t *testing.T, row []any, name string) any {
	t.Helper()
	for i, c := range chproj.Columns {
		if c == name {
			return row[i]
		}
	}
	t.Fatalf("no projected column named %q", name)
	return nil
}

// rowLeaks names which of secrets survives ANYWHERE in a projected row — every
// column, not only the one a test expects to be dangerous.
func rowLeaks(row []any, secrets ...string) []string {
	rendered := fmt.Sprintf("%v", row)
	var found []string
	for _, s := range secrets {
		if strings.Contains(rendered, s) {
			found = append(found, s)
		}
	}
	return found
}

func leakyBatch(t *testing.T) (*m1pv1.Batch, uuid.UUID) {
	t.Helper()
	session := mustV7(t)
	aws := usageEvent(t, session, 1)
	aws.GetUsage().ServiceTier = plantedAWSKey
	gh := usageEvent(t, session, 2)
	gh.GetUsage().RequestId = plantedGHToken
	return testBatch(t, aws, gh)
}

// CON-008 / FR-SPINE-012's "alerts the tenant" half: quarantinesTotal is
// ops-visible, the quarantine object is not tenant-queryable, and the 202's
// quarantined[] dies with a device that has already parked — so the tenant's
// own ledger gets a GuardDecision-class row. It names the rule CLASSES and
// nothing else: writing the matched credential here would convert a caught
// leak into a committed one, in a store with a different retention and access
// path than the quarantine object.
func TestQuarantineAlertsTenantWithRuleClassesAndNoSecret(t *testing.T) {
	h := realSecurityHarness(t)
	b, id := leakyBatch(t)
	body := encodeBatch(t, b)

	// Anti-vacuity 1: a REAL quarantine happened. Without this every "no
	// secret in the event" assertion below is satisfiable by a harness that
	// scanned nothing, quarantined nothing and emitted nothing.
	if rec := h.post(t, id, body, nil); rec.Code != http.StatusAccepted {
		t.Fatalf("want 202 (a real quarantine), got %d: %s", rec.Code, rec.Body.String())
	}
	keys := h.store.keys()
	if len(keys) != 1 || !strings.Contains(keys[0], "/quarantine/v1/") {
		t.Fatalf("no quarantine landing to alert about: %v", keys)
	}
	// Idempotency, on the same path the edge's retry automaton takes.
	if rec := h.post(t, id, body, nil); rec.Code != http.StatusAccepted {
		t.Fatalf("re-POST: want 202, got %d: %s", rec.Code, rec.Body.String())
	}
	h.drain()

	// Anti-vacuity 2: an event WAS emitted — exactly one across both POSTs,
	// and it is the security event, NOT the flagged batch (05 §2.3: nothing
	// from a flagged batch is projected).
	if h.ins.count() != 1 {
		t.Fatalf("want exactly 1 projected row (the security event, once, across two POSTs), got %d", h.ins.count())
	}
	row := h.ins.rows[0]
	if got := projCol(t, row, "event_type"); got != "GuardDecision" {
		t.Fatalf("tenant alert must land as a GuardDecision-class event (08 §9), got %v", got)
	}

	// Identity is the stage-3 stamp from verified claims, never the envelope
	// (which carries no tenant here at all — a recorder reading it would
	// stamp uuid.Nil and file the alert under nobody).
	if got := projCol(t, row, "tenant_id"); got != h.tenant {
		t.Fatalf("security event filed under the wrong tenant: want %s got %v", h.tenant, got)
	}
	if got := projCol(t, row, "device_id"); got != h.device {
		t.Fatalf("security event filed under the wrong device: want %s got %v", h.device, got)
	}

	var payload struct {
		ReasonCode string `json:"reason_code"`
		ErrorCode  string `json:"error_code"`
		BatchID    string `json:"batch_id"`
		Detail     string `json:"detail"`
	}
	raw, ok := projCol(t, row, "payload").(string)
	if !ok {
		t.Fatalf("payload column is not a string: %#v", projCol(t, row, "payload"))
	}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatalf("payload is not JSON: %s", raw)
	}
	if payload.ErrorCode != "M1E-7002" || payload.ReasonCode != "pre_egress_quarantine" {
		t.Fatalf("alert must cite the 08 §9 taxonomy row: %+v", payload)
	}
	if payload.BatchID != id.String() {
		t.Fatalf("alert must name the quarantined batch: want %s got %s", id, payload.BatchID)
	}
	// The property that matters, asserted BEFORE the cosmetic one below so a
	// leak reds this line and not a string-equality line: the credential we
	// caught is not now in the ledger. Checked over the WHOLE row.
	if got := rowLeaks(row, plantedAWSKey, plantedGHToken); len(got) != 0 {
		t.Fatalf("the security event leaks the secret it quarantined: %v (payload=%s)", got, raw)
	}
	// The detail is the rule classes, both of them, and nothing else.
	if payload.Detail != plantedAWSClass+","+plantedGHClass {
		t.Fatalf("detail must be exactly the fired rule classes: %q", payload.Detail)
	}
	// Anti-vacuity 3 (positive control): the check above must be capable of
	// failing. Same row, the secret spliced into the detail — and the
	// detector must name it. A green "no leak" from a detector that cannot
	// see a leak is worse than no test.
	leaking := append([]any(nil), row...)
	for i, c := range chproj.Columns {
		if c == "payload" {
			leaking[i] = `{"detail":"` + plantedAWSKey + `"}`
		}
	}
	if got := rowLeaks(leaking, plantedAWSKey, plantedGHToken); len(got) != 1 || got[0] != plantedAWSKey {
		t.Fatalf("leak detector is vacuous: it did not flag a row that demonstrably carries %s: %v", plantedAWSKey, got)
	}
}

// The alert's identity follows the TOKEN. Two tenants quarantine through the
// same module; neither event may carry the other's tenant or device. The
// envelope is not consulted — a recorder that read it would stamp uuid.Nil,
// and one that reused an ambient/first-seen tenant would file both alerts
// under one tenancy, which is a cross-tenant disclosure of a security event.
func TestQuarantineAlertIdentityIsPerTokenNotAmbient(t *testing.T) {
	h := realSecurityHarness(t)
	otherTenant, otherDevice := uuid.New(), uuid.New()
	otherToken := auth.Mint(testKey, otherTenant, otherDevice, time.Hour)

	b1, id1 := leakyBatch(t)
	if rec := h.post(t, id1, encodeBatch(t, b1), nil); rec.Code != http.StatusAccepted {
		t.Fatalf("tenant A: want 202, got %d: %s", rec.Code, rec.Body.String())
	}
	b2, id2 := leakyBatch(t)
	rec := h.post(t, id2, encodeBatch(t, b2), func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+otherToken)
	})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("tenant B: want 202, got %d: %s", rec.Code, rec.Body.String())
	}
	h.drain()

	if h.ins.count() != 2 {
		t.Fatalf("want one alert per quarantine, got %d rows", h.ins.count())
	}
	got := map[uuid.UUID]uuid.UUID{}
	for _, row := range h.ins.rows {
		tenant, ok := projCol(t, row, "tenant_id").(uuid.UUID)
		if !ok {
			t.Fatalf("tenant_id column is not a uuid: %#v", projCol(t, row, "tenant_id"))
		}
		device, ok := projCol(t, row, "device_id").(uuid.UUID)
		if !ok {
			t.Fatalf("device_id column is not a uuid: %#v", projCol(t, row, "device_id"))
		}
		if prev, dup := got[tenant]; dup {
			t.Fatalf("both alerts filed under tenant %s (device %s then %s)", tenant, prev, device)
		}
		got[tenant] = device
	}
	if got[h.tenant] != h.device {
		t.Fatalf("tenant A's alert names device %v, want %s", got[h.tenant], h.device)
	}
	if got[otherTenant] != otherDevice {
		t.Fatalf("tenant B's alert names device %v, want %s", got[otherTenant], otherDevice)
	}
}

// The two GuardDecision producers on one batch_id must not collapse onto one
// event_id in the ReplacingMergeTree: an M1E-8003 refusal and a later
// M1E-7002 quarantine of the same batch_id are different facts, and losing
// either to a merge is a silently dropped security event.
func TestSecurityEventIDsAreSeparatedByErrorCode(t *testing.T) {
	tenant, device, batch := uuid.New(), uuid.New(), uuid.New()
	at := time.Now()
	disagreement := chproj.SecurityEventRow(tenant, device, batch, "advisory_tenant_id disagrees with token", at)
	quarantine := chproj.QuarantineEventRow(tenant, device, batch, plantedAWSClass, at)
	if projCol(t, disagreement, "event_id") == projCol(t, quarantine, "event_id") {
		t.Fatalf("both security events on batch %s derive event_id %v — one collapses away on merge",
			batch, projCol(t, quarantine, "event_id"))
	}
	// Each is still deterministic in its own right (replay must not multiply).
	if projCol(t, quarantine, "event_id") !=
		projCol(t, chproj.QuarantineEventRow(tenant, device, batch, plantedAWSClass, at.Add(time.Hour)), "event_id") {
		t.Fatal("quarantine event_id is not replay-deterministic")
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
	n, err := Replay(context.Background(), h.tomb, h.store, h.ins, nil, tenant,
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

// v7At mints a uuidv7 carrying at's millisecond timestamp. The landing key's
// dt= partition is derived from the batch id (s3land.IngestKey), so this is
// the only way to file a batch under a day other than today — and the day
// loop is where a partial recovery would hide.
func v7At(t *testing.T, at time.Time) uuid.UUID {
	t.Helper()
	id := mustV7(t) // version/variant bits live in id[6]/id[8]; only the timestamp is rewritten
	ms := uint64(at.UnixMilli())
	for i := 0; i < 6; i++ {
		id[i] = byte(ms >> (40 - 8*i))
	}
	if id.Version() != 7 {
		t.Fatalf("v7At produced a v%d uuid", id.Version())
	}
	return id
}

// rowsByEventID indexes a projection by its event_id column so two projections
// can be compared as sets — replay lists S3 in key order, not arrival order.
func rowsByEventID(t *testing.T, rows [][]any) map[uuid.UUID][]any {
	t.Helper()
	out := make(map[uuid.UUID][]any, len(rows))
	for _, r := range rows {
		id, ok := r[3].(uuid.UUID)
		if !ok {
			t.Fatalf("projected column %q is not a uuid: %#v", chproj.Columns[3], r[3])
		}
		if _, dup := out[id]; dup {
			t.Fatalf("two projected rows carry event_id %s", id)
		}
		out[id] = r
	}
	return out
}

// NFR-DURABILITY-003's second half: "Ledger wiped, replay from S3 alone
// reconstructs all acked events." TestReplayReprojectsIdempotently only shows
// a replayed row agreeing with a live row that is still sitting in the same
// inserter; here the live ledger is DESTROYED — a fresh inserter, a fresh
// Postgres fake and a fresh stage-11 pool — so the landing objects are the
// only surviving input to the rebuild.
func TestReplayFromS3AloneReconstructsAckedEvents(t *testing.T) {
	h := newHarness(t)

	// A second device on the same tenant carries its own token: identity is
	// the stage-3 stamp, and replay must re-derive it from object metadata
	// alone once the token is gone.
	otherDevice := uuid.New()
	otherToken := auth.Mint(testKey, h.tenant, otherDevice, time.Hour)
	asOther := func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+otherToken) }

	session := mustV7(t)
	b1, id1 := testBatch(t, usageEvent(t, session, 1), usageEvent(t, session, 2), usageEvent(t, session, 3))
	b2, id2 := testBatch(t, usageEvent(t, session, 4), usageEvent(t, session, 5))
	// A Dropped entry has no event_id of its own; its row id is derived from
	// (batch_id, index), which replay must re-derive identically.
	b2.Dropped = []*m1pv1.Dropped{{
		Reason:          m1pv1.DropReason_DROP_REASON_SPOOL_SHED,
		Quantity:        7,
		DurabilityClass: m1pv1.DurabilityClass_DURABILITY_CLASS_DIAGNOSTIC,
	}}
	b3, _ := testBatch(t, usageEvent(t, session, 6), usageEvent(t, session, 7))
	id3 := v7At(t, time.Now().UTC().AddDate(0, 0, -1)) // yesterday's dt= partition
	b3.BatchId = id3[:]

	posts := []struct {
		batch  *m1pv1.Batch
		id     uuid.UUID
		mutate func(*http.Request)
	}{
		{b1, id1, nil},
		{b2, id2, asOther},
		{b3, id3, nil},
	}
	for i, p := range posts {
		if rec := h.post(t, p.id, encodeBatch(t, p.batch), p.mutate); rec.Code != http.StatusOK {
			t.Fatalf("setup post %d: want 200, got %d: %s", i, rec.Code, rec.Body.String())
		}
	}
	if got := len(h.store.keys()); got != len(posts) {
		t.Fatalf("want %d landed objects, got %d: %v", len(posts), got, h.store.keys())
	}
	h.drain()

	claims := auth.Claims{TenantID: h.tenant, DeviceID: h.device}
	tenant, err := querychoke.FromClaims(claims)
	if err != nil {
		t.Fatal(err)
	}

	// The complete live result, snapshotted before anything is wiped.
	live := rowsByEventID(t, h.ins.rows)
	liveRows := h.ins.count()
	liveDBCalls := h.db.calls
	liveLeaves := h.sfx.PendingLeafCount(tenant, h.device)
	liveOtherLeaves := h.sfx.PendingLeafCount(tenant, otherDevice)
	if liveRows != 8 || liveLeaves != 5 || liveOtherLeaves != 2 || liveDBCalls != 3 {
		t.Fatalf("live path did not produce the expected ledger: rows=%d leaves=%d/%d sidefx=%d",
			liveRows, liveLeaves, liveOtherLeaves, liveDBCalls)
	}

	// ---- the ledger is wiped: only h.store survives -----------------------
	rebuiltIns := &fakeInserter{}
	rebuiltDB := &fakeDB{}
	rebuiltSfx := sidefx.New(rebuiltDB, nil, nil, 1, 100)
	if rebuiltIns.count() != 0 || rebuiltDB.calls != 0 ||
		rebuiltSfx.PendingLeafCount(tenant, h.device) != 0 || rebuiltSfx.PendingLeafCount(tenant, otherDevice) != 0 {
		t.Fatal("the wiped ledger is not empty — the rebuild would be reading the live projection, not S3")
	}

	now := time.Now().UTC()
	n, err := Replay(context.Background(), h.tomb, h.store, rebuiltIns, rebuiltSfx, tenant,
		now.AddDate(0, 0, -3), now.AddDate(0, 0, 1))
	if err != nil {
		t.Fatal(err)
	}
	rebuiltSfx.Close()

	if n != len(posts) {
		t.Fatalf("replay read %d landing objects, %d were acked", n, len(posts))
	}
	if h.ins.count() != liveRows {
		t.Fatalf("replay wrote into the wiped ledger's inserter (%d → %d rows): the rebuild is not independent",
			liveRows, h.ins.count())
	}

	rebuilt := rowsByEventID(t, rebuiltIns.rows)
	for id, want := range live {
		got, ok := rebuilt[id]
		if !ok {
			t.Fatalf("event %s is not recoverable from S3 alone: the rebuild reconstructed %d of %d acked events",
				id, len(rebuilt), len(live))
		}
		for i := range want {
			if !reflect.DeepEqual(want[i], got[i]) {
				t.Fatalf("event %s: rebuilt column %q disagrees with the acked projection: live %#v, rebuilt %#v",
					id, chproj.Columns[i], want[i], got[i])
			}
		}
	}
	for id := range rebuilt {
		if _, ok := live[id]; !ok {
			t.Fatalf("the rebuild invented event %s, which was never acked", id)
		}
	}
	if len(rebuilt) != len(live) {
		t.Fatalf("the rebuild holds %d distinct events, %d were acked", len(rebuilt), len(live))
	}

	// Stage 11 re-derives too: the pending-leaf set is in-memory, so the
	// landing objects are its ONLY recovery path (05 §2.5).
	if got := rebuiltSfx.PendingLeafCount(tenant, h.device); got != liveLeaves {
		t.Fatalf("rebuilt pending-leaf set for device %s: want %d leaves, got %d", h.device, liveLeaves, got)
	}
	if got := rebuiltSfx.PendingLeafCount(tenant, otherDevice); got != liveOtherLeaves {
		t.Fatalf("rebuilt pending-leaf set for device %s: want %d leaves, got %d", otherDevice, liveOtherLeaves, got)
	}
	if rebuiltDB.calls != liveDBCalls {
		t.Fatalf("rebuilt stage-11 Postgres effects: want %d, got %d", liveDBCalls, rebuiltDB.calls)
	}
}

// §2.4's in-process shed: a saturated ingest pool refuses with 503 + a
// Retry-After the edge's backoff automaton can read, and refuses BEFORE
// stage 4 spends anything on decompression. The body here is a zstd bomb, so
// a refusal that arrived after stage 4 would answer 400 M1E-2001 instead —
// the 503 is what proves the ordering.
func TestSaturatedPoolRefusesWithRetryAfterBeforeDecompression(t *testing.T) {
	h := newHarness(t)

	// The only pool slot is held by a request parked inside m.now(), which
	// handleIngest calls immediately after acquiring it. A one-shot channel
	// rather than sync.Once: if the shed ever moved below this call, the
	// second request would park too and the test would hang instead of fail.
	park := make(chan struct{}, 1)
	park <- struct{}{}
	admitted, release := make(chan struct{}), make(chan struct{})
	mux := http.NewServeMux()
	m := New(Deps{
		Verifier: h.verifier,
		ObsCfg:   obs.Config{ServiceName: "controld-test"},
		PG:       fakeReady{}, Store: h.store, Proj: h.proj, Sidefx: h.sfx, Security: h.sec,
		PoolSize: 1,
		Now: func() time.Time {
			select {
			case <-park:
				close(admitted)
				<-release
			default:
			}
			return time.Now()
		},
	})
	m.RegisterRoutes(mux)
	h.mux = mux

	b, id := testBatch(t)
	parked := make(chan int, 1)
	go func() { parked <- h.post(t, id, encodeBatch(t, b), nil).Code }()
	<-admitted

	bomb := compress(t, make([]byte, 33<<20))
	rec := h.post(t, mustV7(t), bomb, nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("saturated pool must shed with 503 before stage 4 decompression, got %d: %s",
			rec.Code, rec.Body.String())
	}
	if code := errCode(t, rec); code != "M1E-9500" {
		t.Fatalf("want M1E-9500, got %s", code)
	}
	if ra := rec.Header().Get("Retry-After"); ra != "1" {
		t.Fatalf("pool-saturation 503 must carry Retry-After: 1, got %q", ra)
	}

	close(release)
	if code := <-parked; code != http.StatusOK {
		t.Fatalf("the parked request holding the pool slot: want 200, got %d", code)
	}
	if got := len(h.store.keys()); got != 1 {
		t.Fatalf("the shed request must not land: want 1 object, got %d", got)
	}
}
