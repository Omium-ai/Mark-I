//go:build integration

// The security-event ROW, end to end (FR-SPINE-011; FR-SPINE-012's rescan
// alert rides the same chain). Every earlier test on these rows stopped one
// hop short: pipeline_test proves the recorder is CALLED and holds the row a
// fake inserter was handed; chproj_test proves the row is deterministic. The
// chain that actually reaches the tenant's ledger — the production
// projectorSecurity (ingest.Deps.Security nil), Projector.Enqueue, the worker
// pool, chconn's async insert, m1p_events — was never constructed. Here it
// is, against the local ClickHouse: a batch whose envelope claims another
// tenant is refused 403 M1E-8003, and the GuardDecision row is then SELECTed
// back under the TOKEN's tenant. Then a batch landed clean under an older
// scanner edition is rescanned under the current one and its M1E-7002 alert
// is SELECTed back the same way.
//
// Package chproj_test, in this directory, because this is one of the two
// places allowed to import the ClickHouse driver (depguard clickhouse-choke)
// and package chproj itself cannot import ingest. Gate: M1_TEST_CH_DSN
// (absent ⇒ skip, unless M1_REQUIRE_STORES=1 ⇒ fail — chproj.SetupCH).
//
// S3 is a fake here on purpose: the 403 path never reaches stage 8, the
// landing half of the estate is proven against a real server in
// s3land/integration_test.go, and the row this file exists to observe is the
// ClickHouse one.

package chproj_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/klauspost/compress/zstd"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/chproj"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/s3land"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/scanner"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/sidefx"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

// memStore is the smallest s3land.Store: a map. Land/Probe carry the
// conditional-PUT semantics Rescan and the pipeline's quarantine probe rely on.
type memStore struct {
	mu      sync.Mutex
	objects map[string][]byte
	devices map[string]uuid.UUID
}

func newMemStore() *memStore {
	return &memStore{objects: map[string][]byte{}, devices: map[string]uuid.UUID{}}
}

func (m *memStore) Land(_ context.Context, key string, body []byte, _, device uuid.UUID) (s3land.Outcome, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if prior, ok := m.objects[key]; ok {
		if bytes.Equal(prior, body) {
			return s3land.Duplicate, nil
		}
		return s3land.Divergent, nil
	}
	m.objects[key] = append([]byte(nil), body...)
	m.devices[key] = device
	return s3land.Landed, nil
}

func (m *memStore) Probe(_ context.Context, key string, body []byte) (s3land.Outcome, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	prior, ok := m.objects[key]
	switch {
	case !ok:
		return s3land.NotLanded, nil
	case bytes.Equal(prior, body):
		return s3land.Duplicate, nil
	default:
		return s3land.Divergent, nil
	}
}

func (m *memStore) Ready(context.Context) error { return nil }

func (m *memStore) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.objects, key)
	delete(m.devices, key)
	return nil
}

func (m *memStore) List(_ context.Context, prefix string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var keys []string
	for k := range m.objects {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	return keys, nil
}

func (m *memStore) Get(_ context.Context, key string) ([]byte, uuid.UUID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	body, ok := m.objects[key]
	if !ok {
		return nil, uuid.Nil, errors.New("not found")
	}
	return body, m.devices[key], nil
}

func (m *memStore) has(key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.objects[key]
	return ok
}

type noopReady struct{}

func (noopReady) Ready(context.Context) error { return nil }

type noopDB struct{}

func (noopDB) WithTenant(context.Context, querychoke.TenantID, func(pgx.Tx) error) error { return nil }

func v7(t *testing.T) uuid.UUID {
	t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func encode(t *testing.T, b *m1pv1.Batch) []byte {
	t.Helper()
	raw, err := proto.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
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

// usageBatch is one well-formed Usage event; requestID is the string field
// the rescan case plants its secret in.
func usageBatch(t *testing.T, requestID string) (*m1pv1.Batch, uuid.UUID) {
	t.Helper()
	batchID, session, eventID := v7(t), v7(t), v7(t)
	return &m1pv1.Batch{
		BatchId:   batchID[:],
		SessionId: session[:],
		Sdk:       &m1pv1.SdkInfo{Name: "mark1d", Version: "0.0.1-test", Agent: "claudecode"},
		SentAt:    timestamppb.Now(),
		Events: []*m1pv1.Event{{
			EventId: eventID[:], Seq: 1, SessionId: session[:], OccurredAt: timestamppb.Now(),
			Body: &m1pv1.Event_Usage{Usage: &m1pv1.Usage{
				IdemKey: bytes.Repeat([]byte{0xAB}, 32), Model: "claude-test-1",
				RequestId: requestID, InputTokens: 100, OutputTokens: 50,
			}},
		}},
	}, batchID
}

type securityPayload struct {
	ReasonCode string `json:"reason_code"`
	ErrorCode  string `json:"error_code"`
	BatchID    string `json:"batch_id"`
	Detail     string `json:"detail"`
}

// selectSecurityRow polls the ledger (the projector is post-ack and async)
// for THE GuardDecision row under tenant, returning its stamped identity and
// payload. Reader discipline: LIMIT 1 BY event_id (m1_ch_001 footer).
func selectSecurityRow(t *testing.T, query driver.Conn, tenant uuid.UUID, code string) (device uuid.UUID, class string, p securityPayload) {
	t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(20 * time.Second)
	for {
		var raw string
		err := query.QueryRow(ctx, fmt.Sprintf(
			`SELECT device_id, event_class, payload FROM %s
			  WHERE tenant_id = $1 AND event_type = 'GuardDecision'
			    AND JSONExtractString(payload, 'error_code') = $2
			  LIMIT 1 BY event_id`, chproj.Table), tenant, code).Scan(&device, &class, &raw)
		if err == nil {
			if err := json.Unmarshal([]byte(raw), &p); err != nil {
				t.Fatalf("security row payload is not JSON: %s", raw)
			}
			return device, class, p
		}
		if time.Now().After(deadline) {
			t.Fatalf("no %s GuardDecision row reached %s for tenant %s within 20s: %v", code, chproj.Table, tenant, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func countRows(t *testing.T, query driver.Conn, tenant uuid.UUID) uint64 {
	t.Helper()
	var n uint64
	if err := query.QueryRow(context.Background(), fmt.Sprintf(
		`SELECT count() FROM (SELECT event_id FROM %s WHERE tenant_id = $1 LIMIT 1 BY event_id)`, chproj.Table),
		tenant).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestIntegrationSecurityEventRowReachesLedger(t *testing.T) {
	conn, query, _ := chproj.SetupCH(t)
	ctx := context.Background()

	// The production chain: real Projector over chconn, recorder defaulted
	// (Deps.Security nil ⇒ projectorSecurity), scanner pinned to an edition
	// that does not know GitHub tokens so the rescan case below can land clean.
	editionA, err := scanner.Compile("A", map[string]string{"aws_access_key_id": `\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`})
	if err != nil {
		t.Fatal(err)
	}
	proj := chproj.New(conn, 2, 16)
	t.Cleanup(proj.Close)
	store := newMemStore()
	sfx := sidefx.New(noopDB{}, nil, nil, 1, 16)
	t.Cleanup(sfx.Close)
	key := []byte("ledger-it-hmac-key")
	mod := ingest.New(ingest.Deps{
		Verifier: auth.NewHMACVerifier(key, auth.StaticRevocations{}),
		ObsCfg:   obs.Config{ServiceName: "controld-ledger-it"},
		PG:       noopReady{}, Store: store, Proj: proj, Sidefx: sfx, DB: noopDB{},
		Scanner:  editionA,
		PoolSize: 4,
	})
	mux := http.NewServeMux()
	mod.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	tenant, device, other := uuid.New(), uuid.New(), uuid.New()
	token := auth.Mint(key, tenant, device, time.Hour)
	post := func(batchID uuid.UUID, body []byte) (int, string) {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/m1p/v1/ingest", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/x-m1p-protobuf")
		req.Header.Set("Content-Encoding", "zstd")
		req.Header.Set("M1P-Schema", "m1p.v1")
		req.Header.Set("M1P-Batch-Id", batchID.String())
		req.ContentLength = int64(len(body))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		out, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(out)
	}

	// Anti-vacuity: the scratch ledger holds nothing for this tenant before
	// the refusal, so the row found below is this refusal's.
	if n := countRows(t, query, tenant); n != 0 {
		t.Fatalf("scratch ledger not empty for tenant: %d rows", n)
	}

	// ---- FR-SPINE-011: envelope claims tenant `other` on `tenant`'s token.
	b, batchID := usageBatch(t, "req_clean")
	b.AdvisoryTenantId = other[:]
	if code, body := post(batchID, encode(t, b)); code != http.StatusForbidden {
		t.Fatalf("want 403 M1E-8003, got %d: %s", code, body)
	}
	if len(store.objects) != 0 {
		t.Fatal("a refused batch landed")
	}

	gotDevice, class, p := selectSecurityRow(t, query, tenant, "M1E-8003")
	if gotDevice != device {
		t.Fatalf("security row device: want the token's %s, got %s", device, gotDevice)
	}
	if class != "diagnostic" {
		t.Fatalf("GuardDecision row must be event_class diagnostic, got %q", class)
	}
	if p.ReasonCode != "identity_disagreement" || p.BatchID != batchID.String() || !strings.Contains(p.Detail, "advisory_tenant_id") {
		t.Fatalf("security row payload: %+v", p)
	}
	// The row is filed under the TOKEN's tenant and under nobody else's —
	// the envelope's claimed tenant sees nothing, which is the point.
	if n := countRows(t, query, other); n != 0 {
		t.Fatalf("security row leaked into the envelope-claimed tenant's ledger: %d rows", n)
	}
	if n := countRows(t, query, tenant); n != 1 {
		t.Fatalf("want exactly the security row under the token's tenant, got %d", n)
	}

	// ---- FR-SPINE-012 rescan: land clean under edition A, alert under Default.
	leaky, leakyID := usageBatch(t, "ghp_abcdefghijklmnopqrstuvwxyz0123456789")
	leakyBody := encode(t, leaky)
	if code, body := post(leakyID, leakyBody); code != http.StatusOK {
		t.Fatalf("clean under edition A: want 200, got %d: %s", code, body)
	}
	// The ruleset bump: the same module shape, current Default edition,
	// same store and projector.
	bumped := ingest.New(ingest.Deps{
		Verifier: auth.NewHMACVerifier(key, auth.StaticRevocations{}),
		ObsCfg:   obs.Config{ServiceName: "controld-ledger-it"},
		PG:       noopReady{}, Store: store, Proj: proj, Sidefx: sfx, DB: noopDB{},
		PoolSize: 4,
	})
	tid, err := querychoke.FromClaims(auth.Claims{TenantID: tenant})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if flagged, err := bumped.Rescan(ctx, tid, now, now); err != nil || flagged != 1 {
		t.Fatalf("rescan: flagged=%d err=%v", flagged, err)
	}
	if !store.has(s3land.QuarantineKey(tenant, leakyID)) || !store.has(s3land.IngestKey(tenant, leakyID)) {
		t.Fatal("rescan must leave the ingest object and land the quarantine twin")
	}
	gotDevice, _, p = selectSecurityRow(t, query, tenant, "M1E-7002")
	if gotDevice != device {
		t.Fatalf("rescan alert device: want %s (from the landing object's stamp), got %s", device, gotDevice)
	}
	if p.ReasonCode != "pre_egress_quarantine" || p.BatchID != leakyID.String() || p.Detail != "github_token" {
		t.Fatalf("rescan alert payload: %+v", p)
	}
	// The alert carries the class, never the credential — across BOTH alert
	// rows, in the store that would keep it under a different retention.
	if n := rowsCarrying(t, query, tenant, "GuardDecision", "ghp_"); n != 0 {
		t.Fatalf("a GuardDecision row carries the secret the rescan found: %d rows", n)
	}
	// The ceiling, pinned as observed fact: the Usage row projected while
	// the batch was clean under edition A is still in the ledger with the
	// secret in its payload. Rescan alerts and quarantines; it does not
	// un-project — the ledger is append-only and triage owns that step. A
	// green here that came from 0 would mean something silently deleted
	// ledger rows, which is the bigger defect.
	if n := rowsCarrying(t, query, tenant, "Usage", "ghp_"); n != 1 {
		t.Fatalf("expected exactly the edition-A-projected Usage row to still carry the secret (the documented rescan ceiling), got %d", n)
	}
}

func rowsCarrying(t *testing.T, query driver.Conn, tenant uuid.UUID, eventType, needle string) uint64 {
	t.Helper()
	var n uint64
	if err := query.QueryRow(context.Background(), fmt.Sprintf(
		`SELECT count() FROM (SELECT event_id FROM %s WHERE tenant_id = $1 AND event_type = $2
		   AND position(payload, $3) > 0 LIMIT 1 BY event_id)`, chproj.Table),
		tenant, eventType, needle).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
