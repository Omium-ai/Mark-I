// Unit tests for the stage-11 pending-leaf/checkpoint machinery with the
// DB and chain writer faked — the Postgres-backed halves live in
// integration_test.go (DSN-gated) and the receipts package's own suite.

package sidefx

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/receipts"
	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

type nullDB struct{}

func (nullDB) WithTenant(context.Context, querychoke.TenantID, func(pgx.Tx) error) error {
	return nil
}

type fakeChain struct {
	appended  []receipts.CheckpointEvent
	refuse    *receipts.RefusalError
	runSealed bool // newTestSidefx sets it: the seal's tx body (Consume) runs against the memory store
	// inChain answers AlreadyAppended: the set of origin signatures the fake
	// chain "already holds" (replay/at-least-once dedupe, keyed like the real
	// store — the deterministic Ed25519 signature bytes).
	inChain map[string]bool
}

func (f *fakeChain) AppendCheckpoint(_ context.Context, _ querychoke.TenantID, ev receipts.CheckpointEvent,
	sealed func(pgx.Tx, receipts.Appended) error) (receipts.Appended, error) {
	if f.refuse != nil {
		return receipts.Appended{}, f.refuse
	}
	f.appended = append(f.appended, ev)
	// sealed runs with no tx: the memory leaf store consumes without one; the coverage inserts inside it are the integration test's business.
	app := receipts.Appended{Seq: int64(len(f.appended))}
	if f.runSealed {
		if err := sealed(nil, app); err != nil {
			return receipts.Appended{}, err
		}
	}
	return app, nil
}

func (f *fakeChain) AlreadyAppended(_ context.Context, _ querychoke.TenantID, originSig []byte) (bool, error) {
	return f.inChain[string(originSig)], nil
}

// AppendServerRecordTx is reachable only inside a real sealed tx (integration_test.go); the fake never gets there.
func (f *fakeChain) AppendServerRecordTx(context.Context, pgx.Tx, querychoke.TenantID, receipts.ServerRecord) (receipts.Appended, error) {
	return receipts.Appended{}, errors.New("fakeChain: no transaction")
}

func testTenant(t *testing.T) querychoke.TenantID {
	t.Helper()
	tid, err := querychoke.FromClaims(auth.Claims{TenantID: uuid.New()})
	if err != nil {
		t.Fatal(err)
	}
	return tid
}

func uuidV7(t *testing.T) uuid.UUID {
	t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func leafEffect(id uuid.UUID) Effect { return Effect{EventID: id} }

func checkpointEffect(t *testing.T, sealedIDs []uuid.UUID, claimedSeq int64) Effect {
	t.Helper()
	leaves := make([][]byte, len(sealedIDs))
	for i := range sealedIDs {
		leaves[i] = sealedIDs[i][:]
	}
	root, err := receipts.MerkleRoot(leaves)
	if err != nil {
		t.Fatal(err)
	}
	return Effect{EventID: uuidV7(t), Checkpoint: &receipts.CheckpointEvent{
		EventID:              uuidV7(t),
		DeviceKeyID:          "ed25519:test",
		ClaimedCheckpointSeq: claimedSeq,
		MerkleRoot:           root,
		LeafCount:            len(sealedIDs),
		IssuedAt:             time.Now(),
	}}
}

func TestPendingLeavesSealAndConsumeInOrder(t *testing.T) {
	chain := &fakeChain{}
	s, _ := newTestSidefx(chain, nil)
	t.Cleanup(s.Close)
	tenant, device := testTenant(t), uuid.New()

	ids := []uuid.UUID{uuidV7(t), uuidV7(t), uuidV7(t)}
	effects := []Effect{leafEffect(ids[0]), leafEffect(ids[1]), leafEffect(ids[2]),
		checkpointEffect(t, ids[:2], 1)}
	s.Apply(context.Background(), tenant, device, time.Now(), "", effects)

	if len(chain.appended) != 1 {
		t.Fatalf("appended %d checkpoints, want 1", len(chain.appended))
	}
	// The seal consumed exactly its leaf_count, IN ORDER; the third leaf
	// still awaits the next checkpoint.
	if got := s.PendingLeafCount(tenant, device); got != 1 {
		t.Fatalf("pending after seal = %d, want 1", got)
	}
	// The event's identity was stamped from the verified claims, never the wire.
	if chain.appended[0].DeviceID != device {
		t.Fatalf("checkpoint DeviceID = %s, want the authenticated device", chain.appended[0].DeviceID)
	}
}

func TestReplayedLeafIsIdempotent(t *testing.T) {
	s, _ := newTestSidefx(&fakeChain{}, nil)
	t.Cleanup(s.Close)
	tenant, device := testTenant(t), uuid.New()
	id := uuidV7(t)
	s.Apply(context.Background(), tenant, device, time.Now(), "", []Effect{leafEffect(id)})
	s.Apply(context.Background(), tenant, device, time.Now(), "", []Effect{leafEffect(id)})
	if got := s.PendingLeafCount(tenant, device); got != 1 {
		t.Fatalf("replayed leaf doubled the pending set: %d", got)
	}
}

func TestMerkleMismatchRefusesAndKeepsLeaves(t *testing.T) {
	chain := &fakeChain{}
	var securityFired bool
	sec := func(uuid.UUID, uuid.UUID, uuid.UUID, string, time.Time) { securityFired = true }
	s, _ := newTestSidefx(chain, sec)
	t.Cleanup(s.Close)
	tenant, device := testTenant(t), uuid.New()

	ids := []uuid.UUID{uuidV7(t), uuidV7(t)}
	cp := checkpointEffect(t, ids, 1)
	cp.Checkpoint.MerkleRoot[0] ^= 0xff // the device signed a different tree
	s.Apply(context.Background(), tenant, device, time.Now(), "",
		[]Effect{leafEffect(ids[0]), leafEffect(ids[1]), cp})

	if len(chain.appended) != 0 {
		t.Fatal("a mismatched root must never reach the chain writer")
	}
	if !securityFired {
		t.Fatal("merkle mismatch must emit a security event")
	}
	if got := s.PendingLeafCount(tenant, device); got != 2 {
		t.Fatalf("refusal consumed leaves: pending = %d, want 2", got)
	}
}

func TestChainRefusalSecurityOnlyForTamperShapes(t *testing.T) {
	tenant, device := testTenant(t), uuid.New()
	for _, tc := range []struct {
		code     receipts.Defect
		security bool
	}{
		{receipts.DefectBadSignature, true},
		{receipts.DefectUnknownKey, true},
		{receipts.DefectBrokenLink, false}, // stale head = retry semantics, never paged
	} {
		chain := &fakeChain{refuse: &receipts.RefusalError{Code: tc.code, Detail: "x"}}
		fired := false
		s, _ := newTestSidefx(chain, func(uuid.UUID, uuid.UUID, uuid.UUID, string, time.Time) { fired = true })
		ids := []uuid.UUID{uuidV7(t)}
		s.Apply(context.Background(), tenant, device, time.Now(), "",
			[]Effect{leafEffect(ids[0]), checkpointEffect(t, ids, 1)})
		if fired != tc.security {
			t.Errorf("%s: security event = %v, want %v", tc.code, fired, tc.security)
		}
		if got := s.PendingLeafCount(tenant, device); got != 1 {
			t.Errorf("%s: refusal must keep the pending set, got %d", tc.code, got)
		}
		s.Close()
		device = uuid.New() // fresh queue per case
	}
}

// The 05 §2.5 recovery trace that used to wedge a device: a restart erases
// `seen`+`pending`, Replay re-enqueues batches whose checkpoints the chain
// already holds, the re-delivered checkpoint is refused broken_link (stale
// seq) — and the re-admitted, already-sealed leaves must be CONSUMED, or every
// later honest seal reads the stale prefix and fires merkle_mismatch forever.
func TestReplayedCheckpointAfterRestartConsumesPrefix(t *testing.T) {
	chain := &fakeChain{inChain: map[string]bool{"sig-c1": true}}
	var securityFired bool
	s, _ := newTestSidefx(chain, func(uuid.UUID, uuid.UUID, uuid.UUID, string, time.Time) { securityFired = true })
	t.Cleanup(s.Close)
	tenant, device := testTenant(t), uuid.New()

	// Replay after restart: L1..L3 re-admitted, C1 (seals L1..L2) re-delivered
	// and refused broken_link by the chain — but its origin signature is
	// already in m1_receipts.
	ids := []uuid.UUID{uuidV7(t), uuidV7(t), uuidV7(t)}
	c1 := checkpointEffect(t, ids[:2], 1)
	c1.Checkpoint.OriginSig = []byte("sig-c1")
	chain.refuse = &receipts.RefusalError{Code: receipts.DefectBrokenLink, Detail: "stale checkpoint_seq"}
	s.Apply(context.Background(), tenant, device, time.Now(), "",
		[]Effect{leafEffect(ids[0]), leafEffect(ids[1]), leafEffect(ids[2]), c1})

	if securityFired {
		t.Fatal("an honest replay must never page security")
	}
	if got := s.PendingLeafCount(tenant, device); got != 1 {
		t.Fatalf("pending after replayed seal = %d, want 1 (the sealed prefix consumed, L3 kept)", got)
	}

	// The device's next LIVE seal (over L3 alone) must land cleanly — the
	// wedge this test exists to prevent.
	chain.refuse = nil
	c2 := checkpointEffect(t, ids[2:], 3)
	c2.Checkpoint.OriginSig = []byte("sig-c2")
	s.Apply(context.Background(), tenant, device, time.Now(), "", []Effect{c2})
	if securityFired {
		t.Fatal("live seal after replay paged security: the queue was poisoned")
	}
	if len(chain.appended) != 1 {
		t.Fatalf("appended = %d, want 1 (the live seal)", len(chain.appended))
	}
	if got := s.PendingLeafCount(tenant, device); got != 0 {
		t.Fatalf("pending after live seal = %d, want 0", got)
	}
}

// A checkpoint re-delivered AFTER its leaves were already consumed (live
// at-least-once duplicate): the queue prefix is now a DIFFERENT tree, and the
// dedupe must skip quietly — no security page, no consumption of live leaves.
func TestDuplicateCheckpointAfterConsumeSkipsQuietly(t *testing.T) {
	chain := &fakeChain{inChain: map[string]bool{}}
	var securityFired bool
	s, _ := newTestSidefx(chain, func(uuid.UUID, uuid.UUID, uuid.UUID, string, time.Time) { securityFired = true })
	t.Cleanup(s.Close)
	tenant, device := testTenant(t), uuid.New()

	ids := []uuid.UUID{uuidV7(t), uuidV7(t), uuidV7(t)}
	c1 := checkpointEffect(t, ids[:2], 1)
	c1.Checkpoint.OriginSig = []byte("sig-c1")
	s.Apply(context.Background(), tenant, device, time.Now(), "",
		[]Effect{leafEffect(ids[0]), leafEffect(ids[1]), leafEffect(ids[2]), c1})
	if len(chain.appended) != 1 || s.PendingLeafCount(tenant, device) != 1 {
		t.Fatalf("setup: appended=%d pending=%d", len(chain.appended), s.PendingLeafCount(tenant, device))
	}

	// The duplicate arrives; the real chain would refuse its stale seq.
	chain.inChain["sig-c1"] = true
	chain.refuse = &receipts.RefusalError{Code: receipts.DefectBrokenLink, Detail: "stale checkpoint_seq"}
	dup := checkpointEffect(t, ids[:2], 1)
	dup.Checkpoint.OriginSig = []byte("sig-c1")
	s.Apply(context.Background(), tenant, device, time.Now(), "", []Effect{dup})

	if securityFired {
		t.Fatal("a duplicate delivery must never page security")
	}
	if got := s.PendingLeafCount(tenant, device); got != 1 {
		t.Fatalf("duplicate consumed live leaves: pending = %d, want 1", got)
	}
}

// gateDB stalls every WithTenant until released — a stand-in for slow
// stage-11 Postgres, which is exactly the condition under which replay's
// queues are full.
type gateDB struct {
	entered chan struct{} // one tick per WithTenant entry
	release chan struct{}
	applied atomic.Int32
}

func (g *gateDB) WithTenant(context.Context, querychoke.TenantID, func(pgx.Tx) error) error {
	g.entered <- struct{}{}
	<-g.release
	g.applied.Add(1)
	return nil
}

// Replay's enqueue (05 §2.5): a full stage-11 queue means WAIT, never drop —
// a dropped effect here has no later replay to recover it. The only other
// exit is the caller's context.
func TestEnqueueBlockingWaitsOnFullQueueNeverDrops(t *testing.T) {
	gate := &gateDB{entered: make(chan struct{}, 64), release: make(chan struct{})}
	s := New(gate, &fakeChain{}, nil, 1, 0) // 1 worker, 1-slot queue
	tenant, device := testTenant(t), uuid.New()

	// Stall the worker on job #1, then fill the queue until it refuses.
	if !s.Enqueue(tenant, device, time.Now(), "", []Effect{leafEffect(uuidV7(t))}) {
		t.Fatal("first enqueue refused")
	}
	<-gate.entered // the worker is now inside the gated DB
	accepted := 1
	for s.Enqueue(tenant, device, time.Now(), "", []Effect{leafEffect(uuidV7(t))}) {
		accepted++
		if accepted > 8 {
			t.Fatal("queue never filled")
		}
	}

	// The blocking enqueue must WAIT on the full shard, not return.
	done := make(chan error, 1)
	go func() {
		done <- s.EnqueueBlocking(context.Background(), tenant, device, time.Now(),
			[]Effect{leafEffect(uuidV7(t))})
	}()
	select {
	case err := <-done:
		t.Fatalf("EnqueueBlocking returned on a full queue: %v (dropped or lied)", err)
	case <-time.After(50 * time.Millisecond): // still waiting = backpressure holds
	}

	// A cancelled context is the bounded exit, surfaced as the ctx error.
	ctx, cancel := context.WithCancel(context.Background())
	cancelDone := make(chan error, 1)
	go func() {
		cancelDone <- s.EnqueueBlocking(ctx, tenant, device, time.Now(),
			[]Effect{leafEffect(uuidV7(t))})
	}()
	cancel()
	if err := <-cancelDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled EnqueueBlocking: %v, want context.Canceled", err)
	}

	// Release the worker: the waiting enqueue lands and every accepted job —
	// plus the blocked one — applies. Nothing was dropped.
	close(gate.release)
	if err := <-done; err != nil {
		t.Fatalf("EnqueueBlocking after the queue drained: %v", err)
	}
	s.Close()
	// two DB entries per job: last_seen and the leaf landing (m1_083)
	if got := int(gate.applied.Load()); got != 2*(accepted+1) {
		t.Fatalf("applied %d DB entries, want %d (accepted %d + 1 blocking, two each): replay dropped effects", got, 2*(accepted+1), accepted)
	}
}

func TestEffectsFromBatchMapsBodies(t *testing.T) {
	dev := uuidV7(t)
	cov := uuidV7(t)
	ckpt := uuidV7(t)
	at := time.Date(2026, 8, 29, 12, 0, 3, 0, time.UTC)
	b := &m1pv1.Batch{Events: []*m1pv1.Event{
		{EventId: dev[:], OccurredAt: timestamppb.New(at),
			Body: &m1pv1.Event_Usage{Usage: &m1pv1.Usage{}}},
		{EventId: cov[:], OccurredAt: timestamppb.New(at),
			Body: &m1pv1.Event_CoverageTransition{CoverageTransition: &m1pv1.CoverageTransition{
				Kind: m1pv1.CoverageKind_COVERAGE_KIND_BYPASS, DurationMs: 42,
				WorkspaceId: make([]byte, 32), ReasonCode: "proxy_bypass"}}},
		{EventId: ckpt[:], OccurredAt: timestamppb.New(at),
			Body: &m1pv1.Event_ReceiptCheckpoint{ReceiptCheckpoint: &m1pv1.ReceiptCheckpoint{
				CheckpointSeq: 7, MerkleRoot: make([]byte, 32), LeafCount: 2,
				OriginSignature: make([]byte, 64), KeyId: "ed25519:abc"}}},
	}}
	effects := EffectsFromBatch(b, time.Now())
	if len(effects) != 3 {
		t.Fatalf("effects = %d, want 3", len(effects))
	}
	if effects[0].Coverage != nil || effects[0].Checkpoint != nil {
		t.Fatal("plain usage event must be a bare leaf")
	}
	c := effects[1].Coverage
	if c == nil || c.Kind != "bypass_end" || c.Reason != "proxy_bypass" || !c.OccurredAt.Equal(at) {
		t.Fatalf("coverage mapping wrong: %+v", c)
	}
	cp := effects[2].Checkpoint
	if cp == nil || cp.ClaimedCheckpointSeq != 7 || cp.LeafCount != 2 || cp.DeviceKeyID != "ed25519:abc" || !cp.IssuedAt.Equal(at) {
		t.Fatalf("checkpoint mapping wrong: %+v", cp)
	}
}

func TestCoverageKindBypassStartVsEnd(t *testing.T) {
	start := &m1pv1.CoverageTransition{Kind: m1pv1.CoverageKind_COVERAGE_KIND_BYPASS}
	end := &m1pv1.CoverageTransition{Kind: m1pv1.CoverageKind_COVERAGE_KIND_BYPASS, DurationMs: 1}
	if coverageKind(start) != "bypass_start" || coverageKind(end) != "bypass_end" {
		t.Fatalf("bypass mapping wrong: %s / %s", coverageKind(start), coverageKind(end))
	}
}
