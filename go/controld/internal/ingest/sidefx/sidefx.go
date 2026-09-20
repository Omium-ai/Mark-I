// Package sidefx is stage 11 of the ingest pipeline: post-ack Postgres
// side-effects (05 §2.1). Same posture as chproj: never affects the ack,
// every write idempotent, recoverable from the landing object via replay
// (05 §2.5).
//
// The full stage-11 list is now implemented (the C4 deferrals closed by the
// C6 receipt writer, internal/receipts):
//   - device last_seen_at — idempotent GREATEST upsert;
//   - checkpoint pending leaves — every landed event's event_id joins the
//     per-(tenant, device) pending-leaf set for the device's next checkpoint
//     (05 §2.1 stage 11), gauged as checkpoint_pending_leaves. The set is
//     in-memory ON PURPOSE: the frozen migrations define no pending-leaf
//     table, and the durable truth is the landing object — a restart loses
//     only the queue, the next checkpoint refuses (merkle_mismatch), and
//     replay from S3 re-derives it (05 §2.5's recovery contract);
//   - ReceiptCheckpoint events — verified against the pending leaves, then
//     appended to m1_receipts through the dual-sign writer (07 §checkpoint
//     model): origin signature verified, server countersignature over the
//     SAME signing input, gap-free seq under the locked head row;
//   - CoverageTransition rows — inserted in the SAME transaction as the
//     checkpoint receipt that seals them, so m1_043's NOT NULL receipt_id
//     names a receipt that provably exists.
package sidefx

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/fnv"
	"log"
	"math"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/pg"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/receipts"
	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

var (
	sidefxSeconds = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "controld_ingest_sidefx_seconds",
		Help: "Postgres side-effect duration per landed batch (05 §2.1 stage 11)",
	})
	pendingLeaves = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "controld_ingest_checkpoint_pending_leaves",
		Help: "Event ids awaiting their device's next checkpoint seal (05 §2.1 stage 11)",
	})
	checkpointsAppended = promauto.NewCounter(prometheus.CounterOpts{
		Name: "controld_ingest_checkpoints_appended_total",
		Help: "Checkpoint receipts appended to the chain (07 §checkpoint model)",
	})
	checkpointRefusals = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "controld_ingest_checkpoint_refusals_total",
		Help: "Checkpoints the chain refused, by defect code — bad_signature/unknown_key are security events (m1_002)",
	}, []string{"code"})
	coverageRows = promauto.NewCounter(prometheus.CounterOpts{
		Name: "controld_ingest_coverage_rows_total",
		Help: "coverage_transitions rows inserted (m1_043; receipted at seal time)",
	})
	excerptsBound = promauto.NewCounter(prometheus.CounterOpts{
		Name: "controld_ingest_excerpts_bound_total",
		Help: "E1 EvidenceExcerpt events bound to their redaction receipt (m1_077; FR-VERIFY-016)",
	})
	excerptRefusals = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "controld_ingest_excerpt_refusals_total",
		Help: "E1 excerpts refused at stage 11 by defect code — unknown_receipt is a security event (FR-VERIFY-016)",
	}, []string{"code"})
	deletionsAppended = promauto.NewCounter(prometheus.CounterOpts{
		Name: "controld_ingest_quarantine_deletions_appended_total",
		Help: "Edge quarantine_deletion receipts appended in their sealing checkpoint's transaction (m1_080; NFR-OPERABILITY-003)",
	})
	deletionRefusals = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "controld_ingest_quarantine_deletion_refusals_total",
		Help: "Edge QuarantineDeletion events refused at stage 11 by defect code — every code is a security event (NFR-OPERABILITY-003)",
	}, []string{"code"})
)

// DB is the WithTenant-shaped seam (05 §7.2); *pg.TenantDB satisfies it and
// unit tests fake it.
type DB interface {
	WithTenant(ctx context.Context, t querychoke.TenantID, fn func(pgx.Tx) error) error
}

// The seam stays honest at compile time: the production TenantDB IS the DB.
var _ DB = (*pg.TenantDB)(nil)

// ChainAppender is the receipt-writer seam; *receipts.Store satisfies it and
// unit tests fake it. AlreadyAppended is the replay-dedupe read: at-least-once
// ingest and 05 §2.5 S3 replay re-deliver checkpoints the chain already
// sealed, and only the chain can tell a re-delivery apart from a live
// stale-head seal (which must keep its leaves for the 08 §3.4 re-seal).
type ChainAppender interface {
	AppendCheckpoint(ctx context.Context, tenant querychoke.TenantID, ev receipts.CheckpointEvent,
		sealed func(tx pgx.Tx, r receipts.Appended) error) (receipts.Appended, error)
	AlreadyAppended(ctx context.Context, tenant querychoke.TenantID, originSig []byte) (bool, error)
	AppendServerRecordTx(ctx context.Context, tx pgx.Tx, tenant querychoke.TenantID, rec receipts.ServerRecord) (receipts.Appended, error)
}

var _ ChainAppender = (*receipts.Store)(nil)

// Security is the "+ security event" seam for chain refusals that indicate
// tampering (a signature that does not verify, a key that is not the
// device's). nil ⇒ log-only default. The record must outlive the refused
// event, hence a seam the cmd wiring can point at the projector.
type Security func(tenant, device, event uuid.UUID, detail string, at time.Time)

// Coverage is one CoverageTransition event's row-to-be (m1_043). It waits
// with its pending leaf and inserts only when a checkpoint seals it — the
// receipt_id NOT NULL discipline: no receipt, no row.
type Coverage struct {
	Kind            string // coverage_kind enum value
	WorkspaceDigest []byte // 32-byte per-tenant HMAC (m1_043 CHECK)
	OccurredAt      time.Time
	Reason          string
}

// Excerpt is one E1 EvidenceExcerpt's claim: the receipt it names and the evidence event it expands (m1_077).
type Excerpt struct {
	ReceiptID []byte
	SubjectID uuid.UUID
}

// QuarantineDeletion is the edge's on-disk deletion receipt as the wire carries it (envelope arm 23). Verified under
// the enrolled key at Apply, receipted in the chain when its checkpoint seals it (m1_080; NFR-OPERABILITY-003).
type QuarantineDeletion struct {
	BatchID         uuid.UUID
	EventCount      uint32
	QuarantinedAt   time.Time
	DeletedAt       time.Time
	Reason          string
	DeviceKeyID     string
	DeviceSignature []byte
}

// Effect is one event's stage-11 consequence, in spool order.
type Effect struct {
	EventID    uuid.UUID
	BatchID    uuid.UUID // the upload's device-minted UUIDv7: with Index, the leaf's spool order (m1_083)
	Index      int
	Coverage   *Coverage                 // CoverageTransition events
	Checkpoint *receipts.CheckpointEvent // ReceiptCheckpoint events
	Excerpt    *Excerpt                  // EvidenceExcerpt events at tier E1
	Deletion   *QuarantineDeletion       // QuarantineDeletion events
}

// EffectsFromBatch projects a decoded batch into stage-11 effects, in batch
// (= spool) order — the order the device's Merkle tree was built in.
// fallbackAt stands in for a missing device timestamp.
func EffectsFromBatch(b *m1pv1.Batch, fallbackAt time.Time) []Effect {
	effects := make([]Effect, 0, len(b.GetEvents()))
	batchID, _ := uuid.FromBytes(b.GetBatchId())
	for i, ev := range b.GetEvents() {
		id, err := uuid.FromBytes(ev.GetEventId())
		if err != nil {
			continue // stage 6 already refused these; unreachable post-ack
		}
		occurred := fallbackAt
		if ts := ev.GetOccurredAt(); ts != nil {
			occurred = ts.AsTime()
		}
		e := Effect{EventID: id, BatchID: batchID, Index: i}
		switch body := ev.GetBody().(type) {
		case *m1pv1.Event_ReceiptCheckpoint:
			cp := body.ReceiptCheckpoint
			var root [32]byte
			copy(root[:], cp.GetMerkleRoot())
			first, _ := uuid.FromBytes(cp.GetFirstEventId())
			last, _ := uuid.FromBytes(cp.GetLastEventId())
			e.Checkpoint = &receipts.CheckpointEvent{
				EventID:      id,
				DeviceKeyID:  cp.GetKeyId(),
				FirstEventID: first,
				LastEventID:  last,
				// A device may claim any uint64 here, and >MaxInt64 wraps negative. That is
				// survivable ONLY because receipts.store rejects unless the claim EQUALS the
				// tenant's next seq, which is always positive — so every wrapped value fails
				// closed. Relaxing that equality to a range check makes this narrowing live.
				ClaimedCheckpointSeq: int64(cp.GetCheckpointSeq()), //nolint:gosec // G115: see above
				MerkleRoot:           root,
				LeafCount:            int(cp.GetLeafCount()),
				OriginSig:            cp.GetOriginSignature(),
				IssuedAt:             occurred,
			}
		case *m1pv1.Event_CoverageTransition:
			ct := body.CoverageTransition
			e.Coverage = &Coverage{
				Kind:            coverageKind(ct),
				WorkspaceDigest: ct.GetWorkspaceId(),
				OccurredAt:      occurred,
				Reason:          ct.GetReasonCode(),
			}
		case *m1pv1.Event_EvidenceExcerpt:
			// E2 carries no receipt by design (VPC/self-host only); E0 has no excerpt.
			if x := body.EvidenceExcerpt; x.GetTier() == m1pv1.EvidenceTier_EVIDENCE_TIER_E1 {
				subject, _ := uuid.FromBytes(x.GetEvidenceEventId())
				e.Excerpt = &Excerpt{ReceiptID: x.GetRedactionReceiptId(), SubjectID: subject}
			}
		case *m1pv1.Event_QuarantineDeletion:
			q := body.QuarantineDeletion
			batch, _ := uuid.FromBytes(q.GetBatchId())
			e.Deletion = &QuarantineDeletion{
				BatchID: batch, EventCount: q.GetEventCount(),
				QuarantinedAt: fromMillis(q.GetQuarantinedAtMs()), DeletedAt: fromMillis(q.GetDeletedAtMs()),
				Reason: q.GetReason(), DeviceKeyID: q.GetDeviceKeyId(), DeviceSignature: q.GetDeviceSignature(),
			}
		}
		effects = append(effects, e)
	}
	return effects
}

// coverageKind maps the 3-value wire enum onto m1_043's 4-value column enum:
// a BYPASS carrying a closed-window duration is the window's END, a zero
// duration its START (intelligence.proto: duration_ms = "length of a closed
// bypass window; 0 otherwise" — the only wire fact that distinguishes them).
func coverageKind(ct *m1pv1.CoverageTransition) string {
	switch ct.GetKind() {
	case m1pv1.CoverageKind_COVERAGE_KIND_ENABLE:
		return "enable"
	case m1pv1.CoverageKind_COVERAGE_KIND_DISABLE:
		return "disable"
	case m1pv1.CoverageKind_COVERAGE_KIND_BYPASS:
		if ct.GetDurationMs() > 0 {
			return "bypass_end"
		}
		return "bypass_start"
	default:
		return ""
	}
}

type job struct {
	tenant  querychoke.TenantID
	device  uuid.UUID
	seenAt  time.Time
	edgeVer string // X-Mark1-Edge-Version; "" (replay) stamps nothing
	effects []Effect
}

type leaf struct {
	id    uuid.UUID
	batch uuid.UUID // the upload's device-minted UUIDv7: spool order across pods (m1_083)
	idx   int
	cov   *Coverage
	del   *QuarantineDeletion // verified at Apply; nil when refused
}

// Sidefx applies the per-batch side effects on a small async pool (stage 11
// rides "the same worker" tier as projection, 05 §2.1). Jobs shard onto a
// fixed worker by device id so one device's batches apply in arrival order —
// the pending-leaf set is order-bearing (the Merkle tree is built over spool
// order) and two workers interleaving one device's batches would scramble it.
type Sidefx struct {
	db       DB
	chain    ChainAppender
	security Security
	leaves   LeafStore // m1_083: shared across replicas and restarts
	queues   []chan job
	wg       sync.WaitGroup
	closed   sync.Once
}

func New(db DB, chain ChainAppender, security Security, workers, depth int) *Sidefx {
	if workers < 1 {
		workers = 1
	}
	s := &Sidefx{
		db: db, chain: chain, security: security,
		leaves: pgLeaves{db: db},
		queues: make([]chan job, workers),
	}
	if s.security == nil {
		s.security = func(tenant, device, event uuid.UUID, detail string, at time.Time) {
			log.Printf("SECURITY sidefx: tenant=%s device=%s event=%s: %s", tenant, device, event, detail)
		}
	}
	for i := range s.queues {
		s.queues[i] = make(chan job, depth/workers+1)
		s.wg.Add(1)
		go s.worker(s.queues[i])
	}
	return s
}

// queueFor shards jobs onto a fixed worker by device id (see the Sidefx
// comment: the pending-leaf set is order-bearing).
func (s *Sidefx) queueFor(device uuid.UUID) chan job {
	h := fnv.New32a()
	_, _ = h.Write(device[:])
	return s.queues[int(h.Sum32())%len(s.queues)]
}

// Enqueue schedules the batch's side effects. Non-blocking for the same
// reason as chproj.Enqueue: the ack already happened, and everything here is
// re-derivable from the landing object. edgeVer is the request's
// X-Mark1-Edge-Version ("" stamps nothing — replay has no header to carry).
func (s *Sidefx) Enqueue(tenant querychoke.TenantID, device uuid.UUID, seenAt time.Time, edgeVer string, effects []Effect) bool {
	select {
	case s.queueFor(device) <- job{tenant: tenant, device: device, seenAt: seenAt, edgeVer: edgeVer, effects: effects}:
		return true
	default:
		return false
	}
}

// EnqueueBlocking is replay's enqueue (05 §2.5). Replay is the bulk
// background path — exactly when the queues are full — and it IS the
// re-derivation of last resort: an effect dropped here has no later replay to
// recover it. So it applies backpressure instead of the request path's
// drop-and-rederive, blocking until the shard accepts the job or ctx ends,
// logging while it waits so a stalled worker is visible, not silent.
func (s *Sidefx) EnqueueBlocking(ctx context.Context, tenant querychoke.TenantID, device uuid.UUID, seenAt time.Time, effects []Effect) error {
	j := job{tenant: tenant, device: device, seenAt: seenAt, effects: effects}
	q := s.queueFor(device)
	for {
		select {
		case q <- j:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second): // bounded wait per attempt, then a progress line
			log.Printf("sidefx: replay waiting on a full stage-11 queue (device %s)", device)
		}
	}
}

func (s *Sidefx) worker(q chan job) {
	defer s.wg.Done()
	for j := range q {
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second) // §8.3 worker budget
		s.Apply(ctx, j.tenant, j.device, j.seenAt, j.edgeVer, j.effects)
		cancel()
		sidefxSeconds.Observe(time.Since(start).Seconds())
	}
}

// Apply runs one batch's stage-11 effects in order. Post-ack: every failure
// is logged and skipped, never surfaced to the edge — the durable truth is in
// S3 and replay re-derives (05 §2.5).
func (s *Sidefx) Apply(ctx context.Context, tenant querychoke.TenantID, device uuid.UUID, seenAt time.Time, edgeVer string, effects []Effect) {
	if err := s.ApplyLastSeen(ctx, tenant, device, seenAt, edgeVer); err != nil {
		log.Printf("sidefx: last_seen update failed (tenant %s): %v", tenant, err)
	}
	// Leaves land BEFORE any checkpoint in the batch is applied: a checkpoint seals the batch before it, and its own batch's leaves must be in the store when the next one arrives on whichever pod.
	var landed []leaf
	for i := range effects {
		e := &effects[i]
		if e.Checkpoint != nil {
			continue
		}
		if e.Excerpt != nil {
			s.applyExcerpt(ctx, tenant, device, e.EventID, e.Excerpt)
		}
		var del *QuarantineDeletion
		if e.Deletion != nil && s.verifyDeletion(ctx, tenant, device, e.EventID, e.Deletion) {
			del = e.Deletion
		}
		// Every non-checkpoint landed event is a leaf of the device's NEXT
		// checkpoint; the checkpoint announcement itself is sealed AFTER its
		// tree and is deliberately not a leaf of any tree.
		landed = append(landed, leaf{id: e.EventID, batch: e.BatchID, idx: e.Index, cov: e.Coverage, del: del})
	}
	if err := s.leaves.Add(ctx, tenant, device, landed); err != nil {
		log.Printf("sidefx: leaves not landed (tenant %s, %d leaves): %v — replay re-derives (05 §2.5)", tenant, len(landed), err)
		return
	}
	pendingLeaves.Add(float64(len(landed)))
	for i := range effects {
		if cp := effects[i].Checkpoint; cp != nil {
			s.applyCheckpoint(ctx, tenant, device, cp)
		}
	}
}

// SetLeafStore swaps the m1_083 store for another (tests: NewMemoryLeafStore); call before the first Apply.
func (s *Sidefx) SetLeafStore(l LeafStore) { s.leaves = l }

// PendingLeafCount reports one device's unconsumed leaves (tests).
func (s *Sidefx) PendingLeafCount(tenant querychoke.TenantID, device uuid.UUID) int {
	w, err := s.leaves.Window(context.Background(), tenant, device, uuid.Nil, uuid.Nil, math.MaxInt32)
	if err != nil {
		return -1
	}
	return len(w)
}

// leafWindowRetries × leafWindowWait bounds how long a checkpoint waits for its own batch's leaves to land from another pod (stage 10–11 are post-ack and async on whichever pod acked).
const (
	leafWindowRetries = 8
	leafWindowWait    = 500 * time.Millisecond
	leafKeep          = 7 * 24 * time.Hour
)

func (s *Sidefx) applyCheckpoint(ctx context.Context, tenant querychoke.TenantID, device uuid.UUID, cp *receipts.CheckpointEvent) {
	cp.DeviceID = device // identity comes from verified claims, never the event (08 §2.1)

	// A checkpoint re-delivered AFTER its original seal (at-least-once ingest, 05 §2.5 replay) is a duplicate, not a defect. Its leaves are consumed already — unless replay re-landed them into a store that had lost them (the table's first day, a restore), where they would head every later window and wedge the device behind merkle_mismatch: a window that IS this seal's tree is consumed as the seal would have.
	if dup, dupErr := s.chain.AlreadyAppended(ctx, tenant, cp.OriginSig); dupErr == nil && dup {
		if w, err := s.leaves.Window(ctx, tenant, device, cp.FirstEventID, cp.LastEventID, cp.LeafCount); err == nil && len(w) == cp.LeafCount {
			ids := make([]uuid.UUID, len(w))
			leaves := make([][]byte, len(w))
			for i, l := range w {
				ids[i], leaves[i] = l.id, l.id[:]
			}
			if root, err := receipts.MerkleRoot(leaves); err == nil && root == cp.MerkleRoot {
				if err := s.leaves.Consume(ctx, nil, tenant, device, ids, cp.ClaimedCheckpointSeq); err != nil {
					log.Printf("sidefx: checkpoint %s replayed prefix not consumed: %v", cp.EventID, err)
				} else {
					log.Printf("sidefx: checkpoint %s already in the chain; replayed prefix consumed", cp.EventID)
					return
				}
			}
		}
		log.Printf("sidefx: checkpoint %s already in the chain; duplicate delivery skipped", cp.EventID)
		return
	}
	if cp.LeafCount <= 0 {
		checkpointRefusals.WithLabelValues(string(receipts.DefectMerkleMismatch)).Inc()
		log.Printf("sidefx: checkpoint %s refused: seal claims %d leaves", cp.EventID, cp.LeafCount)
		return
	}
	// The seal's leaves are the device's landed leaves from its first to its last id in spool order, exactly LeafCount of them (a seal that names no ids: the oldest LeafCount unconsumed). Short ⇒ the batch before this one is still landing on another pod: wait, bounded. A leaf an earlier refused seal orphaned at the head sits outside the span and shifts nothing.
	var sealed []leaf
	for try := 0; ; try++ {
		w, err := s.leaves.Window(ctx, tenant, device, cp.FirstEventID, cp.LastEventID, cp.LeafCount)
		if err != nil {
			log.Printf("sidefx: checkpoint %s: leaf window read failed: %v (replay re-derives)", cp.EventID, err)
			return
		}
		if len(w) == cp.LeafCount && (cp.LastEventID == uuid.Nil || w[len(w)-1].id == cp.LastEventID) {
			sealed = w
			break
		}
		if try >= leafWindowRetries || ctx.Err() != nil {
			// Fail-closed on integrity: no countersignature over a tree we cannot recompute; replay from the landing objects re-derives the set (05 §2.5).
			checkpointRefusals.WithLabelValues(string(receipts.DefectMerkleMismatch)).Inc()
			log.Printf("sidefx: checkpoint %s refused: %d leaf(s) landed, seal claims %d ending at %s (replay re-derives)",
				cp.EventID, len(w), cp.LeafCount, cp.LastEventID)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(leafWindowWait):
		}
	}
	leaves := make([][]byte, len(sealed))
	ids := make([]uuid.UUID, len(sealed))
	for i, l := range sealed {
		id := l.id
		leaves[i] = id[:]
		ids[i] = l.id
	}
	root, err := receipts.MerkleRoot(leaves)
	if err != nil || root != cp.MerkleRoot {
		// Same dedupe-first rule as above: after a restart+replay the queue
		// prefix can be a LATER tree than a re-delivered old seal — paging
		// security on that would alarm on every honest replay.
		if dup, dupErr := s.chain.AlreadyAppended(ctx, tenant, cp.OriginSig); dupErr == nil && dup {
			log.Printf("sidefx: checkpoint %s already in the chain; duplicate delivery skipped", cp.EventID)
			return
		}
		// The device signed a tree that is not the tree of what it uploaded —
		// tampering or a corrupted spool; either way a security event, and
		// the pending set stays for diagnosis/replay.
		checkpointRefusals.WithLabelValues(string(receipts.DefectMerkleMismatch)).Inc()
		s.security(tenant.UUID(), device, cp.EventID,
			"checkpoint merkle_root does not match the root over the landed leaves (merkle_mismatch)", time.Now())
		return
	}

	_, err = s.chain.AppendCheckpoint(ctx, tenant, *cp, func(tx pgx.Tx, r receipts.Appended) error {
		// Same-tx coverage inserts: receipt_id now provably exists (m1_043's
		// NOT NULL). ON CONFLICT (event_id) DO NOTHING keeps at-least-once
		// ingest from double-counting a gap (m1_043's UNIQUE comment).
		for _, l := range sealed {
			if l.cov == nil || l.cov.Kind == "" {
				continue
			}
			tag, err := tx.Exec(ctx, `
				INSERT INTO coverage_transitions
				  (tenant_id, device_id, workspace_digest, kind, occurred_at, event_id, reason, receipt_id)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
				ON CONFLICT (event_id) DO NOTHING`,
				tenant.UUID(), device, l.cov.WorkspaceDigest, l.cov.Kind,
				l.cov.OccurredAt.UTC(), l.id, l.cov.Reason, r.ReceiptID)
			if err != nil {
				return err
			}
			coverageRows.Add(float64(tag.RowsAffected()))
		}
		// Same-tx deletion receipts: the edge's receipt lands right behind the checkpoint that sealed its leaf.
		for _, l := range sealed {
			if l.del != nil {
				if err := s.appendDeletion(ctx, tx, tenant, l.del); err != nil {
					return err
				}
			}
		}
		// Consumed in the seal's own transaction: a refused or failed seal leaves the set intact for the re-seal or the replay; a consumed leaf stays consumed, so a replayed batch never re-enters it (idempotent on event_id, 05 §2.1 stage 11).
		return s.leaves.Consume(ctx, tx, tenant, device, ids, r.Seq)
	})
	switch refusal, isRefusal := receipts.AsRefusal(err); {
	case err == nil:
		checkpointsAppended.Inc()
		pendingLeaves.Sub(float64(cp.LeafCount))
		if err := s.leaves.Sweep(ctx, tenant, leafKeep); err != nil {
			log.Printf("sidefx: leaf sweep failed (tenant %s): %v", tenant, err)
		}
	case isRefusal:
		checkpointRefusals.WithLabelValues(string(refusal.Code)).Inc()
		if refusal.Code == receipts.DefectBadSignature || refusal.Code == receipts.DefectUnknownKey {
			// A signature that does not verify or a key that is not this
			// device's is tampering-shaped, not staleness-shaped.
			s.security(tenant.UUID(), device, cp.EventID, refusal.Detail, time.Now())
		} else {
			// broken_link = the device sealed against a stale head: an
			// expected retry semantic, logged but never paged.
			log.Printf("sidefx: checkpoint %s refused: %s", cp.EventID, refusal.Detail)
		}
	default:
		// Infrastructure failure post-ack: log and move on; the landing
		// object replays this checkpoint (05 §2.5).
		log.Printf("sidefx: checkpoint append failed (tenant %s): %v", tenant, err)
	}
}

// applyExcerpt binds an E1 excerpt once to the receipt it names (m1_077); any other claim is a security event.
func (s *Sidefx) applyExcerpt(ctx context.Context, tenant querychoke.TenantID, device uuid.UUID, event uuid.UUID, x *Excerpt) {
	if len(x.ReceiptID) != 32 || x.SubjectID == uuid.Nil {
		excerptRefusals.WithLabelValues("malformed").Inc()
		s.security(tenant.UUID(), device, event, "E1 excerpt without a 32-byte redaction_receipt_id and evidence_event_id (FR-VERIFY-016)", time.Now())
		return
	}
	var bound int64
	err := s.db.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE m1_redaction_receipts SET excerpt_event_id = $1
			 WHERE tenant_id = $2 AND device_id = $3 AND receipt_id = $4 AND subject_id = $5
			   AND (excerpt_event_id IS NULL OR excerpt_event_id = $1)`,
			event, tenant.UUID(), device, x.ReceiptID, x.SubjectID)
		bound = tag.RowsAffected()
		return err
	})
	switch {
	case err != nil:
		log.Printf("sidefx: excerpt %s receipt bind failed (tenant %s): %v", event, tenant, err)
	case bound == 0:
		excerptRefusals.WithLabelValues("unknown_receipt").Inc()
		s.security(tenant.UUID(), device, event,
			"E1 excerpt names a redaction receipt this device never uploaded for that evidence event (unknown_receipt, FR-VERIFY-016)", time.Now())
	default:
		excerptsBound.Inc()
	}
}

// AdmitRedactionReceipt is the attach upload's receipt half (08 §2.1): verified under the enrolled key like a checkpoint, stored once.
func (s *Sidefx) AdmitRedactionReceipt(ctx context.Context, tenant querychoke.TenantID, device uuid.UUID, payloadText string, deviceSig []byte) ([32]byte, error) {
	var id [32]byte
	decoded, err := receipts.DecodePayload([]byte(payloadText))
	fields, _ := decoded.(map[string]any)
	if err != nil || fields == nil {
		return id, &receipts.RefusalError{Code: receipts.DefectNonCanonicalPayload, Detail: "redaction payload is not a JSON object"}
	}
	if canon, cerr := receipts.CanonicalJSON(decoded); cerr != nil || canon != payloadText {
		return id, &receipts.RefusalError{Code: receipts.DefectNonCanonicalPayload, Detail: "redaction payload is not its own canonical form"}
	}
	str := func(k string) string { v, _ := fields[k].(string); return v }
	subject, serr := uuid.Parse(str("subject_id"))
	pre, perr := hex.DecodeString(str("pre_hash"))
	post, qerr := hex.DecodeString(str("post_hash"))
	switch {
	case str("type") != "redaction" || str("tier") != "E1":
		return id, &receipts.RefusalError{Code: receipts.DefectPayloadMismatch, Detail: "payload is not a tier-E1 redaction receipt"}
	case str("tenant_id") != tenant.String() || str("device_id") != device.String():
		return id, &receipts.RefusalError{Code: receipts.DefectPayloadMismatch, Detail: "payload names a tenant or device other than the authenticated one (08 §2.1)"}
	case serr != nil || subject == uuid.Nil || perr != nil || len(pre) != 32 || qerr != nil || len(post) != 32:
		return id, &receipts.RefusalError{Code: receipts.DefectPayloadMismatch, Detail: "payload lacks a subject_id or 32-byte pre_hash/post_hash"}
	}
	keyID := str("device_key_id")
	signingInput := append([]byte(receipts.DomainPrefix), payloadText...)
	id = sha256.Sum256(signingInput)
	return id, s.db.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		pub, err := deviceOriginKey(ctx, tx, keyID, device)
		if err != nil {
			return err
		}
		if !receipts.Verify(pub, deviceSig, signingInput) {
			return &receipts.RefusalError{Code: receipts.DefectBadSignature, Detail: "origin signature does not verify over the redaction payload"}
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO m1_redaction_receipts
			  (tenant_id, receipt_id, device_id, device_key_id, device_signature, subject_id, payload, pre_hash, post_hash)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (tenant_id, receipt_id) DO NOTHING`,
			tenant.UUID(), id[:], device, keyID, deviceSig, subject, payloadText, pre, post)
		return err
	})
}

// deviceOriginKey is the enrolled-key lookup every device-signed claim at this stage shares (the AppendCheckpoint
// shape): the wrong table's key, a revoked key and another device's key are refusals with their own names.
func deviceOriginKey(ctx context.Context, tx pgx.Tx, keyID string, device uuid.UUID) (ed25519.PublicKey, error) {
	var pub []byte
	var keyDevice uuid.UUID
	var revokedAt *time.Time
	switch err := tx.QueryRow(ctx,
		`SELECT public_key, device_id, revoked_at FROM m1_device_keys WHERE key_id = $1`, keyID).
		Scan(&pub, &keyDevice, &revokedAt); {
	case errors.Is(err, pgx.ErrNoRows):
		return nil, &receipts.RefusalError{Code: receipts.DefectUnknownKey, Detail: fmt.Sprintf("key_id %q is not a device origin key for this tenant", keyID)}
	case err != nil:
		return nil, err
	case keyDevice != device:
		return nil, &receipts.RefusalError{Code: receipts.DefectUnknownKey, Detail: fmt.Sprintf("key_id %q belongs to device %s, not the authenticated device", keyID, keyDevice)}
	case revokedAt != nil:
		return nil, &receipts.RefusalError{Code: receipts.DefectUnknownKey, Detail: fmt.Sprintf("key_id %q was revoked at %s; it signs nothing new", keyID, revokedAt.UTC().Format(time.RFC3339))}
	}
	return ed25519.PublicKey(pub), nil
}

// DeletionReason is the one closed value the wire may carry (events.proto: free text never rides here).
const DeletionReason = "retention_30d"

func fromMillis(ms uint64) time.Time {
	if ms > math.MaxInt64 {
		return time.Time{}
	}
	return time.UnixMilli(int64(ms)).UTC()
}

// MillisString is the edge receipt's timestamp rendering (uplink/retention.go MillisString): whole milliseconds
// through RFC3339Nano, so the signed bytes rebuild from the wire's unix ms exactly.
func MillisString(t time.Time) string {
	return t.UTC().Truncate(time.Millisecond).Format(time.RFC3339Nano)
}

// DeletionPayload rebuilds the edge's signed receipt payload from the wire fields and the VERIFIED identity — the
// checkpoint discipline (07 §checkpoint model): the device never sends payload text, the server reconstructs it.
func DeletionPayload(tenant, device string, d *QuarantineDeletion) map[string]any {
	return map[string]any{
		"v":              1,
		"type":           "quarantine_deletion",
		"batch_id":       d.BatchID.String(),
		"event_count":    int(d.EventCount),
		"quarantined_at": MillisString(d.QuarantinedAt),
		"deleted_at":     MillisString(d.DeletedAt),
		"reason":         d.Reason,
		"tenant_id":      tenant,
		"device_id":      device,
		"device_key_id":  d.DeviceKeyID,
	}
}

// verifyDeletion checks the edge's signature under its enrolled key before the leaf waits for its checkpoint. Every
// refusal is a security event and a counter, never a silent skip: a forged deletion claim is tampering-shaped.
func (s *Sidefx) verifyDeletion(ctx context.Context, tenant querychoke.TenantID, device, event uuid.UUID, d *QuarantineDeletion) bool {
	refuse := func(code receipts.Defect, detail string) bool {
		deletionRefusals.WithLabelValues(string(code)).Inc()
		s.security(tenant.UUID(), device, event, "QuarantineDeletion refused ("+string(code)+"): "+detail, time.Now())
		return false
	}
	if d.BatchID == uuid.Nil || d.DeviceKeyID == "" || len(d.DeviceSignature) != ed25519.SignatureSize ||
		d.Reason != DeletionReason || d.QuarantinedAt.IsZero() || d.DeletedAt.IsZero() {
		return refuse(receipts.DefectPayloadMismatch, "batch_id, device_key_id, a 64-byte signature, reason retention_30d and both timestamps are required")
	}
	text, err := receipts.CanonicalJSON(DeletionPayload(tenant.String(), device.String(), d))
	if err != nil {
		return refuse(receipts.DefectNonCanonicalPayload, err.Error())
	}
	signingInput := append([]byte(receipts.DomainPrefix), text...)
	err = s.db.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		pub, err := deviceOriginKey(ctx, tx, d.DeviceKeyID, device)
		if err != nil {
			return err
		}
		if !receipts.Verify(pub, d.DeviceSignature, signingInput) {
			return &receipts.RefusalError{Code: receipts.DefectBadSignature, Detail: "device signature does not verify over the reconstructed deletion receipt"}
		}
		return nil
	})
	if refusal, ok := receipts.AsRefusal(err); ok {
		return refuse(refusal.Code, refusal.Detail)
	}
	if err != nil {
		log.Printf("sidefx: quarantine deletion %s key lookup failed (tenant %s): %v", event, tenant, err) // replay re-derives
		return false
	}
	return true
}

// appendDeletion writes the edge's receipt as a quarantine_deletion server record inside the sealing checkpoint's
// transaction. The idempotency key absorbs a replayed leaf whose earlier seal already landed the record.
func (s *Sidefx) appendDeletion(ctx context.Context, tx pgx.Tx, tenant querychoke.TenantID, d *QuarantineDeletion) error {
	key := "edge:" + d.BatchID.String()
	var one int
	err := tx.QueryRow(ctx, `SELECT 1 FROM m1_receipts WHERE record_type = 'quarantine_deletion' AND idempotency_key = $1`, key).Scan(&one)
	if err == nil {
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	_, err = s.chain.AppendServerRecordTx(ctx, tx, tenant, receipts.ServerRecord{
		RecordType: "quarantine_deletion",
		SubjectID:  d.BatchID,
		IssuedAt:   d.DeletedAt,
		Fields: map[string]any{
			"origin": "edge", "reason": d.Reason, "event_count": int(d.EventCount),
			"quarantined_at": MillisString(d.QuarantinedAt), "deleted_at": MillisString(d.DeletedAt),
			"device_key_id": d.DeviceKeyID,
		},
		IdempotencyKey: key,
	})
	if err == nil {
		deletionsAppended.Inc()
	}
	return err
}

// ApplyLastSeen stamps m1_devices.last_seen_at under the tenant GUC. GREATEST
// makes it idempotent AND replay-safe: re-applying an old batch can never
// move the timestamp backwards (05 §2.1: "all idempotent upserts").
// edge_version (m1_061; 08 §3.1's device list) rides the same UPDATE from
// X-Mark1-Edge-Version (08 §10.1: recorded, never rejected on): "" — the
// replay path, whose header died with the original request — stamps nothing,
// which is what keeps the write replay-idempotent.
// ponytail: live traffic is last-write-wins with no semver ordering; two
// interleaved versions from one device converge on the next batch.
func (s *Sidefx) ApplyLastSeen(ctx context.Context, tenant querychoke.TenantID, device uuid.UUID, seenAt time.Time, edgeVer string) error {
	return s.db.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`UPDATE m1_devices
			    SET last_seen_at = GREATEST(COALESCE(last_seen_at, 'epoch'::timestamptz), $2),
			        edge_version = COALESCE(NULLIF($3, ''), edge_version)
			  WHERE id = $1`,
			device, seenAt, edgeVer)
		return err
	})
}

// Close drains and stops (05 §1.5 step 4).
func (s *Sidefx) Close() {
	s.closed.Do(func() {
		for _, q := range s.queues {
			close(q)
		}
	})
	s.wg.Wait()
}
