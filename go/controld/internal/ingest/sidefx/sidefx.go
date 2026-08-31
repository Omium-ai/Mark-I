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
	"hash/fnv"
	"log"
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

// Effect is one event's stage-11 consequence, in spool order.
type Effect struct {
	EventID    uuid.UUID
	Coverage   *Coverage                 // CoverageTransition events
	Checkpoint *receipts.CheckpointEvent // ReceiptCheckpoint events
}

// EffectsFromBatch projects a decoded batch into stage-11 effects, in batch
// (= spool) order — the order the device's Merkle tree was built in.
// fallbackAt stands in for a missing device timestamp.
func EffectsFromBatch(b *m1pv1.Batch, fallbackAt time.Time) []Effect {
	effects := make([]Effect, 0, len(b.GetEvents()))
	for _, ev := range b.GetEvents() {
		id, err := uuid.FromBytes(ev.GetEventId())
		if err != nil {
			continue // stage 6 already refused these; unreachable post-ack
		}
		occurred := fallbackAt
		if ts := ev.GetOccurredAt(); ts != nil {
			occurred = ts.AsTime()
		}
		e := Effect{EventID: id}
		switch body := ev.GetBody().(type) {
		case *m1pv1.Event_ReceiptCheckpoint:
			cp := body.ReceiptCheckpoint
			var root [32]byte
			copy(root[:], cp.GetMerkleRoot())
			e.Checkpoint = &receipts.CheckpointEvent{
				EventID:     id,
				DeviceKeyID: cp.GetKeyId(),
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

type pendKey struct{ tenant, device uuid.UUID }

type leaf struct {
	id  uuid.UUID
	cov *Coverage
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
	queues   []chan job
	wg       sync.WaitGroup
	closed   sync.Once

	mu      sync.Mutex
	pending map[pendKey][]leaf
	seen    map[pendKey]map[uuid.UUID]bool // pending-set dedupe: idempotent on event_id (05 §2.1)
}

func New(db DB, chain ChainAppender, security Security, workers, depth int) *Sidefx {
	if workers < 1 {
		workers = 1
	}
	s := &Sidefx{
		db: db, chain: chain, security: security,
		queues:  make([]chan job, workers),
		pending: map[pendKey][]leaf{},
		seen:    map[pendKey]map[uuid.UUID]bool{},
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
	for i := range effects {
		e := &effects[i]
		if e.Checkpoint != nil {
			s.applyCheckpoint(ctx, tenant, device, e.Checkpoint)
			continue
		}
		// Every non-checkpoint landed event is a leaf of the device's NEXT
		// checkpoint; the checkpoint announcement itself is sealed AFTER its
		// tree and is deliberately not a leaf of any tree.
		s.addLeaf(tenant, device, leaf{id: e.EventID, cov: e.Coverage})
	}
}

func (s *Sidefx) addLeaf(tenant querychoke.TenantID, device uuid.UUID, l leaf) {
	k := pendKey{tenant: tenant.UUID(), device: device}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seen[k] == nil {
		s.seen[k] = map[uuid.UUID]bool{}
	}
	if s.seen[k][l.id] {
		return // replayed batch: the leaf is already pending (idempotent on event_id)
	}
	s.seen[k][l.id] = true
	s.pending[k] = append(s.pending[k], l)
	pendingLeaves.Inc()
}

// PendingLeafCount reports one device's queue depth (tests; checkpoint_hint
// would read the same number).
func (s *Sidefx) PendingLeafCount(tenant querychoke.TenantID, device uuid.UUID) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pending[pendKey{tenant: tenant.UUID(), device: device}])
}

func (s *Sidefx) applyCheckpoint(ctx context.Context, tenant querychoke.TenantID, device uuid.UUID, cp *receipts.CheckpointEvent) {
	cp.DeviceID = device // identity comes from verified claims, never the event (08 §2.1)

	k := pendKey{tenant: tenant.UUID(), device: device}
	s.mu.Lock()
	queue := s.pending[k]
	s.mu.Unlock()

	if len(queue) < cp.LeafCount || cp.LeafCount <= 0 {
		// Before refusing, ask the chain: a checkpoint re-delivered AFTER its
		// original seal consumed the leaves (at-least-once ingest, 05 §2.5
		// replay) arrives with a short — or foreign — queue and is a
		// duplicate, not a defect.
		if dup, dupErr := s.chain.AlreadyAppended(ctx, tenant, cp.OriginSig); dupErr == nil && dup {
			log.Printf("sidefx: checkpoint %s already in the chain; duplicate delivery skipped", cp.EventID)
			return
		}
		// A restart emptied the queue (or the seal names events this server
		// never landed). Fail-closed on integrity: no countersignature over a
		// tree we cannot recompute; replay from the landing objects re-derives
		// the set (05 §2.5).
		checkpointRefusals.WithLabelValues(string(receipts.DefectMerkleMismatch)).Inc()
		log.Printf("sidefx: checkpoint %s refused: %d leaf(s) pending, seal claims %d (replay re-derives)",
			cp.EventID, len(queue), cp.LeafCount)
		return
	}
	sealed := queue[:cp.LeafCount]
	leaves := make([][]byte, len(sealed))
	for i, l := range sealed {
		id := l.id
		leaves[i] = id[:]
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
		return nil
	})
	consume := func() {
		s.mu.Lock()
		s.pending[k] = s.pending[k][cp.LeafCount:]
		s.mu.Unlock()
		pendingLeaves.Sub(float64(cp.LeafCount))
	}
	switch refusal, isRefusal := receipts.AsRefusal(err); {
	case err == nil:
		checkpointsAppended.Inc()
		// Consume ONLY on success or proven-duplicate (below): a refused or
		// failed seal leaves the set intact so a re-seal or replay can still
		// land it. Sealed ids STAY in `seen` — a replayed batch must not
		// re-enter already-sealed leaves into the next tree (idempotent on
		// event_id, 05 §2.1 stage 11).
		// ponytail: seen grows per device for the process lifetime; add an
		// epoch sweep if a long-lived pod's memory ever notices.
		consume()
	case isRefusal:
		// A restart erased `seen`, replay re-admitted the sealed leaves, and
		// this is their checkpoint coming around again: the local root check
		// above proved the queue prefix IS this seal's leaf set, and the
		// chain holding the identical origin signature proves the seal
		// already landed. Consume the prefix exactly as success would have —
		// left in place it offsets queue[:LeafCount] for every later honest
		// seal, wedging the device behind endless merkle_mismatch pages. A
		// live stale-head seal (raced by another device) is NOT in the chain
		// and falls through: its leaves stay for the 08 §3.4 re-seal.
		if dup, dupErr := s.chain.AlreadyAppended(ctx, tenant, cp.OriginSig); dupErr == nil && dup {
			log.Printf("sidefx: checkpoint %s already in the chain; replayed prefix consumed", cp.EventID)
			consume()
			return
		}
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
