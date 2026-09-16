// The gate-facing half of 04 §2.3: the lock-free snapshot cache the stop-gate
// reads, the knee governor evaluated at cache-publish time (never at gate
// time), the block counters behind the local hard caps, and the Engine whose
// recompute goroutine is the only holder of a Fuser. Wiring fusion into a gate
// path would require changing fabric.NewGate's verdict.Reader parameter to
// something that exposes Fuse — a visible API change, which is the point.
package verdict

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

// KneeState is the knee-governor evaluation frozen at publish time so the
// gate read stays a lookup (04 §2.3): stop when p̂_LCB(n)·V(task) ≤ c(n),
// c(n) under the bundle cost_basis.
type KneeState struct {
	N         int     // attempt index the evaluation was made at
	PLCB      float64 // p̂_LCB(n): 95% Wilson LCB of the attempt-n success rate
	VTask     float64 // V(task)
	CostN     float64 // c(n) under CostBasis
	CostBasis string  // "usd" | "quota"
	Stop      bool    // p̂_LCB(n)·V(task) ≤ c(n) — the governor says stop
	Stale     bool    // M1E-3006 posture: gates answer allow, verdict flagged stale_cert
	// Evaluable distinguishes "the inequality was computed and did not hold"
	// from "there was nothing to compute" (no knee table, n below the first row
	// D-Y(b), or an absent p_lcb D-Z). All three answer Stop = false, and a
	// reader that cannot tell them apart reads the absent case as
	// certainly-hopeless — the exact reading frombundle.go exists to forbid.
	Evaluable bool
}

// BlockCounters is the per-entry snapshot of the local hard-cap counters at
// publish time (04 §2.3).
type BlockCounters struct {
	Consecutive uint32 // consecutive blocks for this task
	Hourly      uint32 // blocks across this SESSION's tasks in the current hour window
}

// Cached is one gate-readable entry (04 §2.3).
type Cached struct {
	Verdict *m1pv1.VerdictEvent // stage: PROVISIONAL (or REVISED, superseding)
	Knee    KneeState
	// Blocks carries Consecutive only: Hourly is per session (D-AN(a)) and the
	// publisher knows the task, not the session. The gate reads both LIVE.
	Blocks BlockCounters
	// UnknownVoters is D-X's accounting: votes from verifiers the bundle does
	// not list. They contribute no likelihood — and are not silently dropped.
	UnknownVoters uint32
	ComputedAt    time.Time
}

// Cache is what gates read: writers publish via atomic.Pointer swap
// (copy-on-publish); readers never block and never trigger computation.
type Cache struct {
	p atomic.Pointer[map[TaskID]Cached]
}

func NewCache() *Cache {
	c := &Cache{}
	m := map[TaskID]Cached{}
	c.p.Store(&m)
	return c
}

func (c *Cache) Get(id TaskID) (Cached, bool) {
	e, ok := (*c.p.Load())[id]
	return e, ok
}

// publish is copy-on-write and unexported: only the Engine's recompute
// goroutine publishes. ponytail: O(entries) copy per publish and no eviction —
// an entry-count sweep when long sessions accumulate enough tasks to matter.
func (c *Cache) publish(id TaskID, e Cached) {
	old := *c.p.Load()
	m := make(map[TaskID]Cached, len(old)+1)
	for k, v := range old {
		m[k] = v
	}
	m[id] = e
	c.p.Store(&m)
}

// Reader is the ONLY interface the fabric's GateQuery handler receives.
// It has no method that computes anything.
type Reader interface{ Get(TaskID) (Cached, bool) }

// Blocks is the live hard-cap tracker: the gate handler records its
// decisions, the Engine snapshots it into Cached at publish. Its own mutex —
// the one mutable thing here with two writers, both O(1) and never across I/O.
// D-AN(a): the hourly ceiling is keyed by SESSION. Unkeyed it was machine-wide,
// so one session burning 30 blocks answered M1E-5002 allow for every other
// session on the box until the window rolled — and because that fails toward
// allow, nothing ever complained.
type Blocks struct {
	mu          sync.Mutex
	consecutive map[TaskID]uint32
	hourStart   time.Time
	hourly      map[[16]byte]uint32
}

func NewBlocks() *Blocks {
	return &Blocks{consecutive: map[TaskID]uint32{}, hourly: map[[16]byte]uint32{}}
}

func (b *Blocks) RecordBlock(session [16]byte, t TaskID, now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.roll(now)
	b.consecutive[t]++
	b.hourly[session]++
}

// ResetTask clears the task's consecutive streak. D-Y: the streak resets on
// any cache publish for that task (new evidence, PROVISIONAL or REVISED) and
// on task close — "consecutive" means consecutive blocks ON THE SAME EVIDENCE.
func (b *Blocks) ResetTask(t TaskID) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.consecutive, t)
}

// RecordAllow is deliberately a NO-OP. D-Y: an allow never resets the streak —
// the cap short-circuits before the cache read, so an allow carries no
// evidence. Kept only so the gate handler (whose call order is normative,
// 04 §2.3) still compiles; the call site and this method are deleted together.
func (b *Blocks) RecordAllow(TaskID) {}

func (b *Blocks) Counters(session [16]byte, t TaskID, now time.Time) BlockCounters {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.roll(now)
	return BlockCounters{Consecutive: b.consecutive[t], Hourly: b.hourly[session]}
}

// ConsecutiveFor is the publish-time snapshot the Engine can honestly take: it
// knows the task, and since D-AN(a) the hourly window belongs to a session it
// has no handle on.
func (b *Blocks) ConsecutiveFor(t TaskID) uint32 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.consecutive[t]
}

// roll implements the hourly window under b.mu.
// ponytail: fixed window, not sliding — a burst straddling the boundary can
// see up to 2× the ceiling; a ring of timestamps if that ever matters.
func (b *Blocks) roll(now time.Time) {
	if now.Sub(b.hourStart) >= time.Hour {
		b.hourStart = now
		clear(b.hourly)
	}
}

// kneeFor evaluates the governor for attempt n against the bundle's knee
// table (ascending n; lookup clamps to the LAST row). No table or a stale
// bundle ⇒ never stop — fail-static then fail-open (04 §2.3).
//
// D-Y(b): n below the first row does NOT clamp up to it — you cannot be past
// the knee before the first attempt exists, and row 1's economics are not a
// conservative default for attempt 0. D-Z: a row with no p_lcb is not
// evaluable at that n. Both answer Stop = false.
func kneeFor(m *BundleMatrices, n int) KneeState {
	k := KneeState{N: n, VTask: m.VTask, CostBasis: m.CostBasis, Stale: m.Stale}
	if len(m.Knee) == 0 || n < m.Knee[0].N {
		return k
	}
	row := m.Knee[0]
	for _, r := range m.Knee {
		if r.N > n {
			break
		}
		row = r
	}
	k.CostN = row.CostN
	if row.PLCB == nil {
		return k
	}
	k.PLCB = *row.PLCB
	k.Evaluable = true
	k.Stop = !m.Stale && k.PLCB*k.VTask <= k.CostN
	return k
}

// Correction is 04 §2.3's next-turn correction: a REVISED verdict differing from the one the gate answered on.
type Correction struct {
	Task              TaskID
	Previous, Revised m1pv1.Verdict
}

// job is one recompute request. Attempt is the retry index n the knee is
// evaluated at — the caller (anchor orchestration) owns attempt counting.
type job struct {
	task    TaskID
	votes   []AnchorVote
	attempt int
	revised bool
}

// Engine owns the recompute goroutine — the exclusive writer of the cache
// (04 §8.1). The Fuser lives only inside Run/step; no Engine method returns
// it, so the fabric can only ever be handed the Reader.
type Engine struct {
	cache  *Cache
	blocks *Blocks
	m      atomic.Pointer[BundleMatrices]
	fast   chan job // depth 1, latest-wins: the PostToolUse debounce (04 §8.2)
	slow   chan job // REVISED completions: blocking send, never dropped
	now    func() time.Time

	// Emit is the D-AM(R3) seam: an adjudicated verdict is admitted as an
	// Event, which is the only way a task can ever close RESOLUTION_VERDICT
	// (taskseg, 04 §9.2). Without it 100% of the TVO denominator is unresolved
	// no matter what the gate served. Set once before Run; nil is legal (the
	// cache is still published, nothing is recorded).
	//
	// PROVISIONAL publishes are NOT emitted: 04 §9.2 makes them ACTIVE→ACTIVE
	// recomputes, and one debounced billing-grade event per keystroke is not a
	// record of anything. They still resolve the denominator — D-AS has the
	// segmenter read this cache at task close, which is once per task.
	Emit func(context.Context, *m1pv1.VerdictEvent, TaskID)
	// SessionFor scopes a Correction to the session whose next PostToolUse pulls it; nil, or a miss, queues nothing.
	SessionFor func(TaskID) ([16]byte, bool)

	cmu         sync.Mutex
	corrections map[[16]byte][]Correction
}

func NewEngine(m BundleMatrices, blocks *Blocks, now func() time.Time) *Engine {
	if now == nil {
		now = time.Now
	}
	e := &Engine{
		cache:  NewCache(),
		blocks: blocks,
		fast:   make(chan job, 1),
		slow:   make(chan job, 16),
		now:    now,

		corrections: map[[16]byte][]Correction{},
	}
	e.m.Store(&m)
	return e
}

// Reader is the one handle the gate path gets.
func (e *Engine) Reader() Reader { return e.cache }

// SetBundle swaps the matrices on policy apply; the recompute goroutine loads
// the pointer per job, so no job fuses under a torn bundle.
func (e *Engine) SetBundle(m BundleMatrices) { e.m.Store(&m) }

// Recompute is the debounced fast-anchor trigger: depth-1, latest-wins.
// A superseded pending job is correct to drop — fusion over stale votes is
// repaired by the newest trigger (04 §8.2).
func (e *Engine) Recompute(task TaskID, votes []AnchorVote, attempt int) {
	j := job{task: task, votes: votes, attempt: attempt}
	for {
		select {
		case e.fast <- j:
			return
		default:
			select {
			case <-e.fast:
			default:
			}
		}
	}
}

// PublishRevised queues a slow-anchor completion: the REVISED verdict
// supersedes the cache entry and is never debounced away.
func (e *Engine) PublishRevised(task TaskID, votes []AnchorVote, attempt int) {
	e.slow <- job{task: task, votes: votes, attempt: attempt, revised: true}
}

// Run is the recompute goroutine. It is the only code that ever constructs
// or calls a Fuser after engine start.
func (e *Engine) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case j := <-e.slow:
			e.step(ctx, j)
		case j := <-e.fast:
			e.step(ctx, j)
		}
	}
}

func (e *Engine) step(ctx context.Context, j job) {
	m := e.m.Load()
	f := &Fuser{m: *m}
	ve := f.Fuse(j.task, j.votes)
	if j.revised {
		ve.Stage = m1pv1.VerdictStage_VERDICT_STAGE_REVISED
	}
	now := e.now()
	// D-Y: this publish IS the new evidence, so the streak resets here —
	// before the snapshot, or the entry the gate reads would still carry the
	// capped count and per-task blocking would stay dead for the task's life.
	e.blocks.ResetTask(j.task)
	if prev, ok := e.cache.Get(j.task); ok && j.revised {
		e.queueCorrection(j.task, prev.Verdict.GetVerdict(), ve.GetVerdict())
	}
	e.cache.publish(j.task, Cached{
		Verdict:       ve,
		Knee:          kneeFor(m, j.attempt),
		Blocks:        BlockCounters{Consecutive: e.blocks.ConsecutiveFor(j.task)},
		UnknownVoters: unknownVoters(m, j.votes),
		ComputedAt:    now,
	})
	// After the publish: the cache is the gate's answer and must not wait on
	// an admission that blocks under spool backpressure.
	// REVISED is 04 §9.2's whole R3 predicate: D-AS deleted the CERTIFIED arm,
	// which had two consumers and no producer anywhere in the tree and made this
	// read as though there were two adjudicated paths when there is one.
	if e.Emit != nil && ve.GetStage() == m1pv1.VerdictStage_VERDICT_STAGE_REVISED {
		e.Emit(ctx, ve, j.task)
	}
}

// queueCorrection: a second revision before the pull corrects the verdict the agent saw, not the intermediate one.
func (e *Engine) queueCorrection(task TaskID, prev, rev m1pv1.Verdict) {
	if e.SessionFor == nil {
		return
	}
	sid, ok := e.SessionFor(task)
	if !ok {
		return
	}
	e.cmu.Lock()
	defer e.cmu.Unlock()
	q := e.corrections[sid]
	if n := len(q); n > 0 && q[n-1].Task == task {
		prev = q[n-1].Previous
		q = q[:n-1]
	}
	if prev != rev {
		q = append(q, Correction{Task: task, Previous: prev, Revised: rev})
	}
	e.corrections[sid] = q
}

// TakeCorrections drains the session's queue: one pull, nothing delivered twice.
func (e *Engine) TakeCorrections(session [16]byte) []Correction {
	e.cmu.Lock()
	defer e.cmu.Unlock()
	q := e.corrections[session]
	delete(e.corrections, session)
	return q
}
