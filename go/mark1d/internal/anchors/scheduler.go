package anchors

import (
	"context"
	"log/slog"
	"sort"
	"sync"
	"time"
)

// Scheduling constants (04 §2.2 "Activity-aware scheduling"). Overridable per
// Scheduler for tests only.
const (
	defaultDebounce  = 300 * time.Millisecond
	defaultIdleAfter = 30 * time.Second
	// workQueueCap is 04 §9's "anchor work queue 16" bound; coalescing per
	// (task, anchor) keeps it from ever legitimately filling.
	workQueueCap = 16
	// workers bounds concurrent anchor executions so a burst of catalog
	// entries never saturates the developer's machine (the substrate — the
	// WHY of the whole scheduling section).
	workers = 2
)

// taskKey identifies one (session, task) — the coalescing unit is
// (taskKey, anchor ID).
type taskKey struct{ session, task [16]byte }

type timerKey struct {
	tk taskKey
	id string
}

// Scheduler is the activity-aware trigger seam (04 §2.2): fast anchors fire on
// a PostToolUse debounce, slow anchors only at idle or Stop. It never computes
// verdicts and never blocks a caller — every run lands on the bounded queue.
type Scheduler struct {
	runner *Runner
	// catalogs is Reconcile().Enabled per enabled worktree — the only legal source. One worktree per session: WorktreeFor names it (the hook's cwd), else the default (the first root, the single-project form).
	catalogs map[string][]CatalogEntry
	def      string
	// WorktreeFor resolves a session to the enabled root it works in; nil or "" ⇒ the default worktree. Wired by the daemon from Hello.cwd.
	WorktreeFor func(session [16]byte) string
	// consentPath is re-read before every run: entries above are a snapshot
	// for the Scheduler's whole lifetime, but consent is not — a revocation
	// must stop the NEXT run (doc.go "NOTHING RUNS WITHOUT CONSENT"), not the
	// next daemon restart. The store is one small file; per-run re-read is
	// the whole propagation mechanism.
	consentPath string
	log         *slog.Logger

	// Debounce/IdleAfter default to the 04 §2.2 constants; test seams.
	Debounce  time.Duration
	IdleAfter time.Duration
	// DeferSlow is the battery-saver / sustained-load seam: true defers slow
	// anchors even at idle. nil ⇒ never deferred (no probe wired this phase).
	DeferSlow func() bool

	mu           sync.Mutex
	lastActivity time.Time
	timers       map[timerKey]*time.Timer // fast debounce, coalesced per (task, anchor)
	dirty        map[taskKey]string       // slow work owed since last idle drain, by the task's worktree
	inflight     map[taskKey]int          // runs queued or executing, what Settle waits on
	lastTook     map[string]time.Duration // per anchor, its newest run's wall time: the slow queue's order
	work         chan workItem
}

type workItem struct {
	entry    CatalogEntry
	tk       taskKey
	worktree string
}

// NewScheduler wires runner + the Enabled catalog. Entries with any other
// provenance (Pending, Drifted, Stale) must never reach here — the runner
// re-refuses unconsented entries as defense in depth. consentPath is the
// live store (ConsentPath(stateDir)): the worker re-checks it per run, so a
// revocation takes effect without rebuilding the Scheduler.
func NewScheduler(r *Runner, enabled []CatalogEntry, consentPath, worktree string, log *slog.Logger) *Scheduler {
	if log == nil {
		log = slog.Default()
	}
	return &Scheduler{
		runner:      r,
		catalogs:    map[string][]CatalogEntry{worktree: enabled},
		def:         worktree,
		consentPath: consentPath,
		log:         log,
		Debounce:    defaultDebounce,
		IdleAfter:   defaultIdleAfter,
		timers:      map[timerKey]*time.Timer{},
		dirty:       map[taskKey]string{},
		inflight:    map[taskKey]int{},
		lastTook:    map[string]time.Duration{},
		work:        make(chan workItem, workQueueCap),
	}
}

// SetCatalog swaps the Enabled set and the worktree it runs against, live —
// consent lands through approvals.jsonl while the daemon runs, and a consent
// that only armed at the next restart would be the M1E-5001 bug wearing a
// prompt. Same provenance rule as NewScheduler: Reconcile().Enabled only.
func (s *Scheduler) SetCatalog(worktree string, enabled []CatalogEntry) {
	s.SetCatalogs(worktree, map[string][]CatalogEntry{worktree: enabled})
}

// SetCatalogs is SetCatalog for every enabled worktree at once (the daemon's multi-project form): def is the worktree a session resolves to when WorktreeFor names none.
func (s *Scheduler) SetCatalogs(def string, catalogs map[string][]CatalogEntry) {
	s.mu.Lock()
	s.catalogs, s.def = catalogs, def
	s.mu.Unlock()
}

// Known reports whether SetCatalogs armed wt.
func (s *Scheduler) Known(wt string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.catalogs[wt]
	return ok
}

// worktreeOf is the session's enabled root: WorktreeFor's answer when it names a worktree the catalogs know, else the default.
func (s *Scheduler) worktreeOf(session [16]byte) string {
	if s.WorktreeFor != nil {
		if wt := s.WorktreeFor(session); wt != "" {
			s.mu.Lock()
			_, known := s.catalogs[wt]
			s.mu.Unlock()
			if known {
				return wt
			}
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.def
}

// Start launches the workers and the idle watcher. ctx is the kill switch:
// cancel stops scheduling AND (through the sandbox) SIGKILLs running anchors —
// `mark1 off` cancels this before its other steps (04 §2.2).
func (s *Scheduler) Start(ctx context.Context) {
	for i := 0; i < workers; i++ {
		go s.worker(ctx)
	}
	go s.idleLoop(ctx)
}

// NoteToolUse is the PostToolUse trigger: marks activity (deferring slow
// anchors — an activity burst pauses them entirely), owes the task a slow
// drain, and (re)arms one debounce timer per fast anchor. Coalesced per
// (task, anchor): only the latest event matters, a burst yields one run.
func (s *Scheduler) NoteToolUse(session, task [16]byte) {
	tk := taskKey{session, task}
	wt := s.worktreeOf(session)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastActivity = time.Now()
	s.dirty[tk] = wt
	for _, e := range s.catalogs[wt] {
		if e.Class != ClassFast {
			continue
		}
		k := timerKey{tk, e.ID}
		if t, ok := s.timers[k]; ok {
			t.Reset(s.Debounce) // coalesce: the pending run absorbs this event
			continue
		}
		e := e
		s.timers[k] = time.AfterFunc(s.Debounce, func() {
			s.mu.Lock()
			delete(s.timers, k)
			s.mu.Unlock()
			s.enqueue(workItem{entry: e, tk: tk, worktree: wt})
		})
	}
}

// Stop is the session-Stop trigger: slow anchors owed for the task run now
// rather than waiting out the idle window (04 §2.2).
func (s *Scheduler) Stop(session, task [16]byte) {
	tk := taskKey{session, task}
	s.mu.Lock()
	wt, owed := s.dirty[tk]
	delete(s.dirty, tk)
	s.mu.Unlock()
	if owed {
		s.enqueueSlow(tk, wt)
	}
}

// Settle is Stop with a wait: the task's owed slow anchors are enqueued and the caller blocks until nothing for the task is debouncing, queued or running — or ctx ends. The gate reads its cache after this, so a compile error the agent just wrote is in the verdict it reads (the founder's cargo-check voted 30 s after the agent had said "done").
func (s *Scheduler) Settle(ctx context.Context, session, task [16]byte) {
	tk := taskKey{session, task}
	s.Stop(session, task)
	for {
		s.mu.Lock()
		busy := s.inflight[tk] > 0
		for k := range s.timers {
			busy = busy || k.tk == tk
		}
		s.mu.Unlock()
		if !busy {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// idleLoop drains owed slow work once the session has been tool-silent for
// IdleAfter (04 §2.2: "no tool events for 30 s"), unless DeferSlow holds.
func (s *Scheduler) idleLoop(ctx context.Context) {
	tick := s.IdleAfter / 4
	if tick < 10*time.Millisecond {
		tick = 10 * time.Millisecond
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if s.DeferSlow != nil && s.DeferSlow() {
			continue // battery-saver / sustained load: stay deferred
		}
		s.mu.Lock()
		if s.lastActivity.IsZero() || time.Since(s.lastActivity) < s.IdleAfter {
			s.mu.Unlock()
			continue
		}
		drain := map[taskKey]string{}
		for tk, wt := range s.dirty {
			drain[tk] = wt
			delete(s.dirty, tk)
		}
		s.mu.Unlock()
		for tk, wt := range drain {
			s.enqueueSlow(tk, wt)
		}
	}
}

// enqueueSlow queues the task's slow anchors quickest-first by their newest run's wall time (never run ⇒ first): the gate's Settle has a budget, and a test suite that takes minutes must not stand in front of a `go vet` that takes one second — the founder's cargo-test did, and a vet error the agent had just written sailed through its Stop.
func (s *Scheduler) enqueueSlow(tk taskKey, wt string) {
	for _, e := range s.slowOrder(wt) {
		s.enqueue(workItem{entry: e, tk: tk, worktree: wt})
	}
}

func (s *Scheduler) slowOrder(wt string) []CatalogEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	var slow []CatalogEntry
	for _, e := range s.catalogs[wt] {
		if e.Class == ClassSlow {
			slow = append(slow, e)
		}
	}
	// never run ⇒ static checks before test suites: the one prior a fresh daemon has
	sort.SliceStable(slow, func(i, j int) bool {
		ti, tj := s.lastTook[slow[i].ID], s.lastTook[slow[j].ID]
		if ti != tj {
			return ti < tj
		}
		return slow[i].SideEffect != SideEffectTest && slow[j].SideEffect == SideEffectTest
	})
	return slow
}

// enqueue never blocks a trigger path. A full queue drops the run and logs —
// fail-open (F-31 discipline: scheduling pressure must never stall capture),
// and the next tool event re-owes the work anyway.
func (s *Scheduler) enqueue(w workItem) {
	select {
	case s.work <- w:
		s.mu.Lock()
		s.inflight[w.tk]++
		s.mu.Unlock()
	default:
		s.log.Warn("anchors: work queue full, run dropped", "anchor", w.entry.ID)
	}
}

func (s *Scheduler) runItem(ctx context.Context, w workItem) {
	defer func() {
		s.mu.Lock()
		if s.inflight[w.tk]--; s.inflight[w.tk] <= 0 {
			delete(s.inflight, w.tk)
		}
		s.mu.Unlock()
	}()
	// Consent re-check at the execution point: the entry was Enabled
	// when this Scheduler was built, but `mark1 doctor` may have
	// revoked it since — the runner's binary-hash gate catches a
	// swapped binary, not a withdrawn consent.
	if !stillConsented(s.consentPath, w.entry) {
		s.log.Warn("anchors: consent no longer held, run refused", "anchor", w.entry.ID)
		return
	}
	// Fail-open per run: one anchor's failure never blocks another's
	// schedule (04 §2.2). ErrRefused and infra errors are logged; the
	// VERDICT_ERROR vote (when one was emitted) carries the truth.
	start := time.Now()
	if err := s.runner.RunOne(ctx, w.entry, w.tk.session, w.tk.task, w.worktree); err != nil {
		s.log.Warn("anchors: run failed", "anchor", w.entry.ID, "err", err)
	}
	s.mu.Lock()
	s.lastTook[w.entry.ID] = time.Since(start)
	s.mu.Unlock()
}

func (s *Scheduler) worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case w := <-s.work:
			s.runItem(ctx, w)
		}
	}
}
