package anchors

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/verdict"
)

// Votes is the anchor→fusion adapter (04 §2.3's recompute loop). The Runner
// already emits exactly one AnchorVote Event per run through the Emitter seam;
// Votes wraps that seam, so every vote reaches capture admission unchanged AND
// becomes fusion input. It is deliberately the whole adapter: no second
// transport, no second vote shape.
//
// Fast anchors land on Engine.Recompute — depth-1, latest-wins, which IS the
// PostToolUse debounce reaching fusion (the Scheduler coalesces the runs, the
// Engine coalesces the recomputes). Slow anchors land on PublishRevised, whose
// REVISED verdict supersedes the PROVISIONAL one and is never debounced away.
type Votes struct {
	out  Emitter
	eng  *verdict.Engine
	slow map[string]bool // anchor id → slow class, from the consented catalog

	// TaskFor is D-AA on the vote side: the segmenter resolves the vote's
	// session plus its (usually empty) task_id to a real task. nil, or a miss,
	// means the vote is admitted and NOT fused — fusing it under the all-zero
	// sentinel is what let one session's evidence answer another's gate.
	TaskFor func(session, want [16]byte) ([16]byte, bool)

	mu    sync.Mutex
	tasks map[verdict.TaskID]*taskVotes
}

// taskVotes is one task's live vote set. latest is keyed by anchor id: an
// anchor's newest run replaces its older one — fusion sees each ensemble
// member once, which is what the confusion model assumes.
type taskVotes struct {
	latest  map[string]verdict.AnchorVote
	voted   map[string]bool // anchors that have already voted at this attempt
	attempt int
	// evidence is the typed EvidenceRecord riding on each anchor's newest
	// vote, kept beside the vote because the fusion tee strips it and the
	// verdict cache never held it -- FR-VERIFY-011's evidence_ref has no
	// other source (fabric.Gate.Evidence reads it on BLOCK only).
	evidence map[string]*m1pv1.EvidenceRecord
}

// NewVotes wires the tee. entries is the Enabled catalog (Reconcile's output) —
// the only place the fast/slow class of an anchor id is known by the time its
// vote arrives as an Event.
func NewVotes(out Emitter, eng *verdict.Engine, entries []CatalogEntry) *Votes {
	v := &Votes{out: out, eng: eng, tasks: map[verdict.TaskID]*taskVotes{}}
	v.SetCatalog(entries)
	return v
}

// SetCatalog swaps the class map live, for the same reason Scheduler.SetCatalog
// exists: a slow anchor consented mid-session must land on PublishRevised.
func (v *Votes) SetCatalog(entries []CatalogEntry) {
	slow := map[string]bool{}
	for _, e := range entries {
		if e.Class == ClassSlow {
			slow[e.ID] = true
		}
	}
	v.mu.Lock()
	v.slow = slow
	v.mu.Unlock()
}

// Admit passes every event through to capture and, for AnchorVote bodies,
// triggers a recompute. The admission result is returned unchanged: capture's
// ledger and the verdict plane are separate: a vote that was shed or
// quarantined on its way to the spool still happened, and withholding it from
// fusion would make the gate answer on evidence chosen by backpressure.
func (v *Votes) Admit(ctx context.Context, ev *m1pv1.Event) error {
	err := v.out.Admit(ctx, ev)
	av := ev.GetAnchorVote()
	if av == nil {
		return err
	}
	task, ok := v.resolve(ev)
	if !ok {
		return err
	}
	votes, attempt, slow := v.record(task, verdict.AnchorVote{
		AnchorID: av.GetAnchorId(),
		Vote:     av.GetVote(),
		// The anti-tamper envelope decides admissibility, not the vote value:
		// a tampered vote never enters the likelihood (Thm 5.2).
		Tamper: av.GetIntegrity().GetTamper(),
	}, av.GetEvidence())
	if slow {
		v.eng.PublishRevised(task, votes, attempt)
		return err
	}
	v.eng.Recompute(task, votes, attempt)
	return err
}

// resolve is D-AA for a vote: the session is the event's own session_id, so an
// unsessioned or unsegmented vote resolves to nothing at all rather than to the
// sentinel. There is no path here that returns the all-zero TaskID.
func (v *Votes) resolve(ev *m1pv1.Event) (verdict.TaskID, bool) {
	var sid, want [16]byte
	if len(ev.GetSessionId()) != 16 {
		return verdict.TaskID{}, false
	}
	copy(sid[:], ev.GetSessionId())
	switch b := ev.GetTaskId(); len(b) {
	case 0:
	case 16:
		copy(want[:], b)
	default:
		return verdict.TaskID{}, false
	}
	if v.TaskFor == nil {
		return verdict.TaskID{}, false
	}
	got, ok := v.TaskFor(sid, want)
	if !ok || got == ([16]byte{}) {
		return verdict.TaskID{}, false
	}
	return got, true
}

// record folds one vote into the task's set and returns the snapshot to fuse.
//
// Attempt counting is the caller's job (verdict.Engine takes n as a parameter)
// and no document fixes how the edge derives n, so this is the operational
// definition: an anchor runs at most once per debounce round, so the SECOND
// vote from an anchor that has already voted is the first evidence of the next
// round — that is where n increments. A REVISED (slow) completion is late
// evidence for the attempt it was scheduled in, so it never bumps n on its own.
// ponytail: per-task state is never evicted — task close (04 §9.2) is the
// eviction trigger and the daemon does not segment tasks yet.
func (v *Votes) record(task verdict.TaskID, vote verdict.AnchorVote, ev *m1pv1.EvidenceRecord) ([]verdict.AnchorVote, int, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	tv := v.tasks[task]
	if tv == nil {
		tv = &taskVotes{latest: map[string]verdict.AnchorVote{}, voted: map[string]bool{}, attempt: 1, evidence: map[string]*m1pv1.EvidenceRecord{}}
		v.tasks[task] = tv
	}
	if tv.voted[vote.AnchorID] {
		tv.attempt++
		tv.voted = map[string]bool{}
	}
	tv.voted[vote.AnchorID] = true
	tv.latest[vote.AnchorID] = vote
	tv.evidence[vote.AnchorID] = ev
	out := make([]verdict.AnchorVote, 0, len(tv.latest))
	for _, id := range slices.Sorted(maps.Keys(tv.latest)) {
		out = append(out, tv.latest[id])
	}
	return out, tv.attempt, v.slow[vote.AnchorID]
}

// Evidence renders the failing evidence behind a task's current verdict for
// GateVerdict.evidence_ref (FR-VERIFY-011): every VIOLATED, untampered vote's
// typed record as "<tool>:<code> errors=N warnings=M files=F", anchor-id
// order, "; "-joined. Typed fields only -- no path, no excerpt (CON-004).
// Empty when nothing violated, which the gate renders as no suffix.
func (v *Votes) Evidence(task verdict.TaskID) string {
	v.mu.Lock()
	defer v.mu.Unlock()
	tv := v.tasks[task]
	if tv == nil {
		return ""
	}
	var parts []string
	for _, id := range slices.Sorted(maps.Keys(tv.latest)) {
		vote := tv.latest[id]
		e := tv.evidence[id]
		if vote.Tamper || vote.Vote != m1pv1.Verdict_VERDICT_VIOLATED || e == nil {
			continue
		}
		c := e.GetCounts()
		parts = append(parts, fmt.Sprintf("%s:%s errors=%d warnings=%d files=%d",
			e.GetTool(), e.GetDiagnosticCode(), c.GetErrors(), c.GetWarnings(), c.GetFilesAffected()))
	}
	return strings.Join(parts, "; ")
}
