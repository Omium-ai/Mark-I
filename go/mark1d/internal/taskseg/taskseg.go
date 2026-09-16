// Package taskseg implements task_seg.v1 — ADR-0002's six merge rules, which
// are the TVO denominator. It runs at the edge because R2's overlap predicate
// reads file paths, and paths never leave the machine: only task_id and
// task_seg_version do. The transitions and their emitted events are 04 §9.2.
package taskseg

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"maps"
	"path/filepath"
	"slices"
	"sync"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

// Version stamps every TaskOpen. Opaque — compared by equality, never parsed,
// because N and the overlap predicate are PART OF it (ADR-0002 R6).
const Version = "task_seg.v1"

// proximityTurns is ADR-0002's N. R6 makes it part of the version, so changing
// it is a task_seg.v2 bump, never a config knob.
const proximityTurns = 3

// TaskID is the 16-byte task UUIDv7 (envelope.proto field 4). An alias, not a
// defined type, so the resolver seams in fabric and anchors keep identical
// function types across packages. The all-zero value is D-AA's "unresolved"
// sentinel and is never a key here.
type TaskID = [16]byte

// task is one denominator entry's live state.
type task struct {
	id TaskID
	// files is the R2 predicate's input: per-tenant HMAC path digests, never
	// paths.
	files    map[[32]byte]bool
	lastTurn int    // session assistant-turn counter at this task's last activity
	turns    uint32 // TaskClose.turn_count
	// verdicted marks the R3 state: closed by a certified/revised verdict,
	// still addressable, still reopenable by an overlapping follow-up.
	verdicted bool
}

type session struct {
	turn  int
	tasks []*task // every task not yet terminally closed, in mint order
	cur   *task   // newest task: the R2/R3 candidate and D-AA's "currently open task"
	pend  *task   // R2 candidate awaiting the prompt's subsequent tool activity
}

// Segmenter is the whole state machine. Its scope is the session (R4).
type Segmenter struct {
	// pathKey salts the R2 overlap digests, the same tenant-key discipline as
	// anchors.NewRunner's outputHMACKey — one key, not two.
	pathKey []byte

	// OnClose fires for every task close. D-Y documents the consecutive-block
	// streak as resetting on cache publish AND on task close, and only the
	// publish ever called it: R3 reopens under the SAME task_id, so a streak left
	// at the cap short-circuits the reopened attempt's first gate query to ALLOW
	// before the cache is ever read (D-AR). Wired to verdict.Blocks.ResetTask;
	// nil is legal.
	OnClose func(TaskID)
	// Verdict is D-AS's close-time cache read: the verdict the cache holds for a
	// task at ANY stage. `unresolved` means NO VERDICT, never "no slow anchor
	// ran" — a ruff-only PROVISIONAL is a weak verified outcome, and the D-X/D-AB
	// coverage band is the instrument that reports its weakness. Wired to
	// verdict.Reader; nil means no verdict plane, so every close is unresolved.
	Verdict func(TaskID) (*m1pv1.VerdictEvent, bool)

	mu sync.Mutex
	// ponytail: sessions are evicted on SessionEnd only; a session that never
	// ends leaks one small struct until the daemon restarts. An idle sweep when
	// long-lived daemons show it mattering.
	sessions map[[16]byte]*session
	// ended keeps the task open at SessionEnd, 32 bytes per session, so a Usage the tailer flushes after the session ended (2 s quiesce vs a Stop→SessionEnd within ms) still names the task that spent it.
	ended map[[16]byte]TaskID
}

func New(pathKey []byte) *Segmenter {
	return &Segmenter{pathKey: pathKey, sessions: map[[16]byte]*session{}, ended: map[[16]byte]TaskID{}}
}

// DeriveKey is the one derivation between the tenant HMAC root (04 §2.9) and
// the R2 overlap digests, labelled like every other leg of that root
// (m1p.usage.idem, m1p.anchor.output). A nil root still yields a usable key:
// path digests never leave the machine, so an unkeyed salt leaks nothing — it
// only stops digests being comparable across tenants.
func DeriveKey(tenantRoot []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, tenantRoot, nil, "m1p.taskseg.path", 32)
}

// Observe folds one event into its session's machine and returns the
// TaskOpen/TaskClose events the transition emits, in order — plus, on D-AS's
// close-time resolution, the VerdictEvent the TaskClose names. files carries the
// paths this event's tool activity touched — R2's overlap input — and is empty
// for every other body.
func (s *Segmenter) Observe(ev *m1pv1.Event, files []string) []*m1pv1.Event {
	if len(ev.GetSessionId()) != 16 {
		return nil // no session scope, so no segmentation (R4)
	}
	var sid [16]byte
	copy(sid[:], ev.GetSessionId())
	if sid == ([16]byte{}) {
		// D-AL: session_id is OPTIONAL on the wire (08 §4.3), so the all-zero
		// value means "no authenticated session" — never an address. Bucketing
		// every session-less writer under it puts them all in one segmenter
		// state, and a gate query from any of them then resolves to another's
		// open task.
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	ss := s.sessions[sid]
	if ss == nil {
		if ev.GetUsage() != nil {
			if id, ok := s.ended[sid]; ok && len(ev.TaskId) == 0 {
				ev.TaskId = id[:]
			}
			return nil // a Usage opens nothing (R1): no session state for it
		}
		ss = &session{}
		s.sessions[sid] = ss
	}

	switch b := ev.Body.(type) {
	case *m1pv1.Event_Turn:
		if b.Turn.GetInitiator() == m1pv1.Initiator_INITIATOR_HUMAN {
			return append(s.flush(sid, ss), s.prompt(sid, ss)...)
		}
		ss.turn++
		if live(ss.cur) {
			ss.cur.lastTurn = ss.turn
			ss.cur.turns++
		}
		return nil
	case *m1pv1.Event_ToolUse:
		return s.tool(sid, ss, files)
	case *m1pv1.Event_Usage:
		// The numerator meets the denominator here: an unaddressed Usage takes the currently open task (D-AA's zero-sentinel resolution), so tvo_task has rows.
		if len(ev.TaskId) == 0 && ss.cur != nil {
			id := ss.cur.id
			ev.TaskId = id[:]
		}
		return nil
	case *m1pv1.Event_VerdictEvent:
		// 04 §9.2: a PROVISIONAL verdict is an ACTIVE→ACTIVE recompute; it resolves
		// the denominator at CLOSE instead (D-AS). REVISED is the one adjudicated
		// stage that exists — D-AS deleted the CERTIFIED arm, which had two
		// consumers and no producer anywhere in the tree.
		if b.VerdictEvent.GetStage() != m1pv1.VerdictStage_VERDICT_STAGE_REVISED {
			return nil
		}
		// D-AM: the credit goes to the task the verdict NAMES. Resolved before
		// flush, which mints a fresh ss.cur for a pending prompt — closing that
		// one would launder the task that did the work into unresolved.
		t := target(ss, ev.GetTaskId())
		out := s.flush(sid, ss)
		if live(t) {
			t.verdicted = true
			out = append(out, s.closeTask(sid, ss, t, m1pv1.Resolution_RESOLUTION_VERDICT, ev.GetEventId())...)
		}
		return out
	case *m1pv1.Event_SessionEnd:
		return s.end(sid, ss)
	}
	return nil
}

// TaskFor is D-AA parts 2 and 3: the zero sentinel resolves through the session
// to its currently open task; a named task is honoured only if this session
// owns it. Everything else is a miss — ALLOW at the gate, no fusion for a vote.
func (s *Segmenter) TaskFor(session, want TaskID) (TaskID, bool) {
	if session == ([16]byte{}) {
		return TaskID{}, false // D-AL: "no session" addresses nothing
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ss := s.sessions[session]
	if ss == nil {
		return TaskID{}, false
	}
	if want == (TaskID{}) {
		// D-AR: ledger closure is not gate lifetime. A verdict RESOLVES a task for
		// the ledger and leaves it ADDRESSABLE for the gate until the session ends
		// or a new task opens — ss.cur is cleared by a non-VERDICT close and
		// replaced by the next mint, which is exactly that window. Requiring live()
		// here made the stop-gate answer "no open task" while a VERDICT_VIOLATED
		// sat in the cache, i.e. build/vet/test could not stop the agent at all.
		if ss.cur == nil {
			return TaskID{}, false
		}
		return ss.cur.id, true
	}
	for _, t := range ss.tasks {
		if t.id == want {
			return want, true
		}
	}
	return TaskID{}, false
}

// live is "OPEN or ACTIVE" in 04 §9.2's vocabulary.
func live(t *task) bool { return t != nil && !t.verdicted }

// target resolves the task an event addresses within its own session: the one
// it names, or the currently open one when it names none. A task_id this
// session does not own resolves to nothing rather than falling back to ss.cur —
// the fallback is for an unaddressed event, not for a misaddressed one.
func target(ss *session, id []byte) *task {
	if len(id) != 16 {
		return ss.cur
	}
	var want TaskID
	copy(want[:], id)
	if want == (TaskID{}) {
		return ss.cur
	}
	for _, t := range ss.tasks {
		if t.id == want {
			return t
		}
	}
	return nil
}

// SessionFor is the reverse of TaskFor: the session that owns a task. The
// verdict Engine knows only the task it published for, and an Event needs the
// session scope (R4) to be admitted at all.
// ponytail: linear scan — one session's task list is short and a machine runs
// a handful of sessions; an index when either stops being true.
func (s *Segmenter) SessionFor(task TaskID) ([16]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for sid, ss := range s.sessions {
		for _, t := range ss.tasks {
			if t.id == task {
				return sid, true
			}
		}
	}
	return [16]byte{}, false
}

// prompt is R1+R2's entry: proximity alone decides nothing, it only makes the
// predecessor a candidate. The prompt's SUBSEQUENT tool activity resolves it.
func (s *Segmenter) prompt(sid [16]byte, ss *session) []*m1pv1.Event {
	if ss.cur != nil && ss.turn-ss.cur.lastTurn <= proximityTurns {
		ss.pend = ss.cur
		return nil
	}
	return s.mint(sid, ss, nil, nil)
}

// tool is where R2 and R3 actually resolve, because the overlap predicate needs
// the files the prompt's activity touched.
func (s *Segmenter) tool(sid [16]byte, ss *session, files []string) []*m1pv1.Event {
	if cand := ss.pend; cand != nil {
		ss.pend = nil
		switch {
		case !s.overlaps(cand, files):
			return s.mint(sid, ss, nil, files) // R1
		case cand.verdicted:
			// R3: the retry loop. Same task_id, new attempt, no TaskOpen — so the
			// denominator gains no entry, which is the rule's whole job.
			cand.verdicted = false
			ss.cur = cand
		default:
			// R2 under 04 §9.2: the predecessor closes MERGED_FORWARD and the
			// successor carries parent_task_id. One denominator entry either way,
			// since a MERGED_FORWARD close is never a verified outcome.
			out := s.closeTask(sid, ss, cand, m1pv1.Resolution_RESOLUTION_MERGED_FORWARD, nil)
			return append(out, s.mint(sid, ss, cand, files)...)
		}
	}
	if live(ss.cur) {
		s.touch(ss.cur, files)
		ss.cur.lastTurn = ss.turn
	}
	return nil
}

// flush resolves a pending prompt as "no merge": R2 requires BOTH proximity and
// overlap, so a prompt whose next event is not tool activity merges nothing and
// opens its own task (R1).
func (s *Segmenter) flush(sid [16]byte, ss *session) []*m1pv1.Event {
	if ss.pend == nil {
		return nil
	}
	ss.pend = nil
	return s.mint(sid, ss, nil, nil)
}

// end is R4+R5: merges never cross a session boundary, and every still-open
// task force-closes — into the unresolved class, or into VERDICT if the cache
// holds one for it (D-AS) — rather than being dropped.
func (s *Segmenter) end(sid [16]byte, ss *session) []*m1pv1.Event {
	out := s.flush(sid, ss)
	if ss.cur != nil {
		s.ended[sid] = ss.cur.id
	}
	for _, t := range slices.Clone(ss.tasks) {
		if t.verdicted {
			continue // already closed by R3; kept only for reopen
		}
		out = append(out, s.closeOpen(sid, ss, t)...)
	}
	delete(s.sessions, sid)
	return out
}

func (s *Segmenter) mint(sid [16]byte, ss *session, parent *task, seed []string) []*m1pv1.Event {
	id, err := uuid.NewV7()
	if err != nil {
		// No id, no task: the session stays unresolved and D-AA makes unresolved
		// an ALLOW. Fabricating an id would poison the denominator forever.
		return nil
	}
	t := &task{id: id, files: map[[32]byte]bool{}, lastTurn: ss.turn, turns: 1}
	if parent != nil {
		maps.Copy(t.files, parent.files) // the merged chain keeps its file set
	}
	s.touch(t, seed)
	ss.cur = t
	ss.tasks = append(ss.tasks, t)

	open := &m1pv1.TaskOpen{TaskSegVersion: Version, FileSetDigest: s.fileSetDigest(t)}
	if parent != nil {
		open.ParentTaskId = parent.id[:]
	}
	// prompt_digest stays empty: no wire body carries prompt text into the
	// daemon today, and [P1] absent beats [P1] fabricated.
	ev := newEvent(sid, t.id)
	ev.Body = &m1pv1.Event_TaskOpen{TaskOpen: open}
	return []*m1pv1.Event{ev}
}

// closeOpen is D-AS at R4's force-close: a verdict sitting in the cache at ANY
// stage is a verified outcome, so the task closes RESOLUTION_VERDICT instead of
// being reported as unresolved — the one value that cannot be distinguished
// from "we were not there". The verdict is emitted as its own Event first so
// the stage is recorded and final_verdict_id has something to name (07 §3:
// empty iff UNRESOLVED); its event_id is minted here because capture only mints
// one when absent, and the TaskClose is built before either is admitted.
func (s *Segmenter) closeOpen(sid [16]byte, ss *session, t *task) []*m1pv1.Event {
	unresolved := func() []*m1pv1.Event {
		return s.closeTask(sid, ss, t, m1pv1.Resolution_RESOLUTION_UNRESOLVED_SESSION_END, nil)
	}
	if s.Verdict == nil {
		return unresolved()
	}
	ve, ok := s.Verdict(t.id)
	if !ok {
		return unresolved()
	}
	eid, err := uuid.NewV7()
	if err != nil {
		return unresolved()
	}
	ev := newEvent(sid, t.id)
	ev.EventId = eid[:]
	// Cloned: the same VerdictEvent pointer is live in the gate-readable cache
	// entry, and the admission path redacts in place.
	ev.Body = &m1pv1.Event_VerdictEvent{VerdictEvent: proto.CloneOf(ve)}
	return append([]*m1pv1.Event{ev}, s.closeTask(sid, ss, t, m1pv1.Resolution_RESOLUTION_VERDICT, eid[:])...)
}

// closeTask emits the TaskClose. A VERDICT close deliberately leaves the task
// in ss.tasks: R3 can still reopen it, and D-AA part 3 can still name it.
func (s *Segmenter) closeTask(sid [16]byte, ss *session, t *task, r m1pv1.Resolution, verdictID []byte) []*m1pv1.Event {
	if s.OnClose != nil {
		s.OnClose(t.id) // D-AR: the streak is per attempt, and a close ends one
	}
	if r != m1pv1.Resolution_RESOLUTION_VERDICT {
		ss.tasks = slices.DeleteFunc(ss.tasks, func(x *task) bool { return x == t })
		if ss.cur == t {
			ss.cur = nil
		}
	}
	ev := newEvent(sid, t.id)
	ev.Body = &m1pv1.Event_TaskClose{TaskClose: &m1pv1.TaskClose{
		Resolution: r, FinalVerdictId: verdictID, TurnCount: t.turns,
	}}
	return []*m1pv1.Event{ev}
}

func (s *Segmenter) touch(t *task, files []string) {
	for _, p := range files {
		t.files[s.digest(p)] = true
	}
}

func (s *Segmenter) overlaps(t *task, files []string) bool {
	for _, p := range files {
		if t.files[s.digest(p)] {
			return true
		}
	}
	return false
}

func (s *Segmenter) digest(path string) [32]byte {
	mac := hmac.New(sha256.New, s.pathKey)
	mac.Write([]byte(filepath.Clean(path)))
	var d [32]byte
	copy(d[:], mac.Sum(nil))
	return d
}

// fileSetDigest is TaskOpen.file_set_digest: HMAC over the SORTED digest set,
// so a merge is auditable without carrying one path.
func (s *Segmenter) fileSetDigest(t *task) []byte {
	ds := slices.Collect(maps.Keys(t.files))
	slices.SortFunc(ds, func(a, b [32]byte) int { return bytes.Compare(a[:], b[:]) })
	mac := hmac.New(sha256.New, s.pathKey)
	for _, d := range ds {
		mac.Write(d[:])
	}
	return mac.Sum(nil)
}

func newEvent(sid [16]byte, task TaskID) *m1pv1.Event {
	return &m1pv1.Event{SessionId: sid[:], TaskId: task[:], OccurredAt: timestamppb.Now()}
}
