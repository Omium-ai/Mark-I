package taskseg

import (
	"bytes"
	"fmt"
	"slices"
	"testing"

	"github.com/google/uuid"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

// step is one event in a session script. The vocabulary is exactly the four
// things ADR-0002's rules react to plus the session boundary.
type step struct {
	kind  string // prompt | agent | tool | verdict | end
	files []string
	stage m1pv1.VerdictStage
}

func prompt() step          { return step{kind: "prompt"} }
func agent() step           { return step{kind: "agent"} }
func tool(f ...string) step { return step{kind: "tool", files: f} }
func end() step             { return step{kind: "end"} }
func provisional() step     { return verdict(m1pv1.VerdictStage_VERDICT_STAGE_PROVISIONAL) }
func revised() step         { return verdict(m1pv1.VerdictStage_VERDICT_STAGE_REVISED) }
func verdict(s m1pv1.VerdictStage) step {
	return step{kind: "verdict", stage: s}
}

func (st step) event(sid [16]byte) *m1pv1.Event {
	ev := &m1pv1.Event{SessionId: sid[:], EventId: []byte("verdict-event-id")}
	switch st.kind {
	case "prompt":
		ev.Body = &m1pv1.Event_Turn{Turn: &m1pv1.Turn{Initiator: m1pv1.Initiator_INITIATOR_HUMAN}}
	case "agent":
		ev.Body = &m1pv1.Event_Turn{Turn: &m1pv1.Turn{Initiator: m1pv1.Initiator_INITIATOR_AGENT}}
	case "tool":
		ev.Body = &m1pv1.Event_ToolUse{ToolUse: &m1pv1.ToolUse{ToolName: "Edit"}}
	case "verdict":
		ev.Body = &m1pv1.Event_VerdictEvent{VerdictEvent: &m1pv1.VerdictEvent{Stage: st.stage}}
	case "end":
		ev.Body = &m1pv1.Event_SessionEnd{SessionEnd: &m1pv1.SessionEnd{}}
	}
	return ev
}

// trace runs a script and renders the emitted TaskOpen/TaskClose stream with
// task ids replaced by first-seen labels, so an expectation pins both the
// events and their identity relationships.
func trace(t *testing.T, s *Segmenter, sid [16]byte, script ...step) []string {
	t.Helper()
	var ids []string
	label := func(b []byte) string {
		k := string(b)
		if i := slices.Index(ids, k); i >= 0 {
			return fmt.Sprintf("t%d", i)
		}
		ids = append(ids, k)
		return fmt.Sprintf("t%d", len(ids)-1)
	}
	var out []string
	for _, st := range script {
		for _, ev := range s.Observe(st.event(sid), st.files) {
			id := label(ev.GetTaskId())
			switch b := ev.Body.(type) {
			case *m1pv1.Event_TaskOpen:
				line := "open " + id
				if p := b.TaskOpen.GetParentTaskId(); len(p) > 0 {
					line += " parent=" + label(p)
				}
				if b.TaskOpen.GetTaskSegVersion() != Version {
					t.Fatalf("TaskOpen carries version %q, want %q", b.TaskOpen.GetTaskSegVersion(), Version)
				}
				if b.TaskOpen.GetTaskClass() != "*" {
					t.Fatalf("TaskOpen carries task_class %q, want %q (one class until a classifier exists)", b.TaskOpen.GetTaskClass(), "*")
				}
				out = append(out, line)
			case *m1pv1.Event_TaskClose:
				out = append(out, "close "+id+" "+shortRes(b.TaskClose.GetResolution()))
			default:
				t.Fatalf("segmenter emitted a %T, only TaskOpen/TaskClose are its output", ev.Body)
			}
		}
	}
	return out
}

func shortRes(r m1pv1.Resolution) string {
	return map[m1pv1.Resolution]string{
		m1pv1.Resolution_RESOLUTION_VERDICT:                "VERDICT",
		m1pv1.Resolution_RESOLUTION_MERGED_FORWARD:         "MERGED_FORWARD",
		m1pv1.Resolution_RESOLUTION_UNRESOLVED_SESSION_END: "UNRESOLVED",
	}[r]
}

func newSeg() *Segmenter { return New([]byte("tenant-path-salt")) }

func sid(t *testing.T) [16]byte {
	t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// TestWorkedExamples is ADR-0002's three ambiguous sessions, resolved. They are
// the acceptance criteria for task_seg.v1 and are transcribed rule for rule.
func TestWorkedExamples(t *testing.T) {
	for _, tc := range []struct {
		name   string
		script []step
		want   []string
	}{{
		// Example 1 — same window, different files. Proximity holds (2 ≤ N) and
		// overlap fails, so R2 merges nothing: TWO verified outcomes.
		name: "same window different files",
		script: []step{
			prompt(), tool("auth/session.go"), revised(),
			agent(), agent(),
			prompt(), tool("CHANGELOG.md"),
		},
		want: []string{"open t0", "close t0 VERDICT", "open t1"},
	}, {
		// Example 2 — the retry rephrase. Proximity holds and test_sync.py
		// overlaps, so R3 reopens: ONE task, second attempt, no second TaskOpen
		// and therefore no second denominator entry.
		name: "retry rephrase reopens the same task",
		script: []step{
			prompt(), tool("tests/test_sync.py"), revised(),
			agent(),
			prompt(), tool("tests/conftest.py", "tests/test_sync.py"),
		},
		want: []string{"open t0", "close t0 VERDICT"},
	}, {
		// Example 3 — the overnight orphan, first half. R4 force-closes the
		// abandoned task into the unresolved class rather than dropping it (R5).
		name: "overnight orphan closes unresolved",
		script: []step{
			prompt(), tool("pkg/router/route.go"), end(),
		},
		want: []string{"open t0", "close t0 UNRESOLVED"},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			got := trace(t, newSeg(), sid(t), tc.script...)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("trace %v, want %v", got, tc.want)
			}
		})
	}
}

// TestOvernightOrphanIsTwoTasks is example 3's second half, which only a second
// session can show: R4 is blunt on purpose, so yesterday's unresolved work and
// today's adjudicated work are two entries even on identical files.
func TestOvernightOrphanIsTwoTasks(t *testing.T) {
	s := newSeg()
	files := []string{"pkg/router/route.go"}
	night := trace(t, s, sid(t), prompt(), tool(files...), end())
	morning := trace(t, s, sid(t), prompt(), tool(files...), revised())
	if want := []string{"open t0", "close t0 UNRESOLVED"}; !slices.Equal(night, want) {
		t.Fatalf("night %v, want %v", night, want)
	}
	if want := []string{"open t0", "close t0 VERDICT"}; !slices.Equal(morning, want) {
		t.Fatalf("morning %v, want %v", morning, want)
	}
}

// TestMergeRule is R2 in isolation: BOTH conditions required, and the merge
// itself is 04 §9.2's forward merge — predecessor MERGED_FORWARD, successor
// carrying parent_task_id.
func TestMergeRule(t *testing.T) {
	for _, tc := range []struct {
		name   string
		script []step
		want   []string
	}{{
		name: "proximity and overlap merge forward",
		script: []step{
			prompt(), tool("app/router.go"),
			agent(),
			prompt(), tool("app/router.go"),
		},
		want: []string{"open t0", "close t0 MERGED_FORWARD", "open t1 parent=t0", "close t1 UNRESOLVED"},
	}, {
		name: "overlap without proximity merges nothing",
		script: []step{
			prompt(), tool("app/router.go"), revised(),
			agent(), agent(), agent(), agent(),
			prompt(), tool("app/router.go"),
		},
		want: []string{"open t0", "close t0 VERDICT", "open t1", "close t1 UNRESOLVED"},
	}, {
		name: "proximity without overlap merges nothing",
		script: []step{
			prompt(), tool("app/router.go"),
			agent(),
			prompt(), tool("docs/README.md"),
		},
		want: []string{"open t0", "open t1", "close t0 UNRESOLVED", "close t1 UNRESOLVED"},
	}, {
		// A prompt whose next event is not tool activity merges nothing at all:
		// R2's predicate is never even evaluated.
		name: "prompt with no tool activity opens its own task",
		script: []step{
			prompt(), tool("app/router.go"),
			prompt(), prompt(),
		},
		want: []string{"open t0", "open t1", "open t2", "close t0 UNRESOLVED", "close t1 UNRESOLVED", "close t2 UNRESOLVED"},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			got := trace(t, newSeg(), sid(t), append(slices.Clone(tc.script), end())...)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("trace %v, want %v", got, tc.want)
			}
		})
	}
}

// TestProvisionalVerdictDoesNotClose pins 04 §9.2's ACTIVE→ACTIVE arm: edge
// fusion recomputes a PROVISIONAL verdict continuously, and a task that closed
// on every recompute would make the denominator a function of anchor cadence.
func TestProvisionalVerdictDoesNotClose(t *testing.T) {
	got := trace(t, newSeg(), sid(t), prompt(), tool("a.go"), provisional(), provisional(), end())
	if want := []string{"open t0", "close t0 UNRESOLVED"}; !slices.Equal(got, want) {
		t.Fatalf("trace %v, want %v", got, want)
	}
}

// TestTaskForResolvesThroughTheSession is D-AA parts 2 and 3.
func TestTaskForResolvesThroughTheSession(t *testing.T) {
	s := newSeg()
	a, b := sid(t), sid(t)
	s.Observe(prompt().event(a), nil)
	s.Observe(tool("a.go").event(a), []string{"a.go"})

	task, ok := s.TaskFor(a, TaskID{})
	if !ok || task == (TaskID{}) {
		t.Fatalf("TaskFor(open session, sentinel) = %x/%v, want the session's open task", task, ok)
	}
	// Part 2: a session with no open task is a miss, never the sentinel.
	if got, ok := s.TaskFor(b, TaskID{}); ok {
		t.Fatalf("TaskFor(session with no task) = %x/true, want a miss", got)
	}
	// Part 3: naming another session's task is a miss, not a lookup.
	s.Observe(prompt().event(b), nil)
	if got, ok := s.TaskFor(b, task); ok {
		t.Fatalf("session B resolved session A's task %x (%v) — D-AA part 3 breach", got, ok)
	}
	if got, ok := s.TaskFor(a, task); !ok || got != task {
		t.Fatalf("TaskFor(owning session, named task) = %x/%v, want the task", got, ok)
	}
	// A closed session keeps nothing: SessionEnd is R4's hard boundary.
	s.Observe(end().event(a), nil)
	if got, ok := s.TaskFor(a, task); ok {
		t.Fatalf("TaskFor after SessionEnd = %x/true, want a miss", got)
	}
}

// TestReopenedTaskResolvesAgain: R3's reopen must restore the task to the gate,
// otherwise the second attempt runs ungated.
func TestReopenedTaskResolvesAgain(t *testing.T) {
	s := newSeg()
	id := sid(t)
	s.Observe(prompt().event(id), nil)
	s.Observe(tool("x.go").event(id), []string{"x.go"})
	first, _ := s.TaskFor(id, TaskID{})
	s.Observe(revised().event(id), nil)
	// D-AR: CLOSED_VERDICT means the LEDGER has its answer, never "the agent may
	// now stop". The task stays addressable until the session ends or a new task
	// opens, so the shim's sentinel query still finds it.
	if got, ok := s.TaskFor(id, TaskID{}); !ok || got != first {
		t.Fatalf("verdict-closed task answers the sentinel with %x/%v, want the task %x (D-AR)", got, ok, first)
	}
	s.Observe(prompt().event(id), nil)
	s.Observe(tool("x.go").event(id), []string{"x.go"})
	again, ok := s.TaskFor(id, TaskID{})
	if !ok || again != first {
		t.Fatalf("reopened task is %x, want the original %x (R3: same task_id, new attempt)", again, first)
	}
}

// TestSessionlessEventSegmentsNothing: an event with no session id has no R4
// scope, so it can neither open nor close a task.
func TestSessionlessEventSegmentsNothing(t *testing.T) {
	s := newSeg()
	if got := s.Observe(&m1pv1.Event{Body: &m1pv1.Event_Turn{Turn: &m1pv1.Turn{
		Initiator: m1pv1.Initiator_INITIATOR_HUMAN,
	}}}, nil); got != nil {
		t.Fatalf("sessionless prompt emitted %d events, want none", len(got))
	}
}

// TestAllZeroSessionIsNeverASegmenterKey is D-AL: session_id is OPTIONAL on the
// wire, so the all-zero value means "no authenticated session". Keyed as a
// session it becomes one shared bucket, and every session-less writer on the
// box then resolves to whichever of them opened a task first.
func TestAllZeroSessionIsNeverASegmenterKey(t *testing.T) {
	s := newSeg()
	var zero [16]byte
	if got := s.Observe(prompt().event(zero), nil); got != nil {
		t.Fatalf("an unsessioned prompt emitted %v, want no segmentation (R4)", got)
	}
	s.Observe(tool("a.go").event(zero), []string{"a.go"})
	if got, ok := s.TaskFor(zero, TaskID{}); ok {
		t.Fatalf("TaskFor(all-zero session) resolved %x — the sentinel is an address", got)
	}
}

// TestVerdictCreditsTheTaskItNames is D-AM: the verdict arm used to close
// ss.cur, and flush() re-points ss.cur at a brand-new empty task whenever a
// prompt is pending. The task that did the work was then laundered into the
// unresolved class and the credit landed on an empty one.
func TestVerdictCreditsTheTaskItNames(t *testing.T) {
	s := newSeg()
	id := sid(t)
	s.Observe(prompt().event(id), nil)
	s.Observe(tool("a.go").event(id), []string{"a.go"})
	work, ok := s.TaskFor(id, TaskID{})
	if !ok {
		t.Fatal("setup: no open task")
	}
	// A prompt with no tool activity yet: the next event flushes it into a task
	// of its own (R1), which is what used to steal the verdict.
	s.Observe(prompt().event(id), nil)

	ve := revised().event(id)
	ve.TaskId = work[:]
	var closes []*m1pv1.TaskClose
	var closed [][]byte
	for _, ev := range s.Observe(ve, nil) {
		if c, isClose := ev.Body.(*m1pv1.Event_TaskClose); isClose {
			closes = append(closes, c.TaskClose)
			closed = append(closed, ev.GetTaskId())
		}
	}
	if len(closes) != 1 {
		t.Fatalf("a verdict closed %d tasks, want exactly 1", len(closes))
	}
	if closes[0].GetResolution() != m1pv1.Resolution_RESOLUTION_VERDICT {
		t.Fatalf("resolution %v, want VERDICT", closes[0].GetResolution())
	}
	if !bytes.Equal(closed[0], work[:]) {
		t.Fatalf("VERDICT credited task %x, want the task that did the work %x", closed[0], work)
	}
}

// TestFastAnchorOnlySessionResolvesItsDenominator is D-AS. REVISED is reachable
// only from a consented SLOW anchor, so on any install without one the
// denominator was 100% UNRESOLVED no matter how much fast-anchor evidence the
// cache held — and unresolved is the one value indistinguishable from "we were
// not there". A cached verdict at ANY stage resolves the close, with the stage
// recorded alongside it.
func TestFastAnchorOnlySessionResolvesItsDenominator(t *testing.T) {
	s := newSeg()
	s.Verdict = func(TaskID) (*m1pv1.VerdictEvent, bool) {
		return &m1pv1.VerdictEvent{
			Stage:   m1pv1.VerdictStage_VERDICT_STAGE_PROVISIONAL,
			Verdict: m1pv1.Verdict_VERDICT_SATISFIED,
		}, true
	}
	id := sid(t)
	s.Observe(prompt().event(id), nil)
	s.Observe(tool("a.go").event(id), []string{"a.go"})

	var stage m1pv1.VerdictStage
	var verdictID []byte
	var closed *m1pv1.TaskClose
	for _, ev := range s.Observe(end().event(id), nil) {
		switch b := ev.Body.(type) {
		case *m1pv1.Event_VerdictEvent:
			stage, verdictID = b.VerdictEvent.GetStage(), ev.GetEventId()
		case *m1pv1.Event_TaskClose:
			closed = b.TaskClose
		}
	}
	if closed.GetResolution() != m1pv1.Resolution_RESOLUTION_VERDICT {
		t.Fatalf("resolution %v, want VERDICT — a PROVISIONAL verdict is a weak outcome, not a non-outcome", closed.GetResolution())
	}
	if stage != m1pv1.VerdictStage_VERDICT_STAGE_PROVISIONAL {
		t.Fatalf("the close recorded stage %v; the coverage band is what reports weakness, not suppression", stage)
	}
	if len(verdictID) != 16 || !bytes.Equal(closed.GetFinalVerdictId(), verdictID) {
		t.Fatalf("final_verdict_id %x does not name the emitted VerdictEvent %x (07 §3: empty iff UNRESOLVED)", closed.GetFinalVerdictId(), verdictID)
	}
}

// TestSessionForIsTaskForsInverse: the verdict Engine publishes for a task and
// needs the session scope to admit an Event under (R4).
func TestSessionForIsTaskForsInverse(t *testing.T) {
	s := newSeg()
	id := sid(t)
	s.Observe(prompt().event(id), nil)
	s.Observe(tool("a.go").event(id), []string{"a.go"})
	task, _ := s.TaskFor(id, TaskID{})
	if got, ok := s.SessionFor(task); !ok || got != id {
		t.Fatalf("SessionFor(%x) = %x/%v, want %x", task, got, ok, id)
	}
	if _, ok := s.SessionFor(TaskID{1, 2, 3}); ok {
		t.Fatal("SessionFor invented an owner for an unknown task")
	}
}

// TestOnCloseFiresOnEveryClosePath is D-AR's contract, which nothing asserted.
// The hook exists so cmd/main.go can reset the per-attempt block streak, and a
// close it does not fire on leaks that streak into whatever reopens the task
// under R3 — a streak already at the cap short-circuits the reopened attempt's
// first gate query to ALLOW before the verdict cache is ever read, so the new
// attempt runs ungated on the previous attempt's state.
//
// Asserting the hook rather than the streak is deliberate: the streak lives in
// internal/verdict, and a test that reached for it would prove the wiring of the
// one caller instead of the property every future caller depends on.
func TestOnCloseFiresOnEveryClosePath(t *testing.T) {
	for _, tc := range []struct {
		name    string
		verdict bool
		want    m1pv1.Resolution
	}{
		{"unresolved", false, m1pv1.Resolution_RESOLUTION_UNRESOLVED_SESSION_END},
		{"verdict", true, m1pv1.Resolution_RESOLUTION_VERDICT},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSeg()
			if tc.verdict {
				s.Verdict = func(TaskID) (*m1pv1.VerdictEvent, bool) {
					return &m1pv1.VerdictEvent{Stage: m1pv1.VerdictStage_VERDICT_STAGE_PROVISIONAL}, true
				}
			}
			var closed []TaskID
			s.OnClose = func(id TaskID) { closed = append(closed, id) }

			id := sid(t)
			s.Observe(prompt().event(id), nil)
			s.Observe(tool("a.go").event(id), []string{"a.go"})
			task, ok := s.TaskFor(id, TaskID{})
			if !ok {
				t.Fatal("no task opened")
			}

			var got m1pv1.Resolution
			for _, ev := range s.Observe(end().event(id), nil) {
				if b, isClose := ev.Body.(*m1pv1.Event_TaskClose); isClose {
					got = b.TaskClose.GetResolution()
				}
			}
			if got != tc.want {
				t.Fatalf("resolution %v, want %v — the fixture stopped exercising the path it names", got, tc.want)
			}
			if len(closed) != 1 || closed[0] != task {
				t.Fatalf("OnClose fired %d time(s) with %x, want exactly once with %x (D-AR)", len(closed), closed, task)
			}
		})
	}
}

func TestUsageStampTakesTheOpenTaskAndKeepsAPriorStamp(t *testing.T) {
	s, id := newSeg(), sid(t)
	for _, st := range []step{prompt(), tool("a.go")} {
		s.Observe(st.event(id), nil)
	}
	usage := func(pre []byte) *m1pv1.Event {
		return &m1pv1.Event{SessionId: id[:], TaskId: pre, Body: &m1pv1.Event_Usage{Usage: &m1pv1.Usage{}}}
	}
	live := usage(nil)
	s.Observe(live, nil)
	if len(live.TaskId) != 16 {
		t.Fatalf("live Usage unstamped: task_id=%x", live.TaskId)
	}
	pre := usage([]byte("hook-stamped-task"))
	s.Observe(pre, nil)
	if string(pre.TaskId) != "hook-stamped-task" {
		t.Fatalf("pre-stamped Usage overwritten: %q", pre.TaskId)
	}
	s.Observe(end().event(id), nil)
	late := usage(nil)
	s.Observe(late, nil)
	if string(late.TaskId) != string(live.TaskId) {
		t.Fatalf("post-SessionEnd Usage lost its task: %x vs %x", late.TaskId, live.TaskId)
	}
}

func TestUsageAfterEndKeepsTaskPastAForeignMarker(t *testing.T) {
	s := New(nil)
	sid := uuid.New()
	prompt := &m1pv1.Event{SessionId: sid[:], Body: &m1pv1.Event_Turn{Turn: &m1pv1.Turn{Initiator: m1pv1.Initiator_INITIATOR_HUMAN}}}
	s.Observe(prompt, nil)
	s.Observe(&m1pv1.Event{SessionId: sid[:], Body: &m1pv1.Event_ToolUse{ToolUse: &m1pv1.ToolUse{ToolName: "Bash"}}}, []string{"a.go"})
	var opened []byte
	for _, ev := range s.Observe(&m1pv1.Event{SessionId: sid[:], Body: &m1pv1.Event_SessionEnd{SessionEnd: &m1pv1.SessionEnd{}}}, nil) {
		if ev.GetTaskClose() != nil {
			opened = ev.TaskId
		}
	}
	if len(opened) != 16 {
		t.Fatalf("session end closed no task: %v", opened)
	}
	marker := &m1pv1.Event{SessionId: sid[:], Body: &m1pv1.Event_CoverageTransition{CoverageTransition: &m1pv1.CoverageTransition{}}}
	s.Observe(marker, nil)
	usage := &m1pv1.Event{SessionId: sid[:], Body: &m1pv1.Event_Usage{Usage: &m1pv1.Usage{}}}
	s.Observe(usage, nil)
	if string(usage.TaskId) != string(opened) {
		t.Fatalf("usage after a post-end marker lost its task: got %x want %x", usage.TaskId, opened)
	}
}
