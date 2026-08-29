//go:build unix

package tailers

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"github.com/google/uuid"
)

var testSession = uuid.MustParse("3f9c2e71-58d4-4b6a-9e2f-7a1c0d8b4e55")

func usageLine(msg, req string, out uint64) string {
	return fmt.Sprintf(`{"type":"assistant","isSidechain":false,"requestId":%q,"sessionId":%q,"message":{"id":%q,"model":"claude-fable-5","usage":{"input_tokens":1,"output_tokens":%d,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"service_tier":"standard"}}}`+"\n",
		req, testSession.String(), msg, out)
}

func newTestTailer(t *testing.T, path, state string) *Tailer {
	t.Helper()
	tl, err := newTailer(path, state, stream{role: RoleParent, session: testSession, idemKey: testIdemKey})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tl.close)
	return tl
}

func collect(got *[]*m1pv1.Event) func([]*m1pv1.Event) error {
	return func(evs []*m1pv1.Event) error {
		*got = append(*got, evs...)
		return nil
	}
}

// TestRotation: the path's file identity changes under a held handle — the
// old inode drains to EOF first, then the new file is followed from 0
// (04 §2.1), with nothing lost and nothing doubled.
func TestRotation(t *testing.T) {
	dir, state := t.TempDir(), t.TempDir()
	path := filepath.Join(dir, testSession.String()+".jsonl")
	if err := os.WriteFile(path, []byte(usageLine("msg_1", "req_1", 10)), 0o600); err != nil {
		t.Fatal(err)
	}
	tl := newTestTailer(t, path, state)
	var got []*m1pv1.Event
	now := time.Now()
	if err := tl.poll(now, collect(&got)); err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 { // msg_1 pends
		t.Fatalf("premature emission: %d", len(got))
	}
	// Rotate: a NEW inode appears at the path.
	next := filepath.Join(dir, "next")
	if err := os.WriteFile(next, []byte(usageLine("msg_2", "req_2", 20)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(next, path); err != nil {
		t.Fatal(err)
	}
	if err := tl.poll(now, collect(&got)); err != nil {
		t.Fatal(err)
	}
	if err := tl.flushAndSave(collect(&got)); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].GetUsage().GetMessageId() != "msg_1" || got[1].GetUsage().GetMessageId() != "msg_2" {
		t.Fatalf("rotation lost or reordered: %d events", len(got))
	}
}

// TestTruncation: same identity, size < cursor ⇒ rewritten in place; re-scan
// from 0 and let idempotency absorb the replay (04 §2.1).
func TestTruncation(t *testing.T) {
	dir, state := t.TempDir(), t.TempDir()
	path := filepath.Join(dir, testSession.String()+".jsonl")
	if err := os.WriteFile(path, []byte(usageLine("msg_1", "req_1", 10)+usageLine("msg_2", "req_2", 20)), 0o600); err != nil {
		t.Fatal(err)
	}
	tl := newTestTailer(t, path, state)
	var got []*m1pv1.Event
	now := time.Now()
	if err := tl.poll(now, collect(&got)); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 { // msg_1 emitted when msg_2 appeared; msg_2 pends
		t.Fatalf("want 1 emission pre-truncation, got %d", len(got))
	}
	// Truncate + rewrite shorter: only msg_2, with the FINAL number.
	if err := os.WriteFile(path, []byte(usageLine("msg_2", "req_2", 25)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := tl.poll(now, collect(&got)); err != nil {
		t.Fatal(err)
	}
	if err := tl.flushAndSave(collect(&got)); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 total emissions, got %d", len(got))
	}
	if u := got[1].GetUsage(); u.GetMessageId() != "msg_2" || u.GetOutputTokens() != 25 {
		t.Fatalf("re-scan did not last-write-win: %+v", got[1].GetUsage())
	}
}

// TestCursorResume: a restart resumes from the persisted cursor — already
// emitted lines are not re-read, appended lines still flow.
func TestCursorResume(t *testing.T) {
	dir, state := t.TempDir(), t.TempDir()
	path := filepath.Join(dir, testSession.String()+".jsonl")
	if err := os.WriteFile(path, []byte(usageLine("msg_1", "req_1", 10)), 0o600); err != nil {
		t.Fatal(err)
	}
	tl := newTestTailer(t, path, state)
	var got []*m1pv1.Event
	if err := tl.poll(time.Now(), collect(&got)); err != nil {
		t.Fatal(err)
	}
	if err := tl.flushAndSave(collect(&got)); err != nil { // saves the cursor
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1, got %d", len(got))
	}
	tl.close()

	// Restart: same state dir, cursor keyed by (dev, inode) — no replay.
	tl2 := newTestTailer(t, path, state)
	var got2 []*m1pv1.Event
	if err := tl2.poll(time.Now(), collect(&got2)); err != nil {
		t.Fatal(err)
	}
	if len(got2) != 0 {
		t.Fatal("resume replayed an already-emitted line despite a valid cursor")
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(usageLine("msg_2", "req_2", 20)); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := tl2.poll(time.Now(), collect(&got2)); err != nil {
		t.Fatal(err)
	}
	if err := tl2.flushAndSave(collect(&got2)); err != nil {
		t.Fatal(err)
	}
	if len(got2) != 1 || got2[0].GetUsage().GetMessageId() != "msg_2" {
		t.Fatalf("appended line lost after resume: %d events", len(got2))
	}
}

// TestPartialLineNotConsumed: an unterminated tail line stays unconsumed —
// the cursor only ever advances over whole lines.
func TestPartialLineNotConsumed(t *testing.T) {
	dir, state := t.TempDir(), t.TempDir()
	path := filepath.Join(dir, testSession.String()+".jsonl")
	full := usageLine("msg_1", "req_1", 10)
	half := full[:len(full)/2]
	if err := os.WriteFile(path, []byte(half), 0o600); err != nil {
		t.Fatal(err)
	}
	tl := newTestTailer(t, path, state)
	var got []*m1pv1.Event
	if err := tl.poll(time.Now(), collect(&got)); err != nil {
		t.Fatal(err)
	}
	if tl.off != 0 {
		t.Fatalf("cursor advanced into a partial line: off=%d", tl.off)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(full[len(full)/2:]); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := tl.poll(time.Now(), collect(&got)); err != nil {
		t.Fatal(err)
	}
	if err := tl.flushAndSave(collect(&got)); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].GetUsage().GetOutputTokens() != 10 {
		t.Fatalf("completed line not parsed whole: %d events", len(got))
	}
}

// TestPostQuiesceRewriteDedupe pins the post-emission half of 07 §7 layer 1
// (C8 acceptance "zero duplicate Usage"): a rewrite arriving AFTER the 2 s
// quiesce flush already emitted its key must not duplicate — identical
// numbers are suppressed entirely; UPDATED numbers re-emit exactly once as a
// correction under the SAME idem_key, which the ledger resolves by keeping
// max(event_id) per idem_key (07 §7).
func TestPostQuiesceRewriteDedupe(t *testing.T) {
	s := stream{role: RoleParent, session: testSession, idemKey: testIdemKey}
	now := time.Now()
	if evs := s.consume([]byte(usageLine("msg_a", "req_a", 400)), now); len(evs) != 0 {
		t.Fatal("first key must pend, not emit")
	}
	first := s.quiet(now.Add(quiesce))
	if len(first) != 1 || first[0].GetUsage().GetOutputTokens() != 400 {
		t.Fatalf("quiesce flush emitted %d events", len(first))
	}

	// Identical post-flush rewrite (e.g. the post-compaction re-log): the
	// exact duplicate class — nothing may emit, now or on a later quiesce.
	now = now.Add(3 * quiesce)
	if evs := s.consume([]byte(usageLine("msg_a", "req_a", 400)), now); len(evs) != 0 {
		t.Fatalf("identical post-flush rewrite emitted %d events", len(evs))
	}
	if evs := s.quiet(now.Add(quiesce)); len(evs) != 0 {
		t.Fatalf("identical post-flush rewrite re-emitted on quiesce: %d events", len(evs))
	}

	// Updated numbers (the probe's out=400 → out=500 case): exactly one
	// correction, same idem_key, carrying the new cumulative counts.
	now = now.Add(3 * quiesce)
	if evs := s.consume([]byte(usageLine("msg_a", "req_a", 500)), now); len(evs) != 0 {
		t.Fatal("correction must pend, not emit inline")
	}
	second := s.quiet(now.Add(quiesce))
	if len(second) != 1 || second[0].GetUsage().GetOutputTokens() != 500 {
		t.Fatalf("correction flush emitted %d events", len(second))
	}
	if !bytes.Equal(first[0].GetUsage().GetIdemKey(), second[0].GetUsage().GetIdemKey()) {
		t.Fatal("correction changed idem_key — the server could no longer collapse it (07 §7)")
	}
	// And the correction itself deduplicates: replaying the 500 line is silent.
	if evs := s.consume([]byte(usageLine("msg_a", "req_a", 500)), now.Add(2*quiesce)); len(evs) != 0 {
		t.Fatal("replayed correction emitted again")
	}
}

// TestInterleavedRewritesDedupe pins the interleaving half: key A's rewrite
// arriving after key B flushed A must not re-emit A with unchanged numbers,
// and a changed-number rewrite emits once more with A's final counts — for
// any interleaving, the LAST emission per key carries the last line's numbers
// and no two emissions of one key carry identical numbers (07 §7).
func TestInterleavedRewritesDedupe(t *testing.T) {
	s := stream{role: RoleParent, session: testSession, idemKey: testIdemKey}
	now := time.Now()
	var got []*m1pv1.Event
	feed := func(msg, req string, out uint64) {
		got = append(got, s.consume([]byte(usageLine(msg, req, out)), now)...)
	}
	feed("msg_a", "req_a", 100)
	feed("msg_b", "req_b", 10)  // flushes A(100)
	feed("msg_a", "req_a", 100) // interleaved rewrite, numbers unchanged — silent
	feed("msg_a", "req_a", 150) // interleaved rewrite, numbers moved — flushes B, re-pends A
	got = append(got, s.flush()...)

	perKey := map[string][]uint64{}
	for _, ev := range got {
		u := ev.GetUsage()
		outs := perKey[u.GetMessageId()]
		if len(outs) > 0 && outs[len(outs)-1] == u.GetOutputTokens() {
			t.Fatalf("duplicate Usage for %s at %d output tokens", u.GetMessageId(), u.GetOutputTokens())
		}
		perKey[u.GetMessageId()] = append(outs, u.GetOutputTokens())
	}
	if len(got) != 3 {
		t.Fatalf("emitted %d events, want A(100), B(10), A(150)", len(got))
	}
	if outs := perKey["msg_a"]; len(outs) != 2 || outs[len(outs)-1] != 150 {
		t.Fatalf("msg_a emissions %v — last emission must carry the last line's numbers", outs)
	}
	if outs := perKey["msg_b"]; len(outs) != 1 || outs[0] != 10 {
		t.Fatalf("msg_b emissions %v", outs)
	}
}
