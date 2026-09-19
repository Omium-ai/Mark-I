//go:build unix

package tailers

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/coverage"
	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

func stampedLine(msg string, at time.Time) string {
	return fmt.Sprintf(`{"type":"assistant","timestamp":%q,"requestId":"req_%s","sessionId":%q,"message":{"id":"msg_%s","model":"claude-fable-5","usage":{"input_tokens":1,"output_tokens":5,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"service_tier":"standard"}}}`+"\n",
		at.UTC().Format(time.RFC3339Nano), msg, testSession.String(), msg)
}

// backfillTailer writes lines to a transcript, sets its mtime, and opens it as a FIRST tail at now under the 30 d window.
func backfillTailer(t *testing.T, now, mtime time.Time, lines ...string) (*Tailer, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), testSession.String()+".jsonl")
	var body string
	for _, l := range lines {
		body += l
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatal(err)
	}
	tl, err := newTailer(path, t.TempDir(), stream{role: RoleParent, session: testSession, idemKey: testIdemKey}, now, BackfillWindow)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tl.close)
	return tl, path
}

func drain(t *testing.T, tl *Tailer, now time.Time) []*m1pv1.Event {
	t.Helper()
	var got []*m1pv1.Event
	if err := tl.poll(now, collect(&got)); err != nil {
		t.Fatal(err)
	}
	if err := tl.flushAndSave(collect(&got)); err != nil {
		t.Fatal(err)
	}
	return got
}

func messageIDs(evs []*m1pv1.Event) []string {
	var ids []string
	for _, ev := range evs {
		if u := ev.GetUsage(); u != nil {
			ids = append(ids, u.GetMessageId())
		}
	}
	return ids
}

// An untouched-for-31-days transcript is never replayed: the first tail starts at EOF, and only lines appended afterwards flow, as live capture, with no import marker.
func TestBackfillSkipsTranscriptOlderThanWindow(t *testing.T) {
	now := time.Now()
	old := now.Add(-BackfillWindow - 24*time.Hour)
	tl, path := backfillTailer(t, now, old, stampedLine("a", old), stampedLine("b", old.Add(time.Hour)))
	if got := drain(t, tl, now); len(got) != 0 {
		t.Fatalf("stale transcript replayed %d events", len(got))
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(stampedLine("live", now.Add(time.Second))); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	got := drain(t, tl, now.Add(time.Second))
	if ids := messageIDs(got); len(got) != 1 || len(ids) != 1 || ids[0] != "msg_live" {
		t.Fatalf("appended live line must flow alone, got %d events %v", len(got), ids)
	}
}

// A transcript straddling the cutoff starts at the first line inside the window; the history_import marker precedes the first imported Usage and spans back to that line.
func TestBackfillBoundaryStartsInsideWindow(t *testing.T) {
	now := time.Now()
	cutoff := now.Add(-BackfillWindow)
	tl, _ := backfillTailer(t, now, now.Add(-time.Hour),
		stampedLine("before", cutoff.Add(-time.Second)),
		stampedLine("at", cutoff),
		stampedLine("inside", cutoff.Add(time.Hour)),
	)
	got := drain(t, tl, now)
	if ids := messageIDs(got); len(ids) != 2 || ids[0] != "msg_at" || ids[1] != "msg_inside" {
		t.Fatalf("want the two in-window lines, got %v", ids)
	}
	ct := got[0].GetCoverageTransition()
	if ct == nil || ct.GetReasonCode() != coverage.ReasonHistoryImport || ct.GetKind() != m1pv1.CoverageKind_COVERAGE_KIND_BYPASS {
		t.Fatalf("first emission must be the history_import BYPASS marker, got %v", got[0])
	}
	if string(got[0].GetSessionId()) != string(testSession[:]) || len(ct.GetWorkspaceId()) != coverage.WorkspaceIDLen {
		t.Fatalf("marker must ride the session with a 32-byte workspace id: %v", got[0])
	}
	if want := uint64(BackfillWindow.Milliseconds()); ct.GetDurationMs() < want-1000 || ct.GetDurationMs() > want+1000 {
		t.Fatalf("marker window = %d ms, want ~%d (first-tail instant back to the oldest imported line)", ct.GetDurationMs(), want)
	}
	if got[0].GetOccurredAt().AsTime().Sub(now).Abs() > time.Millisecond {
		t.Fatalf("marker occurred_at = %v, want the first-tail instant %v", got[0].GetOccurredAt().AsTime(), now)
	}
}

// A fresh transcript imports whole, marked once; lines appended after first tail are live and the marker does not repeat.
func TestBackfillFreshTranscriptImportsWholeMarkedOnce(t *testing.T) {
	now := time.Now()
	tl, path := backfillTailer(t, now, now.Add(-time.Minute),
		stampedLine("x", now.Add(-2*24*time.Hour)),
		stampedLine("y", now.Add(-24*time.Hour)),
	)
	got := drain(t, tl, now)
	if ids := messageIDs(got); len(got) != 3 || len(ids) != 2 || got[0].GetCoverageTransition() == nil {
		t.Fatalf("want marker + 2 imported Usage, got %d events %v", len(got), ids)
	}
	if d := got[0].GetCoverageTransition().GetDurationMs(); d != uint64((2 * 24 * time.Hour).Milliseconds()) {
		t.Fatalf("marker window = %d ms, want 2 d", d)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(stampedLine("live", now.Add(time.Second))); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if got := drain(t, tl, now.Add(time.Second)); len(got) != 1 || got[0].GetUsage().GetMessageId() != "msg_live" {
		t.Fatalf("live append must flow without a second marker, got %d events", len(got))
	}
}

// Window 0 is today's behaviour: everything imports, nothing is marked — the corpus replays depend on it.
func TestBackfillWindowZeroImportsEverythingUnmarked(t *testing.T) {
	now := time.Now()
	old := now.Add(-2 * BackfillWindow)
	path := filepath.Join(t.TempDir(), testSession.String()+".jsonl")
	if err := os.WriteFile(path, []byte(stampedLine("a", old)+stampedLine("b", old.Add(time.Hour))), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	tl, err := newTailer(path, t.TempDir(), stream{role: RoleParent, session: testSession, idemKey: testIdemKey}, now, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tl.close)
	if got := drain(t, tl, now); len(got) != 2 || got[0].GetUsage() == nil {
		t.Fatalf("unbounded tail must replay both lines with no marker, got %d", len(got))
	}
}

// A cursor beats the window: a resumed stream never re-filters or re-marks.
func TestBackfillCursorResumeIsNotAFirstTail(t *testing.T) {
	now := time.Now()
	tl, path := backfillTailer(t, now, now, stampedLine("a", now.Add(-time.Hour)), stampedLine("b", now.Add(-time.Minute)))
	if got := drain(t, tl, now); len(got) != 3 {
		t.Fatalf("first tail: want marker + 2, got %d", len(got))
	}
	tl.close()
	resumed, err := newTailer(path, tl.stateDir, stream{role: RoleParent, session: testSession, idemKey: testIdemKey}, now.Add(time.Minute), BackfillWindow)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(resumed.close)
	if !resumed.str.importAt.IsZero() || resumed.off == 0 {
		t.Fatalf("resume must land on the cursor with no import window: off=%d importAt=%v", resumed.off, resumed.str.importAt)
	}
}
