package coverage

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/spool"
)

// The exact bytes go/mark1's three writers put on disk. Restated as literals
// rather than built from a helper: this is a cross-MODULE contract (go/mark1
// and go/mark1d do not import each other), so a test that generated the lines
// from this package's own struct would agree with itself forever while the CLI
// drifted away underneath it.
const (
	cliEnableLine  = `{"kind":"enable","reason":"user_enable","ts":"2026-08-31T10:00:00Z","workspace":"/home/dev/project"}`
	cliDisableLine = `{"kind":"disable","reason":"mark1_off","scope":"all","ts":"2026-08-31T11:30:00Z","until":"2026-08-31T13:30:00Z"}`
	cliOnLine      = `{"kind":"enable","reason":"user_enable","scope":"all","ts":"2026-08-31T12:00:00Z"}`
)

func writeJournal(t *testing.T, stateDir string, lines ...string) {
	t.Helper()
	p := JournalPath(stateDir)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	for _, l := range lines {
		if _, err := f.WriteString(l + "\n"); err != nil {
			t.Fatal(err)
		}
	}
}

// TestDrainJournalReceiptsTheCLIsWindows is the positive control for sites 3
// and 4: `mark1 enable`, `mark1 off` and `mark1 on` cannot sign (08 §7.6 makes
// all three work with the daemon down), so the ONLY thing that turns their
// windows into receipted events is this drain. It must reach the spool, and it
// must carry the CLI's timestamp — not the drain's.
func TestDrainJournalReceiptsTheCLIsWindows(t *testing.T) {
	cov, sp := wire(t)
	state := t.TempDir()
	writeJournal(t, state, cliEnableLine, cliDisableLine, cliOnLine)

	n, err := cov.DrainJournal(context.Background(), state)
	if err != nil {
		t.Fatalf("DrainJournal: %v", err)
	}
	if n != 3 {
		t.Fatalf("drained %d transitions, want 3", n)
	}
	got := landed(t, sp)
	if len(got) != 3 {
		t.Fatalf("spooled = %d, want 3 — the drain reported work it did not do", len(got))
	}

	want := []struct {
		reason string
		kind   m1pv1.CoverageKind
		at     string
		ws     []byte
	}{
		{ReasonUserEnable, m1pv1.CoverageKind_COVERAGE_KIND_ENABLE, "2026-08-31T10:00:00Z", cov.WorkspaceID("/home/dev/project")},
		{ReasonMark1Off, m1pv1.CoverageKind_COVERAGE_KIND_DISABLE, "2026-08-31T11:30:00Z", DeviceWide()},
		{ReasonUserEnable, m1pv1.CoverageKind_COVERAGE_KIND_ENABLE, "2026-08-31T12:00:00Z", DeviceWide()},
	}
	for i, w := range want {
		if got[i].ct.GetReasonCode() != w.reason {
			t.Errorf("[%d] reason = %q, want %q", i, got[i].ct.GetReasonCode(), w.reason)
		}
		if got[i].ct.GetKind() != w.kind {
			t.Errorf("[%d] kind = %v, want %v", i, got[i].ct.GetKind(), w.kind)
		}
		// The CLI's ts, NOT the drain's clock. A daemon that was down for an
		// hour would otherwise move an `off` window an hour forward, and the
		// band would credit coverage the customer never had.
		if at := got[i].ev.GetOccurredAt().AsTime().UTC().Format(time.RFC3339); at != w.at {
			t.Errorf("[%d] occurred_at = %s, want the CLI's %s", i, at, w.at)
		}
		// `off --workspace` collapses to scope "all" today, and "all" is not a
		// path: it must not be HMAC'd as one.
		if string(got[i].ct.GetWorkspaceId()) != string(w.ws) {
			t.Errorf("[%d] workspace_id is the wrong surface", i)
		}
	}
}

// TestDrainJournalRecoversAPreReasonJournal. The CLI only started stamping
// `reason` in this change, so every box that ran `mark1 off` or `mark1 enable`
// before it has journal lines carrying kind and no reason. Refusing them would
// throw away real windows on exactly the machines that have been running
// longest; nothing is guessed, because the two kinds the CLI can write map 1:1
// onto the two codes 04 §2.7 assigns it.
func TestDrainJournalRecoversAPreReasonJournal(t *testing.T) {
	cov, sp := wire(t)
	state := t.TempDir()
	writeJournal(t, state,
		`{"kind":"enable","ts":"2026-08-31T10:00:00Z","workspace":"/home/dev/project"}`,
		`{"kind":"disable","scope":"all","ts":"2026-08-31T11:30:00Z"}`)

	if n, err := cov.DrainJournal(context.Background(), state); err != nil || n != 2 {
		t.Fatalf("n=%d err=%v, want 2, nil — pre-reason windows were dropped", n, err)
	}
	got := landed(t, sp)
	if len(got) != 2 {
		t.Fatalf("spooled = %d, want 2", len(got))
	}
	if got[0].ct.GetReasonCode() != ReasonUserEnable || got[0].ct.GetKind() != m1pv1.CoverageKind_COVERAGE_KIND_ENABLE {
		t.Errorf("enable recovered as %v/%q", got[0].ct.GetKind(), got[0].ct.GetReasonCode())
	}
	if got[1].ct.GetReasonCode() != ReasonMark1Off || got[1].ct.GetKind() != m1pv1.CoverageKind_COVERAGE_KIND_DISABLE {
		t.Errorf("disable recovered as %v/%q", got[1].ct.GetKind(), got[1].ct.GetReasonCode())
	}
}

// TestDrainJournalDoesNotReReceiptWhatItAlreadyDid: the cursor is what keeps a
// 5-second tick from re-emitting the whole journal every pass, which would
// bury the real transitions in duplicates and burn billing-grade spool space.
func TestDrainJournalDoesNotReReceiptWhatItAlreadyDid(t *testing.T) {
	cov, sp := wire(t)
	state := t.TempDir()
	writeJournal(t, state, cliEnableLine)

	if n, err := cov.DrainJournal(context.Background(), state); err != nil || n != 1 {
		t.Fatalf("first drain: n=%d err=%v, want 1, nil", n, err)
	}
	if n, err := cov.DrainJournal(context.Background(), state); err != nil || n != 0 {
		t.Fatalf("second drain: n=%d err=%v, want 0, nil — the cursor did not hold", n, err)
	}
	if got := landed(t, sp); len(got) != 1 {
		t.Fatalf("spooled = %d after two drains, want 1", len(got))
	}

	// Positive control: a NEW line after a consumed one is still picked up.
	// Without this, "0 on the second pass" is satisfied by a drain that has
	// simply stopped working.
	writeJournal(t, state, cliDisableLine)
	if n, err := cov.DrainJournal(context.Background(), state); err != nil || n != 1 {
		t.Fatalf("third drain: n=%d err=%v, want 1, nil — the cursor wedged", n, err)
	}
	if got := landed(t, sp); len(got) != 2 {
		t.Fatalf("spooled = %d, want 2", len(got))
	}
}

// TestDrainJournalWaitsForAWholeLine: the CLI appends while the daemon reads,
// so the drain WILL sometimes see a half-written line. Receipting half a
// transition is worse than waiting 5 seconds for the rest of it.
func TestDrainJournalWaitsForAWholeLine(t *testing.T) {
	cov, sp := wire(t)
	state := t.TempDir()
	p := JournalPath(state)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	half := cliEnableLine[:40]
	if err := os.WriteFile(p, []byte(cliDisableLine+"\n"+half), 0o600); err != nil {
		t.Fatal(err)
	}

	n, err := cov.DrainJournal(context.Background(), state)
	if err != nil {
		t.Fatalf("a fragment should be waited on, not errored: %v", err)
	}
	if n != 1 {
		t.Fatalf("drained %d, want 1 — the complete line before the fragment", n)
	}

	// The CLI finishes its write; the next pass must pick the line up WHOLE.
	if err := os.WriteFile(p, []byte(cliDisableLine+"\n"+cliEnableLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if n, err := cov.DrainJournal(context.Background(), state); err != nil || n != 1 {
		t.Fatalf("completed line: n=%d err=%v, want 1, nil — the fragment was skipped, not waited on", n, err)
	}
	got := landed(t, sp)
	if len(got) != 2 {
		t.Fatalf("spooled = %d, want 2", len(got))
	}
	if got[1].ct.GetReasonCode() != ReasonUserEnable {
		t.Errorf("the completed line landed as %q", got[1].ct.GetReasonCode())
	}
}

// TestDrainJournalRefusesALineItCannotPlace. Both refusals cost a real window,
// so both are errors the caller logs as a gap — never silent skips. The cursor
// advances past them regardless: a line that will not parse now will not parse
// on the next tick either, and wedging would cost every LATER transition too.
func TestDrainJournalRefusesALineItCannotPlace(t *testing.T) {
	for _, c := range []struct{ name, line string }{
		{"unparseable", `{"kind":"enable",`},
		{"unknown kind", `{"kind":"snoozed","ts":"2026-08-31T10:00:00Z"}`},
		{"invented reason", `{"kind":"enable","reason":"network_flake","ts":"2026-08-31T10:00:00Z"}`},
		{"unusable ts", `{"kind":"enable","reason":"user_enable","ts":"yesterday"}`},
		{"missing ts", `{"kind":"enable","reason":"user_enable"}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			cov, sp := wire(t)
			state := t.TempDir()
			writeJournal(t, state, c.line, cliDisableLine)

			n, err := cov.DrainJournal(context.Background(), state)
			if err == nil {
				t.Fatalf("accepted %q; a window nobody can place must be reported, not guessed at", c.line)
			}
			if n != 0 {
				t.Errorf("reported %d receipted transitions from a refused line", n)
			}
			if got := landed(t, sp); len(got) != 0 {
				t.Fatalf("a refused line still reached the spool")
			}
			// The bad line must not wedge the good one behind it.
			n, err = cov.DrainJournal(context.Background(), state)
			if err != nil || n != 1 {
				t.Fatalf("recovery pass: n=%d err=%v, want 1, nil — one bad line stranded every later window", n, err)
			}
		})
	}
}

// TestDrainJournalHoldsTheCursorWhenTheSpoolShedsIt. A shed is transient — the
// spool drains and the next tick can retry — and this row is the evidence for a
// window the customer is billed on, so it must not be skipped past.
func TestDrainJournalHoldsTheCursorWhenTheSpoolShedsIt(t *testing.T) {
	state := t.TempDir()
	writeJournal(t, state, cliEnableLine)

	shed := true
	cov := New(func(context.Context, *m1pv1.Event) error {
		if shed {
			return spool.ErrDiagnosticShed
		}
		return nil
	}, nil)

	if n, err := cov.DrainJournal(context.Background(), state); err == nil || n != 0 {
		t.Fatalf("shed drain: n=%d err=%v, want 0 and an error", n, err)
	}
	shed = false
	if n, err := cov.DrainJournal(context.Background(), state); err != nil || n != 1 {
		t.Fatalf("retry after the shed: n=%d err=%v, want 1, nil — the cursor moved past a lost window", n, err)
	}
}

// TestDrainJournalSurvivesAReplacedJournal: if the file shrank, the cursor is
// describing a file that no longer exists. Re-reading from zero re-emits rows
// the band query absorbs; trusting the stale cursor would skip every line of
// the new file forever.
func TestDrainJournalSurvivesAReplacedJournal(t *testing.T) {
	cov, sp := wire(t)
	state := t.TempDir()
	writeJournal(t, state, cliEnableLine, cliDisableLine, cliOnLine)
	if n, err := cov.DrainJournal(context.Background(), state); err != nil || n != 3 {
		t.Fatalf("first drain: n=%d err=%v", n, err)
	}
	if err := os.WriteFile(JournalPath(state), []byte(cliDisableLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if n, err := cov.DrainJournal(context.Background(), state); err != nil || n != 1 {
		t.Fatalf("after truncation: n=%d err=%v, want 1, nil", n, err)
	}
	if got := landed(t, sp); len(got) != 4 {
		t.Fatalf("spooled = %d, want 4", len(got))
	}
}

// TestDrainJournalIsQuietWithNoJournal: a box where nobody has run enable or
// off must not log a gap every 5 seconds.
func TestDrainJournalIsQuietWithNoJournal(t *testing.T) {
	cov, _ := wire(t)
	if n, err := cov.DrainJournal(context.Background(), t.TempDir()); err != nil || n != 0 {
		t.Fatalf("n=%d err=%v, want 0, nil", n, err)
	}
}

// TestJournalPathMatchesTheCLI pins the cross-module string. go/mark1 and
// go/mark1d are separate modules that do not import each other, so this path
// is a contract kept by agreement — exactly like the OFF marker's name and the
// fabric socket's. cli.Env.CoveragePath() is the other half.
func TestJournalPathMatchesTheCLI(t *testing.T) {
	if got, want := JournalPath("/s"), filepath.Join("/s", "coverage", "transitions.jsonl"); got != want {
		t.Fatalf("JournalPath = %q, want %q (go/mark1/internal/cli.Env.CoveragePath)", got, want)
	}
}
