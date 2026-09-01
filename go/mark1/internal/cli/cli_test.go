package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func testEnv(t *testing.T) *Env {
	t.Helper()
	return &Env{StateDir: t.TempDir(), Stdout: os.Stderr, Stderr: os.Stderr}
}

func TestWriteFileAtomicModeAndContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "f.json")
	if err := WriteFileAtomic(path, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o, want 0600", fi.Mode().Perm())
	}
	if di, _ := os.Stat(filepath.Join(dir, "sub")); runtime.GOOS != "windows" && di.Mode().Perm() != 0o700 {
		t.Fatalf("parent dir mode %o, want 0700", di.Mode().Perm())
	}
	// Overwrite must replace whole content (rename semantics), never append.
	if err := WriteFileAtomic(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "x" {
		t.Fatalf("content %q after overwrite", data)
	}
	// No temp litter left behind.
	entries, _ := os.ReadDir(filepath.Join(dir, "sub"))
	if len(entries) != 1 {
		t.Fatalf("dir has %d entries, want 1", len(entries))
	}
}

func TestLoadEnrollmentAbsentIsNotEnrolled(t *testing.T) {
	env := testEnv(t)
	if _, err := env.LoadEnrollment(); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("got %v, want ErrNotEnrolled", err)
	}
}

func TestLoadEnrollmentRefusesLooseMode(t *testing.T) {
	env := testEnv(t)
	if err := env.SaveEnrollment(&Enrollment{Version: 1, State: "active", TokenExpiresAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(env.EnrollmentPath(), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := env.LoadEnrollment()
	if err == nil || errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("0644 enrollment loaded (err=%v); the 0600 floor must refuse", err)
	}
}

func TestSaveEnrollmentIsPrivate(t *testing.T) {
	env := testEnv(t)
	if err := env.SaveEnrollment(&Enrollment{Version: 1}); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(env.EnrollmentPath())
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("enrollment mode %o, want 0600", fi.Mode().Perm())
	}
}

func TestWorkspacesRoundTrip(t *testing.T) {
	env := testEnv(t)
	ws, err := env.LoadWorkspaces()
	if err != nil || len(ws.Workspaces) != 0 {
		t.Fatalf("fresh load: %v %v", ws, err)
	}
	ws.Workspaces = append(ws.Workspaces, WorkspaceEntry{Path: "/w", EnabledAt: time.Now()})
	if err := env.SaveWorkspaces(ws); err != nil {
		t.Fatal(err)
	}
	got, err := env.LoadWorkspaces()
	if err != nil || len(got.Workspaces) != 1 || got.Workspaces[0].Path != "/w" {
		t.Fatalf("round trip: %+v %v", got, err)
	}
}

// TestCoverageJournalStampsTheFrozenReasonCode. The CLI journals the window;
// mark1d receipts it (coverage.DrainJournal). The reason_code is what lets the
// daemon place the window at all, and 04 §2.7 assigns this command exactly two
// of its seven codes — so a kind outside that pair must be refused here rather
// than journalled into a line nothing downstream can classify.
func TestCoverageJournalStampsTheFrozenReasonCode(t *testing.T) {
	e := testEnv(t)
	for kind, want := range map[string]string{"enable": "user_enable", "disable": "mark1_off"} {
		rec := map[string]any{"ts": "2026-08-31T10:00:00Z", "kind": kind}
		if err := e.AppendCoverageTransition(rec); err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		if rec["reason"] != want {
			t.Errorf("kind %q stamped reason %v, want %q", kind, rec["reason"], want)
		}
	}
	// Positive control: both lines are on disk, whole, one per line, and each
	// decodes with the four keys mark1d's journalLine reads by name.
	data, err := os.ReadFile(e.CoveragePath())
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("journal has %d lines, want 2: %q", len(lines), data)
	}
	seen := map[string]bool{}
	for _, l := range lines {
		var got struct{ TS, Kind, Reason string }
		if err := json.Unmarshal([]byte(l), &got); err != nil {
			t.Fatalf("mark1d cannot parse a line this CLI wrote: %v (%q)", err, l)
		}
		if got.TS == "" || got.Kind == "" || got.Reason == "" {
			t.Errorf("line is missing a field the drain requires: %q", l)
		}
		seen[got.Reason] = true
	}
	if !seen["user_enable"] || !seen["mark1_off"] {
		t.Errorf("journal reasons = %v, want both user_enable and mark1_off", seen)
	}
}

// TestCoverageJournalRefusesAnUnplaceableKind: a line mark1d cannot classify
// costs the whole window, so it must fail at the CLI rather than land as an
// unreadable row.
func TestCoverageJournalRefusesAnUnplaceableKind(t *testing.T) {
	e := testEnv(t)
	for _, kind := range []any{"snoozed", "", nil, "ENABLE"} {
		if err := e.AppendCoverageTransition(map[string]any{"ts": "2026-08-31T10:00:00Z", "kind": kind}); err == nil {
			t.Errorf("kind %v was journalled; mark1d cannot receipt it", kind)
		}
	}
	if _, err := os.Stat(e.CoveragePath()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a refused transition still created the journal: %v", err)
	}
}
