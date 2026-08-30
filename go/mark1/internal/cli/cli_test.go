package cli

import (
	"errors"
	"os"
	"path/filepath"
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
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o, want 0600", fi.Mode().Perm())
	}
	if di, _ := os.Stat(filepath.Join(dir, "sub")); di.Mode().Perm() != 0o700 {
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
	if fi.Mode().Perm() != 0o600 {
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
