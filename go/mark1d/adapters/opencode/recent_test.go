package opencode

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"

	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/tailers"
)

// stageCaptures copies the pinned capture dir under a scratch home with both cwds rewritten to dirs that exist; mtimes follow name order, so FF01 (other) is newest.
func stageCaptures(t *testing.T) (home, acme, other string) {
	t.Helper()
	exp := loadExpectations(t)
	acme, _ = filepath.EvalSymlinks(t.TempDir())
	other, _ = filepath.EvalSymlinks(t.TempDir())
	home = t.TempDir()
	dir, _ := (&Adapter{Home: home}).CaptureDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.CopyFS(dir, os.DirFS(filepath.Join(fixtureRoot, "transcripts", "capture"))); err != nil {
		t.Fatal(err)
	}
	paths, _ := filepath.Glob(filepath.Join(dir, "ses_*.jsonl"))
	for i, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		s := strings.ReplaceAll(string(b), jsonPath(exp.WorkspaceRoot), jsonPath(acme))
		s = strings.ReplaceAll(s, jsonPath("/home/devuser/workspace/other-app"), jsonPath(other))
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		at := time.Now().Add(time.Duration(i-len(paths)) * time.Hour)
		if err := os.Chtimes(p, at, at); err != nil {
			t.Fatal(err)
		}
	}
	return home, acme, other
}

func jsonPath(p string) string {
	b, _ := json.Marshal(p)
	return string(b[1 : len(b)-1])
}

func TestRecentProjectsReadsAssistantPathCwd(t *testing.T) {
	home, acme, other := stageCaptures(t)
	a := &Adapter{Home: home}
	if got := a.RecentProjects(0); !slices.Equal(got, []string{other, acme}) {
		t.Fatalf("RecentProjects = %v, want [%s %s] (newest capture first)", got, other, acme)
	}
	if got := a.RecentProjects(1); !slices.Equal(got, []string{other}) {
		t.Fatalf("limit 1 = %v", got)
	}
	if err := os.RemoveAll(other); err != nil {
		t.Fatal(err)
	}
	if got := a.RecentProjects(0); !slices.Equal(got, []string{acme}) {
		t.Fatalf("a cwd no longer on disk is not a project: %v", got)
	}
	if got := (&Adapter{Home: t.TempDir()}).RecentProjects(0); got == nil || len(got) != 0 {
		t.Fatalf("no capture dir must be an empty list: %v", got)
	}
}

func TestStartTailFillsTheSessionTable(t *testing.T) {
	home, acme, _ := stageCaptures(t)
	set, err := tailers.NewWorkspaceSet(acme)
	if err != nil {
		t.Fatal(err)
	}
	mgr, err := (&Adapter{Home: home}).StartTail(adapters.Workspace{Root: acme}, set, TailConfig{StateDir: t.TempDir(), UsageIdemKey: testIdemKey,
		Emit: func(context.Context, *m1pv1.Event) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mgr.CloseFlush(context.Background()) })
	mgr.Sweep(context.Background())
	got := mgr.Sessions()
	if s := got[SessionUUID("ses_0199a1b2c3d4SynthFixtuAA01")]; len(got) != 1 || s.Agent != "opencode" || s.Root != acme || s.Cwd != acme {
		t.Fatalf("sessions %+v: acme's capture under its derived UUIDv5 id, other-app outside the oracle", got)
	}
}
