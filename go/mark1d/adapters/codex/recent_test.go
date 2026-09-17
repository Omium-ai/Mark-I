package codex

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"

	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/tailers"
)

// stageRollouts copies the pinned sessions tree with its two cwds rewritten to dirs that exist; mtimes follow name order, so aa03 (other) is newest.
func stageRollouts(t *testing.T) (codexHome, acme, other string) {
	t.Helper()
	exp := loadExpectations(t)
	acme, _ = filepath.EvalSymlinks(t.TempDir())
	other, _ = filepath.EvalSymlinks(t.TempDir())
	codexHome = t.TempDir()
	if err := os.CopyFS(codexHome, os.DirFS(filepath.Join(fixtureRoot, "transcripts"))); err != nil {
		t.Fatal(err)
	}
	paths, _ := filepath.Glob(filepath.Join(codexHome, "sessions", "*", "*", "*", "rollout-*.jsonl"))
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
	return codexHome, acme, other
}

func jsonPath(p string) string {
	b, _ := json.Marshal(p)
	return string(b[1 : len(b)-1])
}

func TestRecentProjectsReadsSessionMetaCwd(t *testing.T) {
	codexHome, acme, other := stageRollouts(t)
	a := &Adapter{Home: t.TempDir(), CodexHome: codexHome}
	if got := a.RecentProjects(0); !slices.Equal(got, []string{other, acme}) {
		t.Fatalf("RecentProjects = %v, want [%s %s] (newest rollout first, one row per cwd)", got, other, acme)
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
	if got := (&Adapter{Home: t.TempDir(), CodexHome: t.TempDir()}).RecentProjects(0); got == nil || len(got) != 0 {
		t.Fatalf("no sessions tree must be an empty list: %v", got)
	}
}

func TestStartTailFillsTheSessionTable(t *testing.T) {
	codexHome, acme, _ := stageRollouts(t)
	set, err := tailers.NewWorkspaceSet(acme)
	if err != nil {
		t.Fatal(err)
	}
	a := &Adapter{Home: t.TempDir(), CodexHome: codexHome}
	mgr, err := a.StartTail(adapters.Workspace{Root: acme}, set, TailConfig{StateDir: t.TempDir(), UsageIdemKey: testIdemKey,
		Emit: func(context.Context, *m1pv1.Event) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	mgr.Sweep(context.Background())
	got := mgr.Sessions()
	thread := uuid.MustParse("019965a0-0000-7000-8000-00000000aa01")
	if s := got[thread]; len(got) != 2 || s.Agent != "codex" || s.Root != acme || s.Cwd != acme {
		t.Fatalf("sessions %+v: the two acme threads carry agent codex and the enabled root; other-app is outside the oracle", got)
	}
}
