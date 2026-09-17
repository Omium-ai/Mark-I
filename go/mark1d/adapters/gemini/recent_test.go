package gemini

import (
	"context"
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

// stageChats copies the pinned tmp tree with both markers and their projectHash values rewritten to dirs that exist; mtimes follow glob order, so other-app's chat is newest.
func stageChats(t *testing.T) (geminiDir, acme, other string) {
	t.Helper()
	exp := loadExpectations(t)
	const otherFixture = "/home/devuser/workspace/other-app"
	acme, _ = filepath.EvalSymlinks(t.TempDir())
	other, _ = filepath.EvalSymlinks(t.TempDir())
	geminiDir = t.TempDir()
	if err := os.CopyFS(geminiDir, os.DirFS(filepath.Join(fixtureRoot, "transcripts"))); err != nil {
		t.Fatal(err)
	}
	rewrite := strings.NewReplacer(
		exp.WorkspaceRoot, acme, otherFixture, other,
		projectHash(exp.WorkspaceRoot), projectHash(acme), projectHash(otherFixture), projectHash(other),
	)
	markers, _ := filepath.Glob(filepath.Join(geminiDir, "tmp", "*", ".project_root"))
	chats, _ := filepath.Glob(filepath.Join(geminiDir, "tmp", "*", "chats", "session-*.jsonl"))
	for i, p := range append(markers, chats...) {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(rewrite.Replace(string(b))), 0o600); err != nil {
			t.Fatal(err)
		}
		at := time.Now().Add(time.Duration(i-len(markers)-len(chats)) * time.Hour)
		if err := os.Chtimes(p, at, at); err != nil {
			t.Fatal(err)
		}
	}
	return geminiDir, acme, other
}

func TestRecentProjectsResolvesMarkersThroughProjectHash(t *testing.T) {
	geminiDir, acme, other := stageChats(t)
	a := &Adapter{Home: t.TempDir(), GeminiDir: geminiDir}
	if got := a.RecentProjects(0); !slices.Equal(got, []string{other, acme}) {
		t.Fatalf("RecentProjects = %v, want [%s %s] (newest chat first; the mis-filed aa04 resolves by its hash, not its slug)", got, other, acme)
	}
	if got := a.RecentProjects(1); !slices.Equal(got, []string{other}) {
		t.Fatalf("limit 1 = %v", got)
	}
	if err := os.RemoveAll(other); err != nil {
		t.Fatal(err)
	}
	if got := a.RecentProjects(0); !slices.Equal(got, []string{acme}) {
		t.Fatalf("a marker no longer on disk is not a project: %v", got)
	}
	if got := (&Adapter{Home: t.TempDir(), GeminiDir: t.TempDir()}).RecentProjects(0); got == nil || len(got) != 0 {
		t.Fatalf("no tmp tree must be an empty list: %v", got)
	}
}

func TestStartTailFillsTheSessionTable(t *testing.T) {
	geminiDir, acme, _ := stageChats(t)
	set, err := tailers.NewWorkspaceSet(acme)
	if err != nil {
		t.Fatal(err)
	}
	a := &Adapter{Home: t.TempDir(), GeminiDir: geminiDir}
	mgr, err := a.StartTail(adapters.Workspace{Root: acme}, set, TailConfig{StateDir: t.TempDir(), UsageIdemKey: testIdemKey,
		Emit: func(context.Context, *m1pv1.Event) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mgr.CloseFlush(context.Background()) })
	mgr.Sweep(context.Background())
	got := mgr.Sessions()
	main := uuid.MustParse("6f1e2d3c-0000-4000-8000-00000000aa01")
	if s := got[main]; len(got) != 1 || s.Agent != "gemini" || s.Root != acme || s.Cwd != acme {
		t.Fatalf("sessions %+v: only acme's own chat (its subagent rides the same row); aa04 hashes to other-app and stays unattributable", got)
	}
}
