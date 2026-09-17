package tailers

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

func jsonCwd(t *testing.T, cwd string) string {
	t.Helper()
	b, err := json.Marshal(map[string]string{"type": "user", "cwd": cwd})
	if err != nil {
		t.Fatal(err)
	}
	return string(b) + "\n"
}

func writeStream(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, path, body)
}

func TestSessionsTableFollowsAdmission(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(root, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	parent, foreign, torn := uuid.New(), uuid.New(), uuid.New()
	writeStream(t, filepath.Join(dir, parent.String()+".jsonl"), jsonCwd(t, sub))
	writeStream(t, filepath.Join(dir, parent.String(), "subagents", "agent-1.jsonl"), jsonCwd(t, root))
	writeStream(t, filepath.Join(dir, foreign.String()+".jsonl"), jsonCwd(t, "/elsewhere"))
	writeStream(t, filepath.Join(dir, torn.String()+".jsonl"), "")
	live := NewLiveSet()
	if err := live.SetRoots([]string{root}); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	mgr, err := NewManager(Config{
		Dir: dir, StateDir: t.TempDir(), Allowed: live.Allowed, Roots: live.Roots, Agent: "claudecode",
		UsageIdemKey: testIdemKey, Now: func() time.Time { return at }, PollInterval: 10 * time.Millisecond,
		Emit: func(context.Context, *m1pv1.Event) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	mgr.Sweep(ctx)
	got := mgr.Sessions()
	want := SessionInfo{Agent: "claudecode", Root: root, Cwd: sub, Started: at}
	if len(got) != 1 || got[parent] != want {
		t.Fatalf("sessions %+v, want only %s -> %+v (foreign is denied, torn is unattributable, the subagent rides the parent row)", got, parent, want)
	}
	if _, _, ok := Resolve(parent); ok {
		t.Fatal("Resolve answered for a manager that is not inside Run")
	}
	got[parent] = SessionInfo{}
	if mgr.Sessions()[parent] != want {
		t.Fatal("Sessions handed out the live map, not a copy")
	}
	late := filepath.Join(dir, parent.String(), "subagents", "agent-2.jsonl")
	writeStream(t, late, jsonCwd(t, root))
	mgr.open(late, RoleSubagent, parent)
	if mgr.Sessions()[parent] != want {
		t.Fatalf("a subagent discovered after its parent rewrote the row: %+v", mgr.Sessions()[parent])
	}

	rctx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- mgr.Run(rctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		agent, r, ok := Resolve(parent)
		if ok {
			if agent != "claudecode" || r != root {
				t.Fatalf("Resolve = (%q, %q), want (claudecode, %s)", agent, r, root)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Resolve never saw the running manager's session")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, _, ok := Resolve(foreign); ok {
		t.Fatal("a denied stream's session resolved")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, _, ok := Resolve(parent); ok {
		t.Fatal("a stopped manager still answers Resolve")
	}
	if len(mgr.Sessions()) != 0 {
		t.Fatal("CloseFlush left the session table populated")
	}

	mgr.Sweep(ctx)
	if len(mgr.Sessions()) != 1 {
		t.Fatal("re-sweep did not repopulate")
	}
	if _, _, ok := Resolve(parent); ok {
		t.Fatal("a manager outside Run answers Resolve")
	}
	if err := live.SetRoots(nil); err != nil {
		t.Fatal(err)
	}
	mgr.Sweep(ctx)
	if len(mgr.Sessions()) != 0 {
		t.Fatalf("revoked stream's session lingered: %+v", mgr.Sessions())
	}
}

func TestSessionRootIsTheInnermostEnabledRoot(t *testing.T) {
	outer, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	inner := filepath.Join(outer, "inner")
	leaf := filepath.Join(inner, "leaf")
	if err := os.MkdirAll(leaf, 0o700); err != nil {
		t.Fatal(err)
	}
	roots := []string{inner, outer}
	if got := enclosingRoot(roots, leaf); got != inner {
		t.Fatalf("enclosingRoot(leaf) = %q, want the innermost %q whatever the root order", got, inner)
	}
	if got := enclosingRoot(roots, outer); got != outer {
		t.Fatalf("enclosingRoot(outer) = %q, want %q", got, outer)
	}
	if got := enclosingRoot(roots, outer+"x"); got != "" {
		t.Fatalf("a sibling sharing the root's prefix resolved to %q", got)
	}
	if got := enclosingRoot(nil, leaf); got != "" {
		t.Fatalf("no roots resolved to %q", got)
	}
}

func TestRecentCwdsNewestFirstExistingOnly(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	dir := t.TempDir()
	write := func(name, cwd string, age time.Duration) string {
		p := filepath.Join(dir, name)
		body := ""
		if cwd != "" {
			body = jsonCwd(t, cwd)
		}
		mustWrite(t, p, body)
		at := time.Now().Add(-age)
		if err := os.Chtimes(p, at, at); err != nil {
			t.Fatal(err)
		}
		return p
	}
	paths := []string{
		write("b.jsonl", b, 5*time.Hour),
		write("old-a.jsonl", a, 4*time.Hour),
		write("gone.jsonl", filepath.Join(dir, "deleted"), 3*time.Hour),
		write("torn.jsonl", "", time.Hour),
		write("new-a.jsonl", a, 0),
		filepath.Join(dir, "missing.jsonl"),
	}
	got := RecentCwds(paths, nil, 0)
	if len(got) != 2 || got[0] != a || got[1] != b {
		t.Fatalf("RecentCwds = %v, want [%s %s]: newest first, one row per cwd, no deleted dirs, torn heads skipped", got, a, b)
	}
	if got := RecentCwds(paths, nil, 1); len(got) != 1 || got[0] != a {
		t.Fatalf("limit 1 = %v", got)
	}
	if got := RecentCwds(nil, nil, 0); got == nil || len(got) != 0 {
		t.Fatalf("empty tree must be an empty list, not nil: %v", got)
	}
}
