package intent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/redact"
)

const secret = "AKIAIOSFODNN7EXAMPLE"

var t0 = time.Date(2026, 9, 26, 10, 0, 0, 0, time.UTC)

func fixture(t *testing.T, cwd string, session [16]byte, long string) string {
	t.Helper()
	projects := t.TempDir()
	dir := filepath.Join(projects, "-home-dev-app")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	at := func(s int) string { return t0.Add(time.Duration(s) * time.Second).Format(time.RFC3339Nano) }
	lines := []map[string]any{
		{"type": "user", "cwd": cwd, "timestamp": at(0), "message": map[string]any{"role": "user", "content": "Add pagination to the list view"}},
		{"type": "assistant", "cwd": cwd, "timestamp": at(5), "message": map[string]any{"content": []map[string]any{{"type": "text", "text": "Done, all tests pass"}}}},
		{"type": "user", "cwd": cwd, "timestamp": at(6), "toolUseResult": map[string]any{"stdout": "ANCHOR_OUTPUT ruff E501"}, "message": map[string]any{"content": []map[string]any{{"type": "tool_result", "content": "ANCHOR_OUTPUT ruff E501"}}}},
		{"type": "user", "cwd": cwd, "timestamp": at(7), "isMeta": true, "message": map[string]any{"content": []map[string]any{{"type": "text", "text": "INJECTED_META"}}}},
		{"type": "user", "cwd": cwd, "timestamp": at(60), "isSidechain": true, "message": map[string]any{"content": "SUBAGENT_PROMPT"}},
		{"type": "user", "cwd": cwd, "timestamp": at(60), "message": map[string]any{"content": []map[string]any{{"type": "text", "text": "Fix the off-by-one in next_page; creds " + secret}}}},
		{"type": "user", "cwd": cwd, "timestamp": at(120), "message": map[string]any{"content": long}},
		{"type": "user", "cwd": cwd, "timestamp": at(600), "message": map[string]any{"content": "A later task"}},
	}
	f, err := os.Create(filepath.Join(dir, uuid.UUID(session).String()+".jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	for _, l := range lines {
		b, _ := json.Marshal(l)
		_, _ = f.Write(append(b, '\n'))
	}
	_, _ = f.WriteString("{not json\n")
	return projects
}

func open(p *Provider, session, task [16]byte, at time.Time) *m1pv1.Event {
	ev := &m1pv1.Event{SessionId: session[:], TaskId: task[:], OccurredAt: timestamppb.New(at),
		Body: &m1pv1.Event_TaskOpen{TaskOpen: &m1pv1.TaskOpen{TaskSegVersion: "task_seg.v1"}}}
	p.Observe(ev)
	return ev
}

func scanner(t *testing.T) *redact.Scanner {
	t.Helper()
	sc, err := redact.NewScanner(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return sc
}

func TestIntentIsTheOpeningPromptRedactedAndScoped(t *testing.T) {
	session := [16]byte{1, 2, 3}
	long := strings.Repeat("h", 3000) + strings.Repeat("m", 5000) + "TAIL_MARK"
	projects := fixture(t, "/home/dev/app/pkg", session, long)
	allowed := func(cwd string) bool { return strings.HasPrefix(cwd, "/home/dev/app") }
	p := New(projects, allowed, scanner(t))
	first, second, third, unknown := [16]byte{10}, [16]byte{11}, [16]byte{12}, [16]byte{13}
	open(p, session, first, t0.Add(2*time.Second))
	ev := open(p, session, second, t0.Add(61*time.Second))
	open(p, session, third, t0.Add(121*time.Second))
	before := proto.Clone(ev)

	if got, ok := p.Intent(session, first); !ok || got != "Add pagination to the list view" {
		t.Fatalf("first task intent %q %v", got, ok)
	}
	got, ok := p.Intent([16]byte{}, second)
	if !ok || !strings.HasPrefix(got, "Fix the off-by-one in next_page; creds ") {
		t.Fatalf("second task intent %q %v", got, ok)
	}
	for _, banned := range []string{secret, "ANCHOR_OUTPUT", "all tests pass", "INJECTED_META", "SUBAGENT_PROMPT", "A later task"} {
		if strings.Contains(got, banned) {
			t.Fatalf("intent carries %q: %q", banned, got)
		}
	}
	if !strings.Contains(got, "redacted") {
		t.Fatalf("the key was not replaced by a redaction token: %q", got)
	}
	capped, ok := p.Intent(session, third)
	if !ok || len(capped) > MaxBytes || !strings.HasPrefix(capped, strings.Repeat("h", 1800)) || !strings.HasSuffix(capped, "TAIL_MARK") {
		t.Fatalf("cap: %d bytes ok=%v", len(capped), ok)
	}
	if _, ok := p.Intent(session, unknown); ok {
		t.Fatal("a task never opened has no intent")
	}
	if _, ok := p.Intent([16]byte{9}, first); ok {
		t.Fatal("another session's task has no intent")
	}
	if !proto.Equal(before, ev) {
		t.Fatal("Observe mutated the event: intent must never ride the wire")
	}
	b, _ := proto.Marshal(ev)
	if strings.Contains(string(b), "off-by-one") {
		t.Fatal("intent text reached the event bytes")
	}
}

func TestIntentRespectsEnabledWorkspaces(t *testing.T) {
	session := [16]byte{4}
	projects := fixture(t, "/home/dev/secret-repo", session, "x")
	task := [16]byte{20}
	p := New(projects, func(cwd string) bool { return strings.HasPrefix(cwd, "/home/dev/app") }, scanner(t))
	open(p, session, task, t0.Add(2*time.Second))
	if got, ok := p.Intent(session, task); ok || got != "" {
		t.Fatalf("a transcript outside every enabled workspace is never read: %q", got)
	}
	noScanner := New(projects, func(string) bool { return true }, nil)
	open(noScanner, session, task, t0.Add(2*time.Second))
	if _, ok := noScanner.Intent(session, task); ok {
		t.Fatal("no scanner ⇒ no intent, never raw text")
	}
}
