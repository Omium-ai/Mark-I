package claudecode

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"

	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/tailers"
)

// TestSupportedVersionsMatchTheFixtureTree is what makes SupportedVersions a
// claim rather than a preference: an entry is a promise that a fixture proves
// the shape, so the set and conformance/hooks/claudecode must agree in BOTH
// directions. A const entry with no fixture is an unproven version we would
// parse blind; a fixture with no const entry is a version we captured evidence
// for and then refuse to read.
func TestSupportedVersionsMatchTheFixtureTree(t *testing.T) {
	// claudecode -> adapters -> mark1d -> go -> repo root.
	dir := filepath.Join("..", "..", "..", "..", "conformance", "hooks", "claudecode")
	ents, err := os.ReadDir(dir)
	if err != nil {
		// Never a skip: the fixture tree going missing is exactly the state
		// that would let SupportedVersions drift unchecked.
		t.Fatalf("fixture tree unreadable at %s: %v", dir, err)
	}
	fixtures := map[string]struct{}{}
	for _, e := range ents {
		if e.IsDir() {
			fixtures[strings.TrimPrefix(e.Name(), "v")] = struct{}{}
		}
	}
	if len(fixtures) == 0 {
		t.Fatalf("no version directories under %s", dir)
	}
	for v := range SupportedVersions {
		if _, ok := fixtures[v]; !ok {
			t.Errorf("SupportedVersions has %q with no fixture directory — that version would be parsed blind", v)
		}
	}
	for v := range fixtures {
		if _, ok := SupportedVersions[v]; !ok {
			t.Errorf("conformance/hooks/claudecode/v%s exists but %q is not in SupportedVersions — capture refuses a version we have evidence for", v, v)
		}
	}
}

func TestSupportedRefusesAnUnsniffableVersion(t *testing.T) {
	// Detect returns "" both when `claude --version` fails and when the binary
	// is not on the daemon's PATH. Neither may parse.
	if Supported("") {
		t.Fatal("an empty version is supported; not knowing the version and guessing the format are the same act")
	}
	if Supported("99.0.0") {
		t.Fatal("an unpinned future version is supported; FR-AGENT-002 requires the opposite")
	}
}

// TestTranscriptDirMunge pins 08 §5.1's fallback derivation verbatim —
// '/' replaced by '-' under ~/.claude/projects/ — on the synthetic pair the
// conformance corpus uses (never a real machine's home; the corpus's own
// selfcheck forbids such leaks).
func TestTranscriptDirMunge(t *testing.T) {
	a := &Adapter{Home: "/home/devuser"}
	got, err := a.TranscriptDir("/home/devuser/workspace/acme-app")
	if err != nil {
		t.Fatal(err)
	}
	want := "/home/devuser/.claude/projects/-home-devuser-workspace-acme-app"
	if got != want {
		t.Fatalf("munge = %q, want %q", got, want)
	}
}

// TestStartTailWorkspaceGate: a root outside the WorkspaceSet is refused —
// discovery is bound to the invariant-3 oracle (04 §2.1).
func TestStartTailWorkspaceGate(t *testing.T) {
	enabled := t.TempDir()
	other := t.TempDir()
	set, err := tailers.NewWorkspaceSet(enabled)
	if err != nil {
		t.Fatal(err)
	}
	a := &Adapter{Home: t.TempDir()}
	key, err := tailers.DeriveUsageIdemKey([]byte("test-tenant-root"))
	if err != nil || len(key) != 32 {
		t.Fatalf("HKDF usage-idem key: %v len %d", err, len(key))
	}
	cfg := TailConfig{
		StateDir:     filepath.Join(t.TempDir(), "cursors"),
		UsageIdemKey: key,
		Emit:         func(context.Context, *m1pv1.Event) error { return nil },
	}
	if _, err := a.StartTail(adapters.Workspace{Root: other}, set, cfg); err == nil {
		t.Fatal("root outside the enabled set was accepted")
	}
	mgr, err := a.StartTail(adapters.Workspace{Root: enabled}, set, cfg)
	if err != nil || mgr == nil {
		t.Fatalf("enabled root refused: %v", err)
	}
}

// TestStartTailFollowsDerivedDir: end to end through the adapter — a
// transcript appearing in the derived vendor dir yields Usage emissions.
func TestStartTailFollowsDerivedDir(t *testing.T) {
	home := t.TempDir()
	root := t.TempDir()
	set, err := tailers.NewWorkspaceSet(root)
	if err != nil {
		t.Fatal(err)
	}
	a := &Adapter{Home: home}
	dir, err := a.TranscriptDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	session := "3f9c2e71-58d4-4b6a-9e2f-7a1c0d8b4e55"
	// cwd inside the enabled root: discovery's containment gate (04 §2.1)
	// reads it from the stream head — a cwd-less line would never be tailed.
	line := `{"type":"assistant","cwd":"` + root + `","requestId":"req_x","sessionId":"` + session + `","message":{"id":"msg_x","model":"claude-fable-5","usage":{"input_tokens":1,"output_tokens":9,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"service_tier":"standard"}}}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, session+".jsonl"), []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	key, _ := tailers.DeriveUsageIdemKey([]byte("test-tenant-root"))
	var got []*m1pv1.Event
	mgr, err := a.StartTail(adapters.Workspace{Root: root}, set, TailConfig{
		StateDir:     filepath.Join(home, "cursors"),
		UsageIdemKey: key,
		Emit: func(_ context.Context, ev *m1pv1.Event) error {
			got = append(got, ev)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	mgr.Sweep(ctx)
	if err := mgr.CloseFlush(ctx); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].GetUsage().GetOutputTokens() != 9 {
		t.Fatalf("derived-dir tail emitted %d events", len(got))
	}
	if bytes.Equal(got[0].GetUsage().GetIdemKey(), make([]byte, 32)) {
		t.Fatal("idem_key missing — ingest would 422 this Usage (08 §2.4)")
	}
}

// TestMungeCollisionForeignWorkspaceNeverEmits: the '/'→'-' munge is lossy —
// <base>/ws/app and <base>/ws-app derive the SAME vendor dir — so enabling
// one workspace must not capture the other's transcripts (04 §0.3 invariant
// 3; 04 §2.1 "a transcript whose cwd resolves outside an enabled root is not
// opened, full stop").
func TestMungeCollisionForeignWorkspaceNeverEmits(t *testing.T) {
	home := t.TempDir()
	base := t.TempDir()
	enabled := filepath.Join(base, "ws", "app")
	foreign := filepath.Join(base, "ws-app")
	for _, d := range []string{enabled, foreign} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	a := &Adapter{Home: home}
	dirEnabled, err := a.TranscriptDir(enabled)
	if err != nil {
		t.Fatal(err)
	}
	dirForeign, err := a.TranscriptDir(foreign)
	if err != nil {
		t.Fatal(err)
	}
	if dirEnabled != dirForeign {
		t.Fatalf("fixture drift: %q and %q no longer collide — this test needs a colliding pair", dirEnabled, dirForeign)
	}
	if err := os.MkdirAll(dirEnabled, 0o700); err != nil {
		t.Fatal(err)
	}
	usageLine := func(cwd, session, msg string) string {
		return `{"type":"assistant","cwd":"` + cwd + `","requestId":"req_` + msg + `","sessionId":"` + session + `","message":{"id":"msg_` + msg + `","model":"claude-fable-5","usage":{"input_tokens":1,"output_tokens":7,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"service_tier":"standard"}}}` + "\n"
	}
	ours := "3f9c2e71-58d4-4b6a-9e2f-7a1c0d8b4e55"
	theirs := "9b2d4f60-1e3a-4c58-8a7d-2f5b6c9d0e11"
	if err := os.WriteFile(filepath.Join(dirEnabled, ours+".jsonl"), []byte(usageLine(enabled, ours, "ours")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dirEnabled, theirs+".jsonl"), []byte(usageLine(foreign, theirs, "theirs")), 0o600); err != nil {
		t.Fatal(err)
	}

	set, err := tailers.NewWorkspaceSet(enabled)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := tailers.DeriveUsageIdemKey([]byte("test-tenant-root"))
	var got []*m1pv1.Event
	mgr, err := a.StartTail(adapters.Workspace{Root: enabled}, set, TailConfig{
		StateDir:     filepath.Join(home, "cursors"),
		UsageIdemKey: key,
		Emit: func(_ context.Context, ev *m1pv1.Event) error {
			got = append(got, ev)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	mgr.Sweep(ctx)
	if err := mgr.CloseFlush(ctx); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("emitted %d events, want exactly the enabled workspace's 1", len(got))
	}
	if got[0].GetUsage().GetMessageId() != "msg_ours" {
		t.Fatalf("emitted %q — the foreign workspace's transcript was captured (invariant 3)", got[0].GetUsage().GetMessageId())
	}
}
