package adapters_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"

	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/codex"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/copilot"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/gemini"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/opencode"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/intent"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/redact"
)

const corpus = "../../../conformance/hooks"

// intentAt is the prompt a task opened at `at` in session reads through src alone, with only `root` enabled.
func intentAt(t *testing.T, src intent.Source, root string, session uuid.UUID, at time.Time) (string, bool) {
	t.Helper()
	sc, err := redact.NewScanner(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	p := intent.New("", func(cwd string) bool { return cwd == root || strings.HasPrefix(cwd, root+"/") }, sc)
	p.Sources = []intent.Source{src}
	task := uuid.New()
	p.Observe(&m1pv1.Event{SessionId: session[:], TaskId: task[:], OccurredAt: timestamppb.New(at),
		Body: &m1pv1.Event_TaskOpen{TaskOpen: &m1pv1.TaskOpen{TaskSegVersion: "task_seg.v1"}}})
	return p.Intent(session, task)
}

func at(s string) time.Time { v, _ := time.Parse(time.RFC3339Nano, s); return v }

type want struct {
	at, text string
	ok       bool
}

func check(t *testing.T, name string, src intent.Source, root string, session uuid.UUID, cases []want) {
	t.Helper()
	for _, c := range cases {
		got, ok := intentAt(t, src, root, session, at(c.at))
		if ok != c.ok || got != c.text {
			t.Errorf("%s task opened %s: %q %v, want %q %v", name, c.at, got, ok, c.text, c.ok)
		}
	}
	if got, ok := intentAt(t, src, "/home/devuser/elsewhere", session, at(cases[0].at)); ok || got != "" {
		t.Errorf("%s: a transcript outside every enabled workspace was read: %q", name, got)
	}
	if _, ok := intentAt(t, src, root, uuid.New(), at(cases[0].at)); ok {
		t.Errorf("%s: another session read this one's transcript", name)
	}
}

func TestCodexIntentIsThePersonsPromptNeverInjectedContext(t *testing.T) {
	src := codex.IntentSource(filepath.Join(corpus, "codex/v0.154.0/transcripts/sessions"))
	session := uuid.MustParse("019965a0-0000-7000-8000-00000000aa01")
	check(t, "codex corpus", src, "/home/devuser/workspace/acme-app", session, []want{
		{"2026-09-16T08:25:00.500Z", "Add a retry helper to the HTTP client and cover it with tests.", true},
		{"2026-09-16T08:30:10.000Z", "Now document it in README.", true},
	})

	dir := t.TempDir()
	day := filepath.Join(dir, "2026", "09", "26")
	if err := os.MkdirAll(day, 0o700); err != nil {
		t.Fatal(err)
	}
	s2 := uuid.MustParse("019965a0-0000-7000-8000-00000000bb01")
	lines := `{"timestamp":"2026-09-26T10:00:00.000Z","type":"session_meta","payload":{"id":"` + s2.String() + `","cwd":"/home/devuser/app"}}
{"timestamp":"2026-09-26T10:00:00.001Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"# AGENTS.md instructions for /home/devuser/app\n\n<INSTRUCTIONS>be terse</INSTRUCTIONS>"}]}}
{"timestamp":"2026-09-26T10:00:00.002Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"<environment_context>\n  <cwd>/home/devuser/app</cwd>\n</environment_context>"}]}}
{"timestamp":"2026-09-26T10:00:00.003Z","type":"event_msg","payload":{"type":"user_message","message":"Rename the flag to --dry-run","images":[]}}
{"timestamp":"2026-09-26T10:00:00.003Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"Rename the flag to --dry-run"}]}}
{"timestamp":"2026-09-26T10:05:00.000Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"<environment_context>\n  <cwd>/home/devuser/app/sub</cwd>\n</environment_context>"}]}}
{"timestamp":"2026-09-26T10:05:00.000Z","type":"response_item","payload":{"type":"function_call_output","call_id":"c","output":"PASS"}}
`
	if err := os.WriteFile(filepath.Join(day, "rollout-2026-09-26T10-00-00-"+s2.String()+".jsonl"), []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}
	check(t, "codex injected", codex.IntentSource(dir), "/home/devuser/app", s2, []want{
		{"2026-09-26T10:00:01.000Z", "Rename the flag to --dry-run", true},
		{"2026-09-26T10:06:00.000Z", "Rename the flag to --dry-run", true},
	})
}

func TestGeminiIntentIsATextUserRecordUnderItsAttestedProject(t *testing.T) {
	src := gemini.IntentSource(filepath.Join(corpus, "gemini/v0.59.0/transcripts/tmp"))
	check(t, "gemini corpus", src, "/home/devuser/workspace/acme-app", uuid.MustParse("6f1e2d3c-0000-4000-8000-00000000aa01"), []want{
		{"2026-09-16T08:25:01.500Z", "add a retry to the uploader", true},
		// the functionResponse record at 08:25:06 is a tool turn: the task still reads the person's prompt
		{"2026-09-16T08:25:30.000Z", "add a retry to the uploader", true},
	})
	// filed under the enabled slug with another project's hash, and another project's own chat: never read
	for _, s := range []string{"6f1e2d3c-0000-4000-8000-00000000aa04", "6f1e2d3c-0000-4000-8000-00000000aa03"} {
		if got, ok := intentAt(t, src, "/home/devuser/workspace/acme-app", uuid.MustParse(s), at("2026-09-16T10:00:00Z")); ok {
			t.Errorf("gemini %s is not attested to the enabled project, yet read %q", s, got)
		}
	}
}

func TestCopilotIntentIsUserMessageContentNeverTransformed(t *testing.T) {
	src := copilot.IntentSource(filepath.Join(corpus, "copilot/v1.0.85/transcripts/session-state"))
	check(t, "copilot corpus", src, "/home/devuser/acme-app", uuid.MustParse("c0910000-0000-4000-8000-00000000aa01"), []want{
		{"2026-09-16T10:19:25.000Z", "run echo synth-ok in the shell, then say ok", true},
	})
}

// The plugin's own chat.message note, composed by the corpus harness from the recorded plugin inputs, is what the reader reads.
func TestOpencodeIntentIsThePluginsChatMessageNote(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not on PATH: the plugin cannot run")
	}
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".omium/mark1"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".omium/mark1/workspaces.json"), []byte(`{"version":1,"workspaces":[{"path":"/home/devuser/workspace/acme-app"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(corpus, "opencode/v1.18.31")
	cmd := exec.Command(node, filepath.Join(root, "harness.mjs"), filepath.Join(root, "inputs/plugin-inputs.json"), "opencode/mark1.js", home) //nolint:gosec // G204: the repo's own harness
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("harness: %v %s", err, out)
	}
	notes := filepath.Join(home, ".omium/mark1/capture/opencode")
	if fi, err := os.Stat(filepath.Join(notes, "intent", "ses_0199a1b2c3d4SynthFixtuAA01.jsonl")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the plugin noted no prompt, or not 0600: %v %v", fi, err)
	}
	src := opencode.IntentSource(notes)
	session := opencode.SessionUUID("ses_0199a1b2c3d4SynthFixtuAA01")
	check(t, "opencode plugin", src, "/home/devuser/workspace/acme-app", session, []want{
		{time.Now().UTC().Format(time.RFC3339Nano), "add a retry to the uploader", true},
	})
}
