package corpus

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Omium-ai/omium-mark1/go/mark1/internal/cli"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters"
)

const fixtures = "../../../../conformance/hooks"

func fakeEnv(t *testing.T) (*cli.Env, *bytes.Buffer) {
	t.Helper()
	var out bytes.Buffer
	return &cli.Env{Stdout: &out, Stderr: &out}, &out
}

// TestHarvestGeminiRewritesIdentityAndProjectHash: the pinned gemini tree stands in for a
// live ~/.gemini/tmp; its "real" workspace is /home/devuser/workspace/acme-app, so the harvest
// maps a fake home + workspace onto it and the projectHash must follow the sanitized marker.
func TestHarvestGeminiRewritesIdentityAndProjectHash(t *testing.T) {
	home := t.TempDir()
	ws := filepath.Join(home, "code", "secret-proj")
	src := filepath.Join(home, ".gemini", "tmp", "slug1")
	if err := os.MkdirAll(filepath.Join(src, "chats"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, ".project_root"), []byte(ws+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(ws))
	head := `{"sessionId":"11111111-2222-4333-8444-555555555555","projectHash":"` + hex.EncodeToString(sum[:]) + `","startTime":"x","lastUpdated":"x"}` + "\n"
	reply := `{"id":"66666666-2222-4333-8444-555555555555","timestamp":"x","type":"gemini","content":"key sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789 in ` + ws + `","tokens":{"input":1,"output":1,"cached":0,"thoughts":0},"model":"m"}` + "\n"
	chat := filepath.Join(src, "chats", "session-2026-09-19T08-25-11111111.jsonl")
	if err := os.WriteFile(chat, []byte(head+reply), 0o600); err != nil {
		t.Fatal(err)
	}
	// A stale slug with no fresh chat: its marker must not ride along.
	stale := filepath.Join(home, ".gemini", "tmp", "slug2")
	if err := os.MkdirAll(stale, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stale, ".project_root"), []byte("/elsewhere\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "gemini")
	if err := os.CopyFS(out, os.DirFS(filepath.Join(fixtures, "gemini"))); err != nil {
		t.Fatal(err)
	}
	h := harvester{
		detect: func() (adapters.Detection, error) { return adapters.Detection{Installed: true, Version: "9.9.9"}, nil },
		files: func() ([]artifact, error) {
			tmp := filepath.Join(home, ".gemini", "tmp")
			chats, _ := globbed(tmp, "tmp", nil, "*", "chats", "*.jsonl")
			markers, _ := globbed(tmp, "tmp", nil, "*", ".project_root")
			return append(chats, markers...), nil
		},
		fixup: geminiHashes,
	}
	env, stdout := fakeEnv(t)
	if err := harvest(env, Options{Agent: "gemini", Out: out, Workspace: ws}, h, home); err != nil {
		t.Fatalf("harvest: %v\n%s", err, stdout.String())
	}
	dir := filepath.Join(out, "v9.9.9")
	marker, err := os.ReadFile(filepath.Join(dir, "transcripts", "tmp", "slug1", ".project_root"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(marker)) != synthRoot {
		t.Fatalf("marker = %q, want %q", marker, synthRoot)
	}
	if _, err := os.Stat(filepath.Join(dir, "transcripts", "tmp", "slug2")); err == nil {
		t.Fatal("stale slug's marker was harvested")
	}
	got, err := os.ReadFile(filepath.Join(dir, "transcripts", "tmp", "slug1", "chats", "session-2026-09-19T08-25-11111111.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte(synthRoot))
	var h1 struct {
		SessionID   string `json:"sessionId"`
		ProjectHash string `json:"projectHash"`
	}
	if err := json.Unmarshal(bytes.SplitN(got, []byte("\n"), 2)[0], &h1); err != nil {
		t.Fatal(err)
	}
	if h1.ProjectHash != hex.EncodeToString(want[:]) {
		t.Fatalf("projectHash %s does not hash the sanitized marker", h1.ProjectHash)
	}
	if h1.SessionID == "11111111-2222-4333-8444-555555555555" || !strings.HasPrefix(h1.SessionID, "aa000000-") {
		t.Fatalf("sessionId not synthesized: %s", h1.SessionID)
	}
	for _, leak := range []string{home, ws, "sk-ant-api03", "secret-proj"} {
		if bytes.Contains(got, []byte(leak)) {
			t.Fatalf("fixture still carries %q", leak)
		}
	}
	if !bytes.Contains(got, []byte("⟨redacted:api_key:")) || !bytes.Contains(got, []byte(synthRoot)) {
		t.Fatalf("expected a redaction token and the synthetic root, got %s", got)
	}
	readme, _ := os.ReadFile(filepath.Join(dir, "README.md"))
	if !bytes.Contains(readme, []byte("mark1-redact")) || !bytes.Contains(readme, []byte("spans redacted by mark1-redact")) {
		t.Fatalf("README must document the redaction: %s", readme)
	}
	if _, err := os.Stat(filepath.Join(dir, "selfcheck.py")); err != nil {
		t.Fatal("selfcheck.py not carried forward from v0.59.0")
	}
	for _, line := range []string{`"9.9.9": {},`, "still owed before pinning", "recordedCorpusDigest"} {
		if !strings.Contains(stdout.String(), line) {
			t.Fatalf("stdout lacks %q:\n%s", line, stdout.String())
		}
	}
}

func TestHarvestRefusesUnknownAgentsAndFrozenVersions(t *testing.T) {
	env, _ := fakeEnv(t)
	if err := Harvest(env, Options{Agent: "cursor", Out: t.TempDir()}); err == nil || !strings.Contains(err.Error(), "no recorder") {
		t.Fatalf("cursor must be refused: %v", err)
	}
	out := t.TempDir()
	if err := os.MkdirAll(filepath.Join(out, "v9.9.9"), 0o755); err != nil {
		t.Fatal(err)
	}
	h := harvester{detect: func() (adapters.Detection, error) { return adapters.Detection{Installed: true, Version: "9.9.9"}, nil }}
	if err := harvest(env, Options{Agent: "codex", Out: out}, h, t.TempDir()); err == nil || !strings.Contains(err.Error(), "frozen") {
		t.Fatalf("existing version dir must refuse: %v", err)
	}
	h.files = func() ([]artifact, error) { return nil, nil }
	if err := harvest(env, Options{Agent: "codex", Out: t.TempDir()}, h, t.TempDir()); err == nil || !strings.Contains(err.Error(), "no codex artifact") {
		t.Fatalf("nothing fresh must refuse: %v", err)
	}
	// A rollout another build wrote is not this version's evidence (the 0.50.0 box carried 0.58.0-alpha rollouts).
	home := t.TempDir()
	src := filepath.Join(home, "sessions", "2026", "09", "19", "rollout-2026-09-19T08-25-00-019965a0-0000-7000-8000-00000000bb01.jsonl")
	if err := writeFile(src, []byte(`{"timestamp":"x","type":"session_meta","payload":{"id":"019965a0-0000-7000-8000-00000000bb01","cwd":"/w","cli_version":"8.8.8"}}`+"\n")); err != nil {
		t.Fatal(err)
	}
	h = harvesters()["codex"]
	h.detect = func() (adapters.Detection, error) { return adapters.Detection{Installed: true, Version: "9.9.9"}, nil }
	h.files = func() ([]artifact, error) {
		return globbed(filepath.Join(home, "sessions"), "sessions", nil, "*", "*", "*", "rollout-*.jsonl")
	}
	err := harvest(env, Options{Agent: "codex", Out: t.TempDir(), Since: time.Hour}, h, home)
	if err == nil || !strings.Contains(err.Error(), "stamped 8.8.8, not 9.9.9") {
		t.Fatalf("a foreign-version rollout must be skipped and the harvest refused: %v", err)
	}
}
