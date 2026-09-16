package codex

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"

	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/tailers"
)

// codex -> adapters -> mark1d -> go -> repo root.
const fixtureRoot = "../../../../conformance/hooks/codex/v0.154.0"

var testIdemKey = []byte("m1p-usage-idem-TEST-KEY-32bytes!")

type expectedUsage struct {
	IdemInputs struct {
		SessionID string `json:"session_id"`
		MessageID string `json:"message_id"`
		RequestID string `json:"request_id"`
	} `json:"idem_key_inputs"`
	Usage struct {
		InputTokens              uint64 `json:"input_tokens"`
		OutputTokens             uint64 `json:"output_tokens"`
		CacheCreationInputTokens uint64 `json:"cache_creation_input_tokens"`
		CacheReadInputTokens     uint64 `json:"cache_read_input_tokens"`
	} `json:"usage"`
	Model string `json:"model"`
}

type expectations struct {
	AgentVersion   string `json:"agent_version"`
	WorkspaceRoot  string `json:"workspace_root"`
	OutOfWorkspace []struct {
		File                string `json:"file"`
		NeverEmitResponseID string `json:"never_emit_response_id"`
	} `json:"out_of_workspace_streams"`
	Streams []struct {
		File        string          `json:"file"`
		UsageEvents []expectedUsage `json:"usage_events"`
	} `json:"streams"`
	Reemit struct {
		File                 string `json:"file"`
		ResponseID           string `json:"response_id"`
		TokenCountLines      int    `json:"token_count_lines_carrying_it_as_last_usage"`
		TokenUsageRecordLine int    `json:"token_usage_record_lines"`
		CorrectUsageEvents   int    `json:"correct_usage_events"`
	} `json:"rate_limit_reemit_case"`
	Exec struct {
		File        string          `json:"file"`
		ThreadID    string          `json:"thread_id"`
		UsageEvents []expectedUsage `json:"usage_events"`
	} `json:"exec_stream"`
}

func loadExpectations(t *testing.T) expectations {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtureRoot, "transcripts", "expectations.json"))
	if err != nil {
		t.Fatal(err)
	}
	var exp expectations
	if err := json.Unmarshal(b, &exp); err != nil {
		t.Fatal(err)
	}
	return exp
}

func TestSupportedVersionsMatchTheFixtureTree(t *testing.T) {
	ents, err := os.ReadDir(filepath.Dir(fixtureRoot))
	if err != nil {
		t.Fatalf("fixture tree unreadable: %v", err)
	}
	fixtures := map[string]struct{}{}
	for _, e := range ents {
		if e.IsDir() {
			fixtures[strings.TrimPrefix(e.Name(), "v")] = struct{}{}
		}
	}
	if len(fixtures) == 0 {
		t.Fatal("no version directories under conformance/hooks/codex")
	}
	for v := range SupportedVersions {
		if _, ok := fixtures[v]; !ok {
			t.Errorf("SupportedVersions has %q with no fixture directory — that version would be parsed blind", v)
		}
	}
	for v := range fixtures {
		if _, ok := SupportedVersions[v]; !ok {
			t.Errorf("conformance/hooks/codex/v%s exists but is not in SupportedVersions", v)
		}
	}
}

func TestSupportedRefusesAnUnsniffableVersion(t *testing.T) {
	if Supported("") || Supported("99.0.0") {
		t.Fatal("an unpinned version is supported; FR-AGENT-002 requires the opposite")
	}
}

func TestRegimeFollowsVendorAuthResolution(t *testing.T) {
	ch := t.TempDir()
	a := &Adapter{Home: t.TempDir(), CodexHome: ch}
	t.Setenv("CODEX_API_KEY", "")
	write := func(body string) {
		if err := os.WriteFile(filepath.Join(ch, "auth.json"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if a.regime() != adapters.RegimeSubscription {
		t.Fatal("no auth.json must read as subscription (conservative default)")
	}
	write(`{"OPENAI_API_KEY":null,"tokens":{"id_token":"x","access_token":"y","refresh_token":"z","account_id":"acct_x"},"last_refresh":"2026-09-16T08:00:00Z"}`)
	if a.regime() != adapters.RegimeSubscription {
		t.Fatal("ChatGPT login tokens must read as subscription")
	}
	write(`{"OPENAI_API_KEY":"sk-synth"}`)
	if a.regime() != adapters.RegimeAPIKey {
		t.Fatal("a stored OPENAI_API_KEY with no other credential resolves to ApiKey (AuthDotJson::resolved_mode)")
	}
	write(`{"auth_mode":"chatgpt","OPENAI_API_KEY":"sk-synth"}`)
	if a.regime() != adapters.RegimeSubscription {
		t.Fatal("an explicit auth_mode wins over the stored key")
	}
	write(`{"auth_mode":"apikey","OPENAI_API_KEY":"sk-synth"}`)
	if a.regime() != adapters.RegimeAPIKey {
		t.Fatal("auth_mode apikey is the API-key regime")
	}
	write(`{"OPENAI_API_KEY":"sk-synth","personal_access_token":"pat"}`)
	if a.regime() != adapters.RegimeSubscription {
		t.Fatal("a PAT outranks a stored API key in resolved_mode")
	}
	write(`{"OPENAI_API_KEY":null}`)
	t.Setenv("CODEX_API_KEY", "sk-env")
	if a.regime() != adapters.RegimeAPIKey {
		t.Fatal("CODEX_API_KEY env takes precedence over auth.json")
	}
}

func TestThreadFromName(t *testing.T) {
	want := uuid.MustParse("019965a0-0000-7000-8000-00000000aa01")
	for name, ok := range map[string]bool{
		"rollout-2026-09-16T08-25-00-019965a0-0000-7000-8000-00000000aa01.jsonl":                                      true,
		"rollout-2026-09-16T08-25-00-019965a0-0000-7000-8000-00000000aa01_019965a0-0000-7000-8000-00000000bb02.jsonl": true,
		"rollout-2026-09-16T08-25-00-019965a0-0000-7000-8000-00000000aa01.jsonl.zst":                                  false,
		"rollout-2026-09-16T08-25-00-not-a-uuid.jsonl":                                                                false,
		"session-index.jsonl": false,
	} {
		id, got := threadFromName(name)
		if got != ok || (ok && id != want) {
			t.Errorf("threadFromName(%q) = (%v,%v), want ok=%v", name, id, got, ok)
		}
	}
}

func TestStartTailWorkspaceGate(t *testing.T) {
	enabled, other := t.TempDir(), t.TempDir()
	set, err := tailers.NewWorkspaceSet(enabled)
	if err != nil {
		t.Fatal(err)
	}
	a := &Adapter{Home: t.TempDir(), CodexHome: t.TempDir()}
	cfg := TailConfig{StateDir: filepath.Join(t.TempDir(), "cursors"), UsageIdemKey: testIdemKey,
		Emit: func(context.Context, *m1pv1.Event) error { return nil }}
	if _, err := a.StartTail(adapters.Workspace{Root: other}, set, cfg); err == nil {
		t.Fatal("root outside the enabled set was accepted")
	}
	if mgr, err := a.StartTail(adapters.Workspace{Root: enabled}, set, cfg); err != nil || mgr == nil {
		t.Fatalf("enabled root refused: %v", err)
	}
}

// TestReplayRolloutCorpus is conf_hooks_codex_0.154.0_replay's tailer half: the
// fixture sessions tree through the manager under the corpus's enabled root.
func TestReplayRolloutCorpus(t *testing.T) {
	exp := loadExpectations(t)
	set, err := tailers.NewWorkspaceSet(exp.WorkspaceRoot)
	if err != nil {
		t.Fatal(err)
	}
	a := &Adapter{Home: t.TempDir(), CodexHome: filepath.Join(fixtureRoot, "transcripts")}
	var got []*m1pv1.Event
	mgr, err := a.StartTail(adapters.Workspace{Root: exp.WorkspaceRoot}, set, TailConfig{
		StateDir: t.TempDir(), UsageIdemKey: testIdemKey,
		Emit: func(_ context.Context, ev *m1pv1.Event) error { got = append(got, ev); return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	mgr.Sweep(ctx)
	if err := mgr.CloseFlush(ctx); err != nil {
		t.Fatal(err)
	}
	var wantTotal int
	for _, st := range exp.Streams {
		wantTotal += len(st.UsageEvents)
	}
	if len(got) != wantTotal {
		t.Fatalf("manager emitted %d Usage events, expectations fix %d", len(got), wantTotal)
	}
	byKey := map[string]*m1pv1.Usage{}
	for _, ev := range got {
		u := ev.GetUsage()
		if byKey[string(u.GetIdemKey())] != nil {
			t.Fatalf("duplicate idem_key for (%s,%s)", u.GetMessageId(), u.GetRequestId())
		}
		byKey[string(u.GetIdemKey())] = u
		if bytes.Equal(u.GetIdemKey(), make([]byte, 32)) {
			t.Fatal("idem_key missing — ingest would 422 this Usage (08 §2.4)")
		}
	}
	for _, st := range exp.Streams {
		for _, want := range st.UsageEvents {
			session := uuid.MustParse(want.IdemInputs.SessionID)
			u := byKey[string(tailers.IdemKey(testIdemKey, session, want.IdemInputs.MessageID, want.IdemInputs.RequestID))]
			if u == nil {
				t.Fatalf("expected key (%s,%s) never emitted", want.IdemInputs.MessageID, want.IdemInputs.RequestID)
			}
			if u.GetInputTokens() != want.Usage.InputTokens || u.GetOutputTokens() != want.Usage.OutputTokens ||
				u.GetCacheReadInputTokens() != want.Usage.CacheReadInputTokens ||
				u.GetCacheCreationInputTokens() != want.Usage.CacheCreationInputTokens || u.GetModel() != want.Model {
				t.Fatalf("(%s): got %v, want %+v", want.IdemInputs.RequestID, u, want.Usage)
			}
		}
	}
	// openai/codex#14489: the re-emitted token_count snapshots are on disk and count zero times.
	raw, err := os.ReadFile(filepath.Join(fixtureRoot, exp.Reemit.File))
	if err != nil {
		t.Fatal(err)
	}
	snapshots := strings.Count(string(raw), `"type":"token_count"`)
	if snapshots < exp.Reemit.TokenCountLines {
		t.Fatalf("corpus carries %d token_count snapshots, expectations say ≥%d — the #14489 trap is gone", snapshots, exp.Reemit.TokenCountLines)
	}
	emitted := 0
	for _, ev := range got {
		if ev.GetUsage().GetRequestId() == exp.Reemit.ResponseID {
			emitted++
		}
	}
	if emitted != exp.Reemit.CorrectUsageEvents {
		t.Fatalf("%s emitted %d times; %d token_count re-emits must not double-count (#14489)", exp.Reemit.ResponseID, emitted, exp.Reemit.TokenCountLines)
	}
	if len(exp.OutOfWorkspace) == 0 {
		t.Fatal("corpus lost its out-of-workspace fixture — the containment gate is untested")
	}
	for _, foreign := range exp.OutOfWorkspace {
		if _, err := os.Stat(filepath.Join(fixtureRoot, foreign.File)); err != nil {
			t.Fatalf("foreign fixture missing: %v", err)
		}
		for _, ev := range got {
			if ev.GetUsage().GetRequestId() == foreign.NeverEmitResponseID {
				t.Fatalf("foreign workspace key %s emitted — a non-enabled workspace was captured (invariant 3)", foreign.NeverEmitResponseID)
			}
		}
	}
}

func TestExecStreamReplay(t *testing.T) {
	exp := loadExpectations(t)
	set, err := tailers.NewWorkspaceSet(exp.WorkspaceRoot)
	if err != nil {
		t.Fatal(err)
	}
	run := func(cwd string) []*m1pv1.Event {
		f, err := os.Open(filepath.Join(fixtureRoot, exp.Exec.File))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = f.Close() }()
		var got []*m1pv1.Event
		a := &Adapter{}
		tail := a.TailExec(f, cwd, set, TailConfig{UsageIdemKey: testIdemKey,
			Emit: func(_ context.Context, ev *m1pv1.Event) error { got = append(got, ev); return nil }})
		if err := tail.Run(context.Background()); err != nil {
			t.Fatal(err)
		}
		return got
	}
	got := run(exp.WorkspaceRoot)
	if len(got) != len(exp.Exec.UsageEvents) {
		t.Fatalf("exec stream emitted %d events, want %d", len(got), len(exp.Exec.UsageEvents))
	}
	thread := uuid.MustParse(exp.Exec.ThreadID)
	for i, want := range exp.Exec.UsageEvents {
		u := got[i].GetUsage()
		if !bytes.Equal(u.GetIdemKey(), tailers.IdemKey(testIdemKey, thread, want.IdemInputs.MessageID, want.IdemInputs.RequestID)) {
			t.Fatalf("event %d: idem_key not over (%s,%s,%s)", i, exp.Exec.ThreadID, want.IdemInputs.MessageID, want.IdemInputs.RequestID)
		}
		if u.GetInputTokens() != want.Usage.InputTokens || u.GetOutputTokens() != want.Usage.OutputTokens || u.GetCacheReadInputTokens() != want.Usage.CacheReadInputTokens {
			t.Fatalf("event %d: %v, want %+v", i, u, want.Usage)
		}
	}
	if foreign := run("/home/devuser/workspace/other-app"); len(foreign) != 0 {
		t.Fatalf("a wrapped exec outside the enabled set emitted %d events (invariant 3)", len(foreign))
	}
}

func TestDetectUsageReportsTheLiveReader(t *testing.T) {
	a := &Adapter{Home: t.TempDir(), CodexHome: t.TempDir()}
	if a.DetectUsage() != UsageExecJSON {
		t.Fatal("no sessions tree: only a wrapped exec can supply usage")
	}
	a.CodexHome = filepath.Join(fixtureRoot, "transcripts")
	if a.DetectUsage() != UsageRollout {
		t.Fatal("a sessions tree with token_usage_record lines is the rollout reader")
	}
}
