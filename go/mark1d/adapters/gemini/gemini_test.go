package gemini

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

// gemini -> adapters -> mark1d -> go -> repo root.
const fixtureRoot = "../../../../conformance/hooks/gemini/v0.59.0"

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
	Model      string `json:"model"`
	OccurredAt string `json:"occurred_at"`
}

type neverStream struct {
	File               string `json:"file"`
	NeverEmitMessageID string `json:"never_emit_message_id"`
}

type expectations struct {
	AgentVersion   string        `json:"agent_version"`
	WorkspaceRoot  string        `json:"workspace_root"`
	OutOfWorkspace []neverStream `json:"out_of_workspace_streams"`
	Unattributable []neverStream `json:"unattributable_streams"`
	Streams        []struct {
		File        string          `json:"file"`
		Role        string          `json:"role"`
		UsageEvents []expectedUsage `json:"usage_events"`
	} `json:"streams"`
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
		t.Fatal("no version directories under conformance/hooks/gemini")
	}
	for v := range SupportedVersions {
		if _, ok := fixtures[v]; !ok {
			t.Errorf("SupportedVersions has %q with no fixture directory — that version would be parsed blind", v)
		}
	}
	for v := range fixtures {
		if _, ok := SupportedVersions[v]; !ok {
			t.Errorf("conformance/hooks/gemini/v%s exists but is not in SupportedVersions", v)
		}
	}
}

func TestSupportedRefusesAnUnsniffableVersion(t *testing.T) {
	if Supported("") || Supported("99.0.0") {
		t.Fatal("an unpinned version is supported; FR-AGENT-002 requires the opposite")
	}
}

func TestRegimeFollowsVendorAuthResolution(t *testing.T) {
	gh := t.TempDir()
	a := &Adapter{Home: t.TempDir(), GeminiDir: filepath.Join(gh, ".gemini")}
	for _, k := range []string{"GOOGLE_GENAI_USE_GCA", "GOOGLE_GENAI_USE_VERTEXAI", "GOOGLE_GEMINI_BASE_URL", "GEMINI_API_KEY", "CLOUD_SHELL", "GEMINI_CLI_USE_COMPUTE_ADC"} {
		t.Setenv(k, "")
	}
	settings := filepath.Join(gh, ".gemini", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settings), 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(body string) {
		if err := os.WriteFile(settings, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if a.regime() != adapters.RegimeSubscription {
		t.Fatal("no settings and no env must read as subscription (conservative default)")
	}
	t.Setenv("GEMINI_API_KEY", "AIzaSynth")
	if a.regime() != adapters.RegimeAPIKey {
		t.Fatal("GEMINI_API_KEY alone resolves to gemini-api-key (getAuthTypeFromEnv)")
	}
	t.Setenv("GOOGLE_GENAI_USE_GCA", "true")
	if a.regime() != adapters.RegimeSubscription {
		t.Fatal("GOOGLE_GENAI_USE_GCA outranks GEMINI_API_KEY in getAuthTypeFromEnv")
	}
	t.Setenv("GOOGLE_GENAI_USE_GCA", "")
	t.Setenv("GOOGLE_GEMINI_BASE_URL", "https://gateway.example")
	if a.regime() != adapters.RegimeSubscription {
		t.Fatal("a gateway base URL outranks the key and is not the API-key regime")
	}
	t.Setenv("GOOGLE_GEMINI_BASE_URL", "")
	write(`{"security":{"auth":{"selectedType":"oauth-personal"}}}`)
	if a.regime() != adapters.RegimeSubscription {
		t.Fatal("settings selectedType wins over the env key (validateNonInteractiveAuth)")
	}
	write(`{"security":{"auth":{"selectedType":"vertex-ai"}}}`)
	if a.regime() != adapters.RegimeSubscription {
		t.Fatal("vertex-ai is not the API-key regime")
	}
	t.Setenv("GEMINI_API_KEY", "")
	write(`{"security":{"auth":{"selectedType":"gemini-api-key"}}}`)
	if a.regime() != adapters.RegimeAPIKey {
		t.Fatal("selectedType gemini-api-key is the API-key regime")
	}
	write(`{"security":{"auth":{"selectedType":"gemini-api-key","enforcedType":"oauth-personal"}}}`)
	if a.regime() != adapters.RegimeSubscription {
		t.Fatal("an enforcedType that disagrees makes the CLI refuse to run; nothing is proxyable")
	}
	write(`// comment
{"security":{"auth":{"selectedType":"gemini-api-key"}}}`)
	if a.regime() != adapters.RegimeSubscription {
		t.Fatal("an unparseable settings file falls to the conservative default")
	}
}

func TestStartTailWorkspaceGate(t *testing.T) {
	enabled, other := t.TempDir(), t.TempDir()
	set, err := tailers.NewWorkspaceSet(enabled)
	if err != nil {
		t.Fatal(err)
	}
	a := &Adapter{Home: t.TempDir(), GeminiDir: t.TempDir()}
	cfg := TailConfig{StateDir: filepath.Join(t.TempDir(), "cursors"), UsageIdemKey: testIdemKey,
		Emit: func(context.Context, *m1pv1.Event) error { return nil }}
	if _, err := a.StartTail(adapters.Workspace{Root: other}, set, cfg); err == nil {
		t.Fatal("root outside the enabled set was accepted")
	}
	if mgr, err := a.StartTail(adapters.Workspace{Root: enabled}, set, cfg); err != nil || mgr == nil {
		t.Fatalf("enabled root refused: %v", err)
	}
}

// TestReplayChatsCorpus is conf_hooks_gemini_0.59.0_replay's tailer half: the
// fixture tmp tree through the manager under the corpus's enabled root.
func TestReplayChatsCorpus(t *testing.T) {
	exp := loadExpectations(t)
	set, err := tailers.NewWorkspaceSet(exp.WorkspaceRoot)
	if err != nil {
		t.Fatal(err)
	}
	got := replay(t, exp, exp.WorkspaceRoot, set)
	var wantTotal int
	for _, st := range exp.Streams {
		wantTotal += len(st.UsageEvents)
	}
	if len(got) != wantTotal {
		t.Fatalf("manager emitted %d Usage events, expectations fix %d", len(got), wantTotal)
	}
	byKey := map[string]*m1pv1.Usage{}
	byMsg := map[string]int{}
	for _, ev := range got {
		u := ev.GetUsage()
		if byKey[string(u.GetIdemKey())] != nil {
			t.Fatalf("duplicate idem_key for (%s,%s)", u.GetMessageId(), u.GetRequestId())
		}
		byKey[string(u.GetIdemKey())] = u
		byMsg[u.GetMessageId()]++
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
				t.Fatalf("(%s): got %v, want %+v", want.IdemInputs.MessageID, u, want.Usage)
			}
			if byMsg[want.IdemInputs.MessageID] != 1 {
				t.Fatalf("%s emitted %d times; a re-appended message counts once", want.IdemInputs.MessageID, byMsg[want.IdemInputs.MessageID])
			}
		}
	}
	if len(exp.OutOfWorkspace) == 0 || len(exp.Unattributable) == 0 {
		t.Fatal("corpus lost a containment trap — the gate is untested")
	}
	for _, trap := range append(exp.OutOfWorkspace, exp.Unattributable...) {
		if _, err := os.Stat(filepath.Join(fixtureRoot, trap.File)); err != nil {
			t.Fatalf("trap fixture missing: %v", err)
		}
		if byMsg[trap.NeverEmitMessageID] != 0 {
			t.Fatalf("%s emitted — a stream outside the consented read surface was captured (invariant 3)", trap.NeverEmitMessageID)
		}
	}
}

// TestForeignRootTailsNothing: the same tmp tree under the OTHER project's
// root sees only that project's slug — the marker, not the directory, admits.
func TestForeignRootTailsNothing(t *testing.T) {
	exp := loadExpectations(t)
	const other = "/home/devuser/workspace/other-app"
	set, err := tailers.NewWorkspaceSet(other)
	if err != nil {
		t.Fatal(err)
	}
	got := replay(t, exp, other, set)
	if len(got) != 1 || got[0].GetUsage().GetMessageId() != exp.OutOfWorkspace[0].NeverEmitMessageID {
		t.Fatalf("other-app root must emit exactly its own stream's Usage, got %d", len(got))
	}
}

// TestDiscoverOffersOnlyTheRootsSlug: streams under another project's slug are
// never offered to the manager at all — the marker filters before the oracle.
func TestDiscoverOffersOnlyTheRootsSlug(t *testing.T) {
	exp := loadExpectations(t)
	f := chatsFormat(exp.WorkspaceRoot)
	var offered []string
	f.Discover(filepath.Join(fixtureRoot, "transcripts", "tmp"), func(p string, _ tailers.Role, _ uuid.UUID) { offered = append(offered, p) })
	if len(offered) != 3 {
		t.Fatalf("acme-app slug holds 3 streams, discover offered %d: %v", len(offered), offered)
	}
	for _, p := range offered {
		if strings.Contains(p, "other-app") {
			t.Fatalf("a foreign slug's stream was offered: %s", p)
		}
	}
}

func replay(t *testing.T, exp expectations, root string, set tailers.WorkspaceSet) []*m1pv1.Event {
	t.Helper()
	a := &Adapter{Home: t.TempDir(), GeminiDir: filepath.Join(fixtureRoot, "transcripts")}
	tmp, _ := a.TmpDir()
	f := chatsFormat(root)
	var got []*m1pv1.Event
	mgr, err := tailers.NewManager(tailers.Config{
		Dir: tmp, StateDir: t.TempDir(), Allowed: set.Allowed, UsageIdemKey: testIdemKey,
		Emit:   func(_ context.Context, ev *m1pv1.Event) error { got = append(got, ev); return nil },
		Format: f,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	mgr.Sweep(ctx)
	if err := mgr.CloseFlush(ctx); err != nil {
		t.Fatal(err)
	}
	return got
}

func TestChatParserSkipsLinesWithoutTokens(t *testing.T) {
	p := newChatParser()
	if _, ok := p([]byte(`{"id":"x","timestamp":"t","type":"gemini","content":"","tokens":{"input":1,"output":2,"cached":0,"thoughts":0,"tool":0,"total":3},"model":"m"}`)); ok {
		t.Fatal("a usage line before the metadata head has no session to key on")
	}
	if _, ok := p([]byte(`{"sessionId":"6f1e2d3c-0000-4000-8000-00000000aa01","projectHash":"h"}`)); ok {
		t.Fatal("the metadata head is not a usage line")
	}
	if _, ok := p([]byte(`{"id":"x","timestamp":"t","type":"user","content":[{"text":"hi"}]}`)); ok {
		t.Fatal("user lines never carry usage")
	}
	if _, ok := p([]byte(`{"id":"x","timestamp":"t","type":"gemini","content":"","tokens":null,"model":"m"}`)); ok {
		t.Fatal("tokens: null is no usage")
	}
	l, ok := p([]byte(`{"id":"x","timestamp":"t","type":"gemini","content":"","tokens":{"input":10,"output":2,"cached":4,"thoughts":3,"tool":1,"total":16},"model":"m"}`))
	if !ok || l.MessageID != "x" || l.RequestID != "chat:6f1e2d3c-0000-4000-8000-00000000aa01" || l.InputTokens != 10 || l.OutputTokens != 5 || l.CacheReadTokens != 4 || l.CacheCreationTokens != 0 || l.Model != "m" {
		t.Fatalf("parsed %+v", l)
	}
}
