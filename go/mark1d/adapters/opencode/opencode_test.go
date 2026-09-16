package opencode

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

// opencode -> adapters -> mark1d -> go -> repo root.
const fixtureRoot = "../../../../conformance/hooks/opencode/v1.18.31"

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
		File               string `json:"file"`
		NeverEmitRequestID string `json:"never_emit_request_id"`
	} `json:"out_of_workspace_streams"`
	Streams []struct {
		File        string          `json:"file"`
		UsageEvents []expectedUsage `json:"usage_events"`
	} `json:"streams"`
	Hooks struct {
		Registered []string `json:"registered"`
	} `json:"hooks"`
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
		t.Fatal("no version directories under conformance/hooks/opencode")
	}
	for v := range SupportedVersions {
		if _, ok := fixtures[v]; !ok {
			t.Errorf("SupportedVersions has %q with no fixture directory — that version would be parsed blind", v)
		}
	}
	for v := range fixtures {
		if _, ok := SupportedVersions[v]; !ok {
			t.Errorf("conformance/hooks/opencode/v%s exists but is not in SupportedVersions", v)
		}
	}
}

func TestSupportedRefusesAnUnsniffableVersion(t *testing.T) {
	if Supported("") || Supported("99.0.0") {
		t.Fatal("an unpinned version is supported; FR-AGENT-002 requires the opposite")
	}
}

func TestRegimeFollowsVendorCredentialStore(t *testing.T) {
	cfg, data, state := t.TempDir(), t.TempDir(), t.TempDir()
	a := &Adapter{Home: t.TempDir(), ConfigDir: cfg, DataDir: data, OCState: state}
	write := func(dir, name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if a.regime() != adapters.RegimeSubscription {
		t.Fatal("no config, no credentials: subscription (conservative default)")
	}
	write(data, "auth.json", `{"anthropic":{"type":"api","key":"sk-ant-synth"}}`)
	if a.regime() != adapters.RegimeSubscription {
		t.Fatal("a stored key for a provider nothing selects cannot be classified; subscription")
	}
	write(cfg, "opencode.json", `{"model":"anthropic/claude-sonnet-4-5"}`)
	if a.regime() != adapters.RegimeAPIKey {
		t.Fatal("config model's provider with an auth.json api entry is the API-key regime")
	}
	write(data, "auth.json", `{"anthropic":{"type":"oauth","refresh":"r","access":"a","expires":1}}`)
	if a.regime() != adapters.RegimeSubscription {
		t.Fatal("an oauth credential is the subscription regime")
	}
	write(data, "auth.json", `{"anthropic":{"type":"wellknown","key":"k","token":"t"}}`)
	if a.regime() != adapters.RegimeSubscription {
		t.Fatal("an org-managed wellknown credential is not proxyable")
	}
	write(data, "auth.json", `{"openai":{"type":"api","key":"sk-synth"}}`)
	if a.regime() != adapters.RegimeSubscription {
		t.Fatal("a key for ANOTHER provider does not make the selected one API-key")
	}
	write(cfg, "opencode.json", `{"model":"anthropic/claude-sonnet-4-5","provider":{"anthropic":{"options":{"apiKey":"sk-ant-synth"}}}}`)
	if a.regime() != adapters.RegimeAPIKey {
		t.Fatal("provider.<id>.options.apiKey in opencode.json is the API-key regime")
	}
	write(cfg, "opencode.json", `{}`)
	write(state, "model.json", `{"recent":[{"providerID":"openai","modelID":"gpt-5"}]}`)
	if a.regime() != adapters.RegimeAPIKey {
		t.Fatal("no config model: model.json's newest recent entry selects the provider (provider.ts defaultModel)")
	}
	write(state, "model.json", `{"recent":[{"providerID":"anthropic","modelID":"claude-sonnet-4-5"},{"providerID":"openai","modelID":"gpt-5"}]}`)
	if a.regime() != adapters.RegimeSubscription {
		t.Fatal("recent[0] wins, and anthropic has no stored key here")
	}
}

func TestSessionUUIDMatchesTheCorpusRecipe(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(fixtureRoot, "hooks", "session.created.json"))
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		SessionID string `json:"session_id"`
		Vendor    string `json:"sessionID"`
	}
	if err := json.Unmarshal(b, &body); err != nil {
		t.Fatal(err)
	}
	if got := SessionUUID(body.Vendor).String(); got != body.SessionID {
		t.Fatalf("SessionUUID(%s) = %s, mark1.js composed %s", body.Vendor, got, body.SessionID)
	}
	if SessionUUID("ses_a") == SessionUUID("ses_b") {
		t.Fatal("distinct ids must not collide")
	}
}

func TestPluginNamesEveryFixtureHook(t *testing.T) {
	exp := loadExpectations(t)
	ents, err := os.ReadDir(filepath.Join(fixtureRoot, "hooks"))
	if err != nil {
		t.Fatal(err)
	}
	onDisk := map[string]bool{}
	for _, e := range ents {
		onDisk[strings.TrimSuffix(e.Name(), ".json")] = true
	}
	for _, name := range exp.Hooks.Registered {
		if !onDisk[name] {
			t.Errorf("expectations register %s with no fixture body", name)
		}
		if !strings.Contains(pluginSource, `"`+name+`"`) {
			t.Errorf("mark1.js never names %s; the fixture body could not come from it", name)
		}
	}
	if len(onDisk) != len(exp.Hooks.Registered) {
		t.Errorf("%d fixture bodies, %d registered hooks", len(onDisk), len(exp.Hooks.Registered))
	}
}

func TestStartTailWorkspaceGate(t *testing.T) {
	enabled, other := t.TempDir(), t.TempDir()
	set, err := tailers.NewWorkspaceSet(enabled)
	if err != nil {
		t.Fatal(err)
	}
	a := &Adapter{Home: t.TempDir()}
	cfg := TailConfig{StateDir: filepath.Join(t.TempDir(), "cursors"), UsageIdemKey: testIdemKey,
		Emit: func(context.Context, *m1pv1.Event) error { return nil }}
	if _, err := a.StartTail(adapters.Workspace{Root: other}, set, cfg); err == nil {
		t.Fatal("root outside the enabled set was accepted")
	}
	if mgr, err := a.StartTail(adapters.Workspace{Root: enabled}, set, cfg); err != nil || mgr == nil {
		t.Fatalf("enabled root refused: %v", err)
	}
}

// TestReplayCaptureCorpus is conf_hooks_opencode_1.18.31_replay's tailer half:
// the fixture capture dir through the manager under the corpus's enabled root.
func TestReplayCaptureCorpus(t *testing.T) {
	exp := loadExpectations(t)
	set, err := tailers.NewWorkspaceSet(exp.WorkspaceRoot)
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	capture := filepath.Join(home, ".omium", "mark1", "capture")
	if err := os.MkdirAll(capture, 0o700); err != nil {
		t.Fatal(err)
	}
	src, _ := filepath.Abs(filepath.Join(fixtureRoot, "transcripts", "capture"))
	if err := os.Symlink(src, filepath.Join(capture, "opencode")); err != nil {
		t.Skip("symlink unavailable:", err)
	}
	a := &Adapter{Home: home}
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
	byReq := map[string]int{}
	for _, ev := range got {
		u := ev.GetUsage()
		if byKey[string(u.GetIdemKey())] != nil {
			t.Fatalf("duplicate idem_key for (%s,%s)", u.GetMessageId(), u.GetRequestId())
		}
		byKey[string(u.GetIdemKey())] = u
		byReq[u.GetRequestId()]++
		if bytes.Equal(u.GetIdemKey(), make([]byte, 32)) {
			t.Fatal("idem_key missing — ingest would 422 this Usage (08 §2.4)")
		}
		if ev.GetOccurredAt() == nil {
			t.Fatalf("%s: occurred_at not stamped from the part's time", u.GetRequestId())
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
			if byReq[want.IdemInputs.RequestID] != 1 {
				t.Fatalf("%s emitted %d times; a re-published part counts once", want.IdemInputs.RequestID, byReq[want.IdemInputs.RequestID])
			}
		}
	}
	if len(exp.OutOfWorkspace) == 0 {
		t.Fatal("corpus lost its out-of-workspace fixture — the containment gate is untested")
	}
	for _, foreign := range exp.OutOfWorkspace {
		if _, err := os.Stat(filepath.Join(fixtureRoot, foreign.File)); err != nil {
			t.Fatalf("foreign fixture missing: %v", err)
		}
		if byReq[foreign.NeverEmitRequestID] != 0 {
			t.Fatalf("foreign workspace key %s emitted — a non-enabled workspace was captured (invariant 3)", foreign.NeverEmitRequestID)
		}
	}
}

func TestCaptureParserReadsOnlyStepFinishParts(t *testing.T) {
	p := newCaptureParser()
	if _, ok := p([]byte(`{"type":"message.part.updated","properties":{"sessionID":"ses_x","part":{"id":"prt_1","messageID":"msg_1","type":"text","text":"hi","tokens":{"input":9,"output":9,"reasoning":0,"cache":{"read":0,"write":0}}},"time":1}}`)); ok {
		t.Fatal("only a step-finish part is usage — the type is read, not the presence of tokens")
	}
	if _, ok := p([]byte(`{"type":"message.updated","properties":{"sessionID":"ses_x","info":{"id":"msg_1","role":"assistant","providerID":"anthropic","modelID":"m","tokens":{"input":9,"output":9,"reasoning":0,"cache":{"read":0,"write":0}}}}}`)); ok {
		t.Fatal("AssistantMessage.tokens is the last step's count, never a Usage")
	}
	l, ok := p([]byte(`{"type":"message.part.updated","properties":{"sessionID":"ses_x","part":{"id":"prt_1","messageID":"msg_1","type":"step-finish","reason":"stop","cost":0.1,"tokens":{"input":10,"output":2,"reasoning":3,"cache":{"read":4,"write":5}}},"time":1789547104312}}`))
	if !ok || l.MessageID != "msg_1" || l.RequestID != "prt_1" || l.Model != "anthropic/m" || l.InputTokens != 10 || l.OutputTokens != 5 || l.CacheReadTokens != 4 || l.CacheCreationTokens != 5 || l.Timestamp != "2026-09-16T08:25:04.312Z" {
		t.Fatalf("parsed %+v", l)
	}
	if _, ok := p([]byte(`{"type":"message.part.updated","properties":{"sessionID":"ses_x","part":{"id":"prt_2","messageID":"msg_1","type":"step-finish","reason":"stop","cost":0},"time":1}}`)); ok {
		t.Fatal("a step-finish without tokens is not usage")
	}
}
