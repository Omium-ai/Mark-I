package copilot

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"

	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/tailers"
)

// copilot -> adapters -> mark1d -> go -> repo root.
const fixtureRoot = "../../../../conformance/hooks/copilot/v1.0.85"

var testIdemKey = []byte("m1p-usage-idem-TEST-KEY-32bytes!")

type expectations struct {
	AgentVersion        string `json:"agent_version"`
	WorkspaceRoot       string `json:"workspace_root"`
	UsageClass          string `json:"usage_class"`
	UsageEventsExpected int    `json:"usage_events_expected"`
	Streams             []struct {
		File             string `json:"file"`
		SessionID        string `json:"session_id"`
		DiagnosticEvents []struct {
			Body         string `json:"body"`
			AgentVersion string `json:"agent_version"`
			Reason       string `json:"reason"`
			DurationMs   uint64 `json:"duration_ms"`
		} `json:"diagnostic_events"`
	} `json:"streams"`
	OutOfWorkspace []struct {
		File               string `json:"file"`
		NeverEmitSessionID string `json:"never_emit_session_id"`
	} `json:"out_of_workspace_streams"`
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

func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
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
		t.Fatal("no version directories under conformance/hooks/copilot")
	}
	for v := range SupportedVersions {
		if _, ok := fixtures[v]; !ok {
			t.Errorf("SupportedVersions has %q with no fixture directory — that version would be parsed blind", v)
		}
	}
	for v := range fixtures {
		if _, ok := SupportedVersions[v]; !ok {
			t.Errorf("conformance/hooks/copilot/v%s exists but is not in SupportedVersions", v)
		}
	}
}

func TestSupportedRefusesAnUnsniffableVersion(t *testing.T) {
	if Supported("") || Supported("99.0.0") {
		t.Fatal("an unpinned version is supported; FR-AGENT-002 requires the opposite")
	}
	if v := versionRe.FindString("GitHub Copilot CLI 1.0.85.\nRun 'copilot update' to check for updates.\n"); v != "1.0.85" {
		t.Fatalf("version sniff read %q from the recorded --version banner", v)
	}
}

func TestRegimeFollowsVendorProviderResolution(t *testing.T) {
	ch := t.TempDir()
	a := &Adapter{Home: t.TempDir(), CopilotHome: ch}
	set := func(m map[string]string) { a.Env = envOf(m) }
	byok := map[string]string{"COPILOT_PROVIDER_BASE_URL": "https://api.openai.com/v1", "COPILOT_PROVIDER_API_KEY": "sk-synth"}
	set(map[string]string{})
	if a.regime() != adapters.RegimeSubscription {
		t.Fatal("no provider config: GitHub-billed, subscription (conservative default)")
	}
	set(map[string]string{"COPILOT_PROVIDER_API_KEY": "sk-synth"})
	if a.regime() != adapters.RegimeSubscription {
		t.Fatal("a key without COPILOT_PROVIDER_BASE_URL never activates BYOK (use-byok-models)")
	}
	set(map[string]string{"COPILOT_PROVIDER_BASE_URL": "http://localhost:11434"})
	if a.regime() != adapters.RegimeSubscription {
		t.Fatal("BYOK without a key (Ollama) carries no credential to guard")
	}
	set(byok)
	if a.regime() != adapters.RegimeAPIKey {
		t.Fatal("base URL + plain API key is the API-key regime")
	}
	set(map[string]string{"COPILOT_PROVIDER_GHES_HOST": "ghe.example", "COPILOT_PROVIDER_API_KEY": "sk-synth"})
	if a.regime() != adapters.RegimeSubscription {
		t.Fatal("GHES-hosted Copilot is GitHub-billed, not BYOK")
	}
	for _, k := range []string{"COPILOT_PROVIDER_BEARER_TOKEN", "COPILOT_PROVIDER_API_KEY_COMMAND"} {
		m := map[string]string{k: "x"}
		for kk, v := range byok {
			m[kk] = v
		}
		set(m)
		if a.regime() != adapters.RegimeSubscription {
			t.Fatalf("%s takes precedence over the key at the pin; the wire credential is not the key", k)
		}
	}
	write := func(body string) {
		if err := os.WriteFile(filepath.Join(ch, "providers.json"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	set(byok)
	write(`{"providers":[{"type":"anthropic","baseUrl":"https://api.anthropic.com","apiKey":"sk-ant-synth"}]}`)
	if a.regime() != adapters.RegimeAPIKey {
		t.Fatal("providers.json with plain keys is the API-key regime")
	}
	write(`{"providers":[{"baseUrl":"https://a","apiKey":"k"},{"baseUrl":"https://b","bearerToken":"t"}]}`)
	if a.regime() != adapters.RegimeSubscription {
		t.Fatal("a providers.json with any non-key credential cannot be classified: subscription")
	}
	write(`{"providers":[{"baseUrl":"https://a"}]}`)
	if a.regime() != adapters.RegimeSubscription {
		t.Fatal("a providers.json entry without a key overrides the env key (config wins at the pin)")
	}
	for _, precedent := range []string{"bearerToken", "apiKeyCommand"} {
		write(`{"providers":[{"baseUrl":"https://a","apiKey":"k","` + precedent + `":"x"}]}`)
		if a.regime() != adapters.RegimeSubscription {
			t.Fatalf("%s beside apiKey takes precedence at the pin; the wire credential is not the key", precedent)
		}
	}
	write(`{"providers":[]}`)
	if a.regime() != adapters.RegimeAPIKey {
		t.Fatal("an empty providers array falls through to the environment (e0t)")
	}
	write(`{"providers":[{"baseUrl":"https://a","apiKey":"k"}]}`)
	set(map[string]string{"COPILOT_PROVIDERS_CONFIG": filepath.Join(t.TempDir(), "missing.json")})
	if a.regime() != adapters.RegimeSubscription {
		t.Fatal("COPILOT_PROVIDERS_CONFIG names the file; the default path is not consulted when it is set")
	}
}

// TestGitHubBilledSessionNeverYieldsAWireCredential is FR-AGENT-014's
// negative clause at the adapter: a GitHub-billed session — GitHub's own
// token in every place the CLI or gh would put it, no BYOK base URL — is
// capture-only, and WireCredential refuses with the CON-001 code rather than
// lifting a token the gateway would refuse anyway.
func TestGitHubBilledSessionNeverYieldsAWireCredential(t *testing.T) {
	ch := t.TempDir()
	a := &Adapter{Home: t.TempDir(), CopilotHome: ch}
	gh := "gho_AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTt"
	for _, env := range []map[string]string{
		{},
		{"GITHUB_TOKEN": gh},
		{"GH_TOKEN": gh, "COPILOT_GITHUB_TOKEN": gh},
		{"COPILOT_PROVIDER_GHES_HOST": "ghe.example", "COPILOT_PROVIDER_GHES_TOKEN": gh},
		{"COPILOT_PROVIDER_BASE_URL": "https://api.githubcopilot.com", "COPILOT_PROVIDER_BEARER_TOKEN": gh},
	} {
		a.Env = envOf(env)
		d, err := a.Detect()
		if err != nil || d.Regime != adapters.RegimeSubscription {
			t.Fatalf("%v: regime %v err %v — a GitHub-billed session must never be API-key", env, d.Regime, err)
		}
		cred, err := a.WireCredential()
		if cred != "" || !errors.Is(err, ErrNotEligible) || RefusalCode(err) != CodeNotEligible {
			t.Fatalf("%v: WireCredential = %q, %v — must refuse with %s", env, cred, err, CodeNotEligible)
		}
	}
	// Positive control: the same adapter under BYOK lifts exactly the provider key.
	a.Env = envOf(map[string]string{"GITHUB_TOKEN": gh, "COPILOT_PROVIDER_BASE_URL": "https://api.openai.com/v1", "COPILOT_PROVIDER_API_KEY": "sk-synth"})
	if cred, err := a.WireCredential(); err != nil || cred != "sk-synth" {
		t.Fatalf("BYOK: WireCredential = %q, %v", cred, err)
	}
	if err := os.WriteFile(filepath.Join(ch, "providers.json"), []byte(`{"providers":[{"baseUrl":"https://a","apiKey":"k"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if cred, err := a.WireCredential(); cred != "" || !errors.Is(err, ErrNotEligible) {
		t.Fatalf("providers.json: the entry schema is unconfirmed, so its key is classified but never lifted: %q %v", cred, err)
	}
}

// TestRegistrationsMatchPinnedFixtures: the events the owned file registers
// are exactly the hook bodies the pinned corpus recorded (08 §5 rule 3).
func TestRegistrationsMatchPinnedFixtures(t *testing.T) {
	exp := loadExpectations(t)
	ents, err := os.ReadDir(filepath.Join(fixtureRoot, "hooks"))
	if err != nil {
		t.Fatal(err)
	}
	onDisk := map[string]bool{}
	for _, e := range ents {
		onDisk[strings.TrimSuffix(e.Name(), ".json")] = true
	}
	registered := map[string]bool{}
	for _, r := range hookRegistrations {
		registered[r.Event] = true
		if !onDisk[r.Event] {
			t.Errorf("registers %s with no fixture body under conformance/hooks/copilot/v1.0.85/hooks", r.Event)
		}
	}
	for ev := range onDisk {
		if !registered[ev] {
			t.Errorf("fixture body %s exists but is not registered", ev)
		}
	}
	for _, ev := range exp.Hooks.Registered {
		if !registered[ev] {
			t.Errorf("expectations register %s; the fragment does not", ev)
		}
	}
	if len(exp.Hooks.Registered) != len(hookRegistrations) {
		t.Errorf("expectations register %d events, fragment %d", len(exp.Hooks.Registered), len(hookRegistrations))
	}
}

// TestHooksFileParsesAsCopilotHookConfig pins the on-disk shape to the
// hooks-reference's command-hook format at the pin.
func TestHooksFileParsesAsCopilotHookConfig(t *testing.T) {
	var file struct {
		Version int `json:"version"`
		Hooks   map[string][]struct {
			Type       string            `json:"type"`
			Bash       string            `json:"bash"`
			Env        map[string]string `json:"env"`
			TimeoutSec int               `json:"timeoutSec"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(HooksFile(""), &file); err != nil {
		t.Fatal(err)
	}
	if file.Version != 1 || len(file.Hooks) != len(hookRegistrations) {
		t.Fatalf("version %d, %d events", file.Version, len(file.Hooks))
	}
	for ev, entries := range file.Hooks {
		if len(entries) != 1 {
			t.Fatalf("%s: %d entries", ev, len(entries))
		}
		h := entries[0]
		if h.Type != "command" || h.Bash != DefaultShimPath+" || true" || h.Env["MARK1_AGENT"] != "copilot" || h.TimeoutSec <= 0 {
			t.Fatalf("%s handler: %+v", ev, h)
		}
	}
	if file.Hooks["Stop"][0].TimeoutSec != 30 {
		t.Fatal("Stop keeps the 30 s gate budget")
	}
	if !bytes.Contains(HooksFile("/opt/shim"), []byte(`"bash": "/opt/shim || true"`)) {
		t.Fatal("a custom shim path is not written verbatim")
	}
}

// TestOwnedFileApplyIsIdempotentAndOffDeletesIt: mechanism A end to end —
// apply ∘ apply ≡ apply, then `mark1 off` leaves ~/.copilot byte-equal (no file).
func TestOwnedFileApplyIsIdempotentAndOffDeletesIt(t *testing.T) {
	ch, state := t.TempDir(), t.TempDir()
	target := filepath.Join(ch, "hooks", "mark1.json")
	if _, err := ApplyFragment(filepath.Join(ch, "absent", "hooks", "mark1.json"), state, ""); !errors.Is(err, ErrNoTarget) || RefusalCode(err) != CodeNoTarget {
		t.Fatalf("a missing $COPILOT_HOME must refuse with %s, got %v", CodeNoTarget, err)
	}
	first, err := ApplyFragment(target, state, "")
	if err != nil || !first.Changed || first.Mechanism != "A" {
		t.Fatalf("first apply: %+v %v", first, err)
	}
	after1, _ := os.ReadFile(target)
	if !bytes.Equal(after1, HooksFile("")) {
		t.Fatal("the owned file is not HooksFile's bytes")
	}
	second, err := ApplyFragment(target, state, "")
	if err != nil || second.Changed {
		t.Fatalf("re-apply must be a no-op: %+v %v", second, err)
	}
	after2, _ := os.ReadFile(target)
	if !bytes.Equal(after1, after2) {
		t.Fatal("apply ∘ apply changed bytes")
	}
	st, err := Inspect(state)
	if err != nil || st.State != StateOK || st.Mechanism != "A" || st.Target != target {
		t.Fatalf("inspect: %+v %v", st, err)
	}
	if err := os.WriteFile(target, append(after1, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyFragment(target, state, ""); !errors.Is(err, ErrDamaged) || RefusalCode(err) != CodeDamaged {
		t.Fatalf("a hand-edited owned file must refuse with %s, got %v", CodeDamaged, err)
	}
	if st, _ := Inspect(state); st.State != StateDamaged {
		t.Fatalf("inspect after edit: %+v", st)
	}
	if res, err := Revert(state); err != nil || res.Kind != "fragment-damaged" || len(res.Retained) != 1 {
		t.Fatalf("revert must write nothing over bytes that are not ours (08 §8.4 3b): %+v %v", res, err)
	}
	if _, err := os.Stat(ManifestPath(state)); err != nil {
		t.Fatal("3b keeps the manifest so `mark1 off` keeps seeing it")
	}
	if res, err := RepairFragment(target, state, ""); err != nil || !res.Changed {
		t.Fatalf("doctor --fix: %+v %v", res, err)
	}
	res, err := Revert(state)
	if err != nil || res.Kind != "verbatim" || !res.ByteEquality {
		t.Fatalf("revert: %+v %v", res, err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatal("mechanism A revert must delete the owned file")
	}
	if _, err := os.Stat(ManifestPath(state)); !os.IsNotExist(err) {
		t.Fatal("manifest must be deleted last")
	}
	if res, err := Revert(state); err != nil || res.Kind != "not-provisioned" {
		t.Fatalf("second off must succeed as a no-op: %+v %v", res, err)
	}
	a := &Adapter{Home: t.TempDir(), CopilotHome: ch, StateDir: state}
	if _, err := a.Apply(); err != nil {
		t.Fatal(err)
	}
	if st, _ := Inspect(state); st.State != StateOK || st.Target != target {
		t.Fatalf("adapter paths: %+v", st)
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

// TestReplayEventsCorpus is conf_hooks_copilot_1.0.85_replay's reader half:
// the fixture session-state tree through the manager under the corpus's
// enabled root emits exactly the DIAGNOSTIC boundaries expectations fix,
// nothing for the foreign workspace, and zero Usage.
func TestReplayEventsCorpus(t *testing.T) {
	exp := loadExpectations(t)
	if exp.UsageClass != "DIAGNOSTIC" || exp.UsageEventsExpected != 0 {
		t.Fatal("expectations must fix this surface as DIAGNOSTIC with no Usage")
	}
	set, err := tailers.NewWorkspaceSet(exp.WorkspaceRoot)
	if err != nil {
		t.Fatal(err)
	}
	ch := filepath.Join(t.TempDir(), ".copilot")
	if err := os.MkdirAll(ch, 0o700); err != nil {
		t.Fatal(err)
	}
	src, _ := filepath.Abs(filepath.Join(fixtureRoot, "transcripts", "session-state"))
	if err := os.Symlink(src, filepath.Join(ch, "session-state")); err != nil {
		t.Skip("symlink unavailable:", err)
	}
	a := &Adapter{Home: t.TempDir(), CopilotHome: ch}
	var got []*m1pv1.Event
	observed := 0
	mgr, err := a.StartTail(adapters.Workspace{Root: exp.WorkspaceRoot}, set, TailConfig{
		StateDir: t.TempDir(), UsageIdemKey: testIdemKey,
		Observe: func(*m1pv1.Event) { observed++ },
		Emit:    func(_ context.Context, ev *m1pv1.Event) error { got = append(got, ev); return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	mgr.Sweep(ctx)
	if err := mgr.CloseFlush(ctx); err != nil {
		t.Fatal(err)
	}
	if observed != len(got) {
		t.Fatalf("Observe ran %d times for %d emissions — the segmenter must see every diagnostic first", observed, len(got))
	}
	bySession := map[string][]*m1pv1.Event{}
	for _, ev := range got {
		if ev.GetUsage() != nil {
			t.Fatal("a Usage was emitted from events.jsonl — this surface has no per-request id (08 §2)")
		}
		if ev.GetOccurredAt() == nil {
			t.Fatal("occurred_at not stamped from the line's timestamp")
		}
		id, err := uuid.FromBytes(ev.GetSessionId())
		if err != nil {
			t.Fatal(err)
		}
		bySession[id.String()] = append(bySession[id.String()], ev)
	}
	var wantTotal int
	for _, st := range exp.Streams {
		wantTotal += len(st.DiagnosticEvents)
		evs := bySession[st.SessionID]
		if len(evs) != len(st.DiagnosticEvents) {
			t.Fatalf("%s: emitted %d events, expectations fix %d", st.File, len(evs), len(st.DiagnosticEvents))
		}
		for i, want := range st.DiagnosticEvents {
			switch want.Body {
			case "session_start":
				ss := evs[i].GetSessionStart()
				if ss == nil || ss.GetAgent() != "copilot" || ss.GetAgentVersion() != want.AgentVersion ||
					len(ss.GetCapturePaths()) != 1 || ss.GetCapturePaths()[0] != m1pv1.CapturePath_CAPTURE_PATH_TRANSCRIPT {
					t.Fatalf("%s[%d]: %v", st.File, i, evs[i])
				}
			case "session_end":
				se := evs[i].GetSessionEnd()
				if se == nil || se.GetReason().String() != want.Reason || se.GetDurationMs() != want.DurationMs || se.GetDrained() {
					t.Fatalf("%s[%d]: %v, want %+v", st.File, i, evs[i], want)
				}
			default:
				t.Fatalf("expectations name a body %q this reader does not know", want.Body)
			}
		}
	}
	if len(got) != wantTotal {
		t.Fatalf("manager emitted %d events, expectations fix %d", len(got), wantTotal)
	}
	if len(exp.OutOfWorkspace) == 0 {
		t.Fatal("corpus lost its out-of-workspace fixture — the containment gate is untested")
	}
	for _, foreign := range exp.OutOfWorkspace {
		if _, err := os.Stat(filepath.Join(fixtureRoot, foreign.File)); err != nil {
			t.Fatalf("foreign fixture missing: %v", err)
		}
		if len(bySession[foreign.NeverEmitSessionID]) != 0 {
			t.Fatalf("foreign workspace session %s emitted — a non-enabled workspace was captured (invariant 3)", foreign.NeverEmitSessionID)
		}
	}
}

func TestEventsParserReadsOnlySessionBoundaries(t *testing.T) {
	var got []*m1pv1.Event
	p := newEventsParser(TailConfig{Emit: func(_ context.Context, ev *m1pv1.Event) error { got = append(got, ev); return nil }})
	sid := "c0910000-0000-4000-8000-00000000aa01"
	if _, ok := p([]byte(`{"type":"session.shutdown","data":{"shutdownType":"routine","sessionStartTime":1789553964419,"modelMetrics":{}},"timestamp":"2026-09-16T10:19:24.779Z"}`)); ok || len(got) != 0 {
		t.Fatal("a shutdown before any start has no session to close")
	}
	if _, ok := p([]byte(`{"type":"session.start","data":{"sessionId":"not-a-uuid","copilotVersion":"1.0.85","context":{"cwd":"/w"}},"timestamp":"2026-09-16T10:19:24.448Z"}`)); ok || len(got) != 0 {
		t.Fatal("an unparseable session id emits nothing (never guess)")
	}
	if _, ok := p([]byte(`{"type":"session.start","data":{"sessionId":"` + sid + `","copilotVersion":"1.0.85","context":{"cwd":"/w"}},"timestamp":"2026-09-16T10:19:24.448Z"}`)); ok || len(got) != 1 || got[0].GetSessionStart().GetAgentVersion() != "1.0.85" {
		t.Fatalf("session.start: ok=%v got=%v", ok, got)
	}
	if _, ok := p([]byte(`{"type":"session.start","data":{"sessionId":"` + sid + `","copilotVersion":"1.0.85","context":{"cwd":"/w"}},"timestamp":"2026-09-16T10:19:24.448Z"}`)); ok || len(got) != 1 {
		t.Fatal("a second session.start on one stream opens nothing twice")
	}
	if _, ok := p([]byte(`{"type":"assistant.usage","ephemeral":true,"data":{"model":"m","inputTokens":100,"outputTokens":10},"timestamp":"2026-09-16T10:19:24.600Z"}`)); ok || len(got) != 1 {
		t.Fatal("an assistant.usage line — never persisted by the vendor — is still never a Usage here")
	}
	if _, ok := p([]byte(`{"type":"session.shutdown","data":{"shutdownType":"error","sessionStartTime":1789553964419,"modelMetrics":{"m":{"usage":{"inputTokens":320,"outputTokens":42}}}},"timestamp":"2026-09-16T10:19:24.779Z"}`)); ok || len(got) != 2 {
		t.Fatalf("session.shutdown: ok=%v got=%d", ok, len(got))
	}
	se := got[1].GetSessionEnd()
	if se.GetReason() != m1pv1.EndReason_END_REASON_CRASH_DETECTED || se.GetDurationMs() != 360 || got[1].GetOccurredAt().AsTime().UnixMilli() != 1789553964779 {
		t.Fatalf("session_end: %v", se)
	}
	if id, _ := uuid.FromBytes(got[1].GetSessionId()); id.String() != sid {
		t.Fatalf("session_end stamped session %s", id)
	}
	if startCwd([]byte(`{"type":"session.start","data":{"context":{"cwd":"/w"}}}`)) != "/w" || startCwd([]byte(`{"type":"session.resume","data":{"context":{"cwd":"/w"}}}`)) != "" {
		t.Fatal("cwd comes from session.start's context only")
	}
}
