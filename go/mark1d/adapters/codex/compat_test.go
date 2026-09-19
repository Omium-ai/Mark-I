package codex

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters"
)

const (
	metaLine    = `{"timestamp":"2026-09-19T08:25:00.017Z","ordinal":1,"type":"session_meta","payload":{"id":"019965a0-0000-7000-8000-00000000bb01","timestamp":"2026-09-19T08:25:00.017Z","cwd":"/home/devuser/workspace/acme-app","originator":"codex_cli_rs","cli_version":"9.9.9","source":"cli"}}`
	turnLine    = `{"timestamp":"2026-09-19T08:25:00.019Z","ordinal":2,"type":"turn_context","payload":{"turn_id":"019965a0-0101-7000-8000-000000000101","cwd":"/home/devuser/workspace/acme-app","model":"gpt-5.3-codex"}}`
	replyLine   = `{"timestamp":"2026-09-19T08:25:04.300Z","ordinal":3,"type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"ok"}]}}`
	countLine   = `{"timestamp":"2026-09-19T08:25:04.311Z","ordinal":4,"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":1200,"output_tokens":180}}}}`
	recordLine  = `{"timestamp":"2026-09-19T08:25:04.312Z","ordinal":5,"type":"token_usage_record","payload":{"thread_id":"019965a0-0000-7000-8000-00000000bb01","turn_id":"019965a0-0101-7000-8000-000000000101","response_id":"resp_SynthProbeAAAAAAAA","usage":{"input_tokens":1200,"cached_input_tokens":0,"cache_write_input_tokens":0,"output_tokens":180,"reasoning_output_tokens":64,"total_tokens":1380}}}`
	rolloutName = "rollout-2026-09-19T08-25-00-019965a0-0000-7000-8000-00000000bb01.jsonl"
)

func probeHome(t *testing.T, lines ...string) *Adapter {
	t.Helper()
	ch := t.TempDir()
	dir := filepath.Join(ch, "sessions", "2026", "09", "19")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, rolloutName), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return &Adapter{Home: t.TempDir(), CodexHome: ch}
}

func TestCompatibilityPinnedNeedsNoProbe(t *testing.T) {
	a := &Adapter{Home: t.TempDir(), CodexHome: t.TempDir()}
	if c, err := a.Compatibility("0.154.0"); c != adapters.Pinned || err != nil {
		t.Fatalf("pinned version = %v, %v", c, err)
	}
}

func TestCompatibilityStructuralProbeAdmitsUnpinned(t *testing.T) {
	a := probeHome(t, metaLine, turnLine, replyLine, countLine, recordLine)
	if c, err := a.Compatibility("9.9.9"); c != adapters.CompatibleUnpinned || err != nil || !c.Admits() {
		t.Fatalf("well-shaped unpinned = %v, %v", c, err)
	}
}

func TestCompatibilityRefusesBadShapes(t *testing.T) {
	cases := map[string]struct {
		lines []string
		want  string
	}{
		"missing usage field":                   {[]string{metaLine, turnLine, strings.Replace(recordLine, `"cache_write_input_tokens":0,`, "", 1)}, "usage.cache_write_input_tokens"},
		"missing response_id":                   {[]string{metaLine, turnLine, strings.Replace(recordLine, `"response_id":"resp_SynthProbeAAAAAAAA",`, "", 1)}, "payload.response_id"},
		"mistyped tokens":                       {[]string{metaLine, turnLine, strings.Replace(recordLine, `"output_tokens":180`, `"output_tokens":"180"`, 1)}, "mistyped"},
		"missing cwd":                           {[]string{strings.Replace(metaLine, `"cwd":"/home/devuser/workspace/acme-app",`, "", 1), turnLine, recordLine}, "payload.cwd"},
		"no model":                              {[]string{metaLine, recordLine}, "turn_context.payload.model"},
		"pre-usage-record build (0.50.0 shape)": {[]string{metaLine, turnLine, replyLine, countLine}, "npm i -g @openai/codex@latest"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c, err := probeHome(t, tc.lines...).Compatibility("9.9.9")
			if c != adapters.Incompatible || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, %v; want Incompatible naming %q", c, err, tc.want)
			}
		})
	}
	if c, err := probeHome(t, metaLine, turnLine, recordLine).Compatibility(""); c != adapters.Incompatible || err == nil {
		t.Fatalf("unsniffable = %v, %v", c, err)
	}
}

func TestCompatibilityUnprobedUntilARolloutExists(t *testing.T) {
	for name, lines := range map[string][]string{
		"other version only": {strings.Replace(metaLine, `"cli_version":"9.9.9"`, `"cli_version":"8.8.8"`, 1), turnLine, recordLine},
		"no turn yet":        {metaLine},
		"turn, no response":  {metaLine, turnLine},
	} {
		t.Run(name, func(t *testing.T) {
			c, err := probeHome(t, lines...).Compatibility("9.9.9")
			if c != adapters.Unprobed || err == nil || !strings.Contains(err.Error(), "no codex 9.9.9 rollout") || c.Admits() {
				t.Fatalf("got %v, %v; want Unprobed, refused at the tail gate", c, err)
			}
		})
	}
	if c, err := (&Adapter{Home: t.TempDir(), CodexHome: t.TempDir()}).Compatibility("9.9.9"); c != adapters.Unprobed || err == nil {
		t.Fatalf("empty sessions tree = %v, %v", c, err)
	}
}

func TestCompatibilityProbesThePinnedCorpusShape(t *testing.T) {
	a := &Adapter{Home: t.TempDir(), CodexHome: filepath.Join(fixtureRoot, "transcripts")}
	if err := probe(filepath.Join(a.CodexHome, "sessions"), "0.154.0"); err != nil {
		t.Fatalf("the recorded corpus must pass its own probe: %v", err)
	}
}
