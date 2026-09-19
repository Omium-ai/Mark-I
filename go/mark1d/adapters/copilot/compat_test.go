package copilot

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters"
)

const (
	startLine    = `{"type":"session.start","data":{"sessionId":"c0910000-0000-4000-8000-00000000dd01","version":1,"producer":"copilot-agent","copilotVersion":"9.9.9","startTime":"2026-09-19T10:19:24.419Z","selectedModel":"fake-model","context":{"cwd":"/home/devuser/acme-app","gitRoot":"/home/devuser/acme-app","branch":"master"}},"id":"c0910000-0000-4000-8000-000000000101","timestamp":"2026-09-19T10:19:24.448Z","parentId":null}`
	turnLine     = `{"type":"assistant.turn_start","data":{"turnId":"0","interactionId":"c0910000-0000-4000-8000-000000000106"},"id":"c0910000-0000-4000-8000-000000000109","timestamp":"2026-09-19T10:19:24.600Z","parentId":"c0910000-0000-4000-8000-000000000108"}`
	shutdownLine = `{"type":"session.shutdown","data":{"shutdownType":"routine","totalPremiumRequests":0,"sessionStartTime":1789553964419,"currentModel":"fake-model"},"id":"c0910000-0000-4000-8000-000000000123","timestamp":"2026-09-19T10:19:24.779Z","parentId":"c0910000-0000-4000-8000-000000000122"}`
)

func probeHome(t *testing.T, lines ...string) *Adapter {
	t.Helper()
	ch := t.TempDir()
	dir := filepath.Join(ch, "session-state", "c0910000-0000-4000-8000-00000000dd01")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return &Adapter{Home: t.TempDir(), CopilotHome: ch, StateDir: t.TempDir(), Env: func(string) string { return "" }}
}

func TestCompatibilityPinnedNeedsNoProbe(t *testing.T) {
	a := &Adapter{Home: t.TempDir(), CopilotHome: t.TempDir(), StateDir: t.TempDir(), Env: func(string) string { return "" }}
	if c, err := a.Compatibility("1.0.85"); c != adapters.Pinned || err != nil {
		t.Fatalf("pinned version = %v, %v", c, err)
	}
}

func TestCompatibilityStructuralProbeAdmitsUnpinned(t *testing.T) {
	a := probeHome(t, startLine, turnLine, shutdownLine)
	if c, err := a.Compatibility("9.9.9"); c != adapters.CompatibleUnpinned || err != nil || !c.Admits() {
		t.Fatalf("well-shaped unpinned = %v, %v", c, err)
	}
}

func TestCompatibilityRefusesBadShapes(t *testing.T) {
	cases := map[string]struct {
		lines []string
		want  string
	}{
		"missing cwd":               {[]string{strings.Replace(startLine, `"context":{"cwd":"/home/devuser/acme-app","gitRoot":"/home/devuser/acme-app","branch":"master"}`, `"context":{"gitRoot":"/home/devuser/acme-app"}`, 1), shutdownLine}, "data.context.cwd"},
		"missing sessionId":         {[]string{strings.Replace(startLine, `"sessionId":"c0910000-0000-4000-8000-00000000dd01",`, "", 1), shutdownLine}, "data.sessionId"},
		"sessionId not a uuid":      {[]string{strings.Replace(startLine, `c0910000-0000-4000-8000-00000000dd01`, `session-1`, 1), shutdownLine}, "not a UUID"},
		"missing shutdownType":      {[]string{startLine, strings.Replace(shutdownLine, `"shutdownType":"routine",`, "", 1)}, "data.shutdownType"},
		"missing sessionStartTime":  {[]string{startLine, strings.Replace(shutdownLine, `"sessionStartTime":1789553964419,`, "", 1)}, "data.sessionStartTime"},
		"mistyped sessionStartTime": {[]string{startLine, strings.Replace(shutdownLine, `"sessionStartTime":1789553964419`, `"sessionStartTime":"1789553964419"`, 1)}, "mistyped"},
		"version stamp gone":        {[]string{strings.Replace(startLine, `"copilotVersion":"9.9.9",`, "", 1), shutdownLine}, "data.copilotVersion"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c, err := probeHome(t, tc.lines...).Compatibility("9.9.9")
			if c != adapters.Incompatible || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, %v; want Incompatible naming %q", c, err, tc.want)
			}
		})
	}
	t.Run("hook shape rename", func(t *testing.T) {
		a := probeHome(t, startLine, shutdownLine)
		if err := adapters.WriteShape(a.StateDir, "copilot", "PreToolUse", map[string]string{"hook_event_name": "string"}, []string{"tool_name"}); err != nil {
			t.Fatal(err)
		}
		c, err := a.Compatibility("9.9.9")
		if c != adapters.Incompatible || err == nil || !strings.Contains(err.Error(), "PreToolUse") || !strings.Contains(err.Error(), "tool_name") {
			t.Fatalf("got %v, %v; want Incompatible naming the hook field", c, err)
		}
	})
	if c, err := probeHome(t, startLine, shutdownLine).Compatibility(""); c != adapters.Incompatible || err == nil {
		t.Fatalf("unsniffable = %v, %v", c, err)
	}
}

func TestCompatibilityUnprobedUntilASessionExists(t *testing.T) {
	for name, lines := range map[string][]string{
		"other version only": {strings.Replace(startLine, `"copilotVersion":"9.9.9"`, `"copilotVersion":"8.8.8"`, 1), shutdownLine},
		"not shut down yet":  {startLine, turnLine},
		"empty file":         {""},
	} {
		t.Run(name, func(t *testing.T) {
			c, err := probeHome(t, lines...).Compatibility("9.9.9")
			if c != adapters.Unprobed || err == nil || !strings.Contains(err.Error(), "no copilot 9.9.9 session-state") || c.Admits() {
				t.Fatalf("got %v, %v; want Unprobed, refused at the tail gate", c, err)
			}
		})
	}
	if c, err := (&Adapter{Home: t.TempDir(), CopilotHome: t.TempDir(), StateDir: t.TempDir(), Env: func(string) string { return "" }}).Compatibility("9.9.9"); c != adapters.Unprobed || err == nil {
		t.Fatalf("empty session-state tree = %v, %v", c, err)
	}
}

func TestCompatibilityProbesThePinnedCorpusShape(t *testing.T) {
	if err := probe(filepath.Join(fixtureRoot, "transcripts", "session-state"), "1.0.85"); err != nil {
		t.Fatalf("the pinned corpus must pass its own probe: %v", err)
	}
}
