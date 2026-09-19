package gemini

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters"
)

const (
	headLine   = `{"sessionId":"6f1e2d3c-0000-4000-8000-00000000cc01","projectHash":"daebdc91a9407051591cc1b410cdf3b5bff5216a4d0f53d1f7584d741f8ec23a","startTime":"2026-09-19T08:25:00.000Z","lastUpdated":"2026-09-19T08:25:00.000Z"}`
	userLine   = `{"id":"5b2d0001-0000-4000-8000-000000000001","timestamp":"2026-09-19T08:25:01.000Z","type":"user","content":[{"text":"add a retry"}]}`
	setLine    = `{"$set":{"lastUpdated":"2026-09-19T08:25:01.000Z"}}`
	geminiLine = `{"id":"7a1c0001-0000-4000-8000-000000000001","timestamp":"2026-09-19T08:25:04.312Z","type":"gemini","content":"ok","thoughts":[],"tokens":{"input":1200,"output":180,"cached":0,"thoughts":40,"tool":0,"total":1420},"model":"gemini-2.5-pro"}`
	noTokens   = `{"id":"7a1c0002-0000-4000-8000-000000000002","timestamp":"2026-09-19T08:25:09.000Z","type":"gemini","content":"partial","thoughts":[],"model":"gemini-2.5-pro"}`
)

func probeHome(t *testing.T, lines ...string) *Adapter {
	t.Helper()
	gd := t.TempDir()
	slug := filepath.Join(gd, "tmp", "acme-app")
	if err := os.MkdirAll(filepath.Join(slug, "chats"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(slug, ".project_root"), []byte("/home/devuser/workspace/acme-app\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(slug, "chats", "session-2026-09-19T08-25-6f1e2d3c.jsonl"), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return &Adapter{Home: t.TempDir(), GeminiDir: gd, StateDir: t.TempDir()}
}

func TestCompatibilityPinnedNeedsNoProbe(t *testing.T) {
	a := &Adapter{Home: t.TempDir(), GeminiDir: t.TempDir(), StateDir: t.TempDir()}
	if c, err := a.Compatibility("0.59.0"); c != adapters.Pinned || err != nil {
		t.Fatalf("pinned version = %v, %v", c, err)
	}
}

func TestCompatibilityStructuralProbeAdmitsUnpinned(t *testing.T) {
	a := probeHome(t, headLine, userLine, setLine, noTokens, geminiLine)
	if c, err := a.Compatibility("9.9.9"); c != adapters.CompatibleUnpinned || err != nil || !c.Admits() {
		t.Fatalf("well-shaped unpinned = %v, %v", c, err)
	}
}

func TestCompatibilityRefusesBadShapes(t *testing.T) {
	cases := map[string]struct {
		lines []string
		want  string
	}{
		"missing tokens field": {[]string{headLine, userLine, strings.Replace(geminiLine, `"cached":0,`, "", 1)}, "tokens.cached"},
		"missing model":        {[]string{headLine, userLine, strings.Replace(geminiLine, `,"model":"gemini-2.5-pro"`, "", 1)}, "model"},
		"mistyped tokens":      {[]string{headLine, userLine, strings.Replace(geminiLine, `"output":180`, `"output":"180"`, 1)}, "mistyped"},
		"head lacks hash":      {[]string{strings.Replace(headLine, `"projectHash":"daebdc91a9407051591cc1b410cdf3b5bff5216a4d0f53d1f7584d741f8ec23a",`, "", 1), geminiLine}, "projectHash"},
		"tokens never written": {[]string{headLine, userLine, noTokens}, "none carries tokens"},
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
		a := probeHome(t, headLine, userLine, geminiLine)
		if err := adapters.WriteShape(a.StateDir, "gemini", "BeforeTool", map[string]string{"hook_event_name": "string"}, []string{"tool_name"}); err != nil {
			t.Fatal(err)
		}
		c, err := a.Compatibility("9.9.9")
		if c != adapters.Incompatible || err == nil || !strings.Contains(err.Error(), "BeforeTool") || !strings.Contains(err.Error(), "tool_name") {
			t.Fatalf("got %v, %v; want Incompatible naming the hook field", c, err)
		}
	})
	if c, err := probeHome(t, headLine, geminiLine).Compatibility(""); c != adapters.Incompatible || err == nil {
		t.Fatalf("unsniffable = %v, %v", c, err)
	}
}

func TestCompatibilityUnprobedUntilAChatExists(t *testing.T) {
	for name, lines := range map[string][]string{
		"head only":      {headLine},
		"user turn only": {headLine, userLine, setLine},
		"torn head":      {`{"sessionId":"6f1e2d3c-00`},
	} {
		t.Run(name, func(t *testing.T) {
			c, err := probeHome(t, lines...).Compatibility("9.9.9")
			if c != adapters.Unprobed || err == nil || !strings.Contains(err.Error(), "no gemini 9.9.9 chat") || c.Admits() {
				t.Fatalf("got %v, %v; want Unprobed, refused at the tail gate", c, err)
			}
		})
	}
	if c, err := (&Adapter{Home: t.TempDir(), GeminiDir: t.TempDir(), StateDir: t.TempDir()}).Compatibility("9.9.9"); c != adapters.Unprobed || err == nil {
		t.Fatalf("empty tmp tree = %v, %v", c, err)
	}
}

func TestCompatibilityProbesThePinnedCorpusShape(t *testing.T) {
	if err := probe(filepath.Join(fixtureRoot, "transcripts", "tmp"), "0.59.0"); err != nil {
		t.Fatalf("the pinned corpus must pass its own probe: %v", err)
	}
}
