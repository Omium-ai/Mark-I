package opencode

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters"
)

const (
	assistantLine = `{"type":"message.updated","properties":{"sessionID":"ses_0199a1b2c3d4SynthProbeAA01","info":{"id":"msg_0199a1b2c3d4SynthProbeM001","sessionID":"ses_0199a1b2c3d4SynthProbeAA01","role":"assistant","time":{"created":1789547101100},"modelID":"claude-sonnet-4-5","providerID":"anthropic","path":{"cwd":"/home/devuser/workspace/acme-app","root":"/home/devuser/workspace/acme-app"},"cost":0,"tokens":{"input":0,"output":0,"reasoning":0,"cache":{"read":0,"write":0}}}}}`
	stepLine      = `{"type":"message.part.updated","properties":{"sessionID":"ses_0199a1b2c3d4SynthProbeAA01","part":{"id":"prt_0199a1b2c3d4SynthProbeP001","sessionID":"ses_0199a1b2c3d4SynthProbeAA01","messageID":"msg_0199a1b2c3d4SynthProbeM001","type":"step-finish","reason":"stop","cost":0.0123,"tokens":{"input":1200,"output":180,"reasoning":40,"cache":{"read":0,"write":0}}},"time":1789547104312}}`
	finishedLine  = `{"type":"message.updated","properties":{"sessionID":"ses_0199a1b2c3d4SynthProbeAA01","info":{"id":"msg_0199a1b2c3d4SynthProbeM001","sessionID":"ses_0199a1b2c3d4SynthProbeAA01","role":"assistant","time":{"created":1789547101100},"modelID":"claude-sonnet-4-5","providerID":"anthropic","path":{"cwd":"/home/devuser/workspace/acme-app","root":"/home/devuser/workspace/acme-app"},"cost":0.0123,"tokens":{"input":1200,"output":180,"reasoning":40,"cache":{"read":0,"write":0}},"finish":"stop"}}}`
)

func probeHome(t *testing.T, lines ...string) *Adapter {
	t.Helper()
	home := t.TempDir()
	dir := filepath.Join(home, ".omium", "mark1", "capture", "opencode")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ses_0199a1b2c3d4SynthProbeAA01.jsonl"), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return &Adapter{Home: home, ConfigDir: t.TempDir(), DataDir: t.TempDir(), OCState: t.TempDir(), StateDir: t.TempDir()}
}

func TestCompatibilityPinnedNeedsNoProbe(t *testing.T) {
	a := &Adapter{Home: t.TempDir(), ConfigDir: t.TempDir(), StateDir: t.TempDir()}
	if c, err := a.Compatibility("1.18.31"); c != adapters.Pinned || err != nil {
		t.Fatalf("pinned version = %v, %v", c, err)
	}
}

func TestCompatibilityStructuralProbeAdmitsUnpinned(t *testing.T) {
	a := probeHome(t, assistantLine, stepLine, finishedLine)
	if c, err := a.Compatibility("9.9.9"); c != adapters.CompatibleUnpinned || err != nil || !c.Admits() {
		t.Fatalf("well-shaped unpinned = %v, %v", c, err)
	}
}

func TestCompatibilityRefusesBadShapes(t *testing.T) {
	cases := map[string]struct {
		lines []string
		want  string
	}{
		"missing cache.write":        {[]string{assistantLine, strings.Replace(stepLine, `,"write":0`, "", 1)}, "part.tokens.cache.write"},
		"missing part id":            {[]string{assistantLine, strings.Replace(stepLine, `"id":"prt_0199a1b2c3d4SynthProbeP001",`, "", 1)}, "part.id"},
		"missing time":               {[]string{assistantLine, strings.Replace(stepLine, `,"time":1789547104312`, "", 1)}, "time"},
		"mistyped tokens":            {[]string{assistantLine, strings.Replace(stepLine, `"output":180`, `"output":"180"`, 1)}, "mistyped"},
		"missing providerID":         {[]string{strings.Replace(assistantLine, `"providerID":"anthropic",`, "", 1), stepLine}, "info.providerID"},
		"missing cwd":                {[]string{strings.Replace(assistantLine, `"path":{"cwd":"/home/devuser/workspace/acme-app","root":"/home/devuser/workspace/acme-app"},`, "", 1), stepLine}, "info.path.cwd"},
		"finished with no step part": {[]string{assistantLine, finishedLine}, "no step-finish part"},
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
		a := probeHome(t, assistantLine, stepLine)
		if err := adapters.WriteShape(a.StateDir, "opencode", "tool.execute.before", map[string]string{"hook_event_name": "string"}, []string{"callID"}); err != nil {
			t.Fatal(err)
		}
		c, err := a.Compatibility("9.9.9")
		if c != adapters.Incompatible || err == nil || !strings.Contains(err.Error(), "tool.execute.before") || !strings.Contains(err.Error(), "callID") {
			t.Fatalf("got %v, %v; want Incompatible naming the hook field", c, err)
		}
	})
	if c, err := probeHome(t, assistantLine, stepLine).Compatibility(""); c != adapters.Incompatible || err == nil {
		t.Fatalf("unsniffable = %v, %v", c, err)
	}
}

func TestCompatibilityUnprobedUntilACaptureExists(t *testing.T) {
	for name, lines := range map[string][]string{
		"assistant opened only": {assistantLine},
		"empty file":            {""},
	} {
		t.Run(name, func(t *testing.T) {
			c, err := probeHome(t, lines...).Compatibility("9.9.9")
			if c != adapters.Unprobed || err == nil || !strings.Contains(err.Error(), "no opencode 9.9.9 capture") || c.Admits() {
				t.Fatalf("got %v, %v; want Unprobed, refused at the tail gate", c, err)
			}
		})
	}
	if c, err := (&Adapter{Home: t.TempDir(), ConfigDir: t.TempDir(), StateDir: t.TempDir()}).Compatibility("9.9.9"); c != adapters.Unprobed || err == nil {
		t.Fatalf("empty capture dir = %v, %v", c, err)
	}
}

func TestCompatibilityProbesThePinnedCorpusShape(t *testing.T) {
	if err := probe(filepath.Join(fixtureRoot, "transcripts", "capture"), "1.18.31"); err != nil {
		t.Fatalf("the pinned corpus must pass its own probe: %v", err)
	}
}
