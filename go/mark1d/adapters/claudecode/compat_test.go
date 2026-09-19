package claudecode

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const probeGood = `{"parentUuid":"aa000000-0000-4000-8000-000000000001","isSidechain":false,"message":{"model":"claude-x","id":"msg_01A","type":"message","role":"assistant","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":2,"cache_creation_input_tokens":6425,"cache_read_input_tokens":10143,"output_tokens":4,"service_tier":"standard"}},"requestId":"req_01A","type":"assistant","uuid":"aa000000-0000-4000-8000-000000000002","timestamp":"2026-09-16T08:26:42.110Z","cwd":"/home/devuser/workspace/acme-app","sessionId":"aa000000-0000-4000-8000-000000000201","version":"9.9.9","gitBranch":"HEAD"}`

func probeHome(t *testing.T, lines ...string) *Adapter {
	t.Helper()
	home := t.TempDir()
	dir := filepath.Join(home, ".claude", "projects", "-home-devuser-workspace-acme-app")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := `{"type":"queue-operation","operation":"enqueue","sessionId":"aa000000-0000-4000-8000-000000000201"}` + "\n" + strings.Join(lines, "\n")
	if err := os.WriteFile(filepath.Join(dir, "aa000000-0000-4000-8000-000000000201.jsonl"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return &Adapter{Home: home}
}

func TestCompatibilityPinnedNeedsNoProbe(t *testing.T) {
	a := &Adapter{Home: t.TempDir()} // no transcripts at all
	if c, err := a.Compatibility("2.1.251"); c != Pinned || err != nil {
		t.Fatalf("pinned version = %v, %v", c, err)
	}
}

func TestCompatibilityStructuralProbeAdmitsUnpinned(t *testing.T) {
	a := probeHome(t, probeGood)
	if c, err := a.Compatibility("9.9.9"); c != CompatibleUnpinned || err != nil {
		t.Fatalf("well-shaped unpinned = %v, %v", c, err)
	}
}

func TestCompatibilityRefusesBadShapes(t *testing.T) {
	cases := map[string]struct{ line, want string }{
		"missing usage field": {strings.Replace(probeGood, `"cache_read_input_tokens":10143,`, "", 1), "usage.cache_read_input_tokens"},
		"missing requestId":   {strings.Replace(probeGood, `"requestId":"req_01A",`, "", 1), "requestId"},
		"missing cwd":         {strings.Replace(probeGood, `"cwd":"/home/devuser/workspace/acme-app",`, "", 1), "cwd"},
		"mistyped tokens":     {strings.Replace(probeGood, `"output_tokens":4`, `"output_tokens":"4"`, 1), "mistyped"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			a := probeHome(t, tc.line)
			c, err := a.Compatibility("9.9.9")
			if c != Incompatible || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, %v; want Incompatible naming %q", c, err, tc.want)
			}
		})
	}
	if c, err := probeHome(t, probeGood).Compatibility(""); c != Incompatible || err == nil {
		t.Fatalf("unsniffable = %v, %v", c, err)
	}
}

func TestCompatibilityUnprobedUntilATranscriptExists(t *testing.T) {
	a := probeHome(t, strings.Replace(probeGood, `"version":"9.9.9"`, `"version":"8.8.8"`, 1))
	c, err := a.Compatibility("9.9.9")
	if c != Unprobed || err == nil || !strings.Contains(err.Error(), "no claude 9.9.9 transcript") || c.Admits() {
		t.Fatalf("no line of that version = %v, %v; want Unprobed, refused at the tail gate", c, err)
	}
}
