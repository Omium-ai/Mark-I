package control

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/opencode"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/provision"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/off"
)

// TestResumeReprovisionsWhatStartSkipped: a paused agent keeps its old plugin through the daemon-start upgrade and gets this release's on resume, stamped with the daemon's version.
func TestResumeReprovisionsWhatStartSkipped(t *testing.T) {
	t.Setenv("MARK1_DISABLE", "")
	fakeHome(t)
	s, dir := newServer(t)
	plugin := filepath.Join(t.TempDir(), "opencode", "plugins", "mark1.js")
	if err := os.MkdirAll(filepath.Dir(filepath.Dir(plugin)), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := opencode.ApplyFragment(plugin, dir, "~/.omium/mark1/bin-old/mark1-hookshim"); err != nil {
		t.Fatal(err)
	}
	if resp, body := call(t, s, http.MethodPost, "/v1/agents/opencode/pause", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("pause %d %s", resp.StatusCode, body)
	}
	if out := s.Reprovision(); len(out) != 1 || out[0].Action != "paused" {
		t.Fatalf("start while paused: %+v", out)
	}
	if b, _ := os.ReadFile(plugin); !strings.Contains(string(b), "bin-old") {
		t.Fatal("a paused agent's plugin was rewritten at start")
	}
	if resp, body := call(t, s, http.MethodPost, "/v1/agents/opencode/resume", nil); resp.StatusCode != http.StatusOK || off.AgentOff(dir, "opencode") {
		t.Fatalf("resume %d %s", resp.StatusCode, body)
	}
	if b, _ := os.ReadFile(plugin); string(b) != string(opencode.Plugin("")) {
		t.Fatal("resume did not bring the plugin to this release's bytes")
	}
	if st, err := provision.ReadStamp(dir, "opencode"); err != nil || st.Version != "test" {
		t.Fatalf("stamp %+v %v", st, err)
	}
	_, body := call(t, s, http.MethodGet, "/v1/agents", nil)
	var agents []map[string]any
	if err := json.Unmarshal(body, &agents); err != nil {
		t.Fatal(err)
	}
	for _, a := range agents {
		if a["name"] != "opencode" {
			continue
		}
		if p, ok := a["provisioned"].(map[string]any); !ok || p["provisioned_by"] != "test" {
			t.Fatalf("/v1/agents opencode row: %v", a)
		}
	}
}
