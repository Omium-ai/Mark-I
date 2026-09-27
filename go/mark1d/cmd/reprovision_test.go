//go:build unix

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/opencode"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/provision"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/fabric/fabrictest"
)

// TestDaemonStartReprovisionsStaleFragment is the `mark1 update` path end to end: a plugin an earlier release wrote is brought to this build's bytes on the first start with an enabled workspace (never without one), and stamped with the running version.
func TestDaemonStartReprovisionsStaleFragment(t *testing.T) {
	t.Setenv("MARK1_DISABLE", "")
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	root := filepath.Join(dir, "ws")
	plugin := filepath.Join(dir, "opencode", "plugins", "mark1.js")
	for _, d := range []string{stateDir, root, filepath.Dir(filepath.Dir(plugin))} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := opencode.ApplyFragment(plugin, stateDir, "~/.omium/mark1/bin-old/mark1-hookshim"); err != nil {
		t.Fatal(err)
	}
	cfg := config{
		stateDir: stateDir,
		spoolDir: filepath.Join(dir, "spool"),
		socket:   filepath.Join(fabrictest.SocketDir(t), "sock", "m1p.sock"),
		offPoll:  10 * time.Millisecond,
	}
	stop := runDaemon(t, cfg)
	waitFor(t, "daemon up with no enabled workspace", func() bool { _, err := os.Stat(cfg.socket); return err == nil })
	stop()
	if b, _ := os.ReadFile(plugin); !strings.Contains(string(b), "bin-old") {
		t.Fatal("no enabled workspace: Mark 1 is not on for anything, so no fence is touched")
	}

	ws := `{"version":1,"workspaces":[{"path":"` + filepath.ToSlash(root) + `","enabled_at":"2026-09-26T00:00:00Z"}]}`
	if err := os.WriteFile(filepath.Join(stateDir, "workspaces.json"), []byte(ws), 0o600); err != nil {
		t.Fatal(err)
	}

	stop = runDaemon(t, cfg)
	defer stop()
	waitFor(t, "stale opencode plugin upgraded at daemon start", func() bool {
		b, err := os.ReadFile(plugin)
		return err == nil && !strings.Contains(string(b), "bin-old")
	})
	if b, _ := os.ReadFile(plugin); string(b) != string(opencode.Plugin("")) {
		t.Fatal("the upgraded plugin is not this build's bytes")
	}
	waitFor(t, "release stamp", func() bool {
		s, err := provision.ReadStamp(stateDir, "opencode")
		return err == nil && s.Version == version
	})
}
