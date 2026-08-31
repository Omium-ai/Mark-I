package enable

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"strings"

	"github.com/Omium-ai/omium-mark1/go/mark1/internal/cli"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/claudecode"
)

// enrolledEnv also returns a FAKE home. Every Run below passes it: enable now
// writes an 08 §8 fragment into ~/.claude/settings.json, and a test that
// forgot the seam would edit the developer's own agent config.
func enrolledEnv(t *testing.T) (*cli.Env, *bytes.Buffer, string) {
	t.Helper()
	out := &bytes.Buffer{}
	env := &cli.Env{StateDir: t.TempDir(), JSON: true, Stdout: out, Stderr: os.Stderr}
	if err := env.SaveEnrollment(&cli.Enrollment{
		Version: 1, State: "active", DeviceID: "dev-1", TenantID: "ten-1",
		DeviceToken: "tok", TokenExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	return env, out, t.TempDir()
}

func TestEnableNotEnrolled(t *testing.T) {
	env := &cli.Env{StateDir: t.TempDir(), Stdout: os.Stderr, Stderr: os.Stderr}
	err := Run(env, Options{Path: t.TempDir(), Home: t.TempDir()})
	var ee *cli.ExitError
	if !errors.As(err, &ee) || ee.Code != cli.ExitNotEnrolled {
		t.Fatalf("got %v, want exit 3", err)
	}
}

func TestEnableMissingPathIsUsage(t *testing.T) {
	env, _, home := enrolledEnv(t)
	err := Run(env, Options{Path: filepath.Join(t.TempDir(), "nope"), Home: home})
	var ee *cli.ExitError
	if !errors.As(err, &ee) || ee.Code != cli.ExitUsage {
		t.Fatalf("got %v, want exit 2 (§7.2 path missing)", err)
	}
}

func TestEnableWritesCanonicalAllowList(t *testing.T) {
	env, out, home := enrolledEnv(t)
	realRoot := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(realRoot, link); err != nil {
		t.Skip("no symlinks on this platform")
	}
	if err := Run(env, Options{Path: link, Home: home}); err != nil {
		t.Fatal(err)
	}
	var res Result
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	canon, _ := cli.CanonicalPath(realRoot)
	if res.Workspace != canon || !res.Changed {
		t.Fatalf("result %+v, want canonical %s", res, canon)
	}
	ws, err := env.LoadWorkspaces()
	if err != nil || len(ws.Workspaces) != 1 || ws.Workspaces[0].Path != canon {
		t.Fatalf("allow-list %+v %v", ws, err)
	}
	fi, _ := os.Stat(env.WorkspacesPath())
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("allow-list mode %o, want 0600", fi.Mode().Perm())
	}
	// The enable window is journaled (§7.2's CoverageTransition record).
	if _, err := os.Stat(env.CoveragePath()); err != nil {
		t.Fatalf("coverage journal: %v", err)
	}
}

func TestEnableIdempotent(t *testing.T) {
	env, out, home := enrolledEnv(t)
	root := t.TempDir()
	if err := Run(env, Options{Path: root, Home: home}); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := Run(env, Options{Path: root, Home: home}); err != nil {
		t.Fatal(err)
	}
	var res Result
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatalf("second enable stdout %q: %v", out.String(), err)
	}
	if res.Changed {
		t.Fatal("second enable reported a change; §7.2 requires a silent no-op")
	}
	ws, _ := env.LoadWorkspaces()
	if len(ws.Workspaces) != 1 {
		t.Fatalf("allow-list has %d entries after double enable", len(ws.Workspaces))
	}
}

func TestEnableMark1ignoreOptOut(t *testing.T) {
	env, _, home := enrolledEnv(t)
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".mark1ignore"), []byte("# opted out\n*\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := Run(env, Options{Path: root, Home: home})
	var ee *cli.ExitError
	if !errors.As(err, &ee) || ee.Code != cli.ExitRefused {
		t.Fatalf("got %v, want exit 4 (§7.2 opt-out)", err)
	}
	ws, _ := env.LoadWorkspaces()
	if len(ws.Workspaces) != 0 {
		t.Fatal("opted-out repo still landed in the allow-list")
	}
}

// claudeHome plants a real-shaped ~/.claude/settings.json in a fake home and
// returns both. The body carries a user key and the user's OWN Stop handler,
// because "we never rewrite a file we do not exclusively own" is only testable
// against a file that has something of theirs in it.
func claudeHome(t *testing.T) (home, settings string) {
	t.Helper()
	home = t.TempDir()
	settings = filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settings), 0o700); err != nil {
		t.Fatal(err)
	}
	const body = `{
  "model": "opus",
  "hooks": {
    "Stop": [
      { "matcher": "", "hooks": [ { "type": "command", "command": "/usr/bin/mine.sh" } ] }
    ]
  }
}
`
	if err := os.WriteFile(settings, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return home, settings
}

// TestEnableProvisionsClaudeCode is §7.2's "provisions agent config fragments
// per §8": the hooks actually land in the user's settings file, and the
// agent is named in agents_provisioned rather than assumed.
func TestEnableProvisionsClaudeCode(t *testing.T) {
	env, out, _ := enrolledEnv(t)
	home, settings := claudeHome(t)
	if err := Run(env, Options{Path: t.TempDir(), Home: home}); err != nil {
		t.Fatal(err)
	}
	var res Result
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if len(res.AgentsProvisioned) != 1 || res.AgentsProvisioned[0] != "claudecode" {
		t.Fatalf("agents_provisioned = %v, want [claudecode]", res.AgentsProvisioned)
	}
	b, err := os.ReadFile(settings)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "_mark1_managed") || !strings.Contains(string(b), "mark1-hookshim") {
		t.Fatalf("no fragment in the user's settings:\n%s", b)
	}
	if !strings.Contains(string(b), "/usr/bin/mine.sh") {
		t.Fatalf("the user's own handler did not survive:\n%s", b)
	}
	if _, err := os.Stat(claudecode.ManifestPath(env.StateDir)); err != nil {
		t.Fatalf("no §8.2 manifest under the CLI's state root: %v", err)
	}
}

// TestEnableReconcilesFragmentsOnRerun: §7.2 says re-running reconciles
// fragments. The old early-return on an already-listed workspace meant a user
// who ran `mark1 off` and then `mark1 enable` again got their allow-list entry
// back and no hooks — silently uninstrumented.
func TestEnableReconcilesFragmentsOnRerun(t *testing.T) {
	env, out, _ := enrolledEnv(t)
	home, settings := claudeHome(t)
	root := t.TempDir()
	if err := Run(env, Options{Path: root, Home: home}); err != nil {
		t.Fatal(err)
	}
	// Simulate `mark1 off`: the fragment is gone, the workspace is still listed.
	if _, err := claudecode.Revert(env.StateDir); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(settings); strings.Contains(string(b), "_mark1_managed") {
		t.Fatal("setup: revert left the fragment in place, so the re-apply proves nothing")
	}

	out.Reset()
	if err := Run(env, Options{Path: root, Home: home}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(settings)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "_mark1_managed") {
		t.Fatalf("re-enable did not reconcile the fragment:\n%s", b)
	}
	var res Result
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatalf("re-enable stdout %q: %v", out.String(), err)
	}
	if !res.Changed {
		t.Fatal("a re-enable that re-provisioned reported changed=false")
	}
}

// TestEnableReportsProvisioningRefusal: no settings.json is the common case
// for a user who never customized Claude Code. M1E-7101 is a refusal we
// surface, not a crash — and never an invented file.
func TestEnableReportsProvisioningRefusal(t *testing.T) {
	env, out, home := enrolledEnv(t)
	if err := Run(env, Options{Path: t.TempDir(), Home: home}); err != nil {
		t.Fatalf("a provisioning refusal failed the enable: %v", err)
	}
	var res Result
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if len(res.AgentsRefused) != 1 || res.AgentsRefused[0].Code != claudecode.CodeNoTarget {
		t.Fatalf("agents_refused = %+v, want one %s", res.AgentsRefused, claudecode.CodeNoTarget)
	}
	if len(res.AgentsProvisioned) != 0 {
		t.Fatalf("a refused agent was reported as provisioned: %v", res.AgentsProvisioned)
	}
	if _, err := os.Stat(filepath.Join(home, ".claude")); err == nil {
		t.Fatal("enable created the vendor's config dir")
	}
}
