package enable

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Omium-ai/omium-mark1/go/mark1/internal/cli"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/claudecode"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/codex"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/copilot"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/cursor"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/gemini"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/opencode"
)

// enrolledEnv also returns a FAKE home. Every Run below passes it: enable now
// writes an 08 §8 fragment into ~/.claude/settings.json, and a test that
// forgot the seam would edit the developer's own agent config.
func enrolledEnv(t *testing.T) (*cli.Env, *bytes.Buffer, string) {
	t.Helper()
	// Hermetic PATH: the developer's own `codex`/`gemini`/`opencode` must not be what enable detects.
	t.Setenv("PATH", t.TempDir())
	for _, v := range []string{"CODEX_HOME", "GEMINI_CLI_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "COPILOT_HOME", "COPILOT_PROVIDERS_CONFIG", "COPILOT_PROVIDER_BASE_URL", "COPILOT_PROVIDER_API_KEY"} {
		t.Setenv(v, "")
	}
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

// TestEnableRecordsConsentOnce is FR-CLI-002's "consent-recording": the first
// enable of a root appends one 0600 consent line naming the OS user, the root,
// the time, and the fragments provisioned in the same act; a re-run — silent
// no-op or fragment reconcile alike — appends nothing, because neither changes
// who consented to what.
func TestEnableRecordsConsentOnce(t *testing.T) {
	env, out, _ := enrolledEnv(t)
	home, _ := claudeHome(t)
	root := t.TempDir()
	if err := Run(env, Options{Path: root, Home: home}); err != nil {
		t.Fatal(err)
	}
	var res Result
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatal(err)
	}

	lines := func() [][]byte {
		b, err := os.ReadFile(env.ConsentPath())
		if err != nil {
			t.Fatalf("consent journal: %v", err)
		}
		return bytes.Split(bytes.TrimRight(b, "\n"), []byte("\n"))
	}
	got := lines()
	if len(got) != 1 {
		t.Fatalf("consent journal has %d lines after one enable, want 1:\n%s", len(got), got)
	}
	var c cli.Consent
	if err := json.Unmarshal(got[0], &c); err != nil {
		t.Fatalf("consent line %q: %v", got[0], err)
	}
	if _, err := time.Parse(time.RFC3339, c.TS); err != nil {
		t.Fatalf("ts %q: %v", c.TS, err)
	}
	if c.Workspace != res.Workspace {
		t.Fatalf("consent names %q, enable returned %q", c.Workspace, res.Workspace)
	}
	if len(c.AgentsProvisioned) != 1 || c.AgentsProvisioned[0] != "claudecode" {
		t.Fatalf("agents_provisioned = %v, want [claudecode]", c.AgentsProvisioned)
	}
	// The OS user is recorded when the platform can name one, and left absent
	// — never guessed from $USER — when it cannot.
	if u, err := user.Current(); err == nil && (c.User != u.Username || c.UID != u.Uid) {
		t.Fatalf("consent user %q/%q, want %q/%q", c.User, c.UID, u.Username, u.Uid)
	}
	fi, err := os.Stat(env.ConsentPath())
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("consent journal mode %o, want 0600", fi.Mode().Perm())
	}

	// Silent no-op re-run.
	if err := Run(env, Options{Path: root, Home: home}); err != nil {
		t.Fatal(err)
	}
	if got := lines(); len(got) != 1 {
		t.Fatalf("a no-op re-enable appended a consent line (%d lines)", len(got))
	}
	// Reconcile-after-off re-run: Changed is true, the root is not new.
	if _, err := claudecode.Revert(env.StateDir); err != nil {
		t.Fatal(err)
	}
	if err := Run(env, Options{Path: root, Home: home}); err != nil {
		t.Fatal(err)
	}
	if got := lines(); len(got) != 1 {
		t.Fatalf("a fragment-reconcile re-enable appended a consent line (%d lines)", len(got))
	}
}

// publishCandidates plants what mark1d would have written for root: two
// candidates, one already consented. Hand-built from
// go/mark1d/internal/anchors/candidates.go — the shape is copied, not imported.
func publishCandidates(t *testing.T, env *cli.Env, root string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(env.AnchorsCandidates()), 0o700); err != nil {
		t.Fatal(err)
	}
	body := `{"version":1,"workspaces":[{"path":` + strconv.Quote(root) + `,"anchors":[
{"id":"ruff@cat-1","tool":"ruff","argv":["/usr/bin/ruff","check","."],"binary_path":"/usr/bin/ruff","binary_hash":"aa","tool_version":"ruff 0.6.2","class":"fast","side_effect":"static","exec_hash":"1111","consented_at":"0001-01-01T00:00:00Z","consented":false},
{"id":"tsc@cat-1","tool":"tsc","argv":["/usr/bin/tsc","--noEmit"],"binary_path":"/usr/bin/tsc","binary_hash":"bb","tool_version":"5.5","class":"fast","side_effect":"static","exec_hash":"2222","consented_at":"2026-01-02T03:04:05Z","consented":true}
]}]}`
	if err := os.WriteFile(env.AnchorsCandidates(), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func approvalLines(t *testing.T, env *cli.Env) []cli.AnchorApproval {
	t.Helper()
	b, err := os.ReadFile(env.AnchorsApprovals())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var out []cli.AnchorApproval
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var a cli.AnchorApproval
		if err := json.Unmarshal([]byte(line), &a); err != nil {
			t.Fatalf("approvals line %q: %v", line, err)
		}
		out = append(out, a)
	}
	return out
}

// TestEnableAnchorsApprovesOnTTYOnly: consent is a human act at a terminal.
// --json or a piped stdin names the candidates and writes NO approval line;
// a terminal answering `y` writes one line per consent naming the exact
// exec_hash mark1d published; --anchors <id> consents non-interactively to
// exactly that id (08 §7.2) and refuses an id that is not a candidate.
func TestEnableAnchorsApprovesOnTTYOnly(t *testing.T) {
	root := t.TempDir()
	canon, _ := cli.CanonicalPath(root)

	t.Run("--json approves nothing and names the candidates", func(t *testing.T) {
		env, out, home := enrolledEnv(t)
		publishCandidates(t, env, canon)
		if err := Run(env, Options{Path: root, Home: home, Stdin: strings.NewReader("y\ny\n"), TTY: true}); err != nil {
			t.Fatal(err)
		}
		var res Result
		if err := json.Unmarshal(out.Bytes(), &res); err != nil {
			t.Fatal(err)
		}
		if len(res.AnchorsPending) != 1 || res.AnchorsPending[0] != "ruff@cat-1" {
			t.Fatalf("anchors_pending %v, want [ruff@cat-1]", res.AnchorsPending)
		}
		if len(res.AnchorsConsented) != 1 || res.AnchorsConsented[0] != "tsc@cat-1" {
			t.Fatalf("anchors_consented %v, want the already-consented [tsc@cat-1]", res.AnchorsConsented)
		}
		if lines := approvalLines(t, env); len(lines) != 0 {
			t.Fatalf("--json wrote approvals %+v; a script must not consent", lines)
		}
	})

	t.Run("piped stdin approves nothing", func(t *testing.T) {
		env, out, home := enrolledEnv(t)
		env.JSON = false
		publishCandidates(t, env, canon)
		if err := Run(env, Options{Path: root, Home: home, Stdin: strings.NewReader("y\n"), TTY: false}); err != nil {
			t.Fatal(err)
		}
		if lines := approvalLines(t, env); len(lines) != 0 {
			t.Fatalf("non-TTY wrote approvals %+v", lines)
		}
		if !strings.Contains(out.String(), "ruff@cat-1 NOT consented") || !strings.Contains(out.String(), "no terminal") {
			t.Fatalf("human output must name what was not consented and why:\n%s", out.String())
		}
	})

	t.Run("a terminal answering y writes the exact hash", func(t *testing.T) {
		env, out, home := enrolledEnv(t)
		env.JSON = false
		publishCandidates(t, env, canon)
		if err := Run(env, Options{Path: root, Home: home, Stdin: strings.NewReader("y\n"), TTY: true}); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "/usr/bin/ruff check .") || !strings.Contains(out.String(), "consent? [y/N]") {
			t.Fatalf("prompt must show the argv being consented to:\n%s", out.String())
		}
		lines := approvalLines(t, env)
		if len(lines) != 1 || lines[0].ID != "ruff@cat-1" || lines[0].ExecHash != "1111" || lines[0].Workspace != canon {
			t.Fatalf("approvals %+v, want one line for ruff@cat-1 under exec_hash 1111", lines)
		}
		if lines[0].TS == "" {
			t.Fatalf("approval %+v carries no timestamp", lines[0])
		}
		fi, err := os.Stat(env.AnchorsApprovals())
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
			t.Fatalf("approvals.jsonl mode %o, want 0600", fi.Mode().Perm())
		}
		// A terminal answering n (or nothing) writes nothing more.
		out.Reset()
		if err := os.Remove(env.AnchorsApprovals()); err != nil {
			t.Fatal(err)
		}
		if err := Run(env, Options{Path: root, Home: home, Stdin: strings.NewReader("n\n"), TTY: true}); err != nil {
			t.Fatal(err)
		}
		if lines := approvalLines(t, env); len(lines) != 0 {
			t.Fatalf("`n` wrote approvals %+v", lines)
		}
	})

	t.Run("--anchors names ids non-interactively; unknown id is usage", func(t *testing.T) {
		env, _, home := enrolledEnv(t)
		publishCandidates(t, env, canon)
		if err := Run(env, Options{Path: root, Home: home, Anchors: []string{"ruff@cat-1"}}); err != nil {
			t.Fatal(err)
		}
		lines := approvalLines(t, env)
		if len(lines) != 1 || lines[0].ExecHash != "1111" {
			t.Fatalf("approvals %+v, want ruff@cat-1 under 1111", lines)
		}
		err := Run(env, Options{Path: root, Home: home, Anchors: []string{"black@cat-9"}})
		var ee *cli.ExitError
		if !errors.As(err, &ee) || ee.Code != cli.ExitUsage {
			t.Fatalf("got %v, want exit 2 for an id that is not a candidate", err)
		}
		if lines := approvalLines(t, env); len(lines) != 1 {
			t.Fatalf("the refused --anchors still wrote: %+v", lines)
		}
	})

	t.Run("--no-anchors and an unpublished daemon offer nothing", func(t *testing.T) {
		env, out, home := enrolledEnv(t)
		if err := Run(env, Options{Path: root, Home: home, TTY: true, Stdin: strings.NewReader("y\n"), Socket: filepath.Join(t.TempDir(), "no.sock")}); err != nil {
			t.Fatal(err)
		}
		var res Result
		if err := json.Unmarshal(out.Bytes(), &res); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(res.AnchorsNote, "has not published") {
			t.Fatalf("anchors_note %q must say the daemon has not published, not read as nothing to consent", res.AnchorsNote)
		}
		out.Reset()
		publishCandidates(t, env, canon)
		if err := Run(env, Options{Path: root, Home: home, NoAnchors: true, TTY: true, Stdin: strings.NewReader("y\n")}); err != nil {
			t.Fatal(err)
		}
		if lines := approvalLines(t, env); len(lines) != 0 {
			t.Fatalf("--no-anchors wrote approvals %+v", lines)
		}
	})
}

// TestEnableStopGateWritesTheArtifactOnTTYOnly is FR-POLICY-006's CLI half:
// the opt-in that lets mark1d BLOCK is written only by a human at a terminal,
// byte-for-byte as fabric.OptInPath reads it; --json or piped stdin writes
// nothing and says stop_gate_pending; a re-run is idempotent; --no-stop-gate
// removes it; a plain re-enable never restores it and says so.
func TestEnableStopGateWritesTheArtifactOnTTYOnly(t *testing.T) {
	root := t.TempDir()
	optIn := func(env *cli.Env) string { return filepath.Join(env.StateDir, "gates", "opt-in.json") }

	t.Run("--json and piped stdin write nothing", func(t *testing.T) {
		env, out, home := enrolledEnv(t)
		if err := Run(env, Options{Path: root, Home: home, NoAnchors: true, StopGate: true, Stdin: strings.NewReader("y\n"), TTY: true}); err != nil {
			t.Fatal(err)
		}
		var res Result
		if err := json.Unmarshal(out.Bytes(), &res); err != nil {
			t.Fatal(err)
		}
		if !res.StopGatePending || res.StopGate.State != "not_opted_in" || !strings.Contains(res.StopGateNote, "no terminal") {
			t.Fatalf("--json result %+v, want stop_gate_pending and not_opted_in", res)
		}
		if _, err := os.Stat(optIn(env)); err == nil {
			t.Fatal("--json wrote the opt-in; a script must not arm blocking")
		}
		env.JSON = false
		if err := Run(env, Options{Path: root, Home: home, NoAnchors: true, StopGate: true, Stdin: strings.NewReader("y\n"), TTY: false}); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(optIn(env)); err == nil {
			t.Fatal("piped stdin wrote the opt-in")
		}
	})

	t.Run("a terminal answering y writes it; n does not", func(t *testing.T) {
		env, out, home := enrolledEnv(t)
		env.JSON = false
		if err := Run(env, Options{Path: root, Home: home, NoAnchors: true, StopGate: true, Stdin: strings.NewReader("n\n"), TTY: true}); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "opt in? [y/N]") || !strings.Contains(out.String(), "declined") {
			t.Fatalf("prompt and refusal must be visible:\n%s", out.String())
		}
		if _, err := os.Stat(optIn(env)); err == nil {
			t.Fatal("`n` wrote the opt-in")
		}
		out.Reset()
		if err := Run(env, Options{Path: root, Home: home, NoAnchors: true, StopGate: true, Stdin: strings.NewReader("y\n"), TTY: true}); err != nil {
			t.Fatal(err)
		}
		fi, err := os.Stat(optIn(env))
		if err != nil {
			t.Fatalf("no opt-in after y: %v", err)
		}
		if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
			t.Fatalf("opt-in mode %o, want 0600", fi.Mode().Perm())
		}
		// The exact shape mark1d's fabric.optedIn decodes: stop_gate true, ts, user.
		raw, _ := os.ReadFile(optIn(env))
		var a struct {
			StopGate bool   `json:"stop_gate"`
			TS       string `json:"ts"`
			User     string `json:"user"`
		}
		if err := json.Unmarshal(raw, &a); err != nil || !a.StopGate {
			t.Fatalf("opt-in %q: %v, want stop_gate true", raw, err)
		}
		if _, err := time.Parse(time.RFC3339, a.TS); err != nil {
			t.Fatalf("ts %q: %v", a.TS, err)
		}
		if u, err := user.Current(); err == nil && a.User != u.Username {
			t.Fatalf("user %q, want %q", a.User, u.Username)
		}
		if !strings.Contains(out.String(), "stop gate     opted_in (by "+a.User+" at "+a.TS+")") {
			t.Fatalf("human output must state the posture:\n%s", out.String())
		}
		// consent.jsonl carries the act: the enable line plus one stop_gate line.
		b, _ := os.ReadFile(env.ConsentPath())
		if n := strings.Count(string(b), `"stop_gate":true`); n != 1 {
			t.Fatalf("consent journal has %d stop_gate lines, want 1:\n%s", n, b)
		}

		// Idempotent: a second --stop-gate neither prompts nor rewrites.
		out.Reset()
		if err := Run(env, Options{Path: root, Home: home, NoAnchors: true, StopGate: true, Stdin: strings.NewReader("n\n"), TTY: true}); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out.String(), "opt in?") {
			t.Fatal("an opted-in install was prompted again")
		}
		if again, _ := os.ReadFile(optIn(env)); !bytes.Equal(again, raw) {
			t.Fatalf("re-run rewrote the artifact:\n%s\n%s", raw, again)
		}
		if b, _ := os.ReadFile(env.ConsentPath()); strings.Count(string(b), `"stop_gate":true`) != 1 {
			t.Fatal("re-run appended a second stop_gate consent line")
		}

		// --no-stop-gate removes it; a plain re-enable does not bring it back and says so.
		if err := Run(env, Options{Path: root, Home: home, NoAnchors: true, NoStopGate: true}); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(optIn(env)); err == nil {
			t.Fatal("--no-stop-gate left the opt-in in place")
		}
		env.JSON = true
		out.Reset()
		if err := Run(env, Options{Path: root, Home: home, NoAnchors: true, Stdin: strings.NewReader("y\n"), TTY: true}); err != nil {
			t.Fatal(err)
		}
		var res Result
		if err := json.Unmarshal(out.Bytes(), &res); err != nil {
			t.Fatal(err)
		}
		if res.StopGate.State != "not_opted_in" || res.StopGatePending || !strings.Contains(res.StopGateNote, "never restores") {
			t.Fatalf("plain re-enable %+v, want not_opted_in with the note", res)
		}
		if _, err := os.Stat(optIn(env)); err == nil {
			t.Fatal("a plain re-enable restored the opt-in")
		}
	})
}

// fakeCodex puts a `codex` answering --version on PATH and plants ~/.codex
// (with hooksBody as hooks.json when non-empty) under home.
func fakeCodex(t *testing.T, home, hooksBody string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell-script codex stub")
	}
	fakeBins(t, map[string]string{"codex": "codex-cli 0.154.0"})
	hooks := filepath.Join(home, ".codex", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(hooks), 0o700); err != nil {
		t.Fatal(err)
	}
	if hooksBody != "" {
		if err := os.WriteFile(hooks, []byte(hooksBody), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return hooks
}

const codexHooksBody = "{\n  \"description\": \"mine\",\n  \"hooks\": {\"PreToolUse\": [ {\"matcher\":\"shell\", \"hooks\": [ {\"type\":\"command\",\"command\":\"echo hi\"} ] } ]}\n}\n"

// TestEnableProvisionsCodexBesideClaudeCode: with `codex` on PATH the fenced
// entries land in ~/.codex/hooks.json next to the user's own handler, the
// manifest lands under the state root, and the trust note is printed.
func TestEnableProvisionsCodexBesideClaudeCode(t *testing.T) {
	env, out, _ := enrolledEnv(t)
	home, _ := claudeHome(t)
	hooks := fakeCodex(t, home, codexHooksBody)
	env.JSON = false
	if err := Run(env, Options{Path: t.TempDir(), Home: home, NoAnchors: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "provisioned   codex") || !strings.Contains(out.String(), "accept the hooks review") {
		t.Fatalf("human output must name codex and the trust step:\n%s", out.String())
	}
	b, err := os.ReadFile(hooks)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"_mark1"`) || !strings.Contains(string(b), "MARK1_AGENT=codex") || !strings.Contains(string(b), "echo hi") {
		t.Fatalf("hooks.json after enable:\n%s", b)
	}
	if _, err := os.Stat(codex.ManifestPath(env.StateDir)); err != nil {
		t.Fatalf("no codex manifest under the CLI's state root: %v", err)
	}
	env.JSON = true
	out.Reset()
	if err := Run(env, Options{Path: t.TempDir(), Home: home, NoAnchors: true}); err != nil {
		t.Fatal(err)
	}
	var res Result
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if strings.Join(res.AgentsProvisioned, ",") != "claudecode,codex" {
		t.Fatalf("agents_provisioned = %v", res.AgentsProvisioned)
	}
}

// TestEnableCodexOnlyWhenInstalled: mechanism A creates hooks.json, so an
// install without `codex` on PATH gets neither a file nor a refusal row.
func TestEnableCodexOnlyWhenInstalled(t *testing.T) {
	env, out, home := enrolledEnv(t)
	hooks := filepath.Join(home, ".codex", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(hooks), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := Run(env, Options{Path: t.TempDir(), Home: home, NoAnchors: true}); err != nil {
		t.Fatal(err)
	}
	var res Result
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	for _, r := range res.AgentsRefused {
		if r.Agent == "codex" {
			t.Fatalf("codex reported without being installed: %+v", res.AgentsRefused)
		}
	}
	if _, err := os.Stat(hooks); err == nil {
		t.Fatal("enable created hooks.json for an agent that is not installed")
	}

	// Installed but ~/.codex absent: the refusal is reported, never invented.
	env2, out2, home2 := enrolledEnv(t)
	fakeCodex(t, home2, "")
	if err := os.RemoveAll(filepath.Join(home2, ".codex")); err != nil {
		t.Fatal(err)
	}
	if err := Run(env2, Options{Path: t.TempDir(), Home: home2, NoAnchors: true}); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(out2.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range res.AgentsRefused {
		found = found || (r.Agent == "codex" && r.Code == codex.CodeNoTarget)
	}
	if !found {
		t.Fatalf("agents_refused = %+v, want codex %s", res.AgentsRefused, codex.CodeNoTarget)
	}
}

// TestEnableExplorationWritesTheSiblingField: D-EF's local half shares the
// artifact with the stop-gate opt-in and neither write drops the other.
func TestEnableExplorationWritesTheSiblingField(t *testing.T) {
	env, out, home := enrolledEnv(t)
	root := t.TempDir()
	env.JSON = false
	if err := Run(env, Options{Path: root, Home: home, NoAnchors: true, StopGate: true, Stdin: strings.NewReader("y\n"), TTY: true}); err != nil {
		t.Fatal(err)
	}
	env.JSON = true
	out.Reset()
	if err := Run(env, Options{Path: root, Home: home, NoAnchors: true, Exploration: true}); err != nil {
		t.Fatal(err)
	}
	var res Result
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.Exploration.State != "opted_in" || res.StopGate.State != "opted_in" || !strings.Contains(res.ExplorationNote, "signed bundle") {
		t.Fatalf("result %+v", res)
	}
	a := env.ReadOptIn()
	if !a.StopGate || !a.Exploration || a.TS == "" {
		t.Fatalf("artifact %+v, want both fields true", a)
	}
	if b, _ := os.ReadFile(env.ConsentPath()); strings.Count(string(b), `"exploration":true`) != 1 {
		t.Fatalf("consent journal must carry one exploration line:\n%s", b)
	}

	if err := Run(env, Options{Path: root, Home: home, NoAnchors: true, NoStopGate: true}); err != nil {
		t.Fatal(err)
	}
	if a := env.ReadOptIn(); a.StopGate || !a.Exploration {
		t.Fatalf("--no-stop-gate dropped the exploration sibling: %+v", a)
	}
	if err := Run(env, Options{Path: root, Home: home, NoAnchors: true, NoExploration: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(env.StopGateOptInPath()); err == nil {
		t.Fatal("artifact with neither opt-in must be removed")
	}
	out.Reset()
	if err := Run(env, Options{Path: root, Home: home, NoAnchors: true}); err != nil {
		t.Fatal(err)
	}
	var again Result
	if err := json.Unmarshal(out.Bytes(), &again); err != nil {
		t.Fatal(err)
	}
	if again.Exploration.State != "not_opted_in" || again.ExplorationNote != "" {
		t.Fatalf("plain re-enable %+v", again)
	}
}

// fakeBins prepends shell stubs answering --version to the hermetic PATH.
func fakeBins(t *testing.T, banners map[string]string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell-script stubs")
	}
	bin := t.TempDir()
	for name, banner := range banners {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\necho "+banner+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

const geminiSettingsBody = "{\n  \"theme\": \"mine\",\n  \"hooks\": {\"BeforeTool\": [ {\"matcher\":\"*\", \"hooks\": [ {\"type\":\"command\",\"command\":\"echo hi\"} ] } ]}\n}\n"

// geminiAndOpenCodeHomes plants ~/.gemini/settings.json (when body is non-empty) and the
// opencode config dir (when wantConfig) under home, and puts both binaries on PATH.
func geminiAndOpenCodeHomes(t *testing.T, home, body string, wantConfig bool) (settings, plugin string) {
	t.Helper()
	fakeBins(t, map[string]string{"gemini": "0.59.0", "opencode": "1.18.31"})
	settings = filepath.Join(home, ".gemini", "settings.json")
	if body != "" {
		if err := os.MkdirAll(filepath.Dir(settings), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(settings, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	plugin = filepath.Join(home, ".config", "opencode", "plugins", "mark1.js")
	if wantConfig {
		if err := os.MkdirAll(filepath.Dir(filepath.Dir(plugin)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return settings, plugin
}

// TestEnableProvisionsGeminiAndOpenCode: with both binaries on PATH the fenced
// entries land in ~/.gemini/settings.json beside the user's handler (B) and the
// owned plugin lands under the opencode config dir (A), each with its manifest.
func TestEnableProvisionsGeminiAndOpenCode(t *testing.T) {
	env, out, _ := enrolledEnv(t)
	home, _ := claudeHome(t)
	fakeCodex(t, home, codexHooksBody)
	settings, plugin := geminiAndOpenCodeHomes(t, home, geminiSettingsBody, true)
	root := t.TempDir()
	env.JSON = false
	if err := Run(env, Options{Path: root, Home: home, NoAnchors: true}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"provisioned   gemini", "provisioned   opencode", "restart any running opencode"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("human output lacks %q:\n%s", want, out.String())
		}
	}
	b, err := os.ReadFile(settings)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"_mark1"`) || !strings.Contains(string(b), `"MARK1_AGENT": "gemini"`) || !strings.Contains(string(b), "echo hi") {
		t.Fatalf("settings.json after enable:\n%s", b)
	}
	if p, err := os.ReadFile(plugin); err != nil || !strings.Contains(string(p), "mark1-hookshim") {
		t.Fatalf("plugin after enable (%v):\n%s", err, p)
	}
	for _, m := range []string{gemini.ManifestPath(env.StateDir), opencode.ManifestPath(env.StateDir)} {
		if _, err := os.Stat(m); err != nil {
			t.Fatalf("no manifest under the CLI's state root: %v", err)
		}
	}
	env.JSON = true
	out.Reset()
	if err := Run(env, Options{Path: root, Home: home, NoAnchors: true}); err != nil {
		t.Fatal(err)
	}
	var res Result
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if strings.Join(res.AgentsProvisioned, ",") != "claudecode,codex,gemini,opencode" || len(res.AgentsRefused) != 0 {
		t.Fatalf("agents_provisioned = %v refused = %+v", res.AgentsProvisioned, res.AgentsRefused)
	}
	if res.Changed {
		t.Fatal("a re-run over unchanged fragments reported changed=true")
	}
}

// TestEnableGeminiAndOpenCodeOnlyWhenInstalled: no binary, no row of either
// kind — and no plugin file planted for an agent the user does not run.
func TestEnableGeminiAndOpenCodeOnlyWhenInstalled(t *testing.T) {
	env, out, home := enrolledEnv(t)
	plugin := filepath.Join(home, ".config", "opencode", "plugins", "mark1.js")
	if err := os.MkdirAll(filepath.Dir(filepath.Dir(plugin)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := Run(env, Options{Path: t.TempDir(), Home: home, NoAnchors: true}); err != nil {
		t.Fatal(err)
	}
	var res Result
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	for _, r := range res.AgentsRefused {
		if r.Agent == "gemini" || r.Agent == "opencode" {
			t.Fatalf("%s reported without being installed: %+v", r.Agent, res.AgentsRefused)
		}
	}
	if _, err := os.Stat(plugin); err == nil {
		t.Fatal("enable planted the opencode plugin for an agent that is not installed")
	}
}

// TestEnableReportsGeminiAndOpenCodeRefusals: installed but unprovisionable is
// a refusal row with the adapter's code, never a failed enable — the workspace
// still lands and claudecode still provisions.
func TestEnableReportsGeminiAndOpenCodeRefusals(t *testing.T) {
	codes := func(t *testing.T, out *bytes.Buffer) map[string]Refusal {
		t.Helper()
		var res Result
		if err := json.Unmarshal(out.Bytes(), &res); err != nil {
			t.Fatal(err)
		}
		if strings.Join(res.AgentsProvisioned, ",") != "claudecode" {
			t.Fatalf("agents_provisioned = %v", res.AgentsProvisioned)
		}
		by := map[string]Refusal{}
		for _, r := range res.AgentsRefused {
			by[r.Agent] = r
		}
		return by
	}
	t.Run("absent settings and config dir", func(t *testing.T) {
		env, out, _ := enrolledEnv(t)
		home, _ := claudeHome(t)
		settings, plugin := geminiAndOpenCodeHomes(t, home, "", false)
		root := t.TempDir()
		if err := Run(env, Options{Path: root, Home: home, NoAnchors: true}); err != nil {
			t.Fatalf("a provisioning refusal failed the enable: %v", err)
		}
		by := codes(t, out)
		if by["gemini"].Code != gemini.CodeNoTarget || by["opencode"].Code != opencode.CodeNoTarget {
			t.Fatalf("agents_refused = %+v, want gemini and opencode %s", by, gemini.CodeNoTarget)
		}
		if _, err := os.Stat(settings); err == nil {
			t.Fatal("enable invented ~/.gemini/settings.json")
		}
		if _, err := os.Stat(filepath.Dir(filepath.Dir(plugin))); err == nil {
			t.Fatal("enable created the vendor's config dir")
		}
		ws, err := env.LoadWorkspaces()
		if err != nil || len(ws.Workspaces) != 1 {
			t.Fatalf("workspace not enabled: %v %+v", err, ws)
		}
	})
	t.Run("JSONC settings", func(t *testing.T) {
		env, out, _ := enrolledEnv(t)
		home, _ := claudeHome(t)
		settings, _ := geminiAndOpenCodeHomes(t, home, "// gemini tolerates comments\n"+geminiSettingsBody, false)
		if err := Run(env, Options{Path: t.TempDir(), Home: home, NoAnchors: true}); err != nil {
			t.Fatalf("a JSONC settings file crashed the enable: %v", err)
		}
		r, ok := codes(t, out)["gemini"]
		if !ok || r.Code != "" || !strings.Contains(r.Detail, "not strict JSON") {
			t.Fatalf("gemini refusal %+v, want a coded-empty parse refusal", r)
		}
		if b, _ := os.ReadFile(settings); !strings.HasPrefix(string(b), "// gemini") {
			t.Fatalf("the user's JSONC file was rewritten:\n%s", b)
		}
		if _, err := os.Stat(gemini.ManifestPath(env.StateDir)); err == nil {
			t.Fatal("a refused apply left a manifest behind")
		}
	})
}

const cursorHooksBody = "{\n  \"version\": 1,\n  \"hooks\": {\"preToolUse\": [ {\"command\": \"echo hi\", \"timeout\": 5} ]}\n}\n"

// copilotAndCursorHomes plants ~/.copilot (when wantCopilotHome) and ~/.cursor holding
// hooks.json (when body is non-empty; the dir alone when wantCursorDir) under home, and
// puts both binaries on PATH.
func copilotAndCursorHomes(t *testing.T, home, body string, wantCopilotHome, wantCursorDir bool) (copilotHooks, cursorHooks string) {
	t.Helper()
	fakeBins(t, map[string]string{"copilot": "1.0.85", "cursor-agent": "2026.09.10-fd3934a"})
	copilotHooks = filepath.Join(home, ".copilot", "hooks", "mark1.json")
	if wantCopilotHome {
		if err := os.MkdirAll(filepath.Dir(filepath.Dir(copilotHooks)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	cursorHooks = filepath.Join(home, ".cursor", "hooks.json")
	if wantCursorDir || body != "" {
		if err := os.MkdirAll(filepath.Dir(cursorHooks), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if body != "" {
		if err := os.WriteFile(cursorHooks, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return copilotHooks, cursorHooks
}

// TestEnableProvisionsCopilotAndCursor: with both binaries on PATH the owned hook
// file lands under ~/.copilot/hooks (A, `|| true` because the vendor fails closed)
// and the fenced entries land in ~/.cursor/hooks.json beside the user's (B), each
// with its manifest; with no BYOK env set the human output says the pointer is
// not eligible (covered separately: TestEnableProvisionsCopilotEnvPointer).
func TestEnableProvisionsCopilotAndCursor(t *testing.T) {
	env, out, _ := enrolledEnv(t)
	home, _ := claudeHome(t)
	copilotHooks, cursorHooks := copilotAndCursorHomes(t, home, cursorHooksBody, true, true)
	root := t.TempDir()
	env.JSON = false
	if err := Run(env, Options{Path: root, Home: home, NoAnchors: true}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"provisioned   copilot", "provisioned   cursor", "copilot BYOK pointer not provisioned (subscription regime, no BYOK key, or no proxy listening)"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("human output lacks %q:\n%s", want, out.String())
		}
	}
	b, err := os.ReadFile(copilotHooks)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "mark1-hookshim || true") || !strings.Contains(string(b), `"MARK1_AGENT": "copilot"`) {
		t.Fatalf("copilot hooks file after enable:\n%s", b)
	}
	c, err := os.ReadFile(cursorHooks)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(c), `"_mark1"`) || !strings.Contains(string(c), "mark1-hookshim cursor") || !strings.Contains(string(c), "echo hi") {
		t.Fatalf("cursor hooks.json after enable:\n%s", c)
	}
	for _, m := range []string{copilot.ManifestPath(env.StateDir), cursor.ManifestPath(env.StateDir)} {
		if _, err := os.Stat(m); err != nil {
			t.Fatalf("no manifest under the CLI's state root: %v", err)
		}
	}
	if m, err := cursor.LoadManifest(env.StateDir); err != nil || m.Mechanism != "B" {
		t.Fatalf("cursor manifest %+v %v, want mechanism B over an existing hooks.json", m, err)
	}
	env.JSON = true
	out.Reset()
	if err := Run(env, Options{Path: root, Home: home, NoAnchors: true}); err != nil {
		t.Fatal(err)
	}
	var res Result
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if strings.Join(res.AgentsProvisioned, ",") != "claudecode,copilot,cursor" || len(res.AgentsRefused) != 0 {
		t.Fatalf("agents_provisioned = %v refused = %+v", res.AgentsProvisioned, res.AgentsRefused)
	}
	if res.Changed {
		t.Fatal("a re-run over unchanged fragments reported changed=true")
	}

	// No hooks.json at all: cursor takes mechanism A and owns the file.
	env2, out2, _ := enrolledEnv(t)
	home2, _ := claudeHome(t)
	_, cursorHooks2 := copilotAndCursorHomes(t, home2, "", true, true)
	if err := Run(env2, Options{Path: t.TempDir(), Home: home2, NoAnchors: true}); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(out2.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if strings.Join(res.AgentsProvisioned, ",") != "claudecode,copilot,cursor" {
		t.Fatalf("agents_provisioned = %v", res.AgentsProvisioned)
	}
	if m, err := cursor.LoadManifest(env2.StateDir); err != nil || m.Mechanism != "A" {
		t.Fatalf("cursor manifest %+v %v, want mechanism A over an absent hooks.json", m, err)
	}
	if c, err := os.ReadFile(cursorHooks2); err != nil || !strings.Contains(string(c), `"version": 1`) {
		t.Fatalf("owned hooks.json (%v):\n%s", err, c)
	}
}

// TestEnableProvisionsCopilotEnvPointer: with an eligible BYOK credential and a
// live guard answering the published port, `mark1 enable` writes the owned
// pointer file, registers the key with the guard, prints the exact source line
// and the upstream-routing gap warning, and
// --json carries both copilot_pointer and copilot_source_line; a re-run over
// the unchanged pointer reports changed=false.
func TestEnableProvisionsCopilotEnvPointer(t *testing.T) {
	env, out, _ := enrolledEnv(t)
	home, _ := claudeHome(t)
	copilotAndCursorHomes(t, home, "", true, false)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"reason_code":"M1E-8001"}`))
	}))
	t.Cleanup(srv.Close)
	if err := os.WriteFile(filepath.Join(env.StateDir, "proxy.port"), []byte(strings.TrimPrefix(srv.URL, "http://127.0.0.1:")), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("COPILOT_PROVIDER_BASE_URL", "https://api.openai.com/v1")
	t.Setenv("COPILOT_PROVIDER_API_KEY", "sk-synth")

	root := t.TempDir()
	env.JSON = false
	if err := Run(env, Options{Path: root, Home: home, NoAnchors: true}); err != nil {
		t.Fatal(err)
	}
	target := copilot.EnvFilePath(env.StateDir, runtime.GOOS)
	wantLine := copilot.SourceLine(env.StateDir, runtime.GOOS)
	for _, want := range []string{
		"provisioned   copilot BYOK base URL -> mark1-proxy",
		"add this line to your shell profile: " + wantLine,
		"admits this BYOK key by fingerprint, but the sidecar forwards only to api.anthropic.com",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("human output lacks %q:\n%s", want, out.String())
		}
	}
	b, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "export COPILOT_PROVIDER_BASE_URL="+strconv.Quote(srv.URL)) {
		t.Fatalf("env pointer file: %s", b)
	}
	if _, err := os.Stat(copilot.EnvManifestPath(env.StateDir)); err != nil {
		t.Fatalf("no env-pointer manifest under the CLI's state root: %v", err)
	}
	if reg, err := os.ReadFile(filepath.Join(env.StateDir, "registry")); err != nil || !strings.HasPrefix(string(reg), "copilot ") {
		t.Fatalf("enable did not register the BYOK key with the guard: %q %v", reg, err)
	}

	env.JSON = true
	out.Reset()
	if err := Run(env, Options{Path: root, Home: home, NoAnchors: true}); err != nil {
		t.Fatal(err)
	}
	var res Result
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.CopilotPointer != "provisioned" || res.CopilotSourceLine != wantLine {
		t.Fatalf("copilot_pointer=%q copilot_source_line=%q, want provisioned / %q", res.CopilotPointer, res.CopilotSourceLine, wantLine)
	}
	if res.Changed {
		t.Fatal("a re-run over an unchanged pointer reported changed=true")
	}
}

// TestEnableCopilotAndCursorOnlyWhenInstalled: no binary, no row of either kind,
// and no owned file planted for an agent the user does not run.
func TestEnableCopilotAndCursorOnlyWhenInstalled(t *testing.T) {
	env, out, home := enrolledEnv(t)
	copilotHooks := filepath.Join(home, ".copilot", "hooks", "mark1.json")
	cursorHooks := filepath.Join(home, ".cursor", "hooks.json")
	for _, d := range []string{filepath.Dir(filepath.Dir(copilotHooks)), filepath.Dir(cursorHooks)} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := Run(env, Options{Path: t.TempDir(), Home: home, NoAnchors: true}); err != nil {
		t.Fatal(err)
	}
	var res Result
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	for _, r := range res.AgentsRefused {
		if r.Agent == "copilot" || r.Agent == "cursor" {
			t.Fatalf("%s reported without being installed: %+v", r.Agent, res.AgentsRefused)
		}
	}
	for _, f := range []string{copilotHooks, cursorHooks} {
		if _, err := os.Stat(f); err == nil {
			t.Fatalf("enable planted %s for an agent that is not installed", f)
		}
	}
}

// TestEnableReportsCopilotAndCursorRefusals: installed but unprovisionable is a
// refusal row with the adapter's code, never a failed enable — the workspace
// still lands and claudecode still provisions.
func TestEnableReportsCopilotAndCursorRefusals(t *testing.T) {
	codes := func(t *testing.T, out *bytes.Buffer) map[string]Refusal {
		t.Helper()
		var res Result
		if err := json.Unmarshal(out.Bytes(), &res); err != nil {
			t.Fatal(err)
		}
		if strings.Join(res.AgentsProvisioned, ",") != "claudecode" {
			t.Fatalf("agents_provisioned = %v", res.AgentsProvisioned)
		}
		by := map[string]Refusal{}
		for _, r := range res.AgentsRefused {
			by[r.Agent] = r
		}
		return by
	}
	t.Run("absent vendor dirs", func(t *testing.T) {
		env, out, _ := enrolledEnv(t)
		home, _ := claudeHome(t)
		copilotHooks, cursorHooks := copilotAndCursorHomes(t, home, "", false, false)
		if err := Run(env, Options{Path: t.TempDir(), Home: home, NoAnchors: true}); err != nil {
			t.Fatalf("a provisioning refusal failed the enable: %v", err)
		}
		by := codes(t, out)
		if by["copilot"].Code != copilot.CodeNoTarget || by["cursor"].Code != cursor.CodeNoTarget {
			t.Fatalf("agents_refused = %+v, want copilot and cursor %s", by, copilot.CodeNoTarget)
		}
		for _, d := range []string{filepath.Dir(filepath.Dir(copilotHooks)), filepath.Dir(cursorHooks)} {
			if _, err := os.Stat(d); err == nil {
				t.Fatalf("enable created the vendor's config dir %s", d)
			}
		}
		for _, m := range []string{copilot.ManifestPath(env.StateDir), cursor.ManifestPath(env.StateDir)} {
			if _, err := os.Stat(m); err == nil {
				t.Fatalf("a refused apply left %s behind", m)
			}
		}
		ws, err := env.LoadWorkspaces()
		if err != nil || len(ws.Workspaces) != 1 {
			t.Fatalf("workspace not enabled: %v %+v", err, ws)
		}
	})
	t.Run("duplicate key in cursor hooks.json", func(t *testing.T) {
		env, out, _ := enrolledEnv(t)
		home, _ := claudeHome(t)
		const dup = `{"version":1,"hooks":{},"hooks":{}}`
		_, cursorHooks := copilotAndCursorHomes(t, home, dup, false, true)
		if err := Run(env, Options{Path: t.TempDir(), Home: home, NoAnchors: true}); err != nil {
			t.Fatalf("a duplicate-key hooks.json failed the enable: %v", err)
		}
		if r := codes(t, out)["cursor"]; r.Code != cursor.CodeDuplicateKey {
			t.Fatalf("cursor refusal %+v, want %s", r, cursor.CodeDuplicateKey)
		}
		if b, _ := os.ReadFile(cursorHooks); string(b) != dup {
			t.Fatalf("the user's hooks.json was rewritten:\n%s", b)
		}
	})
}
