package enable

import (
	"bytes"
	"encoding/json"
	"errors"
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
