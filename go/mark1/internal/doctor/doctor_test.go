package doctor

import (
	"bytes"
	"encoding/json"
	"errors"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
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

func enrolledEnv(t *testing.T) (*cli.Env, *bytes.Buffer) {
	t.Helper()
	// Hermetic PATH: the developer's own `claude`/`codex`/`gemini`/`opencode` must not be what doctor sniffs.
	t.Setenv("PATH", t.TempDir())
	for _, v := range []string{"CODEX_HOME", "GEMINI_CLI_HOME", "GEMINI_API_KEY", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "COPILOT_HOME", "COPILOT_PROVIDERS_CONFIG", "COPILOT_PROVIDER_BASE_URL", "COPILOT_PROVIDER_API_KEY"} {
		t.Setenv(v, "")
	}
	out := &bytes.Buffer{}
	stateDir := t.TempDir()
	// t.TempDir is 0700 already; assert rather than assume, since the
	// state_dir health check keys on it.
	if err := os.Chmod(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	env := &cli.Env{StateDir: stateDir, JSON: true, Stdout: out, Stderr: os.Stderr}
	if err := env.SaveEnrollment(&cli.Enrollment{
		Version: 1, State: "active", DeviceID: "dev-1",
		DeviceToken: "tok", TokenExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	return env, out
}

// noRetention points the retention probe at an absent file so a developer's
// real ~/.claude/settings.json cannot sway these tests.
func noRetention(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "absent-settings.json")
}

func TestDoctorNotEnrolled(t *testing.T) {
	env := &cli.Env{StateDir: t.TempDir(), Stdout: os.Stderr, Stderr: os.Stderr}
	err := Run(env, Options{})
	var ee *cli.ExitError
	if !errors.As(err, &ee) || ee.Code != cli.ExitNotEnrolled {
		t.Fatalf("got %v, want exit 3", err)
	}
}

func TestDoctorAllGreen(t *testing.T) {
	env, out := enrolledEnv(t)
	if err := Run(env, Options{ClaudeSettings: noRetention(t), Socket: filepath.Join(t.TempDir(), "no.sock")}); err != nil {
		t.Fatal(err)
	}
	var rep Report
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("report %+v", rep)
	}
}

func TestDoctorFailsOnLooseStateDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits do not exist here; owner-only on Windows is an ACL, which nothing in the daemon sets yet — NFR-SECURITY-007 residual")
	}
	env, out := enrolledEnv(t)
	if err := os.Chmod(env.StateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	err := Run(env, Options{ClaudeSettings: noRetention(t), Socket: filepath.Join(t.TempDir(), "no.sock")})
	var ee *cli.ExitError
	if !errors.As(err, &ee) || ee.Code != cli.ExitRuntime || !ee.Emitted {
		t.Fatalf("got %v, want emitted exit 1 (CI-friendly)", err)
	}
	var rep Report
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("stdout %q: %v", out.String(), err)
	}
	if rep.OK {
		t.Fatal("0755 state dir reported green")
	}
}

// provision applies a real fragment to a real settings file under env's state
// root and returns the target path. It fails loudly if nothing was written —
// a doctor test whose fixture was never provisioned would classify an absence
// and pass while proving nothing.
func provision(t *testing.T, env *cli.Env) string {
	t.Helper()
	target := filepath.Join(t.TempDir(), "settings.json")
	const body = `{
  "model": "opus",
  "hooks": {
    "Stop": [
      { "matcher": "", "hooks": [ { "type": "command", "command": "/usr/bin/mine.sh" } ] }
    ]
  }
}
`
	if err := os.WriteFile(target, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := claudecode.ApplyFragment(target, env.StateDir, "")
	if err != nil || !res.Changed {
		t.Fatalf("setup apply: %v %+v", err, res)
	}
	return target
}

func runDoctor(t *testing.T, env *cli.Env, out *bytes.Buffer, opts Options) (Report, error) {
	t.Helper()
	out.Reset()
	opts.ClaudeSettings = noRetention(t)
	opts.Socket = filepath.Join(t.TempDir(), "no.sock")
	err := Run(env, opts)
	var rep Report
	if uerr := json.Unmarshal(out.Bytes(), &rep); uerr != nil {
		t.Fatalf("doctor emitted no JSON report: %v\n%s", uerr, out.Bytes())
	}
	return rep, err
}

// TestDoctorClassifiesFragmentStates walks §7.4's vocabulary through the CLI,
// including the part a state word alone cannot carry: the provisioned lines,
// byte for byte, so a user can diff what we wrote without opening their file.
func TestDoctorClassifiesFragmentStates(t *testing.T) {
	t.Run("OK with every provisioned line", func(t *testing.T) {
		env, out := enrolledEnv(t)
		provision(t, env)
		rep, err := runDoctor(t, env, out, Options{})
		if err != nil {
			t.Fatalf("a healthy fragment failed doctor: %v", err)
		}
		if len(rep.Fragments) != 1 || rep.Fragments[0].State != "OK" {
			t.Fatalf("fragments %+v", rep.Fragments)
		}
		if len(rep.Fragments[0].Lines) == 0 {
			t.Fatal("doctor showed no provisioned lines; FR-AGENT-003 wants every one")
		}
		for _, l := range rep.Fragments[0].Lines {
			if l.Pointer == "" || l.Value == "" {
				t.Fatalf("empty line row: %+v", l)
			}
		}
	})

	t.Run("MISSING when the target is gone", func(t *testing.T) {
		env, out := enrolledEnv(t)
		target := provision(t, env)
		if err := os.Remove(target); err != nil {
			t.Fatal(err)
		}
		rep, err := runDoctor(t, env, out, Options{})
		var ee *cli.ExitError
		if !errors.As(err, &ee) || ee.Code != cli.ExitRuntime {
			t.Fatalf("got %v, want exit 1 (§7.4: any MISSING fails)", err)
		}
		if len(rep.Fragments) != 1 || rep.Fragments[0].State != "MISSING" {
			t.Fatalf("fragments %+v", rep.Fragments)
		}
	})

	t.Run("FRAGMENT-DAMAGED on a hand edit inside our markers", func(t *testing.T) {
		env, out := enrolledEnv(t)
		damage(t, provision(t, env))
		rep, err := runDoctor(t, env, out, Options{})
		if err == nil {
			t.Fatal("a damaged fragment passed doctor")
		}
		if len(rep.Fragments) != 1 || rep.Fragments[0].State != "FRAGMENT-DAMAGED" {
			t.Fatalf("fragments %+v", rep.Fragments)
		}
	})

	t.Run("no manifest means no row, not a failure", func(t *testing.T) {
		env, out := enrolledEnv(t)
		rep, err := runDoctor(t, env, out, Options{})
		if err != nil {
			t.Fatalf("doctor before any enable: %v", err)
		}
		if len(rep.Fragments) != 0 {
			t.Fatalf("fragments %+v, want none", rep.Fragments)
		}
	})
}

// provisionBaseURL applies the real proxy-pointer fragment. It calls
// ApplyBaseURL rather than ApplyProxyPointer deliberately: the eligibility gate
// wants a detected API-key credential and a live proxy answering the guard
// probe, neither of which a doctor test has, and neither of which changes a
// single byte of what lands in the file.
func provisionBaseURL(t *testing.T, env *cli.Env, target string) string {
	t.Helper()
	if target == "" {
		target = filepath.Join(t.TempDir(), "settings.json")
		if err := os.WriteFile(target, []byte(`{"model": "opus"}`+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	res, err := claudecode.ApplyBaseURL(target, env.StateDir, "http://127.0.0.1:41234", "claudecode")
	if err != nil || !res.Changed {
		t.Fatalf("setup base-URL apply: %v %+v", err, res)
	}
	return target
}

func anchorRow(t *testing.T, rep Report, id string) Anchor {
	t.Helper()
	for _, a := range rep.Anchors {
		if a.ID == id {
			return a
		}
	}
	t.Fatalf("no anchor %q among %+v", id, rep.Anchors)
	return Anchor{}
}

// TestDoctorReadsTheDaemonsCatalogFormat closes the bug two mappers found
// independently: doctor's reader expected {"anchors":[...]}, but the daemon
// (go/mark1d/internal/anchors/consent.go) writes {"version":1,"entries":[...]}
// with per-entry consented_at. The two formats never met, so `mark1 doctor`
// rendered an empty anchor list forever and nothing noticed.
func TestDoctorReadsTheDaemonsCatalogFormat(t *testing.T) {
	t.Run("the daemon's real format", func(t *testing.T) {
		env, out := enrolledEnv(t)
		if err := os.MkdirAll(filepath.Dir(env.AnchorsCatalog()), 0o700); err != nil {
			t.Fatal(err)
		}
		// Hand-built from consent.go:22-25 (consentFile: version, entries) and
		// consent.go:30-41 (ConsentRecord's JSON tags: id, tool, argv,
		// binary_path, binary_hash, tool_version, class, side_effect,
		// exec_hash, consented_at). No import of mark1d — the shape is
		// copied, not referenced.
		//
		// Two entries: a1 carries a consented_at, a2 does not. Both are
		// consented — LoadConsent's rule is that presence in the store IS
		// consent (Approve/Revoke only ever add or remove whole records,
		// never half-write one), so a reader that derives Consented from
		// "has a timestamp" instead of "is in the array" must fail a2.
		const body = `{
  "version": 1,
  "entries": [
    {
      "id": "a1",
      "tool": "git",
      "argv": ["status"],
      "binary_path": "/usr/bin/git",
      "binary_hash": "aa",
      "tool_version": "2.40.0",
      "class": "fast",
      "side_effect": "static",
      "exec_hash": "bb",
      "consented_at": "2026-01-02T03:04:05Z"
    },
    {
      "id": "a2",
      "tool": "make",
      "argv": ["build"],
      "binary_path": "/usr/bin/make",
      "binary_hash": "cc",
      "tool_version": "4.3",
      "class": "slow",
      "side_effect": "test",
      "exec_hash": "dd"
    }
  ]
}`
		if err := os.WriteFile(env.AnchorsCatalog(), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}

		rep, err := runDoctor(t, env, out, Options{})
		if err != nil {
			t.Fatalf("a valid catalog failed doctor: %v\n%+v", err, rep)
		}
		if len(rep.Anchors) != 2 {
			t.Fatalf("anchors %+v, want 2", rep.Anchors)
		}

		a1 := anchorRow(t, rep, "a1")
		wantA1 := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
		if !a1.Consented || !a1.ConsentedAt.Equal(wantA1) || a1.State != "" {
			t.Fatalf("a1 %+v, want consented=true consented_at=%s state=\"\"", a1, wantA1)
		}

		a2 := anchorRow(t, rep, "a2")
		if !a2.Consented {
			t.Fatalf("a2 %+v, want consented — presence in the store is the daemon's whole meaning of consent, a missing timestamp does not undo it", a2)
		}
		if !a2.ConsentedAt.IsZero() {
			t.Fatalf("a2 %+v, want zero consented_at (fixture omits it)", a2)
		}

		// The human render must carry the same two facts, not just the JSON.
		var buf bytes.Buffer
		renderHuman(&buf, &rep)
		human := buf.String()
		if !strings.Contains(human, "anchor        a1 consented=true") || !strings.Contains(human, "2026-01-02T03:04:05Z") {
			t.Fatalf("human render missing a1's consent/timestamp:\n%s", human)
		}
		if !strings.Contains(human, "anchor        a2 consented=true") {
			t.Fatalf("human render missing a2's consent:\n%s", human)
		}
	})

	t.Run("the bug's own fixture: the old {\"anchors\":[...]} shape", func(t *testing.T) {
		env, out := enrolledEnv(t)
		if err := os.MkdirAll(filepath.Dir(env.AnchorsCatalog()), 0o700); err != nil {
			t.Fatal(err)
		}
		const oldBody = `{"anchors":[{"id":"x","consented":true,"state":"ok"}]}`
		if err := os.WriteFile(env.AnchorsCatalog(), []byte(oldBody), 0o600); err != nil {
			t.Fatal(err)
		}

		rep, err := runDoctor(t, env, out, Options{})
		var ee *cli.ExitError
		if !errors.As(err, &ee) || ee.Code != cli.ExitRuntime {
			t.Fatalf("got %v, want exit 1 — the old shape has no version the reader recognises", err)
		}
		if len(rep.Anchors) != 0 {
			t.Fatalf("anchors %+v, want none: the old shape has no \"entries\" key the daemon writes", rep.Anchors)
		}
		found := false
		for _, c := range rep.Health {
			if c.Name == "anchors_catalog_version" {
				found = true
				if c.OK {
					t.Fatalf("finding %+v, want OK=false", c)
				}
				if !strings.Contains(c.Detail, "version 0") {
					t.Fatalf("detail %q does not name the bad version", c.Detail)
				}
			}
		}
		if !found {
			t.Fatalf("health %+v, want an anchors_catalog_version finding — an empty anchor list must be named, not silent (that silence is the bug)", rep.Health)
		}
	})
}

func fragmentRow(t *testing.T, rep Report, name string) Fragment {
	t.Helper()
	for _, f := range rep.Fragments {
		if f.Fragment == name {
			return f
		}
	}
	t.Fatalf("no %q row among %+v", name, rep.Fragments)
	return Fragment{}
}

// TestDoctorClassifiesTheBaseURLFragment closes D-CM. The base-URL fragment
// writes its own §8.2 manifest beside the hooks one, and doctor globs
// `provisioned/*/*.manifest.json` — so before this, provisioning the proxy
// pointer made `mark1 doctor` exit non-zero with "no adapter in this build can
// classify or revert this fragment" about a fragment this build had just
// written. The state assertions below are what separate a real classifier from
// a widened skip list: a skip alone would make every base-URL fragment silently
// invisible, including the one state that is a legal exposure.
func TestDoctorClassifiesTheBaseURLFragment(t *testing.T) {
	t.Run("a freshly provisioned pointer is OK, not an unclassifiable manifest", func(t *testing.T) {
		env, out := enrolledEnv(t)
		provisionBaseURL(t, env, "")
		rep, err := runDoctor(t, env, out, Options{})
		if err != nil {
			t.Fatalf("doctor failed on a fragment this build wrote: %v\n%+v", err, rep.Fragments)
		}
		f := fragmentRow(t, rep, "baseurl")
		if f.State != "OK" || f.Mechanism != "B" {
			t.Fatalf("row %+v", f)
		}
		if len(f.Lines) != 2 {
			t.Fatalf("FR-AGENT-003 wants both provisioned env lines, got %+v", f.Lines)
		}
		for _, l := range f.Lines {
			if !strings.Contains(l.Value, "127.0.0.1:41234") && !strings.Contains(l.Value, "M1-Cred-Ref") {
				t.Fatalf("line %+v shows neither the URL we wrote nor the cred-ref header", l)
			}
		}
	})

	t.Run("both fragments in one settings file stay green", func(t *testing.T) {
		env, out := enrolledEnv(t)
		provisionBaseURL(t, env, provision(t, env))
		rep, err := runDoctor(t, env, out, Options{})
		if err != nil {
			t.Fatalf("the ordinary two-fragment install failed doctor: %v\n%+v", err, rep.Fragments)
		}
		if len(rep.Fragments) != 2 {
			t.Fatalf("fragments %+v, want one row each", rep.Fragments)
		}
		// The hooks apply rewrote the file after the base-URL post-image was
		// recorded, so USER-EDITED here is correct and healthy — our own bytes
		// are checksum-verified intact. Only OK and USER-EDITED may pass.
		if s := fragmentRow(t, rep, "baseurl").State; s != "OK" && s != "USER-EDITED" {
			t.Fatalf("base-URL row is %s after the hooks fragment landed in the same file", s)
		}
	})

	t.Run("a standing pointer with our checksum object deleted is DAMAGED and named", func(t *testing.T) {
		env, out := enrolledEnv(t)
		target := provisionBaseURL(t, env, "")
		var root map[string]json.RawMessage
		b, err := os.ReadFile(target)
		if err != nil || json.Unmarshal(b, &root) != nil {
			t.Fatalf("read back %v", err)
		}
		if _, ok := root["_mark1_managed_baseurl"]; !ok {
			t.Fatalf("fixture drift: no checksum object to delete in\n%s", b)
		}
		delete(root, "_mark1_managed_baseurl")
		b, _ = json.Marshal(root)
		if err := os.WriteFile(target, b, 0o600); err != nil {
			t.Fatal(err)
		}

		rep, err := runDoctor(t, env, out, Options{})
		if err == nil {
			t.Fatal("doctor passed a machine whose agent is still pointed at a loopback port with nothing owning the pointer")
		}
		f := fragmentRow(t, rep, "baseurl")
		if f.State != "FRAGMENT-DAMAGED" {
			t.Fatalf("row %+v, want FRAGMENT-DAMAGED (D-CR: a live pointer is not absence)", f)
		}
		if !strings.Contains(f.Detail, "ANTHROPIC_BASE_URL") {
			t.Fatalf("detail %q does not name what is still set", f.Detail)
		}
	})

	t.Run("--fix reports the remedy instead of re-pointing the agent", func(t *testing.T) {
		env, out := enrolledEnv(t)
		target := provisionBaseURL(t, env, "")
		if err := os.Remove(target); err != nil {
			t.Fatal(err)
		}
		rep, err := runDoctor(t, env, out, Options{Fix: true})
		if err == nil {
			t.Fatal("--fix reported green over a fragment it cannot repair")
		}
		f := fragmentRow(t, rep, "baseurl")
		if f.Fixed {
			t.Fatalf("--fix re-pointed an agent at the proxy without an eligibility check: %+v", f)
		}
		if !strings.Contains(f.Detail, "mark1 enable") {
			t.Fatalf("detail %q leaves the user with no next step", f.Detail)
		}
		if _, err := os.Stat(target); !os.IsNotExist(err) {
			t.Fatalf("--fix created the user's settings file: %v", err)
		}
	})
}

// damage edits a byte INSIDE our fence — the timeout of the Stop gate.
func damage(t *testing.T, target string) {
	t.Helper()
	b, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(b), `"timeout": 30`, `"timeout": 90`, 1)
	if edited == string(b) {
		t.Fatal("fixture drift: nothing inside the fence to edit")
	}
	if err := os.WriteFile(target, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestDoctorListsEveryAgentSlot: one of 08 §5's seven adapters (crush) is declared
// and unbuilt. Doctor says so out loud — its user must not have to infer it from
// an empty fragment list.
func TestDoctorListsEveryAgentSlot(t *testing.T) {
	env, out := enrolledEnv(t)
	rep, err := runDoctor(t, env, out, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Agents) != 7 {
		t.Fatalf("%d agent slots, want 08 §5's seven: %+v", len(rep.Agents), rep.Agents)
	}
	want := map[string]string{"claudecode": "B", "codex": "A/B", "gemini": "B", "opencode": "A", "copilot": "A", "cursor": "A/B"}
	built := map[string]string{}
	for _, a := range rep.Agents {
		if a.Implemented {
			built[a.Name] = a.Mechanism
		} else if a.Mechanism != "" {
			t.Fatalf("slot %s claims mechanism %q with no code behind it", a.Name, a.Mechanism)
		}
	}
	if !maps.Equal(built, want) {
		t.Fatalf("implemented adapters %v, want %v", built, want)
	}
}

func TestDoctorRetentionWarning(t *testing.T) {
	env, out := enrolledEnv(t)
	settings := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(settings, []byte(`{"cleanupPeriodDays": 5}`), 0o600); err != nil {
		t.Fatal(err)
	}
	err := Run(env, Options{ClaudeSettings: settings, Socket: filepath.Join(t.TempDir(), "no.sock")})
	var ee *cli.ExitError
	if !errors.As(err, &ee) || ee.Code != cli.ExitRuntime {
		t.Fatalf("got %v, want exit 1 (retention below catch-up horizon)", err)
	}
	var rep Report
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("stdout %q: %v", out.String(), err)
	}
	found := false
	for _, c := range rep.Health {
		if c.Name == "transcript_retention" && !c.OK {
			found = true
		}
	}
	if !found {
		t.Fatalf("health %+v", rep.Health)
	}
}

// TestDoctorFixRepairsOnlyWhatItMayTouch is the whole --fix contract in one
// test: a damaged fragment is rewritten, and the user's bytes outside our
// pointers come through unchanged. §8.3(d) makes this the ONLY path that may
// overwrite a fragment a human has touched.
func TestDoctorFixRepairsOnlyWhatItMayTouch(t *testing.T) {
	env, out := enrolledEnv(t)
	target := provision(t, env)
	damage(t, target)

	rep, err := runDoctor(t, env, out, Options{Fix: true})
	if err != nil {
		t.Fatalf("--fix left the report red: %v", err)
	}
	if len(rep.Fragments) != 1 || rep.Fragments[0].State != "OK" || !rep.Fragments[0].Fixed {
		t.Fatalf("fragments %+v", rep.Fragments)
	}
	b, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "/usr/bin/mine.sh") || !strings.Contains(string(b), `"opus"`) {
		t.Fatalf("--fix ate the user's own settings:\n%s", b)
	}
	if strings.Contains(string(b), `"timeout": 90`) {
		t.Fatalf("--fix left the hand edit inside our fence:\n%s", b)
	}
}

// TestDoctorFixLeavesAHealthyFragmentAlone: --fix is not a re-provision. A
// user-edited-elsewhere file is healthy, and rewriting it would be the silent
// overwrite the design refuses.
func TestDoctorFixLeavesAHealthyFragmentAlone(t *testing.T) {
	env, out := enrolledEnv(t)
	target := provision(t, env)
	before, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := runDoctor(t, env, out, Options{Fix: true})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Fragments[0].Fixed {
		t.Fatalf("--fix rewrote a healthy fragment: %+v", rep.Fragments[0])
	}
	after, _ := os.ReadFile(target)
	if !bytes.Equal(before, after) {
		t.Fatalf("--fix changed a healthy file:\n--- before\n%s\n--- after\n%s", before, after)
	}
}

func healthRow(t *testing.T, rep Report, name string) Check {
	t.Helper()
	for _, c := range rep.Health {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no %q check among %+v", name, rep.Health)
	return Check{}
}

// TestDoctorListsCandidatesWithState is FR-CLI-004's "anchor catalog matches
// consent store" clause: doctor joins mark1d's candidates.json against
// catalog.json and states every row — consented, pending (never consented),
// drifted (consented under another exec_hash) and stale (consented, no longer
// derivable). An absent candidates file is named as "not published", never
// rendered as an empty list.
func TestDoctorListsCandidatesWithState(t *testing.T) {
	env, out := enrolledEnv(t)
	if err := os.MkdirAll(filepath.Dir(env.AnchorsCatalog()), 0o700); err != nil {
		t.Fatal(err)
	}
	// Store: tsc consented under 2222 (matches), ruff under 9999 (drifted),
	// black under 3333 (no longer derivable anywhere: stale).
	const store = `{"version":1,"entries":[
{"id":"black@cat-1","tool":"black","argv":["x"],"binary_path":"/b","binary_hash":"c","tool_version":"1","class":"fast","side_effect":"static","exec_hash":"3333","consented_at":"2026-01-03T00:00:00Z"},
{"id":"ruff@cat-1","tool":"ruff","argv":["x"],"binary_path":"/r","binary_hash":"a","tool_version":"0.5","class":"fast","side_effect":"static","exec_hash":"9999","consented_at":"2026-01-01T00:00:00Z"},
{"id":"tsc@cat-1","tool":"tsc","argv":["x"],"binary_path":"/t","binary_hash":"b","tool_version":"5.5","class":"fast","side_effect":"static","exec_hash":"2222","consented_at":"2026-01-02T03:04:05Z"}
]}`
	if err := os.WriteFile(env.AnchorsCatalog(), []byte(store), 0o600); err != nil {
		t.Fatal(err)
	}

	rep, err := runDoctor(t, env, out, Options{})
	if err != nil {
		t.Fatalf("doctor failed with the store alone: %v\n%+v", err, rep)
	}
	if c := healthRow(t, rep, "anchor_candidates"); !c.OK || !strings.Contains(c.Detail, "not published") {
		t.Fatalf("anchor_candidates %+v, want OK with 'not published'", c)
	}
	if len(rep.Anchors) != 3 {
		t.Fatalf("store-only rows %+v, want the 3 consented entries", rep.Anchors)
	}
	var buf bytes.Buffer
	renderHuman(&buf, &rep)
	if !strings.Contains(buf.String(), "not published") {
		t.Fatalf("human render must say the daemon has not published:\n%s", buf.String())
	}

	// Now the daemon's candidates: ruff derives under 1111 (drift), tsc under
	// 2222 (consented), eslint under 4444 (pending); black derives nowhere.
	const cands = `{"version":1,"workspaces":[{"path":"/ws","anchors":[
{"id":"eslint@cat-1","tool":"eslint","argv":["x"],"binary_path":"/e","binary_hash":"d","tool_version":"9","class":"fast","side_effect":"static","exec_hash":"4444","consented_at":"0001-01-01T00:00:00Z","consented":false},
{"id":"ruff@cat-1","tool":"ruff","argv":["x"],"binary_path":"/r","binary_hash":"a2","tool_version":"0.6","class":"fast","side_effect":"static","exec_hash":"1111","consented_at":"0001-01-01T00:00:00Z","consented":false},
{"id":"tsc@cat-1","tool":"tsc","argv":["x"],"binary_path":"/t","binary_hash":"b","tool_version":"5.5","class":"fast","side_effect":"static","exec_hash":"2222","consented_at":"2026-01-02T03:04:05Z","consented":true}
]}]}`
	if err := os.WriteFile(env.AnchorsCandidates(), []byte(cands), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err = runDoctor(t, env, out, Options{})
	if err != nil {
		t.Fatalf("doctor failed: %v\n%+v", err, rep)
	}
	want := map[string]struct {
		consented bool
		state     string
	}{
		"eslint@cat-1": {false, "pending"},
		"ruff@cat-1":   {false, "drifted"},
		"tsc@cat-1":    {true, ""},
		"black@cat-1":  {true, "stale"},
	}
	if len(rep.Anchors) != len(want) {
		t.Fatalf("rows %+v, want %d", rep.Anchors, len(want))
	}
	for id, w := range want {
		row := anchorRow(t, rep, id)
		if row.Consented != w.consented || row.State != w.state {
			t.Fatalf("%s: %+v, want consented=%v state=%q", id, row, w.consented, w.state)
		}
	}
	if r := anchorRow(t, rep, "tsc@cat-1"); r.Workspace != "/ws" || r.ConsentedAt.IsZero() {
		t.Fatalf("consented row %+v must carry its workspace and timestamp", r)
	}
	if c := healthRow(t, rep, "anchor_candidates"); !c.OK || !strings.Contains(c.Detail, "1 workspace") {
		t.Fatalf("anchor_candidates %+v", c)
	}

	// Published, but no workspace enabled: still not an empty-list silence.
	if err := os.WriteFile(env.AnchorsCandidates(), []byte(`{"version":1,"workspaces":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(env.AnchorsCatalog()); err != nil {
		t.Fatal(err)
	}
	rep, err = runDoctor(t, env, out, Options{})
	if err != nil {
		t.Fatalf("doctor failed: %v\n%+v", err, rep)
	}
	buf.Reset()
	renderHuman(&buf, &rep)
	if !strings.Contains(buf.String(), "no workspace enabled") {
		t.Fatalf("human render:\n%s", buf.String())
	}
}

// TestDoctorShowsStopGatePosture: the same FR-POLICY-006 posture `status`
// prints, on the CI-facing surface, and never a failure — not opted in is the
// default every install ships with.
func TestDoctorShowsStopGatePosture(t *testing.T) {
	env, out := enrolledEnv(t)
	rep, err := runDoctor(t, env, out, Options{})
	if err != nil || rep.StopGate.State != "not_opted_in" {
		t.Fatalf("report %+v %v, want ok and not_opted_in", rep.StopGate, err)
	}
	if err := env.WriteStopGateOptIn("2026-09-15T00:00:00Z", "alice"); err != nil {
		t.Fatal(err)
	}
	rep, err = runDoctor(t, env, out, Options{})
	if err != nil || rep.StopGate.State != "opted_in" || rep.StopGate.User != "alice" || rep.StopGate.TS != "2026-09-15T00:00:00Z" {
		t.Fatalf("report %+v %v, want ok and opted_in by alice", rep.StopGate, err)
	}
}

// codexHome plants a fake codex home with our fragment applied (mechanism B
// over the user's own PreToolUse handler) and a `codex` stub on PATH.
func codexHome(t *testing.T, env *cli.Env) (home string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell-script codex stub")
	}
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "codex"), []byte("#!/bin/sh\necho codex-cli 0.154.0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	home = filepath.Join(t.TempDir(), ".codex")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	hooks := filepath.Join(home, "hooks.json")
	const body = "{\n  \"hooks\": {\"PreToolUse\": [ {\"matcher\":\"shell\", \"hooks\": [ {\"type\":\"command\",\"command\":\"echo hi\"} ] } ]}\n}\n"
	if err := os.WriteFile(hooks, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if res, err := codex.ApplyFragment(hooks, env.StateDir, ""); err != nil || !res.Changed {
		t.Fatalf("setup apply: %v %+v", err, res)
	}
	return home
}

func codexRow(t *testing.T, rep Report) Agent {
	t.Helper()
	for _, a := range rep.Agents {
		if a.Name == "codex" {
			return a
		}
	}
	t.Fatalf("no codex row in %+v", rep.Agents)
	return Agent{}
}

// trustToml writes config.toml trusting every one of our handlers via the
// discovery.rs hook_key shape, minus the keys named in except, with extra
// appended verbatim.
func trustToml(t *testing.T, env *cli.Env, home string, except map[string]bool, extra string) {
	t.Helper()
	m, err := codex.LoadManifest(env.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, p := range m.Pointers {
		rest := strings.TrimPrefix(p, "/hooks/")
		event, idx, _ := strings.Cut(rest, "/")
		key := m.TargetPath + ":" + snake(event) + ":" + idx + ":0"
		if except[event] {
			continue
		}
		b.WriteString("[hooks.state." + strconv.Quote(key) + "]\ntrusted_hash = \"sha256:deadbeef\"\n\n")
	}
	b.WriteString(extra)
	if err := os.WriteFile(filepath.Join(home, "config.toml"), []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestDoctorCodexRowSaysWhetherCodexTrustsOurHooks: the row is informational
// (doctor stays green) and never silently "ok" — untrusted names the step.
func TestDoctorCodexRowSaysWhetherCodexTrustsOurHooks(t *testing.T) {
	env, out := enrolledEnv(t)
	home := codexHome(t, env)
	opts := Options{CodexHome: home}

	rep, err := runDoctor(t, env, out, opts)
	if err != nil {
		t.Fatalf("an untrusted hook set must not fail doctor: %v", err)
	}
	row := codexRow(t, rep)
	if row.Version != "0.154.0" || row.Regime != "subscription" || row.HooksTrusted != "no" || !strings.Contains(row.Note, "0/11 handlers trusted, run codex once and accept the hooks review") {
		t.Fatalf("no config.toml: %+v", row)
	}
	if len(rep.Fragments) != 1 || rep.Fragments[0].Agent != "codex" || rep.Fragments[0].State != "OK" || len(rep.Fragments[0].Lines) != 11 {
		t.Fatalf("codex fragment row %+v", rep.Fragments)
	}

	trustToml(t, env, home, nil, "")
	rep, _ = runDoctor(t, env, out, opts)
	if row := codexRow(t, rep); row.HooksTrusted != "yes" || row.Note != "" {
		t.Fatalf("all trusted: %+v", row)
	}
	env.JSON = false
	out.Reset()
	if err := Run(env, Options{CodexHome: home, ClaudeSettings: noRetention(t), Socket: filepath.Join(t.TempDir(), "no.sock")}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "agent         codex        mechanism A/B version 0.154.0 regime subscription hooks_trusted: yes") {
		t.Fatalf("human row:\n%s", out.String())
	}
	env.JSON = true

	trustToml(t, env, home, map[string]bool{"Stop": true}, "")
	rep, _ = runDoctor(t, env, out, opts)
	if row := codexRow(t, rep); row.HooksTrusted != "no" || !strings.Contains(row.Note, "10/11 handlers trusted") {
		t.Fatalf("one untrusted: %+v", row)
	}

	// A trusted but disabled handler does not run either.
	m, _ := codex.LoadManifest(env.StateDir)
	stopKey := m.TargetPath + ":stop:0:0"
	trustToml(t, env, home, nil, "[hooks.state."+strconv.Quote(stopKey)+"]\nenabled = false\n")
	rep, _ = runDoctor(t, env, out, opts)
	if row := codexRow(t, rep); row.HooksTrusted != "no" || !strings.Contains(row.Note, "10/11") {
		t.Fatalf("disabled handler counted as trusted: %+v", row)
	}

	// The inline-table spelling of the same state.
	var inline strings.Builder
	inline.WriteString("[hooks.state]\n")
	for _, p := range m.Pointers {
		event, idx, _ := strings.Cut(strings.TrimPrefix(p, "/hooks/"), "/")
		inline.WriteString(strconv.Quote(m.TargetPath+":"+snake(event)+":"+idx+":0") + " = { enabled = true, trusted_hash = \"sha256:abc\" }\n")
	}
	if err := os.WriteFile(filepath.Join(home, "config.toml"), []byte(inline.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, _ = runDoctor(t, env, out, opts)
	if row := codexRow(t, rep); row.HooksTrusted != "yes" {
		t.Fatalf("inline tables: %+v", row)
	}

	// A trusted_hash under some OTHER hooks.json path, or outside
	// [hooks.state], is not ours.
	for _, foreign := range []string{
		strings.ReplaceAll(inline.String(), m.TargetPath, "/elsewhere/hooks.json"),
		strings.Replace(inline.String(), "[hooks.state]", "[hooks.review]", 1),
	} {
		if err := os.WriteFile(filepath.Join(home, "config.toml"), []byte(foreign), 0o600); err != nil {
			t.Fatal(err)
		}
		rep, _ = runDoctor(t, env, out, opts)
		if row := codexRow(t, rep); row.HooksTrusted != "no" {
			t.Fatalf("foreign state counted as ours: %+v\n%s", row, foreign)
		}
	}
}

// TestDoctorCodexRowWithoutCodex: not installed is said, and with no fragment
// there is no trust verdict to fake.
func TestDoctorCodexRowWithoutCodex(t *testing.T) {
	env, out := enrolledEnv(t)
	rep, err := runDoctor(t, env, out, Options{CodexHome: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if row := codexRow(t, rep); row.Note != "codex not on PATH" || row.HooksTrusted != "" || row.Version != "" || row.Regime != "" {
		t.Fatalf("row %+v", row)
	}
	// API-key regime is read from the codex home's auth.json.
	home := codexHome(t, env)
	if err := os.WriteFile(filepath.Join(home, "auth.json"), []byte(`{"auth_mode":"apikey"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, _ = runDoctor(t, env, out, Options{CodexHome: home})
	if row := codexRow(t, rep); row.Regime != "apikey" {
		t.Fatalf("row %+v", row)
	}
}

// TestDoctorFixRepairsACodexFragment: a hand edit inside our entry is
// FRAGMENT-DAMAGED (exit 1) and --fix re-applies it.
func TestDoctorFixRepairsACodexFragment(t *testing.T) {
	env, out := enrolledEnv(t)
	home := codexHome(t, env)
	hooks := filepath.Join(home, "hooks.json")
	b, _ := os.ReadFile(hooks)
	b = []byte(strings.Replace(string(b), `"timeout": 30`, `"timeout": 31`, 1))
	if err := os.WriteFile(hooks, b, 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := runDoctor(t, env, out, Options{CodexHome: home})
	if err == nil || rep.OK || rep.Fragments[0].State != "FRAGMENT-DAMAGED" {
		t.Fatalf("damaged fragment: %v %+v", err, rep.Fragments)
	}
	rep, err = runDoctor(t, env, out, Options{CodexHome: home, Fix: true})
	if err != nil || rep.Fragments[0].State != "OK" || !rep.Fragments[0].Fixed {
		t.Fatalf("--fix: %v %+v", err, rep.Fragments)
	}
}

func TestDoctorShowsExplorationPosture(t *testing.T) {
	env, out := enrolledEnv(t)
	if err := env.UpdateOptIn("2026-09-15T00:00:00Z", "alice", func(a *cli.OptIn) { a.Exploration = true }); err != nil {
		t.Fatal(err)
	}
	rep, err := runDoctor(t, env, out, Options{})
	if err != nil || rep.Exploration.State != "opted_in" || rep.Exploration.User != "alice" || rep.StopGate.State != "not_opted_in" {
		t.Fatalf("%v %+v %+v", err, rep.Exploration, rep.StopGate)
	}
	env.JSON = false
	out.Reset()
	if err := Run(env, Options{ClaudeSettings: noRetention(t), Socket: filepath.Join(t.TempDir(), "no.sock")}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "exploration   opted_in (by alice at 2026-09-15T00:00:00Z)") {
		t.Fatalf("human output:\n%s", out.String())
	}
}

// fakeBin puts a shell stub answering --version on the hermetic PATH.
func fakeBin(t *testing.T, name, banner string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell-script stub")
	}
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\necho "+banner+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func agentRow(t *testing.T, rep Report, name string) Agent {
	t.Helper()
	for _, a := range rep.Agents {
		if a.Name == name {
			return a
		}
	}
	t.Fatalf("no %s row in %+v", name, rep.Agents)
	return Agent{}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestDoctorGeminiAndOpenCodeRowsWithoutBinaries: not installed is said, with
// nothing sniffed to fake a version or regime from.
func TestDoctorGeminiAndOpenCodeRowsWithoutBinaries(t *testing.T) {
	env, out := enrolledEnv(t)
	rep, err := runDoctor(t, env, out, Options{Home: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"gemini", "opencode"} {
		if row := agentRow(t, rep, name); row.Note != name+" not on PATH" || row.Version != "" || row.Regime != "" {
			t.Fatalf("row %+v", row)
		}
	}
}

const geminiSettingsBody = "{\n  \"theme\": \"mine\",\n  \"hooks\": {\"BeforeTool\": [ {\"matcher\":\"*\", \"hooks\": [ {\"type\":\"command\",\"command\":\"echo hi\"} ] } ]}\n}\n"

// TestDoctorGeminiRow: version and regime ride the row; an absent or JSONC
// settings.json is named because mechanism B can never fence one; the
// fragment row classifies through the adapter and --fix repairs a hand edit.
func TestDoctorGeminiRow(t *testing.T) {
	env, out := enrolledEnv(t)
	fakeBin(t, "gemini", "0.59.0")
	home := t.TempDir()
	settings := filepath.Join(home, ".gemini", "settings.json")
	opts := Options{Home: home}

	rep, err := runDoctor(t, env, out, opts)
	if err != nil {
		t.Fatalf("an absent settings file must not fail doctor: %v", err)
	}
	if row := agentRow(t, rep, "gemini"); row.Version != "0.59.0" || row.Regime != "subscription" || !strings.Contains(row.Note, "no ~/.gemini/settings.json") {
		t.Fatalf("absent settings: %+v", row)
	}

	writeFile(t, settings, "// comments\n"+geminiSettingsBody)
	rep, _ = runDoctor(t, env, out, opts)
	if row := agentRow(t, rep, "gemini"); !strings.Contains(row.Note, "not strict JSON") {
		t.Fatalf("JSONC settings: %+v", row)
	}

	writeFile(t, settings, `{"security":{"auth":{"selectedType":"gemini-api-key"}}}`)
	rep, _ = runDoctor(t, env, out, opts)
	if row := agentRow(t, rep, "gemini"); row.Regime != "apikey" || row.Note != "" {
		t.Fatalf("apikey settings: %+v", row)
	}

	fakeBin(t, "gemini", "0.1.0")
	rep, _ = runDoctor(t, env, out, opts)
	if row := agentRow(t, rep, "gemini"); row.Version != "0.1.0" || !strings.Contains(row.Note, "no pinned fixture") {
		t.Fatalf("unsupported version: %+v", row)
	}
	fakeBin(t, "gemini", "0.59.0")

	writeFile(t, settings, geminiSettingsBody)
	if res, err := gemini.ApplyFragment(settings, env.StateDir, ""); err != nil || !res.Changed {
		t.Fatalf("setup apply: %v %+v", err, res)
	}
	rep, err = runDoctor(t, env, out, opts)
	if err != nil {
		t.Fatalf("a healthy gemini fragment failed doctor: %v\n%+v", err, rep.Fragments)
	}
	if len(rep.Fragments) != 1 || rep.Fragments[0].Agent != "gemini" || rep.Fragments[0].Mechanism != "B" || rep.Fragments[0].State != "OK" || len(rep.Fragments[0].Lines) != 7 {
		t.Fatalf("gemini fragment row %+v", rep.Fragments)
	}
	env.JSON = false
	out.Reset()
	if err := Run(env, Options{Home: home, ClaudeSettings: noRetention(t), Socket: filepath.Join(t.TempDir(), "no.sock")}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "agent         gemini       mechanism B version 0.59.0 regime subscription") {
		t.Fatalf("human row:\n%s", out.String())
	}
	env.JSON = true

	b, _ := os.ReadFile(settings)
	writeFile(t, settings, strings.Replace(string(b), `"timeout": 10000`, `"timeout": 10001`, 1))
	rep, err = runDoctor(t, env, out, opts)
	if err == nil || rep.OK || rep.Fragments[0].State != "FRAGMENT-DAMAGED" {
		t.Fatalf("damaged fragment: %v %+v", err, rep.Fragments)
	}
	rep, err = runDoctor(t, env, out, Options{Home: home, Fix: true})
	if err != nil || rep.Fragments[0].State != "OK" || !rep.Fragments[0].Fixed {
		t.Fatalf("--fix: %v %+v", err, rep.Fragments)
	}

	writeFile(t, gemini.ManifestPath(env.StateDir), "not json")
	rep, err = runDoctor(t, env, out, opts)
	if err == nil || len(rep.Fragments) != 1 || rep.Fragments[0].State != "FRAGMENT-DAMAGED" || !strings.Contains(rep.Fragments[0].Detail, gemini.CodeManifestCorrupt) {
		t.Fatalf("corrupt manifest: %v %+v", err, rep.Fragments)
	}
}

// TestDoctorOpenCodeRow: version and regime ride the row; once provisioned the
// row says the plugin only loads at opencode start; the owned file classifies
// OK / FRAGMENT-DAMAGED through the adapter and --fix rewrites it.
func TestDoctorOpenCodeRow(t *testing.T) {
	env, out := enrolledEnv(t)
	fakeBin(t, "opencode", "1.18.31")
	home := t.TempDir()
	cfg := filepath.Join(home, ".config", "opencode")
	if err := os.MkdirAll(cfg, 0o700); err != nil {
		t.Fatal(err)
	}
	opts := Options{Home: home}

	rep, err := runDoctor(t, env, out, opts)
	if err != nil {
		t.Fatal(err)
	}
	if row := agentRow(t, rep, "opencode"); row.Version != "1.18.31" || row.Regime != "subscription" || row.Note != "" {
		t.Fatalf("unprovisioned: %+v", row)
	}

	writeFile(t, filepath.Join(cfg, "opencode.json"), `{"model":"anthropic/claude-sonnet-4"}`)
	writeFile(t, filepath.Join(home, ".local", "share", "opencode", "auth.json"), `{"anthropic":{"type":"api","key":"sk-x"}}`)
	rep, _ = runDoctor(t, env, out, opts)
	if row := agentRow(t, rep, "opencode"); row.Regime != "apikey" {
		t.Fatalf("apikey auth.json: %+v", row)
	}

	fakeBin(t, "opencode", "0.0.1")
	rep, _ = runDoctor(t, env, out, opts)
	if row := agentRow(t, rep, "opencode"); row.Version != "0.0.1" || !strings.Contains(row.Note, "no pinned fixture") {
		t.Fatalf("unsupported version: %+v", row)
	}
	fakeBin(t, "opencode", "1.18.31")

	plugin := filepath.Join(cfg, "plugins", "mark1.js")
	if res, err := opencode.ApplyFragment(plugin, env.StateDir, ""); err != nil || !res.Changed {
		t.Fatalf("setup apply: %v %+v", err, res)
	}
	rep, err = runDoctor(t, env, out, opts)
	if err != nil {
		t.Fatalf("a healthy plugin failed doctor: %v\n%+v", err, rep.Fragments)
	}
	if row := agentRow(t, rep, "opencode"); !strings.Contains(row.Note, "loads at opencode start") {
		t.Fatalf("provisioned row must say the plugin is inert until restart: %+v", row)
	}
	if len(rep.Fragments) != 1 || rep.Fragments[0].Agent != "opencode" || rep.Fragments[0].Mechanism != "A" || rep.Fragments[0].State != "OK" || rep.Fragments[0].Target != plugin {
		t.Fatalf("opencode fragment row %+v", rep.Fragments)
	}
	env.JSON = false
	out.Reset()
	if err := Run(env, Options{Home: home, ClaudeSettings: noRetention(t), Socket: filepath.Join(t.TempDir(), "no.sock")}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "agent         opencode     mechanism A version 1.18.31 regime apikey (plugin loads at opencode start") {
		t.Fatalf("human row:\n%s", out.String())
	}
	env.JSON = true

	b, _ := os.ReadFile(plugin)
	writeFile(t, plugin, string(b)+"\n// mine\n")
	rep, err = runDoctor(t, env, out, opts)
	if err == nil || rep.OK || rep.Fragments[0].State != "FRAGMENT-DAMAGED" {
		t.Fatalf("damaged plugin: %v %+v", err, rep.Fragments)
	}
	rep, err = runDoctor(t, env, out, Options{Home: home, Fix: true})
	if err != nil || rep.Fragments[0].State != "OK" || !rep.Fragments[0].Fixed {
		t.Fatalf("--fix: %v %+v", err, rep.Fragments)
	}
	if got, _ := os.ReadFile(plugin); !bytes.Equal(got, b) {
		t.Fatal("--fix did not restore the owned bytes")
	}

	writeFile(t, opencode.ManifestPath(env.StateDir), "not json")
	rep, err = runDoctor(t, env, out, opts)
	if err == nil || len(rep.Fragments) != 1 || rep.Fragments[0].State != "FRAGMENT-DAMAGED" || !strings.Contains(rep.Fragments[0].Detail, opencode.CodeManifestCorrupt) {
		t.Fatalf("corrupt manifest: %v %+v", err, rep.Fragments)
	}
}

// TestDoctorCopilotAndCursorRowsWithoutBinaries: not installed is said, with
// nothing sniffed to fake a version or regime from.
func TestDoctorCopilotAndCursorRowsWithoutBinaries(t *testing.T) {
	env, out := enrolledEnv(t)
	rep, err := runDoctor(t, env, out, Options{Home: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"copilot", "cursor"} {
		if row := agentRow(t, rep, name); row.Note != name+" not on PATH" || row.Version != "" || row.Regime != "" {
			t.Fatalf("row %+v", row)
		}
	}
}

// TestDoctorCopilotRow: version and regime ride the row; the byok-pointer note
// names one of FR-AGENT-014's three states (doctor only classifies, so it reads
// absent here — only `mark1 enable` applies the pointer, covered separately);
// an absent $COPILOT_HOME is named; the owned hooks file classifies
// OK / FRAGMENT-DAMAGED through the adapter and --fix rewrites it.
func TestDoctorCopilotRow(t *testing.T) {
	env, out := enrolledEnv(t)
	fakeBin(t, "copilot", "1.0.85")
	home := t.TempDir()
	copilotHome := filepath.Join(home, ".copilot")
	opts := Options{Home: home}

	rep, err := runDoctor(t, env, out, opts)
	if err != nil {
		t.Fatalf("an absent vendor dir must not fail doctor: %v", err)
	}
	row := agentRow(t, rep, "copilot")
	if row.Version != "1.0.85" || row.Regime != "subscription" || !strings.Contains(row.Note, "no ~/.copilot") || !strings.Contains(row.Note, "byok pointer absent") {
		t.Fatalf("absent vendor dir: %+v", row)
	}
	if err := os.MkdirAll(copilotHome, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("COPILOT_PROVIDER_BASE_URL", "https://api.openai.com/v1")
	t.Setenv("COPILOT_PROVIDER_API_KEY", "sk-synth")
	rep, _ = runDoctor(t, env, out, opts)
	// doctor only classifies; it never applies the pointer (only `mark1 enable`
	// does), so even under an eligible BYOK env the row still reads absent —
	// nothing was ever written.
	if row := agentRow(t, rep, "copilot"); row.Regime != "apikey" || strings.Contains(row.Note, "no ~/.copilot") || !strings.Contains(row.Note, "byok pointer absent") {
		t.Fatalf("BYOK env: %+v", row)
	}
	t.Setenv("COPILOT_PROVIDER_BASE_URL", "")
	t.Setenv("COPILOT_PROVIDER_API_KEY", "")

	fakeBin(t, "copilot", "0.0.1")
	rep, _ = runDoctor(t, env, out, opts)
	if row := agentRow(t, rep, "copilot"); row.Version != "0.0.1" || !strings.Contains(row.Note, "no pinned fixture") {
		t.Fatalf("unsupported version: %+v", row)
	}
	fakeBin(t, "copilot", "1.0.85")

	hooks := filepath.Join(copilotHome, "hooks", "mark1.json")
	if res, err := copilot.ApplyFragment(hooks, env.StateDir, ""); err != nil || !res.Changed {
		t.Fatalf("setup apply: %v %+v", err, res)
	}
	rep, err = runDoctor(t, env, out, opts)
	if err != nil {
		t.Fatalf("a healthy owned file failed doctor: %v\n%+v", err, rep.Fragments)
	}
	if len(rep.Fragments) != 1 || rep.Fragments[0].Agent != "copilot" || rep.Fragments[0].Mechanism != "A" || rep.Fragments[0].State != "OK" || rep.Fragments[0].Target != hooks {
		t.Fatalf("copilot fragment row %+v", rep.Fragments)
	}
	env.JSON = false
	out.Reset()
	if err := Run(env, Options{Home: home, ClaudeSettings: noRetention(t), Socket: filepath.Join(t.TempDir(), "no.sock")}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "agent         copilot      mechanism A version 1.0.85 regime subscription (byok pointer absent)") {
		t.Fatalf("human row:\n%s", out.String())
	}
	env.JSON = true

	b, _ := os.ReadFile(hooks)
	writeFile(t, hooks, strings.Replace(string(b), "|| true", "|| false", 1))
	rep, err = runDoctor(t, env, out, opts)
	if err == nil || rep.OK || rep.Fragments[0].State != "FRAGMENT-DAMAGED" {
		t.Fatalf("damaged owned file: %v %+v", err, rep.Fragments)
	}
	rep, err = runDoctor(t, env, out, Options{Home: home, Fix: true})
	if err != nil || rep.Fragments[0].State != "OK" || !rep.Fragments[0].Fixed {
		t.Fatalf("--fix: %v %+v", err, rep.Fragments)
	}
	if got, _ := os.ReadFile(hooks); !bytes.Equal(got, b) {
		t.Fatal("--fix did not restore the owned bytes")
	}

	if err := os.Remove(hooks); err != nil {
		t.Fatal(err)
	}
	rep, err = runDoctor(t, env, out, opts)
	if err == nil || rep.Fragments[0].State != "MISSING" {
		t.Fatalf("deleted owned file: %v %+v", err, rep.Fragments)
	}
	rep, err = runDoctor(t, env, out, Options{Home: home, Fix: true})
	if err != nil || rep.Fragments[0].State != "OK" || !rep.Fragments[0].Fixed {
		t.Fatalf("--fix of MISSING: %v %+v", err, rep.Fragments)
	}

	writeFile(t, copilot.ManifestPath(env.StateDir), "not json")
	rep, err = runDoctor(t, env, out, opts)
	if err == nil || len(rep.Fragments) != 1 || rep.Fragments[0].State != "FRAGMENT-DAMAGED" || !strings.Contains(rep.Fragments[0].Detail, copilot.CodeManifestCorrupt) {
		t.Fatalf("corrupt manifest: %v %+v", err, rep.Fragments)
	}
}

// TestDoctorCopilotEnvPointerRow: FR-AGENT-014's three-way byok-pointer state
// — absent before anything is applied; written, not sourced once applied but
// the CURRENT process env does not carry it (never sourced, sourced
// elsewhere, or stale); active once it does — plus the fragment row's OK and
// FRAGMENT-DAMAGED classification through the adapter, with --fix naming the
// remedy instead of performing it (re-pointing needs a fresh `mark1 enable`
// eligibility check, not a blind rewrite).
func TestDoctorCopilotEnvPointerRow(t *testing.T) {
	env, out := enrolledEnv(t)
	fakeBin(t, "copilot", "1.0.85")
	home := t.TempDir()
	opts := Options{Home: home}

	rep, err := runDoctor(t, env, out, opts)
	if err != nil {
		t.Fatalf("nothing applied yet must not fail doctor: %v", err)
	}
	if row := agentRow(t, rep, "copilot"); !strings.Contains(row.Note, "byok pointer absent") {
		t.Fatalf("before apply: %+v", row)
	}
	if len(rep.Fragments) != 0 {
		t.Fatalf("no env-pointer manifest yet, so no fragment row: %+v", rep.Fragments)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"reason_code":"M1E-8001"}`))
	}))
	t.Cleanup(srv.Close)
	if err := os.MkdirAll(env.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(env.StateDir, "proxy.port"), []byte(strconv.Itoa(srv.Listener.Addr().(*net.TCPAddr).Port)), 0o600); err != nil {
		t.Fatal(err)
	}
	a := &copilot.Adapter{Home: home, StateDir: env.StateDir, Env: func(k string) string {
		return map[string]string{"COPILOT_PROVIDER_BASE_URL": "https://api.openai.com/v1", "COPILOT_PROVIDER_API_KEY": "sk-synth"}[k]
	}}
	if _, err := a.ApplyEnvPointer(); err != nil {
		t.Fatalf("setup apply: %v", err)
	}
	target := copilot.EnvFilePath(env.StateDir, runtime.GOOS)

	// Written but the CLI process's own env does not have it: doctor and the
	// user's shell are not the same process unless it was actually sourced.
	rep, err = runDoctor(t, env, out, opts)
	if err != nil {
		t.Fatalf("written-not-sourced must not fail doctor: %v", err)
	}
	if row := agentRow(t, rep, "copilot"); !strings.Contains(row.Note, "byok pointer written, not sourced") {
		t.Fatalf("written, not sourced: %+v", row)
	}
	if len(rep.Fragments) != 1 || rep.Fragments[0].Agent != "copilot" || rep.Fragments[0].Fragment != "env" ||
		rep.Fragments[0].Mechanism != "A" || rep.Fragments[0].State != "OK" || rep.Fragments[0].Target != target {
		t.Fatalf("env fragment row: %+v", rep.Fragments)
	}

	// Sourced into doctor's own process: exactly what "active" means.
	t.Setenv("COPILOT_PROVIDER_BASE_URL", srv.URL)
	rep, err = runDoctor(t, env, out, opts)
	if err != nil {
		t.Fatalf("active must not fail doctor: %v", err)
	}
	if row := agentRow(t, rep, "copilot"); !strings.Contains(row.Note, "byok pointer active") {
		t.Fatalf("active: %+v", row)
	}
	env.JSON = false
	out.Reset()
	if err := Run(env, Options{Home: home, ClaudeSettings: noRetention(t), Socket: filepath.Join(t.TempDir(), "no.sock")}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "byok pointer active") {
		t.Fatalf("human row:\n%s", out.String())
	}
	env.JSON = true
	t.Setenv("COPILOT_PROVIDER_BASE_URL", "https://api.openai.com/v1")

	// A hand-edit is FRAGMENT-DAMAGED, and --fix explains rather than repairs.
	b, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, target, string(b)+"# edited\n")
	rep, err = runDoctor(t, env, out, opts)
	if err == nil || rep.OK || len(rep.Fragments) != 1 || rep.Fragments[0].State != "FRAGMENT-DAMAGED" {
		t.Fatalf("hand-edited pointer: %v %+v", err, rep.Fragments)
	}
	rep, err = runDoctor(t, env, out, Options{Home: home, Fix: true})
	if err == nil || rep.Fragments[0].State != "FRAGMENT-DAMAGED" || rep.Fragments[0].Fixed ||
		!strings.Contains(rep.Fragments[0].Detail, "does not re-point copilot at the proxy") {
		t.Fatalf("--fix must name the remedy, not perform it: %v %+v", err, rep.Fragments)
	}
	if got, _ := os.ReadFile(target); !strings.Contains(string(got), "# edited") {
		t.Fatal("--fix must not have touched the file it refuses to repair")
	}
}

const cursorHooksBody = "{\n  \"version\": 1,\n  \"hooks\": {\"preToolUse\": [ {\"command\": \"echo hi\", \"timeout\": 5} ]}\n}\n"

// TestDoctorCursorRow: version rides the row and the regime is subscription
// whatever is configured (the wire path is a permanent NO-GO); an absent ~/.cursor
// is named; once the claudecode fragment is provisioned the row says Cursor runs
// it too with MARK1_AGENT unset; the fence classifies through the adapter with
// its lines and --fix repairs a hand edit.
func TestDoctorCursorRow(t *testing.T) {
	env, out := enrolledEnv(t)
	fakeBin(t, "cursor-agent", "2026.09.10-fd3934a")
	home := t.TempDir()
	hooks := filepath.Join(home, ".cursor", "hooks.json")
	opts := Options{Home: home}

	rep, err := runDoctor(t, env, out, opts)
	if err != nil {
		t.Fatalf("an absent vendor dir must not fail doctor: %v", err)
	}
	if row := agentRow(t, rep, "cursor"); row.Version != "2026.09.10-fd3934a" || row.Regime != "subscription" || !strings.Contains(row.Note, "no ~/.cursor") || strings.Contains(row.Note, "MARK1_AGENT") {
		t.Fatalf("absent vendor dir: %+v", row)
	}

	writeFile(t, hooks, cursorHooksBody)
	provision(t, env)
	rep, _ = runDoctor(t, env, out, opts)
	if row := agentRow(t, rep, "cursor"); strings.Contains(row.Note, "no ~/.cursor") || !strings.Contains(row.Note, "claudecode fragment") || !strings.Contains(row.Note, "MARK1_AGENT unset") {
		t.Fatalf("claudecode provisioned: %+v", row)
	}
	if err := os.Remove(claudecode.ManifestPath(env.StateDir)); err != nil {
		t.Fatal(err)
	}
	rep, _ = runDoctor(t, env, out, opts)
	if row := agentRow(t, rep, "cursor"); row.Note != "" {
		t.Fatalf("nothing to say once claudecode is unprovisioned: %+v", row)
	}

	fakeBin(t, "cursor-agent", "2026.01.01-0000000")
	rep, _ = runDoctor(t, env, out, opts)
	if row := agentRow(t, rep, "cursor"); row.Version != "2026.01.01-0000000" || !strings.Contains(row.Note, "no pinned fixture") {
		t.Fatalf("unsupported version: %+v", row)
	}
	fakeBin(t, "cursor-agent", "2026.09.10-fd3934a")

	if res, err := cursor.ApplyFragment(hooks, env.StateDir, ""); err != nil || !res.Changed || res.Mechanism != "B" {
		t.Fatalf("setup apply: %v %+v", err, res)
	}
	rep, err = runDoctor(t, env, out, opts)
	if err != nil {
		t.Fatalf("a healthy cursor fragment failed doctor: %v\n%+v", err, rep.Fragments)
	}
	if len(rep.Fragments) != 1 || rep.Fragments[0].Agent != "cursor" || rep.Fragments[0].Mechanism != "B" || rep.Fragments[0].State != "OK" || len(rep.Fragments[0].Lines) != 8 {
		t.Fatalf("cursor fragment row %+v", rep.Fragments)
	}
	env.JSON = false
	out.Reset()
	if err := Run(env, Options{Home: home, ClaudeSettings: noRetention(t), Socket: filepath.Join(t.TempDir(), "no.sock")}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "agent         cursor       mechanism A/B version 2026.09.10-fd3934a regime subscription") || !strings.Contains(out.String(), "/hooks/stop/") {
		t.Fatalf("human row:\n%s", out.String())
	}
	env.JSON = true

	// A user edit outside the fence is USER-EDITED: healthy (exit 0) and --fix leaves the bytes alone.
	b, _ := os.ReadFile(hooks)
	edited := strings.Replace(string(b), "{\n", "{\n  \"mine\": true,\n", 1)
	writeFile(t, hooks, edited)
	rep, err = runDoctor(t, env, out, Options{Home: home, Fix: true})
	if err != nil || !rep.OK || rep.Fragments[0].State != "USER-EDITED" || rep.Fragments[0].Fixed {
		t.Fatalf("user edit outside the fence: %v %+v", err, rep.Fragments)
	}
	if got, _ := os.ReadFile(hooks); string(got) != edited {
		t.Fatalf("--fix rewrote a healthy file:\n%s", got)
	}
	writeFile(t, hooks, string(b))

	writeFile(t, hooks, strings.Replace(string(b), `"timeout": 30`, `"timeout": 90`, 1))
	rep, err = runDoctor(t, env, out, opts)
	if err == nil || rep.OK || rep.Fragments[0].State != "FRAGMENT-DAMAGED" {
		t.Fatalf("damaged fragment: %v %+v", err, rep.Fragments)
	}
	rep, err = runDoctor(t, env, out, Options{Home: home, Fix: true})
	if err != nil || rep.Fragments[0].State != "OK" || !rep.Fragments[0].Fixed {
		t.Fatalf("--fix: %v %+v", err, rep.Fragments)
	}
	if got, _ := os.ReadFile(hooks); !bytes.Equal(got, b) || !strings.Contains(string(got), "echo hi") {
		t.Fatalf("--fix did not restore the fence beside the user's entry:\n%s", got)
	}

	writeFile(t, cursor.ManifestPath(env.StateDir), "not json")
	rep, err = runDoctor(t, env, out, opts)
	if err == nil || len(rep.Fragments) != 1 || rep.Fragments[0].State != "FRAGMENT-DAMAGED" || !strings.Contains(rep.Fragments[0].Detail, cursor.CodeManifestCorrupt) {
		t.Fatalf("corrupt manifest: %v %+v", err, rep.Fragments)
	}
}
