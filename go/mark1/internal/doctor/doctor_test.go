package doctor

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Omium-ai/omium-mark1/go/mark1/internal/cli"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/claudecode"
)

func enrolledEnv(t *testing.T) (*cli.Env, *bytes.Buffer) {
	t.Helper()
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

// TestDoctorListsEveryAgentSlot: six of 08 §5's seven adapters are declared and
// unbuilt. Doctor says so out loud — a cursor user must not have to infer it
// from an empty fragment list.
func TestDoctorListsEveryAgentSlot(t *testing.T) {
	env, out := enrolledEnv(t)
	rep, err := runDoctor(t, env, out, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Agents) != 7 {
		t.Fatalf("%d agent slots, want 08 §5's seven: %+v", len(rep.Agents), rep.Agents)
	}
	built := 0
	for _, a := range rep.Agents {
		if a.Implemented {
			built++
			if a.Name != "claudecode" || a.Mechanism != "B" {
				t.Fatalf("implemented slot %+v", a)
			}
		} else if a.Mechanism != "" {
			t.Fatalf("slot %s claims mechanism %q with no code behind it", a.Name, a.Mechanism)
		}
	}
	if built != 1 {
		t.Fatalf("%d implemented adapters claimed, want exactly claudecode", built)
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
