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
