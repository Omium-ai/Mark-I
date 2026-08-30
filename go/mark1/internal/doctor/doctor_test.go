package doctor

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Omium-ai/omium-mark1/go/mark1/internal/cli"
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
	json.Unmarshal(out.Bytes(), &rep)
	if rep.OK {
		t.Fatal("0755 state dir reported green")
	}
}

func TestDoctorFlagsMissingFragmentTarget(t *testing.T) {
	env, out := enrolledEnv(t)
	mdir := filepath.Join(env.ProvisionedDir(), "claudecode")
	if err := os.MkdirAll(mdir, 0o700); err != nil {
		t.Fatal(err)
	}
	gone := filepath.Join(t.TempDir(), "gone.json")
	manifest := map[string]string{"target_path": gone}
	data, _ := json.Marshal(manifest)
	if err := os.WriteFile(filepath.Join(mdir, "hooks.manifest.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	err := Run(env, Options{ClaudeSettings: noRetention(t), Socket: filepath.Join(t.TempDir(), "no.sock")})
	var ee *cli.ExitError
	if !errors.As(err, &ee) || ee.Code != cli.ExitRuntime {
		t.Fatalf("got %v, want exit 1 (§7.4: any MISSING fails)", err)
	}
	var rep Report
	json.Unmarshal(out.Bytes(), &rep)
	if len(rep.Fragments) != 1 || rep.Fragments[0].State != "MISSING" {
		t.Fatalf("fragments %+v", rep.Fragments)
	}
}

func TestDoctorFragmentPresentIsUnverified(t *testing.T) {
	env, out := enrolledEnv(t)
	mdir := filepath.Join(env.ProvisionedDir(), "claudecode")
	os.MkdirAll(mdir, 0o700)
	target := filepath.Join(t.TempDir(), "settings.json")
	os.WriteFile(target, []byte("{}"), 0o600)
	data, _ := json.Marshal(map[string]string{"target_path": target})
	os.WriteFile(filepath.Join(mdir, "hooks.manifest.json"), data, 0o600)

	if err := Run(env, Options{ClaudeSettings: noRetention(t), Socket: filepath.Join(t.TempDir(), "no.sock")}); err != nil {
		t.Fatal(err)
	}
	var rep Report
	json.Unmarshal(out.Bytes(), &rep)
	// PRESENT-UNVERIFIED, never a fake OK: the blake3 checksum walk is the
	// §8 engine's, and doctor does not pretend to have run it.
	if len(rep.Fragments) != 1 || rep.Fragments[0].State != "PRESENT-UNVERIFIED" {
		t.Fatalf("fragments %+v", rep.Fragments)
	}
}

func TestDoctorRetentionWarning(t *testing.T) {
	env, out := enrolledEnv(t)
	settings := filepath.Join(t.TempDir(), "settings.json")
	os.WriteFile(settings, []byte(`{"cleanupPeriodDays": 5}`), 0o600)
	err := Run(env, Options{ClaudeSettings: settings, Socket: filepath.Join(t.TempDir(), "no.sock")})
	var ee *cli.ExitError
	if !errors.As(err, &ee) || ee.Code != cli.ExitRuntime {
		t.Fatalf("got %v, want exit 1 (retention below catch-up horizon)", err)
	}
	var rep Report
	json.Unmarshal(out.Bytes(), &rep)
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

func TestDoctorFixRefusedUntilEngineLands(t *testing.T) {
	env, _ := enrolledEnv(t)
	err := Run(env, Options{Fix: true, Socket: filepath.Join(t.TempDir(), "no.sock")})
	var ee *cli.ExitError
	if !errors.As(err, &ee) || ee.Code != cli.ExitRuntime {
		t.Fatalf("got %v; --fix must refuse rather than rewrite without the §8 manifest discipline", err)
	}
}
