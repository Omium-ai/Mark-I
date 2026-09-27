//go:build linux

package doctor

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Omium-ai/omium-mark1/go/mark1/internal/apparmor"
	"github.com/Omium-ai/omium-mark1/go/mark1/internal/cli"
)

// init seals every doctor test from the host's AppArmor state: a developer box with the restriction on and mark1d on PATH must not turn TestDoctorAllGreen red. TestAppArmorRow sets the host explicitly.
func init() {
	dir, err := os.MkdirTemp("", "doctor-apparmor-")
	if err != nil {
		panic(err)
	}
	apparmor.RestrictPath = filepath.Join(dir, "absent")
	apparmor.Dir, apparmor.LoadedPath = filepath.Join(dir, "apparmor.d"), filepath.Join(dir, "profiles")
}

// sealHost points the apparmor package at a fake host whose restriction sysctl reads restrict ("" = absent).
func sealHost(t *testing.T, restrict string) {
	t.Helper()
	dir := t.TempDir()
	oldR, oldD, oldL, oldP := apparmor.RestrictPath, apparmor.Dir, apparmor.LoadedPath, daemonPath
	t.Cleanup(func() { apparmor.RestrictPath, apparmor.Dir, apparmor.LoadedPath, daemonPath = oldR, oldD, oldL, oldP })
	apparmor.RestrictPath, apparmor.Dir, apparmor.LoadedPath = filepath.Join(dir, "restrict"), filepath.Join(dir, "apparmor.d"), filepath.Join(dir, "profiles")
	if restrict != "" {
		if err := os.WriteFile(apparmor.RestrictPath, []byte(restrict+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(apparmor.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
}

func rowOf(t *testing.T, restrict string) Check {
	t.Helper()
	for _, c := range healthChecks(&cli.Env{StateDir: t.TempDir()}, Options{ClaudeSettings: noRetention(t), Socket: filepath.Join(t.TempDir(), "no.sock")}) {
		if c.Name == "apparmor_userns" {
			return c
		}
	}
	t.Fatalf("no apparmor_userns row (restrict=%q)", restrict)
	return Check{}
}

// TestAppArmorRow: the row passes on an unrestricting host whatever mark1d is found, fails with the root fix on a restricting host without the profile (and so fails doctor as a whole), and passes once the profile names this mark1d and is loaded.
func TestAppArmorRow(t *testing.T) {
	bin, err := filepath.EvalSymlinks("/usr/bin/true")
	if err != nil || apparmor.RootOwned(bin) != nil {
		t.Skip("no root-owned /usr/bin/true to stand in for an installed mark1d")
	}
	for _, restrict := range []string{"", "0"} {
		sealHost(t, restrict)
		daemonPath = func(string) (string, error) { return bin, nil }
		if c := rowOf(t, restrict); !c.OK || !strings.Contains(c.Detail, "not restricted") {
			t.Fatalf("unrestricted host (%q): %+v", restrict, c)
		}
	}

	sealHost(t, "1")
	daemonPath = func(string) (string, error) { return "", errors.New("absent") }
	if c := rowOf(t, "1"); !c.OK {
		t.Fatalf("no mark1d to inspect fails doctor: %+v", c)
	}
	daemonPath = func(string) (string, error) { return bin, nil }
	if c := rowOf(t, "1"); c.OK || !strings.Contains(c.Detail, "apparmor install") {
		t.Fatalf("restricted host without the profile: %+v", c)
	}
	env, _ := enrolledEnv(t)
	if err := Run(env, Options{ClaudeSettings: noRetention(t), Socket: filepath.Join(t.TempDir(), "no.sock")}); err == nil {
		t.Fatal("doctor passed with the anchor sandbox unable to start")
	}
	text, err := apparmor.Profile(bin)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(apparmor.Dir, apparmor.Name), []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(apparmor.LoadedPath, []byte(apparmor.Name+" (unconfined)\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if c := rowOf(t, "1"); !c.OK || !strings.Contains(c.Detail, "loaded") {
		t.Fatalf("restricted host with the profile loaded: %+v", c)
	}
}
