//go:build linux

package apparmor

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// rootBinary is a real root-owned binary to stand in for an installed mark1d.
func rootBinary(t *testing.T) string {
	t.Helper()
	p, err := filepath.EvalSymlinks("/usr/bin/true")
	if err != nil || RootOwned(p) != nil {
		t.Skip("no root-owned /usr/bin/true on this host")
	}
	return p
}

func seam(t *testing.T, restricted string) (calls *[][]string) {
	t.Helper()
	dir := t.TempDir()
	oldR, oldD, oldL, oldP, oldE := RestrictPath, Dir, LoadedPath, Parser, euid
	t.Cleanup(func() { RestrictPath, Dir, LoadedPath, Parser, euid = oldR, oldD, oldL, oldP, oldE })
	RestrictPath, Dir, LoadedPath = filepath.Join(dir, "restrict"), filepath.Join(dir, "apparmor.d"), filepath.Join(dir, "profiles")
	if err := os.WriteFile(RestrictPath, []byte(restricted+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	var got [][]string
	Parser = func(args ...string) ([]byte, error) { got = append(got, args); return nil, nil }
	euid = func() int { return 0 }
	return &got
}

// TestProfileGrantsUsernsOnlyAndParses: the profile is `userns,` for one literal path, and the host's apparmor_parser accepts it (a broken twin is refused, so the check is not vacuous).
func TestProfileGrantsUsernsOnlyAndParses(t *testing.T) {
	text, err := Profile("/opt/Mark 1/resources/bin/mark1d")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "profile omium-mark1d \"/opt/Mark 1/resources/bin/mark1d\" flags=(unconfined) {\n  userns,\n") || strings.Count(text, ",\n") != 2 {
		t.Fatalf("profile:\n%s", text)
	}
	for _, bad := range []string{"", "mark1d", "/tmp/.mount_*/mark1d", "/a\"b", "/a{b,c}", "/a\nb"} {
		if _, err := Profile(bad); err == nil {
			t.Errorf("Profile(%q) accepted a path AppArmor would read as a pattern", bad)
		}
	}
	parser, err := exec.LookPath("apparmor_parser")
	if err != nil {
		t.Skip("apparmor_parser not installed")
	}
	dir := t.TempDir()
	check := func(body string) error {
		p := filepath.Join(dir, "p")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(parser, "-Q", "-K", p).CombinedOutput()
		if err != nil {
			return errors.New(string(out))
		}
		return nil
	}
	if err := check(text); err != nil {
		t.Fatalf("apparmor_parser refused the profile: %v", err)
	}
	if check(strings.Replace(text, "userns,", "userns", 1)) == nil {
		t.Fatal("apparmor_parser accepted a broken profile; the syntax check proves nothing")
	}
}

// TestInstallOnlyWhenRestrictedAndRootOwned: nothing is written when the kernel does not restrict user namespaces, a user-writable mark1d and a non-root caller are refused, and a real install writes, loads, reports and uninstalls exactly one file.
func TestInstallOnlyWhenRestrictedAndRootOwned(t *testing.T) {
	calls := seam(t, "0")
	if ok, err := Install(rootBinary(t)); ok || err != nil || len(*calls) != 0 {
		t.Fatalf("unrestricted host: installed=%v err=%v parser calls %v", ok, err, *calls)
	}
	if ok, _ := Check(rootBinary(t), "mark1"); !ok {
		t.Fatal("an unrestricted host fails doctor")
	}

	calls = seam(t, "1")
	userOwned := filepath.Join(t.TempDir(), "mark1d")
	if err := os.WriteFile(userOwned, []byte("x"), 0o755); err != nil { //nolint:gosec // G306: a stand-in executable
		t.Fatal(err)
	}
	if _, err := Install(userOwned); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("a user-writable mark1d got a profile: %v", err)
	}
	if ok, detail := Check(userOwned, "mark1"); ok || !strings.Contains(detail, "user-writable") {
		t.Fatalf("doctor on a user-writable mark1d: %v %s", ok, detail)
	}
	euid = func() int { return 1000 }
	if _, err := Install(rootBinary(t)); err == nil || !strings.Contains(err.Error(), "sudo") {
		t.Fatalf("a non-root install: %v", err)
	}
	if ok, detail := Check(rootBinary(t), "/usr/bin/mark1"); ok || !strings.Contains(detail, "sudo /usr/bin/mark1 apparmor install") {
		t.Fatalf("doctor without a profile: %v %s", ok, detail)
	}
	euid = func() int { return 0 }

	bin := rootBinary(t)
	if ok, err := Install(bin); !ok || err != nil {
		t.Fatalf("install: %v %v", ok, err)
	}
	b, err := os.ReadFile(ProfilePath())
	if err != nil || !strings.Contains(string(b), "\""+bin+"\"") {
		t.Fatalf("profile file: %s %v", b, err)
	}
	if len(*calls) != 1 || !slices.Equal((*calls)[0], []string{"-r", "-W", "-T", ProfilePath()}) {
		t.Fatalf("parser calls %v", *calls)
	}
	if ok, detail := Check(bin, "mark1"); !ok || !strings.Contains(detail, "readable by root only") {
		t.Fatalf("installed, load state unreadable: %v %s", ok, detail)
	}
	if err := os.WriteFile(LoadedPath, []byte("other (enforce)\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ok, _ := Check(bin, "mark1"); ok {
		t.Fatal("an installed but unloaded profile passes doctor")
	}
	if err := os.WriteFile(LoadedPath, []byte("omium-mark1d (unconfined)\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ok, detail := Check(bin, "mark1"); !ok || !strings.Contains(detail, "loaded") {
		t.Fatalf("loaded: %v %s", ok, detail)
	}
	if err := Uninstall(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(ProfilePath()); !errors.Is(err, os.ErrNotExist) || !slices.Equal((*calls)[1], []string{"-R", ProfilePath()}) {
		t.Fatalf("uninstall left %v, parser calls %v", err, *calls)
	}
	if entries, _ := os.ReadDir(Dir); len(entries) != 0 {
		t.Fatalf("install/uninstall left %v behind", entries)
	}

	Parser = func(...string) ([]byte, error) { return []byte("syntax error"), errors.New("exit 1") }
	if _, err := Install(bin); err == nil {
		t.Fatal("a profile the kernel refused reported installed")
	}
	if _, err := os.Stat(ProfilePath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a refused profile was left on disk")
	}
}
