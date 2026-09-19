//go:build unix

package adapters

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func plant(t *testing.T, dir, name string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\necho 1.2.3\n"), 0o755); err != nil { //nolint:gosec // G306: a fake executable
		t.Fatal(err)
	}
	return p
}

// TestLookPathFindsDesktopLaunchInstalls is the v0.1.0 "0 of 6 installed" repro: the daemon's PATH is a launchd/GNOME session PATH, the agent lives in a shell-rc-only dir.
func TestLookPathFindsDesktopLaunchInstalls(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	home := t.TempDir()
	if _, err := LookPath("claude", home); err == nil {
		t.Fatal("nothing planted yet: must report not found")
	}
	for _, tc := range []struct{ dir, name string }{
		{filepath.Join(home, ".local", "bin"), "claude"},
		{filepath.Join(home, ".nvm", "versions", "node", "v24.18.0", "bin"), "codex"},
		{filepath.Join(home, ".opencode", "bin"), "opencode"},
		{filepath.Join(home, ".claude", "local"), "claude-local"},
		{filepath.Join(home, ".local", "share", "fnm", "node-versions", "v22.0.0", "installation", "bin"), "gemini"},
	} {
		want := plant(t, tc.dir, tc.name)
		got, err := LookPath(tc.name, home)
		if err != nil || got != want {
			t.Fatalf("LookPath(%s) = %q, %v; want %q", tc.name, got, err, want)
		}
	}
	// Not executable ⇒ not an install.
	if err := os.Chmod(filepath.Join(home, ".local", "bin", "claude"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LookPath("claude", home); err == nil {
		t.Fatal("a non-executable file must not count as installed")
	}
}

// TestLookPathPrefersPATHAndNewestNode: PATH wins over the fallback, and of two nvm versions the newest by name is probed first.
func TestLookPathPrefersPATHAndNewestNode(t *testing.T) {
	home := t.TempDir()
	old := plant(t, filepath.Join(home, ".nvm", "versions", "node", "v20.1.0", "bin"), "claude")
	newer := plant(t, filepath.Join(home, ".nvm", "versions", "node", "v24.18.0", "bin"), "claude")
	t.Setenv("PATH", t.TempDir())
	if got, _ := LookPath("claude", home); got != newer {
		t.Fatalf("got %q, want the newest nvm bin %q (old %q)", got, newer, old)
	}
	onPath := plant(t, filepath.Join(home, "pathbin"), "claude")
	t.Setenv("PATH", filepath.Dir(onPath))
	if got, _ := LookPath("claude", home); got != onPath {
		t.Fatalf("got %q, want the PATH hit %q", got, onPath)
	}
	t.Setenv("PATH", t.TempDir())
	if _, err := LookPath("claude", filepath.Join(home, "nowhere")); err == nil {
		t.Fatal("PATH cleared and a home with no installs: must be not found")
	}
}

// TestLookPathPrefersNativeOverWSLInterop: under WSL the login PATH carries /mnt/c/…, where a Windows npm shim of the agent lives; the Linux install (nvm here) is this daemon's agent, the shim is the Windows daemon's. Only with no native install does the shim answer.
func TestLookPathPrefersNativeOverWSLInterop(t *testing.T) {
	home := t.TempDir()
	drive := filepath.Join(t.TempDir(), "Users", "u", "AppData", "Roaming", "npm")
	shim := plant(t, drive, "claude")
	saved := isInterop
	isInterop = func(p string) bool { return strings.HasPrefix(p, drive) }
	t.Cleanup(func() { isInterop = saved })
	t.Setenv("PATH", drive)
	if got, _ := LookPath("claude", home); got != shim {
		t.Fatalf("no native install: the shim is the only answer, got %q", got)
	}
	native := plant(t, filepath.Join(home, ".nvm", "versions", "node", "v24.18.0", "bin"), "claude")
	if got, _ := LookPath("claude", home); got != native {
		t.Fatalf("got %q, want the native install %q over the interop shim on PATH", got, native)
	}
	t.Setenv("WSL_DISTRO_NAME", "Ubuntu")
	isInterop = saved
	if !isInterop("/mnt/c/Users/u/AppData/Roaming/npm/claude") || isInterop("/home/u/.nvm/versions/node/v24.18.0/bin/claude") || isInterop("/mnt/wsl/x") {
		t.Fatal("isInterop must accept /mnt/<drive>/ paths only")
	}
}
