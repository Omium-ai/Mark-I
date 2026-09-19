package adapters

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
)

// LookPath is exec.LookPath plus the install dirs a desktop-launched or service-supervised daemon's PATH lacks (launchd/systemd --user/GNOME hand it /usr/bin:/bin; nvm, ~/.local/bin and Homebrew live in shell rc files).
// Under WSL the login PATH also carries every Windows dir (/mnt/c/…), so a Windows npm shim of the same agent can shadow the Linux install; that one is the Windows daemon's agent, never this one's — a native hit from the install dirs wins over it, and it is the answer only when nothing native exists.
func LookPath(name, home string) (string, error) {
	interop := ""
	if p, err := exec.LookPath(name); err == nil {
		if !isInterop(p) {
			return p, nil
		}
		interop = p
	}
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	for _, d := range installDirs(home) {
		if p, err := exec.LookPath(filepath.Join(d, name)); err == nil {
			return p, nil
		}
	}
	if interop != "" {
		return interop, nil
	}
	return "", exec.ErrNotFound
}

// isInterop: a Linux path under a WSL drive mount (/mnt/<drive>/…) resolves to a Windows program through binfmt interop. A var so a test can name its own mount.
var isInterop = func(p string) bool {
	if runtime.GOOS != "linux" || os.Getenv("WSL_DISTRO_NAME") == "" && os.Getenv("WSL_INTEROP") == "" {
		return false
	}
	return len(p) > 6 && strings.HasPrefix(p, "/mnt/") && p[6] == '/'
}

func installDirs(home string) []string {
	if home == "" {
		return nil
	}
	if runtime.GOOS == "windows" {
		return []string{
			filepath.Join(os.Getenv("APPDATA"), "npm"),
			filepath.Join(home, ".local", "bin"),
			filepath.Join(home, ".opencode", "bin"),
			filepath.Join(home, ".bun", "bin"),
		}
	}
	dirs := []string{
		filepath.Join(home, ".local", "bin"),
		filepath.Join(home, ".claude", "local"),
		filepath.Join(home, ".npm-global", "bin"),
		filepath.Join(home, ".volta", "bin"),
		filepath.Join(home, ".bun", "bin"),
		filepath.Join(home, ".opencode", "bin"),
		"/opt/homebrew/bin",
		"/usr/local/bin",
	}
	// ponytail: newest nvm/fnm node wins by name sort, not the `default` alias; resolve the alias if two installed versions ever disagree.
	for _, g := range []string{
		filepath.Join(home, ".nvm", "versions", "node", "*", "bin"),
		filepath.Join(home, ".local", "share", "fnm", "node-versions", "*", "installation", "bin"),
		filepath.Join(home, "Library", "Application Support", "fnm", "node-versions", "*", "installation", "bin"),
	} {
		m, _ := filepath.Glob(g)
		slices.Sort(m)
		slices.Reverse(m)
		dirs = append(dirs, m...)
	}
	return dirs
}
