package adapters

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
)

// LookPath is exec.LookPath plus the install dirs a desktop-launched or service-supervised daemon's PATH lacks (launchd/systemd --user/GNOME hand it /usr/bin:/bin; nvm, ~/.local/bin and Homebrew live in shell rc files).
func LookPath(name, home string) (string, error) {
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	for _, d := range installDirs(home) {
		if p, err := exec.LookPath(filepath.Join(d, name)); err == nil {
			return p, nil
		}
	}
	return "", exec.ErrNotFound
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
