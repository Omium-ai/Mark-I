package control

import (
	"os"
	"path/filepath"
	"testing"
)

// The home directory, / and a drive root are never offered as the project to watch.
func TestTooBroadRoots(t *testing.T) {
	home, _ := os.UserHomeDir()
	for p, want := range map[string]bool{home: true, filepath.Join(home, "work", "repo"): false, string(filepath.Separator): true} {
		if got := tooBroad(p); got != want {
			t.Errorf("tooBroad(%q) = %v, want %v", p, got, want)
		}
	}
}

// A Windows path into a WSL distro is refused as a project: the WSL lane exists for it.
func TestWSLSharesAreNotProjects(t *testing.T) {
	for p, want := range map[string]bool{
		`\\wsl.localhost\Ubuntu\home\u\repo`: true,
		`\\wsl$\Ubuntu\home\u\repo`:          true,
		`//wsl.localhost/Ubuntu/home/u/repo`: true,
		`C:\Users\u\repo`:                    false,
		`/home/u/repo`:                       false,
	} {
		if got := isWSLShare(p); got != want {
			t.Errorf("isWSLShare(%q) = %v, want %v", p, got, want)
		}
	}
}
