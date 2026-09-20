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
