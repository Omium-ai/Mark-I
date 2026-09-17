package provision

import (
	"os"
	"path/filepath"
	"testing"
)

// The walk itself is driven end to end by `mark1 enable`/`off` (go/mark1/internal/enable, off) and the control API (go/mark1d/internal/control); this pins the two seams they do not reach.
func TestOnlyAndScopedLeftovers(t *testing.T) {
	dir := t.TempDir()
	if _, err := Apply(Options{StateDir: dir, Only: []string{"crush"}}); err == nil {
		t.Fatal("an unknown agent name must be refused, not skipped")
	}
	foreign := filepath.Join(dir, "provisioned", "zzz", "hooks.manifest.json")
	if err := os.MkdirAll(filepath.Dir(foreign), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(foreign, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if done, left := Revert(dir, "codex"); len(done) != 0 || len(left) != 0 {
		t.Fatalf("a per-agent revert lists only that agent's leftovers: %v %v", done, left)
	}
	if done, left := Revert(dir); len(done) != 0 || len(left) != 1 || left[0] != foreign {
		t.Fatalf("a full revert lists every manifest still on disk: %v %v", done, left)
	}
}
