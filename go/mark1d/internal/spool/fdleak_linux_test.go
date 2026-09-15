//go:build linux

package spool

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// openFDs counts this process's open descriptors. Linux-only because
// /proc/self/fd is the only portable-enough way to read the number back
// without a seam in the spool; the leak it guards is platform-neutral.
func openFDs(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(ents)
}

// TestRefusedOpenLeaksNoDescriptor pins the refused-boot paths of Open closing
// everything they opened. Two refusals, because they leave different files
// behind: a second Open on a HELD spool is turned away inside lockDir with
// only the lock fd open, while a recovery refusal (here an alien seg-*.m1s
// name, listSegments' "operator problem") has already taken the lock and
// opened the ledger — the path that once closed only the lock. On Windows the
// leaked handle also pins the file against deletion; here it is just an fd
// that outlives every error message about it.
func TestRefusedOpenLeaksNoDescriptor(t *testing.T) {
	held := t.TempDir()
	s, err := Open(testConfig(held, 1<<20, 1<<30))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()

	alien := filepath.Join(t.TempDir(), "spool")
	if err := os.MkdirAll(alien, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(alien, "seg-alien.m1s"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ name, dir, want string }{
		{"second Open on a held spool", held, "already open by another mark1d"},
		{"recovery refusal after the lock is taken", alien, "alien file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := openFDs(t)
			second, err := Open(testConfig(tc.dir, 1<<20, 1<<30))
			if err == nil {
				_ = second.Close()
				t.Fatal("Open succeeded, want a refusal")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refused for %v, want %q — the wrong refusal proves nothing about this path", err, tc.want)
			}
			if got := openFDs(t); got != before {
				t.Fatalf("refused Open leaked %d descriptor(s) (%d open before, %d after)", got-before, before, got)
			}
		})
	}
}
