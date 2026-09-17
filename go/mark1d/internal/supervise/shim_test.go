package supervise

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestInstallShimCopiesTheSiblingIntoStateBin: absent ⇒ copied 0755 with no tmp left behind; equal ⇒ untouched; a stale copy ⇒ replaced; a newer user-installed one ⇒ kept and logged; no sibling ⇒ nothing.
func TestInstallShimCopiesTheSiblingIntoStateBin(t *testing.T) {
	src, state := t.TempDir(), t.TempDir()
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	packaged := filepath.Join(src, shimBinary)
	dst := ShimPath(state)
	if runtime.GOOS == "windows" {
		packaged, dst = packaged+".exe", dst+".exe"
	}

	if err := installShim(src, state, log); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatalf("no sibling, yet something was installed: %v", err)
	}

	if err := os.WriteFile(packaged, []byte("#!/bin/sh\necho v1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := installShim(src, state, log); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o755 {
		t.Fatalf("mode %o, want 0755", fi.Mode().Perm())
	}
	if b, _ := os.ReadFile(dst); string(b) != "#!/bin/sh\necho v1\n" {
		t.Fatalf("installed bytes %q", b)
	}
	if _, err := os.Stat(dst + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("tmp file left behind")
	}
	if !strings.Contains(logs.String(), "installed the packaged mark1-hookshim") {
		t.Fatalf("no install log: %s", logs.String())
	}

	logs.Reset()
	if err := installShim(src, state, log); err != nil {
		t.Fatal(err)
	}
	if logs.Len() != 0 {
		t.Fatalf("an equal shim must be silent: %s", logs.String())
	}

	old := time.Now().Add(-2 * time.Hour)
	if err := os.WriteFile(dst, []byte("#!/bin/sh\necho stale\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(dst, old, old); err != nil {
		t.Fatal(err)
	}
	if err := installShim(src, state, log); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(dst); string(b) != "#!/bin/sh\necho v1\n" {
		t.Fatalf("a stale copy was not replaced: %q", b)
	}

	logs.Reset()
	if err := os.WriteFile(dst, []byte("#!/bin/sh\necho mine\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(packaged, old, old); err != nil {
		t.Fatal(err)
	}
	if err := installShim(src, state, log); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(dst); string(b) != "#!/bin/sh\necho mine\n" {
		t.Fatalf("a newer user-installed shim was clobbered: %q", b)
	}
	if !strings.Contains(logs.String(), "keeping a user-installed mark1-hookshim") {
		t.Fatalf("no keep log: %s", logs.String())
	}
}
