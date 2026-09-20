//go:build unix

package evidence

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPutIsPrivateAndLocal(t *testing.T) {
	state := t.TempDir()
	s, err := Open(state)
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(Dir(state)); st.Mode().Perm() != 0o700 {
		t.Fatalf("evidence dir mode %o, want 0700", st.Mode().Perm())
	}
	ref, err := s.Put([16]byte{1}, "ruff@cat-1", []byte("out"), nil, []byte("+ diff"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ref, Dir(state)) {
		t.Fatalf("ref %q escapes the store", ref)
	}
	for _, f := range []string{"stdout", "diff"} {
		st, err := os.Stat(filepath.Join(ref, f))
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("%s: err %v mode %v, want 0600", f, err, st)
		}
	}
	if _, err := os.Stat(filepath.Join(ref, "stderr")); !os.IsNotExist(err) {
		t.Fatal("empty part was written")
	}
	var nilStore *Store
	if ref, err := nilStore.Put([16]byte{}, "x", []byte("y"), nil, nil); ref != "" || err != nil {
		t.Fatalf("nil store wrote: %q %v", ref, err)
	}
}

// Runs older than the 30 d ruling are swept at boot and a task dir left empty with them; younger runs and their task dirs stay.
func TestSweepKeepsRetentionAndDropsEmptyTaskDirs(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var oldTask, newTask [16]byte
	oldTask[0], newTask[0] = 1, 2
	oldRun, err := st.Put(oldTask, "ruff@cat-1", []byte("x"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Put(newTask, "ruff@cat-1", []byte("y"), nil, nil); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-Retention - time.Hour)
	if err := os.Chtimes(oldRun, past, past); err != nil {
		t.Fatal(err)
	}
	if n := st.Sweep(time.Now()); n != 1 {
		t.Fatalf("swept %d runs, want 1", n)
	}
	if _, err := os.Stat(filepath.Dir(oldRun)); !os.IsNotExist(err) {
		t.Fatal("the emptied task dir must go with its last run")
	}
	if entries, _ := os.ReadDir(filepath.Join(st.dir, "02000000000000000000000000000000")); len(entries) != 1 {
		t.Fatalf("the young task lost runs: %v", entries)
	}
}
