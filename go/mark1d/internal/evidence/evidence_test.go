//go:build unix

package evidence

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
