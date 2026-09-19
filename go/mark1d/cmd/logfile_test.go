package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLogFileRotatesOncePastEightMiB(t *testing.T) {
	state := t.TempDir()
	f, err := openLogFile(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(9 << 20); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if _, err := openLogFile(state); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(state, "logs", "mark1d.log.1")); err != nil {
		t.Fatal("the full log was not rotated aside:", err)
	}
	if st, _ := os.Stat(filepath.Join(state, "logs", "mark1d.log")); st.Size() != 0 {
		t.Fatalf("fresh log has %d bytes", st.Size())
	}
}
