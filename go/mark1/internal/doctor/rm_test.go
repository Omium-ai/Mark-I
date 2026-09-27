package doctor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRMRuntimeCheck(t *testing.T) {
	dir := t.TempDir()
	if c := rmRuntimeCheck(dir); !c.OK || !strings.Contains(c.Detail, "not started") {
		t.Fatalf("no status file is not a failure: %+v", c)
	}
	write := func(body string) {
		if err := os.MkdirAll(filepath.Join(dir, "rm"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "rm", "status.json"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"state":"ready","model_id":"rm:m1-a@1","detail":"runtime supervised"}`)
	if c := rmRuntimeCheck(dir); !c.OK || c.Detail != "ready rm:m1-a@1: runtime supervised" {
		t.Fatalf("ready: %+v", c)
	}
	write(`{"state":"failed","model_id":"rm:m1-a@1","detail":"runtime crash-looped"}`)
	if c := rmRuntimeCheck(dir); c.OK {
		t.Fatalf("a crash-looped runtime must fail doctor: %+v", c)
	}
}
