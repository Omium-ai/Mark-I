package querychoke

// The visibility-layer class check (05 §6.1 layer 3, unit-lane edition of
// the §6.4 import negative): the raw-SQL surfaces added to chconn
// (QueryConn/OpenQuery and Conn.ExecTemplateWrite) must be referenced by NO
// code outside internal/querychoke — in particular not by ingest/chproj,
// whose sanctioned chconn borrowing is INSERT-shaped batch appends only.
// cmd/controld is the one wiring exception (MustOpenQuery at boot).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRawSQLSurfacesConfinedToQuerychoke(t *testing.T) {
	internalDir, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	forbidden := []string{"ExecTemplateWrite", "OpenQuery", "QueryConn", "OpenOffboard"}
	err = filepath.WalkDir(internalDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "querychoke" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, sym := range forbidden {
			if strings.Contains(string(src), sym) {
				t.Errorf("%s references %s — the raw-SQL chconn surface is confined to internal/querychoke (05 §6.1)", path, sym)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
