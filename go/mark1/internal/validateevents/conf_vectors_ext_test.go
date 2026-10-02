package validateevents

import (
	"os"
	"path/filepath"
	"testing"
)

// TestConfVectorsExtGoldenValidates is the ext conformance family's
// validator lane (conformance/vectors/ext/README.md): the frozen sample
// session passes `mark1 validate-events` with zero errors. A warning here is
// a finding too — the reference session is what a partner copies, and it
// must not teach a shape the validator complains about.
func TestConfVectorsExtGoldenValidates(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "..", "..", "..", "conformance", "vectors", "ext", "sample.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	rep, err := Validate(f)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK || len(rep.Errors) != 0 || len(rep.Warnings) != 0 {
		t.Fatalf("the frozen sample does not validate clean: errors %v warnings %v", rep.Errors, rep.Warnings)
	}
	if rep.Lines != 9 {
		t.Fatalf("validated %d lines, want the sample's 9", rep.Lines)
	}
}
