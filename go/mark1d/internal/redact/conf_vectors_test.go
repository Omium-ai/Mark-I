// TestConfVectorsRedact drives conformance/vectors/redact/ — the frozen
// Rust↔Go byte contract for the admit axis (12 §3.4). The `ConfVectors` name
// prefix is load-bearing: conformance_crosslang.sh selects Go tests with
// -run ConfVectors, and a run that executes zero vector tests is a failed
// run, not a passed one.
package redact

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const vectorsDir = "../../../../conformance/vectors/redact"

type vectorExp struct {
	Outcome       string   `json:"outcome"`
	Substitutions uint32   `json:"substitutions"`
	Classes       []string `json:"classes"`
	Planted       []string `json:"planted"`
}

type manifest struct {
	HmacKeyUTF8 string               `json:"hmac_key_utf8"`
	Vectors     map[string]vectorExp `json:"vectors"`
}

func TestConfVectorsRedact(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(vectorsDir, "manifest.json"))
	if err != nil {
		t.Fatalf("frozen vectors missing (12 §3.4): %v", err)
	}
	var man manifest
	if err := json.Unmarshal(raw, &man); err != nil {
		t.Fatal(err)
	}
	if len(man.Vectors) == 0 {
		t.Fatal("empty manifest proves nothing")
	}
	sc, err := NewScanner([]byte(man.HmacKeyUTF8))
	if err != nil {
		t.Fatal(err)
	}
	for name, exp := range man.Vectors {
		t.Run(name, func(t *testing.T) {
			input, err := os.ReadFile(filepath.Join(vectorsDir, name))
			if err != nil {
				t.Fatal(err)
			}
			wantOut, err := os.ReadFile(filepath.Join(vectorsDir, strings.Replace(name, ".in", ".out", 1)))
			if err != nil {
				t.Fatal(err)
			}
			got, outcome, subs := sc.Admit(append([]byte(nil), input...))
			// Bit-identical output is the whole contract (NFR-CORRECTNESS-005):
			// these must be the same bytes the Rust reference froze.
			if !bytes.Equal(got, wantOut) {
				t.Fatalf("output bytes diverge from the frozen vector:\n got %q\nwant %q", got, wantOut)
			}
			switch exp.Outcome {
			case "clean":
				if outcome != Clean {
					t.Fatalf("outcome = %v, want Clean", outcome)
				}
			case "redacted":
				if outcome != Redacted || subs != exp.Substitutions {
					t.Fatalf("outcome = %v/%d, want Redacted/%d", outcome, subs, exp.Substitutions)
				}
				for _, planted := range exp.Planted {
					if bytes.Contains(got, []byte(planted)) {
						t.Fatalf("planted secret survives (CON-008): %q", planted)
					}
				}
			default:
				t.Fatalf("unknown outcome %q", exp.Outcome)
			}
		})
	}
}
