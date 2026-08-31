// The publisher is an ENCODER, and it was the only side of the bundle contract
// never driven by conformance/vectors/bundle/. The Rust reference decoder
// (rust/mark1-policy/tests/conf_vectors_bundle.rs) and the Go edge decoder
// (go/mark1d/internal/policy/conf_vectors_test.go) both replay the frozen
// vectors; controld replayed nothing. So controld shipped an `Inclusion` whose
// CBOR keys were audit_path/root_hash/key_id/sig against a frozen contract
// saying path/root -- and since both decoders call strict_keys, every bundle at
// seq > 0 was M1E-3003 on every device in the fleet. Two decoders agreeing with
// each other proves nothing when neither of them is what writes the bytes.
//
// These tests read the frozen artifact rather than restating it, so they cannot
// drift from it. See D-BF.
package policydist

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

const bundleVectorsDir = "../../../../conformance/vectors/bundle"

// inclusionKeysFromFrozenVector pulls the `inclusion` map's key set out of a
// committed vector. Decoding into map[string]any is fine here: we assert on key
// names only, and canonical ordering is bundle.go's separate concern.
func inclusionKeysFromFrozenVector(t *testing.T, file string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(bundleVectorsDir, file))
	if err != nil {
		t.Skipf("frozen vectors unavailable: %v", err)
	}
	var top map[string]any
	if err := cbor.Unmarshal(raw, &top); err != nil {
		t.Fatalf("decode %s: %v", file, err)
	}
	incl, ok := top["inclusion"].(map[any]any)
	if !ok {
		t.Fatalf("%s has no inclusion map (got %T)", file, top["inclusion"])
	}
	keys := make([]string, 0, len(incl))
	for k := range incl {
		s, ok := k.(string)
		if !ok {
			t.Fatalf("%s: non-string inclusion key %v", file, k)
		}
		keys = append(keys, s)
	}
	sort.Strings(keys)
	return keys
}

func TestInclusionWireKeysMatchFrozenVectors(t *testing.T) {
	want := inclusionKeysFromFrozenVector(t, "full.cbor")

	raw, err := canonEnc.Marshal(&Inclusion{
		TreeSize: 3, LeafIndex: 1,
		AuditPath: [][]byte{make([]byte, 32), make([]byte, 32)},
		RootHash:  make([]byte, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := cbor.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(got))
	for k := range got {
		names = append(names, k)
	}
	sort.Strings(names)

	if len(names) != len(want) {
		t.Fatalf("inclusion key set %v, frozen contract %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("inclusion key set %v, frozen contract %v", names, want)
		}
	}
}

// The failure mode this whole file exists for is an EXTRA key, not just a
// missing one: both decoders use strict-key maps, so a field added to Inclusion
// "for debugging" is as fatal as a renamed one, and it is the change most
// likely to look harmless in review.
func TestInclusionRejectsExtraWireKeys(t *testing.T) {
	want := inclusionKeysFromFrozenVector(t, "full.cbor")
	for _, k := range want {
		switch k {
		case "leaf_index", "tree_size", "path", "root":
		default:
			t.Fatalf("frozen vector carries unexpected inclusion key %q -- "+
				"the contract moved and this package has not", k)
		}
	}
	if len(want) != 4 {
		t.Fatalf("frozen inclusion contract has %d keys, expected 4: %v", len(want), want)
	}
}
