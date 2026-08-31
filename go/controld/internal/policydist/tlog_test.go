package policydist

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/google/uuid"
)

// rfc6962Verify is RFC 6962 §2.1.1's verification algorithm, written
// bottom-up and independently of tlog.go's top-down recursion. It exists to be
// a SECOND opinion: the edge will implement something shaped like this, and the
// only way to know our proofs are in the right order is to check them with an
// algorithm that walks the tree the other way. (The first version of
// VerifyInclusion consumed a leaf-to-root path with root-to-leaf split
// arithmetic — correct for the right-most leaf, which is the only one the
// publisher self-checks, and wrong for most others. This function is what
// makes that class of bug fail loudly.)
func rfc6962Verify(leaf []byte, index, size uint64, path [][]byte, root [32]byte) bool {
	if size == 0 || index >= size {
		return false
	}
	fn, sn := index, size-1
	r := LeafHash(leaf)
	for _, p := range path {
		if sn == 0 {
			return false
		}
		if len(p) != 32 {
			return false
		}
		s := [32]byte(p)
		if fn&1 == 1 || fn == sn {
			r = nodeHash(s, r)
			for fn != 0 && fn&1 == 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = nodeHash(r, s)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && r == root
}

func testLeaves(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, uint64(i)*0x9e3779b97f4a7c15)
		out[i] = b
	}
	return out
}

func TestLeafAndNodeDomainSeparation(t *testing.T) {
	d := []byte("bundle body hash")
	want := sha256.Sum256(append([]byte{0x00}, d...))
	if LeafHash(d) != want {
		t.Fatal("LeafHash is not SHA-256(0x00 || d)")
	}
	// Second-preimage resistance: an interior node presented as a leaf must not
	// produce the same hash, or a proof for a subtree becomes a proof for a
	// value that was never logged.
	l, r := LeafHash([]byte("a")), LeafHash([]byte("b"))
	inner := nodeHash(l, r)
	if LeafHash(append(l[:], r[:]...)) == inner {
		t.Fatal("a leaf and an interior node hash the same way")
	}
}

func TestSplitPointIsRFC6962K(t *testing.T) {
	// The largest power of two STRICTLY less than n. The "round up" variant
	// gives 2 for n=2 and breaks the prefix property consistency proofs need.
	for n, want := range map[int]int{2: 1, 3: 2, 4: 2, 5: 4, 7: 4, 8: 4, 9: 8, 16: 8, 17: 16} {
		if got := splitPoint(n); got != want {
			t.Fatalf("splitPoint(%d) = %d, want %d", n, got, want)
		}
	}
}

func TestMerkleRootShape(t *testing.T) {
	if _, err := MerkleRoot(nil); err == nil {
		t.Fatal("the empty tree must have no signed root; tlog_signed_heads CHECKs tree_size >= 1")
	}
	one := testLeaves(1)
	r1, err := MerkleRoot(one)
	if err != nil {
		t.Fatal(err)
	}
	if r1 != LeafHash(one[0]) {
		t.Fatal("MTH of a single leaf must be that leaf's hash")
	}
	two := testLeaves(2)
	r2, err := MerkleRoot(two)
	if err != nil {
		t.Fatal(err)
	}
	if r2 != nodeHash(LeafHash(two[0]), LeafHash(two[1])) {
		t.Fatal("MTH of two leaves must be the node hash of the two leaf hashes")
	}
	// Unbalanced: MTH(3) splits 2|1, not 1|2. Getting this backwards produces a
	// tree that is not a prefix of the next one.
	three := testLeaves(3)
	r3, err := MerkleRoot(three)
	if err != nil {
		t.Fatal(err)
	}
	want3 := nodeHash(r2, LeafHash(three[2]))
	if r3 != want3 {
		t.Fatal("MTH(3) is not MTH(first 2) || MTH(last 1)")
	}
	// Prefix property: appending never changes the left subtree of the new root.
	if r3 == r2 {
		t.Fatal("appending a leaf did not change the root")
	}
}

func TestInclusionProofsRoundTripAgainstAnIndependentVerifier(t *testing.T) {
	checked := 0
	for size := 1; size <= 17; size++ {
		leaves := testLeaves(size)
		root, err := MerkleRoot(leaves)
		if err != nil {
			t.Fatal(err)
		}
		for index := 0; index < size; index++ {
			path, err := InclusionProof(leaves, index)
			if err != nil {
				t.Fatalf("size %d index %d: %v", size, index, err)
			}
			if !rfc6962Verify(leaves[index], uint64(index), uint64(size), path, root) {
				t.Fatalf("size %d index %d: proof fails the RFC 6962 bottom-up verifier (path order is wrong)", size, index)
			}
			if !VerifyInclusion(leaves[index], uint64(index), uint64(size), path, root) {
				t.Fatalf("size %d index %d: proof fails our own verifier", size, index)
			}
			checked++

			// Negative cases. A verifier that accepts everything passes every
			// positive test ever written.
			if size > 1 {
				bad := make([][]byte, len(path))
				copy(bad, path)
				tampered := make([]byte, 32)
				copy(tampered, bad[0])
				tampered[0] ^= 0xff
				bad[0] = tampered
				if VerifyInclusion(leaves[index], uint64(index), uint64(size), bad, root) {
					t.Fatalf("size %d index %d: a tampered audit path verified", size, index)
				}
			}
			if VerifyInclusion([]byte("not the logged leaf"), uint64(index), uint64(size), path, root) {
				t.Fatalf("size %d index %d: a proof verified for a leaf that was never logged", size, index)
			}
			if VerifyInclusion(leaves[index], uint64(index), uint64(size), append(path, make([]byte, 32)), root) {
				t.Fatalf("size %d index %d: an over-long path verified", size, index)
			}
			if index+1 < size && VerifyInclusion(leaves[index], uint64(index+1), uint64(size), path, root) {
				t.Fatalf("size %d: a proof verified at the wrong index", size)
			}
		}
	}
	// Tripwire: 17 sizes, one proof per leaf = 153. If the loop bounds ever
	// collapse, this test must go red rather than pass having proved nothing.
	if checked != 153 {
		t.Fatalf("checked %d proofs, want 153", checked)
	}
	if _, err := InclusionProof(testLeaves(4), 4); err == nil {
		t.Fatal("an out-of-range leaf index produced a proof")
	}
}

func TestVerifyInclusionRejectsDegenerateInputs(t *testing.T) {
	leaves := testLeaves(4)
	root, _ := MerkleRoot(leaves)
	path, _ := InclusionProof(leaves, 1)
	for _, tc := range []struct {
		name        string
		index, size uint64
		path        [][]byte
	}{
		{"empty tree", 0, 0, path},
		{"index past size", 4, 4, path},
		{"short sibling", 1, 4, [][]byte{{1, 2, 3}, path[1]}},
		{"empty path for a real tree", 1, 4, nil},
		// Without the maxTreeSize bound this case does not fail -- it spins,
		// because splitPoint() saturates at 1 for a size that does not fit an
		// int and the descent then walks down one leaf at a time.
		{"size beyond the sanity ceiling", 1, 1 << 62, path},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if VerifyInclusion(leaves[1], tc.index, tc.size, tc.path, root) {
				t.Fatal("accepted")
			}
		})
	}
}

func TestTLogHeadSigningInputIsBoundToTenantAndSize(t *testing.T) {
	a := uuid.MustParse("6f1c8b2e-6a5f-4e70-9f1a-2b6c9d3e4f50")
	b := uuid.MustParse("6f1c8b2e-6a5f-4e70-9f1a-2b6c9d3e4f51")
	root, _ := MerkleRoot(testLeaves(3))
	base, err := TLogHeadSigningInput(a, 3, root)
	if err != nil {
		t.Fatal(err)
	}
	if string(base[:len(TLogHeadDomainPrefix)]) != TLogHeadDomainPrefix {
		t.Fatal("head signing input is not domain-separated from bundle and receipt signatures")
	}
	other, _ := TLogHeadSigningInput(b, 3, root)
	if string(other) == string(base) {
		t.Fatal("a head signed for one tenant would verify against another tenant's log")
	}
	bigger, _ := TLogHeadSigningInput(a, 4, root)
	if string(bigger) == string(base) {
		t.Fatal("tree_size is not covered by the head signature")
	}
	if TLogHeadDomainPrefix == BundleDomainPrefix {
		t.Fatal("a bundle signature and a log head signature would be interchangeable")
	}
}

// Cheap belt-and-braces on the prefix property the whole log depends on: a
// tree of size n must be a prefix of the tree of size n+1, i.e. every proof
// issued at size n still names leaves that are still there.
func TestAppendOnlyPrefixProperty(t *testing.T) {
	for n := 1; n < 12; n++ {
		small := testLeaves(n)
		big := testLeaves(n + 1)
		for i := range small {
			if fmt.Sprintf("%x", small[i]) != fmt.Sprintf("%x", big[i]) {
				t.Fatalf("leaf %d changed between size %d and %d", i, n, n+1)
			}
		}
		rn, _ := MerkleRoot(small)
		rn1, _ := MerkleRoot(big)
		if rn == rn1 {
			t.Fatalf("root did not change from size %d to %d", n, n+1)
		}
	}
}
