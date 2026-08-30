// Checkpoint Merkle — RFC 6962 shape with BLAKE3 (04 §7.2 names BLAKE3;
// 05 §4.4's tlog is already 6962: one tree discipline product-wide). The
// device batches N events, builds the root over their event_ids, and
// origin-signs a checkpoint receipt carrying it (plan C13, 07's receipts
// section); the server recomputes the same root over the leaves it landed
// (05 §2.1 stage 11's pending-leaf set) before it will countersign.
// Construction pinned by conformance/vectors/receipt/README.md §Merkle;
// copy of go/mark1d/internal/identity/merkle.go (the twin precedent, see
// canonical.go's header).

package receipts

import (
	"fmt"

	"lukechampine.com/blake3"
)

// LeafSize: leaves are 16-byte event_ids (UUIDv7 raw bytes), per the vectors.
const LeafSize = 16

// The 0x00/0x01 prefixes are 6962's second-preimage domain separation: an
// interior node can never be replayed as a leaf.
func leafHash(leaf []byte) [32]byte {
	buf := make([]byte, 1+len(leaf))
	copy(buf[1:], leaf)
	return blake3.Sum256(buf)
}

func nodeHash(left, right [32]byte) [32]byte {
	buf := make([]byte, 1+64)
	buf[0] = 0x01
	copy(buf[1:33], left[:])
	copy(buf[33:], right[:])
	return blake3.Sum256(buf)
}

func checkLeaves(leaves [][]byte) error {
	if len(leaves) == 0 {
		return fmt.Errorf("receipts: a checkpoint over zero events has no root to sign")
	}
	for i, l := range leaves {
		if len(l) != LeafSize {
			return fmt.Errorf("receipts: leaf %d is %d bytes, event_ids are %d", i, len(l), LeafSize)
		}
	}
	return nil
}

// largest power of two strictly less than n (6962's split; requires n >= 2).
func splitPoint(n int) int {
	k := 1
	for k*2 < n {
		k *= 2
	}
	return k
}

// MerkleRoot is what the device origin-signs into the checkpoint payload and
// what the server must reproduce from its own landed leaves. Odd counts split
// unbalanced — no leaf duplication, which is the CVE-2012-2459 shape
// (vectors README).
func MerkleRoot(leaves [][]byte) ([32]byte, error) {
	if err := checkLeaves(leaves); err != nil {
		return [32]byte{}, err
	}
	return merkleRoot(leaves), nil
}

func merkleRoot(leaves [][]byte) [32]byte {
	if len(leaves) == 1 {
		return leafHash(leaves[0])
	}
	k := splitPoint(len(leaves))
	return nodeHash(merkleRoot(leaves[:k]), merkleRoot(leaves[k:]))
}

// InclusionPath is the 6962 audit path for leaves[index], bottom-up sibling
// subtree roots — the order m1_receipts.inclusion_path stores (concatenated
// 32-byte hashes).
func InclusionPath(leaves [][]byte, index int) ([][32]byte, error) {
	if err := checkLeaves(leaves); err != nil {
		return nil, err
	}
	if index < 0 || index >= len(leaves) {
		return nil, fmt.Errorf("receipts: leaf index %d outside [0,%d)", index, len(leaves))
	}
	return inclusionPath(leaves, index), nil
}

func inclusionPath(leaves [][]byte, index int) [][32]byte {
	if len(leaves) == 1 {
		return nil
	}
	k := splitPoint(len(leaves))
	if index < k {
		return append(inclusionPath(leaves[:k], index), merkleRoot(leaves[k:]))
	}
	return append(inclusionPath(leaves[k:], index-k), merkleRoot(leaves[:k]))
}

// RootFromPath recomputes the root a (leaf, index, path) triple claims
// membership under, walking the path top-down from its END (the path is
// stored bottom-up) so the tree shape is exactly MerkleRoot's. A wrong-LENGTH
// path is an error, not a mismatched root: the vectors name truncation
// `inclusion_path_invalid` explicitly ("wrong length included").
func RootFromPath(leaf []byte, index, size int, path [][32]byte) ([32]byte, error) {
	if len(leaf) != LeafSize {
		return [32]byte{}, fmt.Errorf("receipts: leaf is %d bytes, event_ids are %d", len(leaf), LeafSize)
	}
	if size < 1 || index < 0 || index >= size {
		return [32]byte{}, fmt.Errorf("receipts: leaf index %d outside tree of %d", index, size)
	}
	return rootFromPath(leafHash(leaf), index, size, path)
}

func rootFromPath(acc [32]byte, index, size int, path [][32]byte) ([32]byte, error) {
	if size == 1 {
		if len(path) != 0 {
			return [32]byte{}, fmt.Errorf("receipts: inclusion path has %d extra hash(es)", len(path))
		}
		return acc, nil
	}
	if len(path) == 0 {
		return [32]byte{}, fmt.Errorf("receipts: inclusion path truncated (tree of %d still unresolved)", size)
	}
	sibling, rest := path[len(path)-1], path[:len(path)-1]
	k := splitPoint(size)
	if index < k {
		sub, err := rootFromPath(acc, index, k, rest)
		if err != nil {
			return [32]byte{}, err
		}
		return nodeHash(sub, sibling), nil
	}
	sub, err := rootFromPath(acc, index-k, size-k, rest)
	if err != nil {
		return [32]byte{}, err
	}
	return nodeHash(sibling, sub), nil
}
