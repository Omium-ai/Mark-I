// The transparency log: RFC 6962 Merkle tree over SHA-256 (05 §4.4).
//
// WHY NOT receipts/merkle.go. That tree is BLAKE3 with 16-byte leaves and its
// shape is frozen by the conformance vectors -- it is the checkpoint tree, and
// changing either parameter breaks every device-signed checkpoint ever issued.
// 05 §4.4 specifies this log as "RFC 6962 shape: leaves are SHA-256(bundle
// canonical bytes)". Two trees, two hash functions, no shared code: the sixty
// lines below are cheaper than a parameterised tree whose call sites decide
// which set of frozen vectors they are about to violate.
//
// Head signing uses the log key class, not a bundle section key (05 §4.4): "a
// bundle-key compromise must not allow rewriting log history". Domain prefix
// keeps the two apart even under key reuse.

package policydist

import (
	"crypto/sha256"
	"fmt"

	"github.com/google/uuid"
)

// TLogHeadDomainPrefix separates a signed log head from every other signature
// in the estate.
const TLogHeadDomainPrefix = "mark1-tlog-head-v1\x00"

// The leaf kinds this package appends (m1_062's CHECK admits a third,
// receipt_chain_head, which the witness job owns). One tree, kind-tagged:
// a head signed after a manifest leaf covers every bundle AND the keys that
// signed them, which is what makes a rotation auditable from one root.
const (
	LeafKindPolicyBundle = "policy_bundle"
	LeafKindKeyManifest  = "key_manifest"
)

// RFC 6962 §2 domain separation: leaves are hashed under 0x00, interior nodes
// under 0x01. Without it, an interior node can be presented as a leaf and a
// proof for a subtree becomes a proof for a value that was never logged.
const (
	leafPrefix = 0x00
	nodePrefix = 0x01
)

// LeafHash is MTH({d}) = SHA-256(0x00 || d). d for a policy bundle is the
// 32-byte SHA-256 of the canonical body minus `inclusion` -- i.e.
// policy_bundles.body_sha256, which is why tlog_leaves stores the unprefixed
// hash: prefixing at rest would make the stored leaf unequal to the column it
// is supposed to be comparable with.
func LeafHash(d []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{leafPrefix})
	h.Write(d)
	return [32]byte(h.Sum(nil))
}

func nodeHash(l, r [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{nodePrefix})
	h.Write(l[:])
	h.Write(r[:])
	return [32]byte(h.Sum(nil))
}

// maxTreeSize is a sanity ceiling, not a product limit: a billion leaves is
// far more publications than any tenant will ever make, and it keeps the int
// conversions below in range even where int is 32 bits.
const maxTreeSize = 1 << 30

// splitPoint is RFC 6962's k: the largest power of two strictly less than n.
// This asymmetric split (not the "round up to a power of two" variant) is what
// makes a tree of size n a prefix of a tree of size n+1, which is what makes
// consistency proofs possible at all.
func splitPoint(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}

// MerkleRoot computes MTH(leaves) where each element is already a leaf
// PREIMAGE (LeafHash is applied here).
func MerkleRoot(leaves [][]byte) ([32]byte, error) {
	if len(leaves) == 0 {
		// RFC 6962 defines MTH({}) = SHA-256(""), but tlog_signed_heads
		// CHECKs tree_size >= 1: an empty log has no head worth signing, and
		// a signature over "the empty tree" is a fact nobody needs.
		return [32]byte{}, fmt.Errorf("policydist: the empty tree has no signed root")
	}
	hashes := make([][32]byte, len(leaves))
	for i, l := range leaves {
		hashes[i] = LeafHash(l)
	}
	return rootOf(hashes), nil
}

func rootOf(h [][32]byte) [32]byte {
	if len(h) == 1 {
		return h[0]
	}
	k := splitPoint(len(h))
	return nodeHash(rootOf(h[:k]), rootOf(h[k:]))
}

// InclusionProof returns the audit path for leaves[index], leaf-to-root.
func InclusionProof(leaves [][]byte, index int) ([][]byte, error) {
	if index < 0 || index >= len(leaves) {
		return nil, fmt.Errorf("policydist: leaf index %d out of range for a tree of %d", index, len(leaves))
	}
	hashes := make([][32]byte, len(leaves))
	for i, l := range leaves {
		hashes[i] = LeafHash(l)
	}
	var path [][]byte
	for len(hashes) > 1 {
		k := splitPoint(len(hashes))
		if index < k {
			sib := rootOf(hashes[k:])
			path = append(path, sib[:])
			hashes = hashes[:k]
		} else {
			sib := rootOf(hashes[:k])
			path = append(path, sib[:])
			hashes = hashes[k:]
			index -= k
		}
	}
	// Collected root-to-leaf above; RFC 6962 orders the path leaf-to-root and
	// the verifier below consumes it in that order.
	for i, j := 0, len(path)-1; i < j; i, j = i+1, j-1 {
		path[i], path[j] = path[j], path[i]
	}
	return path, nil
}

// VerifyInclusion recomputes the root from a leaf preimage and an audit path.
// The publisher runs it on its own freshly built proof before committing --
// cheap, and it turns a tree bug into a failed publication instead of ten
// thousand edges rejecting a valid bundle with M1E-3003.
func VerifyInclusion(leafPreimage []byte, index, size uint64, path [][]byte, root [32]byte) bool {
	if size == 0 || index >= size || size > maxTreeSize {
		// The size bound is not hygiene. splitPoint(n) returns 1 for any n that
		// does not fit an int, and the descent below then decrements n by 1 per
		// iteration -- a hostile size would spin for 2^64 rounds. Refuse instead.
		return false
	}
	// The split arithmetic runs root-to-leaf (splitPoint needs the subtree size,
	// which is only known from the top down), but the path is ordered
	// leaf-to-root. So: descend recording which side the leaf fell on, then fold
	// the path back up through those sides in reverse. Doing both in one pass --
	// consuming path[0] with splitPoint(size) -- pairs the deepest sibling with
	// the shallowest direction, which happens to be right for the right-most
	// leaf and wrong for most others.
	leftAt := make([]bool, 0, 64)
	i, n := index, size
	for n > 1 {
		k := uint64(splitPoint(int(n))) //nolint:gosec // G115: n <= size <= maxTreeSize, checked above.
		if i < k {
			leftAt = append(leftAt, true)
			n = k
		} else {
			leftAt = append(leftAt, false)
			i -= k
			n -= k
		}
	}
	if len(path) != len(leftAt) {
		return false // a proof of the wrong depth is not a proof
	}
	h := LeafHash(leafPreimage)
	for j, sib := range path {
		if len(sib) != 32 {
			return false
		}
		s := [32]byte(sib)
		if leftAt[len(leftAt)-1-j] {
			h = nodeHash(h, s)
		} else {
			h = nodeHash(s, h)
		}
	}
	return h == root
}

// tlogHead is the signed head structure: (tenant, size, root). tenant_id is
// inside because the log is per tenant -- without it a head signed for tenant
// A verifies against tenant B's log and split-view detection loses its
// meaning.
type tlogHead struct {
	TenantID []byte `cbor:"tenant_id"`
	TreeSize uint64 `cbor:"tree_size"`
	RootHash []byte `cbor:"root_hash"`
}

// TLogHeadSigningInput is TLogHeadDomainPrefix || canonical-CBOR(head).
func TLogHeadSigningInput(tenant uuid.UUID, treeSize uint64, root [32]byte) ([]byte, error) {
	t := tenant
	body, err := canonEnc.Marshal(tlogHead{TenantID: t[:], TreeSize: treeSize, RootHash: root[:]})
	if err != nil {
		return nil, fmt.Errorf("policydist: encoding tlog head: %w", err)
	}
	return append([]byte(TLogHeadDomainPrefix), body...), nil
}
