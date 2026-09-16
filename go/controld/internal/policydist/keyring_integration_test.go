//go:build integration

package policydist

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/receipts"
)

// One log, two leaf kinds: a key manifest published as a `key_manifest` leaf
// and the bundle published after it are both under the head the bundle's
// proof targets -- and a cross-signed rotation manifest logs the same way.
func TestIntegrationKeyManifestIsATlogLeafBesideBundles(t *testing.T) {
	h := itSetup(t)
	ctx := context.Background()
	store := h.mod.store
	chain := []ManifestKey{{KeyID: store.headSigner.KeyID(), PubkeyHex: hex.EncodeToString(store.headSigner.Public())}}

	m, err := BuildKeyManifest(h.ring, nil, store.headSigner, chain)
	if err != nil {
		t.Fatal(err)
	}
	mp, err := store.PublishKeyManifest(ctx, h.tenantA, m)
	if err != nil {
		t.Fatalf("PublishKeyManifest: %v", err)
	}
	if mp.Inclusion.LeafIndex != 0 || mp.Inclusion.TreeSize != 1 {
		t.Fatalf("manifest leaf at %d of %d, want 0 of 1", mp.Inclusion.LeafIndex, mp.Inclusion.TreeSize)
	}

	bp, err := h.mod.Publish(ctx, h.tenantA, h.draft("stable"))
	if err != nil {
		t.Fatal(err)
	}
	if bp.TLogIndex != 1 || bp.TreeSize != 2 {
		t.Fatalf("bundle leaf at %d of %d, want 1 of 2", bp.TLogIndex, bp.TreeSize)
	}

	// The bundle's head covers the manifest leaf: recompute the manifest's
	// audit path in the 2-leaf tree and verify it against THAT root.
	rows, err := h.admin.Query(ctx,
		`SELECT kind, leaf_hash FROM tlog_leaves WHERE tenant_id = $1 ORDER BY leaf_index`, h.tenantAID)
	if err != nil {
		t.Fatal(err)
	}
	var kinds []string
	var leaves [][]byte
	for rows.Next() {
		var k string
		var l []byte
		if err := rows.Scan(&k, &l); err != nil {
			t.Fatal(err)
		}
		kinds = append(kinds, k)
		leaves = append(leaves, l)
	}
	rows.Close()
	if len(kinds) != 2 || kinds[0] != LeafKindKeyManifest || kinds[1] != LeafKindPolicyBundle {
		t.Fatalf("leaf kinds %v", kinds)
	}
	if !bytes.Equal(leaves[0], mp.BodySHA256[:]) {
		t.Fatal("manifest leaf preimage is not the canonical manifest's sha256")
	}
	path, err := InclusionProof(leaves, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyInclusion(leaves[0], 0, 2, path, bp.RootHash) {
		t.Fatal("the bundle's signed head does not cover the key manifest leaf")
	}

	// The logged bytes round-trip through the validator and match the leaf.
	var body string
	var proofJSON []byte
	if err := h.admin.QueryRow(ctx,
		`SELECT body, tlog_proof::text FROM key_manifests WHERE tenant_id = $1 AND tlog_index = 0`, h.tenantAID).
		Scan(&body, &proofJSON); err != nil {
		t.Fatal(err)
	}
	var stored KeyManifest
	if err := json.Unmarshal([]byte(body), &stored); err != nil {
		t.Fatal(err)
	}
	if err := ValidateKeyManifest(&stored); err != nil {
		t.Fatalf("stored manifest: %v", err)
	}
	if canon, _ := CanonicalManifest(&stored); !bytes.Equal(canon, mp.Body) {
		t.Fatal("stored manifest bytes are not the canonical bytes that were logged")
	}

	// A rotation: every section cross-signed by its retiring key, logged as
	// leaf 2; the R5 violation is refused before any leaf is written.
	next, err := DeriveKeyring(bytes.Repeat([]byte{0x77}, 32))
	if err != nil {
		t.Fatal(err)
	}
	rot, err := BuildKeyManifest(next, h.ring, store.headSigner, chain)
	if err != nil {
		t.Fatal(err)
	}
	rp, err := store.PublishKeyManifest(ctx, h.tenantA, rot)
	if err != nil {
		t.Fatalf("rotation manifest: %v", err)
	}
	if rp.Inclusion.LeafIndex != 2 {
		t.Fatalf("rotation leaf at %d, want 2", rp.Inclusion.LeafIndex)
	}
	bad := *rot
	bad.UpdateKeys = []ManifestKey{rot.BundleSectionKeys[0]}
	if _, err := store.PublishKeyManifest(ctx, h.tenantA, &bad); err == nil {
		t.Fatal("R5: update key equal to a bundle key was published")
	}
	if n := h.adminCount("tlog_leaves"); n != 3 {
		t.Fatalf("%d leaves after a refused manifest, want 3", n)
	}

	// The server chain rotation step registers the successor cross-signed
	// and the receipts key surface serves the endorsement.
	successor, _ := receipts.NewSigner(bytes.Repeat([]byte{0x78}, 32))
	if err := receipts.RegisterSuccessorKey(ctx, h.admin, store.headSigner, successor); err != nil {
		t.Fatal(err)
	}
	var by string
	var sig []byte
	if err := h.admin.QueryRow(ctx,
		`SELECT cross_signed_by, cross_signature FROM m1_server_signing_keys WHERE key_id = $1`, successor.KeyID()).
		Scan(&by, &sig); err != nil {
		t.Fatal(err)
	}
	if by != store.headSigner.KeyID() || !receipts.VerifyCrossSign(store.headSigner.Public(), receipts.RoleServerChain, successor.Public(), sig) {
		t.Fatal("successor is not cross-signed by the retiring chain key")
	}
}
