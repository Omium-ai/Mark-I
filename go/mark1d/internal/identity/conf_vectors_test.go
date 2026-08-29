// TestConfVectorsReceipt* drive conformance/vectors/receipt/manifest.json —
// the frozen cross-language byte contract (12 §3.4; vectors README). The
// `ConfVectors` name prefix is load-bearing: conformance_crosslang.sh selects
// Go tests with -run ConfVectors, and a run that executes zero vector tests
// is a failed run, not a passed one.

package identity

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

const receiptVectorsDir = "../../../../conformance/vectors/receipt"

type vectorKey struct {
	SeedHex   string `json:"seed_hex"`
	PublicHex string `json:"public_hex"`
	KeyID     string `json:"key_id"`
}

type canonicalVector struct {
	Name              string          `json:"name"`
	Payload           json.RawMessage `json:"payload"`
	CanonicalJSON     string          `json:"canonical_json"`
	CanonicalBytesHex string          `json:"canonical_bytes_hex"`
	ReceiptHashHex    string          `json:"receipt_hash_hex"`
}

type merkleCase struct {
	Name           string              `json:"name"`
	LeavesHex      []string            `json:"leaves_hex"`
	RootHex        string              `json:"root_hex"`
	InclusionPaths map[string][]string `json:"inclusion_paths"`
}

type chainEntry struct {
	Seq                int64           `json:"seq"`
	Payload            json.RawMessage `json:"payload"`
	CanonicalJSON      string          `json:"canonical_json"`
	ReceiptHashHex     string          `json:"receipt_hash_hex"`
	DeviceKeyID        string          `json:"device_key_id"`
	DeviceSignatureHex string          `json:"device_signature_hex"`
	ServerKeyID        string          `json:"server_key_id"`
	ServerSignatureHex string          `json:"server_signature_hex"`
}

type negativeMerkle struct {
	LeavesHex      []string `json:"leaves_hex"`
	ClaimedRootHex string   `json:"claimed_root_hex"`
	LeafIndex      int      `json:"leaf_index"`
	RootHex        string   `json:"root_hex"`
	PathHex        []string `json:"path_hex"`
}

type negative struct {
	Name             string          `json:"name"`
	Receipt          *chainEntry     `json:"receipt"`
	Merkle           *negativeMerkle `json:"merkle"`
	ExpectDefect     string          `json:"expect_defect"`
	VerifyAgainstHex string          `json:"verify_against_prev_hash_hex"`
}

type manifest struct {
	DomainPrefixHex string `json:"domain_prefix_hex"`
	GenesisHashHex  string `json:"genesis_hash_hex"`
	Keys            struct {
		Device vectorKey `json:"device"`
		Server vectorKey `json:"server"`
	} `json:"keys"`
	Canonical []canonicalVector `json:"canonical"`
	Merkle    struct {
		Cases []merkleCase `json:"cases"`
	} `json:"merkle"`
	Chain            []chainEntry `json:"chain"`
	Negatives        []negative   `json:"negatives"`
	DefectVocabulary []string     `json:"defect_vocabulary"`
}

func loadManifest(t *testing.T) *manifest {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(receiptVectorsDir, "manifest.json"))
	if err != nil {
		t.Fatalf("reading manifest: %v", err)
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("parsing manifest: %v", err)
	}
	// Guard against a truncated or hand-edited manifest: a family with
	// missing entries would pass every remaining assertion vacuously.
	if len(m.Canonical) == 0 || len(m.Merkle.Cases) == 0 || len(m.Chain) == 0 || len(m.Negatives) == 0 {
		t.Fatalf("manifest families empty: canonical=%d merkle=%d chain=%d negatives=%d",
			len(m.Canonical), len(m.Merkle.Cases), len(m.Chain), len(m.Negatives))
	}
	return &m
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex in manifest: %v", err)
	}
	return b
}

func unhex32(t *testing.T, s string) [32]byte {
	t.Helper()
	b := unhex(t, s)
	if len(b) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(b))
	}
	return [32]byte(b)
}

func TestConfVectorsReceiptKeys(t *testing.T) {
	m := loadManifest(t)
	if got := hex.EncodeToString([]byte(DomainPrefix)); got != m.DomainPrefixHex {
		t.Errorf("DomainPrefix hex = %s, manifest %s", got, m.DomainPrefixHex)
	}
	if got := hex.EncodeToString(GenesisHash[:]); got != m.GenesisHashHex {
		t.Errorf("GenesisHash hex = %s, manifest %s", got, m.GenesisHashHex)
	}
	for name, vk := range map[string]vectorKey{"device": m.Keys.Device, "server": m.Keys.Server} {
		priv := ed25519.NewKeyFromSeed(unhex(t, vk.SeedHex))
		pub := priv.Public().(ed25519.PublicKey)
		if hex.EncodeToString(pub) != vk.PublicHex {
			t.Errorf("%s: public key = %x, manifest %s", name, pub, vk.PublicHex)
		}
		if got := DeriveKeyID(pub); got != vk.KeyID {
			t.Errorf("%s: DeriveKeyID = %s, manifest %s", name, got, vk.KeyID)
		}
	}
}

func TestConfVectorsReceiptCanonical(t *testing.T) {
	m := loadManifest(t)
	for _, c := range m.Canonical {
		t.Run(c.Name, func(t *testing.T) {
			payload, err := DecodePayload(c.Payload)
			if err != nil {
				t.Fatalf("decoding vector payload: %v", err)
			}
			got, err := CanonicalJSON(payload)
			if err != nil {
				t.Fatalf("CanonicalJSON: %v", err)
			}
			if got != c.CanonicalJSON {
				t.Errorf("canonical_json:\n got %q\nwant %q", got, c.CanonicalJSON)
			}
			gotBytes, err := CanonicalBytes(payload)
			if err != nil {
				t.Fatalf("CanonicalBytes: %v", err)
			}
			if !bytes.Equal(gotBytes, unhex(t, c.CanonicalBytesHex)) {
				t.Errorf("canonical_bytes: got %x", gotBytes)
			}
			gotHash, err := ReceiptHash(payload)
			if err != nil {
				t.Fatalf("ReceiptHash: %v", err)
			}
			if gotHash != unhex32(t, c.ReceiptHashHex) {
				t.Errorf("receipt_hash: got %x, want %s", gotHash, c.ReceiptHashHex)
			}
		})
	}
}

func TestConfVectorsReceiptMerkle(t *testing.T) {
	m := loadManifest(t)
	for _, c := range m.Merkle.Cases {
		t.Run(c.Name, func(t *testing.T) {
			leaves := make([][]byte, len(c.LeavesHex))
			for i, lh := range c.LeavesHex {
				leaves[i] = unhex(t, lh)
			}
			root, err := MerkleRoot(leaves)
			if err != nil {
				t.Fatalf("MerkleRoot: %v", err)
			}
			want := unhex32(t, c.RootHex)
			if root != want {
				t.Fatalf("root = %x, manifest %s", root, c.RootHex)
			}
			for idxStr, pathHex := range c.InclusionPaths {
				idx, err := strconv.Atoi(idxStr)
				if err != nil {
					t.Fatalf("bad index %q", idxStr)
				}
				path, err := InclusionPath(leaves, idx)
				if err != nil {
					t.Fatalf("InclusionPath(%d): %v", idx, err)
				}
				if len(path) != len(pathHex) {
					t.Fatalf("path(%d) length %d, manifest %d", idx, len(path), len(pathHex))
				}
				for i, h := range path {
					if h != unhex32(t, pathHex[i]) {
						t.Errorf("path(%d)[%d] = %x, manifest %s", idx, i, h, pathHex[i])
					}
				}
				if d := VerifyInclusion(leaves[idx], idx, len(leaves), path, want); d != nil {
					t.Errorf("VerifyInclusion(%d) rejected a manifest path: %s", idx, d.Detail)
				}
			}
		})
	}
}

func manifestReceipt(t *testing.T, e *chainEntry, payloadText string) Receipt {
	t.Helper()
	return Receipt{
		Seq:         e.Seq,
		PayloadText: payloadText,
		ReceiptHash: unhex32(t, e.ReceiptHashHex),
		DeviceSig:   unhex(t, e.DeviceSignatureHex),
		ServerKeyID: e.ServerKeyID,
		ServerSig:   unhex(t, e.ServerSignatureHex),
	}
}

func manifestKeySet(t *testing.T, m *manifest) KeySet {
	t.Helper()
	// Role binding is part of the contract under test (README "Signatures"):
	// the device key answers origin claims ONLY, the server key
	// countersignatures ONLY.
	ks := KeySet{}
	ks.Add(ed25519.PublicKey(unhex(t, m.Keys.Device.PublicHex)), RoleDeviceOrigin)
	ks.Add(ed25519.PublicKey(unhex(t, m.Keys.Server.PublicHex)), RoleServerChain)
	return ks
}

func TestConfVectorsReceiptChain(t *testing.T) {
	m := loadManifest(t)
	keys := manifestKeySet(t, m)

	recs := make([]Receipt, len(m.Chain))
	for i := range m.Chain {
		recs[i] = manifestReceipt(t, &m.Chain[i], m.Chain[i].CanonicalJSON)
	}
	rep := VerifyChain(recs, keys, 1)
	if !rep.Valid || len(rep.Defects) != 0 {
		t.Fatalf("manifest chain must verify clean, got defects %+v", rep.Defects)
	}
	head := m.Chain[len(m.Chain)-1].Seq
	if rep.IntactPrefixSeq != head || rep.LastGoodSeq != head || rep.Checked != len(m.Chain) {
		t.Errorf("report = %+v, want intact=lastgood=%d checked=%d", rep, head, len(m.Chain))
	}

	// The origin-sign mirror: rebuilding each checkpoint payload through the
	// device-side builder and signing with the vector seed must reproduce the
	// manifest bytes exactly (Ed25519 is deterministic), and the server
	// countersignature must verify over the SAME signing input.
	deviceKey := deviceKeyFromSeed(unhex(t, m.Keys.Device.SeedHex))
	serverPriv := ed25519.NewKeyFromSeed(unhex(t, m.Keys.Server.SeedHex))
	for _, e := range m.Chain {
		fields, err := DecodePayload(e.Payload)
		if err != nil {
			t.Fatalf("seq %d: decoding payload: %v", e.Seq, err)
		}
		f := fields.(map[string]any)
		// The countersignature mirror holds for EVERY row, server-only
		// classes included.
		signingInput := append([]byte(DomainPrefix), e.CanonicalJSON...)
		if hex.EncodeToString(ed25519.Sign(serverPriv, signingInput)) != e.ServerSignatureHex {
			t.Errorf("seq %d: countersignature diverges from manifest", e.Seq)
		}
		if !Verify(serverPriv.Public().(ed25519.PublicKey), unhex(t, e.ServerSignatureHex), signingInput) {
			t.Errorf("seq %d: manifest countersignature does not verify", e.Seq)
		}
		if f["type"] != "checkpoint" {
			// Server-only classes have no device-side builder: reproduce the
			// canonical bytes directly and assert no device signature rides.
			text, err := CanonicalJSON(fields)
			if err != nil {
				t.Fatalf("seq %d: CanonicalJSON: %v", e.Seq, err)
			}
			if text != e.CanonicalJSON {
				t.Errorf("seq %d: canonical bytes diverge from manifest", e.Seq)
			}
			if e.DeviceKeyID != "" || e.DeviceSignatureHex != "" {
				t.Errorf("seq %d: server-only row carries device fields", e.Seq)
			}
			continue
		}
		asInt := func(k string) int64 {
			n, err := f[k].(json.Number).Int64()
			if err != nil {
				t.Fatalf("seq %d: field %s: %v", e.Seq, k, err)
			}
			return n
		}
		cp := Checkpoint{
			TenantID:        f["tenant_id"].(string),
			DeviceID:        f["device_id"].(string),
			Seq:             asInt("seq"),
			PrevReceiptHash: unhex32(t, f["prev_receipt_hash"].(string)),
			IssuedAt:        f["issued_at"].(string),
			CheckpointSeq:   asInt("checkpoint_seq"),
			MerkleRoot:      unhex32(t, f["merkle_root"].(string)),
			LeafCount:       int(asInt("leaf_count")),
		}
		signed, err := OriginSign(deviceKey, cp.Payload(deviceKey.KeyID()))
		if err != nil {
			t.Fatalf("seq %d: OriginSign: %v", e.Seq, err)
		}
		if signed.PayloadText != e.CanonicalJSON {
			t.Errorf("seq %d: builder payload:\n got %q\nwant %q", e.Seq, signed.PayloadText, e.CanonicalJSON)
		}
		if signed.ReceiptHash != unhex32(t, e.ReceiptHashHex) {
			t.Errorf("seq %d: origin hash = %x, manifest %s", e.Seq, signed.ReceiptHash, e.ReceiptHashHex)
		}
		if hex.EncodeToString(signed.DeviceSig) != e.DeviceSignatureHex {
			t.Errorf("seq %d: origin signature diverges from manifest", e.Seq)
		}
	}
}

func TestConfVectorsReceiptNegatives(t *testing.T) {
	m := loadManifest(t)
	keys := manifestKeySet(t, m)
	vocab := map[string]bool{}
	for _, d := range m.DefectVocabulary {
		vocab[d] = true
	}

	for _, n := range m.Negatives {
		t.Run(n.Name, func(t *testing.T) {
			var got []ChainDefect
			switch {
			case n.Receipt != nil:
				got = verifyNegativeReceipt(t, n, keys)
			case n.Merkle != nil && n.Merkle.ClaimedRootHex != "":
				leaves := unhexLeaves(t, n.Merkle.LeavesHex)
				if d := VerifyCheckpointRoot(leaves, unhex32(t, n.Merkle.ClaimedRootHex)); d != nil {
					got = []ChainDefect{*d}
				}
			case n.Merkle != nil:
				leaves := unhexLeaves(t, n.Merkle.LeavesHex)
				path := make([][32]byte, len(n.Merkle.PathHex))
				for i, h := range n.Merkle.PathHex {
					path[i] = unhex32(t, h)
				}
				d := VerifyInclusion(leaves[n.Merkle.LeafIndex], n.Merkle.LeafIndex, len(leaves), path, unhex32(t, n.Merkle.RootHex))
				if d != nil {
					got = []ChainDefect{*d}
				}
			default:
				t.Fatalf("negative %q has neither receipt nor merkle body", n.Name)
			}
			// The NAMED defect must be reported — a negative that fails for
			// the wrong reason is a failure (vectors README) — and nothing
			// outside the frozen vocabulary may ever be emitted.
			named := false
			for _, d := range got {
				if !vocab[string(d.Defect)] {
					t.Errorf("defect %q not in the frozen vocabulary", d.Defect)
				}
				if string(d.Defect) == n.ExpectDefect {
					named = true
				}
			}
			if !named {
				t.Errorf("expected defect %q, got %+v", n.ExpectDefect, got)
			}
		})
	}
}

// verifyNegativeReceipt reconstructs the stored row a negative models. The
// stored text is the canonical_json field — EXCEPT when the manifest's
// payload object disagrees with what that field parses to, which is the
// tampered_payload construction: the row's payload column was rewritten to
// the tampered object while hash and signatures stayed stale (gen_vectors.py
// n1), so the stored text is the tampered object's serialisation.
func verifyNegativeReceipt(t *testing.T, n negative, keys KeySet) []ChainDefect {
	t.Helper()
	e := n.Receipt
	storedText := e.CanonicalJSON
	obj, err := DecodePayload(e.Payload)
	if err != nil {
		t.Fatalf("decoding negative payload: %v", err)
	}
	objText, err := CanonicalJSON(obj)
	if err != nil {
		t.Fatalf("canonicalising negative payload: %v", err)
	}
	if fieldObj, err := DecodePayload([]byte(storedText)); err == nil {
		if fieldText, err := CanonicalJSON(fieldObj); err == nil && fieldText != objText {
			storedText = objText
		}
	}
	rec := manifestReceipt(t, e, storedText)
	var expectedPrev *[32]byte
	if n.VerifyAgainstHex != "" {
		p := unhex32(t, n.VerifyAgainstHex)
		expectedPrev = &p
	}
	return VerifyReceipt(&rec, keys, expectedPrev, rec.Seq)
}

func unhexLeaves(t *testing.T, hexes []string) [][]byte {
	t.Helper()
	leaves := make([][]byte, len(hexes))
	for i, h := range hexes {
		leaves[i] = unhex(t, h)
	}
	return leaves
}

func TestConfVectorsReceiptDefectVocabulary(t *testing.T) {
	m := loadManifest(t)
	if len(m.DefectVocabulary) != len(DefectVocabulary) {
		t.Fatalf("vocabulary size %d, manifest %d", len(DefectVocabulary), len(m.DefectVocabulary))
	}
	for i, d := range DefectVocabulary {
		if string(d) != m.DefectVocabulary[i] {
			t.Errorf("vocabulary[%d] = %q, manifest %q", i, d, m.DefectVocabulary[i])
		}
	}
}
