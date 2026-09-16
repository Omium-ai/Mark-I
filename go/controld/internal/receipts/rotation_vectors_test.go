// The rotation family of conformance/vectors/receipt (ADR-0004): the chain
// crosses a server-key rotation and stays valid; a bare successor or an
// unannounced hand-over is the one named defect. Driven here because this
// package's VerifyChain is what the operator-side tooling runs; the customer
// binary is driven by tools/verifier's own conf_vectors_ test.

package receipts

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type rotationKey struct {
	PubkeyHex string `json:"pubkey_hex"`
	KeyID     string `json:"key_id"`
	CrossSig  *struct {
		ByKeyID      string `json:"by_key_id"`
		SignatureHex string `json:"signature_hex"`
	} `json:"cross_sig"`
}

type rotationCase struct {
	Name            string        `json:"name"`
	Chain           []chainEntry  `json:"chain"`
	ServerChainKeys []rotationKey `json:"server_chain_keys"`
	ExpectDefect    string        `json:"expect_defect"`
}

type rotationFamily struct {
	CrossSignDomainHex string `json:"cross_sign_domain_hex"`
	Successor          struct {
		vectorKey
		CrossSigHex string `json:"cross_sig_hex"`
	} `json:"successor"`
	Accept           rotationCase   `json:"accept"`
	Negatives        []rotationCase `json:"negatives"`
	DefectVocabulary []string       `json:"defect_vocabulary"`
}

func loadRotation(t *testing.T) (*manifest, *rotationFamily) {
	t.Helper()
	m := loadManifest(t)
	raw, err := os.ReadFile(filepath.Join(receiptVectorsDir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var top struct {
		Rotation rotationFamily `json:"rotation"`
	}
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatal(err)
	}
	if len(top.Rotation.Accept.Chain) == 0 || len(top.Rotation.Negatives) == 0 {
		t.Fatal("rotation family empty")
	}
	return m, &top.Rotation
}

func rotationKeySet(t *testing.T, m *manifest, keys []rotationKey) KeySet {
	t.Helper()
	ks := KeySet{}
	ks.Add(ed25519.PublicKey(unhex(t, m.Keys.Device.PublicHex)), RoleDeviceOrigin)
	for _, k := range keys {
		id := ks.Add(ed25519.PublicKey(unhex(t, k.PubkeyHex)), RoleServerChain)
		if id != k.KeyID {
			t.Fatalf("manifest key_id %s derives to %s", k.KeyID, id)
		}
		if k.CrossSig != nil {
			pk := ks[id]
			pk.CrossSig = &CrossSig{ByKeyID: k.CrossSig.ByKeyID, Sig: unhex(t, k.CrossSig.SignatureHex)}
			ks[id] = pk
		}
	}
	return ks
}

func rotationChain(t *testing.T, entries []chainEntry) []Receipt {
	t.Helper()
	recs := make([]Receipt, len(entries))
	for i := range entries {
		recs[i] = manifestReceipt(t, &entries[i], entries[i].CanonicalJSON)
	}
	return recs
}

func TestConfVectorsReceiptControldRotation(t *testing.T) {
	m, rot := loadRotation(t)
	if hex.EncodeToString([]byte(CrossSignDomain)) != rot.CrossSignDomainHex {
		t.Fatalf("CrossSignDomain drifted from the frozen vectors")
	}
	// The cross-signature byte contract: re-derive it from the frozen seeds.
	old, err := NewSigner(unhex(t, m.Keys.Server.SeedHex))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := CrossSign(old, RoleServerChain, ed25519.PublicKey(unhex(t, rot.Successor.PublicHex)))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(sig) != rot.Successor.CrossSigHex {
		t.Fatalf("cross-signature diverges from the frozen vector")
	}

	rep := VerifyChain(rotationChain(t, rot.Accept.Chain), rotationKeySet(t, m, rot.Accept.ServerChainKeys), 1)
	if !rep.Valid {
		t.Fatalf("%s: chain across a cross-signed rotation must verify: %+v", rot.Accept.Name, rep.Defects)
	}
	if rep.IntactPrefixSeq != rot.Accept.Chain[len(rot.Accept.Chain)-1].Seq {
		t.Fatalf("intact prefix %d", rep.IntactPrefixSeq)
	}

	vocab := map[string]bool{}
	for _, d := range rot.DefectVocabulary {
		vocab[d] = true
	}
	exercised := map[string]bool{}
	for _, n := range rot.Negatives {
		rep := VerifyChain(rotationChain(t, n.Chain), rotationKeySet(t, m, n.ServerChainKeys), 1)
		if rep.Valid {
			t.Fatalf("%s: accepted", n.Name)
		}
		named := false
		for _, d := range rep.Defects {
			if string(d.Defect) == n.ExpectDefect {
				named = true
			} else {
				t.Errorf("%s: unexpected defect %s: %s", n.Name, d.Defect, d.Detail)
			}
		}
		if !named {
			t.Errorf("%s: expected %s, got %+v", n.Name, n.ExpectDefect, rep.Defects)
		}
		exercised[n.ExpectDefect] = true
	}
	for d := range vocab {
		if !exercised[d] {
			t.Errorf("no rotation negative exercises %q", d)
		}
	}
	if string(DefectRotationUnchained) != rot.DefectVocabulary[0] {
		t.Fatalf("rotation vocabulary drift: %v", rot.DefectVocabulary)
	}
}
