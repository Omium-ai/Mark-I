package policydist

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/receipts"
)

func manifestFor(t *testing.T, ring, prev *Keyring, update SectionSigner) *KeyManifest {
	t.Helper()
	m, err := BuildKeyManifest(ring, prev, update, nil)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func kindOf(t *testing.T, err error) string {
	t.Helper()
	var rej *ManifestReject
	if !errors.As(err, &rej) {
		t.Fatalf("expected a ManifestReject, got %v", err)
	}
	return rej.Kind
}

func TestKeyManifestRefusesUpdateKeyEqualToABundleKey(t *testing.T) {
	ring, _ := DeriveKeyring(bytes.Repeat([]byte{1}, 32))
	update, _ := receipts.NewSigner(bytes.Repeat([]byte{2}, 32))
	if _, err := BuildKeyManifest(ring, nil, update, nil); err != nil {
		t.Fatalf("distinct update key refused: %v", err)
	}
	// R5: the route section key offered as the update key.
	_, err := BuildKeyManifest(ring, nil, ring.byName["route"], nil)
	if k := kindOf(t, err); k != "update_equals_bundle" {
		t.Fatalf("kind %s", k)
	}
}

func TestKeyringRotationIsCrossSignedPerSection(t *testing.T) {
	old, _ := DeriveKeyring(bytes.Repeat([]byte{1}, 32))
	next, _ := DeriveKeyring(bytes.Repeat([]byte{3}, 32))
	update, _ := receipts.NewSigner(bytes.Repeat([]byte{2}, 32))
	m := manifestFor(t, next, old, update)
	if len(m.BundleSectionKeys) != 2*len(SectionNames) {
		t.Fatalf("a rotation must publish both rings, got %d keys", len(m.BundleSectionKeys))
	}
	crossed := 0
	for _, k := range m.BundleSectionKeys {
		if k.CrossSig == nil {
			continue
		}
		crossed++
		if k.CrossSig.ByKeyID != old.byName[k.Section].KeyID() {
			t.Fatalf("%s cross-signed by %s, want the retiring %s key", k.KeyID, k.CrossSig.ByKeyID, k.Section)
		}
	}
	if crossed != len(SectionNames) {
		t.Fatalf("%d cross-signatures, want one per section", crossed)
	}
	// Same ring twice is no rotation: nothing cross-signed, nothing doubled.
	same := manifestFor(t, old, old, update)
	if len(same.BundleSectionKeys) != len(SectionNames) {
		t.Fatalf("a no-op rotation published %d keys", len(same.BundleSectionKeys))
	}

	// Mutations on the valid rotation manifest, each named.
	tamper := func(f func(m *KeyManifest)) string {
		mm := manifestFor(t, next, old, update)
		f(mm)
		return kindOf(t, ValidateKeyManifest(mm))
	}
	if k := tamper(func(m *KeyManifest) { m.BundleSectionKeys[1].CrossSig.ByKeyID = m.BundleSectionKeys[1].KeyID }); k != "self_signed" {
		t.Fatalf("self-signed rotation: %s", k)
	}
	if k := tamper(func(m *KeyManifest) { m.BundleSectionKeys[1].CrossSig.ByKeyID = update.KeyID() }); k != "unknown_signer" {
		t.Fatalf("signer outside the role: %s", k)
	}
	if k := tamper(func(m *KeyManifest) {
		sig, _ := hex.DecodeString(m.BundleSectionKeys[1].CrossSig.SignatureHex)
		sig[0] ^= 1
		m.BundleSectionKeys[1].CrossSig.SignatureHex = hex.EncodeToString(sig)
	}); k != "bad_cross_signature" {
		t.Fatalf("flipped cross-signature: %s", k)
	}
	if k := tamper(func(m *KeyManifest) { m.BundleSectionKeys[0].KeyID = "ed25519:0000000000000000" }); k != "key_id_mismatch" {
		t.Fatalf("lying key_id: %s", k)
	}
	if k := tamper(func(m *KeyManifest) { m.BundleSectionKeys = m.BundleSectionKeys[2:] }); k != "missing_section" {
		t.Fatalf("dropped section: %s", k)
	}
}

// A ring of KMS-shaped signers signs a bundle that verifies under the public
// halves: the section split needs nothing from the custody model.
func TestKeyringOverKMSSigners(t *testing.T) {
	kms := fakeKMS{}
	signers := map[string]SectionSigner{}
	for i, name := range SectionNames {
		ref := "alias/mark1-sign-bundle-" + name + "-v1"
		kms[ref] = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{byte(0x70 + i)}, 32))
		s, err := receipts.NewKMSSigner(context.Background(), kms, ref)
		if err != nil {
			t.Fatal(err)
		}
		signers[name] = s
	}
	ring, err := NewKeyring(signers)
	if err != nil {
		t.Fatal(err)
	}
	b := testBundle(t)
	secs, err := sectionBytes(b.Sections)
	if err != nil {
		t.Fatal(err)
	}
	sigs, err := ring.SignSections(b, secs)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range SectionNames {
		input, _ := SigningInput(b, name, secs[name])
		if !receipts.Verify(ring.byName[name].Public(), sigs[name].Sig, input) {
			t.Fatalf("section %s does not verify under its kms key", name)
		}
	}
	if _, err := receipts.NewKMSSigner(context.Background(), kms, "alias/mark1-sign-update-v1"); err == nil {
		t.Fatal("an alias the KMS does not hold must fail at construction")
	}
}

type fakeKMS map[string]ed25519.PrivateKey

func (f fakeKMS) Sign(_ context.Context, ref string, msg []byte) ([]byte, error) {
	k, ok := f[ref]
	if !ok {
		return nil, errors.New("AccessDeniedException")
	}
	return ed25519.Sign(k, msg), nil
}

func (f fakeKMS) PublicKey(_ context.Context, ref string) ([]byte, error) {
	k, ok := f[ref]
	if !ok {
		return nil, errors.New("NotFoundException")
	}
	return k.Public().(ed25519.PublicKey), nil
}

// The publisher-side validator agrees with the edge reference
// (rust/mark1-policy) on every frozen rotation manifest: same accept, same
// refusal kind. `ConfVectorsBundle` is the crosslang script's family token.
func TestConfVectorsBundleRotationManifests(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(bundleVectorsDir, "manifest.json"))
	if err != nil {
		t.Skipf("frozen vectors unavailable: %v", err)
	}
	var top struct {
		Rotation struct {
			CrossSignDomainHex string `json:"cross_sign_domain_hex"`
			Vectors            []struct {
				Name   string `json:"name"`
				File   string `json:"file"`
				Expect string `json:"expect"`
				Kind   string `json:"kind"`
			} `json:"vectors"`
		} `json:"rotation"`
	}
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString([]byte(receipts.CrossSignDomain)) != top.Rotation.CrossSignDomainHex {
		t.Fatal("CrossSignDomain drifted from the frozen vectors")
	}
	if len(top.Rotation.Vectors) == 0 {
		t.Fatal("rotation family empty")
	}
	for _, v := range top.Rotation.Vectors {
		body, err := os.ReadFile(filepath.Join(bundleVectorsDir, v.File))
		if err != nil {
			t.Fatal(err)
		}
		var m KeyManifest
		if err := json.Unmarshal(body, &m); err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		err = ValidateKeyManifest(&m)
		switch v.Expect {
		case "accept":
			if err != nil {
				t.Errorf("%s: refused: %v", v.Name, err)
			}
		case "reject":
			if err == nil {
				t.Errorf("%s: accepted", v.Name)
			} else if k := kindOf(t, err); k != v.Kind {
				t.Errorf("%s: kind %s, want %s", v.Name, k, v.Kind)
			}
		}
	}
}
