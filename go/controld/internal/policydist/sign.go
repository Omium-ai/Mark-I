// Section-split bundle signing (FR-POLICY-003; 05 §4.5 "the key class split").
//
// The invariant: one key per section, and no key in two sections. That is what
// makes "a verify-only key cannot sign routes" a property of the code rather
// than a promise about how the keys were provisioned -- with a single key
// published into all six rings, the section split is a naming convention and
// nothing else.
//
// Ed25519 itself is receipts.Signer: same algorithm, same 32-byte seed, same
// key-id derivation, already conformance-tested. Domain separation keeps the
// two uses apart -- receipts prefix "mark1-label-v1\0", bundles
// "mark1-bundle-v1\0", tlog heads "mark1-tlog-head-v1\0" -- so no signature
// from one plane can be replayed into another even if a key were reused.

package policydist

import (
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/receipts"
)

// SectionSigner signs one section's D-Q signing input.
type SectionSigner interface {
	Sign(domainPrefixed []byte) ([]byte, error)
	KeyID() string
}

// Keyring holds exactly one signer per section of SectionNames.
type Keyring struct {
	byName map[string]SectionSigner
}

// NewKeyring refuses two things: a missing section, and one key id appearing
// twice.
//
// The duplicate check is the enforceable half of the key-class split. A
// partial ring is refused rather than tolerated because a bundle with five of
// six signatures fails at the edge with M1E-3001, which reads as tampering --
// a provisioning gap must not be indistinguishable from an attack.
func NewKeyring(signers map[string]SectionSigner) (*Keyring, error) {
	byID := make(map[string]string, len(SectionNames))
	ring := make(map[string]SectionSigner, len(SectionNames))
	for _, name := range SectionNames {
		s, ok := signers[name]
		if !ok || s == nil {
			return nil, fmt.Errorf("policydist: no signing key for section %q; a partially signed bundle is rejected at every edge", name)
		}
		if prev, dup := byID[s.KeyID()]; dup {
			return nil, fmt.Errorf("policydist: key %s is configured for both %q and %q; the section split is only real if no key signs two sections (05 §4.5)",
				s.KeyID(), prev, name)
		}
		byID[s.KeyID()] = name
		ring[name] = s
	}
	for name := range signers {
		if _, known := ring[name]; !known {
			return nil, fmt.Errorf("policydist: signing key configured for unknown section %q", name)
		}
	}
	return &Keyring{byName: ring}, nil
}

// PrimaryKeyID is policy_bundles.signing_key_id -- the verify section's key,
// denormalised for rotation queries. Any of the six would do; the choice is
// fixed so the column means one thing.
func (k *Keyring) PrimaryKeyID() string { return k.byName["verify"].KeyID() }

// PublicKeyIDs lists the ring, section => key id. Feeds the key manifest.
func (k *Keyring) PublicKeyIDs() map[string]string {
	out := make(map[string]string, len(k.byName))
	for name, s := range k.byName {
		out[name] = s.KeyID()
	}
	return out
}

// SignSections produces the section-split signature map for b. b must already
// carry every envelope field the D-Q signing structure covers; only
// Signatures and Inclusion may still be unset.
func (k *Keyring) SignSections(b *Bundle, sections map[string][]byte) (map[string]Signature, error) {
	out := make(map[string]Signature, len(SectionNames))
	for _, name := range SectionNames {
		input, err := SigningInput(b, name, sections[name])
		if err != nil {
			return nil, err
		}
		sig, err := k.byName[name].Sign(input)
		if err != nil {
			return nil, fmt.Errorf("policydist: signing section %s: %w", name, err)
		}
		out[name] = Signature{KeyID: k.byName[name].KeyID(), Sig: sig}
	}
	return out, nil
}

// DeriveKeyring builds the six section keys from one root seed by HKDF.
//
// ponytail: dev/self-host key management. 10 §9.2's production custody is
// KMS-resident keys with six distinct CMKs, which is the same seam receipts.go
// already defers -- SectionSigner is the interface a KMS signer implements
// with no other change here. What this DOES buy at Mark 1 scale is the real
// property: six distinct keys with six distinct key ids, so a leaked verify
// key genuinely cannot sign routes. One seed in the process memory is a
// custody weakness, not a split-key weakness.
func DeriveKeyring(rootSeed []byte) (*Keyring, error) {
	if len(rootSeed) != 32 {
		return nil, fmt.Errorf("policydist: bundle root seed must be 32 bytes, got %d", len(rootSeed))
	}
	signers := make(map[string]SectionSigner, len(SectionNames))
	for _, name := range SectionNames {
		seed, err := hkdf.Key(sha256.New, rootSeed, nil, "mark1-bundle-section-v1:"+name, 32)
		if err != nil {
			return nil, fmt.Errorf("policydist: deriving %s section key: %w", name, err)
		}
		s, err := receipts.NewSigner(seed)
		if err != nil {
			return nil, fmt.Errorf("policydist: building %s section signer: %w", name, err)
		}
		signers[name] = s
	}
	return NewKeyring(signers)
}

// IssuedAtNow is the timestamp rule for a bundle: UTC, whole seconds. CBOR
// tag 1 can carry a float, and a float epoch that round-trips differently on
// two decoders is a signature that verifies on one machine and not the other.
func IssuedAtNow() time.Time { return time.Now().UTC().Truncate(time.Second) }
