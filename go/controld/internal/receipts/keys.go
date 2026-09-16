// Key identity + the in-process Ed25519 signer. Key CLASSES are split per
// 05 §4.5: this package's Signer holds the SERVER CHAIN key (env-seam seed,
// estate convention — 10 §9.2's KMS-resident custody is that seam's
// production upgrade path); device ORIGIN keys live in m1_device_keys and
// only their PUBLIC halves ever reach this process. The disjoint custody is
// what makes role confusion (the vectors' S1) structurally impossible here:
// a device-origin lookup reads m1_device_keys, never the chain key.

package receipts

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// DeriveKeyID: derived, never configured (estate keys.py; m1_002 column
// comment) — an operator cannot rotate the key and forget to change the
// label, two keys cannot collide on an id, and the same key gets the same id
// everywhere.
func DeriveKeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "ed25519:" + hex.EncodeToString(sum[:])[:16]
}

// Verify reports whether sig is a valid Ed25519 signature over the signing
// input under pub. A bool, not an error: every caller's next move is the same
// either way — record which link failed and keep walking (estate keys.py).
func Verify(pub ed25519.PublicKey, sig, domainPrefixed []byte) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(pub, domainPrefixed, sig)
}

// Signer is an Ed25519 key reconstructed from its 32-byte seed. It signs the
// already-domain-prefixed input — the caller applies DomainPrefix via
// CanonicalBytes (mark1-receipt discipline), so a Signer cannot be tricked
// into signing an unprefixed message that replays in another domain.
type Signer struct {
	priv  ed25519.PrivateKey
	keyID string
}

func NewSigner(seed []byte) (*Signer, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("receipts: signer seed is %d bytes, want %d", len(seed), ed25519.SeedSize)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return &Signer{priv: priv, keyID: DeriveKeyID(priv.Public().(ed25519.PublicKey))}, nil
}

func (s *Signer) Sign(domainPrefixed []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, domainPrefixed), nil
}

func (s *Signer) KeyID() string { return s.keyID }

func (s *Signer) Public() ed25519.PublicKey {
	return s.priv.Public().(ed25519.PublicKey)
}

// CrossSignDomain separates a rotation cross-signature from every other
// signature in the estate (ADR-0004: the predecessor cross-signs the
// successor's manifest entry).
const CrossSignDomain = "mark1-key-rotation-v1\x00"

// RoleUpdate is the update/transparency-log key class; bundle section keys
// are "bundle:<section>". Both live only in the key manifest.
const RoleUpdate KeyRole = "update"

// CrossSignInput is CrossSignDomain || role || 0x00 || pub: the role is under
// the signature so a server-chain successor cannot be replayed as a bundle
// key, and the fixed-width pub after the NUL closes splice ambiguity.
func CrossSignInput(role KeyRole, pub ed25519.PublicKey) []byte {
	out := make([]byte, 0, len(CrossSignDomain)+len(role)+1+len(pub))
	out = append(out, CrossSignDomain...)
	out = append(out, role...)
	out = append(out, 0)
	return append(out, pub...)
}

// CrossSign is the retiring key endorsing its successor for one role.
func CrossSign(retiring SignerLike, role KeyRole, successor ed25519.PublicKey) ([]byte, error) {
	if len(successor) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("receipts: successor public key is %d bytes, want %d", len(successor), ed25519.PublicKeySize)
	}
	if DeriveKeyID(successor) == retiring.KeyID() {
		return nil, fmt.Errorf("receipts: a key cannot cross-sign itself (%s)", retiring.KeyID())
	}
	return retiring.Sign(CrossSignInput(role, successor))
}

// VerifyCrossSign checks that retiringPub endorsed successor for role.
func VerifyCrossSign(retiringPub ed25519.PublicKey, role KeyRole, successor ed25519.PublicKey, sig []byte) bool {
	return len(successor) == ed25519.PublicKeySize && Verify(retiringPub, sig, CrossSignInput(role, successor))
}
