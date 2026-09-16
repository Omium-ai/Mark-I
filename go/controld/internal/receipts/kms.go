// The KMS-shaped signer: same SignerLike seam as the in-process Signer, with
// the private key living behind an API that only ever answers Sign and
// PublicKey. Real AWS wiring (ADR-0004: P-256 in KMS, no Ed25519) is a
// deploy-time adapter implementing KMSAPI plus a "p256:" key_id arm in every
// verifier; nothing in this file or its callers changes for it.

package receipts

import (
	"context"
	"crypto/ed25519"
	"fmt"
)

// KMSAPI is the sign-only, non-exportable custody surface (kms:Sign and
// kms:GetPublicKey, nothing else).
type KMSAPI interface {
	Sign(ctx context.Context, keyRef string, message []byte) ([]byte, error)
	PublicKey(ctx context.Context, keyRef string) ([]byte, error)
}

// KMSSigner signs through a KMSAPI; the public half is fetched once at
// construction so KeyID is derived exactly as for a local key.
type KMSSigner struct {
	api    KMSAPI
	keyRef string
	pub    ed25519.PublicKey
	keyID  string
}

func NewKMSSigner(ctx context.Context, api KMSAPI, keyRef string) (*KMSSigner, error) {
	pub, err := api.PublicKey(ctx, keyRef)
	if err != nil {
		return nil, fmt.Errorf("receipts: kms public key for %s: %w", keyRef, err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("receipts: kms key %s public key is %d bytes, want %d", keyRef, len(pub), ed25519.PublicKeySize)
	}
	return &KMSSigner{api: api, keyRef: keyRef, pub: pub, keyID: DeriveKeyID(pub)}, nil
}

func (k *KMSSigner) Sign(domainPrefixed []byte) ([]byte, error) {
	sig, err := k.api.Sign(context.Background(), k.keyRef, domainPrefixed)
	if err != nil {
		return nil, fmt.Errorf("receipts: kms sign under %s: %w", k.keyID, err)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("receipts: kms returned a %d-byte signature for %s", len(sig), k.keyID)
	}
	return sig, nil
}

func (k *KMSSigner) KeyID() string             { return k.keyID }
func (k *KMSSigner) Public() ed25519.PublicKey { return k.pub }
