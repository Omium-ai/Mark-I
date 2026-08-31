// Device key custody and key identity — the Go rendering of the estate's
// keys.py (vendored from core-services/recovery-orchestrator/app/receipts/
// keys.py, copied 2026-08-29) shaped to 04 §2.9's DeviceKey contract. Key
// CLASSES are split per 05 §4.5: this package holds device ORIGIN keys only —
// the server chain key, bundle keys and the update/log key are other planes'
// custody, and a device key must never be able to impersonate any of them
// (the domain prefix plus disjoint key sets is what enforces that).

package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

const seedLen = ed25519.SeedSize // 32

// ErrNoKey is Custody's "nothing stored yet" — a real state, not a failure:
// NewDeviceKey answers it by generating, anything else propagates.
var ErrNoKey = errors.New("identity: no device key in custody")

// DeviceKey is 04 §2.9's interface, verbatim: the private key never leaves
// custody, Sign() is the only operation. The caller applies the
// "mark1-label-v1\0" prefix (via CanonicalBytes) — mark1-receipt discipline.
type DeviceKey interface {
	Sign(domainPrefixed []byte) ([]byte, error)
	KeyID() string // "ed25519:" + sha256(pub)[:16]
}

// DeriveKeyID: derived, never configured (estate keys.py) — an operator
// cannot rotate the key and forget to change the label, two keys cannot
// collide on an id, and the same key gets the same id everywhere.
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

// Custody is the seam under 04 §2.9's ladder: Keychain/TPM/secret-service
// rungs implement this same pair when enroll lands (see doc.go), and nothing
// above the seam changes. It stores the 32-byte Ed25519 seed, the smallest
// thing that reconstructs the key.
type Custody interface {
	Load() ([]byte, error) // seedLen bytes, or ErrNoKey
	Store(seed []byte) error
}

// FileCustody is the ladder's floor, never skipped-below: a 0600 file under
// ~/.omium/mark1/ (04 §2.9).
type FileCustody struct {
	Path string
}

func (f FileCustody) Load() ([]byte, error) {
	fi, err := os.Stat(f.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoKey
	}
	if err != nil {
		return nil, err
	}
	// A group/world-readable key file means the device identity may already
	// be someone else's; refusing to load is the only honest response.
	// Windows permission bits are decoration, so the check would pass
	// vacuously there — the TPM rung is that platform's real answer.
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("identity: %s has mode %o; a device key must be 0600 — refusing to load it", f.Path, fi.Mode().Perm())
	}
	seed, err := os.ReadFile(f.Path)
	if err != nil {
		return nil, err
	}
	if len(seed) != seedLen {
		return nil, fmt.Errorf("identity: %s holds %d bytes, expected a %d-byte ed25519 seed", f.Path, len(seed), seedLen)
	}
	return seed, nil
}

func (f FileCustody) Store(seed []byte) error {
	if len(seed) != seedLen {
		return fmt.Errorf("identity: refusing to store a %d-byte seed", len(seed))
	}
	if err := os.MkdirAll(filepath.Dir(f.Path), 0o700); err != nil {
		return err
	}
	// O_EXCL: a device key is created exactly once; silently overwriting one
	// would orphan every receipt the old key ever signed.
	fh, err := os.OpenFile(f.Path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := fh.Write(seed); err != nil {
		_ = fh.Close()
		return err
	}
	return fh.Close()
}

type deviceKey struct {
	priv  ed25519.PrivateKey
	keyID string
}

func (k *deviceKey) Sign(domainPrefixed []byte) ([]byte, error) {
	return ed25519.Sign(k.priv, domainPrefixed), nil
}

func (k *deviceKey) KeyID() string { return k.keyID }

// Public exists on the concrete type, not the interface: enrollment sends the
// public half to the server, but nothing that merely SIGNS needs it (04 §8's
// custody table).
func (k *deviceKey) Public() ed25519.PublicKey {
	return k.priv.Public().(ed25519.PublicKey)
}

// NewDeviceKey loads the device key from custody, generating and storing one
// on first run. Generation failure is fatal to the caller — an identity-less
// mark1d could capture but never attribute, and attribution is the product.
func NewDeviceKey(c Custody) (DeviceKey, error) {
	seed, err := c.Load()
	if errors.Is(err, ErrNoKey) {
		seed = make([]byte, seedLen)
		if _, err := rand.Read(seed); err != nil {
			return nil, err
		}
		if err := c.Store(seed); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	return deviceKeyFromSeed(seed), nil
}

func deviceKeyFromSeed(seed []byte) *deviceKey {
	priv := ed25519.NewKeyFromSeed(seed)
	return &deviceKey{priv: priv, keyID: DeriveKeyID(priv.Public().(ed25519.PublicKey))}
}
