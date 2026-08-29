package identity

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestFileCustodyRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mark1", "device.key")
	c := FileCustody{Path: path}

	if _, err := c.Load(); !errors.Is(err, ErrNoKey) {
		t.Fatalf("empty custody: err = %v, want ErrNoKey", err)
	}

	key, err := NewDeviceKey(c)
	if err != nil {
		t.Fatalf("NewDeviceKey: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("key file missing: %v", err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("key file mode %o, the custody floor is 0600 (04 §2.9)", fi.Mode().Perm())
	}

	// Reload must yield the SAME identity: a key that changes across restarts
	// orphans every receipt the previous one signed.
	again, err := NewDeviceKey(c)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if key.KeyID() != again.KeyID() {
		t.Errorf("KeyID changed across reload: %s → %s", key.KeyID(), again.KeyID())
	}

	// Store must never overwrite an existing key (O_EXCL).
	if err := c.Store(make([]byte, seedLen)); err == nil {
		t.Error("Store over an existing key must refuse")
	}
}

func TestFileCustodyRefusesLoosePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permission bits only")
	}
	path := filepath.Join(t.TempDir(), "device.key")
	if err := os.WriteFile(path, make([]byte, seedLen), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := (FileCustody{Path: path}).Load(); err == nil {
		t.Error("a group/world-readable device key must refuse to load")
	}
}

func TestOriginSignVerifies(t *testing.T) {
	key, err := NewDeviceKey(FileCustody{Path: filepath.Join(t.TempDir(), "device.key")})
	if err != nil {
		t.Fatal(err)
	}
	pub := key.(*deviceKey).Public()
	if DeriveKeyID(pub) != key.KeyID() {
		t.Fatalf("KeyID is not derived from the public key")
	}

	cp := Checkpoint{
		TenantID:      "t",
		DeviceID:      "d",
		Seq:           1,
		IssuedAt:      "2026-08-29T00:00:00Z",
		CheckpointSeq: 1,
		LeafCount:     1,
	}
	signed, err := OriginSign(key, cp.Payload(key.KeyID()))
	if err != nil {
		t.Fatalf("OriginSign: %v", err)
	}
	input := append([]byte(DomainPrefix), signed.PayloadText...)
	if !Verify(pub, signed.DeviceSig, input) {
		t.Error("origin signature must verify over the signing input")
	}
	// One flipped byte anywhere in the input must fail — the signature is
	// over prefix+payload as one string, not the payload alone.
	input[0] ^= 0xff
	if Verify(pub, signed.DeviceSig, input) {
		t.Error("signature verified over tampered input")
	}
	if Verify(ed25519.PublicKey(make([]byte, 5)), signed.DeviceSig, input) {
		t.Error("malformed public key must never verify")
	}
}
