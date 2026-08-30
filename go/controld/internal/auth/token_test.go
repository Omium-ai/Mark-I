package auth

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

var seed = []byte("0123456789abcdef0123456789abcdef")

type staticTenantRevocations map[uuid.UUID]bool

func (s staticTenantRevocations) IsRevoked(_ context.Context, _, device uuid.UUID) (bool, error) {
	return s[device], nil
}

type failingTenantRevocations struct{}

func (failingTenantRevocations) IsRevoked(context.Context, uuid.UUID, uuid.UUID) (bool, error) {
	return false, errors.New("cache stale beyond 60s")
}

func mustSigner(t *testing.T) *Signer {
	t.Helper()
	s, err := NewSigner(seed)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mint(t *testing.T, s *Signer, tenant, device uuid.UUID, ttl time.Duration) string {
	t.Helper()
	now := time.Now()
	tok, err := s.Mint(tenant, device, "ed25519:test", now, now.Add(ttl))
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestEd25519MintVerifyRoundtrip(t *testing.T) {
	s := mustSigner(t)
	tenant, device := uuid.New(), uuid.New()
	v := NewEd25519Verifier(s.Public(), staticTenantRevocations{})
	c, err := v.Verify(context.Background(), mint(t, s, tenant, device, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if c.TenantID != tenant || c.DeviceID != device || c.KeyID != "ed25519:test" {
		t.Fatalf("claims mismatch: %+v", c)
	}
}

// Tampered payload/signature ⇒ ErrBadToken, never ErrRevoked — the M1E-1002
// vs M1E-1003 split (08 §3.1) is a contract, not a coincidence.
func TestEd25519TamperedRejected(t *testing.T) {
	s := mustSigner(t)
	v := NewEd25519Verifier(s.Public(), staticTenantRevocations{})
	tok := mint(t, s, uuid.New(), uuid.New(), time.Hour)
	for _, bad := range []string{
		tok[:len(tok)-2] + "xx",  // signature bits flipped
		tok[:9] + "A" + tok[10:], // payload bits flipped
		"m1dev.v1" + tok[8:],     // wrong scheme prefix
	} {
		if _, err := v.Verify(context.Background(), bad); !errors.Is(err, ErrBadToken) {
			t.Fatalf("want ErrBadToken for %q…, got %v", bad[:12], err)
		}
	}
}

func TestEd25519WrongKeyRejected(t *testing.T) {
	s := mustSigner(t)
	otherPub, _, _ := ed25519.GenerateKey(nil)
	v := NewEd25519Verifier(otherPub, staticTenantRevocations{})
	if _, err := v.Verify(context.Background(), mint(t, s, uuid.New(), uuid.New(), time.Hour)); !errors.Is(err, ErrBadToken) {
		t.Fatalf("want ErrBadToken, got %v", err)
	}
}

func TestEd25519ExpiredRejected(t *testing.T) {
	s := mustSigner(t)
	v := NewEd25519Verifier(s.Public(), staticTenantRevocations{})
	v.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if _, err := v.Verify(context.Background(), mint(t, s, uuid.New(), uuid.New(), time.Hour)); !errors.Is(err, ErrBadToken) {
		t.Fatalf("expired token must be ErrBadToken, got %v", err)
	}
}

// The ≤24 h ceiling is enforced at MINT (error, not clamp — a caller asking
// for more has a bug) and re-checked at VERIFY (05 §3.3).
func TestEd25519LifetimeCeiling(t *testing.T) {
	s := mustSigner(t)
	now := time.Now()
	if _, err := s.Mint(uuid.New(), uuid.New(), "k", now, now.Add(25*time.Hour)); err == nil {
		t.Fatal("Mint accepted a >24h lifetime")
	}
}

func TestEd25519RevokedDevice(t *testing.T) {
	s := mustSigner(t)
	device := uuid.New()
	v := NewEd25519Verifier(s.Public(), staticTenantRevocations{device: true})
	if _, err := v.Verify(context.Background(), mint(t, s, uuid.New(), device, time.Hour)); !errors.Is(err, ErrRevoked) {
		t.Fatalf("want ErrRevoked, got %v", err)
	}
}

// Unknown revocation state fails CLOSED (05 §3.4).
func TestEd25519RevocationUnavailableFailsClosed(t *testing.T) {
	s := mustSigner(t)
	v := NewEd25519Verifier(s.Public(), failingTenantRevocations{})
	if _, err := v.Verify(context.Background(), mint(t, s, uuid.New(), uuid.New(), time.Hour)); !errors.Is(err, ErrBadToken) {
		t.Fatalf("want fail-closed ErrBadToken, got %v", err)
	}
}

// Multi: ErrRevoked from the first seam must short-circuit — a revocation
// verdict is never retried against a laxer verifier.
func TestMultiVerifierRevokedShortCircuits(t *testing.T) {
	s := mustSigner(t)
	device := uuid.New()
	prod := NewEd25519Verifier(s.Public(), staticTenantRevocations{device: true})
	dev := NewHMACVerifier([]byte("k"), StaticRevocations{})
	tok := mint(t, s, uuid.New(), device, time.Hour)
	if _, err := Multi(prod, dev).Verify(context.Background(), tok); !errors.Is(err, ErrRevoked) {
		t.Fatalf("want ErrRevoked, got %v", err)
	}
	// And a dev token still verifies through the second seam.
	devTok := Mint([]byte("k"), uuid.New(), uuid.New(), time.Hour)
	if _, err := Multi(prod, dev).Verify(context.Background(), devTok); err != nil {
		t.Fatalf("dev token through Multi: %v", err)
	}
}
