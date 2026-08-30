package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

var key = []byte("test-key")

func TestMintVerifyRoundtrip(t *testing.T) {
	tenant, device := uuid.New(), uuid.New()
	v := NewHMACVerifier(key, StaticRevocations{})
	c, err := v.Verify(context.Background(), Mint(key, tenant, device, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if c.TenantID != tenant || c.DeviceID != device {
		t.Fatalf("claims mismatch: %+v", c)
	}
}

func TestTamperedSignatureRejected(t *testing.T) {
	v := NewHMACVerifier(key, StaticRevocations{})
	tok := Mint(key, uuid.New(), uuid.New(), time.Hour)
	tampered := tok[:len(tok)-2] + "xx"
	if _, err := v.Verify(context.Background(), tampered); !errors.Is(err, ErrBadToken) {
		t.Fatalf("want ErrBadToken, got %v", err)
	}
}

func TestWrongKeyRejected(t *testing.T) {
	v := NewHMACVerifier([]byte("other-key"), StaticRevocations{})
	if _, err := v.Verify(context.Background(), Mint(key, uuid.New(), uuid.New(), time.Hour)); !errors.Is(err, ErrBadToken) {
		t.Fatalf("want ErrBadToken, got %v", err)
	}
}

func TestExpiredTokenRejected(t *testing.T) {
	v := NewHMACVerifier(key, StaticRevocations{})
	v.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if _, err := v.Verify(context.Background(), Mint(key, uuid.New(), uuid.New(), time.Hour)); !errors.Is(err, ErrBadToken) {
		t.Fatalf("want ErrBadToken, got %v", err)
	}
}

// The ≤24 h ceiling is a design floor (05 §3.3): Mint clamps, and a token
// claiming more than 24 h is refused even if its signature is genuine.
func TestTokenLifetimeCeiling(t *testing.T) {
	tok := Mint(key, uuid.New(), uuid.New(), 48*time.Hour)
	v := NewHMACVerifier(key, StaticRevocations{})
	v.now = func() time.Time { return time.Now().Add(25 * time.Hour) }
	if _, err := v.Verify(context.Background(), tok); !errors.Is(err, ErrBadToken) {
		t.Fatalf("token outlived the 24 h ceiling: %v", err)
	}
}

func TestRevokedDevice(t *testing.T) {
	device := uuid.New()
	v := NewHMACVerifier(key, StaticRevocations{device: true})
	if _, err := v.Verify(context.Background(), Mint(key, uuid.New(), device, time.Hour)); !errors.Is(err, ErrRevoked) {
		t.Fatalf("want ErrRevoked, got %v", err)
	}
}

type failingRevocations struct{}

func (failingRevocations) IsRevoked(context.Context, uuid.UUID, uuid.UUID) (bool, error) {
	return false, errors.New("cache stale")
}

// Unknown revocation state fails CLOSED (05 §3.4): "propagates eventually"
// is the fail-open version of a fail-closed requirement.
func TestRevocationStateUnavailableFailsClosed(t *testing.T) {
	v := NewHMACVerifier(key, failingRevocations{})
	_, err := v.Verify(context.Background(), Mint(key, uuid.New(), uuid.New(), time.Hour))
	if !errors.Is(err, ErrBadToken) {
		t.Fatalf("want fail-closed ErrBadToken, got %v", err)
	}
}

func TestGarbageTokensRejected(t *testing.T) {
	v := NewHMACVerifier(key, StaticRevocations{})
	for _, tok := range []string{"", "x", "a.b.c.d", strings.Repeat("m1dev.v1.", 3)} {
		if _, err := v.Verify(context.Background(), tok); err == nil {
			t.Fatalf("accepted garbage token %q", tok)
		}
	}
}
