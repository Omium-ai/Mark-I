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

// The ≤24 h ceiling is a design floor (05 §3.3): a token CLAIMING more than
// 24 h of life is refused on that ground alone, even with a genuine signature
// and even while it is still comfortably unexpired. The distinction is the
// whole test — the previous version minted 48 h (silently clamped to 24 h)
// and then verified at now+25 h, so it was refused by the now.After(exp) leg
// and the ceiling leg was never reached. Deleting the ceiling clause left it
// green (D-DT).
func TestTokenLifetimeCeiling(t *testing.T) {
	v := NewHMACVerifier(key, StaticRevocations{})
	// Positive control: at exactly the ceiling the same token verifies, so a
	// refusal below cannot be some unrelated parse or MAC failure.
	if _, err := v.Verify(context.Background(), Mint(key, uuid.New(), uuid.New(), TokenTTLCeiling)); err != nil {
		t.Fatalf("a token at exactly the ceiling must verify: %v", err)
	}
	tok := Mint(key, uuid.New(), uuid.New(), 48*time.Hour)
	// One second past mint: nowhere near exp, so ONLY the ceiling can refuse.
	v.now = func() time.Time { return time.Now().Add(time.Second) }
	if _, err := v.Verify(context.Background(), tok); !errors.Is(err, ErrBadToken) {
		t.Fatalf("an unexpired token claiming 48 h was accepted: %v", err)
	}
	// And one second over the ceiling is over it — the boundary is not slack.
	over := Mint(key, uuid.New(), uuid.New(), TokenTTLCeiling+time.Second)
	if _, err := v.Verify(context.Background(), over); !errors.Is(err, ErrBadToken) {
		t.Fatalf("ceiling+1s accepted, so the bound is not tight: %v", err)
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
