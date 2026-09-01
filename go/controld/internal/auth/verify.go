package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Claims are the verified device-token claims (05 §2.1 stage 2:
// {tenant_id, device_id, key_id, exp}). They exist only as the output of
// Verify — nothing else in controld may construct an identity.
type Claims struct {
	TenantID  uuid.UUID
	DeviceID  uuid.UUID
	KeyID     string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// Sentinel errors map 1:1 onto 08 §9 rows; the HTTP layer owns the mapping.
var (
	// ErrBadToken → 401 M1E-1002 (missing/expired/bad signature).
	ErrBadToken = errors.New("auth: token missing, expired, or bad signature")
	// ErrRevoked → 403 M1E-1003 (terminal; re-enroll).
	ErrRevoked = errors.New("auth: device revoked")
)

// Verifier is the seam every module authenticates through. One binary, one
// verifier — two modules disagreeing about whether a device is revoked is a
// security bug we choose not to be able to have (05 §0.1).
type Verifier interface {
	Verify(ctx context.Context, bearer string) (Claims, error)
}

// StaticRevocations is the TEST checker: an explicit set, no staleness
// (there is nothing to go stale — it IS the authority in a test). It satisfies
// the same TenantRevocations seam as enroll's cache so both verifier legs
// share one revocation shape (05 §0.1: one binary, one revocation posture);
// the tenant is ignored because the set is device-keyed by construction.
type StaticRevocations map[uuid.UUID]bool

func (s StaticRevocations) IsRevoked(_ context.Context, _, device uuid.UUID) (bool, error) {
	return s[device], nil
}

// ---------------------------------------------------------------------------
// Dev HMAC token: v1.<b64url(claims JSON)>.<b64url(HMAC-SHA256(key, payload))>
// ---------------------------------------------------------------------------

const devPrefix = "m1dev.v1"

type devClaims struct {
	TenantID string `json:"tenant_id"`
	DeviceID string `json:"device_id"`
	KeyID    string `json:"key_id"`
	Iat      int64  `json:"iat"`
	Exp      int64  `json:"exp"`
}

// HMACVerifier verifies dev tokens minted by Mint. The exp ceiling is checked
// against the same TokenTTLCeiling constant the production verifier uses, not
// a second literal — moving the constant now moves both seams together, which
// it did not before D-DT. exp − iat ≤ 24 h is a
// design floor (05 §3.3 — a stolen token dies within a day even if every
// revocation mechanism fails simultaneously), so the dev seam enforces it too
// rather than teaching tests a laxer contract. Revocation rides the SAME
// TenantRevocations seam as the production verifier (05 §3.4): a dev-mode leg
// with an empty revocation set would be a second, laxer revocation posture —
// the exact bug 05 §0.1 forbids the binary from being able to have.
type HMACVerifier struct {
	Key     []byte
	Revoked TenantRevocations
	// now is swappable for expiry tests only.
	now func() time.Time
}

func NewHMACVerifier(key []byte, revoked TenantRevocations) *HMACVerifier {
	return &HMACVerifier{Key: key, Revoked: revoked, now: time.Now}
}

func (v *HMACVerifier) Verify(ctx context.Context, bearer string) (Claims, error) {
	parts := strings.Split(bearer, ".")
	if len(parts) != 4 || parts[0]+"."+parts[1] != devPrefix {
		return Claims{}, ErrBadToken
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Claims{}, ErrBadToken
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return Claims{}, ErrBadToken
	}
	mac := hmac.New(sha256.New, v.Key)
	mac.Write(payload)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return Claims{}, ErrBadToken
	}
	var dc devClaims
	if err := json.Unmarshal(payload, &dc); err != nil {
		return Claims{}, ErrBadToken
	}
	tenant, err := uuid.Parse(dc.TenantID)
	if err != nil || tenant == uuid.Nil {
		return Claims{}, ErrBadToken
	}
	device, err := uuid.Parse(dc.DeviceID)
	if err != nil || device == uuid.Nil {
		return Claims{}, ErrBadToken
	}
	iat, exp := time.Unix(dc.Iat, 0), time.Unix(dc.Exp, 0)
	now := v.now()
	if now.After(exp) || exp.Sub(iat) > TokenTTLCeiling {
		return Claims{}, ErrBadToken
	}
	// Revocation AFTER signature: a forged token must never buy a revocation
	// lookup, and a genuine one must never skip it (05 §2.1 stage 2 order).
	revoked, err := v.Revoked.IsRevoked(ctx, tenant, device)
	if err != nil {
		// Fail closed (05 §3.4): unknown revocation state = not verified.
		return Claims{}, fmt.Errorf("%w: revocation state unavailable", ErrBadToken)
	}
	if revoked {
		return Claims{}, ErrRevoked
	}
	return Claims{TenantID: tenant, DeviceID: device, KeyID: dc.KeyID, IssuedAt: iat, ExpiresAt: exp}, nil
}

// Mint issues a dev token. It has no non-test caller: production minting is
// Signer.Mint, which refuses an over-ceiling request outright (05 §3.3). This
// one deliberately does NOT, and must not — it is the fixture the ceiling is
// tested WITH, so it has to be able to build the token the verifier is
// supposed to refuse. It clamped to 24 h until D-DT: a test asking for 25 h
// silently received a valid 24 h token and passed green having exercised
// nothing, which is why TestOver24hTokenRejectedAtIngestRoute had to hand-sign
// its own tokens rather than ask a minter for one.
func Mint(key []byte, tenant, device uuid.UUID, ttl time.Duration) string {
	now := time.Now()
	payload, _ := json.Marshal(devClaims{
		TenantID: tenant.String(), DeviceID: device.String(),
		KeyID: "dev-hmac-1", Iat: now.Unix(), Exp: now.Add(ttl).Unix(),
	})
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	return devPrefix + "." +
		base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// ---------------------------------------------------------------------------
// Request-context plumbing (the 05 §2.1 stage-3 stamp travels here)
// ---------------------------------------------------------------------------

type ctxKey struct{}

func WithClaims(ctx context.Context, c Claims) context.Context {
	return context.WithValue(ctx, ctxKey{}, c)
}

// ClaimsFrom returns the verified stamp. ok=false means the middleware did
// not run — callers must treat that as a bug, not an anonymous request.
func ClaimsFrom(ctx context.Context) (Claims, bool) {
	c, ok := ctx.Value(ctxKey{}).(Claims)
	return c, ok
}
