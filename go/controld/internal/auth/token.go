package auth

// Production device tokens (05 §3.3): Ed25519-signed by the server, carrying
// {tenant_id, device_id, key_id, iat, exp} with exp − iat ≤ 24 h always.
// Verification is stateless — no DB hit on the hot path except the revocation
// cache, which is why the signature covers the whole payload and the claims
// carry everything ingest needs to stamp tenancy.

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

const tokenPrefix = "m1tok.v1"

// TokenTTLCeiling is the 05 §3.3 design floor: a stolen token dies within a
// day even if every revocation mechanism fails simultaneously.
const TokenTTLCeiling = 24 * time.Hour

// TenantRevocations is the production revocation seam (05 §3.4). It takes the
// tenant as well as the device because the checker reads m1_devices under the
// tenant GUC (05 §7.2) — controld_app cannot see any other tenant's rows, and
// the tenant here comes from the already-signature-verified claims, never from
// the client. An error return is FAIL-CLOSED by the verifier.
type TenantRevocations interface {
	IsRevoked(ctx context.Context, tenant, device uuid.UUID) (bool, error)
}

// Signer holds the server's Ed25519 device-token key. Enrollment is the only
// minter (05 §3.1: APPROVED → ACTIVE issues the first token; §3.3: refresh
// issues the rest).
type Signer struct {
	priv ed25519.PrivateKey
}

// NewSigner derives the keypair from a 32-byte seed (config-delivered; the
// same seed always yields the same public key, so a rolling deploy's pods
// agree on what they signed).
func NewSigner(seed []byte) (*Signer, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("auth: token signing seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	return &Signer{priv: ed25519.NewKeyFromSeed(seed)}, nil
}

func (s *Signer) Public() ed25519.PublicKey {
	return s.priv.Public().(ed25519.PublicKey)
}

// Mint issues a device token. iat/exp are caller-supplied because the FIRST
// token's expiry must satisfy the schema fact ck_m1_enroll_token_ttl
// (token_expires_at ≤ started_at + 24 h, migrations/m1_001): enroll pins
// exp to started_at+24h, refresh pins it to now+24h. The ceiling is enforced
// here too — an error, not a clamp, because a caller asking for more has a
// bug worth surfacing (05 §3.3).
func (s *Signer) Mint(tenant, device uuid.UUID, keyID string, iat, exp time.Time) (string, error) {
	if exp.Sub(iat) > TokenTTLCeiling {
		return "", fmt.Errorf("auth: token lifetime %v exceeds the 24 h ceiling (05 §3.3)", exp.Sub(iat))
	}
	payload, err := json.Marshal(devClaims{
		TenantID: tenant.String(), DeviceID: device.String(),
		KeyID: keyID, Iat: iat.Unix(), Exp: exp.Unix(),
	})
	if err != nil {
		return "", err
	}
	// The signature covers prefix + payload so a token cannot be replayed
	// into a future format version.
	signed := tokenPrefix + "." + base64.RawURLEncoding.EncodeToString(payload)
	sig := ed25519.Sign(s.priv, []byte(signed))
	return signed + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// Ed25519Verifier is the production Verifier: stateless signature + expiry
// checks, then the ≤60 s fail-closed revocation lookup (05 §3.4). It replaces
// the dev HMAC seam as the default in cmd; the checks run in the same order
// as HMACVerifier's so the two seams teach identical contracts.
type Ed25519Verifier struct {
	pub     ed25519.PublicKey
	revoked TenantRevocations
	// now is swappable for expiry tests only.
	now func() time.Time
}

func NewEd25519Verifier(pub ed25519.PublicKey, revoked TenantRevocations) *Ed25519Verifier {
	return &Ed25519Verifier{pub: pub, revoked: revoked, now: time.Now}
}

func (v *Ed25519Verifier) Verify(ctx context.Context, bearer string) (Claims, error) {
	parts := strings.Split(bearer, ".")
	if len(parts) != 4 || parts[0]+"."+parts[1] != tokenPrefix {
		return Claims{}, ErrBadToken
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return Claims{}, ErrBadToken
	}
	signed := parts[0] + "." + parts[1] + "." + parts[2]
	if !ed25519.Verify(v.pub, []byte(signed), sig) {
		return Claims{}, ErrBadToken
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
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
	// The ceiling is re-checked at verify: even a token our own key signed is
	// refused past 24 h of claimed life — defense against a minting bug, the
	// same posture the dev seam already teaches (05 §3.3).
	if now.After(exp) || exp.Sub(iat) > TokenTTLCeiling {
		return Claims{}, ErrBadToken
	}
	// Revocation AFTER signature: a forged token must never buy a revocation
	// lookup, and a genuine one must never skip it (05 §2.1 stage 2 order).
	revoked, err := v.revoked.IsRevoked(ctx, tenant, device)
	if err != nil {
		// Fail closed (05 §3.4): unknown revocation state = not verified.
		return Claims{}, fmt.Errorf("%w: revocation state unavailable", ErrBadToken)
	}
	if revoked {
		return Claims{}, ErrRevoked
	}
	return Claims{TenantID: tenant, DeviceID: device, KeyID: dc.KeyID, IssuedAt: iat, ExpiresAt: exp}, nil
}

// Multi tries verifiers in order — cmd wires it ONLY under AUTH_DEV_MODE=1 so
// dev stacks accept both enroll-minted and hand-minted tokens. ErrRevoked
// short-circuits: a revocation verdict from any seam is terminal, never
// retried against a laxer one.
func Multi(vs ...Verifier) Verifier { return multiVerifier(vs) }

type multiVerifier []Verifier

func (m multiVerifier) Verify(ctx context.Context, bearer string) (Claims, error) {
	for _, v := range m {
		c, err := v.Verify(ctx, bearer)
		if err == nil || errors.Is(err, ErrRevoked) {
			return c, err
		}
	}
	return Claims{}, ErrBadToken
}
