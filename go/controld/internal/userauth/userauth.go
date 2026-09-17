// Package userauth verifies the Omium-issued Mark 1 user token (ES256, aud "mark1", pinned JWKS); distinct from auth.Verifier's device identity by type.
package userauth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	oidc "github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
)

// Audience is the aud every Mark 1 user token must carry.
const Audience = "mark1"

// TenantAdminRole is the platform role that admits the operator surface.
const TenantAdminRole = "tenant_admin"

type UserClaims struct {
	Sub      string
	Email    string
	TenantID uuid.UUID
	Roles    []string
}

func (c UserClaims) HasRole(role string) bool { return slices.Contains(c.Roles, role) }

// ErrBadToken → 401 M1E-1002.
var ErrBadToken = errors.New("userauth: user token missing, expired, or bad signature")

type Verifier struct {
	v *oidc.IDTokenVerifier
}

// New refuses non-P-256 keys: an oct entry in a pinned JWKS is the HS* key-confusion foothold.
func New(issuer, jwksPinned string) (*Verifier, error) {
	if issuer == "" {
		return nil, errors.New("userauth: issuer is empty")
	}
	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal([]byte(jwksPinned), &jwks); err != nil {
		return nil, fmt.Errorf("userauth: pinned JWKS unparseable: %w", err)
	}
	keys := make([]crypto.PublicKey, 0, len(jwks.Keys))
	for _, k := range jwks.Keys {
		pk, ok := k.Key.(*ecdsa.PublicKey)
		if !ok || pk.Curve != elliptic.P256() {
			return nil, fmt.Errorf("userauth: pinned JWKS key %q is not a P-256 public key", k.KeyID)
		}
		keys = append(keys, pk)
	}
	if len(keys) == 0 {
		return nil, errors.New("userauth: pinned JWKS holds no keys")
	}
	return &Verifier{v: oidc.NewVerifier(issuer, &oidc.StaticKeySet{PublicKeys: keys}, &oidc.Config{
		ClientID: Audience, SupportedSigningAlgs: []string{oidc.ES256},
	})}, nil
}

// TenantVerifier admits the user token on the read surface (desktop spec §7.2: the cloud API takes the user session bearer) as an auth.Verifier whose Claims carry the tenant and Subject but no device; auth.Multi composes it beside the device verifier.
func (v *Verifier) TenantVerifier() auth.Verifier { return tenantVerifier{v} }

type tenantVerifier struct{ v *Verifier }

func (t tenantVerifier) Verify(ctx context.Context, bearer string) (auth.Claims, error) {
	c, err := t.v.Verify(ctx, bearer)
	if err != nil {
		return auth.Claims{}, fmt.Errorf("%w: %v", auth.ErrBadToken, err)
	}
	return auth.Claims{TenantID: c.TenantID, Subject: c.Sub}, nil
}

type wireClaims struct {
	Sub      string          `json:"sub"`
	Email    string          `json:"email"`
	TenantID string          `json:"tenant_id"`
	Rol      json.RawMessage `json:"rol"`
}

func (v *Verifier) Verify(ctx context.Context, bearer string) (UserClaims, error) {
	tok, err := v.v.Verify(ctx, bearer)
	if err != nil {
		return UserClaims{}, fmt.Errorf("%w: %v", ErrBadToken, err)
	}
	var wc wireClaims
	if err := tok.Claims(&wc); err != nil {
		return UserClaims{}, fmt.Errorf("%w: %v", ErrBadToken, err)
	}
	tenant, err := uuid.Parse(wc.TenantID)
	if err != nil || tenant == uuid.Nil || wc.Sub == "" {
		return UserClaims{}, fmt.Errorf("%w: claims lack sub or tenant_id", ErrBadToken)
	}
	return UserClaims{Sub: wc.Sub, Email: wc.Email, TenantID: tenant, Roles: roles(wc.Rol)}, nil
}

// roles accepts the platform's list form and the single-string form IdPs also use.
func roles(raw json.RawMessage) []string {
	var list []string
	if json.Unmarshal(raw, &list) == nil {
		return list
	}
	var one string
	if json.Unmarshal(raw, &one) == nil && one != "" {
		return []string{one}
	}
	return nil
}

// Middleware is server.Chain's sibling (auth → stamp → obs); requireRole "" admits any verified user, else 403 M1E-1001.
func Middleware(v *Verifier, obsCfg obs.Config, requireRole string) func(http.Handler) http.Handler {
	obsMW := obsCfg.HTTPMiddleware(nil)
	return func(next http.Handler) http.Handler {
		metered := obsMW(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if !ok || bearer == "" {
				writeErr(w, http.StatusUnauthorized, "M1E-1002", "user token missing")
				return
			}
			claims, err := v.Verify(r.Context(), bearer)
			if err != nil {
				writeErr(w, http.StatusUnauthorized, "M1E-1002", "user token invalid or expired")
				return
			}
			if requireRole != "" && !claims.HasRole(requireRole) {
				writeErr(w, http.StatusForbidden, "M1E-1001", "caller lacks role "+requireRole)
				return
			}
			metered.ServeHTTP(w, r.WithContext(WithClaims(r.Context(), claims)))
		})
	}
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"code": code, "message": msg},
	})
}

type ctxKey struct{}

func WithClaims(ctx context.Context, c UserClaims) context.Context {
	return context.WithValue(ctx, ctxKey{}, c)
}

// ClaimsFrom: ok=false means the middleware did not run — a wiring bug, not an anonymous request.
func ClaimsFrom(ctx context.Context) (UserClaims, bool) {
	c, ok := ctx.Value(ctxKey{}).(UserClaims)
	return c, ok
}
