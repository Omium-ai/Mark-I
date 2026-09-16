package userauth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
)

const issuer = "https://api.omium.ai"

type fixture struct {
	t      *testing.T
	key    *ecdsa.PrivateKey
	tenant uuid.UUID
	v      *Verifier
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	v, err := New(issuer, jwksFor(t, key.Public()))
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{t: t, key: key, tenant: uuid.New(), v: v}
}

// jwksFor pins the key the way the platform publishes it: kid = RFC 7638 thumbprint.
func jwksFor(t *testing.T, pub crypto.PublicKey) string {
	t.Helper()
	jwk := jose.JSONWebKey{Key: pub, Algorithm: "ES256", Use: "sig"}
	tp, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	jwk.KeyID = strings.ToLower(strings.TrimRight(string(tp), "="))
	b, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func (f *fixture) claims() map[string]any {
	now := time.Now()
	return map[string]any{
		"iss": issuer, "aud": Audience, "sub": "user-1", "email": "dev@example.com",
		"tenant_id": f.tenant.String(), "rol": []string{"tenant_admin"},
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "jti": uuid.NewString(),
	}
}

func (f *fixture) sign(alg jose.SignatureAlgorithm, key any, claims map[string]any) string {
	f.t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		f.t.Fatal(err)
	}
	payload, _ := json.Marshal(claims)
	jws, err := signer.Sign(payload)
	if err != nil {
		f.t.Fatal(err)
	}
	raw, err := jws.CompactSerialize()
	if err != nil {
		f.t.Fatal(err)
	}
	return raw
}

func (f *fixture) token(mut func(map[string]any)) string {
	c := f.claims()
	if mut != nil {
		mut(c)
	}
	return f.sign(jose.ES256, f.key, c)
}

func TestUserTokenVerifiesAndStampsClaims(t *testing.T) {
	f := newFixture(t)
	uc, err := f.v.Verify(context.Background(), f.token(nil))
	if err != nil {
		t.Fatal(err)
	}
	if uc.Sub != "user-1" || uc.Email != "dev@example.com" || uc.TenantID != f.tenant || !uc.HasRole("tenant_admin") || uc.HasRole("viewer") {
		t.Fatalf("claims: %+v", uc)
	}
	// The single-string role form some IdPs emit is a one-element list.
	uc, err = f.v.Verify(context.Background(), f.token(func(c map[string]any) { c["rol"] = "member" }))
	if err != nil || len(uc.Roles) != 1 || uc.Roles[0] != "member" {
		t.Fatalf("string rol: %+v %v", uc, err)
	}
}

// Frozen negative: an HS256 token with perfect claims is refused whatever the
// secret — a shared string, or the pinned public key's own bytes (key confusion).
func TestUserTokenRefusesHS256(t *testing.T) {
	f := newFixture(t)
	pubDER, err := x509.MarshalPKIXPublicKey(f.key.Public())
	if err != nil {
		t.Fatal(err)
	}
	for name, secret := range map[string][]byte{
		"shared_secret":    []byte("platform-jwt-secret-key-32-bytes-long!!"),
		"pinned_key_bytes": pubDER,
	} {
		tok := f.sign(jose.HS256, secret, f.claims())
		if _, err := f.v.Verify(context.Background(), tok); !errors.Is(err, ErrBadToken) {
			t.Fatalf("%s: HS256 token admitted: %v", name, err)
		}
	}
}

func TestUserTokenRefusals(t *testing.T) {
	f := newFixture(t)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cases := map[string]string{
		"wrong_aud":      f.token(func(c map[string]any) { c["aud"] = "dashboard" }),
		"wrong_iss":      f.token(func(c map[string]any) { c["iss"] = "https://evil.example" }),
		"expired":        f.token(func(c map[string]any) { c["exp"] = time.Now().Add(-time.Minute).Unix() }),
		"no_tenant":      f.token(func(c map[string]any) { delete(c, "tenant_id") }),
		"nil_tenant":     f.token(func(c map[string]any) { c["tenant_id"] = uuid.Nil.String() }),
		"garbage_tenant": f.token(func(c map[string]any) { c["tenant_id"] = "not-a-uuid" }),
		"no_sub":         f.token(func(c map[string]any) { delete(c, "sub") }),
		"foreign_key":    f.sign(jose.ES256, other, f.claims()),
		"garbage":        "not.a.jwt",
	}
	for name, tok := range cases {
		if _, err := f.v.Verify(context.Background(), tok); !errors.Is(err, ErrBadToken) {
			t.Fatalf("%s admitted: %v", name, err)
		}
	}
}

// Boot refusal: an unparseable, empty, or non-P-256 pinned document is no
// verifier at all — an oct key is exactly the HS* confusion foothold.
func TestNewRefusesBadPinnedJWKS(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	octJWKS, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: []byte("shared-secret"), KeyID: "oct"}}})
	for name, jwks := range map[string]string{
		"garbage": "{not json",
		"empty":   `{"keys":[]}`,
		"rsa":     jwksFor(t, rsaKey.Public()),
		"p384":    jwksFor(t, p384.Public()),
		"oct":     string(octJWKS),
	} {
		if _, err := New(issuer, jwks); err == nil {
			t.Fatalf("%s pinned JWKS accepted", name)
		}
	}
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := New("", jwksFor(t, ecKey.Public())); err == nil {
		t.Fatal("empty issuer accepted")
	}
}

func TestMiddlewareStampsAndMapsErrors(t *testing.T) {
	f := newFixture(t)
	var seen UserClaims
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, ok := ClaimsFrom(r.Context())
		if !ok {
			t.Fatal("claims not stamped")
		}
		seen = c
		w.WriteHeader(http.StatusNoContent)
	})
	obsCfg := obs.Config{ServiceName: "controld-test"}
	do := func(mw func(http.Handler) http.Handler, authz string) (int, string) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		if authz != "" {
			req.Header.Set("Authorization", authz)
		}
		mw(handler).ServeHTTP(rec, req)
		var body map[string]map[string]string
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		return rec.Code, body["error"]["code"]
	}
	anyUser := Middleware(f.v, obsCfg, "")
	admin := Middleware(f.v, obsCfg, TenantAdminRole)

	if st, code := do(anyUser, ""); st != http.StatusUnauthorized || code != "M1E-1002" {
		t.Fatalf("missing: %d %s", st, code)
	}
	if st, code := do(anyUser, "Bearer "+f.token(func(c map[string]any) { c["aud"] = "x" })); st != http.StatusUnauthorized || code != "M1E-1002" {
		t.Fatalf("bad token: %d %s", st, code)
	}
	member := f.token(func(c map[string]any) { c["rol"] = []string{"member"} })
	if st, code := do(admin, "Bearer "+member); st != http.StatusForbidden || code != "M1E-1001" {
		t.Fatalf("non-admin on admin surface: %d %s", st, code)
	}
	if st, _ := do(anyUser, "Bearer "+member); st != http.StatusNoContent || seen.Sub != "user-1" || seen.TenantID != f.tenant {
		t.Fatalf("member admitted on any-user surface: %d %+v", st, seen)
	}
	if st, _ := do(admin, "Bearer "+f.token(nil)); st != http.StatusNoContent {
		t.Fatalf("admin refused: %d", st)
	}
}
