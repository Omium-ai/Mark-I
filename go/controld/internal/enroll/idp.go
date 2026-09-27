package enroll

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	oidc "github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// tenantIdP is the per-tenant identity trust anchor (05 §3.2), read from the
// m1_tenants onboarding columns. The JWKS is the PINNED document
// (oidc_jwks_pinned, 05 §10.1 B2) — never fetched from jwks_uri at verify
// time, so a hijacked JWKS URI cannot mint approvals; rotation is an explicit
// re-pin at onboarding.
type tenantIdP struct {
	tenant             uuid.UUID
	issuer             string
	clientID           string
	jwksPinned         string
	deviceAuthEndpoint string
	tokenEndpoint      string
	operatorAudience   string
	operatorAdminClaim string
	operatorAdminValue string
}

// loadTenantIdP reads the tenant row under its own GUC (the m1_tenants RLS
// policy keys on id, so only the named tenant's row is visible). A tenant
// without completed IdP onboarding cannot enroll device #1 — refusal, not
// guesswork (m1_001 ENG-05).
func loadTenantIdP(ctx context.Context, db DB, tenant uuid.UUID) (*tenantIdP, error) {
	tid, err := tenantIDFor(tenant)
	if err != nil {
		return nil, err
	}
	idp := &tenantIdP{tenant: tenant}
	found := false
	err = db.WithTenant(ctx, tid, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			SELECT COALESCE(oidc_issuer,''), COALESCE(oidc_client_id,''),
			       COALESCE(oidc_jwks_pinned,''),
			       COALESCE(oidc_device_authorization_endpoint,''),
			       COALESCE(oidc_token_endpoint,''),
			       COALESCE(operator_audience,''), COALESCE(operator_admin_claim,''),
			       COALESCE(operator_admin_value,'')
			  FROM m1_tenants WHERE id = $1 AND status = 'active'`, tenant)
		switch scanErr := row.Scan(&idp.issuer, &idp.clientID, &idp.jwksPinned,
			&idp.deviceAuthEndpoint, &idp.tokenEndpoint,
			&idp.operatorAudience, &idp.operatorAdminClaim, &idp.operatorAdminValue); scanErr {
		case nil:
			found = true
			return nil
		case pgx.ErrNoRows:
			return nil
		default:
			return scanErr
		}
	})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errUnknownTenant
	}
	if idp.issuer == "" || idp.clientID == "" || idp.jwksPinned == "" ||
		idp.deviceAuthEndpoint == "" || idp.tokenEndpoint == "" {
		return nil, errTenantNotOnboarded
	}
	return idp, nil
}

// keySet parses the pinned JWKS into go-oidc's static verifier — static by
// design, see the type comment.
func (i *tenantIdP) keySet() (oidc.KeySet, error) {
	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal([]byte(i.jwksPinned), &jwks); err != nil {
		return nil, fmt.Errorf("enroll: pinned JWKS unparseable: %w", err)
	}
	keys := make([]crypto.PublicKey, 0, len(jwks.Keys))
	for _, k := range jwks.Keys {
		keys = append(keys, k.Key)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("enroll: pinned JWKS holds no keys")
	}
	return &oidc.StaticKeySet{PublicKeys: keys}, nil
}

// idpSigningAlgs: the asymmetric algorithms we accept from a tenant IdP.
// HS* is deliberately absent — a shared-secret alg against a public JWKS is
// the classic key-confusion attack.
var idpSigningAlgs = []string{oidc.RS256, oidc.PS256, oidc.ES256, oidc.ES384, oidc.EdDSA}

// approver is who approved an enrollment: the subject stored on the grant, and the email only as far as the issuer vouches for it.
type approver struct {
	subject       string
	email         string
	emailVerified bool
}

// verifyIDToken validates iss, aud (client_id), exp and signature against the
// pinned JWKS (05 §3.2) and returns the approving IdP subject — the
// `approved_by` half of the two-identity split — with its email claims (an undecodable pair reads as unverified).
func (i *tenantIdP) verifyIDToken(ctx context.Context, rawIDToken string) (approver, error) {
	ks, err := i.keySet()
	if err != nil {
		return approver{}, err
	}
	v := oidc.NewVerifier(i.issuer, ks, &oidc.Config{
		ClientID: i.clientID, SupportedSigningAlgs: idpSigningAlgs,
	})
	tok, err := v.Verify(ctx, rawIDToken)
	if err != nil {
		return approver{}, fmt.Errorf("enroll: ID token rejected: %w", err)
	}
	var c struct {
		Email    string `json:"email"`
		Verified bool   `json:"email_verified"`
	}
	if tok.Claims(&c) != nil {
		c.Email, c.Verified = "", false
	}
	return approver{subject: tok.Subject, email: c.Email, emailVerified: c.Verified}, nil
}

// operatorTenantClaim is the claim binding an operator token to the ONE
// tenant it may administer. Required because the rest of the pinned config
// (issuer, JWKS, audience, admin claim/value) is not guaranteed unique per
// tenant: two tenants onboarded against the same corporate IdP with the same
// audience and admin role would otherwise accept each other's admin tokens —
// the X-M1-Tenant header only ROUTES (which config to verify against), it can
// never GRANT. The tenant UUID is the one per-tenant fact that cannot
// collide, so the token must name it (the console requests it as a custom
// claim at mint, the same way Azure's tid / Auth0's org_id ride tokens).
const operatorTenantClaim = "m1_tenant"

// verifyOperatorToken admits the operator surface (08 §3: "a tenant-admin
// OIDC access token"): signature/iss/exp against the pinned JWKS, audience =
// operator_audience, then the onboarding-chosen admin claim must carry the
// onboarding-chosen value (m1_001 ENG-05 (d) — without that rule the operator
// surface has no admission rule at all), then the m1_tenant binding must name
// THIS tenant (see operatorTenantClaim). Binding runs LAST: only a token that
// already proved itself genuine and admin-bearing can learn it is bound
// elsewhere — and that outcome is the tampering-shaped one the caller reports
// as a security event.
func (i *tenantIdP) verifyOperatorToken(ctx context.Context, bearer string) (string, error) {
	if i.operatorAudience == "" || i.operatorAdminClaim == "" || i.operatorAdminValue == "" {
		return "", errTenantNotOnboarded
	}
	ks, err := i.keySet()
	if err != nil {
		return "", err
	}
	v := oidc.NewVerifier(i.issuer, ks, &oidc.Config{
		ClientID: i.operatorAudience, SupportedSigningAlgs: idpSigningAlgs,
	})
	tok, err := v.Verify(ctx, bearer)
	if err != nil {
		return "", fmt.Errorf("enroll: operator token rejected: %w", err)
	}
	var claims map[string]any
	if err := tok.Claims(&claims); err != nil {
		return "", err
	}
	if !claimHasValue(claims[i.operatorAdminClaim], i.operatorAdminValue) {
		return "", errNotAdmin
	}
	raw, _ := claims[operatorTenantClaim].(string)
	bound, parseErr := uuid.Parse(raw)
	if parseErr != nil || bound != i.tenant {
		return "", fmt.Errorf("%w: token %s claim %q, verifying tenant %s",
			errOperatorTenantMismatch, operatorTenantClaim, raw, i.tenant)
	}
	return tok.Subject, nil
}

// claimHasValue matches string claims and membership in array claims (IdPs
// deliver roles/groups both ways).
func claimHasValue(claim any, want string) bool {
	switch v := claim.(type) {
	case string:
		return v == want
	case []any:
		for _, e := range v {
			if s, ok := e.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// The RFC 8628 device-authorization grant, proxied server-side (05 §3.2: the
// device key must be bound to the approval server-side, and the CLI never
// holds an IdP client secret).
// ---------------------------------------------------------------------------

type deviceAuthResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

func (i *tenantIdP) startDeviceAuth(ctx context.Context, client *http.Client) (*deviceAuthResponse, error) {
	// client_id only: the device grant runs as a public client here; the
	// oidc_client_secret_ref (Secrets Manager) resolution is onboarding-plane
	// work not yet wired — recorded in the enroll build report.
	form := url.Values{"client_id": {i.clientID}, "scope": {"openid"}}
	body, status, err := postForm(ctx, client, i.deviceAuthEndpoint, form)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("enroll: IdP device authorization returned %d", status)
	}
	var r deviceAuthResponse
	if err := json.Unmarshal(body, &r); err != nil || r.DeviceCode == "" || r.UserCode == "" {
		return nil, fmt.Errorf("enroll: IdP device authorization response malformed")
	}
	return &r, nil
}

// pollOutcome is the §3.1 transition alphabet as seen from the IdP.
type pollOutcome int

const (
	pollPending pollOutcome = iota
	pollDenied
	pollExpired
	pollApproved
)

// pollIdPToken maps the RFC 8628 token-endpoint responses onto the state
// machine's transitions: authorization_pending/slow_down → PENDING (keep
// polling), access_denied → DENIED_APPROVAL, expired_token → EXPIRED,
// success → the ID token that (only after §3.2 validation) approves.
func (i *tenantIdP) pollIdPToken(ctx context.Context, client *http.Client, idpCode string) (pollOutcome, string, error) {
	form := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {idpCode},
		"client_id":   {i.clientID},
	}
	body, status, err := postForm(ctx, client, i.tokenEndpoint, form)
	if err != nil {
		return pollPending, "", err
	}
	if status == http.StatusOK {
		var r struct {
			IDToken string `json:"id_token"`
		}
		if err := json.Unmarshal(body, &r); err != nil || r.IDToken == "" {
			return pollPending, "", fmt.Errorf("enroll: IdP token response carries no id_token")
		}
		return pollApproved, r.IDToken, nil
	}
	var e struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(body, &e)
	switch e.Error {
	case "authorization_pending", "slow_down":
		return pollPending, "", nil
	case "access_denied":
		return pollDenied, "", nil
	case "expired_token":
		return pollExpired, "", nil
	default:
		return pollPending, "", fmt.Errorf("enroll: IdP token endpoint %d %q", status, e.Error)
	}
}

func postForm(ctx context.Context, client *http.Client, endpoint string, form url.Values) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("enroll: IdP unreachable: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, 0, err
	}
	return body, resp.StatusCode, nil
}
