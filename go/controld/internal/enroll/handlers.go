package enroll

// The 08 §3.1 wire surface. Contract notes where the doc leaves shape open:
//   - /device/start carries an additive "tenant" field: the CLI's
//     `mark1 enroll --tenant <slug>` (08 §7.1) must reach the server somehow
//     and 08 §3.1's body has no tenant carrier; it is a ROUTING key only —
//     a wrong value reads zero rows under RLS and the flow dies at M1E-2001.
//   - /nonce (named but not shaped by 08 §3.1) takes {tenant_id, device_id}
//     and binds them to the nonce server-side, so /enroll/token needs exactly
//     the documented body.
//   - operator endpoints locate the tenant via the X-M1-Tenant header —
//     never TRUSTED (identity is the operator token verifying against that
//     tenant's pinned JWKS + admin claim + m1_tenant binding, idp.go), only
//     used to pick which IdP config to verify against; the token's own
//     m1_tenant claim must name that same tenant or the request is refused
//     as a cross-tenant admin attempt (security event).

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
)

// ---------------------------------------------------------------------------
// POST /api/v1/enroll/device/start
// ---------------------------------------------------------------------------

type startRequest struct {
	Client        string `json:"client"`
	ClientVersion string `json:"client_version"`
	DevicePubkey  string `json:"device_pubkey"`
	Platform      string `json:"platform"`
	HostnameHash  string `json:"hostname_hash"`
	Tenant        string `json:"tenant"`
}

func (m *Module) handleStart(w http.ResponseWriter, r *http.Request) {
	boundBody(w, r)                    // pre-auth: 07 §6's 1 MiB admission bound
	if !m.startIP.Allow(clientIP(r)) { // §8.2: 10/hour per IP
		writeErr(w, http.StatusTooManyRequests, "M1E-9001", "enrollment start rate limit")
		return
	}
	var req startRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "M1E-2001", "malformed enrollment request")
		return
	}
	pubkey, err := parseDevicePubkey(req.DevicePubkey)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "M1E-2001", err.Error())
		return
	}
	hostnameHMAC, err := parseHostnameHash(req.HostnameHash)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "M1E-2001", err.Error())
		return
	}
	tenant, err := uuid.Parse(req.Tenant)
	if err != nil || tenant == uuid.Nil || req.Platform == "" {
		writeErr(w, http.StatusBadRequest, "M1E-2001", "tenant and platform are required")
		return
	}
	idp, err := loadTenantIdP(r.Context(), m.db, tenant)
	if errors.Is(err, errUnknownTenant) || errors.Is(err, errTenantNotOnboarded) {
		writeErr(w, http.StatusBadRequest, "M1E-2001", "tenant unknown or not onboarded for enrollment")
		return
	}
	if err != nil {
		m.serverErr(w, "start: tenant lookup", err)
		return
	}
	grant, err := idp.startDeviceAuth(r.Context(), m.http)
	if err != nil {
		m.serverErr(w, "start: IdP device authorization", err)
		return
	}
	code := encodeDeviceCode(tenant, req.Platform, hostnameHMAC, grant.DeviceCode)
	if err := m.insertEnrollment(r.Context(), tenant, hashCode(code), pubkey); err != nil {
		m.serverErr(w, "start: enrollment insert", err)
		return
	}
	transitionsTotal.WithLabelValues("pending").Inc()
	// user_code/verification_uri are the IdP's, verbatim (05 §3.2); expires_in
	// is capped at the state machine's own 15 min PENDING clock (§3.1) so the
	// CLI never polls a code the server already counts as dead.
	expiresIn := int(codeTTL.Seconds())
	if grant.ExpiresIn > 0 && grant.ExpiresIn < expiresIn {
		expiresIn = grant.ExpiresIn
	}
	interval := int(pollInterval.Seconds())
	if grant.Interval > interval {
		interval = grant.Interval
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"device_code":      code,
		"user_code":        grant.UserCode,
		"verification_uri": grant.VerificationURI,
		"expires_in":       expiresIn,
		"interval":         interval,
	})
}

// ---------------------------------------------------------------------------
// POST /api/v1/enroll/device/poll
// ---------------------------------------------------------------------------

func (m *Module) handlePoll(w http.ResponseWriter, r *http.Request) {
	boundBody(w, r) // pre-auth: 07 §6's 1 MiB admission bound
	var req struct {
		DeviceCode string `json:"device_code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.DeviceCode == "" {
		writeErr(w, http.StatusBadRequest, "M1E-1004", "unknown or expired device_code")
		return
	}
	tenant, platform, hostnameHMAC, idpCode, err := decodeDeviceCode(req.DeviceCode)
	if err != nil {
		// Malformed = unknown: the code is the secret, so its anatomy earns
		// no more detailed an answer than a wrong guess does.
		writeErr(w, http.StatusBadRequest, "M1E-1004", "unknown or expired device_code")
		return
	}
	codeHash := hashCode(req.DeviceCode)
	if !m.pollGap.Allow(hex.EncodeToString(codeHash)) { // §8.2: the flow's own interval
		writeErr(w, http.StatusTooManyRequests, "M1E-9001", "polling faster than interval")
		return
	}
	row, err := m.readEnrollment(r.Context(), tenant, codeHash)
	if err != nil {
		m.serverErr(w, "poll: enrollment read", err)
		return
	}
	switch {
	case row == nil:
		writeErr(w, http.StatusBadRequest, "M1E-1004", "unknown or expired device_code")
		return
	case row.status == "denied":
		// DENIED_APPROVAL is terminal (05 §3.1) — every later poll repeats it.
		writeErr(w, http.StatusForbidden, "M1E-1005", "user denied enrollment at the IdP")
		return
	case row.status != "pending":
		// expired, or approved/revoked — the code is single-use, consumed at
		// the first successful poll (05 §3.5 abuse case 2): a replay never
		// re-issues a token.
		writeErr(w, http.StatusBadRequest, "M1E-1004", "unknown or expired device_code")
		return
	}
	if m.now().After(row.startedAt.Add(codeTTL)) {
		// PENDING → EXPIRED: 15 min, no approval; terminal, restart flow.
		if err := m.transition(r.Context(), tenant, codeHash, "pending", "expired"); err != nil {
			m.serverErr(w, "poll: expire transition", err)
			return
		}
		transitionsTotal.WithLabelValues("expired").Inc()
		writeErr(w, http.StatusBadRequest, "M1E-1004", "device_code expired; re-run enrollment")
		return
	}

	idp, err := loadTenantIdP(r.Context(), m.db, tenant)
	if err != nil {
		m.serverErr(w, "poll: tenant lookup", err)
		return
	}
	outcome, rawIDToken, err := idp.pollIdPToken(r.Context(), m.http, idpCode)
	if err != nil {
		m.serverErr(w, "poll: IdP token endpoint", err)
		return
	}
	switch outcome {
	case pollPending:
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "pending"})
		return
	case pollDenied:
		if err := m.transition(r.Context(), tenant, codeHash, "pending", "denied"); err != nil {
			m.serverErr(w, "poll: deny transition", err)
			return
		}
		transitionsTotal.WithLabelValues("denied").Inc()
		writeErr(w, http.StatusForbidden, "M1E-1005", "user denied enrollment at the IdP")
		return
	case pollExpired:
		if err := m.transition(r.Context(), tenant, codeHash, "pending", "expired"); err != nil {
			m.serverErr(w, "poll: expire transition", err)
			return
		}
		transitionsTotal.WithLabelValues("expired").Inc()
		writeErr(w, http.StatusBadRequest, "M1E-1004", "device_code expired; re-run enrollment")
		return
	}

	// PENDING → APPROVED: only a §3.2-validated ID token approves — iss, aud,
	// exp, signature against the PINNED JWKS. An unverifiable "approval" is a
	// server-side trust failure, not a user denial, and must not consume the
	// grant: 503, retryable.
	subject, err := idp.verifyIDToken(r.Context(), rawIDToken)
	if err != nil {
		m.serverErr(w, "poll: ID token validation", err)
		return
	}
	device, token, expiresIn, err := m.approveEnrollment(r.Context(), tenant, codeHash, platform, hostnameHMAC, subject)
	if errors.Is(err, errCodeConsumed) {
		writeErr(w, http.StatusBadRequest, "M1E-1004", "unknown or expired device_code")
		return
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		// uq_m1_dkeys_key_id: this device key already backs an identity —
		// re-enrollment mints a NEW key by contract (05 §3.4: no un-revoke).
		writeErr(w, http.StatusBadRequest, "M1E-2001", "device key already enrolled; generate a new key")
		return
	}
	if err != nil {
		m.serverErr(w, "poll: approval", err)
		return
	}
	transitionsTotal.WithLabelValues("active").Inc()
	// APPROVED → ACTIVE: first token + endpoints + key manifest, 08 §3.1.
	writeJSON(w, http.StatusOK, map[string]any{
		"status":          "active",
		"device_id":       device.String(),
		"tenant_id":       tenant.String(), // informational; never trusted from the client later
		"device_token":    token,
		"expires_in":      expiresIn,
		"server_min_edge": m.minEdge,
		"endpoints": map[string]string{
			"ingest":        m.baseURL + "/m1p/v1/ingest",
			"attach":        m.baseURL + "/api/v1/attach",
			"policy_stream": m.baseURL + "/api/v1/policy/stream",
		},
		"key_manifest_uri": "/.well-known/mark1-keys",
	})
}

// ---------------------------------------------------------------------------
// POST /api/v1/enroll/nonce  +  POST /api/v1/enroll/token (PoP refresh, §3.3)
// ---------------------------------------------------------------------------

func (m *Module) handleNonce(w http.ResponseWriter, r *http.Request) {
	boundBody(w, r) // pre-auth: 07 §6's 1 MiB admission bound
	// Per-IP FIRST (this route is unauthenticated): the nonce store is the
	// shared 65536-entry substrate of every device's PoP refresh, and an
	// unlimited anonymous filler was the cheap way to 503 the whole fleet.
	if !m.nonceIP.Allow(clientIP(r)) {
		writeErr(w, http.StatusTooManyRequests, "M1E-9001", "nonce rate limit")
		return
	}
	var req struct {
		TenantID string `json:"tenant_id"`
		DeviceID string `json:"device_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "M1E-2001", "malformed nonce request")
		return
	}
	tenant, tErr := uuid.Parse(req.TenantID)
	device, dErr := uuid.Parse(req.DeviceID)
	if tErr != nil || dErr != nil || tenant == uuid.Nil || device == uuid.Nil {
		writeErr(w, http.StatusBadRequest, "M1E-2001", "tenant_id and device_id are required")
		return
	}
	nonce, ok := m.nonces.Issue(tenant, device)
	if !ok {
		writeErr(w, http.StatusServiceUnavailable, "M1E-9500", "nonce store saturated; retry")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"nonce": nonce, "expires_in": 60})
}

type tokenRequest struct {
	DeviceID    string `json:"device_id"`
	SignedNonce struct {
		Nonce       string `json:"nonce"`
		RequestedAt string `json:"requested_at"`
		Sig         string `json:"sig"`
	} `json:"signed_nonce"`
}

func (m *Module) handleToken(w http.ResponseWriter, r *http.Request) {
	boundBody(w, r) // pre-auth: 07 §6's 1 MiB admission bound
	var req tokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusUnauthorized, "M1E-1002", "bad proof-of-possession")
		return
	}
	device, err := uuid.Parse(req.DeviceID)
	if err != nil || device == uuid.Nil {
		writeErr(w, http.StatusUnauthorized, "M1E-1002", "bad proof-of-possession")
		return
	}
	// Single-use FIRST (05 §3.5 abuse case 4): a failed attempt burns the
	// nonce, so a captured request replays into nothing.
	rec, ok := m.nonces.Take(req.SignedNonce.Nonce)
	if !ok || rec.device != device {
		writeErr(w, http.StatusUnauthorized, "M1E-1002", "bad proof-of-possession")
		return
	}
	key, err := m.readDeviceKey(r.Context(), rec.tenant, device)
	if err != nil {
		m.serverErr(w, "token: device key read", err)
		return
	}
	if key == nil {
		writeErr(w, http.StatusUnauthorized, "M1E-1002", "bad proof-of-possession")
		return
	}
	// Signature BEFORE the revocation answer: a requester without the device
	// key never learns device state (same ordering as auth.Verify).
	sig, sigErr := decodeAny(req.SignedNonce.Sig)
	signed := []byte(req.SignedNonce.Nonce + device.String() + req.SignedNonce.RequestedAt)
	if sigErr != nil || len(key.pubkey) != ed25519.PublicKeySize ||
		!ed25519.Verify(ed25519.PublicKey(key.pubkey), signed, sig) {
		writeErr(w, http.StatusUnauthorized, "M1E-1002", "bad proof-of-possession signature")
		return
	}
	// §8.2's 12/day per-device budget is debited only AFTER proof-of-possession:
	// device_id is not a secret (it rides poll responses, enrollment.json and
	// --json output), so debiting on the caller's say-so would let anyone
	// drain a victim's budget and expire its ≤24 h token — denial-of-refresh
	// with no credential. Only the key holder can spend the key holder's budget.
	if !m.refresh.Allow(device.String()) {
		writeErr(w, http.StatusTooManyRequests, "M1E-9001", "token refresh rate limit")
		return
	}
	if key.revoked {
		// Terminal (05 §3.4): no un-revoke; the body says re-enroll.
		writeErr(w, http.StatusForbidden, "M1E-1003", "device revoked; re-enroll to continue")
		return
	}
	now := m.now()
	exp := now.Add(auth.TokenTTLCeiling)
	token, err := m.signer.Mint(rec.tenant, device, key.keyID, now, exp)
	if err != nil {
		m.serverErr(w, "token: mint", err)
		return
	}
	// ACTIVE→ACTIVE (or DORMANT→ACTIVE — same write; DORMANT is derived
	// bookkeeping, 05 §3.1). Best-effort: the token is already minted and the
	// next refresh re-derives last_seen.
	if err := m.touchLastSeen(r.Context(), rec.tenant, device); err != nil {
		log.Printf("enroll: last_seen heartbeat failed (device %s): %v", device, err)
	}
	// server_min_edge + key manifest ride the refresh: it is the fleet
	// heartbeat (05 §3.3), additive to 08 §3.1's minimum body.
	writeJSON(w, http.StatusOK, map[string]any{
		"device_token":     token,
		"expires_in":       int(exp.Sub(now).Seconds()),
		"server_min_edge":  m.minEdge,
		"key_manifest_uri": "/.well-known/mark1-keys",
	})
}

// ---------------------------------------------------------------------------
// Operator surface: POST /enroll/revoke + GET /enroll/devices
// ---------------------------------------------------------------------------

// operatorAuth verifies the operator token against the header-named tenant's
// pinned IdP config and returns (tenant, subject). The header only picks
// WHICH config to verify against; the admitting facts are all the token's
// (signature/iss/aud/admin claim, idp.go) — including its m1_tenant binding,
// which must name this same tenant: pinned configs are not guaranteed unique
// across tenants, so without the binding two tenants sharing an IdP could
// administer each other. Failures are uniformly 403 M1E-1001 — the surface
// does not distinguish "bad token" from "not an admin" to a caller who is
// neither — but a binding mismatch (a genuine admin token aimed at the wrong
// tenant) is additionally a security event.
func (m *Module) operatorAuth(w http.ResponseWriter, r *http.Request) (uuid.UUID, string, bool) {
	tenant, err := uuid.Parse(r.Header.Get("X-M1-Tenant"))
	if err != nil || tenant == uuid.Nil {
		writeErr(w, http.StatusForbidden, "M1E-1001", "not a tenant admin")
		return uuid.Nil, "", false
	}
	authz := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(authz) <= len(prefix) || authz[:len(prefix)] != prefix {
		writeErr(w, http.StatusForbidden, "M1E-1001", "not a tenant admin")
		return uuid.Nil, "", false
	}
	idp, err := loadTenantIdP(r.Context(), m.db, tenant)
	if err != nil {
		writeErr(w, http.StatusForbidden, "M1E-1001", "not a tenant admin")
		return uuid.Nil, "", false
	}
	subject, err := idp.verifyOperatorToken(r.Context(), authz[len(prefix):])
	if err != nil {
		if errors.Is(err, errOperatorTenantMismatch) {
			operatorTenantMismatches.Inc()
			log.Printf("SECURITY enroll: cross-tenant operator attempt on %s %s: %v", r.Method, r.URL.Path, err)
		}
		writeErr(w, http.StatusForbidden, "M1E-1001", "not a tenant admin")
		return uuid.Nil, "", false
	}
	return tenant, subject, true
}

func (m *Module) handleRevoke(w http.ResponseWriter, r *http.Request) {
	boundBody(w, r) // same 1 MiB bound as the pre-auth class (07 §6)
	tenant, subject, ok := m.operatorAuth(w, r)
	if !ok {
		return
	}
	var req struct {
		DeviceID string `json:"device_id"`
		Reason   string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "M1E-2001", "malformed revoke request")
		return
	}
	device, err := uuid.Parse(req.DeviceID)
	if err != nil || device == uuid.Nil {
		writeErr(w, http.StatusBadRequest, "M1E-2001", "device_id is required")
		return
	}
	outcome, err := m.revokeDevice(r.Context(), tenant, device, subject, req.Reason)
	if err != nil {
		m.serverErr(w, "revoke", err)
		return
	}
	if outcome == deviceNotFound {
		writeErr(w, http.StatusNotFound, "M1E-1006", "unknown device")
		return
	}
	if outcome == revokedNow {
		transitionsTotal.WithLabelValues("revoked").Inc()
		if m.cache != nil {
			m.cache.Invalidate(device)
		}
	}
	// receipt_seq (08 §3.1) deliberately absent until the C6 receipt writer
	// lands — see the package doc's DEFERRED note.
	writeJSON(w, http.StatusOK, map[string]any{
		"device_id": device.String(),
		"state":     "revoked",
	})
}

func (m *Module) handleDevices(w http.ResponseWriter, r *http.Request) {
	tenant, _, ok := m.operatorAuth(w, r)
	if !ok {
		return
	}
	limit := 100
	if s := r.URL.Query().Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 {
			writeErr(w, http.StatusBadRequest, "M1E-2001", "malformed limit")
			return
		}
		limit = min(n, 500)
	}
	after, err := parseCursor(r.URL.Query().Get("cursor"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "M1E-2001", "malformed cursor")
		return
	}
	items, err := m.listDevices(r.Context(), tenant, after, limit)
	if err != nil {
		m.serverErr(w, "devices list", err)
		return
	}
	var next any
	if len(items) == limit {
		next = items[len(items)-1].ID.String()
	}
	if items == nil {
		items = []deviceListItem{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": items, "next_cursor": next})
}

// ---------------------------------------------------------------------------
// Device-token surface: the §3.6 fingerprint registry
// ---------------------------------------------------------------------------

func (m *Module) handleFingerprintRegister(w http.ResponseWriter, r *http.Request) {
	boundBody(w, r) // same 1 MiB bound as the pre-auth class (07 §6)
	claims, ok := auth.ClaimsFrom(r.Context())
	if !ok { // middleware did not run — a wiring bug, not an anonymous request
		m.serverErr(w, "fingerprints: no verified claims", errors.New("auth middleware missing"))
		return
	}
	var req struct {
		Fingerprint   string `json:"fingerprint"`
		UpstreamClass string `json:"upstream_class"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.UpstreamClass == "" {
		writeErr(w, http.StatusBadRequest, "M1E-2001", "fingerprint and upstream_class are required")
		return
	}
	fp, err := decodeAny(req.Fingerprint)
	if err != nil || len(fp) != 32 {
		// 32 bytes = HMAC-SHA256(k_device, credential_bytes) (§3.6); the
		// credential bytes themselves never travel.
		writeErr(w, http.StatusBadRequest, "M1E-2001", "fingerprint must decode to 32 bytes")
		return
	}
	if err := m.registerFingerprint(r.Context(), claims.TenantID, claims.DeviceID, fp, req.UpstreamClass); err != nil {
		m.serverErr(w, "fingerprints: register", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"registered": true})
}

func (m *Module) handleFingerprintList(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFrom(r.Context())
	if !ok {
		m.serverErr(w, "fingerprints: no verified claims", errors.New("auth middleware missing"))
		return
	}
	items, err := m.listFingerprints(r.Context(), claims.TenantID, claims.DeviceID)
	if err != nil {
		m.serverErr(w, "fingerprints: list", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"fingerprints": items})
}

// serverErr is the retryable-5xx path: log with context, answer M1E-9500
// (retryable per 08 §9's reading rules) without leaking internals.
func (m *Module) serverErr(w http.ResponseWriter, where string, err error) {
	log.Printf("enroll: %s: %v", where, err)
	writeErr(w, http.StatusServiceUnavailable, "M1E-9500", "temporarily unavailable; retry")
}
