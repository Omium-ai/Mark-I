// Package enroll owns device identity (05 §3): the OIDC device-code state
// machine run against the tenant's own IdP (§3.2), ≤24 h Ed25519 device
// tokens with proof-of-possession refresh (§3.3), revocation with the ≤60 s
// fail-closed cache (§3.4, revocation.go), and the enrollment credential
// fingerprints the proxy guard matches (§3.6). The wire surface is 08 §3.1.
//
// DEFERRED, recorded here and in the build report: every §3.1 transition is
// specified to write a per-event receipt, and 08 §3.1's revoke response shows
// `receipt_seq` — the receipt writer (locked head row, dual signature,
// m1_002) ships with the vendored receipt package (13 §11 C6), the exact
// deferral sidefx already records for CoverageTransition rows. Until then the
// transitions land in Postgres unreceipted and the revoke response omits
// receipt_seq. The daily reconciliation sweep (§3.5 abuse case 3) is also
// C6-adjacent: it is the one enroll path sanctioned to use the worker role
// (05 §7.3) and does not exist yet.
package enroll

import (
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/json"
	"net"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/pg"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/policydist"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/server"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/userauth"

	"errors"

	"github.com/jackc/pgx/v5"
)

var transitionsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "controld_enroll_transitions_total",
	Help: "Device enrollment state-machine transitions (05 §3.1)",
}, []string{"to"})

// operatorTenantMismatches counts genuine, admin-bearing operator tokens
// refused because their m1_tenant binding names ANOTHER tenant (idp.go
// operatorTenantClaim) — each one is a cross-tenant admin attempt and is also
// logged as a SECURITY line by operatorAuth.
var operatorTenantMismatches = promauto.NewCounter(prometheus.CounterOpts{
	Name: "controld_enroll_operator_tenant_mismatch_total",
	Help: "Operator tokens bound to a different tenant than the one they tried to administer (security events)",
})

// DB is the WithTenant-shaped seam (05 §7.2); *pg.TenantDB satisfies it and
// tests fake it.
type DB interface {
	WithTenant(ctx context.Context, t querychoke.TenantID, fn func(pgx.Tx) error) error
}

var _ DB = (*pg.TenantDB)(nil)

// PGReady is the readiness slice of pg.TenantDB (05 §1.4: enroll's readiness
// contributor is a Postgres ping — identity decisions need nothing else).
type PGReady interface {
	Ready(ctx context.Context) error
}

// Sentinel errors internal to the module; handlers own the M1E mapping.
var (
	errUnknownTenant      = errors.New("enroll: unknown tenant")
	errTenantNotOnboarded = errors.New("enroll: tenant IdP onboarding incomplete (m1_001 ck_m1_tenants_onboarded)")
	errNotAdmin           = errors.New("enroll: operator token lacks the tenant admin claim")
	// errOperatorTenantMismatch: the token is genuine and admin-bearing but
	// bound (m1_tenant claim) to a DIFFERENT tenant than the one it is trying
	// to administer — a cross-tenant admin attempt, reported as a security
	// event by operatorAuth.
	errOperatorTenantMismatch = errors.New("enroll: operator token is bound to another tenant")
)

// Deps: everything injected, nothing global — the module-boundary rule
// (05 §0.2).
type Deps struct {
	DB     DB
	PG     PGReady
	Signer *auth.Signer
	// Verifier guards the device-token surface (POST/GET /enroll/fingerprints,
	// §3.6). It is the SHARED verifier from cmd — one binary, one revocation
	// posture (05 §0.1).
	Verifier auth.Verifier
	ObsCfg   obs.Config
	// Cache, when set, gets local invalidation on revoke so THIS pod cuts a
	// revoked device off immediately; other pods ride the ≤60 s ceiling.
	Cache *RevocationCache
	Users *userauth.Verifier // nil ⇒ /approve answers 503 and the operator surface takes tenant-IdP tokens only

	PublicBaseURL string
	ServerMinEdge string
	HTTPClient    *http.Client // nil ⇒ 10 s timeout (§8.3 tenant-IdP hop)
	Now           func() time.Time
	// TenantPepper is config.TenantHMACPepper: the root every tenant's HMAC
	// root is derived from (TenantRoot). Nil ⇒ the enroll and refresh bodies
	// omit tenant_root_hex and the edge can never key idem_key — the caller
	// (cmd) decides whether that is a boot refusal or a dev-mode WARNING.
	TenantPepper []byte
	// Bootstrap is policydist.Module.Bootstrap: the tenant's first bundle, published when a device goes ACTIVE; nil ⇒ none (a fresh edge stays on built-ins).
	Bootstrap func(ctx context.Context, tenant uuid.UUID) error
	// BundleKeys is policydist.Module.BundleKeys: the section keys every ACTIVE and refresh body pins on the edge (bundle_section_keys); nil ⇒ absent.
	BundleKeys func() []policydist.ManifestKey
}

type Module struct {
	db       DB
	pgReady  PGReady
	signer   *auth.Signer
	verifier auth.Verifier
	obsCfg   obs.Config
	cache    *RevocationCache
	users    *userauth.Verifier

	baseURL    string
	minEdge    string
	http       *http.Client
	now        func() time.Time
	pepper     []byte
	bootstrap  func(context.Context, uuid.UUID) error
	bundleKeys func() []policydist.ManifestKey

	nonces    *nonceStore
	pollGap   *pacer         // §8.2: /poll at the flow's own interval (5 s)
	startIP   *bucketLimiter // §8.2: /start per IP, 10/hour
	approveIP *bucketLimiter // /approve per IP, same budget as /start
	refresh   *bucketLimiter // §8.2: token refresh per device, 12/day
	nonceIP   *bucketLimiter // /nonce per IP — see New for the budget's WHY
}

func New(d Deps) *Module {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.HTTPClient == nil {
		d.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &Module{
		db: d.DB, pgReady: d.PG, signer: d.Signer, verifier: d.Verifier,
		obsCfg: d.ObsCfg, cache: d.Cache, users: d.Users,
		baseURL: d.PublicBaseURL, minEdge: d.ServerMinEdge,
		http: d.HTTPClient, now: d.Now, pepper: d.TenantPepper,
		bootstrap: d.Bootstrap, bundleKeys: d.BundleKeys,
		nonces:    newNonceStore(d.Now),
		pollGap:   newPacer(pollInterval, d.Now),
		startIP:   newBucketLimiter(10, time.Hour, d.Now),
		approveIP: newBucketLimiter(10, time.Hour, d.Now),
		refresh:   newBucketLimiter(12, 24*time.Hour, d.Now),
		// /nonce is unauthenticated and was the cheap path to saturating the
		// 65536-entry store (a saturated store 503s EVERY device's PoP refresh
		// within 24 h). 120/hour per IP: a device needs ~1 nonce per refresh at
		// 12/day (§8.2), so even a large NAT'd office fits, while saturating
		// the store now needs tens of thousands of source IPs sustained.
		// ponytail: per-pod bucket like the two above — same shared-store
		// upgrade trigger as §8.2's own note.
		nonceIP: newBucketLimiter(120, time.Hour, d.Now),
	}
}

func (m *Module) Name() string { return "enroll" }

// TenantRoot is 04 §2.9's per-tenant HMAC root — "delivered at enrollment,
// custody same ladder" — derived, never stored: HKDF-SHA256(pepper, info =
// tenant id), so the same tenant always receives the same root and no row
// anywhere holds it (m1_001 hmac_salt_secret_ref: "storing the secret here
// would make this table a credential vault without the vault"). It rides
// ONLY the authenticated enroll/refresh bodies — never a list endpoint.
// ponytail: hmac_salt_version (m1_001) is not folded into the info string;
// fold it in when rotation/crypto-erasure (10 §9) gets a caller.
func (m *Module) TenantRoot(tenant uuid.UUID) ([]byte, error) {
	if len(m.pepper) == 0 {
		return nil, errors.New("enroll: no tenant pepper configured (TENANT_HMAC_PEPPER)")
	}
	return hkdf.Key(sha256.New, m.pepper, nil, "mark1-tenant-root-v1:"+tenant.String(), 32)
}

func (m *Module) Ready(ctx context.Context) error { return m.pgReady.Ready(ctx) }

func (m *Module) RegisterRoutes(mux *http.ServeMux) {
	// Unauthenticated by design (08 §3.1): start/poll are pre-identity (the
	// device_code is the secret), nonce/token are proof-of-possession.
	mux.HandleFunc("POST /api/v1/enroll/device/start", m.handleStart)
	mux.HandleFunc("POST /api/v1/enroll/device/poll", m.handlePoll)
	mux.HandleFunc("POST /api/v1/enroll/nonce", m.handleNonce)
	mux.HandleFunc("POST /api/v1/enroll/token", m.handleToken)
	if m.users != nil { // unconfigured is a loud 503, never an absent route (the INTEL_BASE_URL precedent)
		userChain := userauth.Middleware(m.users, m.obsCfg, "")
		mux.Handle("POST /api/v1/enroll/device/approve", userChain(http.HandlerFunc(m.handleApprove)))
	} else {
		mux.HandleFunc("POST /api/v1/enroll/device/approve", func(w http.ResponseWriter, _ *http.Request) {
			writeErr(w, http.StatusServiceUnavailable, "M1E-9500", "omium user sign-in not configured (OMIUM_USER_ISSUER)")
		})
	}
	// Operator-token surface; admission is operatorAuth per request.
	mux.HandleFunc("POST /api/v1/enroll/revoke", m.handleRevoke)
	mux.HandleFunc("GET /api/v1/enroll/devices", m.handleDevices)
	// Device-token surface (§3.6) through the shared auth middleware.
	chain := server.Chain(m.verifier, m.obsCfg, nil)
	mux.Handle("POST /api/v1/enroll/fingerprints", chain(http.HandlerFunc(m.handleFingerprintRegister)))
	mux.Handle("GET /api/v1/enroll/fingerprints", chain(http.HandlerFunc(m.handleFingerprintList)))
}

// pollInterval is the §3.1 flow interval the CLI is told (and held to, §8.2).
const pollInterval = 5 * time.Second

// codeTTL is the §3.1 PENDING→EXPIRED clock: 15 min, no approval, terminal.
const codeTTL = 15 * time.Minute

// maxBodyBytes bounds every enroll request body (07 §6's 1 MiB admission
// bound, applied to this surface's small JSON envelopes): four of these
// handlers are unauthenticated, and an unbounded json.Decode is an
// unauthenticated memory allocation. Ingest is the only legitimately large
// POST and owns its own stage-1 bounds (05 §2.1).
const maxBodyBytes = 1 << 20

// boundBody caps the request body; the JSON decoder then surfaces an
// over-limit read as a decode error, landing in each handler's existing
// malformed-request path.
func boundBody(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// writeErr emits the one-taxonomy error shape (08 §9).
func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]string{"code": code, "message": msg},
	})
}

func clientIP(r *http.Request) string {
	// ponytail: RemoteAddr only — honoring X-Forwarded-For safely needs the
	// trusted-proxy config 09 owns; a spoofable header is worse than a NAT'd
	// rate bucket.
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
