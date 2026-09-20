// The HTTP surface (08 §3.2):
//
//	GET  /api/v1/policy/bundle?channel=stable   ETag-conditional, application/cbor
//	GET  /api/v1/policy/stream?channel=stable   SSE hints
//	POST /api/v1/policy/ack                     the ACK ledger's intake
//	POST /internal/v1/judge-requests            service-token: fan a JudgeRequest out (judge.go)
//	GET  /.well-known/mark1-keys                08 §3.5: bundle section keys, plus the caller's tlog head under a device token
//
// Publication has no route here on purpose: 05 §4.1 places it on "policydist's
// internal publication path (in-repo, not a public route)". Module.Publish is
// that path. A bundle that can be published over HTTP is a bundle an attacker
// with one stolen operator token can push to a fleet.
//
// Tenancy comes from verified claims on every route, without exception. The
// ACK body deliberately carries no tenant_id and no device_id (08 §3.2
// divergence #4): both are stamped, and a body that could assert them would
// make cross-tenant ACK injection a matter of typing.

package policydist

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/server"
)

// PGReady is the readiness slice of pg.TenantDB.
type PGReady interface {
	Ready(ctx context.Context) error
}

type ModuleDeps struct {
	Store    *Store
	PG       PGReady
	Verifier auth.Verifier
	ObsCfg   obs.Config
	// IntelServiceToken guards the internal judge-request route (judge.go), the same credential as receipts' append route; empty verifies nothing, so the surface is absent, never open.
	IntelServiceToken string
	// Salt is the per-tenant HMAC root (enroll.Module.TenantRoot) the canary controller assigns cohorts with (05 §4.3 item 1).
	Salt func(uuid.UUID) ([]byte, error)
}

type Module struct {
	store        *Store
	pgReady      PGReady
	verifier     auth.Verifier
	obsCfg       obs.Config
	hub          *Hub
	limiter      *limiter
	serviceToken string
	salt         func(uuid.UUID) ([]byte, error)
}

func NewModule(d ModuleDeps) *Module {
	return &Module{
		store: d.Store, pgReady: d.PG, verifier: d.Verifier, obsCfg: d.ObsCfg,
		hub: NewHub(), limiter: newLimiter(), serviceToken: d.IntelServiceToken, salt: d.Salt,
	}
}

// SetSalt wires the cohort salt after enroll exists (enroll is built on this module, so the dependency runs the other way at boot).
func (m *Module) SetSalt(f func(uuid.UUID) ([]byte, error)) { m.salt = f }

func (m *Module) Name() string { return "policydist" }

// Ready: Postgres. The catalog is Postgres and nothing else; the SSE hub is
// in-process and cannot be unready, and the transparency log lives in the same
// database as the catalog.
func (m *Module) Ready(ctx context.Context) error { return m.pgReady.Ready(ctx) }

// Drain is server.Drainer: end every stream with a final ping (05 §1.5).
func (m *Module) Drain() { m.hub.Drain() }

// Hub exposes the fan-out so the revocation path (05 §3.4) can push an epoch
// on every live stream the instant a device is revoked.
func (m *Module) Hub() *Hub { return m.hub }

func (m *Module) RegisterRoutes(mux *http.ServeMux) {
	chain := server.Chain(m.verifier, m.obsCfg, nil)
	mux.Handle("GET /api/v1/policy/bundle", chain(http.HandlerFunc(m.handleBundle)))
	mux.Handle("GET /api/v1/policy/stream", chain(http.HandlerFunc(m.handleStream)))
	mux.Handle("POST /api/v1/policy/ack", chain(http.HandlerFunc(m.handleAck)))
	mux.Handle("POST /internal/v1/judge-requests", m.obsCfg.HTTPMiddleware(nil)(http.HandlerFunc(m.handleJudgeRequest)))
	mux.Handle("GET /.well-known/mark1-keys", m.obsCfg.HTTPMiddleware(nil)(http.HandlerFunc(m.handleKeys)))
}

// BundleKeys is the section ring as 08 §3.5 lists it, nil when this process holds no ring; enrollment pins it on the edge.
func (m *Module) BundleKeys() []ManifestKey {
	if m.store.ring == nil {
		return nil
	}
	keys, _ := m.store.ring.ManifestKeys(nil)
	return keys
}

// handleKeys is unauthenticated by design (08 §3.5) — public keys only. The tlog is per tenant (m1_062), so the head rides only for a verifiable device token, at ?tree_size (the head a bundle's proof targets) or newest.
func (m *Module) handleKeys(w http.ResponseWriter, r *http.Request) {
	keys := m.BundleKeys()
	if keys == nil {
		keys = []ManifestKey{}
	}
	out := map[string]any{"schema": KeyManifestSchema, "bundle_section_keys": keys, "tlog": map[string]any{}}
	if bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok && bearer != "" {
		if claims, err := m.verifier.Verify(r.Context(), bearer); err == nil {
			if tenant, err := querychoke.FromClaims(claims); err == nil {
				size, _ := strconv.ParseInt(r.URL.Query().Get("tree_size"), 10, 64)
				if h, err := m.store.SignedHead(r.Context(), tenant, max(size, 0)); err == nil {
					out["tlog"] = map[string]any{"head": map[string]any{
						"size": h.TreeSize, "root": hex.EncodeToString(h.Root), "key_id": h.KeyID, "sig": hex.EncodeToString(h.Signature),
					}}
				}
			}
		}
	}
	w.Header().Set("Cache-Control", "no-cache")
	writeJSON(w, out)
}

// Publish is the internal publication path. The SSE hint fires only after the
// transaction has committed -- hinting a seq that then rolls back sends the
// whole fleet to fetch a bundle that does not exist.
func (m *Module) Publish(ctx context.Context, tenant querychoke.TenantID, d Draft) (Published, error) {
	p, err := m.store.Publish(ctx, tenant, d)
	if err != nil {
		return Published{}, err
	}
	m.hub.Publish(tenant.UUID(), p.Channel, p.Seq, p.ETag)
	return p, nil
}

// ---------------------------------------------------------------------------
// GET /api/v1/policy/bundle
// ---------------------------------------------------------------------------

// steerChannel (05 §4.3 item 1): on a stable poll an in-cohort device under an active, un-halted, unpromoted canary rollout is told to move to canary.
func (m *Module) steerChannel(ctx context.Context, tenant querychoke.TenantID, deviceID uuid.UUID) string {
	if m.salt == nil {
		return BootstrapChannel
	}
	percent, err := m.store.ActiveCanaryCohort(ctx, tenant)
	if err != nil {
		return BootstrapChannel // fail-closed toward stable: an unreadable cursor steers nobody
	}
	salt, err := m.salt(tenant.UUID())
	if err != nil {
		return BootstrapChannel
	}
	return steerTarget(percent, salt, deviceID)
}

// steerTarget is steerChannel's pure decision, split out so it is testable without a database.
func steerTarget(percent int, salt []byte, deviceID uuid.UUID) string {
	if InCohort(salt, deviceID, percent) {
		return CanaryChannel
	}
	return BootstrapChannel
}

func (m *Module) handleBundle(w http.ResponseWriter, r *http.Request) {
	tenant, claims, ok := identity(w, r)
	if !ok {
		return
	}
	channel, ok := channelOf(w, r)
	if !ok {
		return
	}
	if !m.limiter.allow("poll", claims.DeviceID, pollPerMinute) {
		writeError(w, http.StatusTooManyRequests, "M1E-9001", "bundle poll rate exceeded")
		return
	}
	if channel == BootstrapChannel {
		// Ahead of the ETag/304 short-circuit: a steered device polls stable far more often than stable's body changes and must see the header on a 304 too.
		w.Header().Set("X-Mark1-Channel", m.steerChannel(r.Context(), tenant, claims.DeviceID))
	}

	served, err := m.store.Latest(r.Context(), tenant, channel)
	switch {
	case errors.Is(err, ErrNoChannel):
		// The ONE server-side 3xxx (08 §3.2). Every other 3xxx is an edge-side
		// verdict reported through the next ACK, never an HTTP status.
		writeError(w, http.StatusNotFound, "M1E-3004", "unknown channel")
		return
	case err != nil:
		writeError(w, http.StatusServiceUnavailable, "M1E-9500", "catalog read failed")
		return
	}

	w.Header().Set("ETag", served.ETag)
	w.Header().Set("Cache-Control", "no-cache")
	// If-None-Match may carry a list and W/ weak markers. Exact match only:
	// these ETags are minted by this server, and a fuzzy match on a cache
	// validator that gates a policy change is not a place to be generous.
	if matchesETag(r.Header.Get("If-None-Match"), served.ETag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/cbor")
	w.Header().Set("X-Mark1-Bundle-Seq", fmt.Sprintf("%d", served.Seq))
	w.Header().Set("X-Mark1-Bundle-Sig", served.SigHeader)
	w.Header().Set("X-Mark1-Tlog-Proof", served.Proof)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(served.Body)
}

func matchesETag(header, etag string) bool {
	for _, candidate := range strings.Split(header, ",") {
		c := strings.TrimSpace(candidate)
		c = strings.TrimPrefix(c, "W/")
		if c == etag {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// GET /api/v1/policy/stream
// ---------------------------------------------------------------------------

// heartbeat is 08 §3.2's `event: ping data: {}` every 30 s. It is what reaps
// half-open connections: without a periodic write, a stream whose peer
// vanished holds a slot until the OS notices, which can be hours.
const heartbeat = 30 * time.Second

// eventWriteTimeout is 05 §8.2's "SSE write | 10 s per event; slow consumer ⇒
// close stream".
const eventWriteTimeout = 10 * time.Second

func (m *Module) handleStream(w http.ResponseWriter, r *http.Request) {
	tenant, claims, ok := identity(w, r)
	if !ok {
		return
	}
	channel, ok := channelOf(w, r)
	if !ok {
		return
	}

	s, err := m.hub.subscribe(claims.TenantID, channel)
	if err != nil {
		// 05 §8.2: "New connections 503; edges fall back to polling, which is
		// the correctness path." Retry-After keeps the retry storm bounded.
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusServiceUnavailable, "M1E-9500", "stream capacity reached; poll instead")
		return
	}
	defer m.hub.unsubscribe(s)

	rc := http.NewResponseController(w)
	// Clear the server's 30 s WriteTimeout for this connection. Without this
	// every stream dies at 30 s and the fleet silently degrades to
	// poll-only -- a failure that looks like nothing at all.
	if err := rc.SetWriteDeadline(time.Time{}); err != nil {
		writeError(w, http.StatusInternalServerError, "M1E-9500", "streaming unsupported on this connection")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no") // proxies must not buffer a hint stream
	if channel == BootstrapChannel {
		w.Header().Set("X-Mark1-Channel", m.steerChannel(r.Context(), tenant, claims.DeviceID))
	}
	w.WriteHeader(http.StatusOK)
	if err := rc.Flush(); err != nil {
		return
	}

	ticker := time.NewTicker(heartbeat)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case ev, open := <-s.out:
			if !open {
				return // hub closed us: drain, or slow consumer
			}
			if !writeEvent(rc, w, ev) {
				return
			}
		case <-ticker.C:
			if !writeEvent(rc, w, Event{Name: "ping", Data: "{}"}) {
				return
			}
		}
	}
}

func writeEvent(rc *http.ResponseController, w http.ResponseWriter, ev Event) bool {
	if err := rc.SetWriteDeadline(time.Now().Add(eventWriteTimeout)); err != nil {
		return false
	}
	if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Name, ev.Data); err != nil {
		return false
	}
	if err := rc.Flush(); err != nil {
		return false
	}
	// Back to no deadline: the next write may be 30 s away.
	return rc.SetWriteDeadline(time.Time{}) == nil
}

// ---------------------------------------------------------------------------
// POST /api/v1/policy/ack
// ---------------------------------------------------------------------------

const maxAckBody = 4 << 10 // an ACK is six small fields; anything larger is not one

func (m *Module) handleAck(w http.ResponseWriter, r *http.Request) {
	tenant, claims, ok := identity(w, r)
	if !ok {
		return
	}
	if !m.limiter.allow("ack", claims.DeviceID, ackPerMinute) {
		writeError(w, http.StatusTooManyRequests, "M1E-9001", "ack rate exceeded")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxAckBody+1))
	if err != nil || len(body) > maxAckBody {
		writeError(w, http.StatusBadRequest, "M1E-2001", "ack body missing or too large")
		return
	}
	// 05 §4.3 / 08 §10.1: edge_version is stamped from the header, and the
	// ledger column is NOT NULL. A missing header is a malformed edge request,
	// not an old edge -- 08's "never hard-rejects on it alone" governs the
	// VALUE (an old release speaking an in-window schema is still correct),
	// not the absence of the header every edge request must carry.
	edgeVersion := strings.TrimSpace(r.Header.Get("X-Mark1-Edge-Version"))
	if edgeVersion == "" || len(edgeVersion) > 128 {
		writeError(w, http.StatusBadRequest, "M1E-2001", "X-Mark1-Edge-Version header missing or oversized")
		return
	}

	ack, err := parseAck(body, edgeVersion)
	if err != nil {
		var rej *RejectError
		if errors.As(err, &rej) {
			writeError(w, http.StatusBadRequest, rej.Code, rej.Detail)
			return
		}
		writeError(w, http.StatusBadRequest, "M1E-2001", "ack body is not valid JSON")
		return
	}

	if _, err := m.store.RecordAck(r.Context(), tenant, claims.DeviceID, *ack); err != nil {
		// A foreign-key violation here means an ACK for a bundle this tenant
		// never published, which m1_042 calls "an attack signal, not a row".
		// It reads as 400: the request is wrong, and retrying it unchanged
		// will stay wrong.
		writeError(w, http.StatusBadRequest, "M1E-2001", "ack does not match a published bundle")
		return
	}
	// `recorded: true` on a duplicate as well: the ACK IS recorded (the first
	// one), and telling a retrying edge otherwise would make it retry forever.
	writeJSON(w, map[string]any{"recorded": true})
}

// ackWire is 08 §3.2's body. seq is json.Number so both the quoted proto3 form
// ("483") and a bare 483 parse -- 08's own SSE example is unquoted and its ACK
// example is quoted, and an edge is not going to be refused over which side of
// that the doc means.
type ackWire struct {
	Channel         string      `json:"channel"`
	Seq             json.Number `json:"seq"`
	BundleHash      string      `json:"bundle_hash"`
	Result          string      `json:"result"`
	SectionsSkipped []string    `json:"sections_skipped"`
	RejectCode      *string     `json:"reject_code"`
}

var ackResults = map[string]bool{"applied": true, "rejected": true, "partial": true}

func parseAck(body []byte, edgeVersion string) (*Ack, error) {
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields() // an unknown ACK field is a client speaking a contract we did not publish
	var wire ackWire
	if err := dec.Decode(&wire); err != nil {
		return nil, err
	}
	if err := ident("channel", wire.Channel); err != nil {
		return nil, err
	}
	seq, err := wire.Seq.Int64()
	if err != nil || seq < 1 {
		return nil, reject("M1E-2001", "seq %q is not a positive integer", wire.Seq.String())
	}
	if !ackResults[wire.Result] {
		return nil, reject("M1E-2001", "result %q is not applied|rejected|partial", wire.Result)
	}
	hash, err := parseBundleHash(wire.BundleHash)
	if err != nil {
		return nil, err
	}
	for _, s := range wire.SectionsSkipped {
		if !knownSection(s) {
			// Fail-closed ahead of the ledger's own CHECK: an
			// attacker-chosen section name must not be able to perturb the
			// >20% partial halt denominator.
			return nil, reject("M1E-2001", "sections_skipped contains unknown section %q", s)
		}
	}
	if wire.RejectCode != nil {
		if err := ident("reject_code", *wire.RejectCode); err != nil {
			return nil, err
		}
	}
	// The ledger's result_evidence CHECK, restated so the 400 names the
	// disagreement instead of surfacing a constraint name.
	switch wire.Result {
	case "applied":
		if wire.RejectCode != nil || len(wire.SectionsSkipped) > 0 {
			return nil, reject("M1E-2001", "an applied ACK carries no reject_code and skips no sections")
		}
	case "rejected":
		if wire.RejectCode == nil || len(wire.SectionsSkipped) > 0 {
			return nil, reject("M1E-2001", "a rejected ACK carries a reject_code and skips no sections (rejection is whole-bundle)")
		}
	case "partial":
		if wire.RejectCode != nil || len(wire.SectionsSkipped) == 0 {
			return nil, reject("M1E-2001", "a partial ACK skips at least one section and carries no reject_code")
		}
	}
	return &Ack{
		Channel: wire.Channel, Seq: seq, BundleHash: hash, Result: wire.Result,
		SectionsSkipped: wire.SectionsSkipped, RejectCode: wire.RejectCode,
		EdgeVersion: edgeVersion,
	}, nil
}

func knownSection(s string) bool {
	for _, n := range SectionNames {
		if n == s {
			return true
		}
	}
	return false
}

// parseBundleHash accepts the label-prefixed form 08 §3.2 renders
// ("sha256:…"), the unprefixed form, hex, and base64 — and insists on 32
// bytes.
//
// The label is DISCARDED, not enforced, and that stays true now that the doc
// conflict behind it is closed: 08 §3.2 used to render "blake3:" against 07,
// 05 §4.4 and policy.proto's SHA-256, and row 3 has since moved to "sha256:".
// An edge built before that move still sends the old label and must keep
// working — which is the whole reason this is byte-comparison against
// policy_bundles.body_sha256 and not string-comparison of a prefix.
func parseBundleHash(s string) ([32]byte, error) {
	var out [32]byte
	v := s
	if i := strings.IndexByte(v, ':'); i >= 0 {
		v = v[i+1:]
	}
	if b, err := hex.DecodeString(v); err == nil && len(b) == 32 {
		return [32]byte(b), nil
	}
	// proto3 JSON encodes `bytes` as standard base64, which is the form a
	// generated client emits.
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(v); err == nil && len(b) == 32 {
			return [32]byte(b), nil
		}
	}
	return out, reject("M1E-2001", "bundle_hash is not 32 bytes of hex or base64")
}

// ---------------------------------------------------------------------------
// Shared handler plumbing
// ---------------------------------------------------------------------------

// identity stamps tenancy and device from the verified claims — the ONLY
// identity source (08 §3: "a tenant identifier in a path or body is never
// trusted").
func identity(w http.ResponseWriter, r *http.Request) (querychoke.TenantID, auth.Claims, bool) {
	claims, ok := auth.ClaimsFrom(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, "M1E-9000", "auth middleware did not run")
		return querychoke.TenantID{}, auth.Claims{}, false
	}
	tenant, err := querychoke.FromClaims(claims)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "M1E-9000", "verified claims carry no tenant")
		return querychoke.TenantID{}, auth.Claims{}, false
	}
	return tenant, claims, true
}

// channelOf reads and validates ?channel, defaulting to 08 §3.2's "stable".
// The identifier production is enforced because the value reaches a SQL
// parameter and an SSE routing key; a channel is a lookup key and never
// anything evaluated.
func channelOf(w http.ResponseWriter, r *http.Request) (string, bool) {
	channel := r.URL.Query().Get("channel")
	if channel == "" {
		channel = "stable"
	}
	if err := ident("channel", channel); err != nil {
		writeError(w, http.StatusNotFound, "M1E-3004", "unknown channel")
		return "", false
	}
	return channel, true
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"code": code, "message": msg},
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// ---------------------------------------------------------------------------
// Rate limits (05 §8.2): bundle poll 4/min per device, ACK 10/min per device.
// ---------------------------------------------------------------------------

const (
	pollPerMinute = 4
	ackPerMinute  = 10
)
