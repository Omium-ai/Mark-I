package enroll

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
)

// RevocationCache is the 05 §3.4 enforcement point behind auth's production
// verifier: entries refresh every 30 s and are NEVER served beyond the max-
// stale ceiling (≤60 s, config-clamped down) — past it, unknown state is an
// error and the verifier fails closed (401 + Retry-After semantics at the
// middleware). "Propagates eventually" is the fail-open version of a
// fail-closed requirement.
//
// ponytail: per-(tenant,device) rows, not the doc's fleet-wide revoked set +
// epoch — controld_app cannot enumerate tenants under FORCE RLS (05 §7.1), so
// a fleet cache would need the worker role, and enroll's only sanctioned
// bypass path is the reconciliation sweep (05 §7.3). The observable contract
// (≤60 s, fail-closed) is identical; revisit alongside the sweep if the
// per-device read rate ever matters. The tenant argument always comes from
// already-signature-verified claims (auth.TenantRevocations contract).
type RevocationCache struct {
	db       DB
	refresh  time.Duration
	maxStale time.Duration
	now      func() time.Time
	// fetchFn is the authoritative read; swappable for staleness tests only.
	fetchFn func(ctx context.Context, tenant, device uuid.UUID) (bool, error)

	mu sync.Mutex
	m  map[uuid.UUID]revEntry // keyed by device (device ids are globally unique)
}

type revEntry struct {
	revoked bool
	at      time.Time
}

var errRevocationStale = errors.New("enroll: revocation state older than the fail-closed ceiling")

func NewRevocationCache(db DB, maxStale time.Duration) *RevocationCache {
	if maxStale <= 0 || maxStale > 60*time.Second {
		maxStale = 60 * time.Second // the §3.4 ceiling; config only clamps down
	}
	c := &RevocationCache{
		db: db, refresh: 30 * time.Second, maxStale: maxStale,
		now: time.Now, m: make(map[uuid.UUID]revEntry),
	}
	c.fetchFn = c.fetch
	return c
}

var _ auth.TenantRevocations = (*RevocationCache)(nil)

func (c *RevocationCache) IsRevoked(ctx context.Context, tenant, device uuid.UUID) (bool, error) {
	now := c.now()
	c.mu.Lock()
	e, ok := c.m[device]
	c.mu.Unlock()
	if ok && now.Sub(e.at) <= c.refresh {
		return e.revoked, nil
	}
	revoked, err := c.fetchFn(ctx, tenant, device)
	if err == nil {
		c.mu.Lock()
		if len(c.m) >= 65536 { // bound memory; stale entries re-fetch anyway
			for k, v := range c.m {
				if now.Sub(v.at) > c.maxStale {
					delete(c.m, k)
				}
			}
		}
		c.m[device] = revEntry{revoked: revoked, at: now}
		c.mu.Unlock()
		return revoked, nil
	}
	// Refresh failed: a known answer may be served up to maxStale, past that
	// the state is unknown and unknown is FAIL-CLOSED (05 §3.4).
	if ok && now.Sub(e.at) <= c.maxStale {
		return e.revoked, nil
	}
	return false, errRevocationStale
}

// Invalidate drops a device's entry so THIS pod's next check hits the
// authoritative row immediately after a revoke; sibling pods converge inside
// the ≤60 s ceiling (05 §3.4's worst-case timeline).
func (c *RevocationCache) Invalidate(device uuid.UUID) {
	c.mu.Lock()
	delete(c.m, device)
	c.mu.Unlock()
}

func (c *RevocationCache) fetch(ctx context.Context, tenant, device uuid.UUID) (bool, error) {
	tid, err := tenantIDFor(tenant)
	if err != nil {
		return false, err
	}
	var revoked bool
	found := false
	err = c.db.WithTenant(ctx, tid, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM m1_devices WHERE id = $1`, device)
		switch scanErr := row.Scan(&revoked); scanErr {
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
		return false, err
	}
	// No row under this tenant's GUC = the token names an identity the
	// registry does not hold (or holds under another tenant). Treat as
	// revoked — terminal, re-enroll — rather than fail-open.
	if !found {
		return true, nil
	}
	return revoked, nil
}

// tenantIDFor bridges enrollment's pre-identity flows into the TenantID
// newtype. WHY this is sound rather than a bypass of "constructible only from
// verified claims" (05 §6.2): enrollment is the flow that CREATES claims, so
// its tenant key necessarily precedes them — and every use is only a GUC
// routing key whose reads are self-limiting under RLS (a wrong tenant reads
// zero rows and the flow dies at M1E-1004/1002, never at another tenant's
// data). Verified identity still only ever comes out of auth.Verify.
func tenantIDFor(tenant uuid.UUID) (querychoke.TenantID, error) {
	return querychoke.FromClaims(auth.Claims{TenantID: tenant})
}

// RevokeSubjectDevices is revokeDevice for every device subject enrolled in tenant (15-teams: a removed member stops uploading into the team); idempotent, so a failed call is retried whole.
func (m *Module) RevokeSubjectDevices(ctx context.Context, tenant uuid.UUID, subject, by string) (int, error) {
	tid, err := tenantIDFor(tenant)
	if err != nil {
		return 0, err
	}
	var devices []uuid.UUID
	err = m.db.WithTenant(ctx, tid, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT DISTINCT device_id FROM m1_device_enrollments WHERE oidc_subject = $1 AND status = 'approved' AND device_id IS NOT NULL`, subject)
		if err != nil {
			return err
		}
		devices, err = pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		return err
	})
	if err != nil {
		return 0, err
	}
	n := 0
	for _, d := range devices {
		outcome, err := m.revokeDevice(ctx, tenant, d, by, "removed from team")
		if err != nil {
			return n, err
		}
		if outcome == revokedNow {
			n++
			transitionsTotal.WithLabelValues("revoked").Inc()
			if m.cache != nil {
				m.cache.Invalidate(d)
			}
		}
	}
	return n, nil
}
