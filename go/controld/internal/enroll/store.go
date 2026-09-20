package enroll

// Every function here runs under the tenant GUC discipline (05 §7.2): the
// only pool shape available is WithTenant, so a forgotten tenant context is
// unwritable — and RLS's NULLIF form makes even a bypass read zero rows.
// State transitions guard on the FROM state in SQL (WHERE status = $from), so
// a racing double-transition loses at the row, not in Go.

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
)

type enrollmentRow struct {
	id        uuid.UUID
	status    string
	startedAt time.Time
	pubkey    []byte
}

func (m *Module) insertEnrollment(ctx context.Context, tenant uuid.UUID, codeHash, pubkey []byte) error {
	tid, err := tenantIDFor(tenant)
	if err != nil {
		return err
	}
	return m.db.WithTenant(ctx, tid, func(tx pgx.Tx) error {
		// The pubkey is registered NOW, at /start, before the user approves —
		// the whole §3.5 abuse-case-2 defense: a replayed code binds to a key
		// the attacker does not hold.
		_, err := tx.Exec(ctx, `
			INSERT INTO m1_device_enrollments (tenant_id, device_code_hash, device_pubkey)
			VALUES ($1, $2, $3)`, tenant, codeHash, pubkey)
		return err
	})
}

// upsertUserEnrollment re-arms a still-pending row (crash between insert and approval) so its token pins to a fresh started_at.
func (m *Module) upsertUserEnrollment(ctx context.Context, tenant uuid.UUID, codeHash, pubkey []byte) error {
	tid, err := tenantIDFor(tenant)
	if err != nil {
		return err
	}
	return m.db.WithTenant(ctx, tid, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO m1_device_enrollments (tenant_id, device_code_hash, device_pubkey, approval_kind)
			VALUES ($1, $2, $3, 'omium_user')
			ON CONFLICT (device_code_hash) DO UPDATE SET started_at = now()
			 WHERE m1_device_enrollments.status = 'pending'`, tenant, codeHash, pubkey)
		return err
	})
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// ensurePersonalTenant seeds the personal regime with the tenant (m1_085): one developer on a subscription reads in quota basis — tokens per outcome, shadow price 0 (no dollar claim; D22's confirmation is what a tenant supplies when it wants one), window limit the not-yet-fitted sentinel. Without the row every personal report defaulted to usd and refused for a price it could never pin.
func (m *Module) ensurePersonalTenant(ctx context.Context, tenant uuid.UUID, owner string) (string, error) {
	tid, err := tenantIDFor(tenant)
	if err != nil {
		return "", err
	}
	var status string
	err = m.db.WithTenant(ctx, tid, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO m1_tenants (id, kind, owner_subject, name)
			VALUES ($1, 'personal', $2, 'personal')
			ON CONFLICT (id) DO NOTHING`, tenant, owner); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO m1_tenant_regimes (tenant_id, cost_basis, price_model_id, window_limit_tokens, shadow_price_usd, v_default, set_by)
			VALUES ($1, 'quota', NULL, 1, 0, 1, 'enroll:personal-default')
			ON CONFLICT (tenant_id) DO NOTHING`, tenant); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT status FROM m1_tenants WHERE id = $1`, tenant).Scan(&status)
	})
	return status, err
}

// approveCodeHash keys a one-shot approval on the device key itself, so a retried /approve lands on the same row.
func approveCodeHash(tenant uuid.UUID, pubkey []byte) []byte {
	h := sha256.New()
	h.Write([]byte("omium_user:" + tenant.String() + ":"))
	h.Write(pubkey)
	return h.Sum(nil)
}

// reissueUserDevice re-issues for the same approving subject only; like the PoP refresh, token_hash stays the first grant's audit.
func (m *Module) reissueUserDevice(ctx context.Context, tenant uuid.UUID, codeHash []byte, subject string) (device uuid.UUID, token string, expiresIn int, err error) {
	tid, err := tenantIDFor(tenant)
	if err != nil {
		return uuid.Nil, "", 0, err
	}
	err = m.db.WithTenant(ctx, tid, func(tx pgx.Tx) error {
		var keyID string
		scanErr := tx.QueryRow(ctx, `
			SELECT d.id, k.key_id
			  FROM m1_device_enrollments e
			  JOIN m1_devices d ON d.id = e.device_id
			  JOIN m1_device_keys k ON k.device_id = d.id
			   AND k.superseded_at IS NULL AND k.revoked_at IS NULL
			 WHERE e.device_code_hash = $1 AND e.status = 'approved'
			   AND e.approval_kind = 'omium_user' AND e.oidc_subject = $2`, codeHash, subject).
			Scan(&device, &keyID)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return errCodeConsumed
		}
		if scanErr != nil {
			return scanErr
		}
		now := m.now()
		exp := now.Add(auth.TokenTTLCeiling)
		tok, mintErr := m.signer.Mint(tenant, device, keyID, now, exp)
		if mintErr != nil {
			return mintErr
		}
		token = tok
		expiresIn = int(exp.Sub(now).Seconds())
		return nil
	})
	if err != nil {
		return uuid.Nil, "", 0, err
	}
	return device, token, expiresIn, nil
}

// readEnrollment returns nil when the code is unknown (⇒ M1E-1004).
func (m *Module) readEnrollment(ctx context.Context, tenant uuid.UUID, codeHash []byte) (*enrollmentRow, error) {
	tid, err := tenantIDFor(tenant)
	if err != nil {
		return nil, err
	}
	var row *enrollmentRow
	err = m.db.WithTenant(ctx, tid, func(tx pgx.Tx) error {
		r := enrollmentRow{}
		scanErr := tx.QueryRow(ctx, `
			SELECT id, status, started_at, device_pubkey
			  FROM m1_device_enrollments WHERE device_code_hash = $1`, codeHash).
			Scan(&r.id, &r.status, &r.startedAt, &r.pubkey)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return nil
		}
		if scanErr == nil {
			row = &r
		}
		return scanErr
	})
	return row, err
}

// transition moves a grant between non-approved states (pending→expired,
// pending→denied, approved→revoked); the FROM guard makes it a no-op if
// another pod won the race — which is the correct outcome for every pair.
func (m *Module) transition(ctx context.Context, tenant uuid.UUID, codeHash []byte, from, to string) error {
	tid, err := tenantIDFor(tenant)
	if err != nil {
		return err
	}
	return m.db.WithTenant(ctx, tid, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			UPDATE m1_device_enrollments SET status = $3
			 WHERE device_code_hash = $1 AND status = $2`, codeHash, from, to)
		return err
	})
}

// approveEnrollment is the PENDING → APPROVED → ACTIVE write (05 §3.1): mint
// the device row, register its origin key, issue the first token, and consume
// the code — all one transaction, with the enrollment row locked so a
// replayed poll cannot double-mint (§3.5 abuse case 2: single-use code).
func (m *Module) approveEnrollment(ctx context.Context, tenant uuid.UUID, codeHash []byte,
	platform string, hostnameHMAC []byte, subject string) (device uuid.UUID, token string, expiresIn int, err error) {
	tid, err := tenantIDFor(tenant)
	if err != nil {
		return uuid.Nil, "", 0, err
	}
	err = m.db.WithTenant(ctx, tid, func(tx pgx.Tx) error {
		var (
			enrollID  uuid.UUID
			status    string
			startedAt time.Time
			pubkey    []byte
		)
		scanErr := tx.QueryRow(ctx, `
			SELECT id, status, started_at, device_pubkey
			  FROM m1_device_enrollments WHERE device_code_hash = $1 FOR UPDATE`, codeHash).
			Scan(&enrollID, &status, &startedAt, &pubkey)
		if errors.Is(scanErr, pgx.ErrNoRows) || (scanErr == nil && status != "pending") {
			// Consumed (or vanished) between our read and the IdP round-trip:
			// single-use holds, the replayer gets M1E-1004.
			return errCodeConsumed
		}
		if scanErr != nil {
			return scanErr
		}
		if insErr := tx.QueryRow(ctx, `
			INSERT INTO m1_devices (tenant_id, platform, hostname_hmac)
			VALUES ($1, $2, $3) RETURNING id`, tenant, platform, hostnameHMAC).
			Scan(&device); insErr != nil {
			return insErr
		}
		keyID := deviceKeyID(pubkey)
		if _, insErr := tx.Exec(ctx, `
			INSERT INTO m1_device_keys (tenant_id, device_id, key_id, public_key)
			VALUES ($1, $2, $3, $4)`, tenant, device, keyID, pubkey); insErr != nil {
			return insErr
		}
		// exp is pinned to started_at+24h, not now+24h: ck_m1_enroll_token_ttl
		// (m1_001) makes the ≤24 h promise a schema fact against started_at,
		// and a poll inside the 15-min window loses at most 15 min of life.
		now := m.now()
		exp := startedAt.Add(24 * time.Hour)
		if startedAt.After(now) { // DB clock ahead of ours (one-shot /approve has no poll-interval slack): honour both ceilings
			exp = now.Add(24 * time.Hour)
		}
		tok, mintErr := m.signer.Mint(tenant, device, keyID, now, exp)
		if mintErr != nil {
			return mintErr
		}
		tokenHash := sha256.Sum256([]byte(tok))
		if _, upErr := tx.Exec(ctx, `
			UPDATE m1_device_enrollments
			   SET status = 'approved', device_id = $2, token_hash = $3,
			       token_expires_at = $4, oidc_subject = $5
			 WHERE id = $1`, enrollID, device, tokenHash[:], exp, subject); upErr != nil {
			return upErr
		}
		token = tok
		expiresIn = int(exp.Sub(now).Seconds())
		return nil
	})
	if err != nil {
		return uuid.Nil, "", 0, err
	}
	return device, token, expiresIn, nil
}

var errCodeConsumed = errors.New("enroll: device_code already consumed")

type deviceKeyRow struct {
	revoked bool
	pubkey  []byte
	keyID   string
}

// readDeviceKey returns the device's LIVE origin key (exactly one exists by
// uq_m1_dkeys_live) plus its revocation state; nil when the device is unknown
// under this tenant.
func (m *Module) readDeviceKey(ctx context.Context, tenant, device uuid.UUID) (*deviceKeyRow, error) {
	tid, err := tenantIDFor(tenant)
	if err != nil {
		return nil, err
	}
	var row *deviceKeyRow
	err = m.db.WithTenant(ctx, tid, func(tx pgx.Tx) error {
		r := deviceKeyRow{}
		scanErr := tx.QueryRow(ctx, `
			SELECT d.revoked_at IS NOT NULL, k.public_key, k.key_id
			  FROM m1_devices d
			  JOIN m1_device_keys k ON k.device_id = d.id
			   AND k.superseded_at IS NULL AND k.revoked_at IS NULL
			 WHERE d.id = $1`, device).Scan(&r.revoked, &r.pubkey, &r.keyID)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return nil
		}
		if scanErr == nil {
			row = &r
		}
		return scanErr
	})
	return row, err
}

// touchLastSeen: the refresh IS the fleet heartbeat (05 §3.3); GREATEST keeps
// it monotonic, same discipline as sidefx.ApplyLastSeen.
func (m *Module) touchLastSeen(ctx context.Context, tenant, device uuid.UUID) error {
	tid, err := tenantIDFor(tenant)
	if err != nil {
		return err
	}
	return m.db.WithTenant(ctx, tid, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			UPDATE m1_devices
			   SET last_seen_at = GREATEST(COALESCE(last_seen_at, 'epoch'::timestamptz), $2)
			 WHERE id = $1`, device, m.now())
		return err
	})
}

type revokeOutcome int

const (
	revokedNow revokeOutcome = iota
	alreadyRevoked
	deviceNotFound
)

// revokeDevice is the §3.4 authority write, one transaction: the device row
// (state = REVOKED, attributed to the ordering operator) AND the per-tenant
// revocation_epoch bump — the epoch is what policydist pushes on live SSE
// streams and what a cache compares against; a revoke without the bump is
// invisible to both. The approved grant is closed too, which drops its token
// hash out of ix_m1_enroll_token's partial index — and the device's live
// credential fingerprints are retired in the SAME transaction, so 05 §3.6(b)
// ("a revoked device's proxy has no valid provision set") is a database fact
// a restarted daemon re-verifies against, not an inference. Rows are stamped,
// never deleted (audit: "what could this device forward, when").
// There is no un-revoke.
func (m *Module) revokeDevice(ctx context.Context, tenant, device uuid.UUID, subject, reason string) (revokeOutcome, error) {
	tid, err := tenantIDFor(tenant)
	if err != nil {
		return deviceNotFound, err
	}
	outcome := deviceNotFound
	err = m.db.WithTenant(ctx, tid, func(tx pgx.Tx) error {
		var id uuid.UUID
		scanErr := tx.QueryRow(ctx, `
			UPDATE m1_devices SET revoked_at = now(), revoked_by = $2, revoked_reason = $3
			 WHERE id = $1 AND revoked_at IS NULL RETURNING id`, device, subject, reason).Scan(&id)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			// Not newly revoked: distinguish "already terminal" (idempotent
			// 200 — a retried revoke must not 404) from "no such device".
			var exists bool
			if e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM m1_devices WHERE id = $1)`, device).
				Scan(&exists); e != nil {
				return e
			}
			if exists {
				outcome = alreadyRevoked
			}
			return nil
		}
		if scanErr != nil {
			return scanErr
		}
		if _, e := tx.Exec(ctx, `
			UPDATE m1_device_enrollments SET status = 'revoked'
			 WHERE device_id = $1 AND status = 'approved'`, device); e != nil {
			return e
		}
		// Close every live fingerprint (drops them from uq_m1_fp_live and from
		// the §3.6(a) list a restarted daemon re-verifies against).
		if _, e := tx.Exec(ctx, `
			UPDATE m1_device_credential_fingerprints SET revoked_at = now()
			 WHERE device_id = $1 AND revoked_at IS NULL`, device); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, `
			UPDATE m1_tenants SET revocation_epoch = revocation_epoch + 1
			 WHERE id = $1`, tenant); e != nil {
			return e
		}
		outcome = revokedNow
		return nil
	})
	return outcome, err
}

type deviceListItem struct {
	ID         uuid.UUID  `json:"device_id"`
	State      string     `json:"state"`
	Platform   string     `json:"platform"`
	EnrolledAt time.Time  `json:"enrolled_at"`
	LastSeenAt *time.Time `json:"last_seen_at"`
	// edge_version (08 §3.1) is stamped by ingest from X-Mark1-Edge-Version
	// alongside last_seen_at (m1_061; sidefx.ApplyLastSeen) — null until the
	// device's first ingest.
	EdgeVersion *string `json:"edge_version"`
}

func (m *Module) listDevices(ctx context.Context, tenant uuid.UUID, after uuid.UUID, limit int) ([]deviceListItem, error) {
	tid, err := tenantIDFor(tenant)
	if err != nil {
		return nil, err
	}
	var items []deviceListItem
	err = m.db.WithTenant(ctx, tid, func(tx pgx.Tx) error {
		// DORMANT is derived, never stored (m1_001: a stored state nothing
		// reads is a state that drifts): refresh absent 30 d.
		rows, qErr := tx.Query(ctx, `
			SELECT id,
			       CASE WHEN revoked_at IS NOT NULL THEN 'revoked'
			            WHEN COALESCE(last_seen_at, enrolled_at) < now() - interval '30 days' THEN 'dormant'
			            ELSE 'active' END,
			       platform, enrolled_at, last_seen_at, edge_version
			  FROM m1_devices
			 WHERE id > $1
			 ORDER BY id
			 LIMIT $2`, after, limit)
		if qErr != nil {
			return qErr
		}
		defer rows.Close()
		for rows.Next() {
			var it deviceListItem
			if sErr := rows.Scan(&it.ID, &it.State, &it.Platform, &it.EnrolledAt, &it.LastSeenAt, &it.EdgeVersion); sErr != nil {
				return sErr
			}
			items = append(items, it)
		}
		return rows.Err()
	})
	return items, err
}

// registerFingerprint stores the §3.6 anchor. Idempotent per the live unique
// index: re-provisioning the same credential must not double the
// authoritative set (m1_001 uq_m1_fp_live).
func (m *Module) registerFingerprint(ctx context.Context, tenant, device uuid.UUID, fp []byte, upstreamClass string) error {
	tid, err := tenantIDFor(tenant)
	if err != nil {
		return err
	}
	return m.db.WithTenant(ctx, tid, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO m1_device_credential_fingerprints (tenant_id, device_id, fingerprint, upstream_class)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (device_id, upstream_class, fingerprint) WHERE revoked_at IS NULL
			DO NOTHING`, tenant, device, fp, upstreamClass)
		return err
	})
}

type fingerprintItem struct {
	Fingerprint   string    `json:"fingerprint"`
	UpstreamClass string    `json:"upstream_class"`
	ProvisionedAt time.Time `json:"provisioned_at"`
}

// listFingerprints serves §3.6 (a): the authoritative set a restarted daemon
// re-verifies its provision table against.
func (m *Module) listFingerprints(ctx context.Context, tenant, device uuid.UUID) ([]fingerprintItem, error) {
	tid, err := tenantIDFor(tenant)
	if err != nil {
		return nil, err
	}
	items := []fingerprintItem{}
	err = m.db.WithTenant(ctx, tid, func(tx pgx.Tx) error {
		rows, qErr := tx.Query(ctx, `
			SELECT encode(fingerprint, 'hex'), upstream_class, provisioned_at
			  FROM m1_device_credential_fingerprints
			 WHERE device_id = $1 AND revoked_at IS NULL
			 ORDER BY provisioned_at`, device)
		if qErr != nil {
			return qErr
		}
		defer rows.Close()
		for rows.Next() {
			var it fingerprintItem
			if sErr := rows.Scan(&it.Fingerprint, &it.UpstreamClass, &it.ProvisionedAt); sErr != nil {
				return sErr
			}
			items = append(items, it)
		}
		return rows.Err()
	})
	return items, err
}

// uuidZero is the keyset-pagination floor for listDevices.
var uuidZero = uuid.UUID{}

func parseCursor(s string) (uuid.UUID, error) {
	if s == "" {
		return uuidZero, nil
	}
	id, err := uuid.Parse(s)
	if err != nil {
		return uuidZero, fmt.Errorf("enroll: malformed cursor")
	}
	return id, nil
}
