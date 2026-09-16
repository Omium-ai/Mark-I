// DeviceKeys resolves a device's enrolled Ed25519 origin key for AnchorVote
// signature verification (FR-VERIFY-004). AnchorVote carries no key_id
// (unlike ReceiptCheckpoint), so the lookup is by device_id and reads the
// device's LIVE key -- the same join enroll.readDeviceKey uses, reimplemented
// here since that method is private to the enroll package; the row itself is
// the one enrollment already wrote to m1_device_keys.
package ingest

import (
	"context"
	"crypto/ed25519"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/registry"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
)

// DeviceKeys is what checkInvariants consumes. ok=false covers "no live key
// for this device" and "device unknown" alike: both mean the same thing here
// -- this signature cannot be trusted.
type DeviceKeys interface {
	PublicKey(ctx context.Context, tenant querychoke.TenantID, device uuid.UUID) (pub ed25519.PublicKey, ok bool, err error)
}

// PGDeviceKeys reads m1_device_keys under the tenant GUC (registry.DB is the
// same WithTenant seam registry.PG already uses; reused rather than
// redeclared).
type PGDeviceKeys struct{ db registry.DB }

func NewPGDeviceKeys(db registry.DB) *PGDeviceKeys { return &PGDeviceKeys{db: db} }

func (p *PGDeviceKeys) PublicKey(ctx context.Context, tenant querychoke.TenantID, device uuid.UUID) (ed25519.PublicKey, bool, error) {
	var pub []byte
	err := p.db.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT k.public_key
			  FROM m1_devices d
			  JOIN m1_device_keys k ON k.device_id = d.id
			   AND k.superseded_at IS NULL AND k.revoked_at IS NULL
			 WHERE d.id = $1`, device).Scan(&pub)
	})
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return nil, false, nil
	case err != nil:
		return nil, false, err
	}
	return ed25519.PublicKey(pub), true, nil
}
