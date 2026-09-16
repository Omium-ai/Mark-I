package enroll

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TenantKind is s3land's key-selection seam (ADR-0011 §2): "org" | "personal" for an active
// tenant, memoized because a tenant's kind never changes (§5 mints a new org tenant on team join).
func TenantKind(db DB) func(ctx context.Context, tenant uuid.UUID) (string, error) {
	var memo sync.Map
	return func(ctx context.Context, tenant uuid.UUID) (string, error) {
		if k, ok := memo.Load(tenant); ok {
			return k.(string), nil
		}
		tid, err := tenantIDFor(tenant)
		if err != nil {
			return "", err
		}
		var kind string
		err = db.WithTenant(ctx, tid, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT kind FROM m1_tenants WHERE id = $1 AND status = 'active'`, tenant).Scan(&kind)
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return "", fmt.Errorf("enroll: tenant %s has no active row (kind unknown)", tenant)
		}
		if err != nil {
			return "", err
		}
		memo.Store(tenant, kind)
		return kind, nil
	}
}
