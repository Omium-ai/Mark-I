package sidefx

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
)

// LeafStore holds a device's landed leaves until its checkpoint seals them (m1_083). It lived in this process's memory; at replicas: 2 each pod held half of every device's leaves and every checkpoint refused as merkle_mismatch. Order is the device's spool order — (batch_id, idx), never arrival — because the tree is order-sensitive and two pods land batches in either order.
type LeafStore interface {
	// Add lands a batch's leaves; a leaf already there (replay) is left as it is, consumed or not.
	Add(ctx context.Context, tenant querychoke.TenantID, device uuid.UUID, leaves []leaf) error
	// Window is the oldest n unconsumed leaves in spool order — a seal's leaf set when its count and last id agree.
	Window(ctx context.Context, tenant querychoke.TenantID, device uuid.UUID, n int) ([]leaf, error)
	// Consume marks ids sealed under seq — inside the seal's own transaction when tx is given, in one of the store's own otherwise (a re-delivered seal the chain already holds).
	Consume(ctx context.Context, tx pgx.Tx, tenant querychoke.TenantID, device uuid.UUID, ids []uuid.UUID, seq int64) error
	// Sweep drops consumed leaves older than keep; the landing object is the durable truth (05 §2.5).
	Sweep(ctx context.Context, tenant querychoke.TenantID, keep time.Duration) error
}

type pgLeaves struct{ db DB }

func (p pgLeaves) Add(ctx context.Context, tenant querychoke.TenantID, device uuid.UUID, leaves []leaf) error {
	if len(leaves) == 0 {
		return nil
	}
	n := len(leaves)
	batches, idxs, ids := make([]uuid.UUID, n), make([]int32, n), make([]uuid.UUID, n)
	covs, dels := make([]*string, n), make([]*string, n)
	for i, l := range leaves {
		batches[i], idxs[i], ids[i] = l.batch, int32(l.idx), l.id //nolint:gosec // G115: idx < maxEvents
		if l.cov != nil {
			b, err := json.Marshal(l.cov)
			if err != nil {
				return err
			}
			s := string(b)
			covs[i] = &s
		}
		if l.del != nil {
			b, err := json.Marshal(l.del)
			if err != nil {
				return err
			}
			s := string(b)
			dels[i] = &s
		}
	}
	return p.db.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO m1_checkpoint_leaves (tenant_id, device_id, batch_id, idx, event_id, coverage, deletion)
			SELECT $1, $2, b, i, e, c::jsonb, d::jsonb
			FROM unnest($3::uuid[], $4::int[], $5::uuid[], $6::text[], $7::text[]) AS t(b, i, e, c, d)
			ON CONFLICT (tenant_id, device_id, event_id) DO NOTHING`,
			tenant.UUID(), device, batches, idxs, ids, covs, dels)
		return err
	})
}

func (p pgLeaves) Window(ctx context.Context, tenant querychoke.TenantID, device uuid.UUID, n int) ([]leaf, error) {
	var out []leaf
	err := p.db.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT event_id, batch_id, idx, coverage, deletion
			FROM m1_checkpoint_leaves
			WHERE tenant_id = $1 AND device_id = $2 AND consumed_seq IS NULL
			ORDER BY batch_id, idx
			LIMIT $3`, tenant.UUID(), device, n)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var l leaf
			var cov, del []byte
			if err := rows.Scan(&l.id, &l.batch, &l.idx, &cov, &del); err != nil {
				return err
			}
			if cov != nil {
				l.cov = &Coverage{}
				if err := json.Unmarshal(cov, l.cov); err != nil {
					return fmt.Errorf("leaf %s coverage: %w", l.id, err)
				}
			}
			if del != nil {
				l.del = &QuarantineDeletion{}
				if err := json.Unmarshal(del, l.del); err != nil {
					return fmt.Errorf("leaf %s deletion: %w", l.id, err)
				}
			}
			out = append(out, l)
		}
		return rows.Err()
	})
	return out, err
}

func (p pgLeaves) Consume(ctx context.Context, tx pgx.Tx, tenant querychoke.TenantID, device uuid.UUID, ids []uuid.UUID, seq int64) error {
	consume := func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			UPDATE m1_checkpoint_leaves SET consumed_seq = $4
			WHERE tenant_id = $1 AND device_id = $2 AND event_id = ANY($3) AND consumed_seq IS NULL`,
			tenant.UUID(), device, ids, seq)
		return err
	}
	if tx != nil {
		return consume(tx)
	}
	return p.db.WithTenant(ctx, tenant, consume)
}

func (p pgLeaves) Sweep(ctx context.Context, tenant querychoke.TenantID, keep time.Duration) error {
	return p.db.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM m1_checkpoint_leaves WHERE tenant_id = $1 AND consumed_seq IS NOT NULL AND landed_at < $2`,
			tenant.UUID(), time.Now().Add(-keep))
		return err
	})
}
