package dprelease

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/pg"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
)

var (
	errNotWorkerRole = errors.New("dprelease: pool role lacks BYPASSRLS; the (k,m) count would be one tenant wide (m1_060 §5)")
	ErrNoBudget      = errors.New("dprelease: no privacy budget provisioned for tenant")
)

// Worker is the one sanctioned cross-tenant principal: mark1_federation_worker, BYPASSRLS, SELECT-only on tenant rows.
type Worker struct{ pool *pgxpool.Pool }

// Open refuses a NOBYPASSRLS role: the mirror of pg.Open's refusal, so a misconfigured DSN crashloops instead of gating on k=1.
func Open(ctx context.Context, dsn string) (*Worker, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("dprelease: pool: %w", err)
	}
	var bypass bool
	if err := pool.QueryRow(ctx, `SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&bypass); err != nil {
		pool.Close()
		return nil, fmt.Errorf("dprelease: pg_roles: %w", err)
	}
	if !bypass {
		pool.Close()
		return nil, errNotWorkerRole
	}
	return &Worker{pool: pool}, nil
}

func (w *Worker) Close() { w.pool.Close() }

// candidateSQL is the gate's HAVING form (m1_064) — the only way the worker can FIND a publishable artifact.
const candidateSQL = `SELECT artifact_id FROM federation_contributions
 GROUP BY artifact_id
HAVING count(DISTINCT tenant_id) >= 25 AND count(DISTINCT collusion_group_id) >= 5`

// Candidates returns the artifacts passing the raw (k,m) pre-threshold.
func (w *Worker) Candidates(ctx context.Context) ([]uuid.UUID, error) {
	rows, err := w.pool.Query(ctx, candidateSQL)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
}

// Contributions reads one artifact's gate rows (verified, opted-in, collapsed) for Release and producer sets.
func (w *Worker) Contributions(ctx context.Context, artifact uuid.UUID) ([]Contribution, error) {
	rows, err := w.pool.Query(ctx,
		`SELECT id, artifact_id, tenant_id, org_id, collusion_group_id FROM federation_contributions WHERE artifact_id = $1 ORDER BY id`, artifact)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Contribution])
}

// Publication is the worker's write; Spans[i] lists the contribution ids that produced span i.
type Publication struct {
	ArtifactID, ReviewID, ReceiptID uuid.UUID
	Body                            string
	Spans                           [][]uuid.UUID
	Epsilon                         float64
}

// Publish writes publication + spans + producers in ONE transaction; the deferred gate (k, m, spans, review, ε debit) fires at COMMIT, and that error is the refusal.
func (w *Worker) Publish(ctx context.Context, p Publication) (uuid.UUID, error) {
	var pub uuid.UUID
	err := pgx.BeginFunc(ctx, w.pool, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `
			INSERT INTO artifact_publications (artifact_id, abstraction, review_id, body, epsilon_spent, receipt_id)
			SELECT $1, abstraction, $2, $3, $4, $5 FROM memory_artifacts WHERE id = $1 RETURNING id`,
			p.ArtifactID, p.ReviewID, p.Body, p.Epsilon, p.ReceiptID).Scan(&pub); err != nil {
			return err
		}
		for i, producers := range p.Spans {
			if _, err := tx.Exec(ctx,
				`INSERT INTO publication_spans (publication_id, span_index, span_sha256) VALUES ($1, $2, sha256($3::bytea))`,
				pub, i, []byte(fmt.Sprintf("%s/%d", pub, i))); err != nil {
				return err
			}
			for _, c := range producers {
				if _, err := tx.Exec(ctx,
					`INSERT INTO publication_span_producers (publication_id, span_index, contribution_id) VALUES ($1, $2, $3)`,
					pub, i, c); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("dprelease: publish %s: %w", p.ArtifactID, err)
	}
	return pub, nil
}

// The tenant-visible read (FR-FED-007): both templates carry the tenant predicate AND run under WithTenant's RLS.
const (
	BudgetSQL = `SELECT b.epsilon_cap, coalesce((SELECT sum(l.epsilon) FROM epsilon_ledger l WHERE l.tenant_id = $1), 0)
  FROM tenant_privacy_budgets b WHERE b.tenant_id = $1`
	LedgerSQL = `SELECT publication_id, mechanism, epsilon, composed_at, receipt_id
  FROM epsilon_ledger WHERE tenant_id = $1 ORDER BY composed_at, id`
)

type LedgerRow struct {
	PublicationID *uuid.UUID
	Mechanism     string
	Epsilon       float64
	ComposedAt    time.Time
	ReceiptID     uuid.UUID
}

type Budget struct {
	K, M                     int
	EpsilonCap, EpsilonSpent float64
	Ledger                   []LedgerRow
}

// ReadBudget is the (k,m) defaults + ε balance + ledger for one tenant, through the tenant-GUC choke.
func ReadBudget(ctx context.Context, db *pg.TenantDB, t querychoke.TenantID) (Budget, error) {
	b := Budget{K: K, M: M}
	err := db.WithTenant(ctx, t, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, BudgetSQL, t.UUID()).Scan(&b.EpsilonCap, &b.EpsilonSpent); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNoBudget
			}
			return err
		}
		rows, err := tx.Query(ctx, LedgerSQL, t.UUID())
		if err != nil {
			return err
		}
		b.Ledger, err = pgx.CollectRows(rows, pgx.RowToStructByPos[LedgerRow])
		return err
	})
	return b, err
}
