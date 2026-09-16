package querychoke

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TenantDB is the WithTenant-shaped seam (05 §7.2); *pg.TenantDB satisfies it.
type TenantDB interface {
	WithTenant(ctx context.Context, t TenantID, fn func(pgx.Tx) error) error
}

const (
	costBasisUSD   = "usd"
	costBasisQuota = "quota"
)

// Regime is the report's slice of the tenant's m1_075 row (06 §8.4): the basis, and for usd the model whose pinned price row prices it.
type Regime struct {
	CostBasis    string
	PriceModelID string
}

// RegimeSource resolves a tenant's Regime; (nil, nil) is "no row", the unresolved basis 06 §8.5 issues as indicative.
type RegimeSource interface {
	Regime(ctx context.Context, t TenantID) (*Regime, error)
}

// PGRegimes is the production RegimeSource: app/regime.load_regime's read, under the tenant GUC.
type PGRegimes struct{ DB TenantDB }

func (p PGRegimes) Regime(ctx context.Context, tid TenantID) (*Regime, error) {
	var out *Regime
	err := p.DB.WithTenant(ctx, tid, func(tx pgx.Tx) error {
		var basis string
		var model *string
		err := tx.QueryRow(ctx,
			`SELECT cost_basis, price_model_id FROM m1_tenant_regimes WHERE tenant_id = $1`,
			tid.UUID()).Scan(&basis, &model)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		out = &Regime{CostBasis: basis}
		if model != nil {
			out.PriceModelID = *model
		}
		return nil
	})
	return out, err
}

// CostBasis is chproj.BasisFunc over the same read: the tenant is ingest's stage-3 stamp (05 §2.1), "" when no row exists.
func (p PGRegimes) CostBasis(ctx context.Context, tenant uuid.UUID) (string, error) {
	if tenant == uuid.Nil {
		return "", ErrNoTenant
	}
	r, err := p.Regime(ctx, TenantID{id: tenant})
	if err != nil || r == nil {
		return "", err
	}
	return r.CostBasis, nil
}

func loadRegime(ctx context.Context, src RegimeSource, tid TenantID) (*Regime, error) {
	if src == nil {
		return nil, nil
	}
	return src.Regime(ctx, tid)
}

// modelPricesRaw is a byte-identical copy of python/intel/app/pricing/model_prices.v1.json (go:embed cannot reach outside the module); TestModelPricesTableMatchesIntel reds on drift.
//
//go:embed model_prices.v1.json
var modelPricesRaw []byte

// priceTable is app/pricing.PriceTable's report-facing half: which models are pinned, and the version stamp `<version>@sha256:<file digest>`.
type priceTable struct {
	version string
	pinned  map[string]bool
}

func loadPriceTable(raw []byte) (*priceTable, error) {
	var doc struct {
		Version string `json:"version"`
		Rows    []struct {
			ModelID    string   `json:"model_id"`
			Input      *float64 `json:"input"`
			Output     *float64 `json:"output"`
			CacheWrite *float64 `json:"cache_write"`
			CacheRead  *float64 `json:"cache_read"`
		} `json:"rows"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("model_prices: %w", err)
	}
	if doc.Version == "" {
		return nil, errors.New("model_prices: no version")
	}
	sum := sha256.Sum256(raw)
	t := &priceTable{version: doc.Version + "@sha256:" + hex.EncodeToString(sum[:]), pinned: map[string]bool{}}
	for _, r := range doc.Rows {
		if r.ModelID == "" {
			return nil, errors.New("model_prices: row without model_id")
		}
		if _, dup := t.pinned[r.ModelID]; dup {
			return nil, fmt.Errorf("model_prices: duplicate row for %q", r.ModelID)
		}
		t.pinned[r.ModelID] = r.Input != nil && r.Output != nil && r.CacheWrite != nil && r.CacheRead != nil
	}
	return t, nil
}

// modelPrices is loaded once from the embedded bytes; a malformed table is a build-time defect, so it panics at init (the same crashloop posture as the Must* boot refusals).
var modelPrices = func() *priceTable {
	t, err := loadPriceTable(modelPricesRaw)
	if err != nil {
		panic(err)
	}
	return t
}()
