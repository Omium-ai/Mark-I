package dprelease

import (
	"errors"

	"github.com/google/differential-privacy/go/v4/noise"
	"github.com/google/uuid"
)

// The 05 §5.2 parameter table; k and m are enforced by migrations/m1_064's trigger, these are the worker's pre-threshold.
const (
	K                 = 25
	M                 = 5
	EpsilonRelease    = 0.25
	ContributionBound = 1
	Mechanism         = "laplace_int"
)

var ErrBelowThreshold = errors.New("dprelease: partition below (k,m) pre-threshold; no noise drawn")

// Contribution is one row of the federation_contributions view: verified org, opted-in tenant, collapsed group.
type Contribution struct {
	ID, ArtifactID, TenantID, OrgID, CollusionGroupID uuid.UUID
}

// Stats carries exact gate evidence (never released) and the one released, noised statistic.
type Stats struct {
	K, M     int
	OrgCount int64
	Epsilon  float64
}

// Bound keeps at most c rows per tenant, so sensitivity is c by construction.
func Bound(rows []Contribution, c int) []Contribution {
	seen := map[uuid.UUID]int{}
	out := rows[:0:0]
	for _, r := range rows {
		if seen[r.TenantID] < c {
			seen[r.TenantID]++
			out = append(out, r)
		}
	}
	return out
}

// NoisedCount adds discrete Laplace noise (l0 = lInf = 1, δ = 0) to an integer count.
func NoisedCount(x int64, eps float64) (int64, error) {
	return noise.Laplace().AddNoiseInt64(x, 1, 1, eps, 0)
}

// Release bounds, pre-thresholds on the RAW counts (no noise drawn below τ), then noises the org count.
func Release(rows []Contribution, eps float64) (Stats, error) {
	rows = Bound(rows, ContributionBound)
	tenants, groups, orgs := map[uuid.UUID]struct{}{}, map[uuid.UUID]struct{}{}, map[uuid.UUID]struct{}{}
	for _, r := range rows {
		tenants[r.TenantID], groups[r.CollusionGroupID], orgs[r.OrgID] = struct{}{}, struct{}{}, struct{}{}
	}
	if len(tenants) < K || len(groups) < M {
		return Stats{}, ErrBelowThreshold
	}
	n, err := NoisedCount(int64(len(orgs)), eps)
	if err != nil {
		return Stats{}, err
	}
	return Stats{K: len(tenants), M: len(groups), OrgCount: n, Epsilon: eps}, nil
}
