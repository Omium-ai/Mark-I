package dprelease

import (
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func rows(tenants, perTenant int, groups int) []Contribution {
	var out []Contribution
	for i := 0; i < tenants; i++ {
		t, o := uuid.New(), uuid.New()
		g := uuid.NewSHA1(uuid.Nil, []byte{byte(i % groups)})
		for j := 0; j < perTenant; j++ {
			out = append(out, Contribution{ID: uuid.New(), TenantID: t, OrgID: o, CollusionGroupID: g})
		}
	}
	return out
}

// Laplace at ε=0.25, sensitivity 1: scale 4, sd ≈ 5.66; over N draws the mean's sd ≈ 0.04, so |mean-x| < 0.5 is ~12σ.
func TestNoisedCountIsIntegerAndUnbiased(t *testing.T) {
	const x, n = int64(100), 20_000
	var sum float64
	distinct := map[int64]struct{}{}
	for i := 0; i < n; i++ {
		v, err := NoisedCount(x, EpsilonRelease)
		if err != nil {
			t.Fatal(err)
		}
		sum += float64(v)
		distinct[v] = struct{}{}
	}
	if mean := sum / n; math.Abs(mean-float64(x)) > 0.5 {
		t.Fatalf("mean %.3f over %d draws; want ≈ %d", mean, n, x)
	}
	if len(distinct) < 10 {
		t.Fatalf("only %d distinct outputs: no noise was drawn", len(distinct))
	}
}

func TestNoisedCountRefusesDelta(t *testing.T) {
	if _, err := NoisedCount(1, 0); err == nil {
		t.Fatal("ε=0 must be refused by the mechanism")
	}
}

func TestBoundCapsATenantsRows(t *testing.T) {
	in := rows(3, 4, 3)
	out := Bound(in, ContributionBound)
	if len(out) != 3 {
		t.Fatalf("3 tenants × 4 rows bounded at C=1: got %d rows, want 3", len(out))
	}
	seen := map[uuid.UUID]int{}
	for _, r := range out {
		seen[r.TenantID]++
	}
	for tid, n := range seen {
		if n > ContributionBound {
			t.Fatalf("tenant %s kept %d rows", tid, n)
		}
	}
	if got := Bound(in, 2); len(got) != 6 {
		t.Fatalf("C=2: got %d, want 6", len(got))
	}
}

func TestReleasePreThresholdsBeforeNoise(t *testing.T) {
	for _, tc := range []struct {
		name            string
		tenants, groups int
		want            error
	}{
		{"k_24", K - 1, M, ErrBelowThreshold},
		{"m_4", K, M - 1, ErrBelowThreshold},
		{"k_25_m_5", K, M, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := Release(rows(tc.tenants, 3, tc.groups), EpsilonRelease)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err=%v want %v", err, tc.want)
			}
			if err == nil && (s.K != tc.tenants || s.M != tc.groups || s.Epsilon != EpsilonRelease) {
				t.Fatalf("stats %+v", s)
			}
		})
	}
}

// The choke templates: the tenant predicate is in the SQL text itself, not only in RLS.
func TestBudgetTemplatesCarryTheTenantPredicate(t *testing.T) {
	for name, sql := range map[string]string{"BudgetSQL": BudgetSQL, "LedgerSQL": LedgerSQL} {
		if !strings.Contains(sql, "tenant_id = $1") {
			t.Fatalf("%s lacks the tenant predicate:\n%s", name, sql)
		}
	}
	if !strings.Contains(candidateSQL, "federation_contributions") || !strings.Contains(candidateSQL, ">= 25") || !strings.Contains(candidateSQL, ">= 5") {
		t.Fatalf("candidateSQL is not the m1_064 HAVING form:\n%s", candidateSQL)
	}
}

func TestReleaseNoisesTheOrgCountNotTheTenantCount(t *testing.T) {
	rs := rows(K, 1, M)
	for i := range rs {
		rs[i].OrgID = rs[i%3].OrgID
	}
	var sum float64
	for i := 0; i < 200; i++ {
		s, err := Release(rs, EpsilonRelease)
		if err != nil {
			t.Fatal(err)
		}
		sum += float64(s.OrgCount)
	}
	if m := sum / 200; m < 2 || m > 4 {
		t.Fatalf("mean released org count %.2f, want ≈3 (not the %d tenants)", m, K)
	}
}
