// The typed policy→verdict seam declared in fuse.go's BundleMatrices comment.
// It lives here rather than in internal/policy so that the direction of the
// dependency matches the direction of the data (policy decodes; verdict
// consumes), and so that internal/policy stays a pure decoder with no opinion
// about fusion.
package verdict

import (
	"errors"
	"slices"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/policy"
)

// FromBundle renders a verified, decoded bundle as the matrices fusion and the
// knee governor consume. It never invents a row: a verifier the bundle does not
// list is simply absent (D-X), and a knee row that carries no p_lcb maps to a
// nil PLCB, not to 0.0 (D-Z).
//
// A bundle that carries no usable verify matrices is NOT an error — it is
// 04 §2.3's fail-static posture: priors-only built-ins, Stale set, so the knee
// never stops, gates answer allow and verdicts are flagged stale_cert
// (M1E-3006). The only error is a nil bundle, which is a caller bug.
//
// Staleness by max_age is the CALLER's: FromBundle has no clock, and
// policy.Bundle.IsFresh is the evaluation. Set Stale on the result when the
// caller's clock says the bundle aged out.
func FromBundle(b *policy.Bundle) (*BundleMatrices, error) {
	if b == nil {
		return nil, errors.New("verdict: FromBundle(nil)")
	}
	m := &BundleMatrices{
		Seq:       b.Seq,
		Priors:    [4]float64(b.Verify.Priors),
		Verifiers: map[string]VerifierParams{},
		VTask:     b.Route.Knee.VDefault,
		CostBasis: costBasisName(b.Route.Knee.CostBasis),
	}

	// The bundle's correlation cliques, resolved back to verifier ids. A
	// verifier in no group keeps Group "" — its own clique, per VerifierParams.
	group := make([]string, len(b.Verify.Verifiers))
	for _, g := range b.Verify.CorrelationGroups {
		for _, i := range g.Members {
			if int(i) < len(group) {
				group[i] = g.GroupID
			}
		}
	}
	for i, v := range b.Verify.Verifiers {
		// 07's `quarantine` list: fusion must ignore these votes. Dropping the
		// row (rather than zeroing it) is what makes those votes indistinguish-
		// able from any other unlisted voter — no likelihood, counted by D-X's
		// unknownVoters.
		if i < len(b.Verify.Quarantined) && b.Verify.Quarantined[i] {
			continue
		}
		var c Confusion
		for r, row := range v.Confusion {
			c[r] = [3]float64(row)
		}
		m.Verifiers[v.VerifierID] = VerifierParams{Confusion: c, Group: group[i]}
	}

	for _, r := range b.Route.Knee.Rows {
		// D-Z: the pointer is copied, not dereferenced — absent stays absent
		// (not evaluable ⇒ Stop = false) and never collapses into 0.0, which
		// would read as "certainly hopeless" and stop every attempt.
		m.Knee = append(m.Knee, KneeRow{N: int(r.N), CostN: r.CN, PLCB: r.PLCB}) // #nosec G115 -- attempt index, bounded by the table
	}
	// kneeFor documents "ascending n"; the CDDL does not require the compiler
	// to emit them sorted, so sort rather than trust.
	slices.SortFunc(m.Knee, func(a, b KneeRow) int { return a.N - b.N })
	m.KneeBasis = kneeBasis(b.Route.Knee.Basis)

	for _, l := range b.Route.Ladders {
		rungs := make([]Rung, len(l.Rungs))
		for i, r := range l.Rungs {
			rungs[i] = Rung(r)
		}
		m.Ladders = append(m.Ladders, Ladder{ID: l.LadderID, Rungs: rungs})
	}

	if len(m.Verifiers) == 0 || !isDistribution(m.Priors) {
		// Fail-static: no matrices to fuse with. Built-in priors keep Fuse
		// answering (a coverage-1 vote still yields a posterior), Stale keeps
		// the knee from ever stopping and flags every entry stale_cert. The
		// bundle's knee rows survive: they are route data, and Stale already
		// makes them unable to stop anything.
		built := Builtins()
		m.Priors, m.Verifiers, m.Stale = built.Priors, built.Verifiers, built.Stale
	}
	return m, nil
}

// Builtins is 04 §2.3's fail-static posture as a value: the no-bundle boot
// state (04 §9.4 with no LKG persisted) and what FromBundle falls back to.
// Gates allow, verdicts are flagged stale_cert, the knee never stops.
func Builtins() BundleMatrices {
	return BundleMatrices{Priors: DefaultPriors, Verifiers: map[string]VerifierParams{}, Stale: true}
}

// kneeBasis is the bundle's own word for where the knee's p came from (ADR-0013): a bundle that predates route.knee.basis says nothing, and "unknown" is recorded rather than a guess.
func kneeBasis(b string) string {
	if b == "" {
		return "unknown"
	}
	return b
}

func costBasisName(c policy.CostBasis) string {
	if c == policy.CostBasisQuota {
		return "quota"
	}
	return "usd"
}

// isDistribution is the decode-time guarantee restated as a runtime check: an
// all-zero priors row passes every range check and then makes fusion's softmax
// find zero mass in every class. Tolerance matches internal/policy's distSumTol.
func isDistribution(p [4]float64) bool {
	sum := 0.0
	for _, x := range p {
		if x < 0 || x > 1 {
			return false
		}
		sum += x
	}
	return sum > 1-1e-9 && sum < 1+1e-9
}
