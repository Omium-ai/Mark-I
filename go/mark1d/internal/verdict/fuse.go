// Package verdict is 04 §2.3: naive-Bayes fusion over anchor votes by direct
// product (the edge twin of python/adjudicator/app/adjudicate — one algorithm,
// two deployment points, shared numbers), the knee governor evaluated at
// cache-publish time, and the lock-free cache the stop-gate reads. The gate
// path receives only Reader; Fuser instances live only inside the Engine's
// recompute goroutine — wiring fusion into a gate would need a visible
// constructor change in internal/fabric.
package verdict

import (
	"maps"
	"math"
	"slices"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

// TaskID is Event.task_id's 16 bytes (envelope.proto field 4).
type TaskID [16]byte

// Confusion is one verifier's P(vote | latent class): rows in the frozen
// posterior order [satisfied, violated, refused, error], columns
// [accept, reject, abstain]. D-R: the third column IS the abstention
// likelihood — there is no separate abstention model. D-V: it is consumed by
// an EXPLICIT abstain vote only.
type Confusion [4][3]float64

// VerifierParams is one verifier's row set from the bundle's verify section.
type VerifierParams struct {
	Confusion Confusion
	// Group is the correlation clique (06 §4.1, known BY CONSTRUCTION);
	// "" means the verifier is independent — its own group.
	Group string
}

// KneeRow is one bundle knee-table row (07 knee-table CDDL): attempt n, its
// expected cost c(n) under the bundle cost_basis, and the optional p_lcb —
// the wire source of 04 §2.3's p̂_LCB(n).
//
// D-Z: p_lcb is OPTIONAL on the wire, and 0.0 is a legitimate lower bound, so
// "absent" and "zero" MUST stay distinguishable — hence the pointer rather
// than a float64 that would silently make an unfitted row look like a
// certainly-hopeless one. Absent ⇒ the knee is not evaluable at that n ⇒
// Stop = false.
type KneeRow struct {
	N     int
	CostN float64
	PLCB  *float64
}

// BundleMatrices is the verify+route slice of a decoded PolicyBundle that
// fusion and the knee consume. Defined here, NOT imported from
// internal/policy (built concurrently) — the policy-to-verdict adapter is a
// typed seam for the wiring pass with exactly this constructor signature:
//
//	func FromBundle(b *policy.Bundle) (*verdict.BundleMatrices, error)
//
// living in the wiring package (or internal/policy), never here. That pass
// owns the D-Z mapping too: the knee table's OPTIONAL per-row p_lcb becomes
// KneeRow.PLCB, and a row that omits it maps to nil — never to 0.0.
type BundleMatrices struct {
	Seq       uint64
	Priors    [4]float64
	Verifiers map[string]VerifierParams // keyed by anchor_id
	Knee      []KneeRow                 // ascending n; lookup clamps to the last row
	Ladders   []Ladder                  // bundle order; LadderStep takes the first naming a model
	VTask     float64                   // V(task): bundle v_default (06 §8.1)
	CostBasis string                    // "usd" | "quota" (06 §8.4)
	// Stale is the M1E-3006 posture: past max_age or built-in defaults.
	// Fusion still runs (priors-only built-ins) but the knee never stops and
	// the cache entry is flagged stale_cert — gates answer allow (04 §2.3).
	Stale bool
}

// DefaultPriors mirrors the adjudicator's fallback (06 §3.2's bundle).
var DefaultPriors = [4]float64{0.55, 0.30, 0.10, 0.05}

// AnchorVote is one normalized ensemble member vote. Verdict semantics map to
// the adjudicator's NormalizedVote: SATISFIED=accept, VIOLATED=reject,
// REFUSED=abstain, ERROR=infra failure (uninformative on the likelihood —
// λ ⊥ Y | E — it feeds only the infra-dominance signal, mirroring
// adjudicate/algorithm.py).
type AnchorVote struct {
	AnchorID string
	Vote     m1pv1.Verdict
	// Tamper: integrity envelope failed — the vote NEVER enters the
	// likelihood (Thm 5.2: infra failure ≠ violated).
	Tamper bool
}

// Chow costs, D4 defaults (06 §3.1): band (A/R, 1−A/D) = (1/3, 8/9).
const (
	costAbstain     = 1.0
	costFalseReject = 3.0
	costFalseAccept = 9.0
	thetaError      = 0.5 // D3
	// infra_dominant: more than half the surviving votes are infra failures.
	infraDominantFrac = 0.5
)

const (
	ixSatisfied = 0
	ixViolated  = 1
	ixRefused   = 2
	ixError     = 3
)

const (
	colAccept  = 0
	colReject  = 1
	colAbstain = 2
)

// Fuser is pure math over bundle data. It is NOT exported to the fabric or
// gate paths — structurally, the gate cannot compute: fabric's gate handler
// is constructed with a Reader, and no Engine method returns a Fuser.
type Fuser struct {
	m BundleMatrices
}

// obs is one collapsed observation: a confusion row set + which column the
// vote selects. id breaks selection ties deterministically (D-W: smallest).
type obs struct {
	id   string
	conf Confusion
	col  int
}

// Fuse: naive Bayes by DIRECT PRODUCT (06 §3.1, step for step with the
// adjudicator). Votes are collapsed WITHIN each correlation group, independent
// ACROSS groups. D-V: SILENCE IS NOT AN OBSERVATION — an explicit abstain vote
// consumes the confusion4x3 abstain column, absence consumes nothing.
// Output posterior is [satisfied, violated, refused, error].
//
// D-AK (lead, binding): the log-space form is GONE. IEEE-754 mandates
// correctly-rounded * / + −, and mandates NOTHING for Exp/Log, so Go's pure-Go
// math and CPython's platform libm were free to land an ulp apart on the same
// fusion — and one ulp on a Chow threshold is the edge blocking a developer the
// cloud would not. D-AC's 1e-12 quantisation of the comparison is WITHDRAWN
// with it: rounding relocates the straddle set, it does not remove it (a grid
// sweep found 8 verdict flips invisible to every frozen vector). Log-space
// bought underflow headroom and nothing else; rescale() buys that back exactly.
// The 04 §2.3 signature returns the message by value; Go proto messages are
// no-copy, so this returns the pointer — the one mechanical deviation.
func (f *Fuser) Fuse(taskID TaskID, votes []AnchorVote) *m1pv1.VerdictEvent {
	_ = taskID // identity rides the Event envelope, not the fused body

	// Step 0 — integrity partition.
	tampered := false
	kept := votes[:0:0]
	for _, v := range votes {
		if v.Tamper {
			tampered = true
			continue
		}
		kept = append(kept, v)
	}
	// Steps 1–2 — anchor clamp is the likelihood; clique collapse then
	// independent products across groups. D-V: only members that ACTUALLY
	// VOTED contribute; absence consumes nothing. D-X: a voter the bundle does
	// not list contributes nothing either (the bundle is the sole source of
	// fusion parameters) — it is counted for accounting by unknownVoters.
	infra := 0
	coverage := 0
	groups := map[string][]obs{}
	for _, v := range kept {
		var col int
		switch v.Vote {
		case m1pv1.Verdict_VERDICT_SATISFIED:
			col = colAccept
		case m1pv1.Verdict_VERDICT_VIOLATED:
			col = colReject
		case m1pv1.Verdict_VERDICT_REFUSED:
			col = colAbstain
		default: // ERROR / unspecified: infra — no likelihood term
			infra++
			continue
		}
		p, listed := f.m.Verifiers[v.AnchorID]
		if !listed {
			continue
		}
		// D-AB: membership gates COVERAGE, not only likelihood. Counted before
		// this filter, a stranger's (or a quarantined verifier's — FromBundle
		// drops the row, so both arrive here identically) vote could satisfy D1
		// and unlock a BLOCK on a posterior it provably never moved.
		if col != colAbstain {
			coverage++
		}
		g := p.Group
		if g == "" {
			g = "\x00solo:" + v.AnchorID
		}
		groups[g] = append(groups[g], obs{id: v.AnchorID, conf: p.Confusion, col: col})
	}
	if coverage < 1 { // D1: MIN_EVIDENCE
		verdict := m1pv1.Verdict_VERDICT_REFUSED
		if tampered || infra > 0 {
			verdict = m1pv1.Verdict_VERDICT_ERROR
		}
		return f.event(verdict, degenerate(verdict), len(kept))
	}

	// Steps 1–2 — the posterior by direct product; the anchor clamp needs no
	// branch, it IS the likelihood. Sorted group order, never map order: float
	// products are not associative and 06 §3's cross-implementation conformance
	// is bit-exact (04 §2.3).
	u := f.m.Priors
	for _, g := range slices.Sorted(maps.Keys(groups)) {
		o := groupObservation(groups[g])
		rescale(&u)
		for t := range 4 {
			x := o.conf[t][o.col]
			if x > 0.0 {
				// D-AK step 4. Go's spec lets an implementation fuse this
				// product with the `total +=` below into one FMA "possibly
				// across statements" — a licence arm64 and ppc64 hold and amd64
				// does not, so the same bundle could decide differently on two
				// Go binaries. (Measured: go1.25 emits no FMADD here on either
				// arch, with or without this conversion. The conversion is the
				// spec's one guaranteed rounding, and the guarantee — not
				// today's codegen — is what a cross-language lock can rest on.)
				u[t] = float64(u[t] * x)
			} else {
				// The perfect-precision anchor NEEDS an exact zero (Paper II §9:
				// an anchor reject forces the odds to 0 regardless of the rest),
				// and a malformed negative or NaN row must not become a NaN that
				// sails through every comparison onto the wire. One branch, both.
				u[t] = 0.0
			}
		}
	}
	total := 0.0
	for _, x := range u {
		total = float64(total + x)
	}
	// Zero mass in every class: a broken bundle, not a verdict. The adjudicator
	// raises; this signature cannot, so the latent-error class (unobservable
	// because OUR plane failed) carries the truth. +Inf is the same answer: it
	// only reaches here from a non-finite bundle value, and Inf/Inf is the NaN
	// posterior that would otherwise land on the wire and in every receipt
	// derived from it. Both keep the fail-open direction — gate.go blocks only
	// on VIOLATED. (!(total > 0) also catches a NaN total.)
	if !(total > 0.0) || math.IsInf(total, 1) {
		return f.event(m1pv1.Verdict_VERDICT_ERROR, degenerate(m1pv1.Verdict_VERDICT_ERROR), len(kept))
	}
	var post [4]float64
	for i, x := range u {
		post[i] = x / total
	}

	// Step 3 — the error path (Thm 5.2).
	if post[ixError] > thetaError || (len(kept) > 0 && float64(infra)/float64(len(kept)) > infraDominantFrac) {
		return f.event(m1pv1.Verdict_VERDICT_ERROR, post, len(kept))
	}

	// Step 4 — Chow band (Thm 5.1) on the UNNORMALISED mass. There is no second,
	// "comparison" copy of the posterior any more: the wire copy and the
	// decision are the same numbers.
	return f.event(chowVerdict(u[ixSatisfied], total), post, len(kept))
}

// chowVerdict is 06 §3.1 step 4 on the unnormalised satisfied mass: η = uS/total
// (mirror of the adjudicator's chow.chow_verdict).
//
// D-AK: BY CROSS-MULTIPLICATION, NEVER DIVISION. `η ≥ 1 − A/D` is
// `uS·D ≥ (D−A)·total` and `η ≤ A/R` is `uS·R ≤ A·total` — one fewer rounding on
// each side, and the untyped-constant (D−A)/D rather than the float `1 − A/D`,
// since A/D is not representable and that subtraction was a second rounding
// sitting on the threshold itself. Each product is bound through float64() for
// the same reason as the fusion loop: `a*b >= c*d` is an FMA the compiler is
// free to form.
func chowVerdict(uS, total float64) m1pv1.Verdict {
	switch {
	case float64(uS*costFalseAccept) >= float64((costFalseAccept-costAbstain)*total):
		return m1pv1.Verdict_VERDICT_SATISFIED
	case float64(uS*costFalseReject) <= float64(costAbstain*total):
		return m1pv1.Verdict_VERDICT_VIOLATED
	default:
		return m1pv1.Verdict_VERDICT_REFUSED
	}
}

// rescale pulls the mass vector back up to max ∈ [0.5, 1) by an exact POWER OF
// TWO — the exact replacement for what log-space was actually protecting
// (D-AK step 2). Scaling by 2**k shifts the exponent and touches no mantissa
// bit, so it introduces zero error, and the common factor cancels in the
// normalisation and in the cross-multiplied Chow comparison alike. Without it,
// four cliques of 1e-300 likelihoods multiply straight through the smallest
// subnormal to zero and an ordinary fusion reads as a broken bundle.
//
// Frexp/Ldexp rather than D-AK's fixed 2**-512 threshold, matching the
// adjudicator's _rescale: that constant leaves 512 binary orders of headroom
// and ONE 1e-300 likelihood (2**-996.6) eats all of it.
func rescale(u *[4]float64) {
	_, exp2 := math.Frexp(max(u[0], u[1], u[2], u[3])) // Frexp(0) ⇒ exp 0: no-op
	for i := range u {
		u[i] = math.Ldexp(u[i], -exp2)
	}
}

func (f *Fuser) event(v m1pv1.Verdict, post [4]float64, voteCount int) *m1pv1.VerdictEvent {
	return &m1pv1.VerdictEvent{
		Stage:         m1pv1.VerdictStage_VERDICT_STAGE_PROVISIONAL,
		Verdict:       v,
		Posterior:     post[:],
		BundleSeq:     f.m.Seq,
		VoteCount:     uint32(voteCount), //nolint:gosec // G115: a count of the bundle's verifiers, never negative
		Certification: m1pv1.CertificationStatus_CERTIFICATION_STATUS_UNCERTIFIED,
	}
}

func degenerate(v m1pv1.Verdict) [4]float64 {
	var p [4]float64
	p[int(v)-1] = 1.0
	return p
}

// groupObservation collapses one clique to one term — the adjudicator's
// recorded DESIGN rule (algorithm.py _group_observation): any reject ⇒ the
// sharpest rejecter (min P(reject|satisfied)) — preserves the anchor's
// perfect-precision clamp whole; else any accept ⇒ the most informative
// accepter (max accept likelihood ratio); else all abstained ⇒ the explicit
// abstain likelihood of one member.
//
// D-W: EVERY branch resolves ties to the LEXICALLY SMALLEST verifier id. The
// accept branch used to disagree with the adjudicator's max(), which broke
// toward the largest id — one input, two wire posteriors.
func groupObservation(members []obs) obs {
	var best obs
	bestScore := 0.0
	found := false
	for _, m := range members {
		if m.col != colReject {
			continue
		}
		s := m.conf[ixSatisfied][colReject]
		if !found || s < bestScore || (s == bestScore && m.id < best.id) {
			best, bestScore, found = m, s, true
		}
	}
	if found {
		return best
	}
	for _, m := range members {
		if m.col != colAccept {
			continue
		}
		aS, aV := m.conf[ixSatisfied][colAccept], m.conf[ixViolated][colAccept]
		lr := math.Inf(1)
		if aV > 0 {
			lr = aS / aV
		}
		if !found || lr > bestScore || (lr == bestScore && m.id < best.id) {
			best, bestScore, found = m, lr, true
		}
	}
	if found {
		return best
	}
	best = members[0]
	for _, m := range members[1:] {
		if m.id < best.id {
			best = m
		}
	}
	return best
}

// unknownVoters counts the votes that WOULD have carried a likelihood had the
// bundle listed their verifier. D-X: they contribute none, but they are
// ACCOUNTED, never silently dropped — the Engine stamps this into Cached at
// publish. Tampered and infra-failed votes are excluded on both sides of the
// wire: neither ever reaches the likelihood, and both have their own counters.
func unknownVoters(m *BundleMatrices, votes []AnchorVote) uint32 {
	n := uint32(0)
	for _, v := range votes {
		switch v.Vote {
		case m1pv1.Verdict_VERDICT_SATISFIED, m1pv1.Verdict_VERDICT_VIOLATED, m1pv1.Verdict_VERDICT_REFUSED:
			if _, listed := m.Verifiers[v.AnchorID]; !listed && !v.Tamper {
				n++
			}
		}
	}
	return n
}
