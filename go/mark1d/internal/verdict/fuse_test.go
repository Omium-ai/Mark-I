package verdict

import (
	"math"
	"testing"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

// golden32Bundle is 06 §3.2's worked example verbatim: priors from the
// bundle, the three verifiers' likelihood columns as printed. The accept
// column of cargo-check-warm and the reject column of the judge are the
// table's numbers; the remaining columns only need to be proper rows.
func golden32Bundle() BundleMatrices {
	return BundleMatrices{
		Seq:    7,
		Priors: [4]float64{0.55, 0.30, 0.10, 0.05},
		Verifiers: map[string]VerifierParams{
			"cargo-check-warm": {Group: "syntactic", Confusion: Confusion{
				{0.98, 0.02, 0.00}, // satisfied — P(accept|S)=0.98, D2 anchor reject=ε
				{0.60, 0.35, 0.05}, // violated  — P(accept|V)=0.60
				{0.50, 0.10, 0.40}, // refused   — P(accept|R)=0.50
				{0.50, 0.15, 0.35}, // error     — P(accept|E)=0.50
			}},
			"ruff": {Group: "syntactic", Confusion: Confusion{
				{0.20, 0.10, 0.70},
				{0.15, 0.15, 0.70},
				{0.15, 0.15, 0.70},
				{0.10, 0.20, 0.70},
			}},
			"judge:grounded-rubric": {Group: "judges", Confusion: Confusion{
				{0.80, 0.15, 0.05}, // P(reject|S)=0.15
				{0.25, 0.70, 0.05}, // P(reject|V)=0.70
				{0.20, 0.40, 0.40}, // P(reject|R)=0.40
				{0.20, 0.40, 0.40}, // P(reject|E)=0.40
			}},
		},
	}
}

func golden32Votes() []AnchorVote {
	return []AnchorVote{
		{AnchorID: "cargo-check-warm", Vote: m1pv1.Verdict_VERDICT_SATISFIED},
		{AnchorID: "ruff", Vote: m1pv1.Verdict_VERDICT_REFUSED}, // abstain: no Python in diff
		{AnchorID: "judge:grounded-rubric", Vote: m1pv1.Verdict_VERDICT_VIOLATED},
	}
}

// TestFuseGolden32 reproduces 06 §3.2's numbers to the printed precision:
// posterior [0.3414, 0.5320, 0.0844, 0.0422], verdict refused (in the Chow
// band by 0.008), stage PROVISIONAL at the edge.
func TestFuseGolden32(t *testing.T) {
	f := &Fuser{m: golden32Bundle()}
	ve := f.Fuse(TaskID{1}, golden32Votes())

	want := [4]float64{0.3414, 0.5320, 0.0844, 0.0422}
	if len(ve.Posterior) != 4 {
		t.Fatalf("posterior arity %d, want exactly 4 (frozen wire invariant)", len(ve.Posterior))
	}
	for i, w := range want {
		if math.Abs(ve.Posterior[i]-w) > 1e-4 {
			t.Fatalf("posterior[%d] = %.6f, want %.4f (06 §3.2)", i, ve.Posterior[i], w)
		}
	}
	if ve.Verdict != m1pv1.Verdict_VERDICT_REFUSED {
		t.Fatalf("verdict %v, want refused — η=0.3414 is inside the (0.333, 0.889) band", ve.Verdict)
	}
	if ve.Stage != m1pv1.VerdictStage_VERDICT_STAGE_PROVISIONAL {
		t.Fatalf("stage %v, want PROVISIONAL (edge fusion)", ve.Stage)
	}
	if ve.VoteCount != 3 || ve.BundleSeq != 7 {
		t.Fatalf("vote_count=%d bundle_seq=%d, want 3, 7", ve.VoteCount, ve.BundleSeq)
	}
	if ve.Certification != m1pv1.CertificationStatus_CERTIFICATION_STATUS_UNCERTIFIED {
		t.Fatalf("edge fusion claimed certification %v", ve.Certification)
	}
}

// TestFuseAnchorRejectClamps is 06 §3.2 counterfactual (a): the compile
// anchor rejecting collapses satisfied mass ~50-fold through the ordinary
// product — violated at ≥0.95 with no special-case branch.
func TestFuseAnchorRejectClamps(t *testing.T) {
	f := &Fuser{m: golden32Bundle()}
	votes := golden32Votes()
	votes[0].Vote = m1pv1.Verdict_VERDICT_VIOLATED
	ve := f.Fuse(TaskID{1}, votes)
	// 06 §3.2 (a): the UNNORMALIZED satisfied mass collapses ~50-fold (the
	// 0.98→0.02 anchor factor) and the verdict is violated regardless of the
	// judge. After renormalization that is posterior[0] ≈ 0.0201 — hand-derived
	// from this bundle's rows: u = [0.55·0.02·0.15, 0.30·0.35·0.70,
	// 0.10·0.10·0.40, 0.05·0.15·0.40] = [0.00165, 0.0735, 0.004, 0.003].
	// (The doc's "≥0.95" figure assumes reject columns it never prints.)
	want := [4]float64{0.020085, 0.894705, 0.048691, 0.036519}
	if ve.Verdict != m1pv1.Verdict_VERDICT_VIOLATED {
		t.Fatalf("anchor reject: verdict %v posterior %v, want violated", ve.Verdict, ve.Posterior)
	}
	for i, w := range want {
		if math.Abs(ve.Posterior[i]-w) > 1e-4 {
			t.Fatalf("posterior[%d] = %.6f, want %.6f (hand-derived)", i, ve.Posterior[i], w)
		}
	}
}

// absentProbeBundle is the D-V probe verbatim: an anchor that accepts and a
// second bundle member that never reports, its abstain column deliberately
// asymmetric (0.05/0.05/0.60/0.60) so synthesising it is measurable — that
// synthesis flipped this input to VERDICT_VIOLATED at the edge while the
// adjudicator, iterating received votes, called it refused. Same bundle, same
// votes, opposite answers, and the edge one blocks a developer.
func absentProbeBundle() BundleMatrices {
	return BundleMatrices{
		Seq:    3,
		Priors: [4]float64{0.55, 0.30, 0.10, 0.05},
		Verifiers: map[string]VerifierParams{
			"anchor": {Group: "syntactic", Confusion: Confusion{
				{0.90, 0.02, 0.08},
				{0.55, 0.40, 0.05},
				{0.46, 0.04, 0.50},
				{0.46, 0.04, 0.50},
			}},
			"slow-judge": {Group: "judges", Confusion: Confusion{
				{0.85, 0.10, 0.05},
				{0.25, 0.70, 0.05},
				{0.20, 0.20, 0.60},
				{0.20, 0.20, 0.60},
			}},
		},
	}
}

// TestFuseAbsentMemberContributesNothing pins D-V: SILENCE IS NOT AN
// OBSERVATION. A bundle member that did not report (the fast/slow split's
// normal state — "has not run yet") consumes no column at all, so the
// PROVISIONAL posterior is not a function of which anchors happen to be slow.
func TestFuseAbsentMemberContributesNothing(t *testing.T) {
	f := &Fuser{m: absentProbeBundle()}
	accept := []AnchorVote{{AnchorID: "anchor", Vote: m1pv1.Verdict_VERDICT_SATISFIED}}
	ve := f.Fuse(TaskID{2}, accept)

	// Derived by hand: u(t) = π(t)·P(accept|t) over the anchor alone —
	// [0.55·0.90, 0.30·0.55, 0.10·0.46, 0.05·0.46] = [0.495, 0.165, 0.046, 0.023],
	// Σ = 0.729 ⇒ [0.679012…, 0.226337…, 0.063100…, 0.031550…], η inside the
	// band ⇒ refused, which is what the adjudicator answered on this input.
	want := [4]float64{0.4950 / 0.729, 0.1650 / 0.729, 0.0460 / 0.729, 0.0230 / 0.729}
	for i, w := range want {
		if math.Abs(ve.Posterior[i]-w) > 1e-12 {
			t.Fatalf("posterior[%d] = %.9f, want %.9f — the silent member was given a column", i, ve.Posterior[i], w)
		}
	}
	// Synthesising slow-judge's abstain column drove η to 0.3327 ≤ A/R = 1/3:
	// VIOLATED, i.e. the gate blocking a developer on evidence nobody gathered.
	if ve.Verdict != m1pv1.Verdict_VERDICT_REFUSED {
		t.Fatalf("verdict %v (posterior %v), want refused", ve.Verdict, ve.Posterior)
	}

	// An EXPLICIT abstain is different: that member ran and could not decide,
	// and its abstain column is the whole point of D-R.
	explicit := f.Fuse(TaskID{2}, append(accept,
		AnchorVote{AnchorID: "slow-judge", Vote: m1pv1.Verdict_VERDICT_REFUSED}))
	if math.Abs(explicit.Posterior[0]-ve.Posterior[0]) < 1e-9 {
		t.Fatal("an explicit abstain changed nothing — the abstain column is not being consumed")
	}
}

// TestFuseTamperExcluded: a tampered vote NEVER enters the likelihood
// (Thm 5.2), and under D-V it is not replaced by an abstain either — it is
// exactly as if the verifier had not reported.
func TestFuseTamperExcluded(t *testing.T) {
	f := &Fuser{m: golden32Bundle()}
	votes := golden32Votes()
	votes[2].Tamper = true // judge vote tampered
	ve := f.Fuse(TaskID{3}, votes)
	want := f.Fuse(TaskID{3}, votes[:2])
	for i := range 4 {
		if math.Abs(ve.Posterior[i]-want.Posterior[i]) > 1e-12 {
			t.Fatalf("tampered vote leaked into the likelihood: %v vs %v", ve.Posterior, want.Posterior)
		}
	}
	if ve.VoteCount != 2 {
		t.Fatalf("vote_count %d counts the tampered vote", ve.VoteCount)
	}
}

// TestFuseUnknownVoterContributesNothing pins D-X: the signed bundle is the
// sole source of fusion parameters at the edge. A vote from a verifier it does
// not list gets no default row — a hardcoded per-kind default is exactly the
// edge-invented parameter 04 §2.3 forbids.
func TestFuseUnknownVoterContributesNothing(t *testing.T) {
	f := &Fuser{m: golden32Bundle()}
	base := f.Fuse(TaskID{7}, golden32Votes())
	withStranger := f.Fuse(TaskID{7}, append(golden32Votes(),
		AnchorVote{AnchorID: "mystery-linter", Vote: m1pv1.Verdict_VERDICT_VIOLATED}))
	for i := range 4 {
		if base.Posterior[i] != withStranger.Posterior[i] {
			t.Fatalf("posterior[%d]: %v vs %v — an unlisted verifier moved the posterior", i, base.Posterior, withStranger.Posterior)
		}
	}
	// It still counts as a fused vote count.
	if withStranger.VoteCount != 4 {
		t.Fatalf("vote_count %d — the unknown voter was dropped from accounting", withStranger.VoteCount)
	}
}

// TestFuseUnlistedVoterSuppliesNoCoverage is D-AB: membership gates COVERAGE,
// not only likelihood. Counted ahead of the membership filter, the stranger's
// reject alone met D1 and turned an honest degenerate refused into a fused
// verdict on a posterior it provably never moved — and since FromBundle drops
// quarantined rows, an explicitly distrusted verifier arrived by the same door.
func TestFuseUnlistedVoterSuppliesNoCoverage(t *testing.T) {
	f := &Fuser{m: golden32Bundle()}
	ve := f.Fuse(TaskID{11}, []AnchorVote{
		{AnchorID: "ruff", Vote: m1pv1.Verdict_VERDICT_REFUSED},
		{AnchorID: "mystery-judge", Vote: m1pv1.Verdict_VERDICT_VIOLATED},
	})
	if ve.Verdict != m1pv1.Verdict_VERDICT_REFUSED || ve.Posterior[ixRefused] != 1.0 {
		t.Fatalf("verdict %v posterior %v, want degenerate refused — an unlisted voter supplied D1 coverage", ve.Verdict, ve.Posterior)
	}
}

// TestFuseAcceptTieBreaksToSmallestID pins D-W on the branch that diverged:
// two accepters in one clique with EQUAL accept likelihood ratios, differing
// elsewhere. Go broke toward the smaller id, the adjudicator's max() toward
// the larger — one input, two wire posteriors.
func TestFuseAcceptTieBreaksToSmallestID(t *testing.T) {
	m := BundleMatrices{
		Priors: [4]float64{0.55, 0.30, 0.10, 0.05},
		Verifiers: map[string]VerifierParams{
			// LR = 0.80/0.40 = 2 for both; only the refused/error rows differ.
			"aaa": {Group: "syntactic", Confusion: Confusion{
				{0.80, 0.10, 0.10}, {0.40, 0.50, 0.10}, {0.20, 0.40, 0.40}, {0.20, 0.40, 0.40},
			}},
			"zzz": {Group: "syntactic", Confusion: Confusion{
				{0.80, 0.10, 0.10}, {0.40, 0.50, 0.10}, {0.60, 0.20, 0.20}, {0.60, 0.20, 0.20},
			}},
		},
	}
	f := &Fuser{m: m}
	ve := f.Fuse(TaskID{8}, []AnchorVote{
		{AnchorID: "zzz", Vote: m1pv1.Verdict_VERDICT_SATISFIED},
		{AnchorID: "aaa", Vote: m1pv1.Verdict_VERDICT_SATISFIED},
	})
	// aaa's row: u = [0.55·0.80, 0.30·0.40, 0.10·0.20, 0.05·0.20] =
	// [0.44, 0.12, 0.02, 0.01], Σ = 0.59.
	want := [4]float64{0.44 / 0.59, 0.12 / 0.59, 0.02 / 0.59, 0.01 / 0.59}
	for i, w := range want {
		if math.Abs(ve.Posterior[i]-w) > 1e-12 {
			t.Fatalf("posterior[%d] = %.9f, want %.9f — the tie did not resolve to the smallest id", i, ve.Posterior[i], w)
		}
	}
}

// TestFuseChowBoundaryIsDecidedByTheRule is D-AK on the boundary D-AC was
// invented for: priors (0.4,0.4,0.1,0.1) against an accept column of
// (0.04,0.05,0.06,0.06) put posterior[satisfied] at exactly A/R = 1/3, where the
// rule says violated. Through logsumexp the float landed an ulp ABOVE and Go
// answered refused where the adjudicator answered violated. With no
// transcendental left the fusion is exact IEEE-754 arithmetic, so η is 1/3 on
// the nose in both languages and the rule — not a libm — decides it. Same
// construction as conformance vector chow_boundary_eta_exactly_a_over_r.
func TestFuseChowBoundaryIsDecidedByTheRule(t *testing.T) {
	m := BundleMatrices{
		Priors: [4]float64{0.4, 0.4, 0.1, 0.1},
		Verifiers: map[string]VerifierParams{"boundary": {Group: "judges", Confusion: Confusion{
			{0.04, 0.48, 0.48}, {0.05, 0.47, 0.48}, {0.06, 0.47, 0.47}, {0.06, 0.47, 0.47},
		}}},
	}
	ve := (&Fuser{m: m}).Fuse(TaskID{12}, []AnchorVote{{AnchorID: "boundary", Vote: m1pv1.Verdict_VERDICT_SATISFIED}})
	if ve.Verdict != m1pv1.Verdict_VERDICT_VIOLATED {
		t.Fatalf("verdict %v at η = A/R (%.17g), want violated (η ≤ A/R)", ve.Verdict, ve.Posterior[ixSatisfied])
	}
	if ve.Posterior[ixSatisfied] != 1.0/3.0 {
		t.Fatalf("posterior[satisfied] = %.17g, want exactly 1/3 — a transcendental or a quantisation is still on the verdict path", ve.Posterior[ixSatisfied])
	}
}

// TestChowComparesByCrossMultiplication is D-AK step 3, and it needs its own
// discriminator: the boundary vectors above pass under the divided form too, so
// they do not prove the point. These two masses are the one construction where
// u_S·9 and 8·total are BOTH exactly representable — making cross-multiplication
// provably the exact rational answer — and the quotient still rounds the other
// way. Exact η is strictly below 8/9 (refused); η = u_S/total rounds up to
// exactly 1 − 1/9 and reads satisfied. Pinned identically in the adjudicator's
// test_chow.py, from the same search.
func TestChowComparesByCrossMultiplication(t *testing.T) {
	// Vars, not consts: Go evaluates untyped constant expressions in exact
	// arbitrary precision and rounds once, so `const` here would silently test
	// the referee instead of the float64 arithmetic Fuse actually runs.
	uS, total := 0.8788095083430196, 0.9886606968858972
	if got := uS / total; got < 1-costAbstain/costFalseAccept {
		t.Fatalf("η = %.17g no longer rounds across the threshold — this input stopped discriminating", got)
	}
	if v := chowVerdict(uS, total); v != m1pv1.Verdict_VERDICT_REFUSED {
		t.Fatalf("verdict %v, want refused — the Chow comparison divided instead of cross-multiplying", v)
	}
}

// TestFuseIsNotContracted is the D-AK hazard that is INVISIBLE ON amd64: Go's
// spec lets an implementation fuse a product with a following add into one FMA
// "possibly across statements", a licence arm64 and ppc64 hold. That would make
// one Go binary disagree with another — and with Python everywhere — on the same
// bundle, the exact divergence removing the transcendentals was for. The
// explicit float64() in fuse.go's product is the spec's one guaranteed rounding;
// this pins what that guarantee buys, on constants where the fused and unfused
// answers differ, with math.FMA standing in for what contraction would emit.
//
// Honest scope: go1.25 emits no FMADD in Fuse on either arch today (checked with
// GOARCH=arm64 go build -gcflags=-S, with and without the conversion), so this
// cannot be watched failing here. It guards the toolchain, not today's codegen —
// and the first assertion fails loudly rather than passing vacuously if a
// compiler change ever stops the constants discriminating.
func TestFuseIsNotContracted(t *testing.T) {
	x := 1 + math.Ldexp(1, -52) // exact product needs 2^-103, four bits past a float64
	y := 1 + math.Ldexp(1, -51)
	z := -(1 + math.Ldexp(1, -51) + math.Ldexp(1, -52))
	fused := math.FMA(x, y, z)
	if fused == float64(x*y)+z {
		t.Fatalf("constants stopped discriminating contraction: fma = %.17g", fused)
	}
	if got := float64(x*y) + z; got != 0 {
		t.Fatalf("x*y+z = %.17g, want 0 — the product was contracted into an FMA (fused: %.17g)", got, fused)
	}
}

// TestFuseNegativeLikelihoodIsNotNaN pins the _log mirror: math.Log of a
// negative is NaN, and every NaN comparison downstream falls through — the
// measured result was posterior [NaN NaN NaN NaN] emitted onto the wire.
// A non-positive likelihood is -Inf, exactly as the adjudicator's _log says.
func TestFuseNegativeLikelihoodIsNotNaN(t *testing.T) {
	m := golden32Bundle()
	p := m.Verifiers["judge:grounded-rubric"]
	p.Confusion[ixRefused][colReject] = -0.5 // a malformed bundle row
	m.Verifiers["judge:grounded-rubric"] = p
	ve := (&Fuser{m: m}).Fuse(TaskID{9}, golden32Votes())
	for i, x := range ve.Posterior {
		if math.IsNaN(x) {
			t.Fatalf("posterior[%d] is NaN — a negative likelihood reached math.Log", i)
		}
	}
	if ve.Posterior[ixRefused] != 0 {
		t.Fatalf("posterior[refused] = %v, want exactly 0 (the -Inf term)", ve.Posterior[ixRefused])
	}
}

// TestFuseNonFiniteIsNotNaN is the +Inf twin of the negative case. +Inf IS
// strictly positive, so it survives the likelihood branch and multiplies through
// to an infinite mass; the normalisation is then Inf/Inf = NaN, and a NaN
// posterior sails through every comparison downstream onto the wire and into
// every receipt derived from it. All the constructions below measured
// [NaN NaN NaN NaN]. internal/policy's decode blocks this from a SIGNED bundle;
// the cmd/main.go matrices apply seam and Builtins() do not.
//
// The last case is a genuine fusion, not a refusal, and that is the adjudicator's
// answer too: a zero likelihood zeroes its class BEFORE the infinity can reach
// the sum, so nothing non-finite ever enters the total. Under logsumexp the same
// input was Inf − Inf = NaN, and the guard had to catch it; matching the twin
// matters more than refusing an input that now has an ordinary answer.
func TestFuseNonFiniteIsNotNaN(t *testing.T) {
	inf := math.Inf(1)
	setConf := func(m *BundleMatrices, id string, row, col int, x float64) {
		p := m.Verifiers[id]
		p.Confusion[row][col] = x
		m.Verifiers[id] = p
	}
	cases := map[string]struct {
		mut       func(*BundleMatrices)
		wantFused bool
	}{
		"one likelihood row": {mut: func(m *BundleMatrices) {
			setConf(m, "cargo-check-warm", ixSatisfied, colAccept, inf)
		}},
		"two likelihood rows": {mut: func(m *BundleMatrices) {
			setConf(m, "cargo-check-warm", ixSatisfied, colAccept, inf)
			setConf(m, "cargo-check-warm", ixViolated, colAccept, inf)
		}},
		"infinite prior": {mut: func(m *BundleMatrices) { m.Priors[ixViolated] = inf }},
		"infinite prior over a zero likelihood": {wantFused: true, mut: func(m *BundleMatrices) {
			m.Priors[ixViolated] = inf
			setConf(m, "cargo-check-warm", ixViolated, colAccept, 0)
		}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			m := golden32Bundle()
			tc.mut(&m)
			ve := (&Fuser{m: m}).Fuse(TaskID{13}, golden32Votes())
			for i, p := range ve.Posterior {
				if math.IsNaN(p) || math.IsInf(p, 0) {
					t.Fatalf("posterior[%d] is non-finite — a non-finite bundle value reached the wire: %v", i, ve.Posterior)
				}
			}
			if tc.wantFused {
				if ve.Posterior[ixViolated] != 0 {
					t.Fatalf("posterior[violated] = %v, want exactly 0 (the zero likelihood)", ve.Posterior[ixViolated])
				}
				return
			}
			if ve.Verdict != m1pv1.Verdict_VERDICT_ERROR || ve.Posterior[ixError] != 1.0 {
				t.Fatalf("verdict %v posterior %v, want degenerate error — a broken bundle is not a verdict", ve.Verdict, ve.Posterior)
			}
		})
	}
}

// TestFuseGroupOrderIsDeterministic pins the sorted-group rule: Go's map
// iteration is randomized per run and float log-sums are not associative, so
// the same input produced posteriors differing in the last bits between runs —
// enough to flip a verdict sitting on a Chow threshold, and enough to make
// bit-exact cross-language vectors flake.
func TestFuseGroupOrderIsDeterministic(t *testing.T) {
	m := BundleMatrices{Priors: [4]float64{0.55, 0.30, 0.10, 0.05}, Verifiers: map[string]VerifierParams{}}
	var votes []AnchorVote
	for i, id := range []string{"g1", "g2", "g3", "g4", "g5"} {
		m.Verifiers[id] = VerifierParams{Group: id, Confusion: Confusion{
			{0.7 + float64(i)*0.03, 0.2, 0.1 - float64(i)*0.01},
			{0.31 + float64(i)*0.07, 0.5, 0.19 - float64(i)*0.02},
			{0.23 + float64(i)*0.11, 0.4, 0.37 - float64(i)*0.03},
			{0.17 + float64(i)*0.13, 0.6, 0.23 - float64(i)*0.02},
		}}
		votes = append(votes, AnchorVote{AnchorID: id, Vote: m1pv1.Verdict_VERDICT_SATISFIED})
	}
	f := &Fuser{m: m}
	first := f.Fuse(TaskID{10}, votes).Posterior
	for range 2000 {
		got := f.Fuse(TaskID{10}, votes).Posterior
		for i := range 4 {
			if got[i] != first[i] { // bit-exact, not approximately
				t.Fatalf("posterior[%d] drifted across runs: %.17g vs %.17g", i, got[i], first[i])
			}
		}
	}
}

// TestFuseInsufficientEvidence pins step 0: all abstain ⇒ degenerate refused;
// tamper or infra with no informative vote ⇒ degenerate error.
func TestFuseInsufficientEvidence(t *testing.T) {
	f := &Fuser{m: golden32Bundle()}
	ve := f.Fuse(TaskID{4}, []AnchorVote{{AnchorID: "ruff", Vote: m1pv1.Verdict_VERDICT_REFUSED}})
	if ve.Verdict != m1pv1.Verdict_VERDICT_REFUSED || ve.Posterior[2] != 1.0 {
		t.Fatalf("honest silence: %v %v, want degenerate refused", ve.Verdict, ve.Posterior)
	}
	ve = f.Fuse(TaskID{4}, []AnchorVote{{AnchorID: "cargo-check-warm", Vote: m1pv1.Verdict_VERDICT_ERROR}})
	if ve.Verdict != m1pv1.Verdict_VERDICT_ERROR || ve.Posterior[3] != 1.0 {
		t.Fatalf("infra failure: %v %v, want degenerate error", ve.Verdict, ve.Posterior)
	}
}

// TestFuseZeroMassBundle: every class zeroed out ⇒ latent error, never NaN
// (the -inf arithmetic mirror of the adjudicator's loud refusal).
func TestFuseZeroMassBundle(t *testing.T) {
	m := golden32Bundle()
	m.Priors = [4]float64{0, 0, 0, 0}
	ve := (&Fuser{m: m}).Fuse(TaskID{5}, golden32Votes())
	if ve.Verdict != m1pv1.Verdict_VERDICT_ERROR {
		t.Fatalf("zero-mass bundle produced %v, want error", ve.Verdict)
	}
	for i, p := range ve.Posterior {
		if math.IsNaN(p) {
			t.Fatalf("posterior[%d] is NaN under -inf arithmetic", i)
		}
	}
}
