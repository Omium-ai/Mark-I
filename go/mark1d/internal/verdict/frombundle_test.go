package verdict

import (
	"testing"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/policy"
	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

// bundleWith builds a decoded-shaped bundle: two verifiers in one clique, one
// solo, one quarantined, and a two-row knee table out of order — one row with
// D-Z's optional p_lcb, one without, so both states cross the seam.
func bundleWith() *policy.Bundle {
	pLCB := 0.05 // × VDefault 12.5 = 0.625 ≤ c(3) = 0.9 ⇒ at the knee
	return &policy.Bundle{
		Seq: 7,
		Verify: policy.VerifySection{
			Priors: policy.Posterior4{0.55, 0.30, 0.10, 0.05},
			Verifiers: []policy.VerifierModel{
				{VerifierID: "ruff@cat-1", Confusion: [4]policy.Signal3{{0.9, 0.05, 0.05}, {0.1, 0.8, 0.1}, {0.3, 0.3, 0.4}, {0.2, 0.2, 0.6}}},
				{VerifierID: "cargo-check@cat-3", Confusion: [4]policy.Signal3{{0.8, 0.1, 0.1}, {0.05, 0.9, 0.05}, {0.3, 0.3, 0.4}, {0.2, 0.2, 0.6}}},
				{VerifierID: "tsc@cat-2", Confusion: [4]policy.Signal3{{0.7, 0.2, 0.1}, {0.2, 0.7, 0.1}, {0.3, 0.3, 0.4}, {0.2, 0.2, 0.6}}},
			},
			CorrelationGroups: []policy.CorrelationGroup{{GroupID: "syntactic", Members: []uint32{0, 1}}},
			Quarantined:       []bool{false, false, true},
		},
		Route: policy.RouteSection{Knee: policy.KneeTable{
			CostBasis: policy.CostBasisQuota,
			Rows:      []policy.KneeRow{{N: 3, CN: 0.9, PLCB: &pLCB}, {N: 1, CN: 0.1}},
			VDefault:  12.5,
		}},
	}
}

// TestFromBundleMapsTheVerifySection is the seam itself: ids, confusion rows,
// clique membership, knee ordering, cost basis and V(task) all come from the
// bundle, and a quarantined verifier is absent rather than zeroed.
func TestFromBundleMapsTheVerifySection(t *testing.T) {
	m, err := FromBundle(bundleWith())
	if err != nil {
		t.Fatal(err)
	}
	if m.Stale {
		t.Fatal("a bundle with real matrices must not be fail-static")
	}
	if m.Seq != 7 || m.VTask != 12.5 || m.CostBasis != "quota" {
		t.Fatalf("envelope/route mapping wrong: seq=%d v=%v basis=%q", m.Seq, m.VTask, m.CostBasis)
	}
	if m.Priors != [4]float64{0.55, 0.30, 0.10, 0.05} {
		t.Fatalf("priors = %v", m.Priors)
	}
	if len(m.Verifiers) != 2 {
		t.Fatalf("verifiers = %v, want the two non-quarantined", m.Verifiers)
	}
	if _, listed := m.Verifiers["tsc@cat-2"]; listed {
		t.Fatal("a quarantined verifier must not be listed: fusion must ignore its votes (07 verify.quarantine)")
	}
	ruff := m.Verifiers["ruff@cat-1"]
	if ruff.Group != "syntactic" || m.Verifiers["cargo-check@cat-3"].Group != "syntactic" {
		t.Fatalf("clique membership lost: %v", m.Verifiers)
	}
	if ruff.Confusion[ixViolated][colReject] != 0.8 {
		t.Fatalf("confusion row not carried verbatim: %v", ruff.Confusion)
	}
	if len(m.Knee) != 2 || m.Knee[0].N != 1 || m.Knee[1].N != 3 {
		t.Fatalf("knee rows = %v, want ascending n", m.Knee)
	}
	// D-Z, both directions. The row that carries p_lcb must reach the knee
	// governor with the wire value: if the seam drops it, 04 §2.3's
	// at-the-knee ALLOW is unreachable code and the governor is inert.
	if m.Knee[0].PLCB != nil {
		t.Fatalf("knee row 1 invented a p_lcb: %v", *m.Knee[0].PLCB)
	}
	if m.Knee[1].PLCB == nil || *m.Knee[1].PLCB != 0.05 {
		t.Fatalf("knee row 3 lost its p_lcb: %v", m.Knee[1].PLCB)
	}
	if kneeFor(m, 1).Stop {
		t.Fatal("a knee row with no p_lcb is not evaluable ⇒ Stop must be false (D-Z)")
	}
	if k := kneeFor(m, 3); !k.Stop || k.PLCB != 0.05 {
		t.Fatalf("p̂_LCB·V(task) ≤ c(n) must stop: %+v", k)
	}
}

// TestFromBundleNoVerifySectionIsFailStatic is 04 §2.3's posture: a bundle
// carrying no usable matrices is not an error, it is built-ins + stale_cert.
func TestFromBundleNoVerifySectionIsFailStatic(t *testing.T) {
	b := bundleWith()
	b.Verify = policy.VerifySection{} // decodes to this when `verifiers` is empty
	m, err := FromBundle(b)
	if err != nil {
		t.Fatalf("an empty verify section is a posture, not an error: %v", err)
	}
	if !m.Stale {
		t.Fatal("no matrices must set Stale: gates allow, verdicts flagged stale_cert (M1E-3006)")
	}
	if m.Priors != DefaultPriors {
		t.Fatalf("priors = %v, want the built-ins", m.Priors)
	}
	// Fusion still answers — and a stale entry can never stop the knee.
	f := &Fuser{m: *m}
	ve := f.Fuse(TaskID{}, []AnchorVote{{AnchorID: "ruff@cat-1", Vote: m1pv1.Verdict_VERDICT_VIOLATED}})
	if ve.GetVerdict() == m1pv1.Verdict_VERDICT_UNSPECIFIED {
		t.Fatal("fail-static fusion must still produce a verdict")
	}
	if kneeFor(m, 1).Stop {
		t.Fatal("a stale bundle never stops")
	}
}

// TestFromBundleRejectsNonDistributionPriors: an all-zero priors row passes
// every range check and then leaves softmax with zero mass in every class.
// Decode already refuses it; the seam refuses to hand it to fusion too.
func TestFromBundleRejectsNonDistributionPriors(t *testing.T) {
	b := bundleWith()
	b.Verify.Priors = policy.Posterior4{}
	m, err := FromBundle(b)
	if err != nil {
		t.Fatal(err)
	}
	if !m.Stale || m.Priors != DefaultPriors {
		t.Fatalf("priors %v stale=%v, want the fail-static built-ins", m.Priors, m.Stale)
	}
}

func TestFromBundleNil(t *testing.T) {
	if _, err := FromBundle(nil); err == nil {
		t.Fatal("FromBundle(nil) must error — a caller bug, not a posture")
	}
}
