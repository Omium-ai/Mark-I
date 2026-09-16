package policy

import (
	"math"
	"testing"
)

// TestKneePLCBIsOptionalAndRangeChecked — D-Z: 07's knee-table CDDL carries an
// OPTIONAL `? p_lcb: float` per row. A decoder that rejects it (strictKeys with
// no optional set) makes every CDDL-legal bundle carrying one an M1E-3001, so
// PLCB can never reach the knee governor and 04 §2.3's at-the-knee ALLOW is
// unreachable. Absent must stay distinguishable from present-and-zero.
func TestKneePLCBIsOptionalAndRangeChecked(t *testing.T) {
	route := func(row vmap) any {
		return vmap{
			{"cpvs", []any{}},
			{"ladders", []any{}},
			{"knee", vmap{
				{"cost_basis", "usd"},
				{"rows", []any{row}},
				{"v_default", 1.0},
			}},
		}
	}
	base := vmap{{"n", uint64(1)}, {"c_n", 0.5}}
	with := func(p any) vmap { return append(append(vmap{}, base...), pair{"p_lcb", p}) }

	r, rej := decodeRoute(route(base))
	if rej != nil {
		t.Fatalf("row without p_lcb must decode: %v", rej)
	}
	if r.Knee.Rows[0].PLCB != nil {
		t.Fatal("absent p_lcb must map to nil, never 0.0")
	}
	for _, want := range []float64{0.0, 0.8, 1.0} {
		r, rej := decodeRoute(route(with(want)))
		if rej != nil {
			t.Fatalf("p_lcb %v must decode: %v", want, rej)
		}
		if r.Knee.Rows[0].PLCB == nil || *r.Knee.Rows[0].PLCB != want {
			t.Fatalf("p_lcb %v: got %v", want, r.Knee.Rows[0].PLCB)
		}
	}
	for _, bad := range []any{1.5, -0.1, math.NaN(), math.Inf(1), uint64(1)} {
		if _, rej := decodeRoute(route(with(bad))); rej == nil || rej.Kind() != "schema" {
			t.Fatalf("p_lcb %v must be a schema reject, got %v", bad, rej)
		}
	}
}

// TestEpsilonNeedsSignedOptInWhenKeyPresent — D-EF: ε>0 under a signed opt_in:false is M1E-3001; absent is the pre-ruling grammar the frozen `full` needs until the re-freeze (vector owed).
func TestEpsilonNeedsSignedOptInWhenKeyPresent(t *testing.T) {
	route := func(eps float64, optIn ...any) any {
		m := vmap{
			{"cpvs", []any{}},
			{"ladders", []any{}},
			{"knee", vmap{{"cost_basis", "usd"}, {"rows", []any{vmap{{"n", uint64(1)}, {"c_n", 0.5}}}}, {"v_default", 1.0}}},
			{"exploration", vmap{{"epsilon", eps}}},
		}
		for _, o := range optIn {
			m = append(m, pair{"exploration_opt_in", o})
		}
		return m
	}
	if _, rej := decodeRoute(route(0.05, false)); rej == nil || rej.Kind() != "schema" {
		t.Fatalf("ε 0.05 with opt_in false must be a schema reject, got %v", rej)
	}
	if _, rej := decodeRoute(route(0.05, uint64(1))); rej == nil || rej.Kind() != "schema" {
		t.Fatalf("non-bool opt_in must be a schema reject, got %v", rej)
	}
	for _, tc := range []struct {
		v    any
		want float64
	}{{route(0.05, true), 0.05}, {route(0.0, false), 0.0}, {route(0.05), 0.05}} {
		r, rej := decodeRoute(tc.v)
		if rej != nil || r.ExplorationEpsilon != tc.want {
			t.Fatalf("%v: got %v %v, want ε %v", tc.v, r.ExplorationEpsilon, rej, tc.want)
		}
	}
}

// TestLearnedRankerIsOptionalClosedEnumAndBounded — 07's cortex-section
// `? learned_ranker`: absent is nil (PPR order), the stage is a closed enum,
// weight is [0,1], every float is finite, and each miss is M1E-3001/schema.
func TestLearnedRankerIsOptionalClosedEnumAndBounded(t *testing.T) {
	cortex := func(ranker ...any) any {
		m := vmap{
			{"map_budget_tokens", vmap{{"min", uint64(1)}, {"max", uint64(2)}}},
			{"channels", []any{"session_start"}},
		}
		for _, r := range ranker {
			m = append(m, pair{"learned_ranker", r})
		}
		return m
	}
	four := []any{0.5, 0.25, -0.1, 0.0}
	ranker := func(stage string, weight, bias float64, coef []any) vmap {
		return vmap{{"stage", stage}, {"weight", weight}, {"bias", bias}, {"coefficients", coef}}
	}
	c, rej := decodeCortex(cortex())
	if rej != nil || c.LearnedRanker != nil {
		t.Fatalf("absent must decode to nil: %+v %v", c.LearnedRanker, rej)
	}
	c, rej = decodeCortex(cortex(ranker("shadow", 0.5, 0.1, four)))
	if rej != nil {
		t.Fatalf("valid ranker must decode: %v", rej)
	}
	want := &LearnedRanker{Stage: RankerShadow, Weight: 0.5, Bias: 0.1, Coefficients: [4]float64{0.5, 0.25, -0.1, 0.0}}
	if *c.LearnedRanker != *want {
		t.Fatalf("got %+v, want %+v", *c.LearnedRanker, *want)
	}
	for _, ok := range []vmap{ranker("probation", 1.0, 0.0, four), ranker("active", 0.0, 0.0, four)} {
		if _, rej := decodeCortex(cortex(ok)); rej != nil {
			t.Fatalf("%v must decode: %v", ok, rej)
		}
	}
	for i, bad := range []any{
		ranker("canary", 0.5, 0.0, four),
		ranker("shadow", 1.5, 0.0, four),
		ranker("shadow", -0.1, 0.0, four),
		ranker("shadow", math.NaN(), 0.0, four),
		ranker("shadow", 0.5, math.Inf(1), four),
		ranker("shadow", 0.5, 0.0, []any{0.0, 0.0, math.NaN(), 0.0}),
		ranker("shadow", 0.5, 0.0, []any{0.0, 0.0, 0.0}),
		ranker("shadow", 0.5, 0.0, []any{0.0, 0.0, 0.0, 0.0, 0.0}),
		vmap{{"stage", "shadow"}},
		append(ranker("shadow", 0.5, 0.0, four), pair{"model", "x"}),
		vmap{{"stage", "shadow"}, {"weight", uint64(1)}, {"bias", 0.0}, {"coefficients", four}},
	} {
		if _, rej := decodeCortex(cortex(bad)); rej == nil || rej.Kind() != "schema" {
			t.Fatalf("bad ranker #%d must be a schema reject, got %v", i, rej)
		}
	}
}

// TestBignumTagsAreNonCanonical pins the cross-language reject TAXONOMY, not
// just the accept/reject decision: ciborium normalizes tags 2/3 into an
// integer, so the Rust twin's re-encode compare calls them non_canonical. A
// vtag round-trips verbatim, so Go used to let them through canon and reject
// them later as schema — same answer, different classification, which is not
// actually a cross-language taxonomy. Tag 1 (issued_at) must still pass.
func TestBignumTagsAreNonCanonical(t *testing.T) {
	for _, raw := range [][]byte{{0xc2, 0x42, 0x01, 0x00}, {0xc3, 0x42, 0x01, 0x00}} {
		_, rej := VerifyAndDecode(raw, NewSectionKeys(), nil, nil)
		if rej == nil || rej.Code() != "M1E-3001" || rej.Kind() != "non_canonical" {
			t.Fatalf("bignum tag %#x: got %v, want M1E-3001/non_canonical", raw[0], rej)
		}
	}
	if _, err := decodeCanonical([]byte{0xc1, 0x1a, 0x6a, 0x8b, 0xd0, 0x00}); err != nil {
		t.Fatalf("tag 1 is the bundle's own issued_at: %v", err)
	}
}
