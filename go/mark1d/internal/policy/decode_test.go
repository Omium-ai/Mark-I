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
