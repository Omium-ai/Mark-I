// TestConfVectorsTVOBandGolden — the Go half of the cross-language coverage
// band lock. testdata/tvo_band_golden.json is read by BOTH this test and
// python/intel/tests/test_conf_vectors_tvo_band.py (one fixture, two
// asserters — the wave-5 lesson: stub-tested halves drift). The `ConfVectors`
// name prefix is load-bearing: tools/ci/conformance_crosslang.sh runs
// `go test -run ConfVectors` in go/controld, so this lock rides the same
// gate as the wire vectors.

package querychoke

import (
	"encoding/json"
	"math"
	"os"
	"testing"
)

type bandGoldenCase struct {
	Name                  string `json:"name"`
	ObservedMS            uint64 `json:"observed_ms"`
	BypassMS              uint64 `json:"bypass_ms"`
	DisabledMS            uint64 `json:"disabled_ms"`
	DroppedBilling        uint64 `json:"dropped_billing"`
	EventsBillingIngested uint64 `json:"events_billing_ingested"`
	Verified              uint64 `json:"verified"`
	// Certified defaults to Verified: every older case has certified outcomes; a case that sets it to 0 locks the bootstrapping refusal.
	Certified *uint64 `json:"certified"`
	CostBasis             string `json:"cost_basis"`
	PricePinned           bool   `json:"price_pinned"`
	ShadowPriceConfirmed  bool   `json:"shadow_price_confirmed"`
	Expect                struct {
		Coverage       float64  `json:"coverage"`
		CoverageLower  float64  `json:"coverage_lower"`
		GuaranteeGrade bool     `json:"guarantee_grade"`
		Refusals       []string `json:"refusals"`
	} `json:"expect"`
}

func TestConfVectorsTVOBandGolden(t *testing.T) {
	raw, err := os.ReadFile("testdata/tvo_band_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Floor float64          `json:"floor"`
		Cases []bandGoldenCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Floor != coverageFloor {
		t.Fatalf("fixture floor %v != coverageFloor %v — D23 (06 §8.5) drifted", fixture.Floor, coverageFloor)
	}
	if len(fixture.Cases) == 0 {
		t.Fatal("zero golden cases — an empty lock locks nothing")
	}
	for _, c := range fixture.Cases {
		t.Run(c.Name, func(t *testing.T) {
			coverage, lower := coverageBand(
				c.ObservedMS, c.BypassMS, c.DisabledMS, c.DroppedBilling, c.EventsBillingIngested)
			if math.Abs(coverage-c.Expect.Coverage) > 1e-12 {
				t.Fatalf("coverage %v, want %v", coverage, c.Expect.Coverage)
			}
			if math.Abs(lower-c.Expect.CoverageLower) > 1e-12 {
				t.Fatalf("coverage_lower %v, want %v", lower, c.Expect.CoverageLower)
			}
			certified := c.Verified
			if c.Certified != nil {
				certified = *c.Certified
			}
			refusals := guaranteeRefusals(lower, c.Verified, certified, c.CostBasis, c.PricePinned, c.ShadowPriceConfirmed)
			if (len(refusals) == 0) != c.Expect.GuaranteeGrade {
				t.Fatalf("guarantee_grade %v, want %v (refusals %q)",
					len(refusals) == 0, c.Expect.GuaranteeGrade, refusals)
			}
			if len(refusals) != len(c.Expect.Refusals) {
				t.Fatalf("refusals %q, want %q", refusals, c.Expect.Refusals)
			}
			// Byte-for-byte AND in report.py's order: the joined wire field
			// (refusal reasons "; "-joined) must match across languages.
			for i := range refusals {
				if refusals[i] != c.Expect.Refusals[i] {
					t.Fatalf("refusal[%d] = %q, want %q", i, refusals[i], c.Expect.Refusals[i])
				}
			}
		})
	}
}
