// TestConfVectorsCoverage drives conformance/vectors/coverage/manifest.json —
// NFR-OPERABILITY-001's second half (the family README is normative): what a
// batch's Dropped[] rows do to the coverage band. Each case's rows are
// decoded with protojson into m1pv1.Dropped (a name the wire does not carry
// is a red), folded to dropped_billing on the LOSS's durability class — the
// dropped_by_tenant_day / mv_tvo_session predicate restated in Go — and the
// FOLDED value, never the expectation, is fed to the production band code
// (coverageBand, module.go). The `ConfVectorsCoverage` prefix is
// load-bearing: tools/ci/conformance_crosslang.sh requires this family's Go
// twin by that token. The store-backed leg, where the fold is the REAL SQL
// predicate, is TestConfVectorsCoverageStore
// (conf_vectors_coverage_integration_test.go).

package querychoke

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

const coverageVectorsDir = "../../../../conformance/vectors/coverage"

type coverageCase struct {
	Name    string            `json:"name"`
	Dropped []json.RawMessage `json:"dropped"` // wire-shaped Batch.dropped rows, decoded by protojson below
	Rollup  struct {
		ObservedMS            uint64 `json:"observed_ms"`
		BypassMS              uint64 `json:"bypass_ms"`
		DisabledMS            uint64 `json:"disabled_ms"`
		EventsBillingIngested uint64 `json:"events_billing_ingested"`
	} `json:"rollup"`
	Expect struct {
		DroppedBilling uint64  `json:"dropped_billing"`
		Coverage       float64 `json:"coverage"`
		CoverageLower  float64 `json:"coverage_lower"`
	} `json:"expect"`
}

type coverageManifest struct {
	Tolerance float64        `json:"tolerance"`
	Cases     []coverageCase `json:"cases"`
}

// loadCoverageManifest reads the frozen contract. Anti-vacuity: the family
// froze five cases, and at least one must carry billing-grade loss — a
// truncated manifest of diagnostic-only rows would pass the fold assertion
// with a predicate that always returns zero.
func loadCoverageManifest(t *testing.T) *coverageManifest {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(coverageVectorsDir, "manifest.json"))
	if err != nil {
		t.Fatalf("reading manifest: %v", err)
	}
	var m coverageManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("parsing manifest: %v", err)
	}
	if len(m.Cases) < 5 {
		t.Fatalf("manifest has %d cases, the family froze 5", len(m.Cases))
	}
	if m.Tolerance <= 0 {
		t.Fatalf("manifest tolerance %v — an absent tolerance is not a stricter one", m.Tolerance)
	}
	anyBilling := false
	for _, c := range m.Cases {
		anyBilling = anyBilling || foldDroppedBilling(decodeDropped(t, c.Dropped)) > 0
	}
	if !anyBilling {
		t.Fatal("no case folds to a non-zero dropped_billing — the predicate would pass vacuously")
	}
	return &m
}

// decodeDropped is the wire decode: proto field names and enum NAMES, so a
// row naming a reason or class the generated code does not know fails here.
func decodeDropped(t *testing.T, rows []json.RawMessage) []*m1pv1.Dropped {
	t.Helper()
	out := make([]*m1pv1.Dropped, 0, len(rows))
	for i, raw := range rows {
		d := &m1pv1.Dropped{}
		if err := protojson.Unmarshal(raw, d); err != nil {
			t.Fatalf("dropped[%d]: %v", i, err)
		}
		out = append(out, d)
	}
	return out
}

// foldDroppedBilling is dropped_by_tenant_day's
//
//	sumIf(dropped_quantity, event_type = 'Dropped' AND dropped_durability_class = 'billing_grade')
//
// (templates.go; m1_ch_002 mv_tvo_session) on the wire rows: the LOSS's
// durability class, never the reason, never the Dropped row's own event_class.
func foldDroppedBilling(rows []*m1pv1.Dropped) uint64 {
	var q uint64
	for _, d := range rows {
		if d.GetDurabilityClass() == m1pv1.DurabilityClass_DURABILITY_CLASS_BILLING_GRADE {
			q += d.GetQuantity()
		}
	}
	return q
}

func TestConfVectorsCoverage(t *testing.T) {
	m := loadCoverageManifest(t)
	for _, c := range m.Cases {
		t.Run(c.Name, func(t *testing.T) {
			fold := foldDroppedBilling(decodeDropped(t, c.Dropped))
			if fold != c.Expect.DroppedBilling {
				t.Fatalf("dropped_billing fold = %d, want %d", fold, c.Expect.DroppedBilling)
			}
			coverage, lower := coverageBand(
				c.Rollup.ObservedMS, c.Rollup.BypassMS, c.Rollup.DisabledMS, fold, c.Rollup.EventsBillingIngested)
			if math.Abs(coverage-c.Expect.Coverage) > m.Tolerance {
				t.Fatalf("coverage = %v, want %v", coverage, c.Expect.Coverage)
			}
			if math.Abs(lower-c.Expect.CoverageLower) > m.Tolerance {
				t.Fatalf("coverage_lower = %v, want %v", lower, c.Expect.CoverageLower)
			}
		})
	}
}
