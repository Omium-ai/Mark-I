package querychoke

// The 06 §8.5 guarantee rule end to end on GET /api/v1/reports/tvo: coverage
// at or above D23 AND the tenant's m1_075 regime set AND (usd) its model
// pinned in the price table / (quota) S confirmed by the row. One positive
// control per basis, one negative per condition, and the price-table
// copy locked byte-for-byte to intel's.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// coveredDay is one shed-free, fully covered rollup day: band 0.98 ≥ 0.95, TVO 300/3.
func coveredDay() *fakeRunner {
	return &fakeRunner{
		rows: &Rows{Rows: []map[string]any{{
			"day": time.Now().UTC(), "task_seg_version": "task_seg.v1",
			"tokens_total": uint64(300), "tasks_verified": uint64(3), "tasks_unresolved": uint64(0),
			"retry_loop_tokens": uint64(10), "reexploration_tokens": uint64(20), "over_model_tokens": uint64(30),
			"observed_ms": uint64(980), "bypass_ms": uint64(20), "disabled_ms": uint64(0), "dropped_billing": uint64(0),
		}}},
		byTemplate: map[string]*Rows{"dropped_by_tenant_day": {Rows: []map[string]any{{
			"dropped_billing": uint64(0), "events_billing_ingested": uint64(100),
		}}}},
	}
}

func report(t *testing.T, mux *http.ServeMux, bearer, query string) map[string]any {
	t.Helper()
	w := do(mux, "GET", "/api/v1/reports/tvo?window=1d"+query, bearer, "")
	if w.Code != http.StatusOK {
		t.Fatalf("report %q: %d %s", query, w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body
}

func TestTVOReportGuaranteeGradeFromRegime(t *testing.T) {
	regimes := &fakeRegimes{rows: map[uuid.UUID]*Regime{}}
	run := coveredDay()
	_, mux, tenant, bearer := newTestModule(t, run, false, regimes)

	// Positive control, usd: regime pinned to a table row ⇒ guarantee-grade, the table digest stamped.
	regimes.rows[tenant] = &Regime{CostBasis: "usd", PriceModelID: "claude-sonnet-5"}
	body := report(t, mux, bearer, "&cost_basis=auto")
	if body["guarantee_grade"] != true || body["cost_basis"] != "usd" || body["price_table_version"] != modelPrices.version {
		t.Fatalf("usd positive control: %v", body)
	}
	if _, ok := body["refusal"]; ok {
		t.Fatalf("guarantee-grade report carries a refusal: %v", body)
	}
	if !strings.HasPrefix(body["price_table_version"].(string), "model_prices.v1@sha256:") {
		t.Fatalf("price_table_version: %v", body["price_table_version"])
	}
	// The guarantee-grade body, minus the dated trend, IS testdata/tvo_report_guarantee_body.json — the
	// fixture go/mark1's report tests serve, so the CLI renders exactly what this handler emits.
	delete(body, "trend")
	raw, err := os.ReadFile(filepath.Join("testdata", "tvo_report_guarantee_body.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture map[string]any
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(body)
	want, _ := json.Marshal(fixture)
	if string(got) != string(want) {
		t.Fatalf("guarantee-grade body drifted from the CLI fixture:\n got %s\nwant %s", got, want)
	}

	// Negative: the regime's model is not pinned — absent from the table, or a row a vendor publishes no price for.
	for _, model := range []string{"claude-mythos-5", "gemini-2.5-flash", ""} {
		regimes.rows[tenant] = &Regime{CostBasis: "usd", PriceModelID: model}
		body = report(t, mux, bearer, "")
		if body["guarantee_grade"] != false || body["refusal"] != "cost basis unresolved: no pinned model_prices row for usd (06 §8.4)" {
			t.Fatalf("unpinned model %q: %v", model, body)
		}
		if _, ok := body["price_table_version"]; ok {
			t.Fatalf("unpinned model %q stamped a price table: %v", model, body)
		}
	}

	// Negative: coverage below the floor with a resolved basis — the floor refusal alone, stated first.
	regimes.rows[tenant] = &Regime{CostBasis: "usd", PriceModelID: "claude-sonnet-5"}
	run.byTemplate["dropped_by_tenant_day"] = &Rows{Rows: []map[string]any{{
		"dropped_billing": uint64(100), "events_billing_ingested": uint64(100),
	}}}
	body = report(t, mux, bearer, "")
	if body["guarantee_grade"] != false || body["refusal"] != "M1E-5004 coverage below floor: coverage_lower=0.4900 < 0.95" {
		t.Fatalf("below floor with a pinned regime: %v", body)
	}
	if body["price_table_version"] != modelPrices.version {
		t.Fatalf("an indicative usd report still names the table it priced under: %v", body)
	}
	run.byTemplate["dropped_by_tenant_day"] = coveredDay().byTemplate["dropped_by_tenant_day"]

	// Positive control, quota: the row IS the confirmation of S (D22); auto resolves to quota; no price pin is claimed.
	regimes.rows[tenant] = &Regime{CostBasis: "quota"}
	body = report(t, mux, bearer, "&cost_basis=auto")
	if body["guarantee_grade"] != true || body["cost_basis"] != "quota" {
		t.Fatalf("quota positive control: %v", body)
	}
	if _, ok := body["price_table_version"]; ok {
		t.Fatalf("quota report claims a price pin: %v", body)
	}
	// Cross-basis asks are stamped as asked and refused (routes.py get_price_row / get_shadow_price).
	body = report(t, mux, bearer, "&cost_basis=usd")
	if body["guarantee_grade"] != false || body["cost_basis"] != "usd" || body["refusal"] != "cost basis unresolved: no pinned model_prices row for usd (06 §8.4)" {
		t.Fatalf("usd asked of a quota tenant: %v", body)
	}
	regimes.rows[tenant] = &Regime{CostBasis: "usd", PriceModelID: "claude-sonnet-5"}
	body = report(t, mux, bearer, "&cost_basis=quota")
	if body["guarantee_grade"] != false || body["cost_basis"] != "quota" || body["refusal"] != "cost basis unresolved: shadow price S unconfirmed by tenant (D22)" {
		t.Fatalf("quota asked of a usd tenant: %v", body)
	}

	// Negative: no regime row at all — auto resolves exactly as the bootstrap bundle does (quota, ADR-0013), unresolved.
	delete(regimes.rows, tenant)
	body = report(t, mux, bearer, "&cost_basis=auto")
	if body["guarantee_grade"] != false || body["cost_basis"] != Resolve(nil).CostBasis || body["cost_basis"] != "quota" || body["refusal"] != "cost basis unresolved: shadow price S unconfirmed by tenant (D22)" {
		t.Fatalf("no regime: %v", body)
	}

	// The regime read failing is a 500, never an indicative report dressed as a downgrade.
	regimes.err = errors.New("pg down")
	if w := do(mux, "GET", "/api/v1/reports/tvo?window=1d", bearer, ""); w.Code != http.StatusInternalServerError || errCode(t, w) != "M1E-9500" {
		t.Fatalf("regime lookup failure: %d %s", w.Code, w.Body.String())
	}
}

// The embedded copy is byte-identical to intel's table, and the version stamp is Python's `<version>@sha256:<file digest>` (app/pricing.load_table).
func TestModelPricesTableMatchesIntel(t *testing.T) {
	theirs, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "python", "intel", "app", "pricing", "model_prices.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(theirs) != string(modelPricesRaw) {
		t.Fatal("model_prices.v1.json drifted from python/intel/app/pricing/model_prices.v1.json — copy it over (the report stamps the digest of THESE bytes)")
	}
	sum := sha256.Sum256(theirs)
	if want := "model_prices.v1@sha256:" + hex.EncodeToString(sum[:]); modelPrices.version != want {
		t.Fatalf("version %q, want %q", modelPrices.version, want)
	}
	if !modelPrices.pinned["claude-sonnet-5"] || modelPrices.pinned["gemini-2.5-flash"] || modelPrices.pinned["claude-mythos-5"] {
		t.Fatalf("pinned set: %v", modelPrices.pinned)
	}
	for _, bad := range []string{
		`{"rows": []}`,
		`{"version": "v", "rows": [{"model_id": ""}]}`,
		`{"version": "v", "rows": [{"model_id": "m", "input": 1, "output": 1, "cache_write": 1, "cache_read": 1}, {"model_id": "m"}]}`,
		`not json`,
	} {
		if _, err := loadPriceTable([]byte(bad)); err == nil {
			t.Errorf("loadPriceTable accepted %s", bad)
		}
	}
}

// CostBasis (chproj's stamp source) refuses a nil tenant before any read, exactly as FromClaims does.
func TestCostBasisRefusesNilTenantBeforeReading(t *testing.T) {
	if _, err := (PGRegimes{}).CostBasis(context.Background(), uuid.Nil); !errors.Is(err, ErrNoTenant) {
		t.Fatalf("nil tenant: %v", err)
	}
}
