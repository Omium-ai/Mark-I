// module.go — the 08 §3.3 report/query surface plus the INTERNAL rollup
// write seam. Reads: tenancy is stamped from the verified token by the
// shared middleware; handlers convert Claims → TenantID → Build — a tenant
// identifier in a path, query or body is never read, so there is nothing to
// disagree with (08 §3: "a tenant identifier in a path or body is never
// trusted").
//
// The rollup write route (ADR-0010, signed 2026-09-16) executes only under
// the intel service credential; with RollupWriteEnabled off (no credential
// configured, or QUERYCHOKE_ROLLUP_WRITE=0) it answers 403, so a driver
// pointed at a dark surface fails loudly, not silently.
package querychoke

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/server"
)

// coverageFloor is D23, the guarantee-grade floor (06 §8.5, NORMATIVE — not
// 08 §3.3's 0.85 illustration): issuance is refused when the SHED-NARROWED
// lower edge `coverage_lower` is below 0.95. Same number, same edge, same
// arithmetic as python/intel/app/tvo/coverage.py (COVERAGE_FLOOR) — the
// cross-language golden fixture testdata/tvo_band_golden.json locks the two.
// A report below it still renders — the GUARANTEE is refused, not the number
// (M1E-5004, refusal-by-design).
const coverageFloor = 0.95

type Deps struct {
	Registry *Registry
	Runner   Runner
	Verifier auth.Verifier
	ObsCfg   obs.Config
	// RollupWriteEnabled gates the internal write route (see WHY header).
	RollupWriteEnabled bool
	// IntelServiceToken is the service credential the intel driver presents
	// (the ADR-0010 §2.2 seam). Empty ⇒ the write surface verifies nothing
	// and is therefore absent, never open.
	IntelServiceToken string
	// Regimes resolves the tenant's m1_075 row (06 §8.4); nil ⇒ every basis stays unresolved and reports issue indicative.
	Regimes RegimeSource
}

type Module struct {
	reg    *Registry
	runner Runner
	deps   Deps
}

func New(d Deps) *Module {
	return &Module{reg: d.Registry, runner: d.Runner, deps: d}
}

func (m *Module) Name() string { return "querychoke" }

// Ready: the choke is ready iff its Runner's store answers (05 §1.4). A
// Runner without a readiness probe (test fakes, a future HTTP Runner that
// probes elsewhere) contributes nothing.
func (m *Module) Ready(ctx context.Context) error {
	if p, ok := m.runner.(interface{ Ready(context.Context) error }); ok {
		return p.Ready(ctx)
	}
	return nil
}

func (m *Module) RegisterRoutes(mux *http.ServeMux) {
	// ponytail: 08 §3.3 says "auth: operator token"; the shared Verifier
	// admits device tokens too (the receipts-module precedent for §3.4's
	// device-or-operator surface). Tenancy isolation is unaffected — a
	// device token reads only its own tenant — but a device reading
	// tenant-wide reports is wider than 08 licenses; the ceiling lifts when
	// the substrate grows a role claim to key M1E-1001 off.
	chain := server.Chain(m.deps.Verifier, m.deps.ObsCfg, nil)
	mux.Handle("GET /api/v1/reports/tvo", chain(http.HandlerFunc(m.handleTVOReport)))
	mux.Handle("GET /api/v1/reports/interventions", chain(http.HandlerFunc(m.handleInterventions)))
	mux.Handle("POST /api/v1/query", chain(http.HandlerFunc(m.handleQuery)))
	// INTERNAL — service-credential authenticated, never token-authenticated:
	// the caller is mark1-intel's driver, not a tenant (ADR-0010 §2.2). obs
	// still meters it; the auth chain does not apply.
	mux.Handle("POST /internal/v1/rollup/tvo_tenant_day",
		m.deps.ObsCfg.HTTPMiddleware(nil)(http.HandlerFunc(m.handleRollupWrite)))
	// The driver's READ half of the same seam: its ledger reads (tvo_task_window, coverage inputs, memory_certified_sessions, …) name the tenant in the body under the service credential; /api/v1/query would answer them M1E-1002, it only knows tokens (prod 2026-09-19: every hourly rollup 401ed).
	mux.Handle("POST /internal/v1/query",
		m.deps.ObsCfg.HTTPMiddleware(nil)(http.HandlerFunc(m.handleServiceQuery)))
}

// serviceTenant verifies the intel driver's bearer and resolves the tenant the request names (FromServiceJob); false means the refusal was written.
func (m *Module) serviceTenant(w http.ResponseWriter, r *http.Request, tenantID string) (TenantID, bool) {
	bearer := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(bearer) <= len(prefix) || bearer[:len(prefix)] != prefix {
		writeErr(w, http.StatusForbidden, "M1E-1001", "service credential required")
		return TenantID{}, false
	}
	cred, err := VerifyServiceCredential(m.deps.IntelServiceToken, bearer[len(prefix):])
	if err != nil {
		writeErr(w, http.StatusForbidden, "M1E-1001", "service credential rejected")
		return TenantID{}, false
	}
	tenant, err := uuid.Parse(tenantID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "M1E-2001", "tenant_id: not a UUID")
		return TenantID{}, false
	}
	tid, err := FromServiceJob(cred, tenant)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "M1E-2001", err.Error())
		return TenantID{}, false
	}
	return tid, true
}

// handleServiceQuery is handleQuery for the intel driver: the same closed registry, the same write refusal, the tenant from the body instead of the token.
func (m *Module) handleServiceQuery(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TenantID string `json:"tenant_id"`
		Template string `json:"template"`
		Params   Params `json:"params"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.UseNumber()
	if err := dec.Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "M1E-2001", "malformed query request")
		return
	}
	tid, ok := m.serviceTenant(w, r, req.TenantID)
	if !ok {
		return
	}
	tpl, err := m.reg.Lookup(req.Template)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "M1E-2008",
			fmt.Sprintf("unknown query template %q — the chokepoint refuses, it does not improvise", req.Template))
		return
	}
	if tpl.IsWrite() {
		writeErr(w, http.StatusForbidden, "M1E-1001", "write-shaped templates are not executable on this surface")
		return
	}
	q, err := Build(tid, tpl, req.Params)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "M1E-2001", err.Error())
		return
	}
	rows, ok := m.run(w, r, q)
	if !ok {
		return
	}
	out := rows.Rows
	if out == nil {
		out = []map[string]any{}
	}
	writeJSON(w, map[string]any{"rows": out, "template_version": tpl.Version()})
}

// ---------------------------------------------------------------------------
// Shared plumbing
// ---------------------------------------------------------------------------

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"code": code, "message": msg},
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// tenantFrom converts the middleware's verified stamp into the TenantID the
// builder requires. ok=false means the middleware did not run — a wiring
// bug, answered as a server error, never as an anonymous pass.
func tenantFrom(w http.ResponseWriter, r *http.Request) (TenantID, bool) {
	claims, ok := auth.ClaimsFrom(r.Context())
	if !ok {
		writeErr(w, http.StatusInternalServerError, "M1E-9500", "auth middleware missing")
		return TenantID{}, false
	}
	tid, err := FromClaims(claims)
	if err != nil {
		writeErr(w, http.StatusForbidden, "M1E-1001", "token carries no tenant")
		return TenantID{}, false
	}
	return tid, true
}

var windowRe = regexp.MustCompile(`^([0-9]{1,3})d$`)

// parseWindow maps 08 §3.3's ?window=30d onto a closed [from,to] date range
// ending today (UTC). Bad window ⇒ 400 M1E-2001.
func parseWindow(raw string) (from, to time.Time, err error) {
	if raw == "" {
		raw = "30d"
	}
	match := windowRe.FindStringSubmatch(raw)
	if match == nil {
		return time.Time{}, time.Time{}, fmt.Errorf("window %q: want <days>d", raw)
	}
	n, _ := strconv.Atoi(match[1])
	if n < 1 || n > 365 {
		return time.Time{}, time.Time{}, fmt.Errorf("window %q outside 1d..365d", raw)
	}
	to = time.Now().UTC().Truncate(24 * time.Hour)
	from = to.AddDate(0, 0, -(n - 1))
	return from, to, nil
}

// run executes and maps the shared failure shapes.
func (m *Module) run(w http.ResponseWriter, r *http.Request, q Query) (*Rows, bool) {
	rows, err := m.runner.Run(r.Context(), q)
	if err != nil {
		if errors.Is(err, ErrBusy) {
			writeErr(w, http.StatusServiceUnavailable, "M1E-9500", "query concurrency limit; retry")
			return nil, false
		}
		slog.Error("querychoke: query failed", "template", q.tpl.name, "err", err)
		writeErr(w, http.StatusInternalServerError, "M1E-9500", "query execution failed")
		return nil, false
	}
	if rows == nil {
		rows = &Rows{}
	}
	return rows, true
}

// ---------------------------------------------------------------------------
// GET /api/v1/reports/tvo (08 §3.3)
// ---------------------------------------------------------------------------

func (m *Module) handleTVOReport(w http.ResponseWriter, r *http.Request) {
	tid, ok := tenantFrom(w, r)
	if !ok {
		return
	}
	from, to, err := parseWindow(r.URL.Query().Get("window"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "M1E-2001", err.Error())
		return
	}
	// ponytail: v1 accepts only cohort=all; the auto cohort split arrives
	// with quota-basis events.
	if c := r.URL.Query().Get("cohort"); c != "" && c != "all" {
		writeErr(w, http.StatusBadRequest, "M1E-2001", "cohort: only \"all\" is supported")
		return
	}
	// 08 §3.3 / 06 §8.4: `auto` is the tenant's m1_075 basis (v1 has one cohort per tenant); an explicit basis the regime does not carry is stamped as asked and issues indicative, as routes.py does.
	requestedBasis := r.URL.Query().Get("cost_basis")
	switch requestedBasis {
	case "", "auto", costBasisUSD, costBasisQuota:
	default:
		writeErr(w, http.StatusBadRequest, "M1E-2001", "cost_basis: want auto|usd|quota")
		return
	}
	reg, err := loadRegime(r.Context(), m.deps.Regimes, tid)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "M1E-9500", "tenant regime lookup failed")
		return
	}
	costBasis := requestedBasis
	if costBasis == "" || costBasis == "auto" {
		costBasis = costBasisUSD
		if reg != nil {
			costBasis = reg.CostBasis
		}
	}
	pricePinned := reg != nil && reg.CostBasis == costBasisUSD && modelPrices.pinned[reg.PriceModelID]
	shadowConfirmed := reg != nil && reg.CostBasis == costBasisQuota

	tpl, err := m.reg.Lookup("tvo_report")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "M1E-9500", "registry miswired")
		return
	}
	q, err := Build(tid, tpl, Params{"from": from, "to": to})
	if err != nil {
		writeErr(w, http.StatusBadRequest, "M1E-2001", err.Error())
		return
	}
	rows, ok := m.run(w, r, q)
	if !ok {
		return
	}

	// Fold the (day, series) rows into the report. The template returns one
	// row per (day, task_seg_version series) EXACTLY SO restated days are
	// never blended — and ADR-0010 §6 (RECONCILIATION.md D-F / thirteenth
	// pass) makes a restatement a NEW series that SUPERSEDES the original
	// row, so summing across series would double-count every restated day.
	// Per day exactly ONE row survives: the max task_seg_version — the
	// template exposes no insertion marker, so lexicographic max is the
	// deterministic rule, the same '' < 'task_seg.v1' ordering the
	// migration's own max() trick relies on (m1_ch_002), extended to
	// 'task_seg.v1' < 'task_seg.v1-restated.N'.
	// ponytail: an ADR-0010-noted mid-day version CUTOVER also folds to its
	// newest series here (the two halves are distinguishable from a
	// restatement only by parsing the label, which ADR-0010 §Consequences
	// forbids); the report's certified path already refuses an unshown
	// boundary (06 §8.5), and both series stay readable via POST /query.
	// Days with no rollup row refuse guarantee grade (ADR-0010 §2.7: the
	// batch plane's failure is labeled indicative, never coverage-laundered).
	newest := map[string]map[string]any{}
	for _, row := range rows.Rows {
		day := asDay(row["day"])
		cur, seen := newest[day]
		if !seen || asStr(row["task_seg_version"]) > asStr(cur["task_seg_version"]) {
			newest[day] = row
		}
	}
	var (
		tokensTotal, verified               uint64
		retryLoop, reexploration, overModel uint64
		observed, bypass, disabled          uint64
		segVersion                          string
		daysSeen                            = map[string]bool{}
		perDayTokens                        = map[string]uint64{}
		perDayVerified                      = map[string]uint64{}
	)
	for day, row := range newest {
		daysSeen[day] = true
		tokensTotal += asU64(row["tokens_total"])
		verified += asU64(row["tasks_verified"])
		retryLoop += asU64(row["retry_loop_tokens"])
		reexploration += asU64(row["reexploration_tokens"])
		overModel += asU64(row["over_model_tokens"])
		observed += asU64(row["observed_ms"])
		bypass += asU64(row["bypass_ms"])
		disabled += asU64(row["disabled_ms"])
		perDayTokens[day] = asU64(row["tokens_total"])
		perDayVerified[day] = asU64(row["tasks_verified"])
		if s := asStr(row["task_seg_version"]); s > segVersion {
			segVersion = s
		}
	}

	// Shed accounting (06 §8.2, formula normative in 07): the band's lower
	// edge needs dropped_billing + events_billing_ingested, which live on the
	// loss ledger, not the rollup row — the same `dropped_by_tenant_day` read
	// intel's coverage_inputs() performs (reader.py), so both surfaces narrow
	// from the same numbers. Read first: its per-day billing counts also say
	// which days had anything to roll up.
	var droppedBilling, billingIngested uint64
	billingByDay := map[string]uint64{}
	if shedTpl, err := m.reg.Lookup("dropped_by_tenant_day"); err != nil {
		writeErr(w, http.StatusInternalServerError, "M1E-9500", "registry miswired")
		return
	} else if shedQ, err := Build(tid, shedTpl, Params{"from": from, "to": to}); err != nil {
		writeErr(w, http.StatusBadRequest, "M1E-2001", err.Error())
		return
	} else if shedRows, ok := m.run(w, r, shedQ); !ok {
		return
	} else {
		for _, row := range shedRows.Rows {
			droppedBilling += asU64(row["dropped_billing"])
			billingIngested += asU64(row["events_billing_ingested"])
			billingByDay[asStr(row["day"])] += asU64(row["events_billing_ingested"])
		}
	}

	// A rollup is missing for a CLOSED day that had billing rows and no rollup row. Today never has one yet, a day before the tenant existed or a quiet weekend has nothing to roll up — counting those refused every report of every tenant by construction ("rollup missing for 1 day" on the day itself).
	var missingDays []string
	trend := []map[string]any{}
	today := time.Now().UTC().Format(time.DateOnly)
	for d := from; !d.After(to); d = d.AddDate(0, 0, 1) {
		day := d.Format(time.DateOnly)
		if !daysSeen[day] {
			if day < today && billingByDay[day] > 0 {
				missingDays = append(missingDays, day)
			}
			continue
		}
		trend = append(trend, map[string]any{
			"day": day,
			"tvo": ratio(float64(perDayTokens[day]), float64(perDayVerified[day])),
		})
	}
	covFraction, covLower := coverageBand(observed, bypass, disabled, droppedBilling, billingIngested)

	// certified outcomes: tasks whose stage-final verdict is certified and satisfied over the window — the guarantee-grade gate, read live (the rollup's tasks_verified counts by posterior mode so the number renders in bootstrap).
	var certified uint64
	if certTpl, err := m.reg.Lookup("certified_outcomes"); err != nil {
		writeErr(w, http.StatusInternalServerError, "M1E-9500", "registry miswired")
		return
	} else if certQ, err := Build(tid, certTpl, Params{"from": from, "to": to}); err != nil {
		writeErr(w, http.StatusBadRequest, "M1E-2001", err.Error())
		return
	} else if certRows, ok := m.run(w, r, certQ); !ok {
		return
	} else {
		for _, row := range certRows.Rows {
			certified += asU64(row["certified"])
		}
	}

	// tokens_saved: the verify plane's own decisions over the window (savings.v1), an ESTIMATE from the edge (policy.proto GuardDecision.tokens_saved_estimate); re-exploration and routing have no witness at v1 and say 0.
	var savedArrests, savedBlocks, nBlocks, nArrests uint64
	if savTpl, err := m.reg.Lookup("savings"); err != nil {
		writeErr(w, http.StatusInternalServerError, "M1E-9500", "registry miswired")
		return
	} else if savQ, err := Build(tid, savTpl, Params{"from": from, "to": to}); err != nil {
		writeErr(w, http.StatusBadRequest, "M1E-2001", err.Error())
		return
	} else if savRows, ok := m.run(w, r, savQ); !ok {
		return
	} else {
		for _, row := range savRows.Rows {
			switch asStr(row["reason"]) {
			case "knee_arrest":
				savedArrests, nArrests = asU64(row["tokens_saved"]), asU64(row["decisions"])
			case "stop_gate_block":
				savedBlocks, nBlocks = asU64(row["tokens_saved"]), asU64(row["decisions"])
			}
		}
	}

	// Every refusal is STATED, none silently absorbed (06 §8.5; report.py's
	// assemble_report is the reference implementation). A missing rollup day
	// leads the list: the band below it was computed over the rows that ARE
	// present, so it understates nothing but proves nothing about the hole
	// (ADR-0010 §2.7 — the batch plane's failure is labeled, never
	// coverage-laundered).
	var refusals []string
	if len(missingDays) > 0 {
		refusals = append(refusals, fmt.Sprintf("M1E-5004 rollup missing for %d day(s) in window", len(missingDays)))
	}
	refusals = append(refusals, guaranteeRefusals(covLower, verified, certified, costBasis, pricePinned, shadowConfirmed)...)

	resp := map[string]any{
		"tvo":   ratio(float64(tokensTotal), float64(verified)),
		"trend": trend,
		"coverage_band": map[string]any{
			"observed_fraction": covFraction,
			"coverage_lower":    covLower, // the edge D23 floors (06 §8.5)
			"floor":             coverageFloor,
		},
		"cost_basis":       costBasis,
		"task_seg_version": segVersion,
		"waste": map[string]any{
			"retry_loop_tokens":     retryLoop,
			"re_exploration_tokens": reexploration, // 08 §3.3 spelling
			"over_model_tokens":     overModel,
		},
		"guarantee_grade": len(refusals) == 0,
		"tokens_saved": map[string]any{
			"arrests": savedArrests, "blocks": savedBlocks, "re_exploration_avoided": uint64(0), "routing": uint64(0),
			"total": savedArrests + savedBlocks, "arrest_count": nArrests, "block_count": nBlocks, "estimate": true,
		},
	}
	if costBasis == costBasisUSD && pricePinned {
		resp["price_table_version"] = modelPrices.version // 08 §3.3: usd only, the table the figures were priced under
	}
	if len(missingDays) > 0 {
		resp["missing_days"] = missingDays
	}
	if len(refusals) > 0 {
		// report.py to_body(): one refusal field, reasons joined "; ".
		resp["refusal"] = strings.Join(refusals, "; ")
	}
	writeJSON(w, resp)
}

// coverageBand is coverage.py's coverage_band(), verbatim arithmetic (07
// normative; 06 §8.2): coverage = observed / (observed + bypass + disabled),
// lower edge narrowed by shed accounting
// coverage_lower = coverage × (1 − dropped / (dropped + ingested)).
// Zero surface time is zero coverage — deliberately no "assumed covered".
// Locked to the Python implementation by testdata/tvo_band_golden.json (one
// fixture, two asserters).
func coverageBand(observedMS, bypassMS, disabledMS, droppedBilling, eventsBillingIngested uint64) (coverage, coverageLower float64) {
	coverage = ratio(float64(observedMS), float64(observedMS+bypassMS+disabledMS))
	shed := ratio(float64(droppedBilling), float64(droppedBilling+eventsBillingIngested))
	return coverage, coverage * (1.0 - shed)
}

// guaranteeRefusals is report.py assemble_report's refusal set, restricted to
// the conditions this rollup-read surface can evaluate (06 §8.5, normative):
// the D23 floor on the shed-narrowed lower edge, the symmetric basis rule
// (06 §8.4: quota needs the tenant-confirmed S, D22; usd pins the price-table
// version it used — no pin, no guarantee), and zero verified outcomes
// (intel's engine refuses the whole window for this — routes.py maps it to
// M1E-2001; here the rollup rows still render, so only the guarantee is
// refused). Strings and order match report.py exactly — the golden fixture
// asserts them byte-for-byte.
func guaranteeRefusals(coverageLower float64, verified, certified uint64, costBasis string, pricePinned, shadowConfirmed bool) []string {
	var out []string
	if coverageLower < coverageFloor {
		out = append(out, fmt.Sprintf(
			"M1E-5004 coverage below floor: coverage_lower=%.4f < %v", coverageLower, coverageFloor))
	}
	// report.py's certification refusal, evaluated here from the ledger: verified outcomes count by posterior mode (the number renders), a guarantee needs at least one certified satisfied verdict in the window — none ⇒ the status is bootstrapping (06 §5.4).
	if certified == 0 {
		out = append(out, "noise certificate is 'bootstrapping', not 'certified'")
	}
	if costBasis == costBasisQuota && !shadowConfirmed {
		out = append(out, "cost basis unresolved: shadow price S unconfirmed by tenant (D22)")
	}
	if costBasis == costBasisUSD && !pricePinned {
		out = append(out, "cost basis unresolved: no pinned model_prices row for usd (06 §8.4)")
	}
	if verified == 0 {
		out = append(out, "zero verified outcomes in window, TVO denominator unmeasured")
	}
	return out
}

// ---------------------------------------------------------------------------
// GET /api/v1/reports/interventions (08 §3.3)
// ---------------------------------------------------------------------------

func (m *Module) handleInterventions(w http.ResponseWriter, r *http.Request) {
	tid, ok := tenantFrom(w, r)
	if !ok {
		return
	}
	from, to, err := parseWindow(r.URL.Query().Get("window"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "M1E-2001", err.Error())
		return
	}
	tpl, err := m.reg.Lookup("interventions")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "M1E-9500", "registry miswired")
		return
	}
	q, err := Build(tid, tpl, Params{"from": from, "to": to})
	if err != nil {
		writeErr(w, http.StatusBadRequest, "M1E-2001", err.Error())
		return
	}
	rows, ok := m.run(w, r, q)
	if !ok {
		return
	}
	arrests := []map[string]any{}
	for _, row := range rows.Rows {
		arrests = append(arrests, map[string]any{
			"task_id":               fmt.Sprint(row["task_id"]),
			"tokens_saved_estimate": asU64(row["tokens_saved_estimate"]),
			"verdict":               asStr(row["verdict"]),
			"bundle_seq":            asU64(row["bundle_seq"]),
		})
	}
	writeJSON(w, map[string]any{"knee_arrests": arrests})
}

// ---------------------------------------------------------------------------
// POST /api/v1/query (08 §3.3) — named templates only, no raw SQL
// ---------------------------------------------------------------------------

func (m *Module) handleQuery(w http.ResponseWriter, r *http.Request) {
	tid, ok := tenantFrom(w, r)
	if !ok {
		return
	}
	var req struct {
		Template string `json:"template"`
		Params   Params `json:"params"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.UseNumber()
	if err := dec.Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "M1E-2001", "malformed query request")
		return
	}
	tpl, err := m.reg.Lookup(req.Template)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "M1E-2008",
			fmt.Sprintf("unknown query template %q — the chokepoint refuses, it does not improvise", req.Template))
		return
	}
	if tpl.IsWrite() {
		// A write-shaped template on the tenant-facing surface: known, and
		// exactly what an operator token does not license (05 §6.3 — the
		// rollup write belongs to the intel driver's seam, the offboard
		// delete to the two-person offboarding role).
		writeErr(w, http.StatusForbidden, "M1E-1001", "write-shaped templates are not executable on this surface")
		return
	}
	q, err := Build(tid, tpl, req.Params)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "M1E-2001", err.Error())
		return
	}
	rows, ok := m.run(w, r, q)
	if !ok {
		return
	}
	out := rows.Rows
	if out == nil {
		out = []map[string]any{}
	}
	writeJSON(w, map[string]any{
		"rows":             out,
		"template_version": tpl.Version(),
	})
}

// ---------------------------------------------------------------------------
// POST /internal/v1/rollup/tvo_tenant_day — the ADR-0010 §2.2 seam
// ---------------------------------------------------------------------------

// rollupRequest is the complete row the intel driver assembled (the
// cross-store join happens in the JOB; ADR-0010 §2.1/§2.28 "one (tenant,
// day, series) is one row"), plus the identity that makes it idempotent.
type rollupRequest struct {
	JobKey              string   `json:"job_key"`
	TenantID            string   `json:"tenant_id"`
	Day                 string   `json:"day"`
	Series              string   `json:"series"`
	TokensTotal         any      `json:"tokens_total"`
	CostUSD             any      `json:"cost_usd"`
	TasksVerified       []string `json:"tasks_verified"`
	TasksUnresolved     []string `json:"tasks_unresolved"`
	RetryLoopTokens     any      `json:"retry_loop_tokens"`
	ReexplorationTokens any      `json:"reexploration_tokens"`
	OverModelTokens     any      `json:"over_model_tokens"`
	ObservedMS          any      `json:"observed_ms"`
	BypassMS            any      `json:"bypass_ms"`
	DisabledMS          any      `json:"disabled_ms"`
	DroppedBilling      any      `json:"dropped_billing"`
}

func (m *Module) handleRollupWrite(w http.ResponseWriter, r *http.Request) {
	if !m.deps.RollupWriteEnabled {
		writeErr(w, http.StatusForbidden, "M1E-1001",
			"rollup writes disabled on this controld (no INTEL_SERVICE_TOKEN, or QUERYCHOKE_ROLLUP_WRITE=0)")
		return
	}
	// The service credential seam (ADR-0010 §2.2): the verified principal is
	// the intel driver, presented as a bearer, compared constant-time.
	var req rollupRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20))
	dec.UseNumber()
	if err := dec.Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "M1E-2001", "malformed rollup request")
		return
	}
	tid, ok := m.serviceTenant(w, r, req.TenantID)
	if !ok {
		return
	}
	tpl, err := m.reg.Lookup("tvo_rollup_tenant_day")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "M1E-9500", "registry miswired")
		return
	}
	q, err := BuildWrite(tid, tpl, req.JobKey, Params{
		"day":                  req.Day,
		"series":               req.Series,
		"tokens_total":         req.TokensTotal,
		"cost_usd":             req.CostUSD,
		"tasks_verified":       req.TasksVerified,
		"tasks_unresolved":     req.TasksUnresolved,
		"retry_loop_tokens":    req.RetryLoopTokens,
		"reexploration_tokens": req.ReexplorationTokens,
		"over_model_tokens":    req.OverModelTokens,
		"observed_ms":          req.ObservedMS,
		"bypass_ms":            req.BypassMS,
		"disabled_ms":          req.DisabledMS,
		"dropped_billing":      req.DroppedBilling,
	})
	if err != nil {
		writeErr(w, http.StatusBadRequest, "M1E-2001", err.Error())
		return
	}
	if _, err := m.runner.Run(r.Context(), q); err != nil {
		if errors.Is(err, ErrBusy) {
			writeErr(w, http.StatusServiceUnavailable, "M1E-9500", "query concurrency limit; retry")
			return
		}
		writeErr(w, http.StatusInternalServerError, "M1E-9500", "rollup write failed")
		return
	}
	// A dedup-dropped re-run answers 200 too: idempotent by design — the
	// no-op signal belongs to the driving job's ledger (layer 1), not here.
	writeJSON(w, map[string]any{"status": "written", "job_key": req.JobKey})
}

// ---------------------------------------------------------------------------
// Row-value coercion: the driver hands back concrete CH scan types.
// ---------------------------------------------------------------------------

func asU64(v any) uint64 {
	switch x := v.(type) {
	case uint64:
		return x
	case uint32:
		return uint64(x)
	case int64:
		if x < 0 {
			return 0
		}
		return uint64(x)
	}
	return 0
}

func asStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}

func asDay(v any) string {
	if t, ok := v.(time.Time); ok {
		return t.UTC().Format(time.DateOnly)
	}
	return fmt.Sprint(v)
}

func ratio(num, den float64) float64 {
	if den == 0 {
		return 0
	}
	return num / den
}
