package querychoke

// The 08 §3.3 HTTP contract against a fake Runner: exact M1E codes, the
// verified-token tenancy stamp, the write surface's flag + service
// credential gates, and the job_key → dedup-token pass-through.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
)

// fakeRunner records the last Query and serves canned rows — per template
// name when byTemplate is set (the TVO report handler runs two reads:
// tvo_report + dropped_by_tenant_day), else the shared rows.
type fakeRunner struct {
	last       Query
	rows       *Rows
	byTemplate map[string]*Rows
	err        error
}

func (f *fakeRunner) Run(_ context.Context, q Query) (*Rows, error) {
	f.last = q
	if f.err != nil {
		return nil, f.err
	}
	if r, ok := f.byTemplate[q.Template().Name()]; ok {
		return r, nil
	}
	switch q.Template().Name() {
	case "certified_outcomes":
		return &Rows{Rows: []map[string]any{{"certified": uint64(1)}}}, nil // a certified tenant unless a test says otherwise
	case "tvo_task_window", "coverage_band":
		return &Rows{}, nil // live open-day reads: quiet unless a test cans them
	}
	return f.rows, nil
}

// fakeRegimes serves canned m1_075 rows per tenant (nil = no row), or fails.
type fakeRegimes struct {
	rows map[uuid.UUID]*Regime
	err  error
}

func (f *fakeRegimes) Regime(_ context.Context, t TenantID) (*Regime, error) {
	return f.rows[t.UUID()], f.err
}

const testHMACKey = "module-test-key"

func newTestModule(t *testing.T, run *fakeRunner, rollupEnabled bool, regimes ...RegimeSource) (*Module, *http.ServeMux, uuid.UUID, string) {
	t.Helper()
	reg, err := LoadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	tenant, device := uuid.New(), uuid.New()
	verifier := auth.NewHMACVerifier([]byte(testHMACKey), auth.StaticRevocations{})
	deps := Deps{
		Registry:           reg,
		Runner:             run,
		Verifier:           verifier,
		ObsCfg:             obs.Config{ServiceName: "test"},
		RollupWriteEnabled: rollupEnabled,
		IntelServiceToken:  "intel-secret",
	}
	if len(regimes) > 0 {
		deps.Regimes = regimes[0]
	}
	m := New(deps)
	mux := http.NewServeMux()
	m.RegisterRoutes(mux)
	bearer := auth.Mint([]byte(testHMACKey), tenant, device, time.Hour)
	return m, mux, tenant, bearer
}

func do(mux *http.ServeMux, method, path, bearer, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

func errCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var e struct {
		Error struct{ Code string }
	}
	if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil {
		t.Fatalf("non-envelope error body: %s", w.Body.String())
	}
	return e.Error.Code
}

func TestQueryEndpointContract(t *testing.T) {
	run := &fakeRunner{rows: &Rows{}}
	_, mux, tenant, bearer := newTestModule(t, run, false)

	// No token ⇒ 401 M1E-1002 (middleware).
	if w := do(mux, "POST", "/api/v1/query", "", `{}`); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: got %d", w.Code)
	}
	// Unknown template ⇒ 400 M1E-2008: the chokepoint refuses.
	w := do(mux, "POST", "/api/v1/query", bearer, `{"template":"select_everything","params":{}}`)
	if w.Code != http.StatusBadRequest || errCode(t, w) != "M1E-2008" {
		t.Fatalf("unknown template: got %d %s", w.Code, w.Body.String())
	}
	// Write-shaped template on the tenant surface ⇒ 403 M1E-1001.
	w = do(mux, "POST", "/api/v1/query", bearer, `{"template":"tvo_rollup_tenant_day","params":{}}`)
	if w.Code != http.StatusForbidden || errCode(t, w) != "M1E-1001" {
		t.Fatalf("write template on read surface: got %d %s", w.Code, w.Body.String())
	}
	// Bad params ⇒ 400 M1E-2001.
	w = do(mux, "POST", "/api/v1/query", bearer, `{"template":"usage_by_session","params":{"from":"yesterday","to":"2026-08-29"}}`)
	if w.Code != http.StatusBadRequest || errCode(t, w) != "M1E-2001" {
		t.Fatalf("bad params: got %d %s", w.Code, w.Body.String())
	}
	// Happy path: rows + template_version, and the executed Query carries
	// the TOKEN's tenant — no body field could have named one.
	w = do(mux, "POST", "/api/v1/query", bearer, `{"template":"usage_by_session","params":{"from":"2026-08-01","to":"2026-08-29"}}`)
	if w.Code != http.StatusOK {
		t.Fatalf("happy path: got %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		Rows            []map[string]any `json:"rows"`
		TemplateVersion string           `json:"template_version"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.TemplateVersion != "usage_by_session.v1" || resp.Rows == nil {
		t.Fatalf("response shape: %s", w.Body.String())
	}
	if run.last.Bind()["tid"] != tenant.String() {
		t.Fatalf("executed query bound tenant %q, want the token's %q", run.last.Bind()["tid"], tenant)
	}
}

func TestTVOReportContract(t *testing.T) {
	day := time.Now().UTC().Format(time.DateOnly)
	reportRows := &Rows{Rows: []map[string]any{{
		"day":                  time.Now().UTC(),
		"task_seg_version":     "task_seg.v1",
		"tokens_total":         uint64(300),
		"tasks_verified":       uint64(3),
		"tasks_unresolved":     uint64(0),
		"retry_loop_tokens":    uint64(10),
		"reexploration_tokens": uint64(20),
		"over_model_tokens":    uint64(30),
		"observed_ms":          uint64(980),
		"bypass_ms":            uint64(20),
		"disabled_ms":          uint64(0),
		"dropped_billing":      uint64(0),
	}}}
	// Shed-free loss ledger: coverage_lower = coverage = 0.98 ≥ D23's 0.95. One row per day of the 7-day window (billing rows on every day: each closed day without a rollup is then genuinely missing).
	shedFree := &Rows{}
	for i := 6; i >= 0; i-- {
		shedFree.Rows = append(shedFree.Rows, map[string]any{
			"day":                     time.Now().UTC().AddDate(0, 0, -i).Format(time.DateOnly),
			"dropped_billing":         uint64(0),
			"events_billing_ingested": uint64(100),
		})
	}
	run := &fakeRunner{
		rows:       reportRows,
		byTemplate: map[string]*Rows{"dropped_by_tenant_day": shedFree},
	}
	_, mux, _, bearer := newTestModule(t, run, false)

	if w := do(mux, "GET", "/api/v1/reports/tvo?window=99x", bearer, ""); w.Code != http.StatusBadRequest || errCode(t, w) != "M1E-2001" {
		t.Fatalf("bad window: got %d %s", w.Code, w.Body.String())
	}

	// cost_basis=quota with no regime row: stamped as asked, and the guarantee
	// is refused for want of the tenant-confirmed S (06 §8.4 D22) — the number
	// still renders (08 §3.3), never a 400.
	w := do(mux, "GET", "/api/v1/reports/tvo?window=1d&cost_basis=quota", bearer, "")
	if w.Code != http.StatusOK {
		t.Fatalf("quota basis: got %d %s", w.Code, w.Body.String())
	}
	var quota map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &quota); err != nil {
		t.Fatal(err)
	}
	if quota["cost_basis"] != "quota" || quota["guarantee_grade"] != false ||
		!strings.Contains(quota["refusal"].(string), "shadow price S unconfirmed by tenant (D22)") {
		t.Fatalf("quota without a regime must issue indicative naming D22: %s", w.Body.String())
	}
	if _, ok := quota["price_table_version"]; ok {
		t.Fatalf("a quota report never claims a price pin: %s", w.Body.String())
	}
	if w := do(mux, "GET", "/api/v1/reports/tvo?window=1d&cost_basis=eur", bearer, ""); w.Code != http.StatusBadRequest || errCode(t, w) != "M1E-2001" {
		t.Fatalf("unknown basis: got %d %s", w.Code, w.Body.String())
	}

	// A 1-day window fully covered and shed-free: the band clears D23, but
	// with no m1_075 regime row usd has no pinned model_prices row, so the
	// report is INDICATIVE with the basis refusal stated — never a silent
	// guarantee (06 §8.5). TVO = 300/3.
	w = do(mux, "GET", "/api/v1/reports/tvo?window=1d&cohort=all&cost_basis=auto", bearer, "")
	if w.Code != http.StatusOK {
		t.Fatalf("tvo: got %d %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["tvo"].(float64) != 100 {
		t.Fatalf("tvo: %v", resp["tvo"])
	}
	if resp["guarantee_grade"] != false ||
		!strings.Contains(resp["refusal"].(string), "no pinned model_prices row for usd") {
		t.Fatalf("usd without a price pin must issue indicative with the reason stated: %s", w.Body.String())
	}
	if strings.Contains(resp["refusal"].(string), "M1E-5004") {
		t.Fatalf("band 0.98 must not trip the coverage floor: %s", w.Body.String())
	}
	band := resp["coverage_band"].(map[string]any)
	if band["observed_fraction"].(float64) != 0.98 || band["coverage_lower"].(float64) != 0.98 ||
		band["floor"].(float64) != 0.95 {
		t.Fatalf("coverage_band must carry the shed-narrowed lower edge and D23's floor: %s", w.Body.String())
	}
	if resp["cost_basis"] != "usd" || resp["task_seg_version"] != "task_seg.v1" {
		t.Fatalf("body shape: %s", w.Body.String())
	}
	if _, ok := resp["price_table_version"]; ok {
		t.Fatalf("an unpinned usd report must not stamp a price table: %s", w.Body.String())
	}
	waste := resp["waste"].(map[string]any)
	if waste["re_exploration_tokens"].(float64) != 20 {
		t.Fatalf("waste keys must be 08 §3.3's exact spelling: %s", w.Body.String())
	}
	trend := resp["trend"].([]any)
	if len(trend) != 1 || trend[0].(map[string]any)["day"] != day {
		t.Fatalf("trend: %s", w.Body.String())
	}

	// THE 0.85-hardcode regression: an UN-narrowed fraction of 0.98 with shed
	// accounting 100/(100+100) narrows coverage_lower to 0.49 — the floor
	// must fire on the narrowed edge (06 §8.5; coverage.py's arithmetic).
	run.byTemplate["dropped_by_tenant_day"] = &Rows{Rows: []map[string]any{{
		"dropped_billing":         uint64(100),
		"events_billing_ingested": uint64(100),
	}}}
	w = do(mux, "GET", "/api/v1/reports/tvo?window=1d", bearer, "")
	resp = map[string]any{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["guarantee_grade"] != false ||
		!strings.Contains(resp["refusal"].(string), "M1E-5004 coverage below floor") {
		t.Fatalf("shed-narrowed lower edge below floor must refuse M1E-5004: %s", w.Body.String())
	}
	run.byTemplate["dropped_by_tenant_day"] = shedFree

	// A 7-day window with 6 missing rollup days: number still renders, the
	// guarantee is refused with M1E-5004 and the days are enumerated
	// (ADR-0010 §2.7).
	w = do(mux, "GET", "/api/v1/reports/tvo?window=7d", bearer, "")
	if w.Code != http.StatusOK {
		t.Fatalf("tvo 7d: got %d", w.Code)
	}
	resp = map[string]any{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["guarantee_grade"] != false {
		t.Fatalf("missing rollup days must refuse guarantee grade: %s", w.Body.String())
	}
	if !strings.Contains(resp["refusal"].(string), "M1E-5004 rollup missing") {
		t.Fatalf("refusal must carry M1E-5004: %s", w.Body.String())
	}
	if len(resp["missing_days"].([]any)) != 6 {
		t.Fatalf("missing days must be enumerated: %s", w.Body.String())
	}

	// No certified satisfied verdict in the window: the number renders (outcomes count by posterior mode), the guarantee is refused with report.py's own words.
	run.byTemplate["certified_outcomes"] = &Rows{Rows: []map[string]any{{"certified": uint64(0)}}}
	w = do(mux, "GET", "/api/v1/reports/tvo?window=1d", bearer, "")
	resp = map[string]any{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["tvo"].(float64) != 100 || resp["guarantee_grade"] != false ||
		!strings.Contains(resp["refusal"].(string), "noise certificate is 'bootstrapping', not 'certified'") {
		t.Fatalf("bootstrapping certificate must render the number and refuse the guarantee: %s", w.Body.String())
	}
	delete(run.byTemplate, "certified_outcomes")

	// A day with no billing rows (before the tenant existed, a quiet weekend) and today (never closed yet) are not missing rollups: a fresh tenant's first report must not refuse for the six days before it signed up.
	run.byTemplate["dropped_by_tenant_day"] = &Rows{Rows: []map[string]any{{
		"day":                     time.Now().UTC().Format(time.DateOnly),
		"dropped_billing":         uint64(0),
		"events_billing_ingested": uint64(100),
	}}}
	w = do(mux, "GET", "/api/v1/reports/tvo?window=7d", bearer, "")
	resp = map[string]any{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if refusal, _ := resp["refusal"].(string); strings.Contains(refusal, "rollup missing") || resp["missing_days"] != nil {
		t.Fatalf("quiet days before the tenant's first row are not missing rollups: %s", w.Body.String())
	}
	run.byTemplate["dropped_by_tenant_day"] = shedFree
}

// A restated day arrives as TWO (day, series) rows; ADR-0010 §6 makes the new
// series SUPERSEDE the original (RECONCILIATION.md D-F), so the report must
// fold from the newest series ONLY — summing both was the double-count bug.
func TestTVOReportRestatedDayUsesNewestSeriesOnly(t *testing.T) {
	now := time.Now().UTC()
	mkRow := func(series string, tokens, verified uint64) map[string]any {
		return map[string]any{
			"day": now, "task_seg_version": series,
			"tokens_total": tokens, "tasks_verified": verified,
			"tasks_unresolved": uint64(0), "retry_loop_tokens": uint64(0),
			"reexploration_tokens": uint64(0), "over_model_tokens": uint64(0),
			"observed_ms": uint64(980), "bypass_ms": uint64(20),
			"disabled_ms": uint64(0), "dropped_billing": uint64(0),
		}
	}
	run := &fakeRunner{
		rows: &Rows{Rows: []map[string]any{
			mkRow("task_seg.v1", 300, 3),            // the superseded original
			mkRow("task_seg.v1-restated.2", 400, 2), // the restatement
		}},
		byTemplate: map[string]*Rows{"dropped_by_tenant_day": {Rows: []map[string]any{{
			"dropped_billing": uint64(0), "events_billing_ingested": uint64(100),
		}}}},
	}
	_, mux, _, bearer := newTestModule(t, run, false)
	w := do(mux, "GET", "/api/v1/reports/tvo?window=1d", bearer, "")
	if w.Code != http.StatusOK {
		t.Fatalf("tvo: got %d %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	// Newest series only: 400/2 = 200. Blending would give 700/5 = 140.
	if resp["tvo"].(float64) != 200 {
		t.Fatalf("restated day must fold from the newest series only: tvo=%v body=%s",
			resp["tvo"], w.Body.String())
	}
	if resp["task_seg_version"] != "task_seg.v1-restated.2" {
		t.Fatalf("task_seg_version: %v", resp["task_seg_version"])
	}
	trend := resp["trend"].([]any)
	if len(trend) != 1 || trend[0].(map[string]any)["tvo"].(float64) != 200 {
		t.Fatalf("trend must use the newest series too: %s", w.Body.String())
	}
}

func TestInterventionsContract(t *testing.T) {
	task := uuid.New()
	run := &fakeRunner{rows: &Rows{Rows: []map[string]any{{
		"task_id":               task,
		"tokens_saved_estimate": uint64(1200),
		"verdict":               "satisfied",
		"bundle_seq":            uint64(483),
	}}}}
	_, mux, _, bearer := newTestModule(t, run, false)
	w := do(mux, "GET", "/api/v1/reports/interventions?window=7d", bearer, "")
	if w.Code != http.StatusOK {
		t.Fatalf("interventions: got %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		KneeArrests []map[string]any `json:"knee_arrests"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.KneeArrests) != 1 || resp.KneeArrests[0]["task_id"] != task.String() {
		t.Fatalf("knee_arrests shape: %s", w.Body.String())
	}
}

func TestRollupWriteSurfaceGates(t *testing.T) {
	tenant := uuid.New()
	body := `{"job_key":"tvo.rollup_tenant_day|2026-08-28|abcd","tenant_id":"` + tenant.String() + `",` +
		`"day":"2026-08-28","series":"task_seg.v1","tokens_total":300,"cost_usd":"12.5",` +
		`"tasks_verified":["` + uuid.NewString() + `"],"tasks_unresolved":[],` +
		`"retry_loop_tokens":1,"reexploration_tokens":2,"over_model_tokens":3,` +
		`"observed_ms":4,"bypass_ms":5,"disabled_ms":6,"dropped_billing":7}`

	// Flag OFF (the ADR-0010 production-write guard): loud 403, never a
	// silent no-op — regardless of credential.
	runOff := &fakeRunner{}
	_, muxOff, _, _ := newTestModule(t, runOff, false)
	req := httptest.NewRequest("POST", "/internal/v1/rollup/tvo_tenant_day", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer intel-secret")
	w := httptest.NewRecorder()
	muxOff.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "rollup writes disabled") {
		t.Fatalf("disabled write surface: got %d %s", w.Code, w.Body.String())
	}
	if runOff.last.SQL() != "" {
		t.Fatal("disabled write surface reached the runner")
	}

	// Flag ON: wrong service credential refused; device/operator tokens are
	// NOT service credentials.
	run := &fakeRunner{}
	_, mux, _, bearer := newTestModule(t, run, true)
	for _, cred := range []string{"", "wrong", bearer} {
		req := httptest.NewRequest("POST", "/internal/v1/rollup/tvo_tenant_day", strings.NewReader(body))
		if cred != "" {
			req.Header.Set("Authorization", "Bearer "+cred)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("cred %q: got %d", cred, w.Code)
		}
	}

	// Missing job_key refused (idempotency layer 2 is mandatory).
	noKey := strings.Replace(body, `"job_key":"tvo.rollup_tenant_day|2026-08-28|abcd",`, "", 1)
	req = httptest.NewRequest("POST", "/internal/v1/rollup/tvo_tenant_day", strings.NewReader(noKey))
	req.Header.Set("Authorization", "Bearer intel-secret")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("missing job_key: got %d %s", w.Code, w.Body.String())
	}

	// Happy path: the executed Query is the write template, carries the
	// job_key as dedup token and the REQUEST-NAMED tenant via the verified
	// service seam.
	req = httptest.NewRequest("POST", "/internal/v1/rollup/tvo_tenant_day", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer intel-secret")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("rollup write: got %d %s", w.Code, w.Body.String())
	}
	if run.last.Template().Name() != "tvo_rollup_tenant_day" || !run.last.Template().IsWrite() {
		t.Fatalf("executed template: %s", run.last.Template().Name())
	}
	if run.last.JobKey() != "tvo.rollup_tenant_day|2026-08-28|abcd" {
		t.Fatalf("job_key not carried as dedup token: %q", run.last.JobKey())
	}
	if run.last.Bind()["tid"] != tenant.String() {
		t.Fatalf("write bound tenant %q, want %q", run.last.Bind()["tid"], tenant)
	}
}

// The Go half of the write-seam lock (wave-5 lesson, RECONCILIATION.md:
// stub-tested halves of one contract drift unless one side's tests speak the
// other side's exact wire bytes): replay the EXACT body intel's driver POSTs
// (testdata/rollup_write_body.json, re-derived on the Python side by
// test_tvo_rollup.py through the real reader/rollup code) against the real
// handler. If reader.py changes route/body without this handler — or vice
// versa — one of the two tests goes red.
func TestRollupWriteAcceptsIntelExactBody(t *testing.T) {
	raw, err := os.ReadFile("testdata/rollup_write_body.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Body json.RawMessage `json:"body"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	var want struct {
		JobKey   string `json:"job_key"`
		TenantID string `json:"tenant_id"`
	}
	if err := json.Unmarshal(fixture.Body, &want); err != nil {
		t.Fatal(err)
	}

	run := &fakeRunner{}
	_, mux, _, _ := newTestModule(t, run, true)
	req := httptest.NewRequest("POST", "/internal/v1/rollup/tvo_tenant_day", bytes.NewReader(fixture.Body))
	req.Header.Set("Authorization", "Bearer intel-secret")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("intel's exact body refused: %d %s", w.Code, w.Body.String())
	}
	// The ack shape reader.py decodes, verbatim: {"status", "job_key"}.
	var ack struct {
		Status string `json:"status"`
		JobKey string `json:"job_key"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &ack); err != nil {
		t.Fatal(err)
	}
	if ack.Status != "written" || ack.JobKey != want.JobKey {
		t.Fatalf("ack shape drifted from what reader.py decodes: %s", w.Body.String())
	}
	if run.last.Template().Name() != "tvo_rollup_tenant_day" ||
		run.last.JobKey() != want.JobKey || run.last.Bind()["tid"] != want.TenantID {
		t.Fatalf("executed write drifted: tpl=%s jobKey=%q tid=%q",
			run.last.Template().Name(), run.last.JobKey(), run.last.Bind()["tid"])
	}
}

// ErrBusy maps to 503 (05 §6.5: excess queues 5 s then sheds).
func TestBusyMapsTo503(t *testing.T) {
	run := &fakeRunner{err: ErrBusy}
	_, mux, _, bearer := newTestModule(t, run, false)
	w := do(mux, "POST", "/api/v1/query", bearer, `{"template":"coverage_band","params":{"from":"2026-08-01","to":"2026-08-29"}}`)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("busy: got %d", w.Code)
	}
}

// TestServiceQuerySurface: the intel driver's READ half of the ADR-0010 §2.2 seam — the same registry as /api/v1/query, the tenant from the body under the service credential, never a token (prod 2026-09-19: the hourly rollup's tvo_task_window read 401ed on the token surface).
func TestServiceQuerySurface(t *testing.T) {
	tenant := uuid.New()
	run := &fakeRunner{rows: &Rows{}}
	_, mux, _, deviceBearer := newTestModule(t, run, true)
	body := func(tpl string) string {
		return `{"tenant_id":"` + tenant.String() + `","template":"` + tpl + `","params":{"from":"2026-08-28","to":"2026-08-29"}}`
	}
	post := func(cred, b string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/internal/v1/query", strings.NewReader(b))
		if cred != "" {
			req.Header.Set("Authorization", "Bearer "+cred)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w
	}
	for _, cred := range []string{"", "wrong", deviceBearer} {
		if w := post(cred, body("tvo_task_window")); w.Code != http.StatusForbidden {
			t.Fatalf("cred %q: got %d %s", cred, w.Code, w.Body.String())
		}
	}
	if w := post("intel-secret", body("tvo_rollup_tenant_day")); w.Code != http.StatusForbidden {
		t.Fatalf("write template on the read surface: got %d %s", w.Code, w.Body.String())
	}
	if w := post("intel-secret", `{"tenant_id":"nope","template":"tvo_task_window","params":{}}`); w.Code != http.StatusBadRequest {
		t.Fatalf("bad tenant: got %d", w.Code)
	}
	w := post("intel-secret", body("tvo_task_window"))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"template_version"`) {
		t.Fatalf("service read: got %d %s", w.Code, w.Body.String())
	}
	if run.last.Template().Name() != "tvo_task_window" || run.last.Bind()["tid"] != tenant.String() {
		t.Fatalf("executed %s for tenant %v", run.last.Template().Name(), run.last.Bind()["tid"])
	}
}

func TestTVOReportOpenDayRendersLive(t *testing.T) {
	now := time.Now().UTC()
	today := now.Format(time.DateOnly)
	// Bootstrap rows: the Chow band says refused, the posterior mode says satisfied (v4 p_* columns); attempt 2 follows a violated attempt 1 → its tokens are retry-loop waste.
	att := func(task string, n uint64, tokens uint64, word string, pS, pV float64) map[string]any {
		return map[string]any{
			"task_id": task, "attempt_n": n, "gen_tokens": tokens, "verifier_tokens": uint64(0),
			"fused_verdict": word, "verdict_stage": "revised", "task_seg_version": "task_seg.v1",
			"p_satisfied": pS, "p_violated": pV, "p_refused": 0.04, "p_error": 0.02,
		}
	}
	run := &fakeRunner{
		rows: &Rows{}, // no rollup row: today is open
		byTemplate: map[string]*Rows{
			"dropped_by_tenant_day": {Rows: []map[string]any{{"day": today, "dropped_billing": uint64(0), "events_billing_ingested": uint64(100)}}},
			"tvo_task_window": {Rows: []map[string]any{
				att("a", 1, 100, "violated", 0.29, 0.55),
				att("a", 2, 50, "refused", 0.71, 0.23),
				att("b", 1, 150, "refused", 0.68, 0.25),
				att("c", 1, 100, "violated", 0.29, 0.55),
			}},
			"coverage_band": {Rows: []map[string]any{{"day": now, "observed_ms": uint64(980), "bypass_ms": uint64(20), "disabled_ms": uint64(0)}}},
		},
	}
	_, mux, _, bearer := newTestModule(t, run, false)
	w := do(mux, "GET", "/api/v1/reports/tvo?window=1d", bearer, "")
	if w.Code != http.StatusOK {
		t.Fatalf("tvo: got %d %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	// 400 tokens over 2 outcomes whose terminal mode is satisfied (a, b); c stays violated.
	if resp["tvo"].(float64) != 200 {
		t.Fatalf("an open day must render live by posterior mode: tvo=%v body=%s", resp["tvo"], w.Body.String())
	}
	if resp["waste"].(map[string]any)["retry_loop_tokens"].(float64) != 50 {
		t.Fatalf("retry-loop waste must charge the attempt after a violated one: %s", w.Body.String())
	}
	if resp["coverage_band"].(map[string]any)["observed_fraction"].(float64) != 0.98 {
		t.Fatalf("coverage must come from the day's transitions: %s", w.Body.String())
	}
	if live, _ := resp["live_days"].([]any); len(live) != 1 || live[0] != today {
		t.Fatalf("live_days must name the open day: %s", w.Body.String())
	}
	if resp["guarantee_grade"] != false || !strings.Contains(resp["refusal"].(string), "1 open day(s) reported live") {
		t.Fatalf("a live day must refuse guarantee grade by name: %s", w.Body.String())
	}
	if strings.Contains(resp["refusal"].(string), "rollup missing") {
		t.Fatalf("an open day is never a missing rollup: %s", w.Body.String())
	}
	if resp["task_seg_version"] != "task_seg.v1" {
		t.Fatalf("task_seg_version: %v", resp["task_seg_version"])
	}
}
