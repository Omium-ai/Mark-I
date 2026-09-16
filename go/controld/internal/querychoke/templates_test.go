package querychoke

// The 05 §6.4 negative suites that keep R4 from rotting: marker negatives
// against loadFrom (registering a bad template must fail LOADING, never
// reach a runtime check), the render-grep over EVERY registered template
// (suspenders under the type layer's belt), and the injection attempts the
// parameter layer must refuse.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
)

func testTenant(t *testing.T) TenantID {
	t.Helper()
	tid, err := FromClaims(auth.Claims{TenantID: uuid.New(), DeviceID: uuid.New()})
	if err != nil {
		t.Fatal(err)
	}
	return tid
}

// dummyParams renders valid values for every declared parameter so the grep
// suite can Build every template without knowing it by name.
func dummyParams(tpl *template) Params {
	p := Params{}
	for name, spec := range tpl.params {
		switch spec.kind {
		case pUUID:
			p[name] = uuid.New()
		case pDate:
			p[name] = "2026-08-28"
		case pDateTime:
			p[name] = "2026-08-28 10:00:00"
		case pUInt64:
			p[name] = uint64(7)
		case pDecimal:
			p[name] = "12.5"
		case pUUIDArray:
			p[name] = []uuid.UUID{uuid.New()}
		case pString:
			p[name] = "task_seg.v1"
		}
	}
	return p
}

// The suspenders (05 §6.2): EVERY registered template's render output
// carries the tenant predicate bound to the calling tenant — asserted by
// grep over the closed set, so a template added without the marker fails
// this test even if the loader were broken the same day.
func TestRenderGrepEveryTemplateCarriesTenantPredicate(t *testing.T) {
	reg, err := LoadTemplates()
	if err != nil {
		t.Fatalf("R4: %v", err)
	}
	tid := testTenant(t)
	for name, tpl := range reg.byName {
		handle := Template{t: tpl}
		var q Query
		if tpl.write {
			q, err = BuildWrite(tid, handle, "job:2026-08-28:"+name, dummyParams(tpl))
		} else {
			q, err = Build(tid, handle, dummyParams(tpl))
		}
		if err != nil {
			t.Fatalf("template %s: %v", name, err)
		}
		if !strings.Contains(q.SQL(), tenantPredSQL) {
			t.Errorf("template %s: rendered SQL lacks the tenant predicate:\n%s", name, q.SQL())
		}
		if got := q.Bind()["tid"]; got != tid.String() {
			t.Errorf("template %s: tid bound to %q, want the calling tenant %q", name, got, tid)
		}
		if strings.Contains(q.SQL(), ";") || strings.Contains(q.SQL(), "--") || strings.Contains(q.SQL(), "/*") {
			t.Errorf("template %s: rendered SQL contains a forbidden token:\n%s", name, q.SQL())
		}
		if !tpl.write && !regexp.MustCompile(`\nLIMIT [0-9]+$`).MatchString(q.SQL()) {
			t.Errorf("template %s: read render lacks the builder-appended LIMIT", name)
		}
	}
}

// The at-least-once dedupe tripwire (07 §"m1p_events" engine note + §7,
// 05 §2 step 10): the ledger transport replays batches by design and
// ReplacingMergeTree collapse is EVENTUAL, so EVERY read template over
// m1p_events must carry the reader dedupe form — `LIMIT 1 BY event_id` —
// and never FINAL on a hot path. Structural, not per-template: a template
// added tomorrow that mentions m1p_events enters this sweep automatically.
// (Write templates are exempt: the DELETE carve-out removes rows, it does
// not count them.)
func TestEveryM1pEventsReadTemplateCarriesTheDedupeForm(t *testing.T) {
	reg, err := LoadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	swept := 0
	for name, tpl := range reg.byName {
		if tpl.write || !strings.Contains(tpl.body, "m1p_events") {
			continue
		}
		swept++
		if !strings.Contains(tpl.body, "LIMIT 1 BY event_id") {
			t.Errorf("template %s reads m1p_events without the LIMIT 1 BY event_id dedupe form — at-least-once replay double-counts until background merges:\n%s", name, tpl.body)
		}
		if strings.Contains(tpl.body, "FINAL") {
			t.Errorf("template %s uses FINAL on a hot path (07: readers use LIMIT 1 BY / argMax forms)", name)
		}
	}
	if swept == 0 {
		t.Fatal("swept zero m1p_events read templates — the tripwire is disarmed")
	}
}

// The dropped_by_tenant_day ↔ reader.py coverage_inputs column contract
// (06 §8.2 shed accounting): the template must expose, by exact name, the two
// terms intel _require()s — and the loss-ledger term must filter on
// dropped_durability_class, never event_class (the m1_ch_002 mv_tvo_session
// lesson: an event_class filter on Dropped{} rows sums to zero forever).
func TestDroppedByTenantDayServesCoverageInputs(t *testing.T) {
	reg, err := LoadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	tpl, err := reg.Lookup("dropped_by_tenant_day")
	if err != nil {
		t.Fatal(err)
	}
	body := tpl.t.body
	for _, want := range []string{
		"AS dropped_billing",                         // reader.py: _require(r, "dropped_billing", ...)
		"AS events_billing_ingested",                 // reader.py: _require(r, "events_billing_ingested", ...)
		"dropped_durability_class = 'billing_grade'", // the class of the thing LOST
	} {
		if !strings.Contains(body, want) {
			t.Errorf("dropped_by_tenant_day lost its coverage-inputs contract term %q:\n%s", want, body)
		}
	}
	if regexp.MustCompile(`sumIf\(dropped_quantity[^)]*event_class`).MatchString(body) {
		t.Errorf("loss ledger filtered on event_class — sums to zero forever (m1_ch_002):\n%s", body)
	}
}

// The tvo_task_window ↔ reader.py attempt_window column contract (the
// ADR-0010 rollup driver's only ledger read), plus the shape rules that make
// the numbers mean what rollup.py assumes: attempt boundaries in the
// normative (session_epoch, seq) order, the tail folded into the last
// stage-final attempt, the reader dedupe form, and a half-open window that
// Build must NOT widen (reader.py passes (day, day+1)).
func TestTvoTaskWindowServesAttemptWindow(t *testing.T) {
	reg, err := LoadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	tpl, err := reg.Lookup("tvo_task_window")
	if err != nil {
		t.Fatal(err)
	}
	body := tpl.t.body
	// The column set is the cross-language fixture's row keys — the exact rows
	// reader.py's tests feed attempt_window (testdata/rollup_write_body.json).
	var fixture struct {
		Inputs struct {
			Rows []map[string]any `json:"tvo_task_window"`
		} `json:"inputs"`
	}
	raw, err := os.ReadFile(filepath.Join("testdata", "rollup_write_body.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &fixture); err != nil || len(fixture.Inputs.Rows) == 0 {
		t.Fatalf("fixture rows: %v", err)
	}
	want := []string{
		"ORDER BY session_epoch, seq",                      // 07: causal order, never occurred_at
		"ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING", // an attempt closes ON its verdict row
		"greatest(1, countIf(",                             // the tail folds into the last attempt
		"verdict_stage IN ('certified', 'revised')",        // provisional never splits an attempt
		"toDate(occurred_at) >= {from:Date} AND toDate(occurred_at) < {to:Date}",
		"task_id != toUUID('00000000-0000-0000-0000-000000000000')",
		"JSONExtractString(payload, 'task_seg_version')", // chproj projects no column for it
	}
	for col := range fixture.Inputs.Rows[0] {
		want = append(want, "AS "+col)
	}
	for _, w := range want {
		if !strings.Contains(body, w) {
			t.Errorf("tvo_task_window lost its attempt-window contract term %q:\n%s", w, body)
		}
	}
	if regexp.MustCompile(`argMaxIf\([^)]*occurred_at`).MatchString(body) {
		t.Errorf("attempt verdict ordered by occurred_at — 07 makes (session_epoch, seq) the only causal order:\n%s", body)
	}
	if tpl.t.widenDates {
		t.Error("tvo_task_window widens dates — reader.py's half-open (day, day+1) window would become three days")
	}
	q, err := Build(testTenant(t), tpl, Params{"from": "2026-08-10", "to": "2026-08-11"})
	if err != nil {
		t.Fatal(err)
	}
	if q.Bind()["from"] != "2026-08-10" || q.Bind()["to"] != "2026-08-11" {
		t.Fatalf("window moved: from=%s to=%s", q.Bind()["from"], q.Bind()["to"])
	}
	// Negatives: the parameter belt refuses injection-shaped dates on this
	// template exactly as on every other, and an undeclared slot is refused.
	for _, bad := range []Params{
		{"from": "2026-08-10' OR 1=1", "to": "2026-08-11"},
		{"from": "2026-08-10", "to": "2026-08-11; DROP TABLE m1p_events"},
		{"from": "2026-08-10", "to": "2026-08-11", "tid": uuid.New()},
		{"from": "2026-08-10"},
	} {
		if _, err := Build(testTenant(t), tpl, bad); err == nil {
			t.Errorf("tvo_task_window built with %v", bad)
		}
	}
}

// The intelligence-consumer contracts (batch 1: intel inputs.py decision_row,
// intel corpus/jobs.py _candidate → export.py, adjudicator nightly.py
// spectral_estimate; batch 2: intel policy_compiler/jobs.py read_attempts,
// intel memory/admit.py certified_outcomes, adjudicator nightly.py
// _ledger_pairs; batch 3: intel memory/extract.py certified_sessions): the
// outer SELECT's aliases equal the cross-language
// fixture's keys BOTH ways (testdata/intel_template_rows.json), the shape
// rules each consumer assumes hold, the window is exactly what the consumer
// passes (closed [day, day] or half-open [from, to) — never widened), and the
// per-template marker/parameter negatives refuse.
func TestIntelReadTemplatesServeTheirConsumers(t *testing.T) {
	reg, err := LoadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join("testdata", "intel_template_rows.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	const (
		closedWindow   = "toDate(occurred_at) BETWEEN {from:Date} AND {to:Date}"                  // the consumer passes (day, day)
		halfOpenWindow = "toDate(occurred_at) >= {from:Date} AND toDate(occurred_at) < {to:Date}" // the consumer passes (day, day+1)
	)
	dayDay := Params{"from": "2026-08-10", "to": "2026-08-10"}
	dayNext := Params{"from": "2026-08-10", "to": "2026-08-11"}
	type lock struct {
		terms  []string
		params Params
	}
	shape := map[string]lock{
		"ope_route_decisions": {params: dayDay, terms: []string{
			"ROWS BETWEEN 1 FOLLOWING AND UNBOUNDED FOLLOWING", // served_model = the FIRST later Usage in the task
			"argMinIf(model, (session_epoch, seq), event_type = 'Usage' AND model != '')",
			"if(e.cert_stage = '', NULL, e.cert_conf) AS label_confidence", // uncertified ⇒ NULL, never zero-filled
			"verdict_stage IN ('certified', 'revised')",
			"WHERE e.event_type = 'RouteDecision'",
			"event_type IN ('RouteDecision', 'Usage', 'VerdictEvent')",
			closedWindow,
		}},
		"corpus_candidates": {params: dayDay, terms: []string{
			"HAVING attempts > 0", // a task with no stage-final verdict never exports
			"countIf(e.stage_final)         AS attempts",
			"hex(base64Decode(maxIf(JSONExtractString(e.payload, 'prompt_digest'), e.event_type = 'TaskOpen')))",
			"maxIf(JSONExtractBool(e.payload, 'integrity', 'tamper'), e.event_type = 'AnchorVote') AS tamper",
			"if(countIf(e.event_type = 'RouteDecision') = 0, NULL,", // unrouted ⇒ NULL propensity/fidelity
			"argMaxIf(e.noise_cert_id, (e.session_epoch, e.seq), e.stage_final) AS noise_cert_id",
			closedWindow,
		}},
		"adjudication_votes": {params: dayDay, terms: []string{
			"e.session_id AS session_id", // the ledger re-entry (A3) binds the adjudicated verdict to the original session
			"lower(replaceOne(JSONExtractString(e.payload, 'vote'), 'VERDICT_', '')) AS vote", // protojson enum name → wire verdict
			"IN ('refused', 'error') AS abstained",
			"e.event_type = 'AnchorVote' AS is_anchor",
			"JSONExtractBool(e.payload, 'integrity', 'tamper') AS tamper",
			"WHERE e.event_type != 'VerdictEvent'",
			"event_type IN ('AnchorVote', 'JudgeVote', 'RmScore', 'ConsistencyVote', 'VerdictEvent')",
			closedWindow,
		}},
		"evidence_excerpts": {params: Params{"from": "2026-08-10", "to": "2026-08-10", "task_id": uuid.New()}, terms: []string{
			"AND event_type = 'EvidenceExcerpt'",
			"JSONExtractString(payload, 'tier') = 'EVIDENCE_TIER_E1'", // E2 never served: VPC/self-host only, no receipt (FR-VERIFY-016)
			"AND task_id = {task_id:UUID}",
			"JSONExtractString(e.payload, 'redaction_receipt_id') AS redaction_receipt_id", // the m1_077 key the reader binds against
			"JSONExtractString(e.payload, 'evidence_event_id') AS evidence_event_id",
			"JSONExtractString(e.payload, 'attachment_name') AS attachment_name", // the 08 §2.1 part name; content never rides the choke
			"ORDER BY e.session_epoch, e.seq, e.event_id",
			closedWindow,
		}},
		"policy_compiler_attempts": {params: dayNext, terms: []string{
			"ORDER BY session_epoch, seq",                      // tvo_task_window's attempt arithmetic, verbatim
			"ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING", // an attempt closes ON its verdict row
			"greatest(1, countIf(",                             // the tail folds into the last attempt
			"verdict_stage IN ('certified', 'revised')",        // provisional never splits an attempt
			"argMaxIf(e.model, (e.session_epoch, e.seq), e.event_type = 'Usage' AND e.model != '') AS model_id",
			"max(JSONExtractString(payload, 'task_class')) OVER (PARTITION BY task_id) AS task_class",
			"sum(e.cache_creation_input_tokens) AS cache_creation_tokens", // knee.py AttemptCost names, no _input infix
			"sum(e.cache_read_input_tokens)     AS cache_read_tokens",
			"toFloat64(0) AS verifier_spend_usd", // no witness row exists
			"anyIf(e.cost_basis, e.cost_basis != '') AS cost_basis",
			"HAVING fused_verdict != ''", // a task with no verdict is not an attempt
			"event_type IN ('Usage', 'VerdictEvent', 'TaskOpen')",
			halfOpenWindow,
		}},
		"artifact_outcomes": {params: Params{"from": "2026-08-10", "to": "2026-08-11", "artifact_id": uuid.New()}, terms: []string{
			"base64Encode(UUIDStringToNum(toString({artifact_id:UUID}))) AS wanted", // protojson lands bytes as base64
			"has(JSONExtract(e.payload, 'artifact_ids', 'Array(String)'), e.wanted)) > 0 AS delivered",
			"JSONExtractString(e.payload, 'artifact_id') = e.wanted) > 0 AS closed",
			"WHERE t.delivered AND t.closed AND isFinite(t.control_tvo)", // both halves of the join, and a control cohort
			"sumIf(task_cost, NOT injected AND verdict_stage != '') OVER ()",
			"/ countIf(NOT injected AND verdict = 'satisfied') OVER () AS control_tvo",
			"if(t.verdict = 'satisfied', t.control_tvo - t.task_cost, -t.task_cost) AS utility",
			"argMaxIf(e.verdict, (e.session_epoch, e.seq), e.stage_final)       AS verdict",
			"if(anyIf(e.cost_basis, e.cost_basis != '') = 'usd', toFloat64(sum(e.cost_usd)),",
			"event_type IN ('Usage', 'VerdictEvent', 'MemoryInjection', 'ArtifactOutcome')",
			halfOpenWindow,
		}},
		"gold_vs_verdict": {params: dayDay, terms: []string{
			"HAVING countIf(e.stage_final) > 0", // provisional-only tasks are not certificate evidence (06 §5.4)
			"argMaxIf(e.verdict, (e.session_epoch, e.seq), e.stage_final)       AS fused_verdict",
			"argMaxIf(e.p_satisfied, (e.session_epoch, e.seq), e.stage_final)   AS p_satisfied",
			"any(e.session_id) AS session_id", // m1_021's task_digest = HMAC(root, session_id ‖ task_id)
			"AND event_type = 'VerdictEvent'",
			closedWindow,
		}},
		"memory_certified_sessions": {params: dayNext, terms: []string{
			"HAVING verdict != ''", // a task without a verdict is not a session to extract from
			"argMaxIf(e.verdict_stage, (e.session_epoch, e.seq), e.verdict != '') AS verdict_stage", // the terminal stage: extract.py refuses provisional by name
			"argMaxIf(e.noise_cert_id, (e.session_epoch, e.seq), e.verdict != '') AS noise_cert_id", // the cert the §5.4 live gate re-checks
			"maxIf(JSONExtractBool(e.payload, 'integrity', 'tamper'), e.event_type = 'AnchorVote') AS tamper",
			"::Tuple(digest String, kind String, payload String)", // the event shape extract.py's Session.events reads (digest = event_id)
			"arraySort(x -> (x.1, x.2), groupArray((e.session_epoch, e.seq, toString(e.event_id), e.event_type, e.payload)))",
			halfOpenWindow,
		}},
	}
	alias := regexp.MustCompile(`AS ([a-z_]+)`)
	for name, want := range shape {
		tpl, err := reg.Lookup(name)
		if err != nil {
			t.Fatal(err)
		}
		body := tpl.t.body
		var rows []map[string]any
		if err := json.Unmarshal(fixture[name], &rows); err != nil || len(rows) == 0 {
			t.Fatalf("%s: fixture rows: %v", name, err)
		}
		outer := body[:strings.Index(body, "\nFROM (")]
		aliases := map[string]bool{}
		for _, m := range alias.FindAllStringSubmatch(outer, -1) {
			aliases[m[1]] = true
		}
		for i, row := range rows {
			if len(row) != len(aliases) {
				t.Errorf("%s: fixture row %d has %d keys, template projects %d", name, i, len(row), len(aliases))
			}
			for col := range row {
				if !aliases[col] {
					t.Errorf("%s: consumer reads %q but the template does not project it:\n%s", name, col, outer)
				}
			}
		}
		for col := range aliases {
			if _, ok := rows[0][col]; !ok {
				t.Errorf("%s: template projects %q but the fixture (the consumers' row) lacks it", name, col)
			}
		}
		for _, w := range append(want.terms,
			"task_id != toUUID('00000000-0000-0000-0000-000000000000')",
			"LIMIT 1 BY event_id",
		) {
			if !strings.Contains(body, w) {
				t.Errorf("%s lost its contract term %q:\n%s", name, w, body)
			}
		}
		if regexp.MustCompile(`arg(Max|Min)If\([^)]*, [a-z.]*occurred_at[,)]`).MatchString(body) {
			t.Errorf("%s orders a join by occurred_at — 07 makes (session_epoch, seq) the only causal order", name)
		}
		if tpl.t.widenDates {
			t.Errorf("%s widens dates — the consumer's window would become three days", name)
		}
		q, err := Build(testTenant(t), tpl, want.params)
		if err != nil {
			t.Fatal(err)
		}
		for k, v := range want.params {
			if q.Bind()[k] != fmt.Sprint(v) {
				t.Errorf("%s: parameter %s moved: %s, want %v", name, k, q.Bind()[k], v)
			}
		}
		// Parameter negatives: every declared slot refuses injection-shaped text and
		// cannot be omitted; the reserved tid slot and an empty set refuse.
		bad := []Params{{}, clone(want.params)}
		bad[1]["tid"] = uuid.New()
		for k := range want.params {
			for _, evil := range []any{"2026-08-10' OR 1=1", "2026-08-10; DROP TABLE m1p_events", uuid.New().String() + "' OR 1=1"} {
				p := clone(want.params)
				p[k] = evil
				bad = append(bad, p)
			}
			p := clone(want.params)
			delete(p, k)
			bad = append(bad, p)
		}
		for _, p := range bad {
			if _, err := Build(testTenant(t), tpl, p); err == nil {
				t.Errorf("%s built with %v", name, p)
			}
		}
		// Marker negatives on THIS body: without the marker, or with a second one, load refuses (R4).
		for _, mutate := range []func(string) string{
			func(b string) string { return strings.Replace(b, "WHERE "+tenantMarker+"\n", "WHERE 1 = 1\n", 1) },
			func(b string) string {
				return strings.Replace(b, "WHERE "+tenantMarker, "WHERE "+tenantMarker+" AND "+tenantMarker, 1)
			},
		} {
			bad := *tpl.t
			bad.body = mutate(body)
			if bad.body == body {
				t.Fatalf("%s: mutant did not apply", name)
			}
			if _, err := loadFrom([]template{bad}); err == nil {
				t.Errorf("%s: loadFrom accepted a tenant-less or double-marker copy", name)
			}
		}
	}
}

// R4 marker/character-class negatives (05 §6.4): each bad registration must
// fail loadFrom — the same path MustLoadTemplates crashes boot through.
func TestLoadRefusesBadTemplates(t *testing.T) {
	base := func() template {
		return template{
			name: "t", version: "t.v1",
			body:     "SELECT day FROM tvo_tenant_day WHERE {{tenant_pred}} AND day = {from:Date}",
			params:   map[string]paramSpec{"from": {kind: pDate}},
			readSet:  []string{"tvo_tenant_day"},
			rowLimit: 10, timeout: time.Second,
		}
	}
	cases := []struct {
		name   string
		mutate func(*template)
	}{
		{"no tenant marker", func(t *template) {
			t.body = "SELECT day FROM tvo_tenant_day WHERE day = {from:Date}"
		}},
		{"two tenant markers", func(t *template) {
			t.body += " AND {{tenant_pred}}"
		}},
		{"statement separator", func(t *template) {
			t.body += "; SELECT 1"
		}},
		{"line comment token", func(t *template) {
			t.body += " -- sneak"
		}},
		{"block comment token", func(t *template) {
			t.body += " /* sneak */"
		}},
		{"undeclared body parameter", func(t *template) {
			t.body += " AND session_id = {sid:UUID}"
		}},
		{"declared but unused parameter", func(t *template) {
			t.params["ghost"] = paramSpec{kind: pDate}
		}},
		{"reserved tid parameter", func(t *template) {
			t.params["tid"] = paramSpec{kind: pUUID}
		}},
		{"direct tid reference", func(t *template) {
			t.body = "SELECT day FROM tvo_tenant_day WHERE {{tenant_pred}} AND day = {from:Date} AND tenant_id = {tid:UUID}"
		}},
		{"tenant_value marker on a read template", func(t *template) {
			t.body = "SELECT {{tenant_value}} AS x, day FROM tvo_tenant_day WHERE {{tenant_pred}} AND day = {from:Date}"
		}},
		{"table outside read set", func(t *template) {
			t.readSet = []string{"somewhere_else"}
		}},
		{"string param without character class", func(t *template) {
			t.body = "SELECT day FROM tvo_tenant_day WHERE {{tenant_pred}} AND task_seg_version = {s:String} AND day = {from:Date}"
			t.params["s"] = paramSpec{kind: pString}
		}},
		{"write flag outside the closed two-name set", func(t *template) {
			t.write = true
			t.body = "INSERT INTO tvo_tenant_day SELECT 1 WHERE {{tenant_pred}} AND day = {from:Date}"
		}},
		{"read template with zero row limit", func(t *template) {
			t.rowLimit = 0
		}},
		{"row limit above the 05 §6.5 ceiling", func(t *template) {
			t.rowLimit = maxRowLimit + 1
		}},
	}
	for _, tc := range cases {
		tpl := base()
		tc.mutate(&tpl)
		if _, err := loadFrom([]template{tpl}); err == nil {
			t.Errorf("%s: loadFrom accepted a template it must refuse (R4)", tc.name)
		}
	}
}

// The closed write set must be COMPLETE, not just bounded: dropping a write
// template from the registry must refuse load too, or a same-named read
// template could be introduced later without tripping the two-name rule.
func TestLoadRefusesMissingWriteTemplate(t *testing.T) {
	var pruned []template
	for _, tpl := range v1Templates {
		if tpl.name != "tvo_rollup_tenant_day" {
			pruned = append(pruned, tpl)
		}
	}
	if _, err := loadFrom(pruned); err == nil {
		t.Fatal("loadFrom accepted a registry missing a closed-set write template")
	}
}

// Injection attempts (05 §6.4 predicate fuzz's unit-lane cousin): a hostile
// parameter must be refused by its type/character class — it can never
// reach the SQL text at all (server-side binding), but the belt refuses it
// before it even reaches the wire.
func TestBuildRefusesInjectionShapedParams(t *testing.T) {
	reg, err := LoadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	tid := testTenant(t)

	rollup, err := reg.Lookup("tvo_rollup_tenant_day")
	if err != nil {
		t.Fatal(err)
	}
	good := dummyParams(rollup.t)

	// A '; DROP'-shaped value in the one string slot.
	p := clone(good)
	p["series"] = "task_seg.v1'; DROP TABLE tvo_tenant_day"
	if _, err := BuildWrite(tid, rollup, "job1", p); err == nil {
		t.Fatal("series accepted a statement-separator payload")
	}
	// A tenant_pred spoof riding a parameter value.
	p = clone(good)
	p["series"] = "x' OR tenant_id != '"
	if _, err := BuildWrite(tid, rollup, "job1", p); err == nil {
		t.Fatal("series accepted a predicate-spoof payload")
	}
	// A caller trying to bind the builder's tenant slot.
	p = clone(good)
	p["tid"] = uuid.New()
	if _, err := BuildWrite(tid, rollup, "job1", p); err == nil {
		t.Fatal("caller bound the reserved tid parameter")
	}
	// A date parameter smuggling SQL.
	usage, err := reg.Lookup("usage_by_session")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Build(tid, usage, Params{"from": "2026-08-28' OR 1=1", "to": "2026-08-29"}); err == nil {
		t.Fatal("date parameter accepted non-date text")
	}
	// UUID-array parameter smuggling text.
	canary, err := reg.Lookup("canary_dropped_rate")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Build(tid, canary, Params{
		"from": "2026-08-28 00:00:00", "to": "2026-08-29 00:00:00",
		"cohort": []any{"'] OR ['1"},
	}); err == nil {
		t.Fatal("uuid array accepted non-UUID text")
	}
}

func clone(p Params) Params {
	out := Params{}
	for k, v := range p {
		out[k] = v
	}
	return out
}

// The constructor/type discipline: a zero tenant cannot build; read and
// write constructors refuse each other's templates; the write path demands a
// job key in the ledger's character class (ADR-0010 §2.3).
func TestBuildTypeDiscipline(t *testing.T) {
	reg, err := LoadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	tid := testTenant(t)
	read, _ := reg.Lookup("coverage_band")
	write, _ := reg.Lookup("tvo_rollup_tenant_day")

	if _, err := Build(TenantID{}, read, dummyParams(read.t)); err == nil {
		t.Fatal("zero TenantID built a query")
	}
	if _, err := Build(tid, write, dummyParams(write.t)); err == nil {
		t.Fatal("Build accepted a write-shaped template")
	}
	if _, err := BuildWrite(tid, read, "job1", dummyParams(read.t)); err == nil {
		t.Fatal("BuildWrite accepted a read template")
	}
	if _, err := BuildWrite(tid, write, "", dummyParams(write.t)); err == nil {
		t.Fatal("BuildWrite accepted an empty job key (idempotency layer 2 is mandatory)")
	}
	if _, err := BuildWrite(tid, write, "job key with spaces'", dummyParams(write.t)); err == nil {
		t.Fatal("BuildWrite accepted a job key outside the ledger character class")
	}
	q, err := BuildWrite(tid, write, "tvo.rollup_tenant_day|2026-08-28|abcd", dummyParams(write.t))
	if err != nil {
		t.Fatal(err)
	}
	if q.JobKey() != "tvo.rollup_tenant_day|2026-08-28|abcd" {
		t.Fatalf("job key not carried onto the Query: %q", q.JobKey())
	}
	if _, err := reg.Lookup("no_such_template"); err == nil {
		t.Fatal("Lookup improvised a template")
	}
}

// ADR-0001 midnight-split: session-scoped templates widen the range ±1 day.
func TestBuildWidensSessionDateRange(t *testing.T) {
	reg, err := LoadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	usage, _ := reg.Lookup("usage_by_session")
	q, err := Build(testTenant(t), usage, Params{"from": "2026-08-10", "to": "2026-08-20"})
	if err != nil {
		t.Fatal(err)
	}
	if q.Bind()["from"] != "2026-08-09" || q.Bind()["to"] != "2026-08-21" {
		t.Fatalf("widen ±1 day not applied: from=%s to=%s", q.Bind()["from"], q.Bind()["to"])
	}
}

// The service-credential seam (ADR-0010 §2.2): an unverified cred or an
// empty configured secret must never mint a TenantID.
func TestServiceCredentialSeam(t *testing.T) {
	if _, err := VerifyServiceCredential("", "anything"); err == nil {
		t.Fatal("empty configured secret verified a caller")
	}
	if _, err := VerifyServiceCredential("s3cret", "wrong"); err == nil {
		t.Fatal("wrong credential verified")
	}
	cred, err := VerifyServiceCredential("s3cret", "s3cret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := FromServiceJob(ServiceCred{}, uuid.New()); err == nil {
		t.Fatal("unverified ServiceCred minted a TenantID")
	}
	if _, err := FromServiceJob(cred, uuid.Nil); err == nil {
		t.Fatal("nil tenant UUID minted a TenantID")
	}
	if _, err := FromServiceJob(cred, uuid.New()); err != nil {
		t.Fatal(err)
	}
}
