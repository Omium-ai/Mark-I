// templates.go — the closed template registry (05 §6.3). Templates are
// Go-embedded as a const table: compiled in, never loaded from disk, because
// a runtime-writable template store would be the escape hatch reborn.
// Loading VALIDATES every entry (boot refusal R4, 05 §1.2): a template
// without the {{tenant_pred}} marker, with an undeclared or unused
// parameter, with a statement separator or comment token, or write-flagged
// outside the closed two-name set refuses BOOT — a tenant-less template must
// never be registerable, even transiently.
//
// Adding a template is a PR that adds a registry entry plus its negative
// tests, reviewed as a security change; adding a write-shaped one is an ADR
// (05 §6.3). Table names are UNQUALIFIED: the database rides the connection
// (production "mark1", scratch in tests), never the SQL text.
package querychoke

import (
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"
)

// tenantMarker is the mandatory marker every template body carries exactly
// once (05 §6.2). Build substitutes it — and only it — with the predicate
// text; callers never write WHERE.
const tenantMarker = "{{tenant_pred}}"

// tenantPredSQL is what the marker renders to. The tid parameter is bound by
// Build from the TenantID; no template may declare a caller slot for it.
const tenantPredSQL = "tenant_id = {tid:UUID}"

// tenantValueMarker is the second builder-owned marker, WRITE templates
// only: an insert must also PROJECT the tenant as a column value, and that
// value must be the same builder-bound tid the predicate re-asserts —
// letting a body reference {tid:...} directly would blur who owns the slot,
// so the value travels through a marker exactly like the predicate does.
const tenantValueMarker = "{{tenant_value}}"

// tenantValueSQL renders the value marker to the same bound parameter.
const tenantValueSQL = "{tid:UUID}"

// Timeout classes (05 §6.5).
const (
	timeoutReport      = 30 * time.Second
	timeoutInteractive = 5 * time.Second
)

// maxRowLimit is the 05 §6.5 ceiling: a template may declare lower, never
// higher (the m1p_query profile's max_result_rows is the redundant guard).
const maxRowLimit = 100_000

type paramKind int

const (
	pUUID paramKind = iota
	pDate
	pDateTime
	pUInt64
	pDecimal
	pUUIDArray
	pString // must carry a charClass — there is no free-text type (05 §6.2)
)

// chType is the server-side parameter type each kind renders as; boot
// validation requires the body's {name:Type} annotation to match exactly.
func (k paramKind) chType() string {
	switch k {
	case pUUID:
		return "UUID"
	case pDate:
		return "Date"
	case pDateTime:
		return "DateTime"
	case pUInt64:
		return "UInt64"
	case pDecimal:
		return "Decimal64(8)"
	case pUUIDArray:
		return "Array(UUID)"
	case pString:
		return "String"
	}
	return "?"
}

type paramSpec struct {
	kind paramKind
	// charClass constrains pString values (mandatory for pString). It is a
	// BELT: every value additionally travels as a server-side parameter, so
	// even an admitted value cannot alter statement shape.
	charClass *regexp.Regexp
}

// template is the registry entry (unexported: the only handles callers get
// are the opaque Template from Lookup and the Query from Build).
type template struct {
	name    string
	version string
	write   bool
	body    string
	params  map[string]paramSpec
	// readSet: every table the body may reference; boot-validated against
	// the FROM/INTO/JOIN targets actually present (05 §6.3 "read set").
	readSet []string
	// rowLimit: reads only; Build appends LIMIT (05 §6.5).
	rowLimit int
	timeout  time.Duration
	// widenDates: session-scoped templates take a required date range and
	// Build widens it ±1 day — the ADR-0001 midnight-split rule.
	widenDates bool
}

// seriesClass admits task_seg version/series labels: "task_seg.v1",
// "task_seg.v1-restated.2" (ADR-0010 §2.6). Deliberately excludes quotes,
// backslashes, spaces and every SQL metacharacter.
var seriesClass = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*$`)

// v1Templates is the closed v1 set: exactly what 08 §3.3 exposes plus the
// internal consumers named by 05 §6.3 — the read templates, and the exactly
// two write-shaped carve-outs.
var v1Templates = []template{
	{
		// 08 §3.3 GET /reports/tvo — the certified-report read over the
		// tenant-day rollup (the table ADR-0010's writer feeds). Grouped by
		// series so a restated day shows as two rows, never blended.
		name:    "tvo_report",
		version: "tvo_report.v1",
		body: `SELECT day,
       task_seg_version,
       sumMerge(tokens_total)           AS tokens_total,
       toFloat64(sumMerge(cost_usd))    AS cost_usd,
       uniqExactMerge(tasks_verified)   AS tasks_verified,
       uniqExactMerge(tasks_unresolved) AS tasks_unresolved,
       sumMerge(retry_loop_tokens)      AS retry_loop_tokens,
       sumMerge(reexploration_tokens)   AS reexploration_tokens,
       sumMerge(over_model_tokens)      AS over_model_tokens,
       sumMerge(observed_ms)            AS observed_ms,
       sumMerge(bypass_ms)              AS bypass_ms,
       sumMerge(disabled_ms)            AS disabled_ms,
       sumMerge(dropped_billing)        AS dropped_billing
FROM tvo_tenant_day
WHERE {{tenant_pred}} AND day BETWEEN {from:Date} AND {to:Date}
GROUP BY day, task_seg_version
ORDER BY day, task_seg_version`,
		params:   map[string]paramSpec{"from": {kind: pDate}, "to": {kind: pDate}},
		readSet:  []string{"tvo_tenant_day"},
		rowLimit: 10_000,
		timeout:  timeoutReport,
	},
	{
		// 08 §3.3 GET /reports/interventions — knee arrests at task grain.
		// The arrest evidence rides GuardDecision payloads; the verdict is
		// the task's terminal one (argMax over verdict-bearing rows).
		// The inner subselect is the mandatory reader dedupe (07 §"m1p_events"
		// engine note / §7: transport is at-least-once and ReplacingMergeTree
		// collapse is EVENTUAL — `LIMIT 1 BY event_id`, never FINAL on hot
		// paths, or a replayed batch double-counts until background merges).
		// Column references are qualified `e.` for the same reason
		// m1_ch_002's mv_tvo_task does it: `... AS verdict` over
		// `e.verdict != ''` resolves the unqualified alias recursively and
		// ClickHouse rejects the aggregate-in-WHERE cycle.
		name:    "interventions",
		version: "interventions.v2",
		body: `SELECT e.task_id AS task_id,
       sumIf(JSONExtractUInt(e.payload, 'tokens_saved_estimate'), e.event_type = 'GuardDecision') AS tokens_saved_estimate,
       countIf(e.event_type = 'GuardDecision')              AS arrests,
       argMaxIf(e.verdict, e.occurred_at, e.verdict != '')  AS verdict,
       anyLastIf(e.bundle_seq, e.event_type = 'GuardDecision') AS bundle_seq
FROM (SELECT event_id, task_id, occurred_at, event_type, payload, verdict, bundle_seq
      FROM m1p_events
      WHERE {{tenant_pred}}
        AND toDate(occurred_at) BETWEEN {from:Date} AND {to:Date}
        AND task_id != toUUID('00000000-0000-0000-0000-000000000000')
        AND (event_type = 'GuardDecision' OR verdict != '')
      LIMIT 1 BY event_id) AS e
GROUP BY e.task_id
HAVING arrests > 0
ORDER BY tokens_saved_estimate DESC`,
		params:   map[string]paramSpec{"from": {kind: pDate}, "to": {kind: pDate}},
		readSet:  []string{"m1p_events"},
		rowLimit: 10_000,
		timeout:  timeoutReport,
	},
	{
		// 08 §3.3 POST /query — per-session usage over the session rollup.
		// Session-scoped ⇒ required date range widened ±1 day (ADR-0001
		// midnight-split: a session straddling midnight shows on both days).
		name:    "usage_by_session",
		version: "usage_by_session.v1",
		body: `SELECT day,
       session_id,
       any(agent)                          AS agent,
       sumMerge(tokens_in)                 AS tokens_in,
       sumMerge(tokens_out)                AS tokens_out,
       sumMerge(tokens_cache_read)         AS tokens_cache_read,
       sumMerge(tokens_cache_create)       AS tokens_cache_create,
       toFloat64(sumMerge(cost_usd))       AS cost_usd,
       uniqExactMerge(tasks_opened)        AS tasks_opened,
       uniqExactIfMerge(tasks_satisfied)   AS tasks_satisfied,
       uniqExactIfMerge(tasks_violated)    AS tasks_violated,
       uniqExactIfMerge(tasks_refused)     AS tasks_refused,
       uniqExactIfMerge(tasks_error)       AS tasks_error,
       uniqExactIfMerge(tasks_unresolved)  AS tasks_unresolved,
       sumMerge(dropped_billing)           AS dropped_billing
FROM tvo_session
WHERE {{tenant_pred}} AND day BETWEEN {from:Date} AND {to:Date}
GROUP BY day, session_id
ORDER BY day, session_id`,
		params:     map[string]paramSpec{"from": {kind: pDate}, "to": {kind: pDate}},
		readSet:    []string{"tvo_session"},
		rowLimit:   50_000,
		timeout:    timeoutReport,
		widenDates: true,
	},
	{
		// Coverage-band inputs per day (07: observed/bypass/disabled are
		// columns of the tenant-day row — a missing day is 0/0, which the
		// report layer refuses rather than stretches, ADR-0010 §2.7).
		name:    "coverage_band",
		version: "coverage_band.v1",
		body: `SELECT day,
       sumMerge(observed_ms)     AS observed_ms,
       sumMerge(bypass_ms)       AS bypass_ms,
       sumMerge(disabled_ms)     AS disabled_ms,
       sumMerge(dropped_billing) AS dropped_billing
FROM tvo_tenant_day
WHERE {{tenant_pred}} AND day BETWEEN {from:Date} AND {to:Date}
GROUP BY day
ORDER BY day`,
		params:   map[string]paramSpec{"from": {kind: pDate}, "to": {kind: pDate}},
		readSet:  []string{"tvo_tenant_day"},
		rowLimit: 1_000,
		timeout:  timeoutInteractive,
	},
	{
		// Shed accounting for the coverage band (06 §8.2, formula normative in
		// 07): per day, the two terms reader.py's coverage_inputs REQUIRES by
		// name — `dropped_billing` and `events_billing_ingested` — so the
		// column set here IS a cross-language contract (a rename either side
		// alone is a red test: TestDroppedByTenantDayServesCoverageInputs here,
		// _require() in reader.py there).
		//   - dropped_billing filters the loss ledger on
		//     dropped_durability_class = 'billing_grade' — NEVER on
		//     event_class: a Dropped{} row is itself diagnostic-class;
		//     event_class describes the row, dropped_durability_class the
		//     thing that was LOST (the m1_ch_002 mv_tvo_session lesson: the
		//     event_class filter sums to zero forever and the band never
		//     narrows).
		//   - events_billing_ingested counts rows that DID land whose OWN
		//     class is billing (07 §"Why durability_class": the band narrows
		//     by dropped / (dropped + ingested)).
		name:    "dropped_by_tenant_day",
		version: "dropped_by_tenant_day.v2",
		body: `SELECT toDate(occurred_at)     AS day,
       sumIf(dropped_quantity, event_type = 'Dropped'
                          AND dropped_durability_class = 'billing_grade') AS dropped_billing,
       countIf(event_class = 'billing') AS events_billing_ingested
FROM (SELECT event_id, occurred_at, event_type, event_class,
             dropped_durability_class, dropped_quantity
      FROM m1p_events
      WHERE {{tenant_pred}}
        AND toDate(occurred_at) BETWEEN {from:Date} AND {to:Date}
      LIMIT 1 BY event_id) AS e
GROUP BY day
ORDER BY day`,
		params:   map[string]paramSpec{"from": {kind: pDate}, "to": {kind: pDate}},
		readSet:  []string{"m1p_events"},
		rowLimit: 10_000,
		timeout:  timeoutInteractive,
	},
	{
		// 05 §4.3(c) canary signal 1 of 3: gate block rate, cohort vs
		// control, within one tenant's rollout (canarying is per
		// (tenant, bundle seq), so these are tenant-scoped like every other
		// template). Consumed by policydist's controller (WS-6), 5-min ticks.
		// All three canary bodies carry the mandatory m1p_events reader
		// dedupe (LIMIT 1 BY event_id — see `interventions`): a replayed
		// batch inflating one arm's counts would move a rollout decision.
		name:    "canary_gate_block_rate",
		version: "canary_gate_block_rate.v2",
		body: `SELECT if(has({cohort:Array(UUID)}, device_id), 'cohort', 'control') AS arm,
       countIf(event_type = 'GuardDecision' AND JSONExtractString(payload, 'decision') = 'block') AS blocks,
       countIf(event_type = 'GuardDecision') AS decisions
FROM (SELECT event_id, device_id, event_type, payload
      FROM m1p_events
      WHERE {{tenant_pred}} AND occurred_at >= {from:DateTime} AND occurred_at < {to:DateTime}
      LIMIT 1 BY event_id) AS e
GROUP BY arm`,
		params: map[string]paramSpec{
			"from": {kind: pDateTime}, "to": {kind: pDateTime}, "cohort": {kind: pUUIDArray},
		},
		readSet:  []string{"m1p_events"},
		rowLimit: 10,
		timeout:  timeoutInteractive,
	},
	{
		// Canary signal 2 of 3: Dropped{} rate, cohort vs control.
		name:    "canary_dropped_rate",
		version: "canary_dropped_rate.v2",
		body: `SELECT if(has({cohort:Array(UUID)}, device_id), 'cohort', 'control') AS arm,
       sumIf(dropped_quantity, event_type = 'Dropped') AS dropped,
       count() AS events
FROM (SELECT event_id, device_id, event_type, dropped_quantity
      FROM m1p_events
      WHERE {{tenant_pred}} AND occurred_at >= {from:DateTime} AND occurred_at < {to:DateTime}
      LIMIT 1 BY event_id) AS e
GROUP BY arm`,
		params: map[string]paramSpec{
			"from": {kind: pDateTime}, "to": {kind: pDateTime}, "cohort": {kind: pUUIDArray},
		},
		readSet:  []string{"m1p_events"},
		rowLimit: 10,
		timeout:  timeoutInteractive,
	},
	{
		// Canary signal 3 of 3: fused-violated rate over stage-final
		// verdicts, cohort vs control.
		name:    "canary_fused_violated_rate",
		version: "canary_fused_violated_rate.v2",
		body: `SELECT if(has({cohort:Array(UUID)}, device_id), 'cohort', 'control') AS arm,
       uniqExactIf(task_id, verdict = 'violated' AND verdict_stage IN ('certified', 'revised')) AS violated_tasks,
       uniqExactIf(task_id, verdict != '' AND verdict_stage IN ('certified', 'revised'))        AS verdict_tasks
FROM (SELECT event_id, device_id, task_id, verdict, verdict_stage
      FROM m1p_events
      WHERE {{tenant_pred}} AND occurred_at >= {from:DateTime} AND occurred_at < {to:DateTime}
      LIMIT 1 BY event_id) AS e
GROUP BY arm`,
		params: map[string]paramSpec{
			"from": {kind: pDateTime}, "to": {kind: pDateTime}, "cohort": {kind: pUUIDArray},
		},
		readSet:  []string{"m1p_events"},
		rowLimit: 10,
		timeout:  timeoutInteractive,
	},
	{
		// WRITE CARVE-OUT 1 of exactly 2 (05 §6.3; ADR-0010 §2 — UNSIGNED:
		// no production write may occur; the HTTP seam that drives this ships
		// behind an explicit run flag). mark1-intel's tvo.rollup_tenant_day
		// job DRIVES this insert with the complete row (it joins tvo_task
		// terms with the Postgres coverage_transitions durations — the
		// cross-store join no MV can do); querychoke EXECUTES it, because
		// intel never holds a ClickHouse credential.
		//
		// The {{tenant_pred}} marker does real work here: the inserted row's
		// tenant_id column IS the Build-bound tid (the one-row FROM clause),
		// and the predicate re-asserts it — a row for a different tenant is
		// inexpressible, not just unreviewed. Idempotency layer 2 rides the
		// execution (insert_deduplication_token = job_key); layer 3 is this
		// statement's shape: one (tenant, day, series) = one row = one block.
		name:    "tvo_rollup_tenant_day",
		version: "tvo_rollup_tenant_day.v1",
		write:   true,
		body: `INSERT INTO tvo_tenant_day (tenant_id, day, task_seg_version, tokens_total, cost_usd, tasks_verified, tasks_unresolved, retry_loop_tokens, reexploration_tokens, over_model_tokens, observed_ms, bypass_ms, disabled_ms, dropped_billing)
SELECT tenant_id,
       {day:Date},
       {series:String},
       initializeAggregation('sumState', {tokens_total:UInt64}),
       initializeAggregation('sumState', {cost_usd:Decimal64(8)}),
       arrayReduce('uniqExactState', {tasks_verified:Array(UUID)}),
       arrayReduce('uniqExactState', {tasks_unresolved:Array(UUID)}),
       initializeAggregation('sumState', {retry_loop_tokens:UInt64}),
       initializeAggregation('sumState', {reexploration_tokens:UInt64}),
       initializeAggregation('sumState', {over_model_tokens:UInt64}),
       initializeAggregation('sumState', {observed_ms:UInt64}),
       initializeAggregation('sumState', {bypass_ms:UInt64}),
       initializeAggregation('sumState', {disabled_ms:UInt64}),
       initializeAggregation('sumState', {dropped_billing:UInt64})
FROM (SELECT {{tenant_value}} AS tenant_id)
WHERE {{tenant_pred}}`,
		params: map[string]paramSpec{
			"day":                  {kind: pDate},
			"series":               {kind: pString, charClass: seriesClass},
			"tokens_total":         {kind: pUInt64},
			"cost_usd":             {kind: pDecimal},
			"tasks_verified":       {kind: pUUIDArray},
			"tasks_unresolved":     {kind: pUUIDArray},
			"retry_loop_tokens":    {kind: pUInt64},
			"reexploration_tokens": {kind: pUInt64},
			"over_model_tokens":    {kind: pUInt64},
			"observed_ms":          {kind: pUInt64},
			"bypass_ms":            {kind: pUInt64},
			"disabled_ms":          {kind: pUInt64},
			"dropped_billing":      {kind: pUInt64},
		},
		readSet: []string{"tvo_tenant_day"},
		timeout: timeoutReport,
	},
	{
		// WRITE CARVE-OUT 2 of exactly 2 (05 §6.3): the offboarding deletion
		// mutation (07's deletion path). OpsScope + the two-person
		// offboarding role gate its INVOCATION (that job is not in this
		// wave; no route serves this template); the template itself is still
		// Build-constructed with the mandatory marker, so even the
		// offboarding job cannot express a cross-tenant delete.
		// ponytail: deletes the base ledger only — the rollup tables' rows
		// for an offboarded tenant are a follow-up to the deletion-path job
		// (one statement per template; the closed two-name set forbids three
		// more delete templates without an ADR).
		name:    "offboard_delete_tenant",
		version: "offboard_delete_tenant.v1",
		write:   true,
		body:    `DELETE FROM m1p_events WHERE {{tenant_pred}}`,
		params:  map[string]paramSpec{},
		readSet: []string{"m1p_events"},
		timeout: timeoutReport,
	},
}

// writeNames is the CLOSED set of write-shaped template names (05 §6.3:
// "exactly two"; extending it is an ADR, and the loader refuses any other
// write-flagged name so the extension cannot happen by accident).
var writeNames = map[string]bool{
	"offboard_delete_tenant": true,
	"tvo_rollup_tenant_day":  true,
}

// Registry is the boot-validated closed set. The only way to execute SQL
// above chconn is a Template obtained from Lookup on a loaded Registry.
type Registry struct {
	byName map[string]*template
}

// Template is the opaque handle (05 §6.2): obtainable only via Lookup.
type Template struct {
	t *template
}

// Name is exported for logging/metrics labels only.
func (t Template) Name() string { return t.t.name }

// Version rides 08 §3.3's template_version response field.
func (t Template) Version() string { return t.t.version }

// IsWrite exposes the registry's write flag so surfaces can refuse
// write-shaped templates without switching on names.
func (t Template) IsWrite() bool { return t.t.write }

// paramRef matches server-side parameter references {name:Type} in a body.
var paramRef = regexp.MustCompile(`\{([A-Za-z_][A-Za-z0-9_]*):([^}]+)\}`)

// tableRef matches FROM/INTO/JOIN targets; "(" starts a subquery and is
// exempt. Boot-time only — bodies are const, so this never sees user input.
var tableRef = regexp.MustCompile(`(?i)\b(FROM|INTO|JOIN)\s+([A-Za-z_][A-Za-z0-9_.]*)`)

// LoadTemplates validates the const table into a Registry. Every error here
// is boot refusal R4 material (05 §1.2): the caller is MustLoadTemplates.
func LoadTemplates() (*Registry, error) {
	return loadFrom(v1Templates)
}

// loadFrom is the seam the R4 negative tests aim at (05 §6.4 "marker
// negative": registering a bad template must fail HERE, so R4 can't rot).
func loadFrom(entries []template) (*Registry, error) {
	r := &Registry{byName: make(map[string]*template, len(entries))}
	for i := range entries {
		t := &entries[i]
		if err := validate(t); err != nil {
			return nil, fmt.Errorf("querychoke: template %q: %w (boot refusal R4, 05 §1.2)", t.name, err)
		}
		if _, dup := r.byName[t.name]; dup {
			return nil, fmt.Errorf("querychoke: template %q registered twice (boot refusal R4, 05 §1.2)", t.name)
		}
		r.byName[t.name] = t
	}
	// The closed write set must be fully present too: a registry that lost a
	// write template silently would let a same-named READ template be added
	// later without tripping the two-name rule.
	for name := range writeNames {
		if t, ok := r.byName[name]; !ok || !t.write {
			return nil, fmt.Errorf("querychoke: write template %q missing or not write-flagged (05 §6.3 closed set; boot refusal R4)", name)
		}
	}
	return r, nil
}

func validate(t *template) error {
	if t.name == "" || t.version == "" {
		return fmt.Errorf("unnamed or unversioned template")
	}
	// Exactly one marker: zero is a tenant-less query; two is a template
	// whose second predicate the builder would not bind.
	if n := strings.Count(t.body, tenantMarker); n != 1 {
		return fmt.Errorf("body contains %d %s markers, want exactly 1", n, tenantMarker)
	}
	// Character-class refusals (R4): one statement, no comment tokens.
	for _, tok := range []string{";", "--", "/*"} {
		if strings.Contains(t.body, tok) {
			return fmt.Errorf("body contains forbidden token %q", tok)
		}
	}
	// The tid slot belongs to Build alone.
	if _, declared := t.params["tid"]; declared {
		return fmt.Errorf("parameter name \"tid\" is reserved for the builder-bound tenant")
	}
	if strings.Contains(t.body, "{tid:") {
		return fmt.Errorf("body references {tid:...} directly; the tenant binds only via %s / %s", tenantMarker, tenantValueMarker)
	}
	// The value marker is write-only: a read never needs the tenant as a
	// projected value, so admitting it there would only widen the surface.
	if !t.write && strings.Contains(t.body, tenantValueMarker) {
		return fmt.Errorf("read template carries %s (write templates only)", tenantValueMarker)
	}
	// Every {name:Type} in the body is declared with the matching type, and
	// every declared parameter is used — an unknown parameter is R4.
	seen := map[string]bool{}
	for _, m := range paramRef.FindAllStringSubmatch(t.body, -1) {
		name, chType := m[1], m[2]
		spec, ok := t.params[name]
		if !ok {
			return fmt.Errorf("body references undeclared parameter {%s:%s}", name, chType)
		}
		if spec.kind.chType() != chType {
			return fmt.Errorf("parameter %q declared %s but body annotates %s", name, spec.kind.chType(), chType)
		}
		seen[name] = true
	}
	for name, spec := range t.params {
		if !seen[name] {
			return fmt.Errorf("declared parameter %q never appears in the body", name)
		}
		if spec.kind == pString && spec.charClass == nil {
			return fmt.Errorf("string parameter %q lacks a character class (05 §6.2: no free-text parameter type exists)", name)
		}
	}
	// Read set: every FROM/INTO/JOIN target must be declared.
	rs := map[string]bool{}
	for _, tbl := range t.readSet {
		rs[tbl] = true
	}
	for _, m := range tableRef.FindAllStringSubmatch(t.body, -1) {
		if !rs[m[2]] {
			return fmt.Errorf("body references table %q outside the declared read set %v", m[2], t.readSet)
		}
	}
	// Write flag discipline (05 §6.3): the flag is a validated, closed
	// property, not an inference from the SQL.
	if t.write {
		if !writeNames[t.name] {
			return fmt.Errorf("write-flagged template outside the closed two-name set (05 §6.3: adding one is an ADR)")
		}
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(t.body)), "SELECT") {
			return fmt.Errorf("write-flagged template body is a SELECT")
		}
	} else {
		if !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(t.body)), "SELECT") {
			return fmt.Errorf("read template body must be a single SELECT statement")
		}
		if t.rowLimit <= 0 || t.rowLimit > maxRowLimit {
			return fmt.Errorf("read template row limit %d outside (0, %d]", t.rowLimit, maxRowLimit)
		}
	}
	if t.timeout <= 0 {
		return fmt.Errorf("template has no timeout class")
	}
	if t.widenDates {
		for _, p := range []string{"from", "to"} {
			if spec, ok := t.params[p]; !ok || spec.kind != pDate {
				return fmt.Errorf("widenDates requires a %q Date parameter (ADR-0001 midnight-split rule)", p)
			}
		}
	}
	return nil
}

// MustLoadTemplates is boot step 7 (05 §1.1) — refusal R4, deliberately
// un-caught so the pod crashloops and the deploy is visibly broken. This
// closes cmd/controld's deferred-R4 note.
func MustLoadTemplates() *Registry {
	r, err := LoadTemplates()
	if err != nil {
		log.Fatalf("querychoke: %v", err)
	}
	return r
}

// Lookup is the ONLY way to obtain a Template (05 §6.2). Unknown name ⇒
// ErrUnknownTemplate, which the HTTP layer maps to 400 M1E-2008: the
// chokepoint refuses, it does not improvise.
func (r *Registry) Lookup(name string) (Template, error) {
	t, ok := r.byName[name]
	if !ok {
		return Template{}, fmt.Errorf("%w: %q", ErrUnknownTemplate, name)
	}
	return Template{t: t}, nil
}

// Names returns every registered template name — for the render-grep suite
// that proves EVERY template's render output carries the predicate.
func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.byName))
	for n := range r.byName {
		out = append(out, n)
	}
	return out
}
