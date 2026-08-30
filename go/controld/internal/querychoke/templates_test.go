package querychoke

// The 05 §6.4 negative suites that keep R4 from rotting: marker negatives
// against loadFrom (registering a bad template must fail LOADING, never
// reach a runtime check), the render-grep over EVERY registered template
// (suspenders under the type layer's belt), and the injection attempts the
// parameter layer must refuse.

import (
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
