// builder.go — the construction proof's type layer (05 §6.2). The only
// executable value is Query; its only constructors are Build (reads) and
// BuildWrite (the two write carve-outs); both require a TenantID, and the
// builder itself writes the tenant predicate at the boot-proven marker — no
// caller ever writes WHERE. Values are bound as SERVER-SIDE {name:Type}
// parameters, never spliced into SQL text, so "escaping" is not a defense we
// rely on; the character-class checks below are the belt under that.
package querychoke

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Sentinel errors; the HTTP layer owns the 08 §9 mapping.
var (
	// ErrUnknownTemplate → 400 M1E-2008 (the chokepoint refuses, it does
	// not improvise).
	ErrUnknownTemplate = errors.New("querychoke: unknown query template")
	// ErrBadParams → 400 M1E-2001.
	ErrBadParams = errors.New("querychoke: parameter validation failed")
	// ErrRenderRefused: the 05 §6.2 render-time invariants tripped. Cannot
	// happen if boot validation is correct — which is why it also pages
	// (controld_querychoke_render_refusals_total, alerted in 11).
	ErrRenderRefused = errors.New("querychoke: render-time invariant violated")
	// ErrWriteTemplate / ErrReadTemplate: the constructor and the template's
	// declared shape disagree — "this template writes" is a checked
	// property, not a convention (05 §6.3).
	ErrWriteTemplate = errors.New("querychoke: write-shaped template requires BuildWrite")
	ErrReadTemplate  = errors.New("querychoke: read template refused by BuildWrite")
	// ErrTeamScope → 403 M1E-1001: a team member's read reached a template whose rows carry no device.
	ErrTeamScope = errors.New("querychoke: template not readable per person")
)

var renderRefusals = promauto.NewCounter(prometheus.CounterOpts{
	Name: "controld_querychoke_render_refusals_total",
	Help: "Render-time invariant violations (05 §6.2); any nonzero value pages — boot validation should make this impossible.",
})

// Params carries caller-supplied values keyed by declared parameter name.
// Values may be Go-typed (uuid.UUID, time.Time, uint64, []uuid.UUID) or the
// JSON shapes the §3.3 surface decodes (string, json.Number, []any).
type Params map[string]any

// Query is the executable value (05 §6.2). All fields unexported: the only
// consumers are Runner implementations in this package's subtree.
type Query struct {
	tpl *template
	sql string
	// bind is the server-side parameter set, ALWAYS including tid — the
	// suspenders test greps for it on every registered template's render.
	bind map[string]string
	// jobKey is set only by BuildWrite: idempotency layer 2's
	// insert_deduplication_token (ADR-0010 §2.3).
	jobKey string
}

// SQL/Bind/JobKey expose read-only views for the Runner and the render-grep
// tests; a Query cannot be assembled from them.
func (q Query) SQL() string             { return q.sql }
func (q Query) Bind() map[string]string { return q.bind }
func (q Query) JobKey() string          { return q.jobKey }
func (q Query) Template() Template      { return Template{t: q.tpl} }

// jobKeyClass bounds the dedup token: ClickHouse accepts arbitrary strings,
// but the key is also a ledger identity (intel_jobs.job_key), so it stays in
// a printable, quote-free class.
var jobKeyClass = regexp.MustCompile(`^[A-Za-z0-9._:=|-]{1,255}$`)

// Build renders a READ template for the given tenant (05 §6.2). The tenant
// comes from the verified token via the TenantID newtype — there is no
// parameter slot for it and no way to omit it.
func Build(t TenantID, tpl Template, p Params) (Query, error) {
	if tpl.t == nil {
		return Query{}, ErrUnknownTemplate
	}
	if tpl.t.write {
		return Query{}, ErrWriteTemplate
	}
	return build(t, tpl.t, p, "")
}

// BuildWrite renders one of the exactly-two write carve-outs (05 §6.3),
// requiring the job key that becomes insert_deduplication_token — the
// physical idempotency layer is not optional (ADR-0010 §2.3: a duplicate
// row merges additively and doubles TVO plausibly).
func BuildWrite(t TenantID, tpl Template, jobKey string, p Params) (Query, error) {
	if tpl.t == nil {
		return Query{}, ErrUnknownTemplate
	}
	if !tpl.t.write {
		return Query{}, ErrReadTemplate
	}
	if !jobKeyClass.MatchString(jobKey) {
		return Query{}, fmt.Errorf("%w: job_key must match %s", ErrBadParams, jobKeyClass)
	}
	return build(t, tpl.t, p, jobKey)
}

func build(t TenantID, tpl *template, p Params, jobKey string) (Query, error) {
	if t.IsZero() {
		return Query{}, ErrNoTenant
	}
	// Every declared parameter present, nothing undeclared present.
	for name := range p {
		if _, ok := tpl.params[name]; !ok && (name != deviceParam || !tpl.devices) {
			return Query{}, fmt.Errorf("%w: unknown parameter %q for template %q", ErrBadParams, name, tpl.name)
		}
	}
	bind := make(map[string]string, len(tpl.params)+2)
	for name, spec := range tpl.params {
		v, ok := p[name]
		if !ok {
			return Query{}, fmt.Errorf("%w: missing parameter %q for template %q", ErrBadParams, name, tpl.name)
		}
		enc, err := encodeParam(spec, v)
		if err != nil {
			return Query{}, fmt.Errorf("%w: parameter %q: %v", ErrBadParams, name, err)
		}
		bind[name] = enc
	}
	// ADR-0001 midnight-split rule: session-scoped templates widen the
	// required date range ±1 day so a session straddling midnight is not
	// truncated at the window edge.
	if tpl.widenDates {
		for name, delta := range map[string]int{"from": -1, "to": 1} {
			d, err := time.Parse(time.DateOnly, bind[name])
			if err != nil {
				return Query{}, fmt.Errorf("%w: %q: %v", ErrBadParams, name, err)
			}
			bind[name] = d.AddDate(0, 0, delta).Format(time.DateOnly)
		}
	}
	// The tenant predicate, BY CONSTRUCTION: the builder — not the caller —
	// substitutes the boot-proven markers and binds tid from the TenantID.
	// The value marker (write templates' projected tenant column) binds to
	// the SAME parameter the predicate re-asserts, so a write's row tenant
	// and its predicate tenant cannot diverge.
	pred := tenantPredSQL
	if devices, ok := p[deviceParam]; ok {
		enc, err := encodeParam(paramSpec{kind: pUUIDArray}, devices)
		if err != nil {
			return Query{}, fmt.Errorf("%w: parameter %q: %v", ErrBadParams, deviceParam, err)
		}
		bind[deviceParam], pred = enc, devicePredSQL
	}
	sql := strings.Replace(tpl.body, tenantMarker, pred, 1)
	sql = strings.ReplaceAll(sql, tenantValueMarker, tenantValueSQL)
	bind["tid"] = t.String()
	if !tpl.write {
		// 05 §6.5: builder-appended LIMIT; the m1p_query profile's
		// max_result_rows is the deliberately redundant server-side guard.
		sql = fmt.Sprintf("%s\nLIMIT %d", sql, tpl.rowLimit)
	}
	// Render-time invariants (05 §6.2): belt under the boot validation.
	// Violation increments the pager metric — it cannot happen if R4 held.
	if err := assertRendered(sql, bind); err != nil {
		renderRefusals.Inc()
		return Query{}, err
	}
	return Query{tpl: tpl, sql: sql, bind: bind, jobKey: jobKey}, nil
}

// assertRendered re-proves the rendered statement: exactly one statement, no
// comment token, the tenant predicate present and bound to the tenant.
func assertRendered(sql string, bind map[string]string) error {
	for _, tok := range []string{";", "--", "/*"} {
		if strings.Contains(sql, tok) {
			return fmt.Errorf("%w: rendered SQL contains %q", ErrRenderRefused, tok)
		}
	}
	if strings.Count(sql, tenantPredSQL) < 1 {
		return fmt.Errorf("%w: rendered SQL lacks the tenant predicate", ErrRenderRefused)
	}
	if _, err := uuid.Parse(bind["tid"]); err != nil {
		return fmt.Errorf("%w: tid binding is not a UUID", ErrRenderRefused)
	}
	if _, ok := bind[deviceParam]; ok && strings.Count(sql, devicePredSQL) != 1 {
		return fmt.Errorf("%w: device_ids bound but the device predicate is not rendered exactly once", ErrRenderRefused)
	}
	return nil
}

// narrow re-renders a built read to the given devices (the viewer filter, 15-teams): a template whose rows carry no device refuses rather than answer tenant-wide, and a caller-bound device list is replaced, never kept.
func narrow(q Query, devices []uuid.UUID) (Query, error) {
	if q.tpl == nil || !q.tpl.devices {
		name := ""
		if q.tpl != nil {
			name = q.tpl.name
		}
		return Query{}, fmt.Errorf("%w: template %q reads rows that carry no device", ErrTeamScope, name)
	}
	enc, err := encodeParam(paramSpec{kind: pUUIDArray}, devices)
	if err != nil {
		return Query{}, fmt.Errorf("%w: %v", ErrBadParams, err)
	}
	bind := make(map[string]string, len(q.bind)+1)
	for k, v := range q.bind {
		bind[k] = v
	}
	sql := q.sql
	if _, ok := q.bind[deviceParam]; !ok {
		sql = strings.Replace(sql, tenantPredSQL, devicePredSQL, 1)
	}
	bind[deviceParam] = enc
	if err := assertRendered(sql, bind); err != nil {
		renderRefusals.Inc()
		return Query{}, err
	}
	return Query{tpl: q.tpl, sql: sql, bind: bind, jobKey: q.jobKey}, nil
}

// encodeParam turns a typed value into the server-side parameter string.
// Everything is validated against its declared kind; the output strings are
// drawn from closed character sets (UUID text, digits, DateOnly, the
// declared charClass), so even the belt layer admits no SQL metacharacter.
func encodeParam(spec paramSpec, v any) (string, error) {
	switch spec.kind {
	case pUUID:
		id, err := asUUID(v)
		if err != nil {
			return "", err
		}
		return id.String(), nil
	case pDate:
		switch x := v.(type) {
		case time.Time:
			return x.UTC().Format(time.DateOnly), nil
		case string:
			d, err := time.Parse(time.DateOnly, x)
			if err != nil {
				return "", fmt.Errorf("want YYYY-MM-DD: %v", err)
			}
			return d.Format(time.DateOnly), nil
		}
		return "", fmt.Errorf("want date, got %T", v)
	case pDateTime:
		switch x := v.(type) {
		case time.Time:
			return x.UTC().Format(time.DateTime), nil
		case string:
			for _, layout := range []string{time.DateTime, time.RFC3339} {
				if d, err := time.Parse(layout, x); err == nil {
					return d.UTC().Format(time.DateTime), nil
				}
			}
			return "", fmt.Errorf("want RFC3339 or YYYY-MM-DD HH:MM:SS")
		}
		return "", fmt.Errorf("want datetime, got %T", v)
	case pUInt64:
		n, err := asUint64(v)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%d", n), nil
	case pDecimal:
		var s string
		switch x := v.(type) {
		case string:
			s = x
		case json.Number:
			s = x.String()
		default:
			return "", fmt.Errorf("want decimal string, got %T", v)
		}
		if !decimalClass.MatchString(s) {
			return "", fmt.Errorf("decimal %q outside %s", s, decimalClass)
		}
		return s, nil
	case pUUIDArray:
		ids, err := asUUIDSlice(v)
		if err != nil {
			return "", err
		}
		// ClickHouse array-parameter literal: elements single-quoted. UUID
		// text is [0-9a-f-] only, so the quotes cannot be escaped out of.
		parts := make([]string, len(ids))
		for i, id := range ids {
			parts[i] = "'" + id.String() + "'"
		}
		return "[" + strings.Join(parts, ",") + "]", nil
	case pString:
		s, ok := v.(string)
		if !ok {
			return "", fmt.Errorf("want string, got %T", v)
		}
		if !spec.charClass.MatchString(s) {
			return "", fmt.Errorf("value %q outside declared character class %s", s, spec.charClass)
		}
		return s, nil
	}
	return "", fmt.Errorf("unhandled parameter kind %d", spec.kind)
}

var (
	decimalClass = regexp.MustCompile(`^[0-9]{1,18}(\.[0-9]{1,8})?$`)
	digitsClass  = regexp.MustCompile(`^[0-9]{1,19}$`)
)

func asUUID(v any) (uuid.UUID, error) {
	switch x := v.(type) {
	case uuid.UUID:
		if x == uuid.Nil {
			return uuid.Nil, fmt.Errorf("nil UUID refused")
		}
		return x, nil
	case string:
		id, err := uuid.Parse(x)
		if err != nil || id == uuid.Nil {
			return uuid.Nil, fmt.Errorf("not a UUID")
		}
		return id, nil
	}
	return uuid.Nil, fmt.Errorf("want UUID, got %T", v)
}

func asUUIDSlice(v any) ([]uuid.UUID, error) {
	switch xs := v.(type) {
	case []uuid.UUID:
		return xs, nil
	case []string:
		out := make([]uuid.UUID, len(xs))
		for i, s := range xs {
			id, err := uuid.Parse(s)
			if err != nil {
				return nil, fmt.Errorf("element %d: not a UUID", i)
			}
			out[i] = id
		}
		return out, nil
	case []any: // JSON decode shape
		out := make([]uuid.UUID, len(xs))
		for i, e := range xs {
			s, ok := e.(string)
			if !ok {
				return nil, fmt.Errorf("element %d: want string UUID, got %T", i, e)
			}
			id, err := uuid.Parse(s)
			if err != nil {
				return nil, fmt.Errorf("element %d: not a UUID", i)
			}
			out[i] = id
		}
		return out, nil
	}
	return nil, fmt.Errorf("want UUID array, got %T", v)
}

func asUint64(v any) (uint64, error) {
	switch x := v.(type) {
	case uint64:
		return x, nil
	case int:
		if x < 0 {
			return 0, fmt.Errorf("negative")
		}
		return uint64(x), nil
	case int64:
		if x < 0 {
			return 0, fmt.Errorf("negative")
		}
		return uint64(x), nil
	case json.Number:
		n, err := x.Int64()
		if err != nil || n < 0 {
			return 0, fmt.Errorf("want non-negative integer")
		}
		return uint64(n), nil
	case float64:
		// Tolerated for handler convenience only; a float that lost integer
		// precision is refused rather than rounded.
		if x < 0 || x != math.Trunc(x) || x > float64(1<<53) {
			return 0, fmt.Errorf("want exact non-negative integer")
		}
		return uint64(x), nil
	case string:
		if !digitsClass.MatchString(x) {
			return 0, fmt.Errorf("want digits")
		}
		var n uint64
		if _, err := fmt.Sscanf(x, "%d", &n); err != nil {
			return 0, err
		}
		return n, nil
	}
	return 0, fmt.Errorf("want unsigned integer, got %T", v)
}
