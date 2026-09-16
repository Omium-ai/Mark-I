package appapi

// The storeless contract: a fake Runner that serves rows per (template, bound tenant) — so a handler can only ever see the rows the tenant it bound is entitled to — under the REAL querychoke module for the honesty fields and the real template registry for every Build. Every response is validated against its schema/ file.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
)

type fakeRunner struct {
	rows map[string]map[string][]map[string]any // template → tid → rows
	seen []querychoke.Query
	fail map[string]error
}

func (f *fakeRunner) Run(_ context.Context, q querychoke.Query) (*querychoke.Rows, error) {
	f.seen = append(f.seen, q)
	name := q.Template().Name()
	if err := f.fail[name]; err != nil {
		return nil, err
	}
	return &querychoke.Rows{Rows: f.rows[name][q.Bind()["tid"]]}, nil
}

func (f *fakeRunner) add(template string, tenant uuid.UUID, rows ...map[string]any) {
	if f.rows == nil {
		f.rows = map[string]map[string][]map[string]any{}
	}
	if f.rows[template] == nil {
		f.rows[template] = map[string][]map[string]any{}
	}
	f.rows[template][tenant.String()] = append(f.rows[template][tenant.String()], rows...)
}

const testKey = "appapi-test-key"

type rig struct {
	t       *testing.T
	mux     *http.ServeMux
	run     *fakeRunner
	schemas *schemaSet
	tenantA uuid.UUID
	tenantB uuid.UUID
	tokenA  string
	tokenB  string
}

func newRig(t *testing.T) *rig {
	t.Helper()
	reg, err := querychoke.LoadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	run := &fakeRunner{}
	verifier := auth.NewHMACVerifier([]byte(testKey), auth.StaticRevocations{})
	obsCfg := obs.Config{ServiceName: "appapi-test"}
	reports := querychoke.New(querychoke.Deps{Registry: reg, Runner: run, Verifier: verifier, ObsCfg: obsCfg})
	m := New(Deps{Verifier: verifier, ObsCfg: obsCfg, Registry: reg, Runner: run, Reports: reports})
	mux := http.NewServeMux()
	m.RegisterRoutes(mux)
	reports.RegisterRoutes(mux)
	r := &rig{t: t, mux: mux, run: run, schemas: loadSchemas(t), tenantA: uuid.New(), tenantB: uuid.New()}
	r.tokenA = auth.Mint([]byte(testKey), r.tenantA, uuid.New(), time.Hour)
	r.tokenB = auth.Mint([]byte(testKey), r.tenantB, uuid.New(), time.Hour)
	for _, tenant := range []uuid.UUID{r.tenantA, r.tenantB} {
		r.seedReport(tenant)
	}
	return r
}

// seedReport plants a shed-free, in-band rollup day so /reports/tvo issues guarantee grade for the tenant; the seeded day is today so any window covers it.
func (r *rig) seedReport(tenant uuid.UUID) {
	r.run.add("tvo_report", tenant, map[string]any{
		"day": time.Now().UTC(), "task_seg_version": "task_seg.v1",
		"tokens_total": uint64(300), "tasks_verified": uint64(3), "tasks_unresolved": uint64(0),
		"retry_loop_tokens": uint64(10), "reexploration_tokens": uint64(20), "over_model_tokens": uint64(30),
		"observed_ms": uint64(980), "bypass_ms": uint64(20), "disabled_ms": uint64(0), "dropped_billing": uint64(0),
	})
	r.run.add("dropped_by_tenant_day", tenant, map[string]any{"dropped_billing": uint64(0), "events_billing_ingested": uint64(100)})
}

func (r *rig) get(path, token string) *httptest.ResponseRecorder {
	r.t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	r.mux.ServeHTTP(w, req)
	return w
}

// ok asserts 200, validates against schema/<file>, and decodes the body.
func (r *rig) ok(path, token, schema string) map[string]any {
	r.t.Helper()
	w := r.get(path, token)
	if w.Code != http.StatusOK {
		r.t.Fatalf("GET %s: %d %s", path, w.Code, w.Body.String())
	}
	r.schemas.Validate(schema, w.Body.Bytes())
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		r.t.Fatal(err)
	}
	return out
}

func (r *rig) refused(path, token string, status int, code string) {
	r.t.Helper()
	w := r.get(path, token)
	r.schemas.Validate("error.json", w.Body.Bytes())
	var e struct {
		Error struct{ Code string }
	}
	_ = json.Unmarshal(w.Body.Bytes(), &e)
	if w.Code != status || e.Error.Code != code {
		r.t.Fatalf("GET %s: got %d %s, want %d %s", path, w.Code, e.Error.Code, status, code)
	}
}

// boundTenants asserts every query the fake saw carried the given tenant — the construction proof's observable half.
func (r *rig) boundTenants(tenant uuid.UUID) {
	r.t.Helper()
	if len(r.run.seen) == 0 {
		r.t.Fatal("no query ran")
	}
	for _, q := range r.run.seen {
		if q.Bind()["tid"] != tenant.String() {
			r.t.Fatalf("template %s bound tenant %s, want the token's %s", q.Template().Name(), q.Bind()["tid"], tenant)
		}
	}
	r.run.seen = nil
}

func v7() uuid.UUID { return uuid.Must(uuid.NewV7()) }

func sessionRowFor(session uuid.UUID, agent, projectHex string, paths []string, at time.Time) map[string]any {
	return map[string]any{
		"session_id": session, "agent": agent, "project": projectHex, "capture_paths": paths,
		"started_at": at, "ended_at": at.Add(time.Hour),
		"tokens_in": uint64(1000), "tokens_out": uint64(200), "tokens_cache_read": uint64(50), "tokens_cache_create": uint64(5),
		"tasks": uint64(2), "tasks_verified": uint64(1), "arrests": uint64(1), "injections": uint64(1), "route_decisions": uint64(1),
		"dropped_billing": uint64(3), "checkpoint_seq": uint64(9),
	}
}

const projA = "0f0e0d0c0b0a09080706050403020100ffeeddccbbaa99887766554433221100"

func TestSessionsContract(t *testing.T) {
	r := newRig(t)
	at := time.Now().UTC().Add(-2 * time.Hour)
	s1, s2, s3 := v7(), v7(), v7() // ascending mint order; the list is newest first
	r.run.add("app_sessions", r.tenantA,
		sessionRowFor(s3, "claudecode", projA, []string{"CAPTURE_PATH_HOOKS", "CAPTURE_PATH_PROXY"}, at),
		sessionRowFor(s2, "codex", "", []string{"CAPTURE_PATH_HOOKS"}, at),
		sessionRowFor(s1, "claudecode", projA, []string{"CAPTURE_PATH_TRANSCRIPT"}, at),
	)

	r.refused("/api/v1/sessions", "", http.StatusUnauthorized, "M1E-1002")
	r.refused("/api/v1/sessions?window=0d", r.tokenA, http.StatusBadRequest, "M1E-2001")
	r.refused("/api/v1/sessions?window=7", r.tokenA, http.StatusBadRequest, "M1E-2001")
	r.refused("/api/v1/sessions?cursor=nope", r.tokenA, http.StatusBadRequest, "M1E-2001")
	r.refused("/api/v1/sessions?limit=0", r.tokenA, http.StatusBadRequest, "M1E-2001")
	r.refused("/api/v1/sessions?limit=501", r.tokenA, http.StatusBadRequest, "M1E-2001")
	r.run.seen = nil

	body := r.ok("/api/v1/sessions?window=7d", r.tokenA, "sessions.json")
	r.boundTenants(r.tenantA)
	sessions := body["sessions"].([]any)
	if len(sessions) != 3 || body["next_cursor"] != nil {
		t.Fatalf("want 3 sessions and no cursor: %v", body)
	}
	first := sessions[0].(map[string]any)
	if first["session_id"] != s3.String() || first["project"] != projA {
		t.Fatalf("newest first with the project digest: %v", first)
	}
	cov := first["coverage"].(map[string]any)
	if cov["proxy_in_path"] != true || cov["transcript_tailed"] != false || cov["dropped_billing"] != float64(3) {
		t.Fatalf("coverage posture from capture_paths: %v", cov)
	}
	if paths := cov["capture_paths"].([]any); len(paths) != 2 || paths[0] != "hooks" || paths[1] != "proxy" {
		t.Fatalf("capture paths lowercased, prefix stripped, sorted: %v", paths)
	}
	second := sessions[1].(map[string]any)["coverage"].(map[string]any)
	if second["proxy_in_path"] != false || second["transcript_tailed"] != false {
		t.Fatalf("hooks-only session: %v", second)
	}
	third := sessions[2].(map[string]any)["coverage"].(map[string]any)
	if third["transcript_tailed"] != true || third["proxy_in_path"] != false {
		t.Fatalf("transcript-only session: %v", third)
	}
	// The honesty fields are the report's, verbatim.
	var report map[string]any
	if err := json.Unmarshal(r.get("/api/v1/reports/tvo?window=7d", r.tokenA).Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	honesty := body["honesty"].(map[string]any)
	for _, k := range []string{"coverage_band", "cost_basis", "guarantee_grade", "task_seg_version"} {
		if got, want := jsonString(t, honesty[k]), jsonString(t, report[k]); got != want {
			t.Fatalf("honesty.%s = %s, report says %s", k, got, want)
		}
	}
	if honesty["guarantee_grade"] != false || !strings.Contains(honesty["refusal"].(string), "cost basis unresolved") {
		t.Fatalf("no regime row ⇒ the report is indicative and says why; the list must carry that verbatim: %v", honesty)
	}

	// Filters are exact matches.
	if got := r.ok("/api/v1/sessions?agent=codex", r.tokenA, "sessions.json")["sessions"].([]any); len(got) != 1 || got[0].(map[string]any)["session_id"] != s2.String() {
		t.Fatalf("agent filter: %v", got)
	}
	if got := r.ok("/api/v1/sessions?project="+projA, r.tokenA, "sessions.json")["sessions"].([]any); len(got) != 2 {
		t.Fatalf("project filter: %v", got)
	}
	if got := r.ok("/api/v1/sessions?agent=claudecode&project=", r.tokenA, "sessions.json")["sessions"].([]any); len(got) != 2 {
		t.Fatalf("empty project means no filter: %v", got)
	}

	// Keyset paging: limit=2 hands back the second id as the cursor; the next page starts strictly below it.
	page1 := r.ok("/api/v1/sessions?limit=2", r.tokenA, "sessions.json")
	if page1["next_cursor"] != s2.String() || len(page1["sessions"].([]any)) != 2 {
		t.Fatalf("page 1: %v", page1)
	}
	page2 := r.ok("/api/v1/sessions?limit=2&cursor="+s2.String(), r.tokenA, "sessions.json")
	if got := page2["sessions"].([]any); len(got) != 1 || got[0].(map[string]any)["session_id"] != s1.String() || page2["next_cursor"] != nil {
		t.Fatalf("page 2: %v", page2)
	}
}

func TestSessionsCrossTenantNegative(t *testing.T) {
	r := newRig(t)
	at := time.Now().UTC().Add(-time.Hour)
	sA, sB := v7(), v7()
	r.run.add("app_sessions", r.tenantA, sessionRowFor(sA, "claudecode", "", nil, at))
	r.run.add("app_sessions", r.tenantB, sessionRowFor(sB, "claudecode", "", nil, at))
	for _, c := range []struct {
		token      string
		mine, them uuid.UUID
		tenant     uuid.UUID
	}{{r.tokenA, sA, sB, r.tenantA}, {r.tokenB, sB, sA, r.tenantB}} {
		w := r.get("/api/v1/sessions", c.token)
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), c.mine.String()) {
			t.Fatalf("own session missing: %d %s", w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), c.them.String()) {
			t.Fatalf("the other tenant's session leaked: %s", w.Body.String())
		}
		r.boundTenants(c.tenant)
		// The same session id under the wrong token is not found — never served from the other tenant's rows.
		r.refused("/api/v1/sessions/"+c.them.String()+"?window=7d", c.token, http.StatusNotFound, "M1E-2009")
		r.boundTenants(c.tenant)
	}
}

func eventRow(session, task uuid.UUID, seq uint64, at time.Time, eventType string, tokens uint64, payload string, extra map[string]any) map[string]any {
	row := map[string]any{
		"event_id": v7(), "session_id": session, "task_id": task, "session_epoch": uint32(1), "seq": seq,
		"occurred_at": at.Add(time.Duration(seq) * time.Second), "event_type": eventType, "model": "",
		"tokens": tokens, "cost_usd": float64(tokens) / 1000, "verdict": "", "verdict_stage": "",
		"noise_cert_id": uuid.Nil, "bundle_seq": uint64(0), "checkpoint_seq": uint64(0), "payload": payload,
	}
	for k, v := range extra {
		row[k] = v
	}
	return row
}

func TestSessionDetailFoldsAttemptsTrailAndTypedEvidence(t *testing.T) {
	r := newRig(t)
	at := time.Now().UTC().Add(-3 * time.Hour)
	session, other := v7(), v7()
	task1, task2 := uuid.New(), uuid.New()
	cert := uuid.New()
	r.run.add("app_sessions", r.tenantA, sessionRowFor(session, "claudecode", projA, []string{"CAPTURE_PATH_HOOKS"}, at))
	const leak = "/home/dev/secret_module.py"
	r.run.add("app_session_events", r.tenantA,
		eventRow(session, task1, 1, at, "TaskOpen", 0, `{"task_seg_version":"task_seg.v1","task_class":"edit.small","prompt_digest":"AAEC"}`, nil),
		eventRow(session, task1, 2, at, "Usage", 100, `{"model":"mid"}`, nil),
		eventRow(session, task1, 3, at, "VerdictEvent", 0, `{"certification":"CERTIFICATION_STATUS_BOOTSTRAPPING","bundle_seq":"7"}`, map[string]any{"verdict": "violated", "verdict_stage": "provisional"}),
		eventRow(session, task1, 4, at, "AnchorVote", 0, `{"anchor_id":"ruff@1","vote":"VERDICT_VIOLATED","evidence":{"tool":"ruff","diagnostic_code":"E501","category":"EVIDENCE_CATEGORY_LINT","counts":{"errors":2,"warnings":1,"files_affected":1},"path_role":"PATH_ROLE_SRC","output_hmac":"AAEC","path":"`+leak+`"},"integrity":{"tamper":false}}`, nil),
		eventRow(session, task1, 5, at, "Usage", 50, `{}`, nil),
		eventRow(session, task1, 6, at, "VerdictEvent", 0, `{"certification":"CERTIFICATION_STATUS_CERTIFIED","bundle_seq":"7"}`, map[string]any{"verdict": "violated", "verdict_stage": "certified", "noise_cert_id": cert}),
		eventRow(session, task1, 7, at, "GuardDecision", 0, `{"decision":"block","tokens_saved_estimate":1200}`, map[string]any{"bundle_seq": uint64(7)}),
		eventRow(session, task1, 8, at, "MemoryInjection", 0, `{"artifact_ids":["AAEC","AQID"],"channel":"INJECTION_CHANNEL_HOOK_CONTEXT","tokens_used":12}`, nil),
		eventRow(session, task1, 9, at, "Usage", 30, `{}`, nil),
		eventRow(session, task1, 10, at, "VerdictEvent", 0, `{"certification":"CERTIFICATION_STATUS_CERTIFIED"}`, map[string]any{"verdict": "satisfied", "verdict_stage": "certified", "noise_cert_id": cert}),
		eventRow(session, task1, 11, at, "TaskClose", 0, `{"resolution":"RESOLUTION_VERDICT"}`, nil),
		eventRow(session, task2, 12, at, "TaskOpen", 0, `{"task_seg_version":"task_seg.v1"}`, nil),
		eventRow(session, task2, 13, at, "Usage", 7, `{}`, nil),
		eventRow(session, uuid.Nil, 14, at, "ReceiptCheckpoint", 0, `{}`, map[string]any{"checkpoint_seq": uint64(9)}),
		eventRow(other, uuid.New(), 1, at, "Usage", 999_999, `{}`, nil),
	)

	r.refused("/api/v1/sessions/not-a-uuid", r.tokenA, http.StatusBadRequest, "M1E-2001")
	r.refused("/api/v1/sessions/"+uuid.New().String(), r.tokenA, http.StatusNotFound, "M1E-2009")
	r.run.seen = nil
	body := r.ok("/api/v1/sessions/"+session.String(), r.tokenA, "session_detail.json")
	r.boundTenants(r.tenantA)
	raw, _ := json.Marshal(body)
	if strings.Contains(string(raw), leak) || strings.Contains(string(raw), "output_hmac") || strings.Contains(string(raw), "999999") || strings.Contains(string(raw), other.String()) {
		t.Fatalf("detail carried a path, a digest or another session's rows: %s", raw)
	}
	if body["checkpoint_seq"] != float64(9) {
		t.Fatalf("checkpoint_seq: %v", body["checkpoint_seq"])
	}
	tasks := body["tasks"].([]any)
	if len(tasks) != 2 {
		t.Fatalf("want 2 tasks: %s", raw)
	}
	t1 := tasks[0].(map[string]any)
	if t1["task_id"] != task1.String() || t1["task_seg_version"] != "task_seg.v1" || t1["task_class"] != "edit.small" || t1["resolution"] != "verdict" || t1["opened_at"] == nil || t1["closed_at"] == nil {
		t.Fatalf("task header: %v", t1)
	}
	attempts := t1["attempts"].([]any)
	if len(attempts) != 2 {
		t.Fatalf("two stage-final verdicts ⇒ two attempts: %v", attempts)
	}
	a1, a2 := attempts[0].(map[string]any), attempts[1].(map[string]any)
	if a1["n"] != float64(1) || a1["tokens"] != float64(150) || a1["verdict"] != "violated" || a1["verdict_stage"] != "certified" {
		t.Fatalf("attempt 1 folds the tokens up to and including its closing verdict: %v", a1)
	}
	if a2["n"] != float64(2) || a2["tokens"] != float64(30) || a2["verdict"] != "satisfied" {
		t.Fatalf("attempt 2: %v", a2)
	}
	trail := t1["verdict_trail"].([]any)
	if len(trail) != 3 {
		t.Fatalf("trail: %v", trail)
	}
	s0, s1 := trail[0].(map[string]any), trail[1].(map[string]any)
	if s0["stage"] != "provisional" || s0["certification"] != "bootstrapping" || s0["certificate_id"] != nil || s0["bundle_seq"] != float64(7) {
		t.Fatalf("trail[0]: %v", s0)
	}
	if s1["stage"] != "certified" || s1["certificate_id"] != cert.String() {
		t.Fatalf("trail[1] carries the certificate: %v", s1)
	}
	ev := t1["evidence"].([]any)[0].(map[string]any)
	if ev["anchor_id"] != "ruff@1" || ev["vote"] != "violated" || ev["tool"] != "ruff" || ev["diagnostic_code"] != "E501" || ev["category"] != "lint" || ev["path_role"] != "src" || ev["tamper"] != false {
		t.Fatalf("typed evidence: %v", ev)
	}
	if c := ev["counts"].(map[string]any); c["errors"] != float64(2) || c["warnings"] != float64(1) || c["files_affected"] != float64(1) {
		t.Fatalf("counts: %v", c)
	}
	inj := t1["injections"].([]any)[0].(map[string]any)
	if inj["channel"] != "hook_context" || inj["tokens_used"] != float64(12) || inj["artifact_count"] != float64(2) {
		t.Fatalf("injection: %v", inj)
	}
	arr := t1["arrests"].([]any)[0].(map[string]any)
	if arr["tokens_saved_estimate"] != float64(1200) || arr["bundle_seq"] != float64(7) {
		t.Fatalf("arrest: %v", arr)
	}
	t2 := tasks[1].(map[string]any)
	if a := t2["attempts"].([]any); len(a) != 1 || a[0].(map[string]any)["tokens"] != float64(7) || a[0].(map[string]any)["verdict"] != "" {
		t.Fatalf("a task with no verdict is one open attempt: %v", t2)
	}
	if t2["closed_at"] != nil || t2["resolution"] != "" {
		t.Fatalf("unclosed task: %v", t2)
	}
}

func TestParseWindowBounds(t *testing.T) {
	for _, bad := range []string{"0d", "366d", "7", "1w", "-1d", "07d "} {
		if _, _, err := parseWindow(bad); err == nil {
			t.Errorf("window %q accepted", bad)
		}
	}
	today := time.Now().UTC().Truncate(24 * time.Hour)
	for raw, days := range map[string]int{"": 30, "1d": 1, "365d": 365, "7d": 7} {
		from, to, err := parseWindow(raw)
		if err != nil || !to.Equal(today) || !from.Equal(today.AddDate(0, 0, -(days-1))) {
			t.Errorf("window %q: %v..%v %v", raw, from, to, err)
		}
	}
}

func TestDetailWindowFromUUIDv7(t *testing.T) {
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	old := uuid.Must(uuid.NewV7()) // minted now: its day is today, so the +1 day is capped at today
	from, to, err := detailWindow(old, "", time.Now().UTC())
	if err != nil || !to.Equal(time.Now().UTC().Truncate(24*time.Hour)) || !from.Equal(to.AddDate(0, 0, -1)) {
		t.Fatalf("v7 window today: %v %v %v", from, to, err)
	}
	// A v7 id from a past day scans [day-1, day+1].
	past := uuid.Must(uuid.NewV7())
	ms := uint64(time.Date(2026, 9, 10, 8, 0, 0, 0, time.UTC).UnixMilli())
	past[0], past[1], past[2], past[3], past[4], past[5] = byte(ms>>40), byte(ms>>32), byte(ms>>24), byte(ms>>16), byte(ms>>8), byte(ms)
	from, to, _ = detailWindow(past, "", now)
	if from.Format(time.DateOnly) != "2026-09-09" || to.Format(time.DateOnly) != "2026-09-11" {
		t.Fatalf("past v7 window: %s..%s", from.Format(time.DateOnly), to.Format(time.DateOnly))
	}
	// An explicit window wins; a v4 id falls back to the default window.
	from, to, _ = detailWindow(past, "3d", now)
	if to.Sub(from) != 2*24*time.Hour {
		t.Fatalf("explicit window: %v..%v", from, to)
	}
	from, to, _ = detailWindow(uuid.New(), "", now)
	if to.Sub(from) != 29*24*time.Hour {
		t.Fatalf("v4 default window: %v..%v", from, to)
	}
	if _, _, err := detailWindow(past, "400d", now); err == nil {
		t.Fatal("window beyond 365d accepted")
	}
}

func TestMomentsFeed(t *testing.T) {
	r := newRig(t)
	now := time.Now().UTC()
	session, task := v7(), uuid.New()
	mk := func(at time.Time, eventType, payload string, extra map[string]any) map[string]any {
		row := map[string]any{"event_id": v7(), "occurred_at": at, "session_id": session, "task_id": task, "agent": "claudecode",
			"event_type": eventType, "propensity": float64(1), "fidelity": "", "bundle_seq": uint64(0), "payload": payload}
		for k, v := range extra {
			row[k] = v
		}
		return row
	}
	r.run.add("app_moments", r.tenantA,
		mk(now.Add(-1*time.Minute), "RouteDecision", `{"action":"mid","candidates":["small","mid"]}`, map[string]any{"fidelity": "wire_enforced", "bundle_seq": uint64(483)}),
		mk(now.Add(-2*time.Minute), "MemoryInjection", `{"artifact_ids":["AAEC"],"channel":"INJECTION_CHANNEL_MCP_PULL","tokens_used":40}`, map[string]any{"task_id": uuid.Nil}),
		mk(now.Add(-3*time.Minute), "GuardDecision", `{"decision":"block","tokens_saved_estimate":900}`, map[string]any{"bundle_seq": uint64(483)}),
		mk(now.Add(-30*time.Hour), "GuardDecision", `{"tokens_saved_estimate":1}`, nil),
		mk(now.Add(-4*time.Minute), "EdgeHealth", `{}`, nil),
	)
	r.refused("/api/v1/moments?since=yesterday", r.tokenA, http.StatusBadRequest, "M1E-2001")
	r.refused("/api/v1/moments?since=2020-01-01T00:00:00Z", r.tokenA, http.StatusBadRequest, "M1E-2001")
	r.refused("/api/v1/moments?limit=1001", r.tokenA, http.StatusBadRequest, "M1E-2001")
	r.run.seen = nil

	body := r.ok("/api/v1/moments", r.tokenA, "moments.json")
	r.boundTenants(r.tenantA)
	moments := body["moments"].([]any)
	if len(moments) != 3 {
		t.Fatalf("default since is 24h and unknown families are dropped: %v", moments)
	}
	kinds := []string{}
	for _, m := range moments {
		kinds = append(kinds, m.(map[string]any)["kind"].(string))
	}
	if strings.Join(kinds, ",") != "route,injection,arrest" {
		t.Fatalf("newest first, one kind each: %v", kinds)
	}
	route := moments[0].(map[string]any)
	if route["route"].(map[string]any)["fidelity"] != "wire_enforced" || route["route"].(map[string]any)["bundle_seq"] != float64(483) || route["arrest"] != nil {
		t.Fatalf("route detail only: %v", route)
	}
	inj := moments[1].(map[string]any)
	if inj["task_id"] != nil || inj["injection"].(map[string]any)["channel"] != "mcp_pull" {
		t.Fatalf("session-level injection: %v", inj)
	}
	if moments[2].(map[string]any)["arrest"].(map[string]any)["tokens_saved_estimate"] != float64(900) {
		t.Fatalf("arrest detail: %v", moments[2])
	}
	if body["next_since"] != route["at"] {
		t.Fatalf("next_since is the newest moment: %v vs %v", body["next_since"], route["at"])
	}
	// Polling forward from next_since yields nothing new; a since between rows cuts exactly.
	if got := r.ok("/api/v1/moments?since="+body["next_since"].(string), r.tokenA, "moments.json"); len(got["moments"].([]any)) != 0 || got["next_since"] != nil {
		t.Fatalf("nothing after the newest: %v", got)
	}
	cut := now.Add(-150 * time.Second).Format(time.RFC3339)
	if got := r.ok("/api/v1/moments?since="+cut, r.tokenA, "moments.json")["moments"].([]any); len(got) != 2 {
		t.Fatalf("since cuts strictly after: %v", got)
	}
	if got := r.ok("/api/v1/moments?limit=1", r.tokenA, "moments.json"); len(got["moments"].([]any)) != 1 || got["next_since"] != route["at"] {
		t.Fatalf("limit keeps next_since at the newest: %v", got)
	}
}

func TestRouteDecisionsContract(t *testing.T) {
	r := newRig(t)
	session, task, decision := v7(), uuid.New(), v7()
	conf := float32(0.91)
	r.run.add("ope_route_decisions", r.tenantA,
		map[string]any{"decision_id": decision, "task_id": task, "session_id": session, "session_epoch": uint32(1), "seq": uint64(6), "agent": "claudecode",
			"action": "mid", "candidates": []string{"small", "mid"}, "propensity": float64(1), "fidelity": "wire_enforced", "bundle_seq": uint64(483),
			"served_model": "mid", "verdict": "satisfied", "verdict_stage": "certified", "label_confidence": &conf},
		map[string]any{"decision_id": uuid.New(), "task_id": task, "session_id": session, "session_epoch": uint32(1), "seq": uint64(9), "agent": "claudecode",
			"action": "small", "candidates": []string{}, "propensity": float64(0.97), "fidelity": "config_steered", "bundle_seq": uint64(483),
			"served_model": "", "verdict": "", "verdict_stage": "", "label_confidence": (*float32)(nil)},
	)
	r.refused("/api/v1/route/decisions?window=1y", r.tokenA, http.StatusBadRequest, "M1E-2001")
	r.run.seen = nil
	body := r.ok("/api/v1/route/decisions?window=7d", r.tokenA, "route_decisions.json")
	r.boundTenants(r.tenantA)
	decisions := body["decisions"].([]any)
	if len(decisions) != 2 {
		t.Fatalf("decisions: %v", decisions)
	}
	d0, d1 := decisions[0].(map[string]any), decisions[1].(map[string]any)
	if d0["at"] == nil || d0["label_confidence"] != float64(0.9100000262260437) || d0["served_model"] != "mid" {
		t.Fatalf("v7 id ⇒ at; Float32 confidence widened: %v", d0)
	}
	sec, _ := decision.Time().UnixTime()
	if at, _ := time.Parse(time.RFC3339Nano, d0["at"].(string)); at.Unix() != sec {
		t.Fatalf("at derived from the decision id: %v", d0["at"])
	}
	if d1["at"] != nil || d1["label_confidence"] != nil || d1["candidates"] == nil {
		t.Fatalf("v4 id ⇒ at null; uncertified ⇒ null confidence; empty candidates stay an array: %v", d1)
	}
	if r.ok("/api/v1/route/decisions", r.tokenB, "route_decisions.json")["decisions"].([]any) != nil && len(r.run.seen) == 0 {
		t.Fatal("tenant B ran no query")
	}
}

func TestHonestyIsNotOptional(t *testing.T) {
	r := newRig(t)
	r.run.add("app_sessions", r.tenantA, sessionRowFor(v7(), "claudecode", "", nil, time.Now().UTC()))
	r.run.fail = map[string]error{"tvo_report": errors.New("clickhouse down")}
	r.refused("/api/v1/sessions", r.tokenA, http.StatusInternalServerError, "M1E-9500")
	r.refused("/api/v1/moments", r.tokenA, http.StatusInternalServerError, "M1E-9500")
	r.refused("/api/v1/route/decisions", r.tokenA, http.StatusInternalServerError, "M1E-9500")
	r.run.fail = map[string]error{"app_sessions": querychoke.ErrBusy}
	r.refused("/api/v1/sessions", r.tokenA, http.StatusServiceUnavailable, "M1E-9500")
}

func jsonString(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
