package policydist

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
)

const judgePath = "/internal/v1/judge-requests"

var (
	judgeTenant  = uuid.MustParse("6b9f0f2e-4c1d-4a4e-8f0a-9d2b7c5e3a10")
	judgeTask    = base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	judgeSession = base64.StdEncoding.EncodeToString([]byte("fedcba9876543210"))
)

// goodJudge is the protojson a betterproto client renders: camelCase, integer enums, base64 bytes.
func goodJudge() map[string]any {
	return map[string]any{
		"requestId": "b1c2d3e4-0000-4000-8000-000000000001", "judgeId": "judge:grounded-rubric@1",
		"taskId": judgeTask, "sessionId": judgeSession, "attempt": 2,
		"rubric": "Reply with exactly one word from: satisfied|violated|refused|error.",
		"tier":   1, "model": "claude-sonnet-5", "tokenBudget": 2048, "locus": 1,
	}
}

func judgeModule(token string) *Module {
	return NewModule(ModuleDeps{ObsCfg: obs.Config{ServiceName: "policydist-judge-test"}, IntelServiceToken: token})
}

func postJudge(t *testing.T, m *Module, bearer string, tenant string, req any) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	m.RegisterRoutes(mux)
	var body []byte
	switch r := req.(type) {
	case string:
		body = []byte(r)
	default:
		var err error
		if body, err = json.Marshal(map[string]any{"tenant_id": tenant, "request": r}); err != nil {
			t.Fatal(err)
		}
	}
	hr := httptest.NewRequest(http.MethodPost, judgePath, strings.NewReader(string(body)))
	if bearer != "" {
		hr.Header.Set("Authorization", bearer)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, hr)
	return w
}

func TestJudgeRouteFansOutToEveryStreamOfTheTenantOnly(t *testing.T) {
	m := judgeModule("intel-secret")
	stable, err := m.hub.subscribe(judgeTenant, "stable")
	if err != nil {
		t.Fatal(err)
	}
	canary, err := m.hub.subscribe(judgeTenant, "canary")
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := m.hub.subscribe(uuid.New(), "stable")
	if err != nil {
		t.Fatal(err)
	}

	w := postJudge(t, m, "Bearer intel-secret", judgeTenant.String(), goodJudge())
	if w.Code != http.StatusOK {
		t.Fatalf("got %d %s, want 200", w.Code, w.Body.String())
	}
	var out struct {
		RequestID string `json:"request_id"`
		Streams   int    `json:"streams"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Streams != 2 || out.RequestID != "b1c2d3e4-0000-4000-8000-000000000001" {
		t.Fatalf("response = %+v, want both of the tenant's streams and the request_id echoed", out)
	}
	for _, s := range []*stream{stable, canary} {
		ev, open := drainOne(t, s)
		if !open || ev.Name != "judge_request" {
			t.Fatalf("frame = %+v (open=%v), want event judge_request", ev, open)
		}
		var got m1pv1.JudgeRequest
		if err := protojson.Unmarshal([]byte(ev.Data), &got); err != nil {
			t.Fatalf("data is not protojson a Go edge decodes: %v\n%s", err, ev.Data)
		}
		if got.GetRequestId() != out.RequestID || got.GetLocus() != m1pv1.JudgeLocus_JUDGE_LOCUS_CLIENT_SIDE ||
			got.GetTier() != m1pv1.EvidenceTier_EVIDENCE_TIER_E0 || got.GetTokenBudget() != 2048 ||
			string(got.GetTaskId()) != "0123456789abcdef" || string(got.GetSessionId()) != "fedcba9876543210" ||
			got.GetAttempt() != 2 || got.GetModel() != "claude-sonnet-5" || got.GetJudgeId() != "judge:grounded-rubric@1" {
			t.Fatalf("decoded request lost a field: %v", got.String())
		}
		if strings.Contains(ev.Data, "\n") {
			t.Fatal("SSE data must be one line; a newline would split the frame")
		}
	}
	select {
	case ev := <-foreign.out:
		t.Fatalf("another tenant's stream received the judge request: %+v", ev)
	default:
	}
	// A repost is the caller's retry after a miss; with no device connected it answers streams:0 rather than pretending.
	m.hub.unsubscribe(stable)
	m.hub.unsubscribe(canary)
	w = postJudge(t, m, "Bearer intel-secret", judgeTenant.String(), goodJudge())
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"streams":0`) {
		t.Fatalf("repost with no streams: got %d %s, want 200 streams:0", w.Code, w.Body.String())
	}
}

func TestJudgeRouteRefusesServiceCredentialBeforeReadingTheBody(t *testing.T) {
	m := judgeModule("intel-secret")
	for name, bearer := range map[string]string{"missing": "", "bare": "Bearer ", "wrong": "Bearer intel-secre", "basic": "Basic intel-secret"} {
		if w := postJudge(t, m, bearer, judgeTenant.String(), goodJudge()); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "M1E-1001") {
			t.Errorf("%s credential: got %d %s, want 403 M1E-1001", name, w.Code, w.Body.String())
		}
	}
	for _, bearer := range []string{"Bearer ", "Bearer x"} {
		if w := postJudge(t, judgeModule(""), bearer, judgeTenant.String(), goodJudge()); w.Code != http.StatusForbidden {
			t.Errorf("empty configured token + %q: got %d, want 403 (an absent surface, never an open one)", bearer, w.Code)
		}
	}
}

func TestJudgeRouteRejectsEveryMalformedField(t *testing.T) {
	m := judgeModule("intel-secret")
	mutate := func(k string, v any) map[string]any {
		r := goodJudge()
		if v == nil {
			delete(r, k)
		} else {
			r[k] = v
		}
		return r
	}
	cases := map[string]any{
		"no request_id":       mutate("requestId", nil),
		"request_id with nl":  mutate("requestId", "a\nb"),
		"judge_id not judge:": mutate("judgeId", "rm:grounded@1"),
		"no judge_id":         mutate("judgeId", nil),
		"task_id 15 bytes":    mutate("taskId", base64.StdEncoding.EncodeToString([]byte("0123456789abcde"))),
		"task_id nil uuid":    mutate("taskId", base64.StdEncoding.EncodeToString(make([]byte, 16))),
		"session_id missing":  mutate("sessionId", nil),
		"empty rubric":        mutate("rubric", ""),
		"rubric over 16 KiB":  mutate("rubric", strings.Repeat("x", MaxRubricLen+1)),
		"model missing":       mutate("model", nil),
		"token_budget 0":      mutate("tokenBudget", 0),
		"token_budget huge":   mutate("tokenBudget", MaxJudgeTokenBudget+1),
		"tier unspecified":    mutate("tier", 0),
		"locus cloud":         mutate("locus", 2),
		"locus unspecified":   mutate("locus", 0),
		"unknown field":       mutate("evidence", "never crosses"),
		"not protojson":       "[]",
	}
	for name, req := range cases {
		var w *httptest.ResponseRecorder
		if s, ok := req.(string); ok {
			w = postJudge(t, m, "Bearer intel-secret", "", `{"tenant_id":"`+judgeTenant.String()+`","request":`+s+`}`)
		} else {
			w = postJudge(t, m, "Bearer intel-secret", judgeTenant.String(), req)
		}
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "M1E-2001") {
			t.Errorf("%s: got %d %s, want 400 M1E-2001", name, w.Code, w.Body.String())
		}
	}
	for name, tenant := range map[string]string{"not a uuid": "tenant-1", "nil uuid": uuid.Nil.String()} {
		if w := postJudge(t, m, "Bearer intel-secret", tenant, goodJudge()); w.Code != http.StatusBadRequest {
			t.Errorf("tenant %s: got %d %s, want 400", name, w.Code, w.Body.String())
		}
	}
	if w := postJudge(t, m, "Bearer intel-secret", "", `{"tenant_id":"`+judgeTenant.String()+`","request":{"rubric":"`+strings.Repeat("x", maxJudgeBody)+`"}}`); w.Code != http.StatusBadRequest {
		t.Errorf("oversized body: got %d, want 400", w.Code)
	}
	if m.hub.Live() != 0 {
		t.Fatal("test bug: a stream was left live")
	}
}

func TestHubJudgeCountsOnlyStreamsThatTookIt(t *testing.T) {
	h := NewHub()
	slow, err := h.subscribe(judgeTenant, "stable")
	if err != nil {
		t.Fatal(err)
	}
	live, err := h.subscribe(judgeTenant, "stable")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < streamBuffer; i++ {
		h.Revoke(judgeTenant, int64(i))
		drainOne(t, live)
	}
	if n := h.Judge(judgeTenant, `{"requestId":"r"}`); n != 1 {
		t.Fatalf("Judge delivered to %d streams, want 1: the full one is closed, not counted", n)
	}
	for {
		if _, open := drainOne(t, slow); !open {
			break
		}
	}
	if ev, open := drainOne(t, live); !open || ev.Name != "judge_request" || ev.Data != `{"requestId":"r"}` {
		t.Fatalf("live stream frame = %+v", ev)
	}
	if h.Judge(uuid.New(), "{}") != 0 {
		t.Fatal("a tenant with no streams took a request")
	}
}

// The Go half of the judge-request seam lock (testdata/judge_request_body.json): specs.py's exact body passes the real handler and reaches a stream decodable.
func TestJudgeRouteAcceptsPythonExactBody(t *testing.T) {
	raw, err := os.ReadFile("testdata/judge_request_body.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Body json.RawMessage `json:"body"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	m := judgeModule("intel-secret")
	s, err := m.hub.subscribe(judgeTenant, "stable")
	if err != nil {
		t.Fatal(err)
	}
	w := postJudge(t, m, "Bearer intel-secret", "", string(fixture.Body))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"streams":1`) {
		t.Fatalf("Python's exact body: got %d %s, want 200 streams:1", w.Code, w.Body.String())
	}
	ev, open := drainOne(t, s)
	var got m1pv1.JudgeRequest
	if !open || protojson.Unmarshal([]byte(ev.Data), &got) != nil {
		t.Fatalf("frame = %+v", ev)
	}
	if got.GetRequestId() != "c8174949-94d6-52c9-85da-9c7fa304b757" || got.GetJudgeId() != "judge:grounded-rubric@1" ||
		uuid.UUID(got.GetTaskId()).String() != "189d8bb1-cba6-5f57-9312-46b0b6cb8154" ||
		uuid.UUID(got.GetSessionId()).String() != "0ea6592a-9ed8-415c-b0aa-382dd0227d90" ||
		got.GetTier() != m1pv1.EvidenceTier_EVIDENCE_TIER_E0 || got.GetTokenBudget() != 2048 || got.GetModel() != "claude-sonnet-5" ||
		!strings.Contains(got.GetRubric(), "satisfied|violated|refused|error") {
		t.Fatalf("decoded = %v", got.String())
	}
}
