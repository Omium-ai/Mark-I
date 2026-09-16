package judge

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/verdict"
)

const (
	apiKey    = "sk-ant-api03-AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz01"
	rubric    = "Reply with exactly one word from: satisfied|violated|refused|error."
	evidence  = "ruff:E501 errors=3 warnings=0 files=1"
	requestID = "b1c2d3e4-0000-4000-8000-000000000001"
)

var (
	task    = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	session = [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
	root    = bytes.Repeat([]byte{7}, 32)
)

type stubCall struct {
	method, path string
	header       http.Header
	body         map[string]any
}

// anthropic is the ONLY server in the test; every call the runner makes lands here or fails.
type anthropic struct {
	mu     sync.Mutex
	calls  []stubCall
	status int
	reply  string
	stop   string
	srv    *httptest.Server
}

func newAnthropic(t *testing.T) *anthropic {
	t.Helper()
	a := &anthropic{status: 200, reply: "violated", stop: "end_turn"}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		a.mu.Lock()
		a.calls = append(a.calls, stubCall{method: r.Method, path: r.URL.Path, header: r.Header.Clone(), body: body})
		status, reply, stop := a.status, a.reply, a.stop
		a.mu.Unlock()
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"stop_reason": stop,
			"content":     []map[string]any{{"type": "thinking", "thinking": ""}, {"type": "text", "text": reply}},
		})
	}))
	t.Cleanup(a.srv.Close)
	return a
}

func (a *anthropic) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.calls)
}

// logBuf is a goroutine-safe slog sink: the worker logs after the vote is admitted.
type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

type harness struct {
	t        *testing.T
	stub     *anthropic
	cfg      Config
	admitted chan *m1pv1.Event
	logs     *logBuf
	dir      string
	owned    bool
	cached   bool
	cred     string
	evidence string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{t: t, stub: newAnthropic(t), admitted: make(chan *m1pv1.Event, 8), logs: &logBuf{}, dir: t.TempDir(), owned: true, cred: apiKey, evidence: evidence}
	h.cfg = Config{
		StateDir:   h.dir,
		BaseURL:    h.stub.srv.URL,
		Credential: func() string { return h.cred },
		TenantRoot: root,
		TaskFor: func(s, w [16]byte) ([16]byte, bool) {
			if h.owned && s == session && w == task {
				return w, true
			}
			return [16]byte{}, false
		},
		Verdict:  func(t [16]byte) (*m1pv1.VerdictEvent, bool) { return nil, h.cached && t == task },
		Evidence: func(id verdict.TaskID) string { return h.evidence },
		Admit:    func(_ context.Context, ev *m1pv1.Event) error { h.admitted <- ev; return nil },
		Log:      slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	return h
}

func (h *harness) runner() *Runner {
	h.t.Helper()
	r, err := New(h.cfg)
	if err != nil {
		h.t.Fatal(err)
	}
	return r
}

func request(mut func(*m1pv1.JudgeRequest)) []byte {
	req := &m1pv1.JudgeRequest{
		RequestId: requestID, JudgeId: "judge:grounded-rubric@1", TaskId: task[:], SessionId: session[:], Attempt: 1,
		Rubric: rubric, Tier: m1pv1.EvidenceTier_EVIDENCE_TIER_E0, Model: "claude-sonnet-5", TokenBudget: 2048,
		Locus: m1pv1.JudgeLocus_JUDGE_LOCUS_CLIENT_SIDE,
	}
	if mut != nil {
		mut(req)
	}
	b, err := protojson.Marshal(req)
	if err != nil {
		panic(err)
	}
	return b
}

func (h *harness) vote(r *Runner) *m1pv1.JudgeVote {
	h.t.Helper()
	select {
	case ev := <-h.admitted:
		if string(ev.GetTaskId()) != string(task[:]) || string(ev.GetSessionId()) != string(session[:]) || ev.GetOccurredAt() == nil {
			h.t.Fatalf("event is not scoped to the request's task/session: %v", ev)
		}
		jv := ev.GetJudgeVote()
		if jv == nil {
			h.t.Fatalf("admitted event is not a JudgeVote: %v", ev)
		}
		settle(h.t, r)
		return jv
	case <-time.After(10 * time.Second):
		h.t.Fatal("no vote admitted within 10s")
		return nil
	}
}

func settle(t *testing.T, r *Runner) {
	t.Helper()
	for i := 0; i < 200; i++ {
		r.mu.Lock()
		n := len(r.inflight)
		r.mu.Unlock()
		if n == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("a request stayed in flight")
}

func (h *harness) noVote() {
	h.t.Helper()
	select {
	case ev := <-h.admitted:
		h.t.Fatalf("a vote was admitted: %v", ev)
	case <-time.After(150 * time.Millisecond):
	}
}

func seenLines(t *testing.T, dir string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "judge", "seen"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Fields(string(raw))
}

func TestJudgeCallsTheMessagesAPIOnceWithTheExactShapeAndKeyOnlyInTheHeader(t *testing.T) {
	h := newHarness(t)
	r := h.runner()
	r.Handle(request(nil))
	jv := h.vote(r)

	if n := h.stub.count(); n != 1 {
		t.Fatalf("%d model calls, want exactly 1", n)
	}
	c := h.stub.calls[0]
	if c.method != http.MethodPost || c.path != "/v1/messages" {
		t.Fatalf("%s %s, want POST /v1/messages on the configured base URL", c.method, c.path)
	}
	if c.header.Get("x-api-key") != apiKey || c.header.Get("anthropic-version") != apiVersion || c.header.Get("content-type") != "application/json" {
		t.Fatalf("headers = %v", c.header)
	}
	if c.header.Get("Authorization") != "" {
		t.Fatal("an Authorization header is the OAuth path; the key rides x-api-key only")
	}
	want := map[string]any{
		"model": "claude-sonnet-5", "max_tokens": float64(2048),
		"system":   []any{map[string]any{"type": "text", "text": rubric, "cache_control": map[string]any{"type": "ephemeral"}}},
		"messages": []any{map[string]any{"role": "user", "content": evidence}},
	}
	got, _ := json.Marshal(c.body)
	exp, _ := json.Marshal(want)
	if string(got) != string(exp) {
		t.Fatalf("request body\n got %s\nwant %s", got, exp)
	}
	if jv.GetVote() != m1pv1.Verdict_VERDICT_VIOLATED || jv.GetJudgeId() != "judge:grounded-rubric@1" ||
		jv.GetTierUsed() != m1pv1.EvidenceTier_EVIDENCE_TIER_E0 || jv.GetLocus() != m1pv1.JudgeLocus_JUDGE_LOCUS_CLIENT_SIDE {
		t.Fatalf("vote = %v", jv)
	}
	mac := hmac.New(sha256.New, r.key)
	mac.Write([]byte(rubric))
	if !bytes.Equal(jv.GetRubricHash(), mac.Sum(nil)) || len(jv.GetRubricHash()) != 32 {
		t.Fatal("rubric_hash is not HMAC_tenant(rubric) under the m1p.judge.rubric leg")
	}
	// The key is in one request header and nowhere else: not in the log, not in the spooled vote, not in the seen file.
	if b, _ := json.Marshal(jv); bytes.Contains(b, []byte(apiKey)) {
		t.Fatal("the key reached the spool")
	}
	raw, _ := os.ReadFile(filepath.Join(h.dir, "judge", "seen"))
	for name, blob := range map[string][]byte{"log": []byte(h.logs.String()), "seen file": raw} {
		if bytes.Contains(blob, []byte(apiKey)) || bytes.Contains(blob, []byte(apiKey[len(apiKey)-12:])) {
			t.Fatalf("the key (or its tail) appears in the %s", name)
		}
	}
	if !strings.Contains(h.logs.String(), "vote=VERDICT_VIOLATED") {
		t.Fatalf("the vote itself should be logged: %s", h.logs.String())
	}
}

func TestJudgeMakesZeroCallsWithoutACustomerKey(t *testing.T) {
	h := newHarness(t)
	h.cred = ""
	r := h.runner()
	r.Handle(request(nil))
	jv := h.vote(r)
	if jv.GetVote() != m1pv1.Verdict_VERDICT_REFUSED || jv.GetTierUsed() != m1pv1.EvidenceTier_EVIDENCE_TIER_E0 {
		t.Fatalf("vote = %v, want REFUSED at E0", jv)
	}
	if h.stub.count() != 0 {
		t.Fatal("a model call was made with no key")
	}
	if !strings.Contains(h.logs.String(), "subscription") {
		t.Fatalf("the refusal reason should name the regime: %s", h.logs.String())
	}
}

// Shapes from rust/mark1-proxy/src/guard/shape.rs's in-crate corpus (the conformance/canary/token-shapes half).
func TestJudgeRefusesEveryCredentialThatIsNotAnAPIKey(t *testing.T) {
	for name, cred := range map[string]string{
		"anthropic oauth access":  "sk-ant-oat01-AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz01",
		"anthropic oauth refresh": "sk-ant-ort01-AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz01",
		"anthropic oauth session": "sk-ant-sid01-AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz01",
		"jwt bearer":              "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl",
		"openai key":              "sk-proj-AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz01",
		"stem only":               "sk-ant-api03-",
		"non-digit version":       "sk-ant-apiXX-AaBbCc",
		"bad alphabet":            "sk-ant-api03-AaBb Cc",
		"bearer prefixed":         "Bearer " + apiKey,
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			h.cred = cred
			r := h.runner()
			r.Handle(request(nil))
			if jv := h.vote(r); jv.GetVote() != m1pv1.Verdict_VERDICT_REFUSED {
				t.Fatalf("vote = %v, want REFUSED", jv)
			}
			if h.stub.count() != 0 {
				t.Fatal("a model call was made on a credential that is not an API key")
			}
			if strings.Contains(h.logs.String(), cred[3:]) {
				t.Fatal("the refused credential was logged")
			}
		})
	}
	for _, ok := range []string{apiKey, "sk-ant-api04-x", "sk-ant-api99-A_b-C"} {
		if !apiKeyShaped(ok) {
			t.Fatalf("%q must classify as an API key", ok)
		}
	}
}

func TestJudgeIgnoresTasksThisDeviceDoesNotOwn(t *testing.T) {
	h := newHarness(t)
	h.owned = false
	r := h.runner()
	r.Handle(request(nil))
	h.noVote()
	if h.stub.count() != 0 || len(seenLines(t, h.dir)) != 0 {
		t.Fatal("a foreign task was judged or marked seen")
	}
	r.Handle(request(func(q *m1pv1.JudgeRequest) { q.SessionId = bytes.Repeat([]byte{9}, 16) }))
	h.noVote()
	// The session ended but the verdict cache still holds the task: still ours.
	h.cached = true
	r.Handle(request(nil))
	if jv := h.vote(r); jv.GetVote() != m1pv1.Verdict_VERDICT_VIOLATED {
		t.Fatalf("vote = %v", jv)
	}
}

func TestJudgeVotesOncePerRequestIDAcrossRestarts(t *testing.T) {
	h := newHarness(t)
	r := h.runner()
	r.Handle(request(nil))
	h.vote(r)
	r.Handle(request(nil))
	h.noVote()
	fi, err := os.Stat(filepath.Join(h.dir, "judge", "seen"))
	if err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600) {
		t.Fatalf("seen file mode = %v, err %v; want 0600", fi.Mode(), err)
	}
	if got := seenLines(t, h.dir); len(got) != 1 || got[0] != requestID {
		t.Fatalf("seen = %v", got)
	}
	r2 := h.runner() // a restarted daemon must remember
	r2.Handle(request(nil))
	h.noVote()
	r2.Handle(request(func(q *m1pv1.JudgeRequest) { q.RequestId = "b1c2d3e4-0000-4000-8000-000000000002" }))
	h.vote(r2)
	if h.stub.count() != 2 {
		t.Fatalf("%d calls, want 2: one per distinct request_id", h.stub.count())
	}
}

func TestJudgeMapsEveryAnswerToTheVocabularyAndNeverGuesses(t *testing.T) {
	for name, tc := range map[string]struct {
		reply, stop string
		status      int
		want        m1pv1.Verdict
	}{
		"satisfied with punctuation": {"Satisfied.", "end_turn", 200, m1pv1.Verdict_VERDICT_SATISFIED},
		"violated in backticks":      {"`violated`", "end_turn", 200, m1pv1.Verdict_VERDICT_VIOLATED},
		"refused word":               {"refused", "end_turn", 200, m1pv1.Verdict_VERDICT_REFUSED},
		"model refusal":              {"", "refusal", 200, m1pv1.Verdict_VERDICT_REFUSED},
		"unspecified is not a vote":  {"unspecified", "end_turn", 200, m1pv1.Verdict_VERDICT_ERROR},
		"free text":                  {"looks fine to me", "end_turn", 200, m1pv1.Verdict_VERDICT_ERROR},
		"budget exhausted":           {"", "max_tokens", 200, m1pv1.Verdict_VERDICT_ERROR},
		"http 500":                   {"violated", "end_turn", 500, m1pv1.Verdict_VERDICT_ERROR},
		"http 401":                   {"violated", "end_turn", 401, m1pv1.Verdict_VERDICT_ERROR},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			h.stub.reply, h.stub.stop, h.stub.status = tc.reply, tc.stop, tc.status
			r := h.runner()
			r.Handle(request(nil))
			if jv := h.vote(r); jv.GetVote() != tc.want {
				t.Fatalf("vote = %v, want %v", jv.GetVote(), tc.want)
			}
		})
	}
	t.Run("network error", func(t *testing.T) {
		h := newHarness(t)
		h.stub.srv.Close()
		r := h.runner()
		r.Handle(request(nil))
		if jv := h.vote(r); jv.GetVote() != m1pv1.Verdict_VERDICT_ERROR {
			t.Fatalf("vote = %v, want ERROR", jv.GetVote())
		}
		if strings.Contains(h.logs.String(), h.stub.srv.URL) {
			t.Fatal("the transport error echoed the request URL into the log")
		}
	})
}

func TestJudgeRefusesWithNoTypedEvidenceAndClampsTierToE0(t *testing.T) {
	h := newHarness(t)
	h.evidence = ""
	r := h.runner()
	r.Handle(request(nil))
	if jv := h.vote(r); jv.GetVote() != m1pv1.Verdict_VERDICT_REFUSED {
		t.Fatalf("vote = %v, want REFUSED", jv)
	}
	if h.stub.count() != 0 {
		t.Fatal("a call was made with nothing to show the judge")
	}
	h.evidence = evidence
	r.Handle(request(func(q *m1pv1.JudgeRequest) { q.RequestId = "e1"; q.Tier = m1pv1.EvidenceTier_EVIDENCE_TIER_E1 }))
	jv := h.vote(r)
	if jv.GetTierUsed() != m1pv1.EvidenceTier_EVIDENCE_TIER_E0 || jv.GetVote() != m1pv1.Verdict_VERDICT_VIOLATED {
		t.Fatalf("an E1 request must be answered at the consented E0, got %v", jv)
	}
	c := h.stub.calls[0]
	if strings.Contains(c.body["messages"].([]any)[0].(map[string]any)["content"].(string), "diff") {
		t.Fatal("hunks reached the prompt at E0")
	}
}

func TestJudgeIgnoresMalformedRequestsWithoutAVote(t *testing.T) {
	h := newHarness(t)
	r := h.runner()
	for name, data := range map[string][]byte{
		"not protojson":  []byte("[]"),
		"cloud locus":    request(func(q *m1pv1.JudgeRequest) { q.Locus = m1pv1.JudgeLocus_JUDGE_LOCUS_CLOUD }),
		"zero budget":    request(func(q *m1pv1.JudgeRequest) { q.TokenBudget = 0 }),
		"huge budget":    request(func(q *m1pv1.JudgeRequest) { q.TokenBudget = maxBudget + 1 }),
		"short task id":  request(func(q *m1pv1.JudgeRequest) { q.TaskId = q.TaskId[:15] }),
		"empty rubric":   request(func(q *m1pv1.JudgeRequest) { q.Rubric = "" }),
		"oversize":       request(func(q *m1pv1.JudgeRequest) { q.Rubric = strings.Repeat("x", maxRubric+1) }),
		"request id nl":  request(func(q *m1pv1.JudgeRequest) { q.RequestId = "a\nb" }),
		"model not iden": request(func(q *m1pv1.JudgeRequest) { q.Model = "claude sonnet" }),
	} {
		r.Handle(data)
		if h.stub.count() != 0 {
			t.Fatalf("%s: a model call was made", name)
		}
	}
	h.noVote()
	if len(seenLines(t, h.dir)) != 0 {
		t.Fatal("a malformed request was marked seen")
	}
}

func TestJudgeWithoutATenantRootEmitsNoRubricHashRatherThanAnUnkeyedOne(t *testing.T) {
	h := newHarness(t)
	h.cfg.TenantRoot = nil
	r := h.runner()
	r.Handle(request(nil))
	if jv := h.vote(r); len(jv.GetRubricHash()) != 0 {
		t.Fatalf("rubric_hash = %x without a tenant root", jv.GetRubricHash())
	}
}

func TestJudgeNewRequiresItsSeams(t *testing.T) {
	h := newHarness(t)
	for name, mut := range map[string]func(*Config){
		"state dir": func(c *Config) { c.StateDir = "" },
		"task for":  func(c *Config) { c.TaskFor = nil },
		"evidence":  func(c *Config) { c.Evidence = nil },
		"admit":     func(c *Config) { c.Admit = nil },
	} {
		cfg := h.cfg
		mut(&cfg)
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: New accepted a config with no %s", name, name)
		}
	}
	cfg := h.cfg
	cfg.Credential, cfg.BaseURL, cfg.HTTPClient, cfg.Log = nil, "", nil, nil
	t.Setenv("ANTHROPIC_API_KEY", "")
	r, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if r.base != DefaultBaseURL || r.cfg.Credential() != "" {
		t.Fatalf("defaults: base %q, credential %q", r.base, r.cfg.Credential())
	}
	t.Setenv("ANTHROPIC_API_KEY", apiKey)
	if r.cfg.Credential() != apiKey {
		t.Fatal("the default credential is not the daemon's ANTHROPIC_API_KEY (the proxy provisioning's reading)")
	}
}

// The edge third of the judge-request seam lock (go/controld/internal/policydist/testdata/judge_request_body.json): the cloud's exact request decodes here and is answered.
func TestJudgeDecodesTheCloudsExactRequest(t *testing.T) {
	raw, err := os.ReadFile("../../../controld/internal/policydist/testdata/judge_request_body.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Body struct {
			Request json.RawMessage `json:"request"`
		} `json:"body"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	req, err := decode(fixture.Body.Request)
	if err != nil {
		t.Fatalf("the cloud's exact request does not decode at the edge: %v", err)
	}
	if req.GetRequestId() != "c8174949-94d6-52c9-85da-9c7fa304b757" || req.GetTokenBudget() != 2048 || req.GetModel() != "claude-sonnet-5" || len(req.GetTaskId()) != 16 {
		t.Fatalf("decoded = %v", req.String())
	}
	h := newHarness(t)
	copy(task[:], req.GetTaskId())
	copy(session[:], req.GetSessionId())
	t.Cleanup(func() {
		task = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
		session = [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
	})
	r := h.runner()
	r.Handle(fixture.Body.Request)
	if jv := h.vote(r); jv.GetVote() != m1pv1.Verdict_VERDICT_VIOLATED || jv.GetJudgeId() != "judge:grounded-rubric@1" {
		t.Fatalf("vote = %v", jv)
	}
	if got := h.stub.calls[0].body["max_tokens"]; got != float64(2048) {
		t.Fatalf("max_tokens = %v, want the request's token_budget", got)
	}
}
