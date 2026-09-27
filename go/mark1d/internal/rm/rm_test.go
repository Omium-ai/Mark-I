package rm

import (
	"bytes"
	"cmp"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/anchors"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/redact"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/supervise"
)

// TestMain doubles as the stub runtime: MARK1_RM_TEST_STUB=serve|crash turns the test binary into a llama-server stand-in.
func TestMain(m *testing.M) {
	anchors.MaybeRunHelper() // the anchors sandbox re-execs this binary for its helper stage
	if os.Getenv("MARK1_RM_TEST_STUB") != "" && slices.Contains(os.Args, "--version") {
		_, _ = os.Stderr.WriteString("version: 0.5.0-dev (build " + cmp.Or(os.Getenv("MARK1_RM_TEST_BUILD"), "11193") + ", commit 4e7481175)\n")
		os.Exit(0)
	}
	switch os.Getenv("MARK1_RM_TEST_STUB") {
	case "serve":
		stubServe()
	case "crash":
		os.Exit(3)
	}
	os.Exit(m.Run())
}

func stubServe() {
	port := ""
	for i, a := range os.Args {
		if a == "--port" && i+1 < len(os.Args) {
			port = os.Args[i+1]
		}
	}
	yes, no := 0.6, 0.2
	if strings.Contains(strings.Join(os.Args, " "), "mark1-rm-b@") {
		yes, no = 0.2, 0.6
	}
	stub := newStub(os.Getenv("LLAMA_API_KEY"), yes, no)
	stub.promptOut, stub.trace = os.Getenv("MARK1_RM_TEST_PROMPT_OUT"), os.Getenv("MARK1_RM_TEST_TRACE")
	_ = http.ListenAndServe("127.0.0.1:"+port, stub.mux()) //nolint:gosec // G114: test stub
	os.Exit(0)
}

const stubYes, stubNo = 1 << 20, 1<<20 + 1

// stubRuntime is llama-server's scoring surface over a rune tokenizer: " yes"/" no" are single tokens, every other text one token per rune.
type stubRuntime struct {
	key              string
	yes, no          float64
	promptOut, trace string
	raw              string // a verbatim /completion answer; "500" answers HTTP 500
	mu               sync.Mutex
	prompt           []int
	req              map[string]any
}

func newStub(key string, yes, no float64) *stubRuntime {
	return &stubRuntime{key: key, yes: yes, no: no}
}

func (st *stubRuntime) last() ([]int, map[string]any) {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.prompt, st.req
}

func stubTokens(text string, special bool) []int {
	switch {
	case special && text == " yes":
		return []int{stubYes}
	case special && text == " no":
		return []int{stubNo}
	}
	var ids []int
	for _, r := range text {
		ids = append(ids, int(r))
	}
	return ids
}

func stubText(ids []int) string {
	var b strings.Builder
	for _, id := range ids {
		b.WriteRune(rune(id))
	}
	return b.String()
}

func (st *stubRuntime) mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"status":"ok"}`)) })
	authed := func(h func(map[string]any) any) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer "+st.key {
				http.Error(w, "no key", http.StatusUnauthorized)
				return
			}
			if r.URL.Path == "/completion" && st.raw == "500" {
				http.Error(w, "x", http.StatusInternalServerError)
				return
			}
			if r.URL.Path == "/completion" && st.raw != "" {
				_, _ = w.Write([]byte(st.raw))
				return
			}
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			_ = json.NewEncoder(w).Encode(h(body))
		}
	}
	mux.HandleFunc("POST /tokenize", authed(func(b map[string]any) any {
		return map[string]any{"tokens": stubTokens(b["content"].(string), b["parse_special"].(bool))}
	}))
	mux.HandleFunc("POST /completion", authed(func(b map[string]any) any {
		var ids []int
		for _, v := range b["prompt"].([]any) {
			ids = append(ids, int(v.(float64)))
		}
		st.mu.Lock()
		st.prompt, st.req = ids, b
		st.mu.Unlock()
		if st.promptOut != "" {
			_ = os.WriteFile(st.promptOut, []byte(stubText(ids)), 0o600)
		}
		if st.trace != "" {
			appendLine(st.trace, "begin")
			time.Sleep(80 * time.Millisecond)
			if os.Getenv("MARK1_RM_TEST_SLOW") != "" {
				time.Sleep(time.Second)
			}
			defer appendLine(st.trace, "end")
		}
		return map[string]any{"completion_probabilities": []any{map[string]any{"top_probs": []any{
			map[string]any{"id": stubYes, "token": " yes", "prob": st.yes}, map[string]any{"id": stubNo, "token": " no", "prob": st.no},
		}}}}
	}))
	return mux
}

func appendLine(path, line string) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // G304: test trace
	if err == nil {
		_, _ = f.WriteString(line + "\n")
		_ = f.Close()
	}
}

type fakeKey struct{ priv ed25519.PrivateKey }

func (f fakeKey) Sign(msg []byte) ([]byte, error) { return ed25519.Sign(f.priv, msg), nil }
func (f fakeKey) KeyID() string                   { return "test" }

func TestRenderMatchesTrainingRenderer(t *testing.T) {
	b, err := os.ReadFile("testdata/parity.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name, Task, Diff, Abstain, Text string
		MaxDiffChars                    int `json:"max_diff_chars"`
	}
	if err := json.Unmarshal(b, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) < 10 {
		t.Fatalf("parity fixture has %d cases", len(cases))
	}
	for _, c := range cases {
		r := Render(c.Task, c.Diff, c.MaxDiffChars)
		got := ""
		if r.Abstain == "" {
			got = r.Text()
		}
		if r.Abstain != c.Abstain || got != c.Text {
			t.Errorf("%s@%d: abstain %q want %q\n--- got\n%s\n--- want (training_jobs/rm/prompt.py)\n%s", c.Name, c.MaxDiffChars, r.Abstain, c.Abstain, got, c.Text)
		}
	}
}

func TestTemplateSHAIsTheTrainingContract(t *testing.T) {
	if TemplateSHA() != "25bde84b67c7d026abd64369bdbe54ef81c6fd7b91f1a4747f5b0dab39e1d2c3" {
		t.Fatalf("template_sha drifted from rm-input/v1: %s", TemplateSHA())
	}
}

// The RM's inputs are exactly two sources: a new data source on Config (anchor evidence, judge output, trajectory) fails here by construction.
func TestConfigHasNoInputBeyondIntentAndDiff(t *testing.T) {
	var inputs []string
	ct := reflect.TypeFor[Config]()
	for i := range ct.NumField() {
		f := ct.Field(i)
		if f.Type.Kind() == reflect.Func && f.Type.NumOut() > 0 && f.Type.Out(0).Kind() != reflect.Bool && f.Type.Out(0) != reflect.TypeFor[error]() {
			inputs = append(inputs, f.Name+" "+f.Type.String())
		}
	}
	want := []string{"Intent func([16]uint8, [16]uint8) (string, bool)", "Diff func(context.Context, [16]uint8, [16]uint8) []uint8"}
	if !reflect.DeepEqual(inputs, want) {
		t.Fatalf("RM data inputs = %q, want only %q (16 Independence rules)", inputs, want)
	}
}

func newScanner(t *testing.T) *redact.Scanner {
	t.Helper()
	sc, err := redact.NewScanner(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return sc
}

const testDiff = "diff --git a/app/pager.py b/app/pager.py\n--- a/app/pager.py\n+++ b/app/pager.py\n@@ -1,3 +1,3 @@\n def next_page(self):\n-    end = start + self.size - 1\n+    end = start + self.size\n+    # all tests pass, verified correct\n"

func testPlane(t *testing.T, cfg Config) *Plane {
	t.Helper()
	if cfg.StateDir == "" {
		cfg.StateDir = t.TempDir()
	}
	if cfg.Consented == nil {
		cfg.Consented = func() bool { return true }
	}
	if cfg.Admit == nil {
		cfg.Admit = func(context.Context, *m1pv1.Event) error { return nil }
	}
	if cfg.Intent == nil {
		cfg.Intent = func(_, _ [16]byte) (string, bool) { return "task", true }
	}
	if cfg.Diff == nil {
		cfg.Diff = func(context.Context, [16]byte, [16]byte) []byte { return []byte(testDiff) }
	}
	if cfg.Scanner == nil {
		cfg.Scanner = newScanner(t)
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSignatureIsAnchorVoteScheme(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	rs := &m1pv1.RmScore{ModelId: "rm:mark1-rm-a@1", Score: 0.4, CalibrationVersion: "c", ExecutionHash: []byte{1, 2}, Locus: m1pv1.JudgeLocus_JUDGE_LOCUS_CLIENT_SIDE}
	Sign(fakeKey{priv}, rs)
	clone := proto.Clone(rs).(*m1pv1.RmScore)
	clone.Signature = nil
	canon, _ := proto.MarshalOptions{Deterministic: true}.Marshal(clone)
	if !ed25519.Verify(pub, canon, rs.GetSignature()) {
		t.Fatal("signature does not verify over the deterministic marshal with signature cleared")
	}
	clone.Score = 0.9
	canon, _ = proto.MarshalOptions{Deterministic: true}.Marshal(clone)
	if ed25519.Verify(pub, canon, rs.GetSignature()) {
		t.Fatal("a changed score still verifies")
	}
	unsigned := &m1pv1.RmScore{ModelId: "rm:mark1-rm-a@1"}
	Sign(nil, unsigned)
	if len(unsigned.GetSignature()) != 0 {
		t.Fatal("no key must leave the score unsigned, never forged")
	}
}

const testRuntime = "llama.cpp b11193"

func stubManifest(slot string) Manifest {
	return Manifest{Name: "mark1-rm-" + slot, Version: 1, SHA256: strings.Repeat("0", 64), SizeBytes: 1, CalibrationVersion: "temp-v1",
		TemplateSHA: TemplateSHA(), EvalCardSHA: strings.Repeat("1", 64), ExecutionHash: strings.Repeat("2", 64), Scoring: Scoring{Method: "logit_diff", Yes: " yes", No: " no"}}
}

// The runtime receives Render(intent, redacted diff) as token ids and nothing else: sentinels planted in every other channel never arrive.
func TestPromptCarriesOnlyIntentAndDiff(t *testing.T) {
	stub := newStub("k", 0.3, 0.1)
	srv := httptest.NewServer(stub.mux())
	defer srv.Close()
	secret := "AKIAIOSFODNN7EXAMPLE"
	p := testPlane(t, Config{
		Intent: func(_, _ [16]byte) (string, bool) { return "Fix the off-by-one in next_page", true },
		Diff: func(context.Context, [16]byte, [16]byte) []byte {
			return []byte(testDiff + "+    key = \"" + secret + "\"\n")
		},
	})
	r := p.prompt(context.Background(), closed{})
	score, err := p.complete(context.Background(), liveSlot(stubManifest("a"), srv), r.Prefix)
	if err != nil || math.Abs(score-0.75) > 1e-9 {
		t.Fatalf("score %v err %v", score, err)
	}
	ids, req := stub.last()
	got := stubText(ids)
	diff, _, _ := newScanner(t).Admit([]byte(testDiff + "+    key = \"" + secret + "\"\n"))
	if want := Prompt("Fix the off-by-one in next_page", diff).Text(); got != want {
		t.Fatalf("runtime prompt is not Render(intent, diff):\n%s\n---\n%s", got, want)
	}
	for _, banned := range []string{secret, "all tests pass", "EvidenceRecord", "VERDICT_", "judge"} {
		if strings.Contains(got, banned) {
			t.Fatalf("prompt carries %q:\n%s", banned, got)
		}
	}
	if !strings.HasPrefix(got, "<|task|>\nFix the off-by-one") || !strings.HasSuffix(got, Suffix) {
		t.Fatalf("prompt shape:\n%s", got)
	}
	var want map[string]any
	b, _ := json.Marshal(scoreRequest)
	_ = json.Unmarshal(b, &want)
	for k, v := range want {
		if !reflect.DeepEqual(req[k], v) {
			t.Errorf("request %s = %v, want %v", k, req[k], v)
		}
	}
	if b := req["logit_bias"]; !reflect.DeepEqual(b, []any{[]any{float64(stubYes), logitBias}, []any{float64(stubNo), logitBias}}) {
		t.Errorf("logit_bias %v", b)
	}
}

// A prefix past the context keeps its head and the whole suffix, exactly objective.encode's cut.
func TestInputIDsTruncateLikeTraining(t *testing.T) {
	srv := httptest.NewServer(newStub("k", 0.5, 0.5).mux())
	defer srv.Close()
	base := srv.URL
	prefix := strings.Repeat("x", MaxSeqLen*2)
	ids, yes, no, err := inputIDs(context.Background(), base, "k", stubManifest("a"), prefix)
	if err != nil || yes != stubYes || no != stubNo {
		t.Fatalf("%v %d %d", err, yes, no)
	}
	keep := MaxSeqLen - len([]rune(Suffix))
	if len(ids) != MaxSeqLen || stubText(ids) != prefix[:keep]+Suffix {
		t.Fatalf("ids %d long, want the first %d prefix tokens then the suffix", len(ids), keep)
	}
	if ids, _, _, _ := inputIDs(context.Background(), base, "k", stubManifest("a"), "short"); stubText(ids) != "short"+Suffix {
		t.Fatalf("an in-budget prefix is sent whole: %q", stubText(ids))
	}
	m := stubManifest("a")
	m.Scoring.Yes = " maybe"
	if _, _, _, err := inputIDs(context.Background(), base, "k", m, "x"); err == nil {
		t.Fatal("an answer that is not one token must refuse to score")
	}
}

func liveSlot(m Manifest, srv *httptest.Server) *slot {
	s := &slot{m: m}
	if srv != nil {
		k := "k"
		s.key.Store(&k)
		s.port.Store(int64(srv.Listener.Addr().(*net.TCPAddr).Port))
	}
	s.live.Store(true)
	return s
}

func TestAbstainPaths(t *testing.T) {
	noIntent := func(_, _ [16]byte) (string, bool) { return "", false }
	noDiff := func(context.Context, [16]byte, [16]byte) []byte { return nil }
	lockOnly := func(context.Context, [16]byte, [16]byte) []byte {
		return []byte("diff --git a/yarn.lock b/yarn.lock\n--- a/yarn.lock\n+++ b/yarn.lock\n@@ -1 +1 @@\n-a\n+b\n")
	}
	for name, c := range map[string]struct {
		cfg    Config
		reason string
	}{
		"no intent":     {Config{Intent: noIntent}, AbstainNoTask},
		"no diff":       {Config{Diff: noDiff}, AbstainNoChange},
		"lockfile only": {Config{Diff: lockOnly}, AbstainNoChange},
	} {
		if r := testPlane(t, c.cfg).prompt(context.Background(), closed{}); r.Abstain != c.reason {
			t.Errorf("%s: abstain %q, want %q", name, r.Abstain, c.reason)
		}
	}
	yesOnly := newStub("k", 0, 0)
	yesOnly.raw = `{"completion_probabilities":[{"top_probs":[{"id":1048576,"token":" yes","prob":0.9}]}]}`
	onlyYes := httptest.NewServer(yesOnly.mux())
	defer onlyYes.Close()
	failing := newStub("k", 0, 0)
	failing.raw = "500"
	broken := httptest.NewServer(failing.mux())
	defer broken.Close()
	p := testPlane(t, Config{})
	for name, s := range map[string]*slot{"runtime 500": liveSlot(stubManifest("a"), broken), "one side ranked": liveSlot(stubManifest("a"), onlyYes), "runtime down": liveSlot(stubManifest("a"), nil)} {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		if _, err := p.complete(ctx, s, "x"); err == nil {
			t.Errorf("%s: a runtime failure must not yield a score", name)
		}
		cancel()
	}
}

func modelServer(t *testing.T, bodies map[string][]byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for slot, body := range bodies {
			if r.URL.Path == "/mark1-rm-"+slot+"@1/model.gguf" {
				_, _ = w.Write(body)
				return
			}
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func pinned(slot string, body []byte) Manifest {
	m := stubManifest(slot)
	h := sha256.Sum256(body)
	x, _ := executionHash(bytes.NewReader(body), testRuntime)
	m.SHA256, m.SizeBytes, m.ExecutionHash = hex.EncodeToString(h[:]), int64(len(body)), hex.EncodeToString(x)
	return m
}

func TestCatalogHashPin(t *testing.T) {
	body := []byte("GGUF tiny model bytes")
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.URL.Path != "/mark1-rm-a@1/model.gguf" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	dir := t.TempDir()
	m := pinned("a", body)
	path, err := ensureModel(context.Background(), srv.Client(), srv.URL, dir, m)
	if err != nil || path != ModelPath(dir, m) {
		t.Fatalf("pinned download: %v %s", err, path)
	}
	if _, err := ensureModel(context.Background(), srv.Client(), srv.URL, dir, m); err != nil || hits != 1 {
		t.Fatalf("a verified model is not fetched twice: hits %d err %v", hits, err)
	}
	if err := os.WriteFile(path, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureModel(context.Background(), srv.Client(), srv.URL, dir, m); err != nil || hits != 2 {
		t.Fatalf("a tampered model is replaced from the pin: hits %d err %v", hits, err)
	}
	bad := m
	bad.SHA256 = strings.Repeat("a", 64)
	dir2 := t.TempDir()
	if _, err := ensureModel(context.Background(), srv.Client(), srv.URL, dir2, bad); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("hash mismatch: %v", err)
	}
	if _, err := os.Stat(ModelPath(dir2, bad)); !os.IsNotExist(err) {
		t.Fatal("a model failing the pin must not be left on disk")
	}
	short := m
	short.SizeBytes = 3
	if _, err := ensureModel(context.Background(), srv.Client(), srv.URL, t.TempDir(), short); err == nil {
		t.Fatal("a body longer than size_bytes must be refused")
	}
}

func TestManifestValidation(t *testing.T) {
	good := stubManifest("a")
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*Manifest){
		"no name":        func(m *Manifest) { m.Name = "" },
		"slot c":         func(m *Manifest) { m.Name = "mark1-rm-c" },
		"other name":     func(m *Manifest) { m.Name = "rm-a" },
		"version 0":      func(m *Manifest) { m.Version = 0 },
		"short sha":      func(m *Manifest) { m.SHA256 = "abc" },
		"no calibration": func(m *Manifest) { m.CalibrationVersion = "" },
		"other template": func(m *Manifest) { m.TemplateSHA = strings.Repeat("2", 64) },
		"pairwise":       func(m *Manifest) { m.Scoring.Method = "bt" },
		"same tokens":    func(m *Manifest) { m.Scoring.No = " yes" },
		"quote token":    func(m *Manifest) { m.Scoring.Yes = `" | x` },
	} {
		m := good
		mut(&m)
		if m.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	a2 := stubManifest("a")
	a2.Version = 2
	badA3 := stubManifest("a")
	badA3.Version, badA3.TemplateSHA = 3, "x"
	got := Active([]Manifest{stubManifest("b"), stubManifest("a"), a2, badA3})
	if len(got) != 2 || got[0].ModelID() != "rm:mark1-rm-a@2" || got[1].ModelID() != "rm:mark1-rm-b@1" {
		t.Fatalf("newest valid per slot, a before b, an invalid newest skipped: %v", got)
	}
	if len(Active(nil)) != 0 {
		t.Fatal("an empty catalog serves nothing")
	}
	if Catalog() == nil {
		t.Fatal("the embedded catalog does not parse")
	}
	for _, m := range Catalog() {
		if err := m.Validate(); err != nil {
			t.Errorf("shipped catalog entry %s: %v", m.ModelID(), err)
		}
	}
	for name, doc := range map[string]string{
		"string version": `[{"name":"mark1-rm-a","version":"1"}]`,
		"unknown field":  `[{"name":"mark1-rm-a","version":1,"slot":"a"}]`,
		"scoring extra":  `[{"name":"mark1-rm-a","version":1,"scoring":{"method":"logit_diff","yes":" yes","no":" no","bias":1}}]`,
	} {
		if _, err := parseCatalog([]byte(doc)); err == nil {
			t.Errorf("%s: a catalog off the export's manifest shape parsed", name)
		}
	}
}

func waitStatus(t *testing.T, dir, want string, detail ...string) Status {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if s, ok := ReadStatus(dir); ok && s.State == want && !slices.ContainsFunc(detail, func(d string) bool { return !strings.Contains(s.Detail, d) }) {
			return s
		}
		time.Sleep(20 * time.Millisecond)
	}
	s, _ := ReadStatus(dir)
	t.Fatalf("status %+v, want %s %q", s, want, detail)
	return s
}

type harness struct {
	p        *Plane
	dir      string
	admitted chan *m1pv1.Event
	stop     func() // ends the session ctx (`mark1 off`) and waits for Run
}

func runPlane(t *testing.T, stub string, catalog []Manifest, bodies map[string][]byte, mut func(*Config)) *harness {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("MARK1_RM_TEST_STUB", stub)
	srv := modelServer(t, bodies)
	h := &harness{dir: t.TempDir(), admitted: make(chan *m1pv1.Event, 8)}
	cfg := Config{
		StateDir: h.dir, Catalog: catalog, BaseURL: srv.URL, Binary: self, HTTP: srv.Client(), Poll: 30 * time.Millisecond,
		Admit:  func(_ context.Context, ev *m1pv1.Event) error { h.admitted <- ev; return nil },
		Intent: func(_, _ [16]byte) (string, bool) { return "TASK_SENTINEL fix pager", true },
	}
	if mut != nil {
		mut(&cfg)
	}
	h.p = testPlane(t, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); h.p.Run(ctx) }()
	h.stop = func() { cancel(); <-done }
	t.Cleanup(h.stop)
	return h
}

func (h *harness) closeTask(task [16]byte) {
	session := [16]byte{9}
	h.p.Observe(&m1pv1.Event{SessionId: session[:], TaskId: task[:], Body: &m1pv1.Event_TaskClose{TaskClose: &m1pv1.TaskClose{Resolution: m1pv1.Resolution_RESOLUTION_UNRESOLVED_SESSION_END}}})
}

func (h *harness) scores(t *testing.T, n int) map[string]*m1pv1.RmScore {
	t.Helper()
	out := map[string]*m1pv1.RmScore{}
	for len(out) < n {
		select {
		case ev := <-h.admitted:
			out[ev.GetRmScore().GetModelId()] = ev.GetRmScore()
		case <-time.After(15 * time.Second):
			t.Fatalf("got %d RmScores, want %d", len(out), n)
		}
	}
	select {
	case extra := <-h.admitted:
		t.Fatalf("an extra RmScore: %v", extra)
	case <-time.After(200 * time.Millisecond):
	}
	return out
}

func verifies(pub ed25519.PublicKey, rs *m1pv1.RmScore) bool {
	clone := proto.Clone(rs).(*m1pv1.RmScore)
	clone.Signature = nil
	canon, _ := proto.MarshalOptions{Deterministic: true}.Marshal(clone)
	return ed25519.Verify(pub, canon, rs.GetSignature())
}

// Both slots score one task: two signed RmScores with distinct model ids and executions, computed one after the other; revocation stops both children.
func TestBothSlotsScoreOneTask(t *testing.T) {
	bodies := map[string][]byte{"a": []byte("GGUF qwen"), "b": []byte("GGUF granite")}
	trace := filepath.Join(t.TempDir(), "trace")
	t.Setenv("MARK1_RM_TEST_TRACE", trace)
	promptOut := filepath.Join(t.TempDir(), "prompt")
	t.Setenv("MARK1_RM_TEST_PROMPT_OUT", promptOut)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	var mu sync.Mutex
	on := true
	h := runPlane(t, "serve", []Manifest{pinned("a", bodies["a"]), pinned("b", bodies["b"])}, bodies, func(c *Config) {
		c.Consented = func() bool { mu.Lock(); defer mu.Unlock(); return on }
	})
	h.p.SetSigner(fakeKey{priv})
	if s := waitStatus(t, h.dir, "ready"); s.ModelID != "rm:mark1-rm-a@1,rm:mark1-rm-b@1" {
		t.Fatalf("status %+v", s)
	}
	task := [16]byte{7}
	h.p.Observe(&m1pv1.Event{SessionId: task[:], TaskId: task[:], Body: &m1pv1.Event_TaskClose{TaskClose: &m1pv1.TaskClose{Resolution: m1pv1.Resolution_RESOLUTION_MERGED_FORWARD}}})
	h.closeTask(task)
	got := h.scores(t, 2)
	a, b := got["rm:mark1-rm-a@1"], got["rm:mark1-rm-b@1"]
	if a == nil || b == nil || math.Abs(a.GetScore()-0.75) > 1e-9 || math.Abs(b.GetScore()-0.25) > 1e-9 {
		t.Fatalf("scores %v", got)
	}
	for slot, rs := range map[string]*m1pv1.RmScore{"a": a, "b": b} {
		want, _ := hex.DecodeString(pinned(slot, bodies[slot]).ExecutionHash)
		if !reflect.DeepEqual(rs.GetExecutionHash(), want) || rs.GetLocus() != m1pv1.JudgeLocus_JUDGE_LOCUS_CLIENT_SIDE || rs.GetCalibrationVersion() != "temp-v1" || !verifies(pub, rs) {
			t.Fatalf("slot %s RmScore %v", slot, rs)
		}
		if wire, _ := proto.Marshal(rs); strings.Contains(string(wire), "TASK_SENTINEL") {
			t.Fatal("task text reached the spooled event")
		}
	}
	if reflect.DeepEqual(a.GetExecutionHash(), b.GetExecutionHash()) {
		t.Fatal("the two slots must name different executions")
	}
	if p, _ := os.ReadFile(promptOut); !strings.HasPrefix(string(p), "<|task|>\nTASK_SENTINEL fix pager\n<|meta|>") {
		t.Fatalf("child saw %q", p)
	}
	if tr, _ := os.ReadFile(trace); string(tr) != "begin\nend\nbegin\nend\n" {
		t.Fatalf("the two models must never compute at once: %q", tr)
	}
	mu.Lock()
	on = false
	mu.Unlock()
	waitStatus(t, h.dir, "off")
	for _, s := range h.p.slots {
		if s.port.Load() != 0 || s.live.Load() {
			t.Fatalf("revoking the consent must stop slot %s", s.m.Slot())
		}
	}
}

// `mark1 off` cancels the session ctx: both llama-server children are gone when Run returns.
func TestSessionEndKillsBothChildren(t *testing.T) {
	bodies := map[string][]byte{"a": []byte("GGUF qwen"), "b": []byte("GGUF granite")}
	h := runPlane(t, "serve", []Manifest{pinned("a", bodies["a"]), pinned("b", bodies["b"])}, bodies, nil)
	waitStatus(t, h.dir, "ready")
	var bases []string
	for _, s := range h.p.slots {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		base, _, err := waitHealthy(ctx, s)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		bases = append(bases, base)
	}
	h.stop()
	for _, base := range bases {
		if resp, err := http.Get(base + "/health"); err == nil { //nolint:noctx // a loopback probe of a child that must be dead
			_ = resp.Body.Close()
			t.Fatalf("%s still answers after the session ended", base)
		}
	}
}

// Withdrawing local_rm mid-download aborts the transfer instead of finishing a GB the user just declined.
func TestRevokeAbortsADownloadInFlight(t *testing.T) {
	body := []byte("GGUF qwen, long")
	var on atomic.Bool
	on.Store(true)
	started, aborted := make(chan struct{}), make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body[:4])
		w.(http.Flusher).Flush()
		close(started)
		<-r.Context().Done()
		close(aborted)
	}))
	defer srv.Close()
	self, _ := os.Executable()
	dir := t.TempDir()
	p := testPlane(t, Config{StateDir: dir, Catalog: []Manifest{pinned("a", body)}, BaseURL: srv.URL, Binary: self, HTTP: srv.Client(),
		Poll: 20 * time.Millisecond, Consented: on.Load})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); p.Run(ctx) }()
	defer func() { cancel(); <-done }()
	<-started
	on.Store(false)
	select {
	case <-aborted:
	case <-time.After(5 * time.Second):
		t.Fatal("the download kept running after the consent was withdrawn")
	}
	waitStatus(t, dir, "off")
	if _, err := os.Stat(ModelPath(dir, pinned("a", body)) + ".part"); !os.IsNotExist(err) {
		t.Fatal("an aborted download must leave no partial file")
	}
}

func TestOneSlotMissingTheOtherStillScores(t *testing.T) {
	t.Run("not in the catalog", func(t *testing.T) {
		body := []byte("GGUF granite")
		h := runPlane(t, "serve", []Manifest{pinned("b", body)}, map[string][]byte{"b": body}, nil)
		if s := waitStatus(t, h.dir, "ready"); s.ModelID != "rm:mark1-rm-b@1" {
			t.Fatalf("status %+v", s)
		}
		h.closeTask([16]byte{1})
		if got := h.scores(t, 1); got["rm:mark1-rm-b@1"] == nil {
			t.Fatalf("%v", got)
		}
	})
	t.Run("download fails", func(t *testing.T) {
		body := []byte("GGUF qwen")
		h := runPlane(t, "serve", []Manifest{pinned("a", body), pinned("b", []byte("never served"))}, map[string][]byte{"a": body}, nil)
		s := waitStatus(t, h.dir, "download_failed", "rm:mark1-rm-a@1 ready", "rm:mark1-rm-b@1 download_failed")
		if len(s.Models) != 2 || s.Models[0].State != "ready" || s.Models[1].State != "download_failed" {
			t.Fatalf("status %+v", s)
		}
		h.closeTask([16]byte{2})
		if got := h.scores(t, 1); got["rm:mark1-rm-a@1"] == nil {
			t.Fatalf("%v", got)
		}
	})
}

func TestWeightsBudgetServesWhatFits(t *testing.T) {
	a, b := []byte("GGUF qwen 12345"), []byte("GGUF granite 1")
	h := runPlane(t, "serve", []Manifest{pinned("a", a), pinned("b", b)}, map[string][]byte{"a": a, "b": b}, func(c *Config) {
		c.WeightsBudget = int64(len(a) + len(b) - 1)
	})
	s := waitStatus(t, h.dir, "ready")
	if s.ModelID != "rm:mark1-rm-a@1" || !strings.Contains(s.Detail, "rm:mark1-rm-b@1 not_served") || len(s.Models) != 2 || s.Models[1].State != "not_served" || len(h.p.slots) != 1 {
		t.Fatalf("status %+v", s)
	}
	h.closeTask([16]byte{3})
	h.scores(t, 1)
	if p := testPlane(t, Config{Catalog: []Manifest{pinned("a", a), pinned("b", b)}}); len(p.slots) != 2 || p.cfg.WeightsBudget != WeightsBudget {
		t.Fatal("the default budget serves both slots")
	}
}

func TestCrashLoopTripsTheBreakerAndStaysDown(t *testing.T) {
	body := []byte("GGUF stub")
	h := runPlane(t, "crash", []Manifest{pinned("a", body)}, map[string][]byte{"a": body}, func(c *Config) {
		c.Backoff = supervise.Backoff{Base: time.Millisecond, Cap: 2 * time.Millisecond}
		c.Breaker = supervise.Breaker{Max: 2, Window: time.Minute}
	})
	s := waitStatus(t, h.dir, "failed")
	if s.Healthy() || !strings.Contains(s.Detail, "crash-looped") {
		t.Fatalf("status %+v", s)
	}
	if ok, _ := Check(h.dir); ok {
		t.Fatal("doctor must report a crash-looped runtime")
	}
	time.Sleep(200 * time.Millisecond)
	if st, _ := ReadStatus(h.dir); st.State != "failed" || h.p.slots[0].live.Load() {
		t.Fatalf("a FAILED runtime restarted within the session: %+v", st)
	}
}

func TestNoCatalogEntryIsAnHonestNoModel(t *testing.T) {
	dir := t.TempDir()
	p := testPlane(t, Config{StateDir: dir, Catalog: []Manifest{}, Poll: time.Hour})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); p.Run(ctx) }()
	s := waitStatus(t, dir, "no_model")
	if ok, _ := Check(dir); !ok || s.ModelID != "" {
		t.Fatalf("no published model is not a failure: %+v", s)
	}
	cancel()
	<-done
}

// rm-exec/v1 is one recipe on both sides: this vector is export.py's execution_hash for the same inputs (blake3 1.0.9).
func TestExecutionHashIsTheExportRecipe(t *testing.T) {
	gguf := filepath.Join(t.TempDir(), "model.gguf")
	if err := os.WriteFile(gguf, []byte("GGUF rm-exec/v1 vector"), 0o600); err != nil {
		t.Fatal(err)
	}
	h, err := ExecutionHash(gguf, testRuntime)
	if err != nil || hex.EncodeToString(h) != "32a997ee8842d4906314d2175efa4b9b5d83c2def873f4577dbe12758db03fea" {
		t.Fatalf("%x %v", h, err)
	}
	for _, other := range []string{"llama.cpp b11194", ""} {
		if o, _ := ExecutionHash(gguf, other); reflect.DeepEqual(o, h) {
			t.Fatalf("runtime %q left the hash unchanged", other)
		}
	}
	self, _ := os.Executable()
	t.Setenv("MARK1_RM_TEST_STUB", "serve")
	t.Setenv("MARK1_RM_TEST_BUILD", "11193")
	if id, err := RuntimeID(context.Background(), self); err != nil || id != testRuntime {
		t.Fatalf("runtime id %q %v", id, err)
	}
	t.Setenv("MARK1_RM_TEST_STUB", "")
	if _, err := RuntimeID(context.Background(), self); err == nil {
		t.Fatal("a binary that names no build is not a runtime")
	}
}

// A runtime other than the one the catalog's execution_hash names never serves: the slot is refused, the other keeps scoring.
func TestForeignRuntimeIsRefusedNotServed(t *testing.T) {
	bodies := map[string][]byte{"a": []byte("GGUF qwen"), "b": []byte("GGUF granite")}
	b := pinned("b", bodies["b"])
	x, _ := executionHash(bytes.NewReader(bodies["b"]), "llama.cpp b9999")
	b.ExecutionHash = hex.EncodeToString(x)
	h := runPlane(t, "serve", []Manifest{pinned("a", bodies["a"]), b}, bodies, nil)
	s := waitStatus(t, h.dir, "refused", "rm:mark1-rm-a@1 ready", "rm:mark1-rm-b@1 refused")
	if ok, _ := Check(h.dir); ok || s.Healthy() || h.p.slots[1].live.Load() {
		t.Fatalf("status %+v", s)
	}
	h.closeTask([16]byte{4})
	if got := h.scores(t, 1); got["rm:mark1-rm-a@1"] == nil {
		t.Fatalf("%v", got)
	}
}

// The RM reads the task's diff from the HEAD it opened at: a file the agent committed during the task is in the model input (FR-VERIFY-021).
func TestInputIncludesWhatTheAgentCommitted(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("no git on PATH")
	}
	repo, _ := filepath.EvalSymlinks(t.TempDir())
	home := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command(git, args...) //nolint:gosec // G204: test git
		cmd.Dir = repo
		cmd.Env = append(os.Environ(), "HOME="+home, "XDG_CONFIG_HOME="+home, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=",
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(repo, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	run("init", "-q", "-b", "main", ".")
	write("pager.py", "def next_page(self):\n    return 1\n")
	run("add", "pager.py")
	run("commit", "-q", "-m", "init")
	runner := anchors.NewRunner(anchors.NewSandbox(t.TempDir()), nil, nil, false)
	runner.StateDir = t.TempDir()
	session, task := [16]byte{8}, [16]byte{9}
	runner.OpenTask(task, repo)
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if _, err := os.Stat(anchors.TaskBasesPath(runner.StateDir)); err == nil {
			break
		} else if time.Now().After(deadline) {
			t.Fatal("the open-time HEAD was never recorded")
		}
	}
	write("committed_fix.py", "def fixed():\n    return 2\n")
	run("add", "committed_fix.py")
	run("commit", "-q", "-m", "agent's own commit")
	write("pager.py", "def next_page(self):\n    return 2\n")
	p := testPlane(t, Config{Diff: func(ctx context.Context, _, tk [16]byte) []byte { return runner.TaskDiffFor(ctx, tk, repo) }})
	r := p.prompt(context.Background(), closed{session: session, task: task})
	for _, want := range []string{"+++ b/committed_fix.py", "+    return 2", "+++ b/pager.py"} {
		if r.Abstain != "" || !strings.Contains(r.Prefix, want) {
			t.Fatalf("RM input lacks %q (abstain %q):\n%s", want, r.Abstain, r.Prefix)
		}
	}
}

// Tasks close faster than they score: the backlog keeps the newest, drops the oldest as a counted rm_backlog abstain, and each render is its close-time diff.
func TestBacklogDropsOldestCounted(t *testing.T) {
	trace := filepath.Join(t.TempDir(), "trace")
	t.Setenv("MARK1_RM_TEST_TRACE", trace)
	t.Setenv("MARK1_RM_TEST_SLOW", "1")
	body := []byte("GGUF qwen")
	var diffN atomic.Int64
	h := runPlane(t, "serve", []Manifest{pinned("a", body)}, map[string][]byte{"a": body}, func(c *Config) {
		c.Backlog = 2
		c.Diff = func(context.Context, [16]byte, [16]byte) []byte {
			return []byte(strings.Replace(testDiff, "self.size", fmt.Sprintf("self.size%d", diffN.Add(1)), 1))
		}
	})
	waitStatus(t, h.dir, "ready")
	h.closeTask([16]byte{1})
	deadline := time.Now().Add(10 * time.Second)
	for b, _ := os.ReadFile(trace); !strings.Contains(string(b), "begin"); b, _ = os.ReadFile(trace) {
		if time.Now().After(deadline) {
			t.Fatal("the first task never reached the runtime")
		}
		time.Sleep(10 * time.Millisecond)
	}
	for i := byte(2); i <= 6; i++ {
		h.closeTask([16]byte{i})
	}
	for diffN.Load() < 6 {
		time.Sleep(10 * time.Millisecond)
	}
	var got []byte
	for range 3 {
		select {
		case ev := <-h.admitted:
			got = append(got, ev.GetTaskId()[0])
		case <-time.After(15 * time.Second):
			t.Fatalf("scored %v", got)
		}
	}
	if !reflect.DeepEqual(got, []byte{1, 5, 6}) {
		t.Fatalf("scored tasks %v, want the in-flight 1 then the newest 5 and 6", got)
	}
	for s, _ := ReadStatus(h.dir); s.Backlog != 3; s, _ = ReadStatus(h.dir) {
		if time.Now().After(deadline.Add(10 * time.Second)) {
			t.Fatalf("status rm_backlog %d, want 3", s.Backlog)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
