package control

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"

	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/claudecode"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/anchors"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/coverage"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/fabric"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/off"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/tailers"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/verdict"
)

func newServer(t *testing.T) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := Listen(Config{StateDir: dir, SpoolDir: filepath.Join(dir, "spool"), SpoolCap: 1 << 20, Version: "test", Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.Serve() }()
	t.Cleanup(func() { _ = s.Close() })
	return s, dir
}

func call(t *testing.T, s *Server, method, path string, body any, mutate ...func(*http.Request)) (*http.Response, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, "http://"+s.Addr()+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+s.Token())
	for _, m := range mutate {
		m(req)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func want(t *testing.T, resp *http.Response, body []byte, status int, code string) {
	t.Helper()
	if resp.StatusCode != status {
		t.Fatalf("status %d, want %d: %s", resp.StatusCode, status, body)
	}
	if code != "" && !strings.Contains(string(body), `"code":"`+code+`"`) {
		t.Fatalf("body %s lacks code %s", body, code)
	}
}

func decodeTo(t *testing.T, body []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(body, v); err != nil {
		t.Fatalf("not JSON: %v: %s", err, body)
	}
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

func TestControlJSONIsPrivateAndPerBoot(t *testing.T) {
	s, dir := newServer(t)
	fi, err := os.Stat(Path(dir))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("control.json mode %o, want 0600", fi.Mode().Perm())
	}
	var d discovery
	b, _ := os.ReadFile(Path(dir))
	decodeTo(t, b, &d)
	if d.Token != s.Token() || len(d.Token) != 64 || !strings.HasSuffix(s.Addr(), ":"+strconv.Itoa(d.Port)) || !strings.HasPrefix(s.Addr(), "127.0.0.1:") {
		t.Fatalf("discovery %+v vs addr %s token %s", d, s.Addr(), s.Token())
	}
	if _, body := call(t, s, http.MethodGet, "/v1/status", nil); !strings.Contains(string(body), `"running":true`) {
		t.Fatalf("status %s", body)
	}
	s2, err := Listen(Config{StateDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s2.Close() }()
	if s2.Token() == s.Token() {
		t.Fatal("token must rotate per boot")
	}
	b, _ = os.ReadFile(Path(dir))
	decodeTo(t, b, &d)
	if d.Token != s2.Token() {
		t.Fatal("control.json must carry the newest boot's token")
	}
	_ = s2.Close()
	if _, err := os.Stat(Path(dir)); !os.IsNotExist(err) {
		t.Fatal("Close must remove control.json")
	}
}

func TestWallRefusals(t *testing.T) {
	s, _ := newServer(t)
	resp, body := call(t, s, http.MethodGet, "/v1/status", nil, func(r *http.Request) { r.Header.Del("Authorization") })
	want(t, resp, body, http.StatusUnauthorized, "M1E-1002")
	resp, body = call(t, s, http.MethodGet, "/v1/status", nil, func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+strings.Repeat("0", 64)) })
	want(t, resp, body, http.StatusUnauthorized, "M1E-1002")
	resp, body = call(t, s, http.MethodGet, "/v1/status", nil, func(r *http.Request) { r.Host = "localhost" + s.Addr()[len("127.0.0.1"):] })
	want(t, resp, body, http.StatusForbidden, "M1E-4004")
	resp, body = call(t, s, http.MethodGet, "/v1/status", nil, func(r *http.Request) { r.Host = "127.0.0.1.evil.example" + s.Addr()[len("127.0.0.1"):] })
	want(t, resp, body, http.StatusForbidden, "M1E-4004") // literal equality, not a prefix: a rebinding name that starts with the loopback literal is still refused
	resp, body = call(t, s, http.MethodGet, "/v1/status", nil, func(r *http.Request) { r.Header.Set("Origin", "") })
	want(t, resp, body, http.StatusForbidden, "M1E-4005")
	resp, body = call(t, s, http.MethodGet, "/v1/status", nil, func(r *http.Request) { r.Header.Set("Origin", "http://"+s.Addr()) })
	want(t, resp, body, http.StatusForbidden, "M1E-4005")
	resp, body = call(t, s, http.MethodGet, "/v1/nope", nil, func(r *http.Request) { r.Host = "evil.example" })
	want(t, resp, body, http.StatusForbidden, "M1E-4004")
	resp, body = call(t, s, http.MethodGet, "/v1/nope", nil)
	want(t, resp, body, http.StatusNotFound, "M1E-2001")
}

func sessionEvent(sid byte, body any) *m1pv1.Event {
	id := make([]byte, 16)
	id[0] = sid
	ev := &m1pv1.Event{SessionId: id}
	switch b := body.(type) {
	case *m1pv1.SessionStart:
		ev.Body = &m1pv1.Event_SessionStart{SessionStart: b}
	case *m1pv1.SessionEnd:
		ev.Body = &m1pv1.Event_SessionEnd{SessionEnd: b}
	case *m1pv1.Usage:
		ev.Body = &m1pv1.Event_Usage{Usage: b}
	case *m1pv1.VerdictEvent:
		ev.Body = &m1pv1.Event_VerdictEvent{VerdictEvent: b}
	case *m1pv1.AnchorVote:
		ev.Body = &m1pv1.Event_AnchorVote{AnchorVote: b}
	case *m1pv1.EdgeHealth:
		ev.Body = &m1pv1.Event_EdgeHealth{EdgeHealth: b}
	}
	return ev
}

func TestStatusFields(t *testing.T) {
	s, dir := newServer(t)
	if err := os.MkdirAll(filepath.Join(dir, "spool"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "spool", "seg-0000000000000001.m1s"), make([]byte, 64), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "spool", "ledger"), make([]byte, 999), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(filepath.Join(dir, "workspaces.json"), []byte(`{"version":1,"workspaces":[{"path":"/w/a","enabled_at":"2026-09-16T00:00:00Z"},{"path":"/w/b","enabled_at":"2026-09-16T00:00:00Z"}]}`)); err != nil {
		t.Fatal(err)
	}
	s.SetHardStop(true)
	s.Hub().Publish(sessionEvent(1, &m1pv1.SessionStart{Agent: "claudecode"}))
	s.Hub().Publish(sessionEvent(1, &m1pv1.Usage{InputTokens: 10, OutputTokens: 5, CacheCreationInputTokens: 3, CacheReadInputTokens: 2}))
	s.Hub().Publish(sessionEvent(2, &m1pv1.SessionStart{Agent: "codex"}))
	s.Hub().Publish(sessionEvent(2, &m1pv1.SessionEnd{}))
	s.Hub().Publish(sessionEvent(3, &m1pv1.Usage{InputTokens: 99}))

	var st struct {
		Running    bool   `json:"running"`
		Paused     bool   `json:"paused"`
		Version    string `json:"version"`
		Since      string `json:"since"`
		AgentsLive []struct {
			Agent     string `json:"agent"`
			SessionID string `json:"session_id"`
			Tokens    uint64 `json:"tokens"`
		} `json:"agents_live"`
		ProjectsEnabled int `json:"projects_enabled"`
		Spool           struct {
			Bytes    int64 `json:"bytes"`
			Cap      int64 `json:"cap"`
			HardStop bool  `json:"hard_stop"`
		} `json:"spool"`
	}
	_, body := call(t, s, http.MethodGet, "/v1/status", nil)
	decodeTo(t, body, &st)
	if !st.Running || st.Paused || st.Version != "test" || st.ProjectsEnabled != 2 || st.Spool.Bytes != 64 || st.Spool.Cap != 1<<20 || !st.Spool.HardStop {
		t.Fatalf("status %s", body)
	}
	if _, err := time.Parse(time.RFC3339, st.Since); err != nil {
		t.Fatalf("since %q: %v", st.Since, err)
	}
	if len(st.AgentsLive) != 1 || st.AgentsLive[0].Agent != "claudecode" || st.AgentsLive[0].Tokens != 20 || st.AgentsLive[0].SessionID != "01000000000000000000000000000000" {
		t.Fatalf("agents_live %+v", st.AgentsLive)
	}
	if err := os.WriteFile(off.Marker(dir), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, body = call(t, s, http.MethodGet, "/v1/status", nil)
	decodeTo(t, body, &st)
	if !st.Paused || !st.Running {
		t.Fatalf("paused status %s", body)
	}
}

type recorder struct{ events []*m1pv1.Event }

func (r *recorder) admit(_ context.Context, ev *m1pv1.Event) error {
	r.events = append(r.events, ev)
	return nil
}

func TestProjectsLifecycle(t *testing.T) {
	s, dir := newServer(t)
	repo := t.TempDir()
	root, _ := canonical(repo)
	if err := os.MkdirAll(filepath.Join(repo, ".mark1"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".mark1", "anchors.json"), []byte(`{"tests":true}`), 0o600); err != nil {
		t.Fatal(err)
	}

	resp, body := call(t, s, http.MethodPost, "/v1/projects", map[string]string{"path": filepath.Join(repo, "sub", "..")})
	want(t, resp, body, http.StatusOK, "")
	var p struct {
		Path          string `json:"path"`
		EnabledAt     string `json:"enabled_at"`
		TestsEnabled  bool   `json:"tests_enabled"`
		IgnorePresent bool   `json:"ignore_present"`
	}
	decodeTo(t, body, &p)
	if p.Path != root || !p.TestsEnabled || p.IgnorePresent {
		t.Fatalf("project %s", body)
	}
	if _, err := time.Parse(time.RFC3339, p.EnabledAt); err != nil {
		t.Fatal(err)
	}
	if roots, err := tailers.LoadWorkspacesFile(filepath.Join(dir, "workspaces.json")); err != nil || len(roots) != 1 || roots[0] != root {
		t.Fatalf("the daemon's own reader sees %v, %v", roots, err)
	}
	resp, body = call(t, s, http.MethodPost, "/v1/projects", map[string]string{"path": repo})
	want(t, resp, body, http.StatusOK, "")
	_, body = call(t, s, http.MethodGet, "/v1/projects", nil)
	var list []map[string]any
	decodeTo(t, body, &list)
	if len(list) != 1 {
		t.Fatalf("re-enable must be idempotent: %s", body)
	}
	if lines := readLines(t, filepath.Join(dir, "consent.jsonl")); len(lines) != 1 || !strings.Contains(lines[0], `"workspace":"`+root+`"`) {
		t.Fatalf("consent.jsonl %v", lines)
	}

	resp, body = call(t, s, http.MethodPost, "/v1/projects", map[string]string{"path": filepath.Join(repo, "nope")})
	want(t, resp, body, http.StatusBadRequest, "M1E-2001")
	ignored := t.TempDir()
	if err := os.WriteFile(filepath.Join(ignored, ".mark1ignore"), []byte("# all\n*\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	resp, body = call(t, s, http.MethodPost, "/v1/projects", map[string]string{"path": ignored})
	want(t, resp, body, http.StatusConflict, "M1E-2001")
	resp, body = call(t, s, http.MethodPost, "/v1/projects", map[string]string{"path": repo, "extra": "x"})
	want(t, resp, body, http.StatusBadRequest, "M1E-2001")

	resp, body = call(t, s, http.MethodDelete, "/v1/projects", map[string]string{"path": repo})
	want(t, resp, body, http.StatusNoContent, "")
	resp, body = call(t, s, http.MethodDelete, "/v1/projects", map[string]string{"path": repo})
	want(t, resp, body, http.StatusNotFound, "M1E-2001")
	if roots, _ := tailers.LoadWorkspacesFile(filepath.Join(dir, "workspaces.json")); len(roots) != 0 {
		t.Fatalf("still enabled: %v", roots)
	}

	rec := &recorder{}
	cov := coverage.New(rec.admit, []byte("k"))
	if n, err := cov.DrainJournal(context.Background(), dir); err != nil || n != 2 {
		t.Fatalf("drain %d %v", n, err)
	}
	ct := []*m1pv1.CoverageTransition{rec.events[0].GetCoverageTransition(), rec.events[1].GetCoverageTransition()}
	if ct[0].GetKind() != m1pv1.CoverageKind_COVERAGE_KIND_ENABLE || ct[0].GetReasonCode() != coverage.ReasonUserEnable ||
		ct[1].GetKind() != m1pv1.CoverageKind_COVERAGE_KIND_DISABLE || ct[1].GetReasonCode() != coverage.ReasonMark1Off ||
		!bytes.Equal(ct[0].GetWorkspaceId(), cov.WorkspaceID(root)) || !bytes.Equal(ct[1].GetWorkspaceId(), cov.WorkspaceID(root)) {
		t.Fatalf("receipted transitions %v", ct)
	}
}

func catalogEntry() anchors.CatalogEntry {
	return anchors.CatalogEntry{ID: "ruff@cat-1", Tool: "ruff", Argv: []string{"ruff", "check"}, Class: anchors.ClassSlow, SideEffect: anchors.SideEffectStatic,
		BinaryPath: "/usr/bin/ruff", BinaryHash: bytes.Repeat([]byte{7}, 32), ToolVersion: "0.9.1"}
}

func TestAnchorsConsentGoesThroughTheDaemonsReconcile(t *testing.T) {
	s, dir := newServer(t)
	repo, _ := canonical(t.TempDir())
	e := catalogEntry()
	derived := map[string][]anchors.CatalogEntry{repo: {e}}
	publish := func() {
		consented, err := anchors.LoadConsent(anchors.ConsentPath(dir))
		if err != nil {
			t.Fatal(err)
		}
		if err := anchors.PublishCandidates(anchors.CandidatesPath(dir), consented, derived); err != nil {
			t.Fatal(err)
		}
	}
	resp, body := call(t, s, http.MethodGet, "/v1/anchors?project="+repo, nil)
	want(t, resp, body, http.StatusOK, "")
	if strings.TrimSpace(string(body)) != "[]" {
		t.Fatalf("no candidates yet must be an empty list: %s", body)
	}
	publish()
	var rows []map[string]any
	_, body = call(t, s, http.MethodGet, "/v1/anchors?project="+repo, nil)
	decodeTo(t, body, &rows)
	if len(rows) != 1 {
		t.Fatalf("rows %s", body)
	}
	row := rows[0]
	execHash := row["exec_hash"].(string)
	if row["id"] != "ruff@cat-1" || row["tool"] != "ruff" || row["version"] != "0.9.1" || row["latency_class"] != "slow" || row["side_effect"] != "static" || row["consented"] != false || len(execHash) != 64 {
		t.Fatalf("row %s", body)
	}
	for _, k := range []string{"tier", "last_run", "consented_at", "argv"} {
		if _, ok := row[k]; ok {
			t.Fatalf("%s has no source in the daemon and must be absent, not invented: %s", k, body)
		}
	}
	_, body = call(t, s, http.MethodGet, "/v1/anchors?project="+t.TempDir(), nil)
	if strings.TrimSpace(string(body)) != "[]" {
		t.Fatalf("other project must filter to empty: %s", body)
	}

	resp, body = call(t, s, http.MethodPost, "/v1/anchors/consent", map[string]string{"project": repo, "id": "ruff@cat-1", "exec_hash": strings.Repeat("0", 64)})
	want(t, resp, body, http.StatusConflict, "M1E-2001")
	if _, err := os.Stat(anchors.ApprovalsPath(dir)); !os.IsNotExist(err) {
		t.Fatal("a refused consent must write no approval line")
	}

	var offset int64
	steps := 0
	s.SetReconcile(func() {
		steps++
		off, _, err := anchors.ApplyApprovals(anchors.ConsentPath(dir), anchors.ApprovalsPath(dir), offset, derived, time.Now(), slog.Default())
		if err != nil {
			t.Error(err)
		}
		offset = off
		publish()
	})
	resp, body = call(t, s, http.MethodPost, "/v1/anchors/consent", map[string]string{"project": repo, "id": "ruff@cat-1", "exec_hash": execHash})
	want(t, resp, body, http.StatusOK, "")
	decodeTo(t, body, &row)
	if row["consented"] != true || row["exec_hash"] != execHash || steps != 1 {
		t.Fatalf("consented row %s steps %d", body, steps)
	}
	lines := readLines(t, anchors.ApprovalsPath(dir))
	var a anchors.Approval
	if len(lines) != 1 || json.Unmarshal([]byte(lines[0]), &a) != nil || a.ID != "ruff@cat-1" || a.ExecHash != execHash || a.Workspace != repo || a.TS == "" {
		t.Fatalf("approvals.jsonl %v", lines)
	}
	if !anchors.Reconcile(derived[repo], mustConsent(t, dir)).Enabled[0].ConsentedAt.After(time.Time{}) {
		t.Fatal("the store must hold the consent the daemon's Reconcile arms")
	}
}

func mustConsent(t *testing.T, dir string) []anchors.ConsentRecord {
	t.Helper()
	recs, err := anchors.LoadConsent(anchors.ConsentPath(dir))
	if err != nil || len(recs) != 1 {
		t.Fatalf("consent store %v %v", recs, err)
	}
	return recs
}

func TestOptInsDriveTheGateReaders(t *testing.T) {
	s, dir := newServer(t)
	repo, _ := canonical(t.TempDir())
	if err := writeAtomic(filepath.Join(dir, "workspaces.json"), []byte(`{"version":1,"workspaces":[{"path":"`+repo+`","enabled_at":"2026-09-16T00:00:00Z"}]}`)); err != nil {
		t.Fatal(err)
	}
	var o struct {
		StopGate       bool            `json:"stop_gate"`
		Exploration    bool            `json:"exploration"`
		TestsByProject map[string]bool `json:"tests_by_project"`
		Consents       *map[string]any `json:"consents"`
	}
	_, body := call(t, s, http.MethodGet, "/v1/optins", nil)
	decodeTo(t, body, &o)
	if o.StopGate || o.Exploration || o.TestsByProject[repo] || o.Consents != nil {
		t.Fatalf("defaults %s", body)
	}
	tr := true
	resp, body := call(t, s, http.MethodPut, "/v1/optins", map[string]*bool{"stop_gate": &tr})
	want(t, resp, body, http.StatusOK, "")
	decodeTo(t, body, &o)
	if !o.StopGate || o.Exploration {
		t.Fatalf("after put %s", body)
	}
	if fabric.ExplorationEpsilon(dir, 0.5) != 0 {
		t.Fatal("exploration must stay off")
	}
	var onDisk struct {
		StopGate    bool   `json:"stop_gate"`
		Exploration bool   `json:"exploration"`
		TS          string `json:"ts"`
	}
	b, _ := os.ReadFile(fabric.OptInPath(dir))
	decodeTo(t, b, &onDisk)
	if !onDisk.StopGate || onDisk.Exploration || onDisk.TS == "" {
		t.Fatalf("opt-in.json %s", b)
	}
	_, body = call(t, s, http.MethodPut, "/v1/optins", map[string]*bool{"exploration": &tr})
	decodeTo(t, body, &o)
	if !o.StopGate || !o.Exploration || fabric.ExplorationEpsilon(dir, 0.5) != 0.5 {
		t.Fatalf("exploration put %s", body)
	}
	if lines := readLines(t, filepath.Join(dir, "consent.jsonl")); len(lines) != 2 || !strings.Contains(lines[1], `"exploration":true`) {
		t.Fatalf("consent.jsonl %v", lines)
	}
	f := false
	_, body = call(t, s, http.MethodPut, "/v1/optins", map[string]*bool{"stop_gate": &f, "exploration": &f})
	decodeTo(t, body, &o)
	if o.StopGate || o.Exploration {
		t.Fatalf("clear %s", body)
	}
	if _, err := os.Stat(fabric.OptInPath(dir)); !os.IsNotExist(err) {
		t.Fatal("both false must remove the artifact, as cli.UpdateOptIn does")
	}
	if lines := readLines(t, filepath.Join(dir, "consent.jsonl")); len(lines) != 2 {
		t.Fatalf("opting out records no consent: %v", lines)
	}
}

type stubReader map[verdict.TaskID]verdict.Cached

func (r stubReader) Get(t verdict.TaskID) (verdict.Cached, bool) { e, ok := r[t]; return e, ok }

func blockableGate(dir string) *fabric.Gate {
	entry := verdict.Cached{
		Verdict:    &m1pv1.VerdictEvent{Stage: m1pv1.VerdictStage_VERDICT_STAGE_PROVISIONAL, Verdict: m1pv1.Verdict_VERDICT_VIOLATED, Posterior: []float64{0.02, 0.90, 0.05, 0.03}},
		Knee:       verdict.KneeState{N: 2, PLCB: 0.4, VTask: 10, CostN: 1, CostBasis: "usd", Evaluable: true},
		ComputedAt: time.Now(),
	}
	g := fabric.NewGate(stubReader{{1}: entry}, verdict.NewBlocks(), dir)
	g.TaskFor = func(_, want [16]byte) ([16]byte, bool) { return want, want != [16]byte{} }
	return g
}

func TestPauseIsTheOffSwitchEveryGateChecksFirst(t *testing.T) {
	s, dir := newServer(t)
	if err := writeAtomic(fabric.OptInPath(dir), []byte(`{"stop_gate":true,"ts":"2026-09-16T00:00:00Z","user":"test"}`)); err != nil {
		t.Fatal(err)
	}
	g := blockableGate(dir)
	task := make([]byte, 16)
	task[0] = 1
	q := &m1pv1.GateQuery{TaskId: task, Gate: m1pv1.GateKind_GATE_KIND_STOP, DeadlineMs: 5000}
	session := [16]byte{0xAA}
	if v := g.Answer(q, session); v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_BLOCK {
		t.Fatalf("precondition: gate must BLOCK before pause, got %v %q", v.GetDecision(), v.GetReason())
	}

	resp, body := call(t, s, http.MethodPost, "/v1/pause", nil)
	want(t, resp, body, http.StatusOK, "")
	if strings.TrimSpace(string(body)) != `{"paused":true}` {
		t.Fatalf("pause %s", body)
	}
	if !off.Off(dir) {
		t.Fatal("pause must be the OFF marker off.Off reads")
	}
	if v := g.Answer(q, session); v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_ALLOW || v.GetReason() != "mark1_off" {
		t.Fatalf("paused gate answered %v %q, want allow mark1_off", v.GetDecision(), v.GetReason())
	}
	var marker struct {
		Scope     string `json:"scope"`
		WrittenAt string `json:"written_at"`
	}
	b, _ := os.ReadFile(off.Marker(dir))
	decodeTo(t, b, &marker)
	if marker.Scope != "all" || marker.WrittenAt == "" {
		t.Fatalf("marker %s must carry the CLI's shape", b)
	}
	if _, body := call(t, s, http.MethodPost, "/v1/pause", nil); strings.TrimSpace(string(body)) != `{"paused":true}` {
		t.Fatalf("pause twice %s", body)
	}

	resp, body = call(t, s, http.MethodPost, "/v1/resume", nil)
	want(t, resp, body, http.StatusOK, "")
	if strings.TrimSpace(string(body)) != `{"paused":false}` || off.Off(dir) {
		t.Fatalf("resume %s off=%v", body, off.Off(dir))
	}
	if v := g.Answer(q, session); v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_BLOCK {
		t.Fatalf("resumed gate must gate again, got %v %q", v.GetDecision(), v.GetReason())
	}
	if _, body := call(t, s, http.MethodPost, "/v1/resume", nil); strings.TrimSpace(string(body)) != `{"paused":false}` {
		t.Fatalf("resume twice %s", body)
	}

	rec := &recorder{}
	cov := coverage.New(rec.admit, []byte("k"))
	if n, err := cov.DrainJournal(context.Background(), dir); err != nil || n != 3 {
		t.Fatalf("drain %d %v (pause, pause, resume)", n, err)
	}
	kinds := []m1pv1.CoverageKind{}
	for _, ev := range rec.events {
		ct := ev.GetCoverageTransition()
		if !bytes.Equal(ct.GetWorkspaceId(), coverage.DeviceWide()) {
			t.Fatalf("pause is device-wide: %v", ct)
		}
		kinds = append(kinds, ct.GetKind())
	}
	if kinds[0] != m1pv1.CoverageKind_COVERAGE_KIND_DISABLE || kinds[1] != m1pv1.CoverageKind_COVERAGE_KIND_DISABLE || kinds[2] != m1pv1.CoverageKind_COVERAGE_KIND_ENABLE {
		t.Fatalf("kinds %v", kinds)
	}
}

func TestEventsStreamWithin100ms(t *testing.T) {
	s, _ := newServer(t)
	req, _ := http.NewRequest(http.MethodGet, "http://"+s.Addr()+"/v1/events", nil)
	req.Header.Set("Authorization", "Bearer "+s.Token())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("stream %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	rd := bufio.NewReader(resp.Body)
	frames := make(chan string, 8)
	go func() {
		for {
			var sb strings.Builder
			for {
				line, err := rd.ReadString('\n')
				if err != nil {
					return
				}
				if line == "\n" {
					break
				}
				sb.WriteString(line)
			}
			frames <- sb.String()
		}
	}()
	next := func() string {
		select {
		case f := <-frames:
			return f
		case <-time.After(100 * time.Millisecond):
			t.Fatal("no frame within 100 ms")
			return ""
		}
	}
	time.Sleep(20 * time.Millisecond)
	s.Hub().Publish(sessionEvent(1, &m1pv1.EdgeHealth{}))
	s.Hub().Publish(sessionEvent(1, &m1pv1.AnchorVote{AnchorId: "ruff@cat-1", Integrity: &m1pv1.AnchorIntegrity{Tamper: true}}))
	s.Hub().Publish(sessionEvent(1, &m1pv1.SessionStart{Agent: "claudecode", AgentVersion: "2.1.0"}))
	f := next()
	if !strings.HasPrefix(f, "event: session_start\ndata: ") {
		t.Fatalf("frame %q", f)
	}
	var data struct {
		SessionID    string `json:"session_id"`
		SessionStart struct {
			Agent        string `json:"agent"`
			AgentVersion string `json:"agent_version"`
		} `json:"session_start"`
	}
	decodeTo(t, []byte(strings.TrimPrefix(f, "event: session_start\ndata: ")), &data)
	if data.SessionID != "AQAAAAAAAAAAAAAAAAAAAA==" || data.SessionStart.Agent != "claudecode" || data.SessionStart.AgentVersion != "2.1.0" {
		t.Fatalf("frame %q", f)
	}
	s.Hub().Publish(sessionEvent(1, &m1pv1.VerdictEvent{Verdict: m1pv1.Verdict_VERDICT_VIOLATED}))
	if f := next(); !strings.HasPrefix(f, "event: verdict\n") {
		t.Fatalf("frame %q", f)
	}
	ev := &m1pv1.Event{SessionId: make([]byte, 16), Body: &m1pv1.Event_GuardDecision{GuardDecision: &m1pv1.GuardDecision{ReasonCode: "x"}}}
	ev.SessionId[0] = 1
	s.Hub().Publish(ev)
	if f := next(); !strings.HasPrefix(f, "event: arrest\n") {
		t.Fatalf("frame %q", f)
	}
	select {
	case f := <-frames:
		t.Fatalf("unlisted family leaked: %q", f)
	case <-time.After(30 * time.Millisecond):
	}

	var rows []map[string]json.RawMessage
	_, body := call(t, s, http.MethodGet, "/v1/verify/events?project=/w", nil)
	decodeTo(t, body, &rows)
	if len(rows) != 3 {
		t.Fatalf("verify/events must hold tamper + verdict + arrest: %s", body)
	}
	if _, ok := rows[0]["anchor_vote"]; !ok {
		t.Fatalf("tamper vote missing: %s", body)
	}
	if _, ok := rows[1]["verdict_event"]; !ok {
		t.Fatalf("verdict missing: %s", body)
	}
	if _, ok := rows[2]["guard_decision"]; !ok {
		t.Fatalf("arrest missing: %s", body)
	}
}

func TestAgentsAndDoctorReadTheAdapterEngine(t *testing.T) {
	bin := t.TempDir()
	t.Setenv("PATH", bin)
	t.Setenv("HOME", t.TempDir())
	s, dir := newServer(t)
	var agents []map[string]any
	_, body := call(t, s, http.MethodGet, "/v1/agents", nil)
	decodeTo(t, body, &agents)
	if len(agents) != 7 || agents[0]["name"] != "claudecode" || agents[6]["name"] != "crush" {
		t.Fatalf("agents %s", body)
	}
	for _, a := range agents {
		if _, ok := a["provisioned"]; ok {
			t.Fatalf("nothing is provisioned yet: %s", body)
		}
	}
	if r := agents[0]["regime"]; r != "subscription" && r != "apikey" {
		t.Fatalf("regime %v", r)
	}
	if _, ok := agents[6]["regime"]; ok {
		t.Fatalf("unimplemented slot must carry no sniff: %s", body)
	}

	settings := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(settings, []byte(`{"model": "opus"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := claudecode.ApplyFragment(settings, dir, ""); err != nil {
		t.Fatal(err)
	}
	_, body = call(t, s, http.MethodGet, "/v1/agents", nil)
	decodeTo(t, body, &agents)
	prov, ok := agents[0]["provisioned"].(map[string]any)
	if !ok {
		t.Fatalf("claudecode must show as provisioned: %s", body)
	}
	files := prov["files"].([]any)
	if prov["mechanism"] != "B" || len(files) != 1 || files[0].(map[string]any)["path"] != settings || files[0].(map[string]any)["lines_added"].(float64) < 1 {
		t.Fatalf("provisioned %v", prov)
	}
	if _, ok := prov["notes"]; ok {
		t.Fatalf("an OK fragment has no notes: %v", prov)
	}
	if _, ok := files[0].(map[string]any)["byte_equal_revert"]; ok {
		t.Fatal("byte_equal_revert has no source and must be absent")
	}

	var doc struct {
		OK        bool             `json:"ok"`
		Agents    []map[string]any `json:"agents"`
		Fragments []fragment       `json:"fragments"`
		Anchors   []map[string]any `json:"anchors"`
		Health    []check          `json:"health"`
	}
	_, body = call(t, s, http.MethodGet, "/v1/doctor", nil)
	decodeTo(t, body, &doc)
	if doc.OK || len(doc.Fragments) != 1 || doc.Fragments[0].State != "OK" || doc.Fragments[0].Target != settings || len(doc.Agents) != 7 {
		t.Fatalf("doctor %s", body)
	}
	byName := map[string]check{}
	for _, c := range doc.Health {
		byName[c.Name] = c
	}
	if byName["anchor_candidates"].OK || !byName["off"].OK || !byName["disk_hard_stop"].OK {
		t.Fatalf("health %+v", doc.Health)
	}

	if err := writeAtomic(anchors.CandidatesPath(dir), []byte(`{"version":1,"workspaces":[]}`)); err != nil {
		t.Fatal(err)
	}
	_, body = call(t, s, http.MethodGet, "/v1/doctor", nil)
	decodeTo(t, body, &doc)
	if !doc.OK {
		t.Fatalf("doctor %s", body)
	}
	b, _ := os.ReadFile(settings)
	if err := os.WriteFile(settings, bytes.Replace(b, []byte(claudecode.DefaultShimPath), []byte("/evil"), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	_, body = call(t, s, http.MethodGet, "/v1/doctor", nil)
	decodeTo(t, body, &doc)
	if doc.OK || doc.Fragments[0].State != "FRAGMENT-DAMAGED" {
		t.Fatalf("damaged doctor %s", body)
	}
	_, body = call(t, s, http.MethodGet, "/v1/agents", nil)
	decodeTo(t, body, &agents)
	notes := agents[0]["provisioned"].(map[string]any)["notes"].([]any)
	if len(notes) == 0 || !strings.Contains(notes[0].(string), "FRAGMENT-DAMAGED") {
		t.Fatalf("notes %v", notes)
	}
	s.SetHardStop(true)
	if err := os.WriteFile(off.Marker(dir), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, body = call(t, s, http.MethodGet, "/v1/doctor", nil)
	decodeTo(t, body, &doc)
	byName = map[string]check{}
	for _, c := range doc.Health {
		byName[c.Name] = c
	}
	if byName["disk_hard_stop"].OK || !byName["off"].OK || !strings.HasPrefix(byName["off"].Detail, "ACTIVE") {
		t.Fatalf("hard stop reds, pause is a user choice that only changes the detail: %+v", doc.Health)
	}
}

func TestReceiptsAndVerifier(t *testing.T) {
	s, dir := newServer(t)
	_, body := call(t, s, http.MethodGet, "/v1/receipts", nil)
	if strings.TrimSpace(string(body)) != "{}" {
		t.Fatalf("no local head: %s", body)
	}
	if err := writeAtomic(filepath.Join(dir, "receipt", "last-head"), []byte(`{"seq":92,"hash":"ab","checkpoint_seq":4}`)); err != nil {
		t.Fatal(err)
	}
	var head struct {
		Seq           int64  `json:"seq"`
		Hash          string `json:"hash"`
		CheckpointSeq int64  `json:"checkpoint_seq"`
	}
	_, body = call(t, s, http.MethodGet, "/v1/receipts", nil)
	decodeTo(t, body, &head)
	if head.Seq != 92 || head.Hash != "ab" || head.CheckpointSeq != 4 {
		t.Fatalf("head %s", body)
	}

	resp, body := call(t, s, http.MethodPost, "/v1/receipts/verify", map[string]string{"chain": "/c"})
	want(t, resp, body, http.StatusBadRequest, "M1E-2001")
	t.Setenv("MARK1_VERIFIER", filepath.Join(t.TempDir(), "absent"))
	resp, body = call(t, s, http.MethodPost, "/v1/receipts/verify", map[string]string{"chain": "/c", "keys": "/k"})
	want(t, resp, body, http.StatusInternalServerError, "M1E-9500")
	if runtime.GOOS == "windows" {
		t.Skip("shell stub verifier")
	}
	stub := filepath.Join(t.TempDir(), "mark1-verifier")
	script := "#!/bin/sh\necho \"$@\" >&2\ncase \"$*\" in *--witness*) echo '{\"ok\":false,\"defects\":[\"gap\"]}'; exit 5;; *bad*) echo input >&2; exit 1;; esac\necho '{\"ok\":true}'\n"
	if err := os.WriteFile(stub, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MARK1_VERIFIER", stub)
	resp, body = call(t, s, http.MethodPost, "/v1/receipts/verify", map[string]string{"chain": "/c", "keys": "/k"})
	want(t, resp, body, http.StatusOK, "")
	if strings.TrimSpace(string(body)) != `{"ok":true}` {
		t.Fatalf("verifier stdout must be the result verbatim: %s", body)
	}
	resp, body = call(t, s, http.MethodPost, "/v1/receipts/verify", map[string]string{"chain": "/c", "keys": "/k", "witness": "/w"})
	want(t, resp, body, http.StatusOK, "")
	if !strings.Contains(string(body), `"defects":["gap"]`) {
		t.Fatalf("exit 5 is a verdict, not an error: %s", body)
	}
	resp, body = call(t, s, http.MethodPost, "/v1/receipts/verify", map[string]string{"chain": "/bad", "keys": "/k"})
	want(t, resp, body, http.StatusBadRequest, "M1E-2001")
}
