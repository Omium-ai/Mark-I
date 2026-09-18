package control

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/claudecode"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/codex"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/provision"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/anchors"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/consents"
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
	if _, err := Listen(Config{StateDir: dir}); !errors.Is(err, ErrAlreadyServing) {
		t.Fatalf("a second boot beside a live daemon must refuse, got %v", err)
	}
	b, _ = os.ReadFile(Path(dir))
	decodeTo(t, b, &d)
	if d.Token != s.Token() {
		t.Fatal("the refused boot must leave the live daemon's control.json untouched")
	}
	_ = s.Close()
	if _, err := os.Stat(Path(dir)); !os.IsNotExist(err) {
		t.Fatal("Close must remove control.json")
	}
	if err := os.WriteFile(Path(dir), b, 0o600); err != nil { // the dead daemon's file, as after a crash
		t.Fatal(err)
	}
	s2, err := Listen(Config{StateDir: dir})
	if err != nil {
		t.Fatalf("a stale control.json must be taken over, got %v", err)
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
	stale := Server{cfg: Config{StateDir: dir}, token: s.Token(), http: &http.Server{}, l: s.l}
	_ = stale.Close()
	if _, err := os.Stat(Path(dir)); err != nil {
		t.Fatal("an older boot's Close must not remove a newer boot's control.json")
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

func TestShutdownRouteRunsTheStopHook(t *testing.T) {
	s, _ := newServer(t)
	resp, body := call(t, s, http.MethodPost, "/v1/shutdown", nil)
	want(t, resp, body, http.StatusServiceUnavailable, "M1E-9500")
	stopped := make(chan struct{})
	s.SetShutdown(func() { close(stopped) })
	resp, body = call(t, s, http.MethodPost, "/v1/shutdown", nil, func(r *http.Request) { r.Header.Del("Authorization") })
	want(t, resp, body, http.StatusUnauthorized, "M1E-1002")
	select {
	case <-stopped:
		t.Fatal("an unauthenticated POST stopped the daemon")
	default:
	}
	resp, body = call(t, s, http.MethodPost, "/v1/shutdown", nil)
	want(t, resp, body, http.StatusOK, "")
	var got struct {
		OK bool `json:"ok"`
	}
	decodeTo(t, body, &got)
	if !got.OK {
		t.Fatalf("body %s", body)
	}
	select {
	case <-stopped:
	default:
		t.Fatal("stop hook did not run")
	}
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
			Project   string `json:"project"`
			SessionID string `json:"session_id"`
			Tokens    uint64 `json:"tokens"`
		} `json:"agents_live"`
		ProjectsEnabled []string `json:"projects_enabled"`
		Spool           struct {
			Bytes    int64 `json:"bytes"`
			Cap      int64 `json:"cap"`
			HardStop bool  `json:"hard_stop"`
		} `json:"spool"`
	}
	_, body := call(t, s, http.MethodGet, "/v1/status", nil)
	decodeTo(t, body, &st)
	if !st.Running || st.Paused || st.Version != "test" || !slices.Equal(st.ProjectsEnabled, []string{"/w/a", "/w/b"}) || st.Spool.Bytes != 64 || st.Spool.Cap != 1<<20 || !st.Spool.HardStop {
		t.Fatalf("status %s", body)
	}
	if _, err := time.Parse(time.RFC3339, st.Since); err != nil {
		t.Fatalf("since %q: %v", st.Since, err)
	}
	if len(st.AgentsLive) != 1 || st.AgentsLive[0].Agent != "claudecode" || st.AgentsLive[0].Tokens != 20 || st.AgentsLive[0].SessionID != "01000000-0000-0000-0000-000000000000" || st.AgentsLive[0].Project != "" {
		t.Fatalf("agents_live %+v (no transcript names this session, so project is unattributed, not guessed)", st.AgentsLive)
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

// fakeHome makes every provisioning route hermetic: a scratch HOME, an empty PATH and no vendor overrides, so a test can never edit the developer's own agent config.
func fakeHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("PATH", t.TempDir())
	for _, v := range []string{"CODEX_HOME", "GEMINI_CLI_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "COPILOT_HOME", "ANTHROPIC_API_KEY"} {
		t.Setenv(v, "")
	}
	return home
}

func TestProjectsLifecycle(t *testing.T) {
	fakeHome(t)
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
		Path              string              `json:"path"`
		EnabledAt         string              `json:"enabled_at"`
		AgentsSeen        []string            `json:"agents_seen"`
		TestsEnabled      bool                `json:"tests_enabled"`
		IgnorePresent     bool                `json:"ignore_present"`
		AgentsProvisioned []string            `json:"agents_provisioned"`
		AgentsRefused     []provision.Refusal `json:"agents_refused"`
	}
	decodeTo(t, body, &p)
	if p.Path != root || !p.TestsEnabled || p.IgnorePresent || p.AgentsSeen == nil || len(p.AgentsSeen) != 0 {
		t.Fatalf("project %s", body)
	}
	if len(p.AgentsProvisioned) != 0 || len(p.AgentsRefused) != 1 || p.AgentsRefused[0].Agent != "claudecode" || p.AgentsRefused[0].Code != claudecode.CodeNoTarget {
		t.Fatalf("with no ~/.claude/settings.json the enable is an M1E-7101 refusal row, never an invented file: %s", body)
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
	if lines := readLines(t, filepath.Join(dir, "consent.jsonl")); len(lines) != 1 || !strings.Contains(lines[0], `"workspace":`+jsonString(root)) || !strings.Contains(lines[0], `"agents_provisioned":[]`) {
		t.Fatalf("consent.jsonl %v", lines)
	}
	resp, body = call(t, s, http.MethodPost, "/v1/projects", map[string]any{"path": repo, "agents": []string{"crush"}})
	want(t, resp, body, http.StatusBadRequest, "M1E-2001")

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
	want(t, resp, body, http.StatusOK, "")
	if strings.TrimSpace(string(body)) != `{"byte_equality":true,"not_reverted":[],"path":`+jsonString(root)+`,"receipted_transition_id":null,"removed":true,"reverted":[]}` {
		t.Fatalf("remove %s (the receipt is minted by the coverage drain later, so the id is null, never invented)", body)
	}
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
	for _, k := range []string{"tier", "consented_at", "argv"} {
		if _, ok := row[k]; ok {
			t.Fatalf("%s has no source in the daemon and must be absent, not invented: %s", k, body)
		}
	}
	if lr, ok := row["last_run"]; !ok || lr != nil {
		t.Fatalf("last_run is null until this boot sees a vote, never invented: %s", body)
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

	vote := sessionEvent(1, &m1pv1.AnchorVote{AnchorId: "ruff@cat-1", Vote: m1pv1.Verdict_VERDICT_SATISFIED})
	vote.OccurredAt = timestamppb.New(time.Date(2026, 9, 16, 14, 12, 0, 0, time.UTC))
	s.Hub().Publish(vote)
	resp, body = call(t, s, http.MethodPost, "/v1/anchors/consent", map[string]any{"id": "ruff@cat-1", "consented": false})
	want(t, resp, body, http.StatusOK, "")
	decodeTo(t, body, &row)
	if row["consented"] != false || row["last_run"] != "2026-09-16T14:12:00Z" || steps != 2 {
		t.Fatalf("revoked row %s steps %d", body, steps)
	}
	if recs, err := anchors.LoadConsent(anchors.ConsentPath(dir)); err != nil || len(recs) != 0 {
		t.Fatalf("revoke must empty the store the runner's stillConsented reads: %v %v", recs, err)
	}
	if len(readLines(t, anchors.ApprovalsPath(dir))) != 1 {
		t.Fatal("a revoke writes no approval line")
	}
	resp, body = call(t, s, http.MethodPost, "/v1/anchors/consent", map[string]any{"id": "ruff@cat-1", "consented": true})
	want(t, resp, body, http.StatusOK, "")
	decodeTo(t, body, &row)
	if row["consented"] != true || row["exec_hash"] != execHash {
		t.Fatalf("re-consent without exec_hash must bind to the catalog's current hash: %s", body)
	}
	resp, body = call(t, s, http.MethodPost, "/v1/anchors/consent", map[string]any{"id": "nope@cat-1", "consented": true})
	want(t, resp, body, http.StatusConflict, "M1E-2001")
	resp, body = call(t, s, http.MethodPost, "/v1/anchors/consent", map[string]any{"id": "ruff@cat-1", "project": t.TempDir(), "consented": true})
	want(t, resp, body, http.StatusConflict, "M1E-2001")
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
	if err := writeAtomic(filepath.Join(dir, "workspaces.json"), []byte(`{"version":1,"workspaces":[{"path":`+jsonString(repo)+`,"enabled_at":"2026-09-16T00:00:00Z"}]}`)); err != nil {
		t.Fatal(err)
	}
	var o struct {
		StopGate       bool              `json:"stop_gate"`
		Exploration    bool              `json:"exploration"`
		TestsByProject map[string]bool   `json:"tests_by_project"`
		Consents       consents.Consents `json:"consents"`
	}
	_, body := call(t, s, http.MethodGet, "/v1/optins", nil)
	decodeTo(t, body, &o)
	if o.StopGate || o.Exploration || o.TestsByProject[repo] || o.Consents != (consents.Consents{}) || !strings.Contains(string(body), `"consents":{"e1":false,"cloud_judge":false,"training":false}`) {
		t.Fatalf("defaults are false until the user consents: %s", body)
	}
	resp, body := call(t, s, http.MethodPut, "/v1/optins", map[string]any{"consents": map[string]bool{"training": true}})
	want(t, resp, body, http.StatusOK, "")
	decodeTo(t, body, &o)
	if o.Consents != (consents.Consents{Training: true}) || consents.Read(dir) != (consents.Consents{Training: true}) {
		t.Fatalf("partial consents update %s", body)
	}
	_, body = call(t, s, http.MethodPut, "/v1/optins", map[string]any{"consents": map[string]bool{"e1": true, "cloud_judge": true}})
	decodeTo(t, body, &o)
	if o.Consents != (consents.Consents{E1: true, CloudJudge: true, Training: true}) {
		t.Fatalf("merge keeps the untouched field %s", body)
	}
	_, body = call(t, s, http.MethodPut, "/v1/optins", map[string]any{"consents": map[string]bool{"training": false}})
	decodeTo(t, body, &o)
	if o.Consents.Training || !o.Consents.E1 {
		t.Fatalf("withdraw %s", body)
	}
	if lines := readLines(t, filepath.Join(dir, "consent.jsonl")); len(lines) != 3 || !strings.Contains(lines[2], `"consents":{"e1":true,"cloud_judge":true,"training":false}`) {
		t.Fatalf("every consent change is journalled: %v", lines)
	}
	resp, body = call(t, s, http.MethodPut, "/v1/optins", map[string]any{"consents": map[string]bool{"nope": true}})
	want(t, resp, body, http.StatusBadRequest, "M1E-2001")
	tr := true
	resp, body = call(t, s, http.MethodPut, "/v1/optins", map[string]*bool{"stop_gate": &tr})
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
	if lines := readLines(t, filepath.Join(dir, "consent.jsonl")); len(lines) != 5 || !strings.Contains(lines[4], `"exploration":true`) {
		t.Fatalf("consent.jsonl %v", lines)
	}
	resp, body = call(t, s, http.MethodPut, "/v1/optins", map[string]any{"tests_by_project": map[string]bool{repo: true}})
	want(t, resp, body, http.StatusOK, "")
	decodeTo(t, body, &o)
	if !o.TestsByProject[repo] || !anchors.TestsOptedIn(repo) {
		t.Fatalf("tests opt-in must land where anchors.TestsOptedIn reads: %s", body)
	}
	if err := os.WriteFile(anchors.RepoOptInPath(repo), []byte(`{"tests":true,"keep":1}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, body = call(t, s, http.MethodPut, "/v1/optins", map[string]any{"tests_by_project": map[string]bool{repo: false}})
	decodeTo(t, body, &o)
	if o.TestsByProject[repo] || anchors.TestsOptedIn(repo) {
		t.Fatalf("tests opt-out %s", body)
	}
	if b, _ := os.ReadFile(anchors.RepoOptInPath(repo)); !strings.Contains(string(b), `"keep": 1`) {
		t.Fatalf("read-modify-write must keep the repo's other keys: %s", b)
	}
	resp, body = call(t, s, http.MethodPut, "/v1/optins", map[string]any{"tests_by_project": map[string]bool{t.TempDir(): true}})
	want(t, resp, body, http.StatusBadRequest, "M1E-2001")
	f := false
	_, body = call(t, s, http.MethodPut, "/v1/optins", map[string]*bool{"stop_gate": &f, "exploration": &f})
	decodeTo(t, body, &o)
	if o.StopGate || o.Exploration {
		t.Fatalf("clear %s", body)
	}
	if _, err := os.Stat(fabric.OptInPath(dir)); !os.IsNotExist(err) {
		t.Fatal("both false must remove the artifact, as cli.UpdateOptIn does")
	}
	if lines := readLines(t, filepath.Join(dir, "consent.jsonl")); len(lines) != 5 {
		t.Fatalf("opting out records no consent: %v", lines)
	}
	if consents.Read(dir) != (consents.Consents{E1: true, CloudJudge: true}) {
		t.Fatal("clearing the gate opt-ins must not touch the consent record")
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
	if strings.TrimSpace(string(body)) != `{"paused":true,"receipted_transition_id":null}` {
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
	if _, body := call(t, s, http.MethodPost, "/v1/pause", nil); strings.TrimSpace(string(body)) != `{"paused":true,"receipted_transition_id":null}` {
		t.Fatalf("pause twice %s", body)
	}

	resp, body = call(t, s, http.MethodPost, "/v1/resume", nil)
	want(t, resp, body, http.StatusOK, "")
	if strings.TrimSpace(string(body)) != `{"paused":false,"receipted_transition_id":null}` || off.Off(dir) {
		t.Fatalf("resume %s off=%v", body, off.Off(dir))
	}
	if v := g.Answer(q, session); v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_BLOCK {
		t.Fatalf("resumed gate must gate again, got %v %q", v.GetDecision(), v.GetReason())
	}
	if _, body := call(t, s, http.MethodPost, "/v1/resume", nil); strings.TrimSpace(string(body)) != `{"paused":false,"receipted_transition_id":null}` {
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
	ve := sessionEvent(1, &m1pv1.VerdictEvent{Verdict: m1pv1.Verdict_VERDICT_VIOLATED, NoiseCertId: "cert_1", Certification: m1pv1.CertificationStatus_CERTIFICATION_STATUS_BOOTSTRAPPING})
	ve.EventId, ve.TaskId = bytes.Repeat([]byte{2}, 16), bytes.Repeat([]byte{3}, 16)
	ve.OccurredAt = timestamppb.New(time.Date(2026, 9, 16, 14, 14, 0, 0, time.UTC))
	s.Hub().Publish(ve)
	if f := next(); !strings.HasPrefix(f, "event: verdict\n") {
		t.Fatalf("frame %q", f)
	}
	ev := &m1pv1.Event{SessionId: make([]byte, 16), Body: &m1pv1.Event_GuardDecision{GuardDecision: &m1pv1.GuardDecision{ReasonCode: "x"}}}
	ev.SessionId[0] = 1
	s.Hub().Publish(ev)
	select {
	case f := <-frames:
		t.Fatalf("a proxy credential refusal is not a knee arrest; unlisted family leaked: %q", f)
	case <-time.After(30 * time.Millisecond):
	}
	s.Hub().Arrest([16]byte{1}, [16]byte{3}, verdict.KneeState{N: 3, PLCB: 0.18, VTask: 6000, CostN: 2900, Stop: true, Evaluable: true}, "ev_3")
	f = next()
	if !strings.HasPrefix(f, "event: arrest\ndata: ") {
		t.Fatalf("frame %q", f)
	}
	var arrest map[string]any
	decodeTo(t, []byte(strings.TrimPrefix(f, "event: arrest\ndata: ")), &arrest)
	if arrest["type"] != "arrest" || arrest["attempt"] != 3.0 || arrest["p_lcb"] != 0.18 || arrest["v"] != 6000.0 || arrest["c_n"] != 2900.0 || arrest["inequality"] != "0.180 * 6000.00 <= 2900.00" || arrest["evidence_ref"] != "ev_3" || arrest["session_id"] != "01000000-0000-0000-0000-000000000000" || arrest["task_id"] != "03000000-0000-0000-0000-000000000000" {
		t.Fatalf("arrest %v", arrest)
	}
	s.Hub().Arrest([16]byte{1}, [16]byte{3}, verdict.KneeState{N: 1}, "")
	decodeTo(t, []byte(strings.TrimPrefix(next(), "event: arrest\ndata: ")), &arrest)
	if arrest["p_lcb"] != nil || arrest["inequality"] != nil || arrest["evidence_ref"] != nil {
		t.Fatalf("an unevaluable knee carries no numbers (D-Z): %v", arrest)
	}

	var rows []map[string]any
	_, body := call(t, s, http.MethodGet, "/v1/verify/events?project=/w", nil)
	decodeTo(t, body, &rows)
	if len(rows) != 4 {
		t.Fatalf("verify/events must hold tamper + verdict + 2 arrests, never the guard refusal: %s", body)
	}
	if rows[0]["type"] != "tamper" || rows[0]["anchor_id"] != "ruff@cat-1" || rows[0]["session_id"] != "01000000-0000-0000-0000-000000000000" {
		t.Fatalf("tamper row %v", rows[0])
	}
	if rows[1]["type"] != "verdict" || rows[1]["verdict"] != "violated" || rows[1]["state"] != "bootstrapping" || rows[1]["certificate_id"] != "cert_1" || rows[1]["id"] != "02020202-0202-0202-0202-020202020202" || rows[1]["task_id"] != "03030303-0303-0303-0303-030303030303" || rows[1]["time"] != "2026-09-16T14:14:00Z" {
		t.Fatalf("verdict row %v", rows[1])
	}
	if rows[2]["type"] != "arrest" || rows[3]["type"] != "arrest" {
		t.Fatalf("arrest rows %v", rows[2:])
	}
	plain := sessionEvent(1, &m1pv1.VerdictEvent{})
	s.Hub().Publish(plain)
	_ = next()
	_, body = call(t, s, http.MethodGet, "/v1/verify/events", nil)
	decodeTo(t, body, &rows)
	if last := rows[len(rows)-1]; last["state"] != "uncertified" || last["certificate_id"] != nil || last["verdict"] != "unspecified" {
		t.Fatalf("unspecified certification reads uncertified and an empty cert id is null: %v", last)
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
		for _, k := range []string{"provisioned", "version", "compat"} {
			if v, ok := a[k]; !ok || v != nil {
				t.Fatalf("%s is null, never absent, until known: %s", k, body)
			}
		}
		if rp, ok := a["recent_projects"].([]any); !ok || len(rp) != 0 {
			t.Fatalf("recent_projects is an empty list when nothing is installed: %s", body)
		}
	}
	if r := agents[0]["regime"]; r != "subscription" && r != "apikey" {
		t.Fatalf("regime %v", r)
	}
	if r, ok := agents[6]["regime"]; !ok || r != nil {
		t.Fatalf("unimplemented slot carries a null regime, no sniff: %s", body)
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
	if notes, ok := prov["notes"].([]any); !ok || len(notes) != 0 {
		t.Fatalf("an OK fragment has an empty notes list: %v", prov)
	}
	if files[0].(map[string]any)["byte_equal_revert"] != true {
		t.Fatalf("an OK fragment reverts verbatim (08 §8.4 step 2): %v", prov)
	}
	post := b0(t, settings)
	if err := os.WriteFile(settings, append(append([]byte{}, post...), "\n\n"...), 0o600); err != nil {
		t.Fatal(err)
	}
	_, body = call(t, s, http.MethodGet, "/v1/agents", nil)
	decodeTo(t, body, &agents)
	prov = agents[0]["provisioned"].(map[string]any)
	if prov["files"].([]any)[0].(map[string]any)["byte_equal_revert"] != false || len(prov["notes"].([]any)) != 2 {
		t.Fatalf("a user-edited target reverts surgically, not byte-equal: %v", prov)
	}
	if err := os.WriteFile(settings, post, 0o600); err != nil {
		t.Fatal(err)
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
	if doc.OK || len(doc.Fragments) != 1 || doc.Fragments[0].State != "OK" || doc.Fragments[0].Target != settings || len(doc.Agents) != 7 || len(doc.Fragments[0].Lines) == 0 {
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
	if strings.TrimSpace(string(body)) != `{"checkpoints":[],"head":{"checkpoint_seq":0,"hash":"","seq":0},"status":"not_started"}` {
		t.Fatalf("no local head: %s", body)
	}
	if err := writeAtomic(filepath.Join(dir, "receipt", "last-head"), []byte(`{"seq":92,"hash":"ab","checkpoint_seq":4}`)); err != nil {
		t.Fatal(err)
	}
	for i, n := range []uint32{10, 20, 30} {
		cp := &m1pv1.Event{OccurredAt: timestamppb.New(time.Date(2026, 9, 16, 12+i, 0, 0, 0, time.UTC)), Body: &m1pv1.Event_ReceiptCheckpoint{ReceiptCheckpoint: &m1pv1.ReceiptCheckpoint{CheckpointSeq: uint64(i + 2), MerkleRoot: bytes.Repeat([]byte{byte(i)}, 32), LeafCount: n, KeyId: "ed25519:k"}}}
		s.Hub().Publish(cp)
	}
	var view struct {
		Status string `json:"status"`
		Head   struct {
			Seq           int64  `json:"seq"`
			Hash          string `json:"hash"`
			CheckpointSeq int64  `json:"checkpoint_seq"`
		} `json:"head"`
		Checkpoints []struct {
			Seq           uint64 `json:"seq"`
			Time          string `json:"time"`
			EventsCovered uint32 `json:"events_covered"`
			MerkleRoot    string `json:"merkle_root"`
			KeyID         string `json:"key_id"`
		} `json:"checkpoints"`
	}
	_, body = call(t, s, http.MethodGet, "/v1/receipts", nil)
	decodeTo(t, body, &view)
	if view.Status != "sealed" || view.Head.Seq != 92 || view.Head.Hash != "ab" || view.Head.CheckpointSeq != 4 {
		t.Fatalf("head %s", body)
	}
	if len(view.Checkpoints) != 3 || view.Checkpoints[0].Seq != 4 || view.Checkpoints[2].Seq != 2 || view.Checkpoints[0].EventsCovered != 30 || view.Checkpoints[0].Time != "2026-09-16T14:00:00Z" || view.Checkpoints[2].MerkleRoot != strings.Repeat("00", 32) || view.Checkpoints[0].KeyID != "ed25519:k" {
		t.Fatalf("checkpoints newest first %s", body)
	}
	_, body = call(t, s, http.MethodGet, "/v1/receipts?before=4", nil)
	decodeTo(t, body, &view)
	if len(view.Checkpoints) != 2 || view.Checkpoints[0].Seq != 3 {
		t.Fatalf("?before pages back %s", body)
	}

	t.Setenv("PATH", t.TempDir())
	resp, body := call(t, s, http.MethodPost, "/v1/receipts/verify", map[string]string{"chain": "/c", "keys": "/k"})
	want(t, resp, body, http.StatusServiceUnavailable, "M1E-9500")
	t.Setenv("MARK1_VERIFIER", filepath.Join(t.TempDir(), "absent"))
	resp, body = call(t, s, http.MethodPost, "/v1/receipts/verify", map[string]string{"chain": "/c"})
	want(t, resp, body, http.StatusBadGateway, "M1E-1002") // no keys ⇒ the enrolled server's export path, and this daemon is not enrolled
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

func jsonString(v string) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func b0(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSessionsAttributeToTheRootTheirTranscriptNames(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell stub for claude")
	}
	bin, home := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "claude"), []byte("#!/bin/sh\necho '2.1.251 (Claude Code)'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	t.Setenv("HOME", home)
	s, dir := newServer(t)
	root, _ := canonical(t.TempDir())
	if err := writeAtomic(filepath.Join(dir, "workspaces.json"), []byte(`{"version":1,"workspaces":[{"path":`+jsonString(root)+`,"enabled_at":"2026-09-16T00:00:00Z"}]}`)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".mark1ignore"), []byte("vendor/\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	txDir, err := (&claudecode.Adapter{}).TranscriptDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(txDir, 0o700); err != nil {
		t.Fatal(err)
	}
	transcript := func(sid byte, cwd string) {
		id := [16]byte{sid}
		if err := os.MkdirAll(txDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(txDir, uuid.UUID(id).String()+".jsonl"), []byte("{\"type\":\"summary\"}\n{\"cwd\":"+jsonString(cwd)+"}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	transcript(1, root)
	transcript(2, "/elsewhere")
	transcript(4, filepath.Join(root, "vendor"))
	for sid, agent := range map[byte]string{1: "claudecode", 2: "claudecode", 3: "codex", 4: "claudecode"} {
		s.Hub().Publish(sessionEvent(sid, &m1pv1.SessionStart{Agent: agent}))
	}
	var st struct {
		AgentsLive []struct {
			Agent     string `json:"agent"`
			Project   string `json:"project"`
			SessionID string `json:"session_id"`
		} `json:"agents_live"`
	}
	_, body := call(t, s, http.MethodGet, "/v1/status", nil)
	decodeTo(t, body, &st)
	got := map[string]string{}
	for _, ls := range st.AgentsLive {
		got[ls.SessionID[:2]] = ls.Project
	}
	if got["01"] != root || got["02"] != "" || got["03"] != "" || got["04"] != "" {
		t.Fatalf("attribution %v: only a transcript whose cwd the root's oracle admits names a project (02 is outside, 04 is .mark1ignore'd, 03 is not claudecode)", got)
	}
	var projects []struct {
		Path       string   `json:"path"`
		AgentsSeen []string `json:"agents_seen"`
	}
	_, body = call(t, s, http.MethodGet, "/v1/projects", nil)
	decodeTo(t, body, &projects)
	if len(projects) != 1 || !slices.Equal(projects[0].AgentsSeen, []string{"claudecode"}) {
		t.Fatalf("agents_seen %s", body)
	}
	s.Hub().Publish(sessionEvent(1, &m1pv1.SessionEnd{}))
	_, body = call(t, s, http.MethodGet, "/v1/projects", nil)
	decodeTo(t, body, &projects)
	if !slices.Equal(projects[0].AgentsSeen, []string{"claudecode"}) {
		t.Fatalf("the on-disk transcript still says claudecode worked here: %s", body)
	}
	if err := os.RemoveAll(txDir); err != nil {
		t.Fatal(err)
	}
	_, body = call(t, s, http.MethodGet, "/v1/projects", nil)
	decodeTo(t, body, &projects)
	if len(projects[0].AgentsSeen) != 0 {
		t.Fatalf("nothing observed ⇒ nothing claimed: %s", body)
	}
	var agents []struct {
		Name           string   `json:"name"`
		RecentProjects []string `json:"recent_projects"`
	}
	transcript(1, root)
	other, _ := (&claudecode.Adapter{}).TranscriptDir("/elsewhere")
	if err := os.MkdirAll(other, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, uuid.UUID([16]byte{7}).String()+".jsonl"), []byte("{\"cwd\":\"/elsewhere\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, body = call(t, s, http.MethodGet, "/v1/agents", nil)
	decodeTo(t, body, &agents)
	if agents[0].Name != "claudecode" || !slices.Equal(agents[0].RecentProjects, []string{root, "/elsewhere"}) && !slices.Equal(agents[0].RecentProjects, []string{"/elsewhere", root}) {
		t.Fatalf("recent_projects are the cwds the transcripts name, not the munged dir names: %s", body)
	}
}

// TestLiveConsultsTheSessionResolverFirst pins the attribution order: the fleet resolver wins when it names the session's own agent, an agent-less row (a manager without Config.Agent) is trusted, a mismatch falls through to the transcript-head resolve, and a hit is cached.
func TestLiveConsultsTheSessionResolverFirst(t *testing.T) {
	h := NewHub()
	for sid, agent := range map[byte]string{1: "codex", 2: "gemini", 3: "claudecode", 4: "copilot"} {
		h.Publish(sessionEvent(sid, &m1pv1.SessionStart{Agent: agent}))
	}
	h.SetSessionResolver(func(id uuid.UUID) (string, string, bool) {
		switch id[0] {
		case 1:
			return "codex", "/r/codex", true
		case 2:
			return "codex", "/r/wrong-agent", true
		case 3:
			return "", "/r/agentless", true
		}
		return "", "", false
	})
	fallback := func(agent string, sid [16]byte) string {
		if sid[0] == 1 || sid[0] == 2 {
			return "/fallback/" + agent
		}
		return ""
	}
	got := map[byte]string{}
	for _, ls := range h.live(fallback) {
		got[uuid.MustParse(ls.SessionID)[0]] = ls.Project
	}
	want := map[byte]string{1: "/r/codex", 2: "/fallback/gemini", 3: "/r/agentless", 4: ""}
	if !maps.Equal(got, want) {
		t.Fatalf("live = %v, want %v", got, want)
	}
	h.SetSessionResolver(nil)
	got = map[byte]string{}
	for _, ls := range h.live(nil) {
		got[uuid.MustParse(ls.SessionID)[0]] = ls.Project
	}
	if !maps.Equal(got, want) {
		t.Fatalf("a resolved project is cached on the live row: %v", got)
	}
}

// TestCodexSessionAttributesThroughTheTailerResolver drives the production chain: a codex rollout under the enabled root, its tailer inside Run, tailers.Resolve on the hub, and a SessionStart carrying the thread id the hookshim derives — agents_live.project, agents_seen and recent_projects all name the root.
func TestCodexSessionAttributesThroughTheTailerResolver(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell stubs for claude and codex")
	}
	bin, home := t.TempDir(), t.TempDir()
	for stub, version := range map[string]string{"claude": "2.1.251 (Claude Code)", "codex": "codex-cli 0.154.0"} {
		if err := os.WriteFile(filepath.Join(bin, stub), []byte("#!/bin/sh\necho '"+version+"'\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin)
	t.Setenv("HOME", home)
	codexHome := t.TempDir()
	t.Setenv("CODEX_HOME", codexHome)
	s, dir := newServer(t)
	root, _ := canonical(t.TempDir())
	if err := writeAtomic(filepath.Join(dir, "workspaces.json"), []byte(`{"version":1,"workspaces":[{"path":`+jsonString(root)+`,"enabled_at":"2026-09-16T00:00:00Z"}]}`)); err != nil {
		t.Fatal(err)
	}
	thread := uuid.MustParse("019965a0-0000-7000-8000-00000000aa01")
	day := filepath.Join(codexHome, "sessions", "2026", "09", "17")
	if err := os.MkdirAll(day, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(day, "rollout-2026-09-17T08-00-00-"+thread.String()+".jsonl"), []byte(`{"type":"session_meta","payload":{"cwd":`+jsonString(root)+`}}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	txDir, err := (&claudecode.Adapter{}).TranscriptDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(txDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(txDir, uuid.UUID([16]byte{2}).String()+".jsonl"), []byte(`{"cwd":`+jsonString(root)+`}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	s.Hub().SetSessionResolver(tailers.Resolve)
	live := tailers.NewLiveSet()
	if err := live.SetRoots([]string{root}); err != nil {
		t.Fatal(err)
	}
	mgr, err := (&codex.Adapter{CodexHome: codexHome}).StartTail(adapters.Workspace{Root: root}, live, codex.TailConfig{
		StateDir: t.TempDir(), UsageIdemKey: []byte("m1p-usage-idem-TEST-KEY-32bytes!"),
		Emit: func(context.Context, *m1pv1.Event) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- mgr.Run(ctx) }()
	s.Hub().Publish(&m1pv1.Event{SessionId: thread[:], Body: &m1pv1.Event_SessionStart{SessionStart: &m1pv1.SessionStart{Agent: "codex"}}})
	s.Hub().Publish(sessionEvent(2, &m1pv1.SessionStart{Agent: "claudecode"}))

	var st struct {
		AgentsLive []struct {
			Agent   string `json:"agent"`
			Project string `json:"project"`
		} `json:"agents_live"`
	}
	projects := func() map[string]string {
		_, body := call(t, s, http.MethodGet, "/v1/status", nil)
		decodeTo(t, body, &st)
		out := map[string]string{}
		for _, ls := range st.AgentsLive {
			out[ls.Agent] = ls.Project
		}
		return out
	}
	deadline := time.Now().Add(5 * time.Second)
	for projects()["codex"] != root {
		if time.Now().After(deadline) {
			t.Fatalf("codex session never attributed through the tailer: %v", projects())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := projects(); got["claudecode"] != root {
		t.Fatalf("the transcript-head fallback must still run beside the resolver: %v", got)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	s.Hub().Publish(&m1pv1.Event{SessionId: thread[:], Body: &m1pv1.Event_SessionEnd{SessionEnd: &m1pv1.SessionEnd{}}})
	var rows []struct {
		AgentsSeen []string `json:"agents_seen"`
	}
	_, body := call(t, s, http.MethodGet, "/v1/projects", nil)
	decodeTo(t, body, &rows)
	if len(rows) != 1 || !slices.Equal(rows[0].AgentsSeen, []string{"claudecode", "codex"}) {
		t.Fatalf("agents_seen unions the on-disk codex rollout tree with the transcript dir once the session is gone: %s", body)
	}
	var agentRows []struct {
		Name           string   `json:"name"`
		RecentProjects []string `json:"recent_projects"`
	}
	_, body = call(t, s, http.MethodGet, "/v1/agents", nil)
	decodeTo(t, body, &agentRows)
	if agentRows[1].Name != "codex" || !slices.Equal(agentRows[1].RecentProjects, []string{root}) {
		t.Fatalf("codex recent_projects come from its rollout heads: %s", body)
	}
}

// TestEnableProvisionsThroughTheControlAPI: POST /v1/projects is `mark1 enable` — the 08 §8 fragment lands, the manifest records it, the consent line names it, a re-POST reconciles, and the per-agent routes repair and revert it byte-equal.
func TestEnableProvisionsThroughTheControlAPI(t *testing.T) {
	home := fakeHome(t)
	s, dir := newServer(t)
	settings := filepath.Join(home, ".claude", "settings.json")
	original := "{\n  \"model\": \"opus\",\n  \"hooks\": {\"Stop\": [ {\"matcher\": \"\", \"hooks\": [{\"type\": \"command\", \"command\": \"/usr/bin/mine.sh\"}]} ]}\n}\n"
	if err := os.MkdirAll(filepath.Dir(settings), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settings, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	repoA, repoB := t.TempDir(), t.TempDir()
	type added struct {
		AgentsProvisioned []string            `json:"agents_provisioned"`
		AgentsRefused     []provision.Refusal `json:"agents_refused"`
	}
	enable := func(repo string, agents []string) added {
		t.Helper()
		body := map[string]any{"path": repo}
		if agents != nil {
			body["agents"] = agents
		}
		resp, b := call(t, s, http.MethodPost, "/v1/projects", body)
		want(t, resp, b, http.StatusOK, "")
		var a added
		decodeTo(t, b, &a)
		return a
	}
	fragmentPresent := func() bool { return strings.Contains(string(b0(t, settings)), "_mark1_managed") }

	a := enable(repoA, nil)
	if strings.Join(a.AgentsProvisioned, ",") != "claudecode" || len(a.AgentsRefused) != 0 || !fragmentPresent() || !strings.Contains(string(b0(t, settings)), "/usr/bin/mine.sh") {
		t.Fatalf("enable %+v; settings:\n%s", a, b0(t, settings))
	}
	m, err := claudecode.LoadManifest(dir)
	if err != nil || m.TargetPath != settings {
		t.Fatalf("manifest %+v %v", m, err)
	}
	if lines := readLines(t, filepath.Join(dir, "consent.jsonl")); len(lines) != 1 || !strings.Contains(lines[0], `"agents_provisioned":["claudecode"]`) {
		t.Fatalf("consent.jsonl %v", lines)
	}

	if _, err := claudecode.Revert(dir); err != nil || fragmentPresent() {
		t.Fatalf("setup: off-style revert %v", err)
	}
	if a := enable(repoA, nil); strings.Join(a.AgentsProvisioned, ",") != "claudecode" || !fragmentPresent() {
		t.Fatalf("re-POST of an enabled root must reconcile the fragment: %+v", a)
	}
	if lines := readLines(t, filepath.Join(dir, "consent.jsonl")); len(lines) != 1 {
		t.Fatalf("a reconcile is not a second consent: %v", lines)
	}

	edited := strings.Replace(string(b0(t, settings)), `"timeout": 30`, `"timeout": 90`, 1)
	if err := os.WriteFile(settings, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	if a := enable(repoA, nil); len(a.AgentsProvisioned) != 0 || len(a.AgentsRefused) != 1 || a.AgentsRefused[0].Code != claudecode.CodeDamaged || string(b0(t, settings)) != edited {
		t.Fatalf("a hand-edited fence is an M1E-7102 refusal, never overwritten by enable: %+v", a)
	}
	resp, body := call(t, s, http.MethodPost, "/v1/agents/claudecode/provision", nil)
	want(t, resp, body, http.StatusOK, "")
	var fixed struct {
		Agent       string              `json:"agent"`
		Provisioned bool                `json:"provisioned"`
		Changed     bool                `json:"changed"`
		Refused     []provision.Refusal `json:"refused"`
		Fragments   []fragment          `json:"fragments"`
	}
	decodeTo(t, body, &fixed)
	if fixed.Agent != "claudecode" || !fixed.Provisioned || !fixed.Changed || len(fixed.Refused) != 0 || len(fixed.Fragments) != 1 || fixed.Fragments[0].State != string(claudecode.StateOK) || len(fixed.Fragments[0].Lines) != 9 {
		t.Fatalf("repair %s", body)
	}
	if m2, err := claudecode.LoadManifest(dir); err != nil || m2.PreImageHash != m.PreImageHash {
		t.Fatalf("repair re-snapshotted the pre-image: %v %+v", err, m2)
	}
	resp, body = call(t, s, http.MethodPost, "/v1/agents/claudecode/provision", nil)
	want(t, resp, body, http.StatusOK, "")
	decodeTo(t, body, &fixed)
	if fixed.Changed {
		t.Fatalf("a second repair over an OK fence is the idempotent no-op: %s", body)
	}

	resp, body = call(t, s, http.MethodPost, "/v1/agents/claudecode/disable", nil)
	want(t, resp, body, http.StatusOK, "")
	var off struct {
		Agent        string               `json:"agent"`
		Reverted     []provision.Reverted `json:"reverted"`
		NotReverted  []string             `json:"not_reverted"`
		ByteEquality bool                 `json:"byte_equality"`
	}
	decodeTo(t, body, &off)
	if off.Agent != "claudecode" || len(off.Reverted) != 1 || off.Reverted[0].Kind != "verbatim" || off.Reverted[0].Target != settings || !off.ByteEquality || len(off.NotReverted) != 0 {
		t.Fatalf("disable %s", body)
	}
	if string(b0(t, settings)) != original {
		t.Fatalf("not byte-equal after disable:\n%s", b0(t, settings))
	}
	if _, err := os.Stat(claudecode.ManifestPath(dir)); !os.IsNotExist(err) {
		t.Fatalf("manifest survives the revert: %v", err)
	}
	if roots, err := tailers.LoadWorkspacesFile(filepath.Join(dir, "workspaces.json")); err != nil || len(roots) != 1 {
		t.Fatalf("disabling an agent must keep the workspace: %v %v", roots, err)
	}
	resp, body = call(t, s, http.MethodPost, "/v1/agents/claudecode/disable", nil)
	want(t, resp, body, http.StatusOK, "")
	if !strings.Contains(string(body), `"reverted":[]`) {
		t.Fatalf("disable twice succeeds twice: %s", body)
	}

	resp, body = call(t, s, http.MethodPost, "/v1/agents/crush/provision", nil)
	want(t, resp, body, http.StatusNotFound, "M1E-2001")
	resp, body = call(t, s, http.MethodPost, "/v1/agents/codex/provision", nil)
	want(t, resp, body, http.StatusConflict, "M1E-2001")
	if a := enable(repoA, []string{"codex"}); len(a.AgentsProvisioned) != 0 || len(a.AgentsRefused) != 0 || fragmentPresent() {
		t.Fatalf("agents:[codex] must not walk claudecode: %+v", a)
	}

	enable(repoA, nil)
	enable(repoB, nil)
	resp, body = call(t, s, http.MethodDelete, "/v1/projects", map[string]string{"path": repoA})
	want(t, resp, body, http.StatusOK, "")
	if !strings.Contains(string(body), `"reverted":[]`) || !fragmentPresent() {
		t.Fatalf("removing one of two projects must leave the other's hooks in place: %s", body)
	}
	resp, body = call(t, s, http.MethodDelete, "/v1/projects", map[string]string{"path": repoB})
	want(t, resp, body, http.StatusOK, "")
	var removed struct {
		Reverted     []provision.Reverted `json:"reverted"`
		ByteEquality bool                 `json:"byte_equality"`
	}
	decodeTo(t, body, &removed)
	if len(removed.Reverted) != 1 || removed.Reverted[0].Kind != "verbatim" || !removed.ByteEquality || string(b0(t, settings)) != original {
		t.Fatalf("removing the last project reverts as `mark1 off` does: %s\n%s", body, b0(t, settings))
	}
}

// TestLiveDropsASessionQuietForTheIdleTTL: opencode never sends SessionEnd (session.idle is a turn), so a quiet session must leave agents_live on its own; any event refreshes it.
func TestLiveDropsASessionQuietForTheIdleTTL(t *testing.T) {
	h := NewHub()
	h.Publish(sessionEvent(1, &m1pv1.SessionStart{Agent: "opencode"}))
	h.Publish(sessionEvent(2, &m1pv1.SessionStart{Agent: "codex"}))
	h.mu.Lock()
	for id, s := range h.sessions {
		if id[0] == 1 {
			s.seen = time.Now().Add(-liveIdleTTL - time.Second)
		}
	}
	h.mu.Unlock()
	h.Publish(sessionEvent(2, &m1pv1.Usage{InputTokens: 1}))
	got := map[byte]bool{}
	for _, ls := range h.live(nil) {
		got[uuid.MustParse(ls.SessionID)[0]] = true
	}
	if got[1] || !got[2] {
		t.Fatalf("live = %v, want only the session that spoke within the TTL", got)
	}
	h.mu.Lock()
	_, stale := h.sessions[[16]byte{1}]
	h.mu.Unlock()
	if stale {
		t.Fatal("the idle session was listed out but not evicted")
	}
}
