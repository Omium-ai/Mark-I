//go:build integration

package querychoke_test

// DSN-gated ClickHouse integration for the desktop app's ledger routes (internal/appapi): events planted for two tenants through the production projection path (chproj.RowsFromBatch → the INSERT-only principal's chconn), read back through the real CHRunner under the real templates, and asserted as tenant A never to carry a tenant-B marker. Lives here, not in appapi, because the query principal's constructor is confined to this directory (confinement_test.go); the routes under test are appapi's.

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/appapi"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/appapi/schemacheck"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/chproj"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke/chconn"
	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

func appEndpoint(t *testing.T) (addr, user, pass string) {
	t.Helper()
	v := os.Getenv("M1_TEST_CH_DSN")
	if v == "" {
		if os.Getenv("M1_REQUIRE_STORES") == "1" {
			t.Fatal("M1_TEST_CH_DSN required (M1_REQUIRE_STORES=1) but unset")
		}
		t.Skip("M1_TEST_CH_DSN unset; skipping ClickHouse-backed test")
	}
	u, err := url.Parse(v)
	if err != nil {
		t.Fatal(err)
	}
	user = "default"
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}
	if u.Scheme == "clickhouse" || u.Scheme == "tcp" {
		return u.Host, user, pass
	}
	probe := *u
	probe.User = nil
	q := probe.Query()
	q.Set("query", "SELECT getServerPort('tcp_port')")
	probe.RawQuery = q.Encode()
	req, err := http.NewRequest(http.MethodGet, probe.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-ClickHouse-User", user)
	if pass != "" {
		req.Header.Set("X-ClickHouse-Key", pass)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("cannot reach test ClickHouse: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("tcp_port probe: %d %s", resp.StatusCode, body)
	}
	return net.JoinHostPort(u.Hostname(), strings.TrimSpace(string(body))), user, pass
}

func appStatements(sql string) []string {
	var b strings.Builder
	for _, line := range strings.Split(sql, "\n") {
		if i := strings.Index(line, "--"); i >= 0 {
			line = line[:i]
		}
		b.WriteString(line + "\n")
	}
	var out []string
	for _, s := range strings.Split(b.String(), ";") {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

type appRig struct {
	t      *testing.T
	ingest *chconn.Conn
	api    *httptest.Server
	schema *schemacheck.Set
}

func setupApp(t *testing.T) *appRig {
	t.Helper()
	ctx := context.Background()
	addr, user, pass := appEndpoint(t)
	bootstrap, err := clickhouse.Open(&clickhouse.Options{Addr: []string{addr}, Auth: clickhouse.Auth{Database: "default", Username: user, Password: pass}})
	if err != nil {
		t.Fatal(err)
	}
	scratch := fmt.Sprintf("appapi_it_%d", time.Now().UnixNano())
	if err := bootstrap.Exec(ctx, "CREATE DATABASE "+scratch); err != nil {
		t.Fatalf("cannot reach test ClickHouse: %v", err)
	}
	t.Cleanup(func() {
		_ = bootstrap.Exec(context.Background(), "DROP DATABASE IF EXISTS "+scratch)
		_ = bootstrap.Close()
	})
	for _, file := range []string{"m1_ch_001_events.sql", "m1_ch_002_rollups.sql"} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "migrations", file))
		if err != nil {
			t.Fatal(err)
		}
		for _, stmt := range appStatements(string(raw)) {
			stmt = strings.ReplaceAll(stmt, "mark1.", scratch+".")
			stmt = strings.ReplaceAll(stmt, "EXISTS mark1", "EXISTS "+scratch)
			if err := bootstrap.Exec(ctx, stmt); err != nil {
				t.Fatalf("%s: %v\n%s", file, err, stmt)
			}
		}
	}
	// The two runtime principals with the real grant shapes (05 §6 / 07).
	const itPass = "mark1-it"
	qUser, iUser := scratch+"_query", scratch+"_ingest"
	for _, stmt := range []string{
		"CREATE USER " + qUser + " IDENTIFIED WITH plaintext_password BY '" + itPass + "'",
		"CREATE USER " + iUser + " IDENTIFIED WITH plaintext_password BY '" + itPass + "' SETTINGS async_insert = 1, wait_for_async_insert = 1",
		"GRANT SELECT ON " + scratch + ".* TO " + qUser,
		"GRANT INSERT, SELECT ON " + scratch + ".* TO " + iUser,
	} {
		if err := bootstrap.Exec(ctx, stmt); err != nil {
			t.Fatalf("principal provisioning: %v\n%s", err, stmt)
		}
	}
	t.Cleanup(func() { _ = bootstrap.Exec(context.Background(), "DROP USER IF EXISTS "+qUser+", "+iUser) })
	write, err := chconn.Open(ctx, chconn.Options{Addr: addr, Database: scratch, Username: iUser, Password: itPass})
	if err != nil {
		t.Fatalf("chconn.Open (R3): %v", err)
	}
	t.Cleanup(func() { _ = write.Close() })
	read, err := chconn.OpenQuery(ctx, chconn.Options{Addr: addr, Database: scratch, Username: qUser, Password: itPass})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = read.Close() })

	reg, err := querychoke.LoadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	runner := querychoke.NewRunner(read, write, nil)
	verifier := auth.NewHMACVerifier([]byte(appKey), auth.StaticRevocations{})
	obsCfg := obs.Config{ServiceName: "appapi-ch-it"}
	m := appapi.New(appapi.Deps{
		Verifier: verifier, ObsCfg: obsCfg, Registry: reg, Runner: runner,
		Reports: querychoke.New(querychoke.Deps{Registry: reg, Runner: runner, Verifier: verifier, ObsCfg: obsCfg}),
	})
	mux := http.NewServeMux()
	m.RegisterRoutes(mux)
	api := httptest.NewServer(mux)
	t.Cleanup(api.Close)
	return &appRig{t: t, ingest: write, api: api, schema: schemacheck.Load(t, filepath.Join("..", "appapi", "schema"))}
}

const appKey = "appapi-ch-it-key"

func (r *appRig) raw(path string, tenant uuid.UUID) (int, []byte) {
	r.t.Helper()
	req, err := http.NewRequest(http.MethodGet, r.api.URL+path, nil)
	if err != nil {
		r.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+auth.Mint([]byte(appKey), tenant, uuid.New(), time.Hour))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

// get fetches as the tenant and validates the body against the route's schema (error.json on a non-200).
func (r *appRig) get(path string, tenant uuid.UUID) (int, []byte) {
	r.t.Helper()
	code, body := r.raw(path, tenant)
	schema := "error.json"
	if code == http.StatusOK {
		schema = map[string]string{"/sessions": "sessions.json", "/moments": "moments.json", "/route/decisions": "route_decisions.json"}[routeOf(path)]
		if schema == "" {
			schema = "session_detail.json"
		}
	}
	r.schema.Validate(schema, body)
	return code, body
}

func routeOf(path string) string {
	p := strings.TrimPrefix(strings.SplitN(path, "?", 2)[0], "/api/v1")
	if strings.HasPrefix(p, "/sessions/") {
		return "/sessions/{id}"
	}
	return p
}

// planted is what one tenant's batch put in the ledger, by id.
type planted struct {
	session, task, decision, cert uuid.UUID
	workspaceHex                  string
	tokens                        uint64
}

// plant lands one session through the production projection path: SessionStart (workspace + capture paths), a task with its verdict trail, an anchor vote with typed evidence, a memory injection, a route decision followed by the Usage that served it, a task-bearing GuardDecision and a receipt checkpoint.
func plant(t *testing.T, r *appRig, tenant uuid.UUID, tokens uint64) planted {
	t.Helper()
	ctx := context.Background()
	at := time.Now().UTC().Add(-2 * time.Hour)
	device, batchID := uuid.New(), uuid.Must(uuid.NewV7())
	p := planted{session: uuid.Must(uuid.NewV7()), task: uuid.New(), decision: uuid.Must(uuid.NewV7()), cert: uuid.New(), tokens: tokens}
	workspace := make([]byte, 32)
	workspace[0], workspace[31] = byte(tokens), 0x7f
	p.workspaceHex = hex.EncodeToString(workspace)
	idem := make([]byte, 32)
	idem[0] = 1
	ev := func(seq uint64, task uuid.UUID, body any) *m1pv1.Event {
		return evFor(t, p.session, at, seq, task, body)
	}
	artifact := uuid.New()
	batch := &m1pv1.Batch{
		BatchId: batchID[:], SessionId: p.session[:], Sdk: &m1pv1.SdkInfo{Agent: "claudecode"}, SentAt: timestamppb.New(at),
		Events: []*m1pv1.Event{
			ev(1, uuid.Nil, &m1pv1.SessionStart{Agent: "claudecode", AgentVersion: "2.1.0", WorkspaceId: workspace, CapturePaths: []m1pv1.CapturePath{m1pv1.CapturePath_CAPTURE_PATH_HOOKS, m1pv1.CapturePath_CAPTURE_PATH_PROXY}}),
			ev(2, p.task, &m1pv1.TaskOpen{TaskSegVersion: "task_seg.v1", TaskClass: "edit.small", PromptDigest: workspace}),
			ev(3, p.task, &m1pv1.RouteDecision{DecisionId: p.decision[:], Action: "mid", Candidates: []string{"small", "mid"}, Propensity: 1, Fidelity: m1pv1.RouteFidelity_ROUTE_FIDELITY_WIRE_ENFORCED, BundleSeq: 483}),
			ev(4, p.task, &m1pv1.Usage{IdemKey: idem, Model: "mid", InputTokens: tokens, OutputTokens: 10}),
			ev(5, p.task, &m1pv1.VerdictEvent{Stage: m1pv1.VerdictStage_VERDICT_STAGE_PROVISIONAL, Verdict: m1pv1.Verdict_VERDICT_VIOLATED, Posterior: []float64{0.1, 0.8, 0.05, 0.05}}),
			ev(6, p.task, &m1pv1.AnchorVote{AnchorId: "ruff@1", Vote: m1pv1.Verdict_VERDICT_VIOLATED,
				Evidence:  &m1pv1.EvidenceRecord{Tool: "ruff", DiagnosticCode: "E501", Category: m1pv1.EvidenceCategory_EVIDENCE_CATEGORY_LINT, Counts: &m1pv1.EvidenceCounts{Errors: 2, Warnings: 1, FilesAffected: 1}, PathRole: m1pv1.PathRole_PATH_ROLE_SRC, OutputHmac: workspace},
				Integrity: &m1pv1.AnchorIntegrity{Tamper: false}}),
			ev(7, p.task, &m1pv1.GuardDecision{Outcome: m1pv1.GuardOutcome_GUARD_OUTCOME_REFUSED, SampleRate: 1, ReasonCode: "knee_arrest"}),
			ev(8, p.task, &m1pv1.MemoryInjection{ArtifactIds: [][]byte{artifact[:]}, Channel: m1pv1.InjectionChannel_INJECTION_CHANNEL_HOOK_CONTEXT, TokensUsed: 12}),
			ev(9, p.task, &m1pv1.Usage{IdemKey: append([]byte{2}, idem[1:]...), Model: "mid", InputTokens: 20, OutputTokens: 5}),
			ev(10, p.task, &m1pv1.VerdictEvent{Stage: m1pv1.VerdictStage_VERDICT_STAGE_CERTIFIED, Verdict: m1pv1.Verdict_VERDICT_SATISFIED, Posterior: []float64{0.9, 0.05, 0.03, 0.02}, NoiseCertId: p.cert.String(), BundleSeq: 483, Certification: m1pv1.CertificationStatus_CERTIFICATION_STATUS_CERTIFIED}),
			ev(11, p.task, &m1pv1.TaskClose{Resolution: m1pv1.Resolution_RESOLUTION_VERDICT, TurnCount: 3}),
			ev(12, uuid.Nil, &m1pv1.ReceiptCheckpoint{CheckpointSeq: 41}),
		},
	}
	rows := chproj.RowsFromBatch(batch, tenant, device, at)
	if len(rows) != len(batch.Events) {
		t.Fatalf("projection skipped events: %d of %d", len(rows), len(batch.Events))
	}
	if err := r.ingest.InsertRows(ctx, chproj.Table, chproj.Columns, rows); err != nil {
		t.Fatalf("projection insert: %v", err)
	}
	// A §2.5 replay of the same batch: the reader dedupe must keep every count exact.
	if err := r.ingest.InsertRows(ctx, chproj.Table, chproj.Columns, chproj.RowsFromBatch(batch, tenant, device, at)); err != nil {
		t.Fatalf("replay insert: %v", err)
	}
	return p
}

func v7b() []byte {
	id := uuid.Must(uuid.NewV7())
	return id[:]
}

func evFor(t *testing.T, session uuid.UUID, at time.Time, seq uint64, task uuid.UUID, body any) *m1pv1.Event {
	t.Helper()
	e := &m1pv1.Event{EventId: v7b(), Seq: seq, SessionEpoch: 1, SessionId: session[:], OccurredAt: timestamppb.New(at.Add(time.Duration(seq) * time.Second))}
	if task != uuid.Nil {
		e.TaskId = task[:]
	}
	switch b := body.(type) {
	case *m1pv1.SessionStart:
		e.Body = &m1pv1.Event_SessionStart{SessionStart: b}
	case *m1pv1.TaskOpen:
		e.Body = &m1pv1.Event_TaskOpen{TaskOpen: b}
	case *m1pv1.TaskClose:
		e.Body = &m1pv1.Event_TaskClose{TaskClose: b}
	case *m1pv1.Usage:
		e.Body = &m1pv1.Event_Usage{Usage: b}
	case *m1pv1.VerdictEvent:
		e.Body = &m1pv1.Event_VerdictEvent{VerdictEvent: b}
	case *m1pv1.AnchorVote:
		e.Body = &m1pv1.Event_AnchorVote{AnchorVote: b}
	case *m1pv1.MemoryInjection:
		e.Body = &m1pv1.Event_MemoryInjection{MemoryInjection: b}
	case *m1pv1.RouteDecision:
		e.Body = &m1pv1.Event_RouteDecision{RouteDecision: b}
	case *m1pv1.GuardDecision:
		e.Body = &m1pv1.Event_GuardDecision{GuardDecision: b}
	case *m1pv1.ReceiptCheckpoint:
		e.Body = &m1pv1.Event_ReceiptCheckpoint{ReceiptCheckpoint: b}
	default:
		t.Fatalf("unhandled body %T", body)
	}
	return e
}

// The agent every app surface reports is the SESSION's (its SessionStart), not whichever batch-level SdkInfo.agent chproj happened to stamp on the row: a codex session whose SessionStart landed in an earlier batch than its moments, on a device whose SdkInfo says claudecode, reads codex everywhere; a session with no SessionStart in the window keeps its stamped agent rather than going blank.
func TestIntegrationAgentIsTheSessionsNotTheBatchStamp(t *testing.T) {
	r := setupApp(t)
	ctx := context.Background()
	tenant, device := uuid.New(), uuid.New()
	at := time.Now().UTC().Add(-2 * time.Hour)
	codex, orphan := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	taskC, taskO := uuid.New(), uuid.New()
	idem := make([]byte, 32)
	idem[0] = 9
	agentCol := 0
	for i, c := range chproj.Columns {
		if c == "agent" {
			agentCol = i
		}
	}
	land := func(sdkAgent string, legacy bool, events ...*m1pv1.Event) [][]any {
		t.Helper()
		rows := chproj.RowsFromBatch(&m1pv1.Batch{BatchId: v7b(), SessionId: events[0].SessionId, Sdk: &m1pv1.SdkInfo{Agent: sdkAgent}, SentAt: timestamppb.New(at), Events: events}, tenant, device, at)
		for _, row := range rows {
			if legacy {
				row[agentCol] = ""
			}
		}
		if err := r.ingest.InsertRows(ctx, chproj.Table, chproj.Columns, rows); err != nil {
			t.Fatalf("projection insert: %v", err)
		}
		return rows
	}
	land("claudecode", false,
		evFor(t, codex, at, 1, uuid.Nil, &m1pv1.SessionStart{Agent: "codex", CapturePaths: []m1pv1.CapturePath{m1pv1.CapturePath_CAPTURE_PATH_HOOKS}}),
		evFor(t, codex, at, 2, taskC, &m1pv1.TaskOpen{TaskSegVersion: "task_seg.v1"}))
	later := land("claudecode", false,
		evFor(t, codex, at, 3, taskC, &m1pv1.RouteDecision{DecisionId: v7b(), Action: "mid", Candidates: []string{"small", "mid"}, Propensity: 1, Fidelity: m1pv1.RouteFidelity_ROUTE_FIDELITY_WIRE_ENFORCED, BundleSeq: 1}),
		evFor(t, codex, at, 4, taskC, &m1pv1.Usage{IdemKey: idem, Model: "mid", InputTokens: 7, OutputTokens: 1}),
		evFor(t, codex, at, 5, taskC, &m1pv1.GuardDecision{Outcome: m1pv1.GuardOutcome_GUARD_OUTCOME_REFUSED, SampleRate: 1, ReasonCode: "knee_arrest"}),
		evFor(t, codex, at, 6, taskC, &m1pv1.MemoryInjection{ArtifactIds: [][]byte{v7b()}, Channel: m1pv1.InjectionChannel_INJECTION_CHANNEL_HOOK_CONTEXT, TokensUsed: 1}))
	for _, row := range later {
		if row[agentCol] != "claudecode" {
			t.Fatalf("precondition: the later batch's rows carry the device stamp, got %v", row[agentCol])
		}
	}
	land("gemini", false,
		evFor(t, orphan, at, 1, taskO, &m1pv1.TaskOpen{TaskSegVersion: "task_seg.v1"}),
		evFor(t, orphan, at, 2, taskO, &m1pv1.RouteDecision{DecisionId: v7b(), Action: "small", Candidates: []string{"small"}, Propensity: 1, Fidelity: m1pv1.RouteFidelity_ROUTE_FIDELITY_CONFIG_STEERED, BundleSeq: 1}),
		evFor(t, orphan, at, 3, taskO, &m1pv1.GuardDecision{Outcome: m1pv1.GuardOutcome_GUARD_OUTCOME_REFUSED, SampleRate: 1, ReasonCode: "knee_arrest"}))
	// Pre-fix rows: an unarmed daemon stamped '' on every row; the SessionStart payload still names the agent.
	legacy, taskL := uuid.Must(uuid.NewV7()), uuid.New()
	land("", true,
		evFor(t, legacy, at, 1, uuid.Nil, &m1pv1.SessionStart{Agent: "opencode"}),
		evFor(t, legacy, at, 2, taskL, &m1pv1.TaskOpen{TaskSegVersion: "task_seg.v1"}),
		evFor(t, legacy, at, 3, taskL, &m1pv1.RouteDecision{DecisionId: v7b(), Action: "small", Candidates: []string{"small"}, Propensity: 1, Fidelity: m1pv1.RouteFidelity_ROUTE_FIDELITY_CONFIG_STEERED, BundleSeq: 1}),
		evFor(t, legacy, at, 4, taskL, &m1pv1.GuardDecision{Outcome: m1pv1.GuardOutcome_GUARD_OUTCOME_REFUSED, SampleRate: 1, ReasonCode: "knee_arrest"}))

	want := map[string]string{codex.String(): "codex", orphan.String(): "gemini", legacy.String(): "opencode"}
	check := func(path string, items []any) {
		t.Helper()
		seen := map[string]int{}
		for _, it := range items {
			m := it.(map[string]any)
			sid := m["session_id"].(string)
			if m["agent"] != want[sid] {
				t.Errorf("%s: session %s reads agent %v, want %s", path, sid, m["agent"], want[sid])
			}
			seen[sid]++
		}
		if len(seen) != len(want) {
			t.Errorf("%s: want every session, saw %v", path, seen)
		}
	}
	for path, key := range map[string]string{"/api/v1/sessions?window=2d": "sessions", "/api/v1/moments?since=" + at.Add(-time.Hour).Format(time.RFC3339): "moments", "/api/v1/route/decisions?window=2d": "decisions"} {
		code, raw := r.get(path, tenant)
		if code != http.StatusOK {
			t.Fatalf("%s: %d %s", path, code, raw)
		}
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatal(err)
		}
		check(path, body[key].([]any))
	}
	if _, raw := r.get("/api/v1/sessions?window=2d&agent=codex", tenant); !strings.Contains(string(raw), codex.String()) || strings.Contains(string(raw), orphan.String()) {
		t.Fatalf("agent filter must see the SessionStart agent: %s", raw)
	}
}

func TestIntegrationAppRoutesOverPlantedLedger(t *testing.T) {
	r := setupApp(t)
	tenantA, tenantB := uuid.New(), uuid.New()
	a := plant(t, r, tenantA, 1000)
	b := plant(t, r, tenantB, 987_654)
	leaks := func(body []byte) {
		t.Helper()
		for marker, what := range map[string]string{b.session.String(): "B's session", b.task.String(): "B's task", b.decision.String(): "B's decision", "987654": "B's token count", b.workspaceHex: "B's workspace", tenantB.String(): "B's tenant id"} {
			if strings.Contains(string(body), marker) {
				t.Fatalf("tenant A's response carried %s: %s", what, body)
			}
		}
	}
	noPayloadLeak := func(body []byte) {
		t.Helper()
		if strings.Contains(string(body), base64.StdEncoding.EncodeToString(make([]byte, 4))) || strings.Contains(string(body), "output_hmac") || strings.Contains(string(body), "prompt_digest") || strings.Contains(string(body), "idem_key") {
			t.Fatalf("payload remainder leaked into the app surface: %s", body)
		}
	}

	// /sessions: one row for A, projected from the real SessionStart/Usage/Verdict/etc rows, replay-exact.
	code, raw := r.get("/api/v1/sessions?window=2d", tenantA)
	if code != http.StatusOK {
		t.Fatalf("sessions: %d %s", code, raw)
	}
	leaks(raw)
	var sessions struct {
		Sessions []map[string]any `json:"sessions"`
		Honesty  map[string]any   `json:"honesty"`
	}
	if err := json.Unmarshal(raw, &sessions); err != nil {
		t.Fatal(err)
	}
	if len(sessions.Sessions) != 1 {
		t.Fatalf("A sees exactly its session: %s", raw)
	}
	s := sessions.Sessions[0]
	if s["session_id"] != a.session.String() || s["agent"] != "claudecode" || s["project"] != a.workspaceHex {
		t.Fatalf("session identity from SessionStart: %v", s)
	}
	if tk := s["tokens"].(map[string]any); tk["input"] != float64(1020) || tk["output"] != float64(15) {
		t.Fatalf("tokens replay-exact: %v", tk)
	}
	if s["tasks"] != float64(1) || s["verified_outcomes"] != float64(1) || s["arrests"] != float64(1) || s["injections"] != float64(1) || s["route_decisions"] != float64(1) || s["checkpoint_seq"] != float64(41) {
		t.Fatalf("counts: %v", s)
	}
	if cov := s["coverage"].(map[string]any); cov["proxy_in_path"] != true || cov["transcript_tailed"] != false {
		t.Fatalf("capture paths: %v", cov)
	}
	if sessions.Honesty["guarantee_grade"] != false || !strings.Contains(sessions.Honesty["refusal"].(string), "M1E-5004") {
		t.Fatalf("no rollup day ⇒ the honesty fields say indicative and why: %v", sessions.Honesty)
	}
	if _, raw := r.get("/api/v1/sessions?window=2d&project="+b.workspaceHex, tenantA); !strings.Contains(string(raw), `"sessions":[]`) {
		t.Fatalf("A filtering on B's workspace sees nothing: %s", raw)
	}

	// /sessions/{id}: attempts, trail, typed evidence from the real projected payloads.
	code, raw = r.get("/api/v1/sessions/"+a.session.String(), tenantA)
	if code != http.StatusOK {
		t.Fatalf("detail: %d %s", code, raw)
	}
	leaks(raw)
	noPayloadLeak(raw)
	var detail struct {
		Tasks         []map[string]any `json:"tasks"`
		CheckpointSeq float64          `json:"checkpoint_seq"`
	}
	if err := json.Unmarshal(raw, &detail); err != nil {
		t.Fatal(err)
	}
	if len(detail.Tasks) != 1 || detail.CheckpointSeq != 41 {
		t.Fatalf("detail: %s", raw)
	}
	task := detail.Tasks[0]
	if task["task_id"] != a.task.String() || task["task_seg_version"] != "task_seg.v1" || task["task_class"] != "edit.small" || task["resolution"] != "verdict" {
		t.Fatalf("task header: %v", task)
	}
	attempts := task["attempts"].([]any)
	if len(attempts) != 1 || attempts[0].(map[string]any)["tokens"] != float64(1035) || attempts[0].(map[string]any)["verdict"] != "satisfied" || attempts[0].(map[string]any)["verdict_stage"] != "certified" {
		t.Fatalf("one stage-final verdict ⇒ one attempt holding every token: %v", attempts)
	}
	trail := task["verdict_trail"].([]any)
	if len(trail) != 2 || trail[0].(map[string]any)["stage"] != "provisional" || trail[1].(map[string]any)["certificate_id"] != a.cert.String() || trail[1].(map[string]any)["certification"] != "certified" || trail[1].(map[string]any)["bundle_seq"] != float64(483) {
		t.Fatalf("verdict trail: %v", trail)
	}
	ev := task["evidence"].([]any)[0].(map[string]any)
	if ev["tool"] != "ruff" || ev["diagnostic_code"] != "E501" || ev["category"] != "lint" || ev["path_role"] != "src" || ev["counts"].(map[string]any)["errors"] != float64(2) || ev["vote"] != "violated" {
		t.Fatalf("typed evidence: %v", ev)
	}
	if inj := task["injections"].([]any)[0].(map[string]any); inj["channel"] != "hook_context" || inj["tokens_used"] != float64(12) || inj["artifact_count"] != float64(1) {
		t.Fatalf("injection: %v", inj)
	}
	if len(task["arrests"].([]any)) != 1 {
		t.Fatalf("arrest: %v", task["arrests"])
	}
	// B's session under A's token: not found, never B's rows.
	code, raw = r.get("/api/v1/sessions/"+b.session.String()+"?window=2d", tenantA)
	if code != http.StatusNotFound {
		t.Fatalf("B's session as A: %d %s", code, raw)
	}
	leaks(raw)

	// /moments: three kinds, newest first, A's only.
	code, raw = r.get("/api/v1/moments?since="+time.Now().UTC().Add(-3*time.Hour).Format(time.RFC3339), tenantA)
	if code != http.StatusOK {
		t.Fatalf("moments: %d %s", code, raw)
	}
	leaks(raw)
	noPayloadLeak(raw)
	var moments struct {
		Moments []map[string]any `json:"moments"`
	}
	if err := json.Unmarshal(raw, &moments); err != nil {
		t.Fatal(err)
	}
	kinds := []string{}
	for _, m := range moments.Moments {
		kinds = append(kinds, m["kind"].(string))
	}
	if strings.Join(kinds, ",") != "injection,arrest,route" {
		t.Fatalf("moments newest first: %v", kinds)
	}
	if rt := moments.Moments[2]["route"].(map[string]any); rt["fidelity"] != "wire_enforced" || rt["bundle_seq"] != float64(483) || rt["action"] != "mid" {
		t.Fatalf("route moment: %v", rt)
	}

	// /route/decisions: the C9 served-model join and the certified label.
	code, raw = r.get("/api/v1/route/decisions?window=2d", tenantA)
	if code != http.StatusOK {
		t.Fatalf("route decisions: %d %s", code, raw)
	}
	leaks(raw)
	var decisions struct {
		Decisions []map[string]any `json:"decisions"`
	}
	if err := json.Unmarshal(raw, &decisions); err != nil {
		t.Fatal(err)
	}
	if len(decisions.Decisions) != 1 {
		t.Fatalf("decisions: %s", raw)
	}
	d := decisions.Decisions[0]
	// decision_id is the RouteDecision EVENT id (ope_route_decisions), a UUIDv7 the route dates from.
	if _, err := uuid.Parse(d["decision_id"].(string)); err != nil || d["served_model"] != "mid" || d["verdict"] != "satisfied" || d["fidelity"] != "wire_enforced" || d["at"] == nil || d["label_confidence"] == nil {
		t.Fatalf("decision: %v", d)
	}

	// The mirror image: B sees its own session and none of A's.
	_, rawB := r.get("/api/v1/sessions?window=2d", tenantB)
	if !strings.Contains(string(rawB), b.session.String()) || strings.Contains(string(rawB), a.session.String()) || strings.Contains(string(rawB), a.workspaceHex) {
		t.Fatalf("B's view: %s", rawB)
	}
}
