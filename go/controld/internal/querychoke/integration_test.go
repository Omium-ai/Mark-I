//go:build integration

package querychoke

// DSN-gated ClickHouse integration: a scratch database gets the REAL
// m1_ch_001 + m1_ch_002 DDL (database name rewritten, nothing else), and the
// suite proves the two claims that make the choke a control rather than a
// convention, against a live server:
//
//   1. The estate's decorative-RLS test, CH edition (05 §6.4 "live
//      negative"): with two tenants' rows present, every read template run
//      as tenant A returns zero tenant-B rows.
//   2. ADR-0010 §2.3's idempotency: the tvo_rollup_tenant_day write template
//      inserts one row; re-running with the same job_key does not double it
//      (insert_deduplication_token pins identity to the JOB, so even a
//      re-run with different bytes is dropped); a restated series under a
//      new job_key lands beside the original.
//
// Gate: M1_TEST_CH_DSN (the one store-contract var, justfile / 12 §11.4);
// absent ⇒ skip, unless M1_REQUIRE_STORES=1 ⇒ fail. The compose stack's
// native endpoint is clickhouse://default:mark1@127.0.0.1:59000.

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke/chconn"
)

// chIntEndpoint mirrors chconn's resolver: the contract var is the HTTP URL;
// native lanes pass clickhouse://user:pass@host:port directly.
func chIntEndpoint(t *testing.T) (addr, user, pass string) {
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
		t.Fatalf("M1_TEST_CH_DSN unparseable: %v", err)
	}
	user = "default"
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}
	switch u.Scheme {
	case "clickhouse", "tcp":
		return u.Host, user, pass
	case "http", "https":
	default:
		t.Fatalf("M1_TEST_CH_DSN scheme %q: want http(s) or clickhouse", u.Scheme)
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
		t.Fatalf("cannot reach test ClickHouse over M1_TEST_CH_DSN: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("tcp_port probe: status %d: %s", resp.StatusCode, body)
	}
	return net.JoinHostPort(u.Hostname(), strings.TrimSpace(string(body))), user, pass
}

// splitStatements strips -- comments line-wise and splits on ';' — sound for
// the two migration files (no string literal in either contains one).
func splitStatements(sql string) []string {
	var b strings.Builder
	for _, line := range strings.Split(sql, "\n") {
		if i := strings.Index(line, "--"); i >= 0 {
			line = line[:i]
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	var out []string
	for _, s := range strings.Split(b.String(), ";") {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

type itRig struct {
	scratch string
	boot    driver.Conn // scratch-scoped raw handle for test-side assertions
	runner  *CHRunner
	// ingest is the INSERT-only principal's handle — the chproj seed path,
	// exported to tests so seeding itself exercises the real grant.
	ingest *chconn.Conn
}

func setupQC(t *testing.T) *itRig {
	t.Helper()
	ctx := context.Background()
	addr, user, pass := chIntEndpoint(t)

	bootstrap, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{addr},
		Auth: clickhouse.Auth{Database: "default", Username: user, Password: pass},
	})
	if err != nil {
		t.Fatal(err)
	}
	scratch := fmt.Sprintf("qc_it_%d", time.Now().UnixNano())
	if err := bootstrap.Exec(ctx, "CREATE DATABASE "+scratch); err != nil {
		t.Fatalf("cannot reach test ClickHouse: %v", err)
	}
	t.Cleanup(func() {
		_ = bootstrap.Exec(context.Background(), "DROP DATABASE IF EXISTS "+scratch)
		_ = bootstrap.Close()
	})

	// The REAL DDL: m1_ch_001 (events) then m1_ch_002 (rollups), database
	// name rewritten for scratch isolation, nothing else.
	for _, file := range []string{"m1_ch_001_events.sql", "m1_ch_002_rollups.sql"} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "migrations", file))
		if err != nil {
			t.Fatal(err)
		}
		for _, stmt := range splitStatements(string(raw)) {
			stmt = strings.ReplaceAll(stmt, "mark1.", scratch+".")
			stmt = strings.ReplaceAll(stmt, "EXISTS mark1", "EXISTS "+scratch)
			if err := bootstrap.Exec(ctx, stmt); err != nil {
				t.Fatalf("%s statement failed: %v\n%s", file, err, stmt)
			}
		}
	}
	// No test-side ALTER here, deliberately: m1_ch_002 itself now sets
	// non_replicated_deduplication_window = 10000 on tvo_tenant_day (the
	// wave-7 lead fix — without it insert_deduplication_token is a NO-OP on
	// a non-replicated MergeTree and ADR-0010 layer 2 is decoration), so the
	// idempotency proof below runs against the MIGRATED setting, proving the
	// migration and not a test-lane patch.

	// The runner's principals, SQL-provisioned per scratch with the REAL
	// grant shapes (05 §6 / 07: m1p_query SELECT-only, m1p_ingest
	// INSERT-only, the offboarding role ALTER DELETE — the deletion path's
	// own principal), the way the e2e lane provisions m1p_ingest in its
	// users.xml (justfile stores-up). WHY not the superuser: the wave-7
	// skeptic caught the offboard DELETE routed to the INSERT-only principal
	// — ACCESS_DENIED in production, invisible to a suite that connects as
	// `default`. Connecting as the real grants makes any principal/grant
	// mismatch a red test here. The two runtime users carry the async-insert
	// settings per 07's m1p_ingest profile (R3's probe reads them live).
	const itPass = "mark1-it"
	qUser, iUser, oUser := scratch+"_query", scratch+"_ingest", scratch+"_offboard"
	for _, stmt := range []string{
		"CREATE USER " + qUser + " IDENTIFIED WITH plaintext_password BY '" + itPass + "'",
		"CREATE USER " + iUser + " IDENTIFIED WITH plaintext_password BY '" + itPass + "' SETTINGS async_insert = 1, wait_for_async_insert = 1",
		"CREATE USER " + oUser + " IDENTIFIED WITH plaintext_password BY '" + itPass + "'",
		"GRANT SELECT ON " + scratch + ".* TO " + qUser,
		// INSERT + SELECT, not INSERT alone: pushing an m1p_events insert
		// through the m1_ch_002 MVs requires SELECT on the source columns —
		// the exact grant shape the e2e lane's users.d gives m1p_ingest
		// ("GRANT INSERT, SELECT ON mark1.*", m1p-users.xml).
		"GRANT INSERT, SELECT ON " + scratch + ".* TO " + iUser,
		"GRANT SELECT, ALTER DELETE ON " + scratch + ".* TO " + oUser,
	} {
		if err := bootstrap.Exec(ctx, stmt); err != nil {
			t.Fatalf("principal provisioning: %v\n%s", err, stmt)
		}
	}
	t.Cleanup(func() {
		_ = bootstrap.Exec(context.Background(),
			"DROP USER IF EXISTS "+qUser+", "+iUser+", "+oUser)
	})

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
	offboard, err := chconn.OpenOffboard(ctx, chconn.Options{Addr: addr, Database: scratch, Username: oUser, Password: itPass})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = offboard.Close() })

	scoped, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{addr},
		Auth: clickhouse.Auth{Database: scratch, Username: user, Password: pass},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = scoped.Close() })

	return &itRig{
		scratch: scratch,
		boot:    scoped,
		runner:  NewRunner(read, write, offboard),
		ingest:  write,
	}
}

func mustTenant(t *testing.T, id uuid.UUID) TenantID {
	t.Helper()
	tid, err := FromClaims(auth.Claims{TenantID: id, DeviceID: uuid.New()})
	if err != nil {
		t.Fatal(err)
	}
	return tid
}

// seed lands a FULL-SURFACE dataset for one tenant through the same chconn
// insert path production uses: Usage (billing class), Dropped (billing_grade
// loss), a GuardDecision arrest and a certified verdict on a task, plus a
// tvo_tenant_day rollup row via the REAL ADR-0010 write template (no MV
// feeds that table). WHY every shape: the wave-7 skeptic caught the tenancy
// negative passing VACUOUSLY — with only Usage/Dropped rows, 6 of 8 read
// templates returned zero rows for BOTH tenants and the marker grep proved
// nothing (the decorative-control class). Every event family some read
// template filters on is seeded, and the sweep test refuses zero-row
// results for the seeded tenant before trusting the leak grep. seedEventRows
// counts the m1p_events rows this writes (the offboard test's ledger math).
// Returns the task every task-grain template keys on.
const seedEventRows = 14

// seedExcerptTaskID is shared by every tenant so evidence_excerpts' tenancy negative is a real key match.
var seedExcerptTaskID = uuid.MustParse("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")

// The E1 row's redaction_receipt_id (32 bytes) and evidence_event_id (16 bytes) as protojson lands bytes.
const (
	seedExcerptReceiptB64 = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="
	seedExcerptSubjectB64 = "AAECAwQFBgcICQoLDA0ODw=="
)

// seedArtifactID is the artifact `task` receives (MemoryInjection) and closes
// on (ArtifactOutcome) — the same id for every tenant, so artifact_outcomes'
// tenancy negative is a real join and not a disjoint key.
var seedArtifactID = uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")

// seedNoiseCertID rides the certified verdict (gold_vs_verdict / corpus read it back).
var seedNoiseCertID = uuid.MustParse("55555555-5555-4555-8555-555555555555")

func seed(t *testing.T, rig *itRig, conn *chconn.Conn, tenant, session uuid.UUID, tokens, droppedQty uint64) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	at := time.Date(2026, 8, 28, 10, 0, 0, 0, time.UTC)
	device := uuid.New()
	task := uuid.New()
	// cost_basis rides every row as chproj's Stamper lands it (quota, so artifact_outcomes below stays token-costed).
	usageCols := []string{
		"tenant_id", "occurred_at", "session_id", "event_id", "seq", "session_epoch",
		"device_id", "event_type", "event_class", "agent", "input_tokens", "output_tokens", "cost_basis",
	}
	if err := conn.InsertRows(ctx, "m1p_events", usageCols, [][]any{
		{tenant, at, session, uuid.Must(uuid.NewV7()), uint64(1), uint32(1),
			device, "Usage", "billing", "claudecode", tokens, uint64(1), "quota"},
	}); err != nil {
		t.Fatalf("seed usage: %v", err)
	}
	dropCols := append(usageCols, "dropped_reason", "dropped_durability_class", "dropped_quantity")
	if err := conn.InsertRows(ctx, "m1p_events", dropCols, [][]any{
		{tenant, at, session, uuid.Must(uuid.NewV7()), uint64(2), uint32(1),
			device, "Dropped", "diagnostic", "claudecode", uint64(0), uint64(0), "quota",
			"spool_shed", "billing_grade", droppedQty},
	}); err != nil {
		t.Fatalf("seed dropped: %v", err)
	}
	// The knee-arrest evidence `interventions` and `canary_gate_block_rate`
	// filter on: a GuardDecision with a real task_id, payload and bundle_seq.
	guardCols := append(usageCols, "task_id", "payload", "bundle_seq")
	if err := conn.InsertRows(ctx, "m1p_events", guardCols, [][]any{
		{tenant, at, session, uuid.Must(uuid.NewV7()), uint64(3), uint32(1),
			device, "GuardDecision", "route", "claudecode", uint64(0), uint64(0), "quota",
			task, `{"outcome":"GUARD_OUTCOME_ARRESTED","reason_code":"knee_arrest","tokens_saved_estimate":1200,"attempt":3}`, uint64(483)},
	}); err != nil {
		t.Fatalf("seed guard decision: %v", err)
	}
	// The stage-final verdict `interventions` and `canary_fused_violated_rate`
	// key on.
	verdictCols := append(usageCols, "task_id", "verdict", "verdict_stage",
		"p_satisfied", "p_violated", "p_refused", "p_error", "noise_cert_id")
	if err := conn.InsertRows(ctx, "m1p_events", verdictCols, [][]any{
		{tenant, at, session, uuid.Must(uuid.NewV7()), uint64(4), uint32(1),
			device, "VerdictEvent", "verdict", "claudecode", uint64(0), uint64(0), "quota",
			task, "satisfied", "certified",
			float32(0.9), float32(0.05), float32(0.03), float32(0.02), seedNoiseCertID},
	}); err != nil {
		t.Fatalf("seed verdict: %v", err)
	}
	// The intelligence consumers' rows (templates_test.go
	// TestIntelReadTemplatesServeTheirConsumers): TaskOpen carrying the
	// digests, a RouteDecision followed by the Usage that served it (the C9
	// confirmation join), and the AnchorVote/JudgeVote pair per task.
	taskCols := append(usageCols, "task_id", "payload")
	if err := conn.InsertRows(ctx, "m1p_events", taskCols, [][]any{
		{tenant, at, session, uuid.Must(uuid.NewV7()), uint64(5), uint32(1),
			device, "TaskOpen", "diagnostic", "claudecode", uint64(0), uint64(0), "quota",
			task, `{"task_seg_version":"task_seg.v1","task_class":"*","prompt_digest":"` + seedPromptDigestB64 + `"}`},
		{tenant, at, session, uuid.Must(uuid.NewV7()), uint64(8), uint32(1),
			device, "AnchorVote", "diagnostic", "claudecode", uint64(0), uint64(0), "quota",
			task, `{"anchor_id":"ruff@1","vote":"VERDICT_SATISFIED","integrity":{"tamper":false}}`},
		{tenant, at, session, uuid.Must(uuid.NewV7()), uint64(9), uint32(1),
			device, "JudgeVote", "diagnostic", "claudecode", uint64(0), uint64(0), "quota",
			task, `{"judge_id":"judge:rubric@2","vote":"VERDICT_VIOLATED"}`},
	}); err != nil {
		t.Fatalf("seed task rows: %v", err)
	}
	// The E1 excerpt evidence_excerpts serves and the E2 excerpt it must never serve (FR-VERIFY-016).
	if err := conn.InsertRows(ctx, "m1p_events", taskCols, [][]any{
		{tenant, at, session, uuid.Must(uuid.NewV7()), uint64(13), uint32(1),
			device, "EvidenceExcerpt", "diagnostic", "claudecode", uint64(0), uint64(0), "quota",
			seedExcerptTaskID, `{"tier":"EVIDENCE_TIER_E1","evidence_event_id":"` + seedExcerptSubjectB64 + `","attachment_name":"attach.` + tenant.String() + `.e1","redaction_receipt_id":"` + seedExcerptReceiptB64 + `"}`},
		{tenant, at, session, uuid.Must(uuid.NewV7()), uint64(14), uint32(1),
			device, "EvidenceExcerpt", "diagnostic", "claudecode", uint64(0), uint64(0), "quota",
			seedExcerptTaskID, `{"tier":"EVIDENCE_TIER_E2","attachment_name":"attach.` + tenant.String() + `.e2"}`},
	}); err != nil {
		t.Fatalf("seed excerpt rows: %v", err)
	}
	routeCols := append(taskCols, "propensity", "fidelity", "bundle_seq")
	if err := conn.InsertRows(ctx, "m1p_events", routeCols, [][]any{
		{tenant, at, session, uuid.Must(uuid.NewV7()), uint64(6), uint32(1),
			device, "RouteDecision", "route", "claudecode", uint64(0), uint64(0), "quota",
			task, `{"action":"mid","candidates":["small","mid"]}`, float64(1), "wire_enforced", uint64(483)},
	}); err != nil {
		t.Fatalf("seed route decision: %v", err)
	}
	servedCols := append(usageCols, "task_id", "model", "cache_read_input_tokens")
	if err := conn.InsertRows(ctx, "m1p_events", servedCols, [][]any{
		{tenant, at, session, uuid.Must(uuid.NewV7()), uint64(7), uint32(1),
			device, "Usage", "billing", "claudecode", uint64(0), uint64(0), "quota",
			task, "mid", uint64(300)},
	}); err != nil {
		t.Fatalf("seed served usage: %v", err)
	}
	// The memory join (artifact_outcomes): `task` is delivered seedArtifactID
	// and closes on it — payloads exactly as chproj lands protojson (bytes →
	// base64, enum names) — and a second, un-injected certified task is the
	// control cohort the utility is measured against (zero cost: no Usage row,
	// so dropped_by_tenant_day's billing count and tokens_in stay as asserted).
	artifactB64 := base64.StdEncoding.EncodeToString(seedArtifactID[:])
	control := uuid.New()
	if err := conn.InsertRows(ctx, "m1p_events", taskCols, [][]any{
		{tenant, at, session, uuid.Must(uuid.NewV7()), uint64(10), uint32(1),
			device, "MemoryInjection", "diagnostic", "claudecode", uint64(0), uint64(0), "quota",
			task, `{"artifact_ids":["` + artifactB64 + `"],"channel":"INJECTION_CHANNEL_HOOK_CONTEXT","tokens_used":12}`},
		{tenant, at, session, uuid.Must(uuid.NewV7()), uint64(11), uint32(1),
			device, "ArtifactOutcome", "diagnostic", "claudecode", uint64(0), uint64(0), "quota",
			task, `{"artifact_id":"` + artifactB64 + `","task_verdict":"VERDICT_SATISFIED"}`},
	}); err != nil {
		t.Fatalf("seed memory rows: %v", err)
	}
	if err := conn.InsertRows(ctx, "m1p_events", verdictCols, [][]any{
		{tenant, at, session, uuid.Must(uuid.NewV7()), uint64(12), uint32(1),
			device, "VerdictEvent", "verdict", "claudecode", uint64(0), uint64(0), "quota",
			control, "satisfied", "certified",
			float32(0.8), float32(0.1), float32(0.05), float32(0.05), seedNoiseCertID},
	}); err != nil {
		t.Fatalf("seed control verdict: %v", err)
	}
	// The tenant-day rollup row `tvo_report` and `coverage_band` read —
	// written through the real write carve-out, tenant-bound by BuildWrite.
	reg, err := LoadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	rollup, err := reg.Lookup("tvo_rollup_tenant_day")
	if err != nil {
		t.Fatal(err)
	}
	q, err := BuildWrite(mustTenant(t, tenant), rollup, "seed|"+tenant.String(), Params{
		"day":                  "2026-08-28",
		"series":               "task_seg.v1",
		"tokens_total":         tokens,
		"cost_usd":             "1.0",
		"tasks_verified":       []uuid.UUID{task},
		"tasks_unresolved":     []uuid.UUID{},
		"retry_loop_tokens":    uint64(0),
		"reexploration_tokens": uint64(0),
		"over_model_tokens":    uint64(0),
		"observed_ms":          uint64(90),
		"bypass_ms":            uint64(10),
		"disabled_ms":          uint64(0),
		"dropped_billing":      droppedQty,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rig.runner.Run(ctx, q); err != nil {
		t.Fatalf("seed rollup row: %v", err)
	}
	return task
}

// Claim 1 — the live tenancy negative, over EVERY read template.
func TestIntegrationReadTemplatesReturnOnlyCallingTenant(t *testing.T) {
	rig := setupQC(t)
	ctx := context.Background()
	// Seeding rides the INSERT-only principal (the chproj path), not the
	// superuser — item of the same lesson as the runner principals below.
	conn := rig.ingest

	tenantA, tenantB := uuid.New(), uuid.New()
	sessionA, sessionB := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	seed(t, rig, conn, tenantA, sessionA, 100, 5)
	seed(t, rig, conn, tenantB, sessionB, 987_654, 7)

	reg, err := LoadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	tidA := mustTenant(t, tenantA)

	// Exactness on the session grain: tenant A sees exactly its one session.
	usage, _ := reg.Lookup("usage_by_session")
	q, err := Build(tidA, usage, Params{"from": "2026-08-28", "to": "2026-08-28"})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := rig.runner.Run(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows.Rows) != 1 {
		t.Fatalf("tenant A sees %d session rows, want exactly 1: %v", len(rows.Rows), rows.Rows)
	}
	if got := fmt.Sprint(rows.Rows[0]["session_id"]); got != sessionA.String() {
		t.Fatalf("tenant A sees session %s, want %s", got, sessionA)
	}
	if got := rows.Rows[0]["tokens_in"]; asU64(got) != 100 {
		t.Fatalf("tenant A tokens_in = %v, want 100", got)
	}

	// The shed-accounting read (reader.py coverage_inputs' contract): A's
	// dropped 5 (billing_grade) against A's 2 ingested billing rows — never
	// B's 7.
	dropped, _ := reg.Lookup("dropped_by_tenant_day")
	q, err = Build(tidA, dropped, Params{"from": "2026-08-28", "to": "2026-08-28"})
	if err != nil {
		t.Fatal(err)
	}
	rows, err = rig.runner.Run(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows.Rows) != 1 || asU64(rows.Rows[0]["dropped_billing"]) != 5 ||
		asU64(rows.Rows[0]["events_billing_ingested"]) != 2 {
		t.Fatalf("tenant A shed accounting: %v", rows.Rows)
	}

	// NON-VACUITY FIRST (the wave-7 lesson: a marker grep over templates
	// that return zero rows for BOTH tenants proves nothing — the
	// decorative-control class): EVERY read template, run AS tenant B over
	// the seeded day, must return at least one row of B's own data. A
	// template this sweep cannot make produce rows is a template whose leak
	// assertion below would pass empty — so that is a FAILURE here, not a
	// silent skip.
	tidB := mustTenant(t, tenantB)
	for name, tpl := range reg.byName {
		if tpl.write {
			continue
		}
		q, err := Build(tidB, Template{t: tpl}, dummyParamsForDay(tpl))
		if err != nil {
			t.Fatalf("template %s: %v", name, err)
		}
		rows, err := rig.runner.Run(ctx, q)
		if err != nil {
			t.Fatalf("template %s failed against live ClickHouse: %v", name, err)
		}
		if len(rows.Rows) == 0 {
			t.Errorf("template %s returned ZERO rows for tenant B's seeded data — the tenancy negative below would pass vacuously; extend seed() for whatever this template filters on", name)
		}
	}

	// EVERY read template executes live as tenant A and leaks no tenant-B
	// marker (session UUID, tenant UUID, or sentinel token count) — the
	// decorative-RLS test generalized over the closed set, so a new template
	// cannot ship without entering this sweep. Armed by the pass above:
	// every one of these templates provably CAN return B's rows.
	for name, tpl := range reg.byName {
		if tpl.write {
			continue
		}
		q, err := Build(tidA, Template{t: tpl}, dummyParamsForDay(tpl))
		if err != nil {
			t.Fatalf("template %s: %v", name, err)
		}
		rows, err := rig.runner.Run(ctx, q)
		if err != nil {
			t.Fatalf("template %s failed against live ClickHouse: %v", name, err)
		}
		dump := fmt.Sprint(rows.Rows)
		for marker, what := range map[string]string{
			sessionB.String(): "tenant B's session id",
			tenantB.String():  "tenant B's tenant id",
			"987654":          "tenant B's sentinel token count",
		} {
			if strings.Contains(dump, marker) {
				t.Errorf("template %s leaked %s: %s", name, what, dump)
			}
		}
	}
}

// dummyParamsForDay is dummyParams pinned to the seeded day so the live
// sweep actually scans the populated range — `to` is the day after, so a
// half-open [from, to) template (tvo_task_window) scans it as well.
func dummyParamsForDay(tpl *template) Params {
	p := Params{}
	for name, spec := range tpl.params {
		switch spec.kind {
		case pDate:
			if name == "to" {
				p[name] = "2026-08-29"
			} else {
				p[name] = "2026-08-28"
			}
		case pDateTime:
			if name == "from" {
				p[name] = "2026-08-28 00:00:00"
			} else {
				p[name] = "2026-08-29 00:00:00"
			}
		case pUUIDArray:
			p[name] = []uuid.UUID{uuid.New()}
		case pUUID:
			p[name] = uuid.New()
			if name == "artifact_id" {
				p[name] = seedArtifactID
			}
			if name == "task_id" {
				p[name] = seedExcerptTaskID
			}
		case pUInt64:
			p[name] = uint64(1)
		case pDecimal:
			p[name] = "1.0"
		case pString:
			p[name] = "task_seg.v1"
		}
	}
	return p
}

// seedPromptDigestB64 is TaskOpen.prompt_digest as protojson lands it (bytes
// → base64); corpus_candidates must hand it back as the hex intel's
// bytes.fromhex reads.
const seedPromptDigestB64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="

// The three intelligence-consumer templates, live: the semantics their
// readers assume (C9 served-model join, certified-only candidates with the
// hex digest, the vote rows' anchor flag and wire verdicts) hold on real
// ClickHouse, and every row is the calling tenant's.
func TestIntegrationIntelTemplatesServeConsumersLive(t *testing.T) {
	rig := setupQC(t)
	ctx := context.Background()
	tenantA, tenantB := uuid.New(), uuid.New()
	sessionA := uuid.Must(uuid.NewV7())
	taskA := seed(t, rig, rig.ingest, tenantA, sessionA, 100, 5)
	seed(t, rig, rig.ingest, tenantB, uuid.Must(uuid.NewV7()), 987_654, 7)
	reg, err := LoadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	run := func(name string, extra ...Params) []map[string]any {
		t.Helper()
		tpl, err := reg.Lookup(name)
		if err != nil {
			t.Fatal(err)
		}
		params := Params{"from": "2026-08-28", "to": "2026-08-28"}
		for _, e := range extra {
			for k, v := range e {
				params[k] = v
			}
		}
		q, err := Build(mustTenant(t, tenantA), tpl, params)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := rig.runner.Run(ctx, q)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(rows.Rows) == 0 || strings.Contains(fmt.Sprint(rows.Rows), tenantB.String()) {
			t.Fatalf("%s: %v", name, rows.Rows)
		}
		return rows.Rows
	}
	ope := run("ope_route_decisions")
	if len(ope) != 1 || fmt.Sprint(ope[0]["served_model"]) != "mid" || fmt.Sprint(ope[0]["action"]) != "mid" ||
		fmt.Sprint(ope[0]["verdict"]) != "satisfied" || fmt.Sprint(ope[0]["verdict_stage"]) != "certified" ||
		fmt.Sprint(ope[0]["session_id"]) != sessionA.String() {
		t.Fatalf("ope_route_decisions: %v", ope)
	}
	if conf, ok := ope[0]["label_confidence"].(*float32); !ok || conf == nil {
		t.Fatalf("ope_route_decisions: certified decision must carry a non-NULL label_confidence: %#v", ope[0]["label_confidence"])
	}
	// Two certified tasks (taskA + the un-injected control) are candidates; the
	// digest/route/model semantics are asserted on taskA's row.
	corpus := byTask(run("corpus_candidates"), taskA)
	if corpus == nil || fmt.Sprint(corpus["prompt_digest"]) != "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F" ||
		fmt.Sprint(corpus["task_seg_version"]) != "task_seg.v1" || asU64(corpus["attempts"]) != 1 ||
		fmt.Sprint(corpus["model"]) != "mid" || fmt.Sprint(corpus["tamper"]) != "0" ||
		fmt.Sprint(corpus["fidelity"]) == "<nil>" {
		t.Fatalf("corpus_candidates: %v", corpus)
	}
	excerpts := run("evidence_excerpts", Params{"task_id": seedExcerptTaskID})
	if len(excerpts) != 1 || fmt.Sprint(excerpts[0]["redaction_receipt_id"]) != seedExcerptReceiptB64 ||
		fmt.Sprint(excerpts[0]["attachment_name"]) != "attach."+tenantA.String()+".e1" ||
		fmt.Sprint(excerpts[0]["evidence_event_id"]) != seedExcerptSubjectB64 {
		t.Fatalf("evidence_excerpts: want tenant A's one E1 row and never the E2 row: %v", excerpts)
	}
	votes := run("adjudication_votes")
	got := map[string]string{}
	for _, r := range votes {
		got[fmt.Sprint(r["verifier_id"])] = fmt.Sprint(r["vote"], "/", r["is_anchor"], "/", r["stage"])
	}
	if len(votes) != 2 || got["ruff@1"] != "satisfied/1/certified" || got["judge:rubric@2"] != "violated/0/certified" {
		t.Fatalf("adjudication_votes: %v", votes)
	}

	// Batch 2. policy_compiler_attempts over the half-open day: taskA's one
	// attempt (its certified verdict at seq 4, the tail folded in) carries the
	// served model, the split token classes, the stamped basis and the TaskOpen's task_class.
	attempt := byTask(run("policy_compiler_attempts", Params{"to": "2026-08-29"}), taskA)
	if attempt == nil || asU64(attempt["attempt_n"]) != 1 || fmt.Sprint(attempt["model_id"]) != "mid" ||
		fmt.Sprint(attempt["fused_verdict"]) != "satisfied" || fmt.Sprint(attempt["verdict_stage"]) != "certified" ||
		asU64(attempt["cache_read_tokens"]) != 300 || asU64(attempt["input_tokens"]) != 0 ||
		fmt.Sprint(attempt["cost_basis"]) != "quota" || fmt.Sprint(attempt["task_class"]) != "*" {
		t.Fatalf("policy_compiler_attempts: %v", attempt)
	}
	// artifact_outcomes: exactly taskA for the seeded artifact — delivered AND
	// closed — costed at its 300 cache-read tokens against a zero-cost control
	// (TVO_control 0 ⇒ utility −300); a different artifact has no sample.
	outcomes := run("artifact_outcomes", Params{"to": "2026-08-29", "artifact_id": seedArtifactID})
	if len(outcomes) != 1 || fmt.Sprint(outcomes[0]["task_id"]) != taskA.String() ||
		fmt.Sprint(outcomes[0]["verdict"]) != "satisfied" || fmt.Sprint(outcomes[0]["verdict_stage"]) != "certified" ||
		fmt.Sprint(outcomes[0]["noise_cert_id"]) != seedNoiseCertID.String() ||
		fmt.Sprint(outcomes[0]["task_cost"]) != "300" || fmt.Sprint(outcomes[0]["utility"]) != "-300" {
		t.Fatalf("artifact_outcomes: %v", outcomes)
	}
	other, err := Build(mustTenant(t, tenantA), must(reg.Lookup("artifact_outcomes")),
		Params{"from": "2026-08-28", "to": "2026-08-29", "artifact_id": uuid.New()})
	if err != nil {
		t.Fatal(err)
	}
	if rows, err := rig.runner.Run(ctx, other); err != nil || len(rows.Rows) != 0 {
		t.Fatalf("artifact_outcomes for an undelivered artifact: %v %v", rows, err)
	}
	// gold_vs_verdict: both certified tasks, taskA's row carrying the posterior,
	// cert and session the adjudicator's digest join needs.
	gold := byTask(run("gold_vs_verdict"), taskA)
	if gold == nil || fmt.Sprint(gold["fused_verdict"]) != "satisfied" || fmt.Sprint(gold["verdict_stage"]) != "certified" ||
		fmt.Sprint(gold["session_id"]) != sessionA.String() || fmt.Sprint(gold["noise_cert_id"]) != seedNoiseCertID.String() ||
		fmt.Sprint(gold["p_satisfied"]) != "0.9" {
		t.Fatalf("gold_vs_verdict: %v", gold)
	}

	// Batch 3. memory_certified_sessions over the half-open day: taskA with its
	// certified verdict, cert and untampered anchor, and its nine ledger rows
	// as (digest, kind, payload) in (session_epoch, seq) order — digest is the
	// event_id the receipt chain leafs on, never a transcript.
	sessions := run("memory_certified_sessions", Params{"to": "2026-08-29"})
	mem := byTask(sessions, taskA)
	if mem == nil || fmt.Sprint(mem["verdict"]) != "satisfied" || fmt.Sprint(mem["verdict_stage"]) != "certified" ||
		fmt.Sprint(mem["noise_cert_id"]) != seedNoiseCertID.String() || fmt.Sprint(mem["session_id"]) != sessionA.String() ||
		fmt.Sprint(mem["tamper"]) != "0" {
		t.Fatalf("memory_certified_sessions: %v", mem)
	}
	events, ok := mem["events"].([]map[string]any)
	if !ok || len(events) != 9 {
		t.Fatalf("memory_certified_sessions events: %T %v", mem["events"], mem["events"])
	}
	var kinds []string
	for _, ev := range events {
		if _, err := uuid.Parse(fmt.Sprint(ev["digest"])); err != nil {
			t.Fatalf("event digest is not the event_id: %v", ev)
		}
		kinds = append(kinds, fmt.Sprint(ev["kind"]))
	}
	if strings.Join(kinds, ",") != "GuardDecision,VerdictEvent,TaskOpen,RouteDecision,Usage,AnchorVote,JudgeVote,MemoryInjection,ArtifactOutcome" {
		t.Fatalf("events out of (session_epoch, seq) order: %v", kinds)
	}
	if !strings.Contains(fmt.Sprint(events[2]["payload"]), `"task_seg_version":"task_seg.v1"`) {
		t.Fatalf("event payload is not the typed remainder: %v", events[2])
	}
}

func byTask(rows []map[string]any, task uuid.UUID) map[string]any {
	for _, r := range rows {
		if fmt.Sprint(r["task_id"]) == task.String() {
			return r
		}
	}
	return nil
}

func must(tpl Template, err error) Template {
	if err != nil {
		panic(err)
	}
	return tpl
}

// Claim 2 — ADR-0010 §2.3 idempotency on the live table.
func TestIntegrationRollupWriteIdempotency(t *testing.T) {
	rig := setupQC(t)
	ctx := context.Background()

	reg, err := LoadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	tenant := uuid.New()
	tid := mustTenant(t, tenant)
	rollup, _ := reg.Lookup("tvo_rollup_tenant_day")

	verified := []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}
	params := Params{
		"day":                  "2026-08-28",
		"series":               "task_seg.v1",
		"tokens_total":         uint64(300),
		"cost_usd":             "12.5",
		"tasks_verified":       verified,
		"tasks_unresolved":     []uuid.UUID{},
		"retry_loop_tokens":    uint64(10),
		"reexploration_tokens": uint64(20),
		"over_model_tokens":    uint64(30),
		"observed_ms":          uint64(90),
		"bypass_ms":            uint64(10),
		"disabled_ms":          uint64(0),
		"dropped_billing":      uint64(0),
	}
	const jobKey = "tvo.rollup_tenant_day|2026-08-28|series=task_seg.v1"

	assertState := func(wantRows, wantTokens, wantVerified uint64, when string) {
		t.Helper()
		var rows, tokens, ver uint64
		if err := rig.boot.QueryRow(ctx,
			"SELECT count(), sumMerge(tokens_total), uniqExactMerge(tasks_verified) FROM tvo_tenant_day",
		).Scan(&rows, &tokens, &ver); err != nil {
			t.Fatal(err)
		}
		if rows != wantRows || tokens != wantTokens || ver != wantVerified {
			t.Fatalf("%s: rows=%d tokens=%d verified=%d, want %d/%d/%d",
				when, rows, tokens, ver, wantRows, wantTokens, wantVerified)
		}
	}

	// First write: one row, TVO = 300/3 = 100.
	q, err := BuildWrite(tid, rollup, jobKey, params)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rig.runner.Run(ctx, q); err != nil {
		t.Fatal(err)
	}
	assertState(1, 300, 3, "after first write")

	// Same job_key re-run: dropped by the dedup token (ADR-0010 §2.3 layer
	// 2) — the AggregatingMergeTree would otherwise merge ADDITIVELY and
	// report TVO 200 with no error.
	if _, err := rig.runner.Run(ctx, q); err != nil {
		t.Fatal(err)
	}
	assertState(1, 300, 3, "after same-job_key re-run")

	// Same job_key, DIFFERENT bytes (a retry that re-read a source which
	// gained a late row): still dropped — identity is pinned to the JOB,
	// not to what the job happened to read (ADR-0010 §2.4 row 2).
	late := clone(params)
	late["tokens_total"] = uint64(999)
	q2, err := BuildWrite(tid, rollup, jobKey, late)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rig.runner.Run(ctx, q2); err != nil {
		t.Fatal(err)
	}
	assertState(1, 300, 3, "after same-job_key different-bytes retry")

	// A restatement is a NEW series under a NEW job_key (ADR-0010 §2.6):
	// lands beside the original, never on top of it.
	restated := clone(params)
	restated["series"] = "task_seg.v1-restated.2"
	restated["tokens_total"] = uint64(250)
	q3, err := BuildWrite(tid, rollup, jobKey+"|series=task_seg.v1-restated.2", restated)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rig.runner.Run(ctx, q3); err != nil {
		t.Fatal(err)
	}
	var rows uint64
	if err := rig.boot.QueryRow(ctx,
		"SELECT count() FROM tvo_tenant_day WHERE tenant_id = ?", tenant.String(),
	).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 2 {
		t.Fatalf("restated series: %d rows, want 2 (original + restatement)", rows)
	}

	// The report read sees both series as distinct rows for the day.
	report, _ := reg.Lookup("tvo_report")
	rq, err := Build(tid, report, Params{"from": "2026-08-28", "to": "2026-08-28"})
	if err != nil {
		t.Fatal(err)
	}
	out, err := rig.runner.Run(ctx, rq)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Rows) != 2 {
		t.Fatalf("tvo_report rows: %v", out.Rows)
	}
}

// The second write carve-out, live: offboard_delete_tenant removes exactly
// the named tenant's ledger rows.
func TestIntegrationOffboardDeleteIsTenantScoped(t *testing.T) {
	rig := setupQC(t)
	ctx := context.Background()
	conn := rig.ingest

	tenantA, tenantB := uuid.New(), uuid.New()
	seed(t, rig, conn, tenantA, uuid.Must(uuid.NewV7()), 100, 1)
	seed(t, rig, conn, tenantB, uuid.Must(uuid.NewV7()), 200, 1)

	reg, err := LoadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	offboard, _ := reg.Lookup("offboard_delete_tenant")
	q, err := BuildWrite(mustTenant(t, tenantB), offboard, "offboard|"+tenantB.String(), Params{})
	if err != nil {
		t.Fatal(err)
	}
	// The wave-7 defect, pinned as a live negative: the INSERT-only ingest
	// principal must REFUSE this DELETE (no ALTER DELETE grant). If this ever
	// succeeds, the grant split is decorative and the principal routing in
	// runner.go is untestable.
	if err := rig.ingest.ExecTemplateWrite(ctx, q.SQL(), q.Bind(), q.JobKey()); err == nil {
		t.Fatal("INSERT-only principal executed a DELETE — the offboarding grant split is decorative")
	}
	if _, err := rig.runner.Run(ctx, q); err != nil {
		t.Fatal(err)
	}

	count := func(tenant uuid.UUID) uint64 {
		var n uint64
		if err := rig.boot.QueryRow(ctx,
			"SELECT count() FROM m1p_events WHERE tenant_id = ?", tenant.String(),
		).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := count(tenantB); n != 0 {
		t.Fatalf("offboarded tenant still has %d ledger rows", n)
	}
	if n := count(tenantA); n != seedEventRows {
		t.Fatalf("offboarding tenant B touched tenant A's rows: %d left, want %d", n, seedEventRows)
	}
}
