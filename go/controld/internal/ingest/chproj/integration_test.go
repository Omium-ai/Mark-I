//go:build integration

package chproj

// DSN-gated ClickHouse integration: a scratch database gets the REAL
// migrations/m1_ch_*.sql DDL (database name rewritten, nothing else), chconn
// opens against it with the R3 async-insert assertion live, and the tests
// prove the projection lands, that a §2.5 replay collapses to the same
// reader-facing rows under the 07 dedupe discipline (LIMIT 1 BY event_id),
// and that the schema the server actually built is the one ADR-0001 fixed.
//
// This file may speak SELECT because it lives under internal/ingest/chproj —
// one of the two depguard-sanctioned ClickHouse dirs (13 §7.3); production
// chproj code still has no SELECT surface.
//
// Gate: M1_TEST_CH_DSN — the ONE store-contract var (justfile / 12 §11.4),
// which the repo defines as the HTTP interface URL (e.g.
// http://127.0.0.1:8123/?database=default); a native-protocol endpoint
// (clickhouse://default:pass@127.0.0.1:9000) is also accepted for lanes where
// the native port is not the server-reported one. Absent ⇒ skip, unless
// M1_REQUIRE_STORES=1 ⇒ fail.

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/pg"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke/chconn"
	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

// chEndpoint resolves M1_TEST_CH_DSN to the NATIVE endpoint chconn speaks.
// The contract var is defined ONCE, as the HTTP URL (justfile, 12 §11.4), so
// an http(s) DSN is resolved by asking the server for its own tcp_port —
// sound in the sanctioned lane, which runs the stores as native binaries on
// the runner with no port remapping (12 §11.4: "no Docker required").
// ponytail: a container lane that remaps the native port makes tcp_port
// unresolvable from an HTTP DSN — point M1_TEST_CH_DSN at the native endpoint
// directly (clickhouse://user:pass@host:port) there.
func chEndpoint(t *testing.T) (addr, user, pass string) {
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
		return nativeAddrOverHTTP(t, u, user, pass), user, pass
	default:
		t.Fatalf("M1_TEST_CH_DSN scheme %q: want http(s) (12 §11.4 lane) or clickhouse (native)", u.Scheme)
		return "", "", ""
	}
}

// nativeAddrOverHTTP asks the HTTP interface for the server's native port and
// pairs it with the DSN's own host.
func nativeAddrOverHTTP(t *testing.T, u *url.URL, user, pass string) string {
	t.Helper()
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
		t.Fatalf("tcp_port probe over M1_TEST_CH_DSN: status %d: %s", resp.StatusCode, body)
	}
	return net.JoinHostPort(u.Hostname(), strings.TrimSpace(string(body)))
}

func setupCH(t *testing.T) (*chconn.Conn, driver.Conn, string) {
	t.Helper()
	ctx := context.Background()
	addr, user, pass := chEndpoint(t)

	bootstrap, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{addr},
		Auth: clickhouse.Auth{Database: "default", Username: user, Password: pass},
	})
	if err != nil {
		t.Fatal(err)
	}
	scratch := fmt.Sprintf("c4_mark1_it_%d", time.Now().UnixNano())
	if err := bootstrap.Exec(ctx, "CREATE DATABASE "+scratch); err != nil {
		t.Fatalf("cannot reach test ClickHouse: %v", err)
	}
	t.Cleanup(func() {
		_ = bootstrap.Exec(context.Background(), "DROP DATABASE IF EXISTS "+scratch)
		_ = bootstrap.Close()
	})

	// The real DDL, every m1_ch_*.sql in order, database name rewritten for scratch isolation.
	files, err := filepath.Glob(filepath.Join("..", "..", "..", "..", "..", "migrations", "m1_ch_*.sql"))
	if err != nil || len(files) == 0 {
		t.Fatalf("ClickHouse migrations not found: %v", err)
	}
	sort.Strings(files)
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, stmt := range splitCHStatements(string(raw)) {
			stmt = strings.ReplaceAll(stmt, "mark1.", scratch+".")
			stmt = strings.ReplaceAll(stmt, "EXISTS mark1", "EXISTS "+scratch)
			if err := bootstrap.Exec(ctx, stmt); err != nil {
				t.Fatalf("%s statement failed: %v\n%s", filepath.Base(f), err, stmt)
			}
		}
	}

	// chconn.Open runs the R3 assertion (async_insert=1 +
	// wait_for_async_insert=1, effective on this connection) as at boot.
	conn, err := chconn.Open(ctx, chconn.Options{Addr: addr, Database: scratch, Username: user, Password: pass})
	if err != nil {
		t.Fatalf("chconn.Open (R3): %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	query, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{addr},
		Auth: clickhouse.Auth{Database: scratch, Username: user, Password: pass},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = query.Close() })
	return conn, query, scratch
}

// splitCHStatements strips comments and splits on ';' — sufficient for the
// migration's two statements (no string literal in the file contains either).
func splitCHStatements(sql string) []string {
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

func TestIntegrationProjectAndReplayDedupe(t *testing.T) {
	conn, query, _ := setupCH(t)
	ctx := context.Background()

	tenant, device := uuid.New(), uuid.New()
	batchID, session := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	usageID := uuid.Must(uuid.NewV7())
	verdictID := uuid.Must(uuid.NewV7())
	at := time.Date(2026, 8, 29, 10, 0, 0, 0, time.UTC)
	idem := make([]byte, 32)
	idem[31] = 0x01

	batch := &m1pv1.Batch{
		BatchId:   batchID[:],
		SessionId: session[:],
		Sdk:       &m1pv1.SdkInfo{Agent: "claudecode"},
		SentAt:    timestamppb.New(at),
		Events: []*m1pv1.Event{
			{
				EventId: usageID[:], Seq: 41, SessionId: session[:], OccurredAt: timestamppb.New(at),
				Body: &m1pv1.Event_Usage{Usage: &m1pv1.Usage{
					IdemKey: idem, Model: "claude-test-1",
					InputTokens: 2113, OutputTokens: 388, CacheReadInputTokens: 19244,
				}},
			},
			{
				EventId: verdictID[:], Seq: 42, SessionId: session[:], OccurredAt: timestamppb.New(at),
				Body: &m1pv1.Event_VerdictEvent{VerdictEvent: &m1pv1.VerdictEvent{
					Stage:     m1pv1.VerdictStage_VERDICT_STAGE_PROVISIONAL,
					Verdict:   m1pv1.Verdict_VERDICT_SATISFIED,
					Posterior: []float64{0.86, 0.09, 0.03, 0.02},
				}},
			},
		},
		Dropped: []*m1pv1.Dropped{{
			Reason: m1pv1.DropReason_DROP_REASON_SPOOL_SHED, Quantity: 17,
			DurabilityClass: m1pv1.DurabilityClass_DURABILITY_CLASS_DIAGNOSTIC,
		}},
	}

	rows := RowsFromBatch(batch, tenant, device, at)
	if err := conn.InsertRows(ctx, Table, Columns, rows); err != nil {
		t.Fatalf("projection insert: %v", err)
	}
	// §2.5 replay: same batch, re-projected — wait_for_async_insert=1 means
	// both inserts are durably in parts when these calls return.
	if err := conn.InsertRows(ctx, Table, Columns, RowsFromBatch(batch, tenant, device, at)); err != nil {
		t.Fatalf("replay insert: %v", err)
	}

	// Reader discipline (m1_ch_001 footer): dedupe is EVENTUAL, so readers
	// use LIMIT 1 BY event_id — replay must collapse to the original 3 rows.
	var deduped uint64
	if err := query.QueryRow(ctx, fmt.Sprintf(
		`SELECT count() FROM (SELECT event_id FROM %s WHERE tenant_id = $1 LIMIT 1 BY event_id)`, Table),
		tenant).Scan(&deduped); err != nil {
		t.Fatal(err)
	}
	if deduped != 3 {
		t.Fatalf("replayed batch changed the ledger: want 3 deduped rows, got %d", deduped)
	}

	var (
		gotType, gotClass, gotModel string
		gotIn, gotCacheRead         uint64
	)
	if err := query.QueryRow(ctx, fmt.Sprintf(
		`SELECT event_type, event_class, model, input_tokens, cache_read_input_tokens
		   FROM %s WHERE tenant_id = $1 AND event_id = $2 LIMIT 1 BY event_id`, Table),
		tenant, usageID).Scan(&gotType, &gotClass, &gotModel, &gotIn, &gotCacheRead); err != nil {
		t.Fatal(err)
	}
	if gotType != "Usage" || gotClass != "billing" || gotModel != "claude-test-1" ||
		gotIn != 2113 || gotCacheRead != 19244 {
		t.Fatalf("usage row mismatch: %s %s %s %d %d", gotType, gotClass, gotModel, gotIn, gotCacheRead)
	}

	var gotVerdict, gotStage string
	var pSat float32
	if err := query.QueryRow(ctx, fmt.Sprintf(
		`SELECT verdict, verdict_stage, p_satisfied FROM %s WHERE tenant_id = $1 AND event_id = $2 LIMIT 1 BY event_id`, Table),
		tenant, verdictID).Scan(&gotVerdict, &gotStage, &pSat); err != nil {
		t.Fatal(err)
	}
	if gotVerdict != "satisfied" || gotStage != "provisional" || pSat != 0.86 {
		t.Fatalf("verdict row mismatch: %s %s %f", gotVerdict, gotStage, pSat)
	}

	// The Dropped{} loss-ledger row (07 MV predicate: event_type='Dropped').
	var qty uint64
	var class string
	if err := query.QueryRow(ctx, fmt.Sprintf(
		`SELECT dropped_quantity, dropped_durability_class FROM %s
		  WHERE tenant_id = $1 AND event_type = 'Dropped' LIMIT 1 BY event_id`, Table),
		tenant).Scan(&qty, &class); err != nil {
		t.Fatal(err)
	}
	if qty != 17 || class != "diagnostic" {
		t.Fatalf("dropped row mismatch: %d %s", qty, class)
	}
}

// FR-SPINE-014 layer 3: the ENGINE's collapse, which nothing above observes.
//
// TestIntegrationProjectAndReplayDedupe counts through `LIMIT 1 BY event_id`.
// That is reader-side dedupe — it would pass byte-identically against a plain
// MergeTree that collapses nothing — so the merge itself is unproven by it, and
// the DDL guard below only reads system.tables and never watches one happen.
//
// The version column is the half that carries the money. m1_ch_001:66-67 makes
// `ingested_at` the ReplacingMergeTree version so the LATEST server ingest wins;
// a wrong one keeps an arbitrary row per key, and the direction that costs is
// exactly m1_ch_001:87's ~2.5x streaming overcount — a first count that a later
// ingest corrects DOWNWARD. So the two ingests here differ only in their token
// count, and the newer one is the smaller: an engine that kept the older row
// (or the larger value) bills the overcount forever, silently.
func TestIntegrationReplacingMergeCollapsesToNewestIngest(t *testing.T) {
	conn, query, _ := setupCH(t)
	ctx := context.Background()

	tenant, device := uuid.New(), uuid.New()
	batchID, session := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	eventID := uuid.Must(uuid.NewV7())
	at := time.Date(2026, 8, 29, 10, 0, 0, 0, time.UTC)
	const overcounted, corrected uint64 = 5000, 2000

	// The engine collapses on the WHOLE ordering key (ADR-0001:
	// tenant_id, toDate(occurred_at), session_id, event_id), not on event_id
	// alone, so every term but the token count is held equal here — which is
	// also what RowsFromBatch's replay determinism (chproj.go:88-94) buys.
	usage := func(in uint64) *m1pv1.Batch {
		return &m1pv1.Batch{
			BatchId: batchID[:], SessionId: session[:],
			Sdk: &m1pv1.SdkInfo{Agent: "claudecode"}, SentAt: timestamppb.New(at),
			Events: []*m1pv1.Event{{
				EventId: eventID[:], Seq: 7, SessionId: session[:], OccurredAt: timestamppb.New(at),
				Body: &m1pv1.Event_Usage{Usage: &m1pv1.Usage{
					Model: "claude-test-1", InputTokens: in, OutputTokens: 11,
				}},
			}},
		}
	}
	for _, in := range []uint64{overcounted, corrected} {
		if err := conn.InsertRows(ctx, Table, Columns, RowsFromBatch(usage(in), tenant, device, at)); err != nil {
			t.Fatalf("insert (input_tokens=%d): %v", in, err)
		}
	}

	// ANTI-VACUITY, before any merge. "One row after OPTIMIZE" is also what a
	// second insert that silently failed produces, and "the newest wins" is a
	// coin flip if the two versions are equal — so both physical rows and two
	// distinct versions have to be shown to exist first. argMax establishes
	// which count IS the newest from the data rather than from the write order.
	var raw, versions, newest uint64
	if err := query.QueryRow(ctx, fmt.Sprintf(
		`SELECT count(), uniqExact(ingested_at), argMax(input_tokens, ingested_at)
		   FROM %s WHERE tenant_id = $1 AND event_id = $2`, Table),
		tenant, eventID).Scan(&raw, &versions, &newest); err != nil {
		t.Fatal(err)
	}
	if raw != 2 {
		t.Fatalf("pre-merge physical rows = %d, want 2 — the collapse below would prove nothing", raw)
	}
	if versions != 2 {
		t.Fatal("both ingests share one ingested_at; ReplacingMergeTree picks arbitrarily between equal " +
			"versions, so this test would be a coin flip rather than an assertion")
	}
	if newest != corrected {
		t.Fatalf("newest ingested_at carries input_tokens=%d, want the corrected %d", newest, corrected)
	}

	// Deterministically, not by waiting: background merges are asynchronous and
	// a sleep here would be a flake with a timeout. optimize_throw_if_noop turns
	// "nothing was merged" into a named error instead of a confusing count.
	if err := query.Exec(ctx, fmt.Sprintf(
		"OPTIMIZE TABLE %s FINAL SETTINGS optimize_throw_if_noop = 1", Table)); err != nil {
		t.Fatalf("OPTIMIZE ... FINAL: %v", err)
	}

	// No LIMIT 1 BY: this counts what is PHYSICALLY on disk, which is the only
	// form that can tell the engine's dedupe apart from the reader's.
	var survivors, tokens uint64
	if err := query.QueryRow(ctx, fmt.Sprintf(
		`SELECT count(), max(input_tokens) FROM %s WHERE tenant_id = $1 AND event_id = $2`, Table),
		tenant, eventID).Scan(&survivors, &tokens); err != nil {
		t.Fatal(err)
	}
	if survivors != 1 {
		t.Fatalf("after OPTIMIZE ... FINAL, %d physical rows survive for one event_id — the engine is not "+
			"collapsing duplicates, so FR-SPINE-014 layer 3 rests entirely on every reader remembering "+
			"LIMIT 1 BY (m1_ch_001 footer)", survivors)
	}
	if tokens != corrected {
		t.Fatalf("the surviving row carries input_tokens=%d, want the newest ingest's %d — the version "+
			"column is not ingested_at, so a corrected token count loses to the one it corrected "+
			"(m1_ch_001:66-67; the ~2.5x overcount at :87 is billed forever)", tokens, corrected)
	}
}

// The R3 refusal negatives live in chconn's own integration suite
// (internal/querychoke/chconn), where the assertion can be exercised against
// effective-0 settings for real instead of asserted by proxy.

// ─── FR-SPINE-013: the guard on the one irreversible decision ──────────────
//
// A MergeTree ORDER BY cannot be altered in place. ADR-0001 exists for exactly
// that reason: every other physical choice in the analytics plane — codecs,
// TTLs, skip indexes, even the partition key — is adjustable after the fact,
// and this one is not (ADR-0001 §Context, §Reversibility: a new table plus a
// full S3 replay, hours at pilot and days plus four-to-five figures at 100×).
// The migrations already ran against a real server above, but nothing read the
// resulting schema back — so a key that shipped as (session_id, event_id), or
// a ReplacingMergeTree quietly demoted to MergeTree, passed every gate green
// and would have surfaced only as unfixable data at a customer. This test
// reads system.tables and compares what the server built, term for term in
// order, against ADR-0001 §Decision.

// chTableShape is the unalterable half of a table's DDL: the engine WITH its
// arguments and the whole ordering key as an ordered tuple. Partition key and
// TTL are deliberately absent — ADR-0001 §Context names both as adjustable
// after the fact, so pinning them here would only manufacture false reds.
type chTableShape struct{ engine, sortingKey string }

// chExpectedShapes is ADR-0001 §Decision transcribed, plus the three rollups'
// (tenant_id, day, …) prefix that ADR-0001 §Consequences requires them to
// share with the base table. The set is diffed against system.tables in BOTH
// directions: a table that vanishes and a table nobody told this test about
// are the same defect, and the second is the one a hardcoded list normally
// lets through six months later.
var chExpectedShapes = map[string]chTableShape{
	"m1p_events": {
		engine:     "ReplacingMergeTree(ingested_at)",
		sortingKey: "tenant_id, toDate(occurred_at), session_id, event_id",
	},
	"tvo_session":    {engine: "AggregatingMergeTree", sortingKey: "tenant_id, day, session_id"},
	"tvo_task":       {engine: "AggregatingMergeTree", sortingKey: "tenant_id, day, task_id"},
	"tvo_tenant_day": {engine: "AggregatingMergeTree", sortingKey: "tenant_id, day, task_seg_version"},
	// The MVs carry no sorting key of their own; they are listed so that the
	// set diff below stays total over the database.
	"mv_tvo_session": {engine: "MaterializedView"},
	"mv_tvo_task":    {engine: "MaterializedView"},
}

func TestIntegrationClickHouseDDLMatchesADR0001(t *testing.T) {
	query, scratch := setupCHSchema(t)
	ctx := context.Background()

	rows, err := query.Query(ctx,
		`SELECT name, engine, engine_full, sorting_key FROM system.tables WHERE database = $1`, scratch)
	if err != nil {
		t.Fatalf("system.tables: %v", err)
	}
	defer func() { _ = rows.Close() }()

	got := make(map[string]chTableShape)
	for rows.Next() {
		var name, engine, engineFull, sortingKey string
		if err := rows.Scan(&name, &engine, &engineFull, &sortingKey); err != nil {
			t.Fatal(err)
		}
		got[name] = chTableShape{
			engine: engineWithArgs(engine, engineFull),
			// Whitespace only. Re-ordering the terms here would erase the very
			// difference the test exists to catch: (tenant_id, toDate, session,
			// event) and (tenant_id, session, event, toDate) hold the same four
			// terms and differ catastrophically.
			sortingKey: strings.Join(strings.Fields(sortingKey), " "),
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	// Positive count first: "every table matched" is also what a read that
	// found no tables at all reports, and a scratch database that silently
	// received no DDL would otherwise pass this test green.
	if len(got) == 0 {
		t.Fatalf("system.tables reports no tables in %s — the migrations did not run, so every assertion below is vacuous", scratch)
	}
	if len(got) != len(chExpectedShapes) {
		t.Errorf("migrations created %d ClickHouse tables, ADR-0001 accounts for %d", len(got), len(chExpectedShapes))
	}

	for name, want := range chExpectedShapes {
		g, ok := got[name]
		if !ok {
			t.Errorf("migrations no longer create %s: ADR-0001 covers it and system.tables does not list it", name)
			continue
		}
		if g.engine != want.engine {
			t.Errorf("%s engine drifted from ADR-0001 §Decision: want %s, got %s", name, want.engine, g.engine)
		}
		if g.sortingKey != want.sortingKey {
			t.Errorf("%s ORDER BY drifted from ADR-0001 §Decision, and ORDER BY IS NOT ALTERABLE IN PLACE:\n"+
				"  want ORDER BY (%s)\n"+
				"  got  ORDER BY (%s)\n"+
				"If the new key is intended, it needs a superseding ADR and the §\"Migration path and cost\" "+
				"sequence (new table → dual-write → S3 replay → parity → cutover), not an edit to this expectation.",
				name, want.sortingKey, g.sortingKey)
		}
	}
	for name, g := range got {
		if _, ok := chExpectedShapes[name]; !ok {
			t.Errorf("ClickHouse table %s exists but no ADR-0001 expectation covers it "+
				"(engine %s, ORDER BY (%s)) — its ordering key is being written unreviewed; "+
				"add it to chExpectedShapes once the ADR accounts for it", name, g.engine, g.sortingKey)
		}
	}
}

// engineWithArgs re-attaches the argument list that system.tables.engine drops.
// FR-SPINE-013 promises "ReplacingMergeTree on event_id" with the newest server
// ingest winning, and that second half is entirely the `(ingested_at)` version
// column: without it the engine keeps an arbitrary row per key, which no amount
// of ordering-key correctness recovers. engine_full is empty for views, hence
// the prefix test rather than a blind split.
func engineWithArgs(engine, engineFull string) string {
	if !strings.HasPrefix(engineFull, engine+"(") {
		return engine
	}
	depth := 0
	for i := len(engine); i < len(engineFull); i++ {
		switch engineFull[i] {
		case '(':
			depth++
		case ')':
			if depth--; depth == 0 {
				return engineFull[:i+1]
			}
		}
	}
	return engineFull // unbalanced: report it verbatim rather than guess
}

// setupCHSchema applies EVERY ClickHouse migration, not just m1_ch_001 as
// setupCH does, and discovers them by glob rather than by name: a migration
// added next month must land in the guard above by existing, not by someone
// remembering to list it here.
func setupCHSchema(t *testing.T) (driver.Conn, string) {
	t.Helper()
	ctx := context.Background()
	addr, user, pass := chEndpoint(t)

	bootstrap, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{addr},
		Auth: clickhouse.Auth{Database: "default", Username: user, Password: pass},
	})
	if err != nil {
		t.Fatal(err)
	}
	scratch := fmt.Sprintf("c4_mark1_ddl_%d", time.Now().UnixNano())
	if err := bootstrap.Exec(ctx, "CREATE DATABASE "+scratch); err != nil {
		t.Fatalf("cannot reach test ClickHouse: %v", err)
	}
	t.Cleanup(func() {
		_ = bootstrap.Exec(context.Background(), "DROP DATABASE IF EXISTS "+scratch)
		_ = bootstrap.Close()
	})

	// Glob returns its matches sorted, which is the migrations' apply order:
	// m1_ch_002's materialized views select FROM the m1_ch_001 base table.
	files, err := filepath.Glob(filepath.Join("..", "..", "..", "..", "..", "migrations", "m1_ch_*.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no migrations/m1_ch_*.sql found — the DDL guard would assert against an empty database")
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, stmt := range splitCHStatements(string(raw)) {
			stmt = strings.ReplaceAll(stmt, "mark1.", scratch+".")
			stmt = strings.ReplaceAll(stmt, "EXISTS mark1", "EXISTS "+scratch)
			if err := bootstrap.Exec(ctx, stmt); err != nil {
				t.Fatalf("%s statement failed: %v\n%s", filepath.Base(f), err, stmt)
			}
		}
	}
	return bootstrap, scratch
}

// Stamped(chconn, PGRegimes.CostBasis) end to end: a real m1_075 row under the tenant GUC lands its basis on every row of the batch, no row lands empty (never usd), and the TaskOpen payload carries task_class under the key policy_compiler_attempts extracts.
func TestIntegrationStampsTenantRegimeBasis(t *testing.T) {
	conn, query, _ := setupCH(t)
	dsn := os.Getenv("M1_TEST_PG_DSN")
	if dsn == "" {
		if os.Getenv("M1_REQUIRE_STORES") == "1" {
			t.Fatal("M1_TEST_PG_DSN required (M1_REQUIRE_STORES=1) but unset")
		}
		t.Skip("M1_TEST_PG_DSN unset; skipping Postgres-backed test")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("cannot reach test Postgres: %v", err)
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	pool, err := pg.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("pg.Open: %v", err)
	}
	t.Cleanup(pool.Close)
	mkTenant := func(basis string) uuid.UUID {
		t.Helper()
		tag := "chproj-it-" + uuid.NewString()[:8]
		tenant := uuid.New()
		err := pgx.BeginFunc(ctx, admin, func(tx pgx.Tx) error {
			var org uuid.UUID
			if err := tx.QueryRow(ctx, `INSERT INTO m1_organizations (name, primary_domain) VALUES ($1, $2) RETURNING id`, tag, tag+".example").Scan(&org); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tenant.String()); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO m1_tenants (id, org_id, name) VALUES ($1, $2, $3)`, tenant, org, tag); err != nil {
				return err
			}
			switch basis {
			case "usd":
				_, err = tx.Exec(ctx, `INSERT INTO m1_tenant_regimes (tenant_id, cost_basis, price_model_id, v_default, set_by)
					VALUES ($1, 'usd', 'claude-sonnet-5', 25, 'chproj-it')`, tenant)
			case "quota":
				_, err = tx.Exec(ctx, `INSERT INTO m1_tenant_regimes (tenant_id, cost_basis, window_limit_tokens, shadow_price_usd, v_default, set_by)
					VALUES ($1, 'quota', 100000, 150, 25, 'chproj-it')`, tenant)
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return tenant
	}
	st := Stamped(conn, querychoke.PGRegimes{DB: pg.NewTenantDB(pool)}.CostBasis)
	at := time.Date(2026, 8, 29, 10, 0, 0, 0, time.UTC)
	session := uuid.Must(uuid.NewV7())
	for tenant, want := range map[uuid.UUID]string{mkTenant("usd"): "usd", mkTenant("quota"): "quota", mkTenant(""): ""} {
		batch := &m1pv1.Batch{
			BatchId: v7b(t), SessionId: session[:], Sdk: &m1pv1.SdkInfo{Agent: "claudecode"}, SentAt: timestamppb.New(at),
			Events: []*m1pv1.Event{
				{EventId: v7b(t), Seq: 1, SessionId: session[:], OccurredAt: timestamppb.New(at),
					Body: &m1pv1.Event_TaskOpen{TaskOpen: &m1pv1.TaskOpen{TaskSegVersion: "task_seg.v1", TaskClass: "*"}}},
				{EventId: v7b(t), Seq: 2, SessionId: session[:], OccurredAt: timestamppb.New(at),
					Body: &m1pv1.Event_Usage{Usage: &m1pv1.Usage{Model: "claude-test-1", InputTokens: 5}}},
			},
			Dropped: []*m1pv1.Dropped{{Reason: m1pv1.DropReason_DROP_REASON_SPOOL_SHED, Quantity: 1}},
		}
		if err := st.InsertRows(ctx, Table, Columns, RowsFromBatch(batch, tenant, uuid.New(), at)); err != nil {
			t.Fatalf("stamped insert: %v", err)
		}
		var basis, taskClass string
		var n uint64
		if err := query.QueryRow(ctx, fmt.Sprintf(
			`SELECT cost_basis, count(), maxIf(JSONExtractString(payload, 'task_class'), event_type = 'TaskOpen')
			   FROM (SELECT * FROM %s WHERE tenant_id = $1 LIMIT 1 BY event_id) GROUP BY cost_basis`, Table),
			tenant).Scan(&basis, &n, &taskClass); err != nil {
			t.Fatal(err)
		}
		if basis != want || n != 3 || taskClass != "*" {
			t.Fatalf("tenant %s: basis %q over %d rows (task_class %q), want %q over 3", tenant, basis, n, taskClass, want)
		}
	}
}
