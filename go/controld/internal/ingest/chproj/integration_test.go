package chproj

// DSN-gated ClickHouse integration: a scratch database gets the REAL
// m1_ch_001_events.sql DDL (database name rewritten, nothing else), chconn
// opens against it with the R3 async-insert assertion live, and the tests
// prove the projection lands and that a §2.5 replay collapses to the same
// reader-facing rows under the 07 dedupe discipline (LIMIT 1 BY event_id).
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
	"strings"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

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
	defer resp.Body.Close()
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

	// The real DDL, database name rewritten for scratch isolation.
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "..", "migrations", "m1_ch_001_events.sql"))
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range splitCHStatements(string(raw)) {
		stmt = strings.ReplaceAll(stmt, "mark1.", scratch+".")
		stmt = strings.ReplaceAll(stmt, "EXISTS mark1", "EXISTS "+scratch)
		if err := bootstrap.Exec(ctx, stmt); err != nil {
			t.Fatalf("m1_ch_001 statement failed: %v\n%s", err, stmt)
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

// The R3 refusal negatives live in chconn's own integration suite
// (internal/querychoke/chconn), where the assertion can be exercised against
// effective-0 settings for real instead of asserted by proxy.
