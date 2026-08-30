// queryconn.go extends the sealed chconn package around the frozen ingest
// handle (chconn.go): the SELECT principal (m1p_query, 07: exactly two
// runtime CH users) and the write-template execution surface the ingest
// principal lends to querychoke's two Build-constructed write templates
// (05 §6.2 carve-outs; ADR-0010 §2). Both surfaces accept raw SQL text —
// which is exactly why they live HERE, inside internal/querychoke/chconn,
// where Go's internal rule plus the depguard clickhouse-choke confinement
// (13 §7.3) keep them reachable only from querychoke itself. querychoke's
// exported API re-seals them: there is no Run(ctx, sql string) above this
// package (05 §6.2 "the escape hatch is absent").
package chconn

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// QueryConn is the read principal's handle (m1p_query in production; scratch
// users in tests). Deliberately a DISTINCT type from Conn: ingest/chproj
// receives *Conn and can therefore never express a SELECT even inside the
// sealed package's import allowance (05 §6: the wiring exception is
// INSERT-shaped, no SELECT surface).
type QueryConn struct {
	ch driver.Conn
}

// OpenQuery connects the SELECT principal. No R3 assertion here: R3's
// subject is the m1p_ingest async-insert profile (05 §1.2); the query
// principal's guard is the server-side readonly profile plus 05 §6.5's
// cost-guard settings, both owned by 07/09 — a client-side re-assertion of a
// read-only profile would only ever read back its own values.
func OpenQuery(ctx context.Context, o Options) (*QueryConn, error) {
	ch, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{o.Addr},
		Auth: clickhouse.Auth{Database: o.Database, Username: o.Username, Password: o.Password},
	})
	if err != nil {
		return nil, fmt.Errorf("chconn: open query principal %s: %w", o.Addr, err)
	}
	if err := ch.Ping(ctx); err != nil {
		_ = ch.Close()
		return nil, fmt.Errorf("chconn: query principal unreachable %s: %w", o.Addr, err)
	}
	return &QueryConn{ch: ch}, nil
}

// MustOpenQuery is boot wiring for the querychoke module; unreachable store
// at boot ⇒ Fatal, crashloop on purpose (05 §1.2 posture).
func MustOpenQuery(ctx context.Context, o Options) *QueryConn {
	q, err := OpenQuery(ctx, o)
	if err != nil {
		log.Fatalf("chconn: boot refusal (05 §1.2): %v", err)
	}
	return q
}

// Query executes one SELECT with SERVER-SIDE {name:Type} parameters only —
// values never touch the SQL text on the client, so a hostile parameter
// value cannot change the statement's shape (05 §6.2: typed parameters,
// no free-text splice). The sole caller is querychoke's Runner.
func (q *QueryConn) Query(ctx context.Context, sql string, params map[string]string) (driver.Rows, error) {
	return q.ch.Query(clickhouse.Context(ctx, clickhouse.WithParameters(params)), sql)
}

func (q *QueryConn) Ping(ctx context.Context) error { return q.ch.Ping(ctx) }

func (q *QueryConn) Close() error { return q.ch.Close() }

// ErrNoDedupToken: a write-shaped template execution without a job key is
// refused before it reaches the server — the dedup token is idempotency
// layer 2 of ADR-0010 §2.3 and is mandatory, not defensive (a duplicate row
// under AggregatingMergeTree merges ADDITIVELY and doubles TVO plausibly).
var ErrNoDedupToken = errors.New("chconn: write-template execution requires a dedup token (ADR-0010 §2.3 layer 2)")

// ExecTemplateWrite executes one Build-constructed write template under the
// ingest principal with insert_deduplication_token = jobKey (ADR-0010 §2.3:
// the physical idempotency layer; the logical layer is intel_jobs.job_key
// UNIQUE in the DRIVING job's ledger, and the structural layer is that one
// (tenant, day, series) is one row in one insert block — which this single
// statement is). Its ONLY sanctioned callers are querychoke's two write
// templates (05 §6.3's closed two-name set); ingest/chproj must never
// reference it — asserted by querychoke's confinement test.
func (c *Conn) ExecTemplateWrite(ctx context.Context, sql string, params map[string]string, jobKey string) error {
	if jobKey == "" {
		return ErrNoDedupToken
	}
	ctx = clickhouse.Context(ctx,
		clickhouse.WithParameters(params),
		clickhouse.WithSettings(clickhouse.Settings{"insert_deduplication_token": jobKey}),
	)
	return c.ch.Exec(ctx, sql)
}
