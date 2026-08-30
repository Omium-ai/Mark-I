// Package chconn holds the ONLY ClickHouse client handle in the codebase
// (05 §0.3, §6.1 visibility layer). It is importable solely by querychoke
// itself and by ingest/chproj's INSERT-only projector — confinement enforced
// by the depguard clickhouse-choke rule (13 §7.3), so no other code can reach
// ClickHouse even with a hand-built string.
package chconn

import (
	"context"
	"fmt"
	"log"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// Options: the ingest principal's connection. The username is m1p_ingest by
// contract (07: exactly two runtime CH users); tests override to hit scratch
// databases, production never does.
type Options struct {
	Addr     string // host:port of the ClickHouse NATIVE interface (9000-class)
	Database string // "mark1" in production; scratch in tests
	Username string // "m1p_ingest" in production
	Password string
}

// Conn wraps the driver handle. No SELECT surface is exported: chproj gets
// InsertRows and Ping, nothing that could express a read (05 §6: the wiring
// exception is INSERT-shaped).
type Conn struct {
	ch driver.Conn
	db string
}

// Open connects and enforces boot refusal R3 (05 §1.2): the SERVER-side
// settings for this user (the m1p_ingest profile, 07: users.d/m1p-ingest.yaml)
// MUST already grant async_insert=1 and wait_for_async_insert=1. R3's subject
// is the server profile, so the assertion runs on a probe connection that
// carries NO client-side settings — asserting on a connection that sets them
// itself would only ever read back its own values, and the refusal could
// never fire (a check that passes by never executing). The working connection
// then ALSO passes the settings client-side (deliberately redundant, 07:
// a client bug and a server bug must coincide) and re-asserts, which catches
// a profile constraint that force-overrides the client values.
// wait_for_async_insert=1 is what makes the insert call return only once data
// is durably in a part — the projection-side half of the "nothing acked can
// be lost" story.
func Open(ctx context.Context, o Options) (*Conn, error) {
	// Native protocol (the clickhouse-go default): the batch INSERT path and
	// per-connection settings both ride it first-class; the HTTP interface is
	// not used by controld.
	auth := clickhouse.Auth{
		Database: o.Database,
		Username: o.Username,
		Password: o.Password,
	}
	probe, err := clickhouse.Open(&clickhouse.Options{Addr: []string{o.Addr}, Auth: auth})
	if err != nil {
		return nil, fmt.Errorf("chconn: open %s: %w", o.Addr, err)
	}
	perr := assertAsyncInsert(ctx, probe, "server-side profile")
	_ = probe.Close()
	if perr != nil {
		return nil, perr
	}

	ch, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{o.Addr},
		Auth: auth,
		Settings: clickhouse.Settings{
			"async_insert":          1,
			"wait_for_async_insert": 1,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("chconn: open %s: %w", o.Addr, err)
	}
	if err := assertAsyncInsert(ctx, ch, "connection-effective settings"); err != nil {
		_ = ch.Close()
		return nil, err
	}
	return &Conn{ch: ch, db: o.Database}, nil
}

// OpenOffboard connects the offboarding-deletion principal. WHY a third
// principal (07 §"deletion path"): the tenant-erasure mutations are "issued
// by the offboarding role through the query choke" — a role of its OWN,
// neither of the two runtime users: m1p_ingest is INSERT-only and answers
// ACCESS_DENIED to a DELETE (the wave-7 defect: the delete carve-out was
// routed to it and only the superuser-connected test could not see the
// refusal), and m1p_query is SELECT-only. No R3 assertion here: R3's subject
// is the ingest async-insert profile (05 §1.2), and a principal that never
// inserts would otherwise be refused at boot over a setting its one
// statement shape cannot use — blocking a legal deletion obligation.
func OpenOffboard(ctx context.Context, o Options) (*Conn, error) {
	ch, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{o.Addr},
		Auth: clickhouse.Auth{Database: o.Database, Username: o.Username, Password: o.Password},
	})
	if err != nil {
		return nil, fmt.Errorf("chconn: open offboard principal %s: %w", o.Addr, err)
	}
	if err := ch.Ping(ctx); err != nil {
		_ = ch.Close()
		return nil, fmt.Errorf("chconn: offboard principal unreachable %s: %w", o.Addr, err)
	}
	return &Conn{ch: ch, db: o.Database}, nil
}

// MustOpen is boot step 4 (05 §1.1); mismatch ⇒ Fatal, crashloop on purpose.
func MustOpen(ctx context.Context, o Options) *Conn {
	c, err := Open(ctx, o)
	if err != nil {
		log.Fatalf("chconn: boot refusal R3 (05 §1.2): %v", err)
	}
	return c
}

// assertAsyncInsert reads the EFFECTIVE settings of the given connection: on
// the settings-free probe that is the server-side grant R3 names; on the
// working connection it is server grant + client settings + any profile
// constraint, whichever the server let win.
func assertAsyncInsert(ctx context.Context, ch driver.Conn, where string) error {
	for _, name := range []string{"async_insert", "wait_for_async_insert"} {
		var v string
		row := ch.QueryRow(ctx, fmt.Sprintf("SELECT toString(getSetting('%s'))", name))
		if err := row.Scan(&v); err != nil {
			return fmt.Errorf("chconn: cannot read setting %s: %w", name, err)
		}
		if v != "1" && v != "true" {
			return fmt.Errorf("chconn: %s: setting %s=%q, want 1 (R3: a silent revert to synchronous small-part inserts is a slow-motion outage)", where, name, v)
		}
	}
	return nil
}

// InsertRows batch-inserts into db.table with the named columns. The one
// write surface chproj borrows.
func (c *Conn) InsertRows(ctx context.Context, table string, columns []string, rows [][]any) error {
	if len(rows) == 0 {
		return nil
	}
	cols := ""
	for i, col := range columns {
		if i > 0 {
			cols += ", "
		}
		cols += col
	}
	batch, err := c.ch.PrepareBatch(ctx, fmt.Sprintf("INSERT INTO %s.%s (%s)", c.db, table, cols))
	if err != nil {
		return fmt.Errorf("chconn: prepare insert %s: %w", table, err)
	}
	for _, r := range rows {
		if err := batch.Append(r...); err != nil {
			_ = batch.Abort()
			return fmt.Errorf("chconn: append: %w", err)
		}
	}
	return batch.Send()
}

func (c *Conn) Ping(ctx context.Context) error { return c.ch.Ping(ctx) }

func (c *Conn) Close() error { return c.ch.Close() }
