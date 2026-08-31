// runner.go — the exported Runner seam (05 §0.2): defined here, consumed by
// the route table, so extracting querychoke later means implementing Runner
// over HTTP and changing zero call sites. Note what does NOT exist:
// Run(ctx, sql string). The escape hatch is absent, not discouraged.
package querychoke

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke/chconn"
)

// Rows is the JSON-shaped result the §3.3 surfaces serialize verbatim.
type Rows struct {
	Columns []string
	Rows    []map[string]any
}

// Runner is the only execution surface (05 §6.2).
type Runner interface {
	Run(ctx context.Context, q Query) (*Rows, error)
}

// ErrBusy: the 05 §6.5 concurrency guard — 8 concurrent choke queries per
// pod, excess queues 5 s then sheds. The HTTP layer maps it to 503.
var ErrBusy = errors.New("querychoke: query concurrency limit reached")

const (
	maxConcurrent = 8
	queueWait     = 5 * time.Second
)

// CHRunner executes against the three ClickHouse principals, one per
// statement family (05 §6 / 07 §"deletion path"): reads on m1p_query
// (SELECT-only), the tvo_rollup_tenant_day INSERT on m1p_ingest (INSERT-only
// — the same principal chproj borrows), and the offboard DELETE on the
// dedicated offboarding role (ALTER DELETE; 07: erasure mutations are
// "issued by the offboarding role through the query choke"). WHY the third
// handle exists (wave-7 skeptic): routing the delete to the INSERT-only
// principal is ACCESS_DENIED in production, invisible to any test that
// connects as a superuser — so the integration suite now connects as the
// real grant shapes and a mismatch is a red test.
type CHRunner struct {
	read     *chconn.QueryConn
	write    *chconn.Conn
	offboard *chconn.Conn
	sem      chan struct{}
}

// NewRunner takes the offboard principal as nil-able: no route drives the
// delete template in this wave, and a nil handle refuses LOUDLY at run time
// ("no offboard principal wired") rather than borrowing a principal whose
// grants cannot execute the statement.
func NewRunner(read *chconn.QueryConn, write, offboard *chconn.Conn) *CHRunner {
	return &CHRunner{read: read, write: write, offboard: offboard, sem: make(chan struct{}, maxConcurrent)}
}

// Ready is the module's readiness contribution (05 §1.4): the choke is ready
// iff its read principal answers.
func (r *CHRunner) Ready(ctx context.Context) error { return r.read.Ping(ctx) }

func (r *CHRunner) Run(ctx context.Context, q Query) (*Rows, error) {
	if q.tpl == nil {
		return nil, ErrUnknownTemplate // zero Query cannot execute
	}
	wait := time.NewTimer(queueWait)
	defer wait.Stop()
	select {
	case r.sem <- struct{}{}:
		defer func() { <-r.sem }()
	case <-wait.C:
		return nil, ErrBusy
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	// 05 §6.5 timeout classes; the m1p_query profile's max_execution_time is
	// the deliberately redundant server-side guard.
	ctx, cancel := context.WithTimeout(ctx, q.tpl.timeout)
	defer cancel()

	if q.tpl.write {
		// Principal-per-statement-family (05 §6 / 07 §"deletion path"). The
		// name switch is safe because the write set is CLOSED at exactly two
		// names, boot-validated (templates.go writeNames; extending it is an
		// ADR that must also decide its principal here).
		conn := r.write
		if q.tpl.name == "offboard_delete_tenant" {
			conn = r.offboard
		}
		if conn == nil {
			return nil, fmt.Errorf("querychoke: no principal wired for write template %s (m1p_ingest cannot execute a DELETE; wire the offboarding role)", q.tpl.name)
		}
		// jobKey == "" is unreachable through BuildWrite; ExecTemplateWrite
		// refuses it again (ADR-0010 §2.3 layer 2 is mandatory).
		if err := conn.ExecTemplateWrite(ctx, q.sql, q.bind, q.jobKey); err != nil {
			return nil, fmt.Errorf("querychoke: write template %s: %w", q.tpl.name, err)
		}
		return nil, nil
	}

	rows, err := r.read.Query(ctx, q.sql, q.bind)
	if err != nil {
		return nil, fmt.Errorf("querychoke: template %s: %w", q.tpl.name, err)
	}
	defer func() { _ = rows.Close() }()

	cols := rows.Columns()
	types := rows.ColumnTypes()
	out := &Rows{Columns: cols}
	for rows.Next() {
		ptrs := make([]any, len(cols))
		for i, ct := range types {
			ptrs[i] = reflect.New(ct.ScanType()).Interface()
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, fmt.Errorf("querychoke: scan: %w", err)
		}
		m := make(map[string]any, len(cols))
		for i, c := range cols {
			m[c] = reflect.ValueOf(ptrs[i]).Elem().Interface()
		}
		out.Rows = append(out.Rows, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("querychoke: rows: %w", err)
	}
	return out, nil
}
