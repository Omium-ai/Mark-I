// Package registry is the `m1p-registry` of FR-SPINE-023: released schema
// versions and per-tenant accepted windows (migrations/m1_063). Ingest asks
// one question of it — which schemas may THIS tenant present — and answers
// 426 M1E-2007 with the structured upgrade hint (08 §10.2) when the presented
// one is not among them.
//
// Read-only by construction: controld_app holds SELECT and nothing else on
// both tables, so no code path here can widen a window.
package registry

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
)

// V1 is the one schema this binary decodes.
const V1 = "m1p.v1"

// Compiled is the window this binary was built with — what ingest served
// before the registry existed, and what it serves when the registry cannot be
// read (fail-static, 08 §9: capture is fail-open for availability).
var Compiled = Window{
	Accepted: []string{V1},
	NotesURI: map[string]string{V1: "https://docs.omium.ai/mark1/upgrade/m1p-v1"},
}

// Window is one tenant's view of the registry. Accepted is sorted by major;
// the maps are keyed by schema and cover every released schema (not only the
// accepted ones) so the 426 hint can describe both the presented schema and
// its successor.
type Window struct {
	Accepted []string
	MinEdge  map[string]string
	Closes   map[string]*time.Time // tenant rows only: when a window closed/closes
	NotesURI map[string]string
}

// Accepts is the 426 decision.
func (w Window) Accepts(schema string) bool {
	for _, s := range w.Accepted {
		if s == schema {
			return true
		}
	}
	return false
}

// Hint is the 08 §10.2 upgrade body for an out-of-window presentation:
// accepted, the SUCCESSOR's min_edge (the smallest accepted major above the
// presented one, else the newest accepted — 08's example: presented v1,
// accepted [v2], min_edge "2.0.0", notes for v2), the presented schema's
// window_closes if the tenant has one, and the successor's notes_uri (the
// presented schema's own when there is no successor to point at).
func (w Window) Hint(presented string) (accepted []string, minEdge *string, closes *time.Time, notesURI string) {
	accepted = append([]string{}, w.Accepted...) // never null on the wire
	target, ok := "", false
	p := major(presented)
	for _, s := range w.Accepted {
		if major(s) > p {
			target, ok = s, true
			break
		}
	}
	if !ok && len(w.Accepted) > 0 {
		target, ok = w.Accepted[len(w.Accepted)-1], true
	}
	if ok {
		if me, has := w.MinEdge[target]; has {
			minEdge = &me
		}
		notesURI = w.NotesURI[target]
	} else {
		notesURI = w.NotesURI[presented]
	}
	return accepted, minEdge, w.Closes[presented], notesURI
}

// major parses the N of "m1p.vN"; 0 for anything else (sorts first).
func major(schema string) int {
	n, _ := strconv.Atoi(strings.TrimPrefix(schema, "m1p.v"))
	return n
}

// Registry is what ingest consumes. The tenant always comes from verified
// claims (querychoke.TenantID cannot be built from a string a handler
// assembled).
type Registry interface {
	Window(ctx context.Context, tenant querychoke.TenantID) (Window, error)
}

// Static serves one fixed window to every tenant: tests, and the fail-static
// fallback (Static(Compiled)).
type Static Window

func (s Static) Window(context.Context, querychoke.TenantID) (Window, error) {
	return Window(s), nil
}

// DB is the WithTenant-shaped seam (05 §7.2); *pg.TenantDB satisfies it.
type DB interface {
	WithTenant(ctx context.Context, t querychoke.TenantID, fn func(pgx.Tx) error) error
}

// PG reads m1_063 under the tenant GUC — the same tx-local set_config path
// sidefx uses, so RLS is what scopes the window rows, not a WHERE clause.
type PG struct{ db DB }

func NewPG(db DB) *PG { return &PG{db: db} }

// Window applies m1_063's semantics: no tenant rows ⇒ every unretired
// schema; tenant rows ⇒ exactly those rows whose window is still open. The
// clock is Postgres's now(), inside the same statement, so a window that
// closes mid-request closes atomically.
// ponytail: one SELECT per ingest request, no cache — at pilot rates
// (≈10 batches/s/pod) it is noise next to the S3 PUT; add a per-tenant TTL
// cache shaped like enroll.RevocationCache if ack_seconds ever notices.
func (p *PG) Window(ctx context.Context, tenant querychoke.TenantID) (Window, error) {
	type row struct {
		schema    string
		unretired bool
		minEdge   *string
		notesURI  string
		scoped    bool
		closes    *time.Time
		open      bool
	}
	var rows []row
	err := p.db.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		rs, err := tx.Query(ctx, `
			SELECT v.schema, v.retired_at IS NULL, v.min_edge, v.notes_uri,
			       w.tenant_id IS NOT NULL, w.window_closes,
			       (w.window_closes IS NULL OR w.window_closes > now())
			  FROM m1_schema_versions v
			  LEFT JOIN m1_tenant_schema_windows w ON w.schema = v.schema`)
		if err != nil {
			return err
		}
		defer rs.Close()
		for rs.Next() {
			var r row
			if err := rs.Scan(&r.schema, &r.unretired, &r.minEdge, &r.notesURI, &r.scoped, &r.closes, &r.open); err != nil {
				return err
			}
			rows = append(rows, r)
		}
		return rs.Err()
	})
	if err != nil {
		return Window{}, err
	}
	w := Window{MinEdge: map[string]string{}, Closes: map[string]*time.Time{}, NotesURI: map[string]string{}}
	narrowed := false
	for _, r := range rows {
		narrowed = narrowed || r.scoped
	}
	for _, r := range rows {
		w.NotesURI[r.schema] = r.notesURI
		if r.minEdge != nil {
			w.MinEdge[r.schema] = *r.minEdge
		}
		if r.scoped && r.closes != nil {
			w.Closes[r.schema] = r.closes
		}
		if (narrowed && r.scoped && r.open) || (!narrowed && r.unretired) {
			w.Accepted = append(w.Accepted, r.schema)
		}
	}
	sort.Slice(w.Accepted, func(i, j int) bool { return major(w.Accepted[i]) < major(w.Accepted[j]) })
	return w, nil
}
