// Package ingest is the C4 module built IN FULL (13 §11 row C4): the 05 §2
// pipeline — token-stamped tenancy, bounded decode, invariant checks, the
// independent pre-egress scanner, S3-first landing, idempotent ack, and the
// post-ack ClickHouse/Postgres projections. The wire contract is 08 §2; the
// governing invariant is 05 §2.2's: a 200/202 means "Omium can no longer
// lose this data."
package ingest

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/chproj"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/s3land"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/sidefx"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/server"
)

// SecurityRecorder is the "+ security event" half of the M1E-8003 reject
// (05 §2.1 stage 3): the record must outlive the refused request, so the
// production recorder writes a GuardDecision-class row through the projector.
type SecurityRecorder interface {
	RecordIdentityDisagreement(tenant, device, batch uuid.UUID, detail string, at time.Time)
}

// PGReady is the readiness slice of pg.TenantDB (interface here so unit
// tests fake readiness without a pool).
type PGReady interface {
	Ready(ctx context.Context) error
}

// Deps: everything injected, nothing global — the module-boundary rule
// (05 §0.2) means extraction is copy + main.go, and that only stays true if
// wiring stays in main.
type Deps struct {
	Verifier auth.Verifier
	ObsCfg   obs.Config
	PG       PGReady
	Store    s3land.Store
	Proj     *chproj.Projector
	Sidefx   *sidefx.Sidefx
	Security SecurityRecorder // nil ⇒ log+project via Proj
	// PoolSize is the §8.1 ingest pipeline bound (64 at prod defaults).
	PoolSize int
	Now      func() time.Time
}

type Module struct {
	verifier auth.Verifier
	obsCfg   obs.Config
	pgReady  PGReady
	store    s3land.Store
	proj     *chproj.Projector
	sfx      *sidefx.Sidefx
	security SecurityRecorder
	limiter  *Limiter
	sem      chan struct{}
	now      func() time.Time
}

func New(d Deps) *Module {
	if d.PoolSize == 0 {
		d.PoolSize = 64 // 05 §8.1
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	m := &Module{
		verifier: d.Verifier,
		obsCfg:   d.ObsCfg,
		pgReady:  d.PG,
		store:    d.Store,
		proj:     d.Proj,
		sfx:      d.Sidefx,
		security: d.Security,
		limiter:  NewLimiter(),
		sem:      make(chan struct{}, d.PoolSize),
		now:      d.Now,
	}
	if m.security == nil {
		m.security = &projectorSecurity{proj: d.Proj}
	}
	return m
}

func (m *Module) Name() string { return "ingest" }

// RegisterRoutes mounts POST /m1p/v1/ingest behind the 05 §0.3 middleware
// order (auth → tenancy stamp → obs); auth failures land in THIS module's
// metric namespace via the callback.
func (m *Module) RegisterRoutes(mux *http.ServeMux) {
	chain := server.Chain(m.verifier, m.obsCfg, func(reason string) {
		authFailures.WithLabelValues(reason).Inc()
	})
	mux.Handle("POST /m1p/v1/ingest", chain(http.HandlerFunc(m.handleIngest)))
}

// Ready is ingest's readiness contributor (05 §1.4): Postgres app-pool ping
// AND the cached S3 HeadBucket. ClickHouse is deliberately NOT here — the ack
// promise is S3-durability, and ingest keeps that promise straight through a
// ClickHouse outage; putting CH in readiness would convert a degraded ledger
// view into a full capture outage.
func (m *Module) Ready(ctx context.Context) error {
	if err := m.pgReady.Ready(ctx); err != nil {
		return err
	}
	return m.store.Ready(ctx)
}

// projectorSecurity: the default M1E-8003 recorder — a deterministic
// GuardDecision-class row through the async projector (see
// chproj.SecurityEventRow for the idempotency story), plus a log line so the
// event exists even if the projector queue is saturated.
type projectorSecurity struct {
	proj *chproj.Projector
}

func (p *projectorSecurity) RecordIdentityDisagreement(tenant, device, batch uuid.UUID, detail string, at time.Time) {
	log.Printf("SECURITY ingest M1E-8003: tenant=%s device=%s batch=%s: %s", tenant, device, batch, detail)
	if p.proj != nil {
		p.proj.Enqueue([][]any{chproj.SecurityEventRow(tenant, device, batch, detail, at)}, at)
	}
}
