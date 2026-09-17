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
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/chproj"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/registry"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/s3land"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/scanner"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/sidefx"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/server"
)

// SecurityRecorder is the "+ security event" half of the two ingest refusals
// that must outlive the request they refused, so the production recorder
// writes a GuardDecision-class row through the projector.
type SecurityRecorder interface {
	// RecordIdentityDisagreement is the M1E-8003 reject (05 §2.1 stage 3).
	RecordIdentityDisagreement(tenant, device, batch uuid.UUID, detail string, at time.Time)
	// RecordQuarantine is CON-008's "+ tenant alert" on a stage-7 hit
	// (08 §9 M1E-7002). classes are the scanner rule classes that fired and
	// are the ONLY thing the scan is allowed to carry out — see
	// chproj.QuarantineEventRow for why nothing else may ride along.
	RecordQuarantine(tenant, device, batch uuid.UUID, classes []string, at time.Time)
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
	// Registry is the m1p-registry (FR-SPINE-023): per-tenant schema windows
	// behind the 426. nil ⇒ the compiled-in [m1p.v1] window for every tenant.
	Registry registry.Registry
	// Scanner is the stage-7 ruleset edition. nil ⇒ scanner.Default. Tests
	// land batches under one edition and Rescan them under another.
	Scanner *scanner.Ruleset
	// DeviceKeys resolves the enrolled key for AnchorVote.signature
	// verification (FR-VERIFY-004). nil ⇒ a non-empty signature can never be
	// verified and is refused -- the safe default for the check that exists
	// to catch forgery.
	DeviceKeys DeviceKeys
	// DB writes the m1_quarantined_batches tombstone in the request path that lands a quarantine twin (quarantine.go);
	// nil refuses every flagged batch with 503 — the never-replay marker is not optional.
	DB registry.DB
	// PoolSize is the §8.1 ingest pipeline bound (64 at prod defaults).
	PoolSize int
	Now      func() time.Time
	// IntelServiceToken verifies the internal service ingest route (service.go); empty ⇒ the surface is absent, never open.
	IntelServiceToken string
}

type Module struct {
	verifier     auth.Verifier
	obsCfg       obs.Config
	pgReady      PGReady
	store        s3land.Store
	proj         *chproj.Projector
	sfx          *sidefx.Sidefx
	security     SecurityRecorder
	registry     registry.Registry
	scanner      *scanner.Ruleset
	deviceKeys   DeviceKeys
	db           registry.DB
	limiter      *Limiter
	sem          chan struct{}
	now          func() time.Time
	serviceToken string
}

func New(d Deps) *Module {
	if d.PoolSize == 0 {
		d.PoolSize = 64 // 05 §8.1
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Registry == nil {
		d.Registry = registry.Static(registry.Compiled)
	}
	if d.Scanner == nil {
		d.Scanner = scanner.Default
	}
	m := &Module{
		verifier:     d.Verifier,
		obsCfg:       d.ObsCfg,
		pgReady:      d.PG,
		store:        d.Store,
		proj:         d.Proj,
		sfx:          d.Sidefx,
		security:     d.Security,
		registry:     d.Registry,
		scanner:      d.Scanner,
		deviceKeys:   d.DeviceKeys,
		db:           d.DB,
		limiter:      NewLimiter(),
		sem:          make(chan struct{}, d.PoolSize),
		now:          d.Now,
		serviceToken: d.IntelServiceToken,
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
	mux.Handle("PUT /api/v1/consents", chain(http.HandlerFunc(m.handleConsents)))
	mux.Handle("POST /internal/v1/ingest/service", m.obsCfg.HTTPMiddleware(nil)(http.HandlerFunc(m.handleServiceIngest)))
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

// projectorSecurity: the default recorder — a deterministic GuardDecision-class
// row through the async projector (see chproj.SecurityEventRow for the
// idempotency story), plus a log line so the event exists even if the projector
// queue is saturated.
//
// Overflow is COUNTED, not blocked on. A bounded block here would hold an
// ingest pool slot (05 §8.1) for the bound on the one path an attacker
// controls the rate of — disagreeing envelopes cost the sender nothing — so
// a slow ClickHouse plus a hostile device would turn the security path into
// the shed lever for honest tenants. The ledger classes the row diagnostic
// (chproj.securityRow), and 11 §10.1's rule for that class is that loss is
// accounted, never silent: the drop lands in securityEventsDropped (pages on
// any nonzero) alongside the log line and the stage-3 counter that already
// page.
type projectorSecurity struct {
	proj *chproj.Projector
}

func (p *projectorSecurity) RecordIdentityDisagreement(tenant, device, batch uuid.UUID, detail string, at time.Time) {
	log.Printf("SECURITY ingest M1E-8003: tenant=%s device=%s batch=%s: %s", tenant, device, batch, detail)
	p.project("M1E-8003", batch, chproj.SecurityEventRow(tenant, device, batch, detail, at), at)
}

func (p *projectorSecurity) project(code string, batch uuid.UUID, row []any, at time.Time) {
	if p.proj == nil {
		return
	}
	if !p.proj.Enqueue([][]any{row}, at) {
		securityEventsDropped.WithLabelValues(code).Inc()
		log.Printf("SECURITY ingest %s: batch=%s: ledger row DROPPED on projector overflow — no replay path; the log line above is the only record", code, batch)
	}
}

// RecordQuarantine logs and projects the rule CLASSES only. Everything here —
// the log line included — is class-level: a log line naming the matched text
// would put the secret in a third store with a third retention.
func (p *projectorSecurity) RecordQuarantine(tenant, device, batch uuid.UUID, classes []string, at time.Time) {
	detail := strings.Join(classes, ",")
	log.Printf("SECURITY ingest M1E-7002: tenant=%s device=%s batch=%s: quarantined on rule classes [%s]",
		tenant, device, batch, detail)
	p.project("M1E-7002", batch, chproj.QuarantineEventRow(tenant, device, batch, detail, at), at)
}
