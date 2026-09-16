// The draft publisher: 05 §4.1's in-repo publication path, the only thing that
// turns a compiler draft (m1_070 bundle_drafts, written by mark1-intel) into a
// publication. Per pending draft it reassembles the six canonical section byte
// strings, checks the compiler's hash, honours the knee sanity gate the
// compiler recorded (06 §10.3), runs the STRICT reference decode -- any string
// outside its production is M1E-3005 and the draft is refused and recorded,
// never published -- then hands the Draft to Module.Publish, where signing, the
// transparency log and the catalog commit already live. On success it attaches
// the canary plan 06 §10.4 rule 4 requires, derived from the same constants and
// cohort assignment the rollout controller runs on. Shaped like controller.go:
// Run/RunOnce/Tick, Clock injection, a Postgres lease instead of memory.

package policydist

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
)

var draftOutcomes = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "controld_policydist_draft_outcomes_total",
	Help: "Compiler drafts by outcome (06 §10.4): published, unchanged, refused, error. A refusal pages.",
}, []string{"outcome"})

// DraftTickInterval: a draft is nightly; a minute of latency is nothing, a day is a missed rollout.
const DraftTickInterval = time.Minute

// draftLease bounds how long a crashed publisher can hold a claimed draft before a sibling retries it.
const draftLease = 10 * time.Minute

type DraftPublisher struct {
	ctrl *Controller
	now  func() time.Time
	tick <-chan time.Time
}

// NewDraftPublisher composes on the rollout controller: same Module, tenant source and cohort assignment.
func NewDraftPublisher(ctrl *Controller) *DraftPublisher {
	return &DraftPublisher{ctrl: ctrl, now: time.Now}
}

// Clock injects the time source and tick channel for tests; production keeps the defaults.
func (p *DraftPublisher) Clock(now func() time.Time, tick <-chan time.Time) {
	p.now, p.tick = now, tick
}

// Run ticks until ctx ends; a failed tick is logged and the next one catches up (05 §1.5).
func (p *DraftPublisher) Run(ctx context.Context) {
	tick := p.tick
	if tick == nil {
		t := time.NewTicker(DraftTickInterval)
		defer t.Stop()
		tick = t.C
	}
	for {
		if err := p.RunOnce(ctx); err != nil {
			log.Printf("policydist: draft tick failed: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick:
		}
	}
}

// RunOnce drains every tenant's pending drafts; per-tenant failures never stop the sweep.
func (p *DraftPublisher) RunOnce(ctx context.Context) error {
	ids, err := p.ctrl.tenants(ctx)
	if err != nil {
		return err
	}
	for _, id := range ids {
		tenant, err := querychoke.FromClaims(auth.Claims{TenantID: id})
		if err != nil {
			return err
		}
		if err := p.Tick(ctx, tenant); err != nil {
			draftOutcomes.WithLabelValues("error").Inc()
			log.Printf("policydist: draft tick %s failed: %v", id, err)
		}
	}
	return nil
}

// draft is one bundle_drafts row as the publisher reads it.
type draft struct {
	Channel     string
	WindowStart time.Time
	Sections    map[string][]byte
	Hash        []byte
	MaxAge      time.Duration
	KneeOK      bool
	KneeNote    string
}

// vet is the pure gate: reassemble, prove the compiler's hash, honour the knee gate, strict-decode; a *RejectError is final for these bytes.
func vet(d draft) (Draft, []byte, error) {
	raw := make(map[string]cbor.RawMessage, len(SectionNames))
	for _, name := range SectionNames {
		b, ok := d.Sections[name]
		if !ok || len(b) == 0 {
			return Draft{}, nil, reject("M1E-3001", "draft has no %s section bytes", name)
		}
		raw[name] = b
	}
	body, err := canonEnc.Marshal(raw)
	if err != nil {
		return Draft{}, nil, reject("M1E-3005", "section bytes are not well-formed canonical CBOR: %v", err)
	}
	if sum := sha256.Sum256(body); !bytes.Equal(sum[:], d.Hash) {
		return Draft{}, nil, reject("M1E-3001", "draft_hash does not match the section bytes; the compiler disagrees with itself")
	}
	if !d.KneeOK {
		return Draft{}, nil, reject("M1E-3001", "knee sanity gate refused by the compiler (06 §10.3): %s", d.KneeNote)
	}
	if _, err := DecodeSections(body); err != nil {
		return Draft{}, nil, err
	}
	return Draft{Channel: d.Channel, MaxAge: d.MaxAge, SectionsCBOR: body}, body, nil
}

// Tick claims and settles one tenant's pending drafts until none remain; a DB error leaves the claim to the lease, a refusal is final.
func (p *DraftPublisher) Tick(ctx context.Context, tenant querychoke.TenantID) error {
	for {
		d, found, err := p.claim(ctx, tenant)
		if err != nil || !found {
			return err
		}
		outcome, err := p.settle(ctx, tenant, d)
		if err != nil {
			return err
		}
		draftOutcomes.WithLabelValues(outcome).Inc()
	}
}

func (p *DraftPublisher) settle(ctx context.Context, tenant querychoke.TenantID, d draft) (string, error) {
	dr, body, err := vet(d)
	if err != nil {
		return p.refuse(ctx, tenant, d, err)
	}
	// 06 §7.3 resume: content that IS the head (crash after Publish, or nothing new) settles against it, never republishes.
	head, err := p.ctrl.mod.store.Latest(ctx, tenant, d.Channel)
	if err != nil && !errors.Is(err, ErrNoChannel) {
		return "", err
	}
	if err == nil {
		prior, err := Unmarshal(head.Body)
		if err != nil {
			return "", err
		}
		priorSections, err := canonEnc.Marshal(prior.Sections)
		if err != nil {
			return "", err
		}
		if bytes.Equal(priorSections, body) {
			return "unchanged", p.mark(ctx, tenant, d, head.Seq, nil)
		}
	}
	pub, err := p.ctrl.mod.Publish(ctx, tenant, dr)
	if err != nil {
		var rej *RejectError
		if errors.As(err, &rej) {
			return p.refuse(ctx, tenant, d, rej)
		}
		return "", err
	}
	plan, err := p.plan(ctx, tenant, pub.Seq)
	if err != nil {
		return "", fmt.Errorf("policydist: draft %s/%s published at seq %d but the canary plan failed: %w", tenant, d.Channel, pub.Seq, err)
	}
	log.Printf("policydist: draft %s/%s (window %s) published at seq %d", tenant, d.Channel, d.WindowStart.Format(time.DateOnly), pub.Seq)
	return "published", p.mark(ctx, tenant, d, pub.Seq, plan)
}

func (p *DraftPublisher) refuse(ctx context.Context, tenant querychoke.TenantID, d draft, why error) (string, error) {
	log.Printf("policydist: draft %s/%s (window %s) REFUSED: %v", tenant, d.Channel, d.WindowStart.Format(time.DateOnly), why)
	err := p.ctrl.mod.store.db.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			UPDATE bundle_drafts SET state = 'refused', refusal_reason = $4, updated_at = now()
			 WHERE tenant_id = $1 AND channel = $2 AND window_start = $3 AND state = 'pending'`,
			tenant.UUID(), d.Channel, d.WindowStart, why.Error())
		return err
	})
	return "refused", err
}

func (p *DraftPublisher) mark(ctx context.Context, tenant querychoke.TenantID, d draft, seq int64, plan []byte) error {
	return p.ctrl.mod.store.db.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			UPDATE bundle_drafts SET state = 'published', published_seq = $4, canary_plan = $5, updated_at = now()
			 WHERE tenant_id = $1 AND channel = $2 AND window_start = $3 AND state = 'pending'`,
			tenant.UUID(), d.Channel, d.WindowStart, seq, plan)
		return err
	})
}

// claim leases the oldest unclaimed or lease-expired pending draft; SKIP LOCKED keeps sibling replicas off it.
func (p *DraftPublisher) claim(ctx context.Context, tenant querychoke.TenantID) (draft, bool, error) {
	var d draft
	var maxAge float64
	found := true
	err := p.ctrl.mod.store.db.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		var verify, route, memory, cortex, gates, agentMaps []byte
		err := tx.QueryRow(ctx, `
			UPDATE bundle_drafts d SET claimed_at = $3, updated_at = now()
			 WHERE (d.tenant_id, d.channel, d.window_start) = (
			       SELECT tenant_id, channel, window_start FROM bundle_drafts
			        WHERE tenant_id = $1 AND state = 'pending'
			          AND (claimed_at IS NULL OR claimed_at < $3::timestamptz - $2::interval)
			        ORDER BY window_start LIMIT 1 FOR UPDATE SKIP LOCKED)
			 RETURNING d.channel, d.window_start, d.verify_cbor, d.route_cbor, d.memory_cbor, d.cortex_cbor,
			           d.gates_cbor, d.agent_maps_cbor, d.draft_hash, extract(epoch FROM d.max_age)::float8,
			           d.knee_gate_ok, d.knee_note`,
			tenant.UUID(), draftLease.String(), p.now()).
			Scan(&d.Channel, &d.WindowStart, &verify, &route, &memory, &cortex, &gates, &agentMaps,
				&d.Hash, &maxAge, &d.KneeOK, &d.KneeNote)
		if errors.Is(err, pgx.ErrNoRows) {
			found = false
			return nil
		}
		d.Sections = map[string][]byte{
			"verify": verify, "route": route, "memory": memory,
			"cortex": cortex, "gates": gates, "agent_maps": agentMaps,
		}
		return err
	})
	d.MaxAge = time.Duration(maxAge * float64(time.Second))
	return d, found, err
}

// CanaryPlan is 06 §10.4 rule 4 in the terms the rollout controller actually enforces (05 §4.3); every number is its constant.
type CanaryPlan struct {
	Seq          int64 `json:"seq"`
	Steps        []int `json:"steps"`
	CanaryCohort struct {
		Percent int         `json:"percent"`
		Devices []uuid.UUID `json:"devices"`
	} `json:"canary_cohort"`
	WidenCriteria struct {
		AckCoverageMin float64  `json:"ack_coverage_min"`
		RejectedMax    int      `json:"rejected_max"`
		SoakMinutes    int      `json:"soak_minutes"`
		HealthSignals  []string `json:"health_signals"`
		HealthRule     string   `json:"health_rule"`
	} `json:"widen_criteria"`
	Halt struct {
		CommandStringMax int     `json:"command_string_acks_max"`
		RejectedRatioMax float64 `json:"rejected_ratio_max"`
		PartialRatioMax  float64 `json:"partial_ratio_max"`
	} `json:"halt"`
	Rollback string `json:"rollback"`
}

// NewCanaryPlan fills the plan from the package constants; devices is the first-step cohort.
func NewCanaryPlan(seq int64, devices []uuid.UUID) CanaryPlan {
	var cp CanaryPlan
	cp.Seq, cp.Steps = seq, append([]int(nil), WidenSteps...)
	cp.CanaryCohort.Percent, cp.CanaryCohort.Devices = WidenSteps[0], devices
	cp.WidenCriteria.AckCoverageMin, cp.WidenCriteria.RejectedMax = WidenCoverage, 0
	cp.WidenCriteria.SoakMinutes = int(SoakWindow / time.Minute)
	cp.WidenCriteria.HealthSignals = append([]string(nil), healthSignals...)
	cp.WidenCriteria.HealthRule = "no cohort-vs-control delta over 2 sigma of the trailing-7-day baseline for two consecutive ticks"
	cp.Halt.CommandStringMax, cp.Halt.RejectedRatioMax, cp.Halt.PartialRatioMax = 0, HaltRejectedRatio, HaltPartialRatio
	cp.Rollback = "previous content republished under a higher seq"
	return cp
}

func (p *DraftPublisher) plan(ctx context.Context, tenant querychoke.TenantID, seq int64) ([]byte, error) {
	devices, err := p.ctrl.cohort(ctx, tenant, WidenSteps[0])
	if err != nil {
		return nil, err
	}
	if devices == nil {
		devices = []uuid.UUID{}
	}
	return json.Marshal(NewCanaryPlan(seq, devices))
}
