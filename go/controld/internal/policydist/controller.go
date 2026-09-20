// The canary controller (05 §4.3): a background loop, cursor in Postgres
// (m1_066 rollout_cursor), idempotent-resumable per §1.5. Per (tenant,
// channel) it reads the ACK ledger, re-scopes the M1E-3005 tripwire to the
// rollout under control, derives the health input from the three §4.3(c)
// querychoke templates, calls Decide, widens by NextStep, and on a halt
// publishes the previous content forward at seq+1. The transition itself is
// the pure step() so the widen/halt/rollback sequence is testable without a
// database; Tick is the I/O around it.

package policydist

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/receipts"
)

var rolloutDecisions = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "controld_policydist_rollout_decisions_total",
	Help: "Canary controller decisions by outcome (05 §4.3); any halt pages.",
}, []string{"decision"})

// TickInterval is 05 §4.3(c)'s evaluation cadence.
const TickInterval = 5 * time.Minute

// healthBaseline is the trailing window the 2σ rule is measured against.
const healthBaseline = 7 * 24 * time.Hour

// healthSignals are the three 05 §4.3(c) templates, each SELECTing (arm, numerator, denominator).
var healthSignals = []string{"canary_gate_block_rate", "canary_dropped_rate", "canary_fused_violated_rate"}

type Controller struct {
	mod     *Module
	runner  querychoke.Runner
	tpl     *querychoke.Registry
	salt    func(uuid.UUID) ([]byte, error)
	tenants receipts.TenantSource
	now     func() time.Time
	tick    <-chan time.Time
}

// NewController wires the loop. salt is the per-tenant HMAC root (enroll.TenantRoot); tenants is the same seam the witness job uses.
func NewController(mod *Module, runner querychoke.Runner, tpl *querychoke.Registry, salt func(uuid.UUID) ([]byte, error), tenants receipts.TenantSource) *Controller {
	return &Controller{mod: mod, runner: runner, tpl: tpl, salt: salt, tenants: tenants, now: time.Now}
}

// Clock injects the time source and tick channel for tests; production keeps the defaults.
func (c *Controller) Clock(now func() time.Time, tick <-chan time.Time) { c.now, c.tick = now, tick }

// Run ticks until ctx ends; a failed tick is logged and the next one catches up (05 §1.5).
func (c *Controller) Run(ctx context.Context) {
	tick := c.tick
	if tick == nil {
		t := time.NewTicker(TickInterval)
		defer t.Stop()
		tick = t.C
	}
	for {
		if err := c.RunOnce(ctx); err != nil {
			log.Printf("policydist: rollout tick failed: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick:
		}
	}
}

// RunOnce ticks every channel with a head for every tenant the source yields; per-channel failures never stop the sweep.
func (c *Controller) RunOnce(ctx context.Context) error {
	ids, err := c.tenants(ctx)
	if err != nil {
		return err
	}
	for _, id := range ids {
		tenant, err := querychoke.FromClaims(auth.Claims{TenantID: id})
		if err != nil {
			return err
		}
		var channels []string
		err = c.mod.store.db.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT channel FROM bundle_channel_heads WHERE tenant_id = $1 AND head_seq > 0`, id)
			if err != nil {
				return err
			}
			channels, err = pgx.CollectRows(rows, pgx.RowTo[string])
			return err
		})
		if err != nil {
			return err
		}
		for _, ch := range channels {
			if err := c.Tick(ctx, tenant, ch); err != nil {
				rolloutDecisions.WithLabelValues("error").Inc()
				log.Printf("policydist: rollout tick %s/%s failed: %v", id, ch, err)
			}
		}
	}
	return nil
}

// cursor is one rollout_cursor row. RollbackSeq/PromotedSeq 0 means none.
type cursor struct {
	Seq         int64
	Cohort      int
	StepStarted time.Time
	HealthTicks int
	Halted      bool
	HaltReason  string
	RollbackSeq int64
	// PromotedSeq is the STABLE seq a completed canary rollout's content landed at (m1_089): set once, by promote(), never by save().
	PromotedSeq int64
}

// step is the pure transition: Decide plus the two-tick health counter and the widen ladder.
func step(cov Coverage, cur cursor, regressed bool, now time.Time) (cursor, Decision, string) {
	next := cur
	next.HealthTicks = 0
	if regressed {
		next.HealthTicks = cur.HealthTicks + 1
	}
	d, why := Decide(cov, RolloutState{CohortPercent: cur.Cohort, SoakElapsed: now.Sub(cur.StepStarted), HealthRegressed: next.HealthTicks >= 2})
	switch {
	case d == DecisionWiden && regressed:
		d, why = DecisionHold, "health regressed this tick; 05 §4.3 step 2 widens only on a clean one"
	case d == DecisionWiden:
		next.Cohort, next.StepStarted, next.HealthTicks = NextStep(cur.Cohort), now, 0
	case d == DecisionHalt:
		next.Halted, next.HaltReason = true, why
	}
	return next, d, why
}

// Tick is the worker entrypoint (ingest.Replay's shape): one evaluation of one (tenant, channel). Any error leaves the cursor untouched, which is a hold.
func (c *Controller) Tick(ctx context.Context, tenant querychoke.TenantID, channel string) error {
	cov, err := c.mod.store.AckCoverage(ctx, tenant, channel, nil)
	if err != nil || cov.HeadSeq == 0 {
		return err
	}
	cur, found, err := c.load(ctx, tenant, channel)
	if err != nil {
		return err
	}
	now := c.now()
	if !found || cur.Seq != cov.HeadSeq {
		if found && cur.RollbackSeq == cov.HeadSeq {
			return nil // frozen at our own rollback until a new publication moves the head
		}
		cur = cursor{Seq: cov.HeadSeq, Cohort: WidenSteps[0], StepStarted: now}
		if err := c.reset(ctx, tenant, channel, cur); err != nil {
			return err
		}
	}
	if cur.Halted {
		if cur.RollbackSeq == 0 && cur.Seq > 1 {
			return c.rollback(ctx, tenant, channel, cur.Seq) // resumed after a crash between halt and publish
		}
		return nil
	}
	// 05 §4.3 item 1: under steering only cohort devices ever poll and ACK canary, so under 100% the whole-fleet coverage above can never reach the widen floor -- re-measure over the cohort. At 100% the cohort IS the whole fleet, so the first read already has the right numbers.
	if channel == CanaryChannel && cur.Cohort < 100 {
		cohortIDs, err := c.cohort(ctx, tenant, cur.Cohort)
		if err != nil {
			return err
		}
		if cov, err = c.mod.store.AckCoverage(ctx, tenant, channel, cohortIDs); err != nil {
			return err
		}
	}
	// AckCoverage's CommandString is channel-lifetime; the halt is per rollout, or one historical 3005 bricks the channel forever.
	if cov.CommandString, err = c.tripwire(ctx, tenant, channel, cur.Seq); err != nil {
		return err
	}
	regressed, err := c.regressed(ctx, tenant, channel, cur.Cohort, now)
	if err != nil {
		return err
	}
	next, d, why := step(cov, cur, regressed, now)
	won, err := c.save(ctx, tenant, channel, cur, next)
	if err != nil || !won {
		return err // lost the race to a sibling replica; its tick owns this step
	}
	rolloutDecisions.WithLabelValues(string(d)).Inc()
	log.Printf("policydist: rollout %s/%s seq %d at %d%%: %s -- %s", tenant, channel, cur.Seq, cur.Cohort, d, why)
	if d == DecisionHalt && cur.Seq > 1 {
		return c.rollback(ctx, tenant, channel, cur.Seq)
	}
	// 05 §4.3 item 1's completion: canary held clean at 100% through one more soak promotes its content onto stable.
	if channel == CanaryChannel && next.Cohort == 100 && cur.PromotedSeq == 0 && now.Sub(next.StepStarted) >= SoakWindow {
		return c.promote(ctx, tenant, cur.Seq)
	}
	return nil
}

// promote is 05 §4.3 item 1's rollout completion: the canary head's sections republished onto stable at STABLE's own head+1
func (c *Controller) promote(ctx context.Context, tenant querychoke.TenantID, seq int64) error {
	var body []byte
	var maxAge float64
	err := c.mod.store.db.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT body_cbor, extract(epoch FROM max_age)::float8 FROM policy_bundles WHERE tenant_id = $1 AND channel = $2 AND seq = $3`,
			tenant.UUID(), CanaryChannel, seq).Scan(&body, &maxAge)
	})
	if err != nil {
		return fmt.Errorf("policydist: promotion of canary seq %d: reading it: %w", seq, err)
	}
	canary, err := Unmarshal(body)
	if err != nil {
		return err
	}
	sections, err := canonEnc.Marshal(canary.Sections)
	if err != nil {
		return err
	}
	p, err := c.mod.Publish(ctx, tenant, Draft{Channel: BootstrapChannel, MaxAge: time.Duration(maxAge * float64(time.Second)), SectionsCBOR: sections})
	if err != nil {
		return fmt.Errorf("policydist: promotion of canary seq %d: %w", seq, err)
	}
	log.Printf("policydist: rollout %s/%s seq %d completed at 100%%; content promoted to stable seq %d", tenant, CanaryChannel, seq, p.Seq)
	return c.mod.store.db.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE rollout_cursor SET promoted_seq = $1, updated_at = now() WHERE tenant_id = $2 AND channel = $3 AND seq = $4 AND promoted_seq IS NULL`,
			p.Seq, tenant.UUID(), CanaryChannel, seq)
		return err
	})
}

// rollback is 05 §4.6: the content of seq-1 published forward at head+1, then recorded on the cursor.
func (c *Controller) rollback(ctx context.Context, tenant querychoke.TenantID, channel string, seq int64) error {
	var body []byte
	var maxAge float64
	err := c.mod.store.db.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT body_cbor, extract(epoch FROM max_age)::float8 FROM policy_bundles WHERE tenant_id = $1 AND channel = $2 AND seq = $3`,
			tenant.UUID(), channel, seq-1).Scan(&body, &maxAge)
	})
	if err != nil {
		return fmt.Errorf("policydist: rollback of seq %d: reading seq %d: %w", seq, seq-1, err)
	}
	prior, err := Unmarshal(body)
	if err != nil {
		return err
	}
	sections, err := canonEnc.Marshal(prior.Sections)
	if err != nil {
		return err
	}
	p, err := c.mod.Publish(ctx, tenant, Draft{Channel: channel, MaxAge: time.Duration(maxAge * float64(time.Second)), SectionsCBOR: sections})
	if err != nil {
		return fmt.Errorf("policydist: rollback of seq %d: %w", seq, err)
	}
	log.Printf("policydist: rollout %s/%s seq %d halted; prior content republished at seq %d", tenant, channel, seq, p.Seq)
	return c.mod.store.db.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE rollout_cursor SET rollback_seq = $4, updated_at = now() WHERE tenant_id = $1 AND channel = $2 AND seq = $3 AND rollback_seq IS NULL`,
			tenant.UUID(), channel, seq, p.Seq)
		return err
	})
}

func (c *Controller) load(ctx context.Context, tenant querychoke.TenantID, channel string) (cursor, bool, error) {
	var cur cursor
	var haltedAt *time.Time
	var reason *string
	var rb, promoted *int64
	found := true
	err := c.mod.store.db.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT seq, cohort_percent, step_started_at, health_ticks, halted_at, halt_reason, rollback_seq, promoted_seq FROM rollout_cursor WHERE tenant_id = $1 AND channel = $2`,
			tenant.UUID(), channel).Scan(&cur.Seq, &cur.Cohort, &cur.StepStarted, &cur.HealthTicks, &haltedAt, &reason, &rb, &promoted)
		if errors.Is(err, pgx.ErrNoRows) {
			found = false
			return nil
		}
		return err
	})
	if haltedAt != nil {
		cur.Halted, cur.HaltReason = true, *reason
	}
	if rb != nil {
		cur.RollbackSeq = *rb
	}
	if promoted != nil {
		cur.PromotedSeq = *promoted
	}
	return cur, found, err
}

// reset seeds the row for a new rollout; unconditional, because every replica computes the same first step from the same head.
func (c *Controller) reset(ctx context.Context, tenant querychoke.TenantID, channel string, cur cursor) error {
	return c.mod.store.db.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO rollout_cursor (tenant_id, channel, seq, cohort_percent, step_started_at)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (tenant_id, channel) DO UPDATE
			   SET seq = EXCLUDED.seq, cohort_percent = EXCLUDED.cohort_percent, step_started_at = EXCLUDED.step_started_at,
			       health_ticks = 0, halted_at = NULL, halt_reason = NULL, rollback_seq = NULL, promoted_seq = NULL, updated_at = now()`,
			tenant.UUID(), channel, cur.Seq, cur.Cohort, cur.StepStarted)
		return err
	})
}

// save is a compare-and-set on the step the tick was computed from, so two replicas cannot both widen or both roll back.
func (c *Controller) save(ctx context.Context, tenant querychoke.TenantID, channel string, prev, next cursor) (bool, error) {
	var haltedAt *time.Time
	var reason *string
	if next.Halted {
		t := c.now()
		haltedAt, reason = &t, &next.HaltReason
	}
	won := false
	err := c.mod.store.db.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE rollout_cursor
			   SET cohort_percent = $5, step_started_at = $6, health_ticks = $7, halted_at = $8, halt_reason = $9, updated_at = now()
			 WHERE tenant_id = $1 AND channel = $2 AND seq = $3 AND cohort_percent = $4 AND halted_at IS NULL`,
			tenant.UUID(), channel, prev.Seq, prev.Cohort, next.Cohort, next.StepStarted, next.HealthTicks, haltedAt, reason)
		won = tag.RowsAffected() == 1
		return err
	})
	return won, err
}

// tripwire is 05 §4.3(a) scoped to one rollout, on m1_042's partial index.
func (c *Controller) tripwire(ctx context.Context, tenant querychoke.TenantID, channel string, seq int64) (int64, error) {
	var n int64
	err := c.mod.store.db.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(DISTINCT device_id) FROM bundle_acks WHERE tenant_id = $1 AND channel = $2 AND seq = $3 AND reject_code = 'M1E-3005'`,
			tenant.UUID(), channel, seq).Scan(&n)
	})
	return n, err
}

// regressed is 05 §4.3(c) for one tick: any of the three signals' cohort-vs-control delta over the last tick exceeds the trailing-7-day delta by 2σ.
func (c *Controller) regressed(ctx context.Context, tenant querychoke.TenantID, channel string, percent int, now time.Time) (bool, error) {
	if percent >= 100 {
		return false, nil // no control arm left to compare against
	}
	cohort, err := c.cohort(ctx, tenant, percent)
	if err != nil {
		return false, err
	}
	for _, name := range healthSignals {
		tpl, err := c.tpl.Lookup(name)
		if err != nil {
			return false, err
		}
		cur, err := c.arms(ctx, tenant, tpl, cohort, now.Add(-TickInterval), now)
		if err != nil {
			return false, err
		}
		base, err := c.arms(ctx, tenant, tpl, cohort, now.Add(-healthBaseline), now.Add(-TickInterval))
		if err != nil {
			return false, err
		}
		if regressedSignal(cur, base) {
			log.Printf("policydist: rollout %s/%s: %s regressed (cohort %v vs control %v; baseline cohort %v vs control %v)", tenant, channel, name, cur.cohort, cur.control, base.cohort, base.control)
			return true, nil
		}
	}
	return false, nil
}

// cohort is 06 §10.4's assignment over the active fleet, CohortOf's min-one rule included (Store.ActiveDevices filtered by InCohort, plus the lowest-percentile device once percent > 0).
func (c *Controller) cohort(ctx context.Context, tenant querychoke.TenantID, percent int) ([]uuid.UUID, error) {
	salt, err := c.salt(tenant.UUID())
	if err != nil {
		return nil, err
	}
	active, err := c.mod.store.ActiveDevices(ctx, tenant)
	if err != nil {
		return nil, err
	}
	return CohortOf(salt, active, percent), nil
}

type arm struct{ num, den float64 }

func (a arm) rate() float64 { return a.num / a.den }

type arms struct{ cohort, control arm }

// arms runs one canary template over one window; the templates SELECT (arm, numerator, denominator) in that column order.
func (c *Controller) arms(ctx context.Context, tenant querychoke.TenantID, tpl querychoke.Template, cohort []uuid.UUID, from, to time.Time) (arms, error) {
	q, err := querychoke.Build(tenant, tpl, querychoke.Params{"from": from, "to": to, "cohort": cohort})
	if err != nil {
		return arms{}, err
	}
	rows, err := c.runner.Run(ctx, q)
	if err != nil {
		return arms{}, err
	}
	var out arms
	for _, r := range rows.Rows {
		a := arm{num: num(r[rows.Columns[1]]), den: num(r[rows.Columns[2]])}
		switch r[rows.Columns[0]] {
		case "cohort":
			out.cohort = a
		case "control":
			out.control = a
		}
	}
	return out, nil
}

// num reads whatever integer width the ClickHouse driver scanned the aggregate into.
func num(v any) float64 {
	f, _ := strconv.ParseFloat(fmt.Sprint(v), 64)
	return f
}

// regressedSignal is the 2σ test for one signal. An empty arm puts NaN or Inf on a side of the compare, which is false: no data is no evidence, not a regression.
// ponytail: σ is the Poisson standard error at baseline rates over this tick's denominators, not an empirical σ over 2016 tick deltas; add a delta-history table if fleets prove over-dispersed.
func regressedSignal(cur, base arms) bool {
	pc, pk := base.cohort.rate(), base.control.rate()
	sigma := math.Sqrt(pc/cur.cohort.den + pk/cur.control.den)
	delta := (cur.cohort.rate() - cur.control.rate()) - (pc - pk)
	return delta > 2*sigma
}
