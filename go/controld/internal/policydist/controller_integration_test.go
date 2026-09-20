//go:build integration

// The canary controller against the real schema (m1_066): the cursor survives
// a controller restart, a planted M1E-3005 ACK halts and rolls back, the
// rollback body carries the PRIOR content byte-for-byte, a halted channel
// stays frozen, and a fresh publication after the halt is not bricked by the
// historical 3005. Same harness, same NOBYPASSRLS role, as integration_test.go.

package policydist

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/receipts"
)

type itCursor struct {
	Seq, Cohort, Ticks int64
	Halted             *time.Time
	Reason             *string
	Rollback           *int64
	Promoted           *int64
}

func (h *itHarness) cursor(channel string) itCursor {
	h.t.Helper()
	var c itCursor
	if err := h.admin.QueryRow(context.Background(),
		`SELECT seq, cohort_percent, health_ticks, halted_at, halt_reason, rollback_seq, promoted_seq FROM rollout_cursor WHERE tenant_id = $1 AND channel = $2`,
		h.tenantAID, channel).Scan(&c.Seq, &c.Cohort, &c.Ticks, &c.Halted, &c.Reason, &c.Rollback, &c.Promoted); err != nil && err != pgx.ErrNoRows {
		h.t.Fatal(err)
	}
	return c
}

// sectionsOf is the content a rollback must reproduce: the canonical sections, minus everything the server re-mints (seq, prev_hash, issued_at, signatures, inclusion).
func (h *itHarness) sectionsOf(channel string, seq int64) []byte {
	h.t.Helper()
	var body []byte
	if err := h.admin.QueryRow(context.Background(),
		`SELECT body_cbor FROM policy_bundles WHERE tenant_id = $1 AND channel = $2 AND seq = $3`, h.tenantAID, channel, seq).Scan(&body); err != nil {
		h.t.Fatal(err)
	}
	b, err := Unmarshal(body)
	if err != nil {
		h.t.Fatal(err)
	}
	return mustEncode(h.t, b.Sections)
}

func (h *itHarness) ack(ctx context.Context, device uuid.UUID, channel string, seq int64, result string, code *string) {
	h.t.Helper()
	if _, err := h.mod.store.RecordAck(ctx, h.tenantA, device, Ack{Channel: channel, Seq: seq, Result: result, RejectCode: code, EdgeVersion: "1.0.0"}); err != nil {
		h.t.Fatal(err)
	}
}

func TestIntegrationRolloutController(t *testing.T) {
	h := itSetup(t)
	ctx := context.Background()
	const ch = "canary"

	now := time.Now()
	regressTick := false
	runner := &fakeRunner{rows: func(q querychoke.Query) *querychoke.Rows {
		cohort := map[string]any{"arm": "cohort", "n": uint64(10), "d": uint64(1000)}
		if regressTick && q.Bind()["from"] == now.Add(-TickInterval).UTC().Format(time.DateTime) {
			cohort["n"] = uint64(200)
		}
		return &querychoke.Rows{Columns: []string{"arm", "n", "d"}, Rows: []map[string]any{cohort, {"arm": "control", "n": uint64(10), "d": uint64(1000)}}}
	}}
	salt := func(uuid.UUID) ([]byte, error) { return []byte("it-salt"), nil }
	newController := func() *Controller {
		c := NewController(h.mod, runner, querychoke.MustLoadTemplates(), salt, receipts.StaticTenants([]uuid.UUID{h.tenantAID}))
		c.Clock(func() time.Time { return now }, nil)
		return c
	}
	c := newController()

	first, err := h.mod.Publish(ctx, h.tenantA, h.draft(ch))
	if err != nil {
		t.Fatal(err)
	}
	h.ack(ctx, h.deviceA1, ch, first.Seq, "applied", nil)
	h.ack(ctx, h.deviceA2, ch, first.Seq, "applied", nil)

	t.Run("first_tick_seeds_the_cursor_at_the_first_step", func(t *testing.T) {
		if err := c.RunOnce(ctx); err != nil {
			t.Fatal(err)
		}
		if cur := h.cursor(ch); cur.Seq != first.Seq || cur.Cohort != 5 || cur.Halted != nil {
			t.Fatalf("cursor after first tick: %+v", cur)
		}
	})

	t.Run("cursor_persists_across_a_restart", func(t *testing.T) {
		now = now.Add(SoakWindow + time.Minute)
		if err := c.Tick(ctx, h.tenantA, ch); err != nil {
			t.Fatal(err)
		}
		if cur := h.cursor(ch); cur.Cohort != 25 {
			t.Fatalf("soaked at 100%% coverage did not widen to 25: %+v", cur)
		}
		// A fresh process resumes from Postgres, not from the first step.
		c = newController()
		now = now.Add(SoakWindow + time.Minute)
		if err := c.Tick(ctx, h.tenantA, ch); err != nil {
			t.Fatal(err)
		}
		if cur := h.cursor(ch); cur.Cohort != 100 {
			t.Fatalf("restarted controller did not resume at 25 and widen to 100: %+v", cur)
		}
		queries := len(runner.seen)
		if err := c.Tick(ctx, h.tenantA, ch); err != nil {
			t.Fatal(err)
		}
		if cur := h.cursor(ch); cur.Cohort != 100 || cur.Halted != nil {
			t.Fatalf("100%% is terminal: %+v", cur)
		}
		if len(runner.seen) != queries {
			t.Fatalf("a terminal step ran %d health queries; there is no control arm to compare", len(runner.seen)-queries)
		}
	})

	var second Published
	t.Run("a_new_publication_starts_a_new_rollout", func(t *testing.T) {
		s := validSections()
		s.Gates.HourlyBlockCeiling = 7 // different content, so the rollback below is distinguishable from re-publishing seq 2
		second, err = h.mod.Publish(ctx, h.tenantA, Draft{Channel: ch, MaxAge: 15 * time.Minute, SectionsCBOR: mustEncode(t, s)})
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Tick(ctx, h.tenantA, ch); err != nil {
			t.Fatal(err)
		}
		if cur := h.cursor(ch); cur.Seq != second.Seq || cur.Cohort != 5 {
			t.Fatalf("cursor did not reset for seq %d: %+v", second.Seq, cur)
		}
	})

	t.Run("a_planted_M1E_3005_halts_and_rolls_back_the_prior_content", func(t *testing.T) {
		code := "M1E-3005"
		h.ack(ctx, h.deviceA1, ch, second.Seq, "rejected", &code)
		bundlesBefore := h.adminCount("policy_bundles")
		if err := c.Tick(ctx, h.tenantA, ch); err != nil {
			t.Fatal(err)
		}
		cur := h.cursor(ch)
		if cur.Seq != second.Seq || cur.Halted == nil || cur.Reason == nil || !strings.Contains(*cur.Reason, "M1E-3005") {
			t.Fatalf("no halt recorded: %+v", cur)
		}
		if cur.Rollback == nil || *cur.Rollback != second.Seq+1 || h.headSeq(ch) != second.Seq+1 {
			t.Fatalf("rollback is not the forward publication at seq+1: cursor %+v head %d", cur, h.headSeq(ch))
		}
		if h.adminCount("policy_bundles") != bundlesBefore+1 {
			t.Fatal("the halt published something other than exactly one rollback")
		}
		// THE ASSERTION THE LEDGER NEVER MADE: the rollback body IS the prior content.
		if !bytes.Equal(h.sectionsOf(ch, second.Seq+1), h.sectionsOf(ch, first.Seq)) {
			t.Fatal("rollback sections differ from seq 1's")
		}
		if bytes.Equal(h.sectionsOf(ch, second.Seq+1), h.sectionsOf(ch, second.Seq)) {
			t.Fatal("rollback republished the halted content")
		}
	})

	t.Run("a_halted_channel_stays_frozen", func(t *testing.T) {
		head := h.headSeq(ch)
		for i := 0; i < 3; i++ {
			if err := c.Tick(ctx, h.tenantA, ch); err != nil {
				t.Fatal(err)
			}
		}
		if cur := h.cursor(ch); cur.Seq != second.Seq || cur.Halted == nil || h.headSeq(ch) != head {
			t.Fatalf("a frozen channel moved: cursor %+v head %d", cur, h.headSeq(ch))
		}
	})

	var fix Published
	t.Run("a_fix_after_the_halt_is_not_bricked_by_the_historical_3005", func(t *testing.T) {
		fix, err = h.mod.Publish(ctx, h.tenantA, h.draft(ch))
		if err != nil {
			t.Fatal(err)
		}
		cov, err := h.mod.store.AckCoverage(ctx, h.tenantA, ch)
		if err != nil || cov.CommandString == 0 {
			t.Fatalf("the channel-lifetime tripwire should still be lit: %+v %v", cov, err)
		}
		if err := c.Tick(ctx, h.tenantA, ch); err != nil {
			t.Fatal(err)
		}
		if cur := h.cursor(ch); cur.Seq != fix.Seq || cur.Cohort != 5 || cur.Halted != nil {
			t.Fatalf("the fix's rollout was halted by a 3005 on a superseded seq: %+v", cur)
		}
	})

	t.Run("two_regressed_health_ticks_halt_through_the_real_templates", func(t *testing.T) {
		h.ack(ctx, h.deviceA1, ch, fix.Seq, "applied", nil)
		h.ack(ctx, h.deviceA2, ch, fix.Seq, "applied", nil)
		regressTick = true
		now = now.Add(SoakWindow + time.Minute)
		if err := c.Tick(ctx, h.tenantA, ch); err != nil {
			t.Fatal(err)
		}
		if cur := h.cursor(ch); cur.Ticks != 1 || cur.Cohort != 5 || cur.Halted != nil {
			t.Fatalf("one regressed tick must hold and count: %+v", cur)
		}
		now = now.Add(TickInterval)
		if err := c.Tick(ctx, h.tenantA, ch); err != nil {
			t.Fatal(err)
		}
		cur := h.cursor(ch)
		if cur.Halted == nil || cur.Reason == nil || !strings.Contains(*cur.Reason, "regressed") || cur.Rollback == nil {
			t.Fatalf("two regressed ticks did not halt: %+v", cur)
		}
		if !bytes.Equal(h.sectionsOf(ch, *cur.Rollback), h.sectionsOf(ch, fix.Seq-1)) {
			t.Fatal("health rollback did not carry the prior content")
		}
		ran := map[string]bool{}
		for _, q := range runner.seen {
			ran[q.Template().Name()] = true
		}
		for _, name := range healthSignals {
			if !ran[name] {
				t.Fatalf("the health input never ran the %s template: %v", name, ran)
			}
		}
	})

	t.Run("a_halt_interrupted_before_its_rollback_resumes", func(t *testing.T) {
		regressTick = false
		sixth, err := h.mod.Publish(ctx, h.tenantA, h.draft(ch))
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Tick(ctx, h.tenantA, ch); err != nil {
			t.Fatal(err)
		}
		// The crash: halt persisted, process died before Publish (05 §1.5 resumable).
		if err := h.db.WithTenant(ctx, h.tenantA, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE rollout_cursor SET halted_at = now(), halt_reason = 'planted crash' WHERE channel = $1 AND seq = $2`, ch, sixth.Seq)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if err := newController().Tick(ctx, h.tenantA, ch); err != nil {
			t.Fatal(err)
		}
		cur := h.cursor(ch)
		if cur.Rollback == nil || *cur.Rollback != sixth.Seq+1 || h.headSeq(ch) != sixth.Seq+1 {
			t.Fatalf("the resumed halt did not publish its rollback: %+v head %d", cur, h.headSeq(ch))
		}
		if !bytes.Equal(h.sectionsOf(ch, sixth.Seq+1), h.sectionsOf(ch, sixth.Seq-1)) {
			t.Fatal("resumed rollback did not carry the prior content")
		}
	})

	t.Run("save_is_a_compare_and_set", func(t *testing.T) {
		// The row is halted from the previous subtest: a sibling replica that computed a step from the pre-halt cursor must lose.
		live, _, err := c.load(ctx, h.tenantA, ch)
		if err != nil {
			t.Fatal(err)
		}
		stale := live
		stale.Halted = false
		if won, err := c.save(ctx, h.tenantA, ch, stale, stale); err != nil || won {
			t.Fatalf("a save over a halted row won (%v, %v)", won, err)
		}
		if err := h.db.WithTenant(ctx, h.tenantA, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE rollout_cursor SET halted_at = NULL, halt_reason = NULL, rollback_seq = NULL, cohort_percent = 25 WHERE channel = $1`, ch)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if won, err := c.save(ctx, h.tenantA, ch, stale, stale); err != nil || won {
			t.Fatalf("a save from a stale cohort step won (%v, %v)", won, err)
		}
		stale.Cohort = 25
		if won, err := c.save(ctx, h.tenantA, ch, stale, stale); err != nil || !won {
			t.Fatalf("a save from the live step lost (%v, %v)", won, err)
		}
	})

	t.Run("a_halt_at_seq_1_freezes_with_nothing_to_roll_back", func(t *testing.T) {
		only, err := h.mod.Publish(ctx, h.tenantA, h.draft("stable"))
		if err != nil {
			t.Fatal(err)
		}
		code := "M1E-3005"
		h.ack(ctx, h.deviceA1, "stable", only.Seq, "rejected", &code)
		for i := 0; i < 2; i++ {
			if err := c.Tick(ctx, h.tenantA, "stable"); err != nil {
				t.Fatalf("tick %d: %v", i, err)
			}
		}
		if cur := h.cursor("stable"); cur.Halted == nil || cur.Rollback != nil || h.headSeq("stable") != only.Seq {
			t.Fatalf("seq 1 halt: %+v head %d", cur, h.headSeq("stable"))
		}
	})

	t.Run("cursor_is_tenant_isolated", func(t *testing.T) {
		var n int64
		err := h.db.WithTenant(ctx, h.tenantB, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM rollout_cursor`).Scan(&n)
		})
		if err != nil || n != 0 || h.adminCount("rollout_cursor") == 0 {
			t.Fatalf("tenant B sees %d cursor rows (admin %d): %v", n, h.adminCount("rollout_cursor"), err)
		}
	})
}

// itHealthyRunner: the "nothing regressed" fake querychoke.Runner the promotion tests share.
func itHealthyRunner() *fakeRunner {
	return &fakeRunner{rows: func(querychoke.Query) *querychoke.Rows {
		return &querychoke.Rows{Columns: []string{"arm", "n", "d"}, Rows: []map[string]any{
			{"arm": "cohort", "n": uint64(10), "d": uint64(1000)},
			{"arm": "control", "n": uint64(10), "d": uint64(1000)},
		}}
	}}
}

// TestIntegrationRolloutPromotion: canary at 100% held clean through one more soak forward-publishes onto stable exactly once (05 §4.3 item 1).
func TestIntegrationRolloutPromotion(t *testing.T) {
	h := itSetup(t)
	ctx := context.Background()

	now := time.Now()
	salt := func(uuid.UUID) ([]byte, error) { return []byte("it-salt"), nil }
	c := NewController(h.mod, itHealthyRunner(), querychoke.MustLoadTemplates(), salt, receipts.StaticTenants([]uuid.UUID{h.tenantAID}))
	c.Clock(func() time.Time { return now }, nil)

	first, err := h.mod.Publish(ctx, h.tenantA, h.draft(CanaryChannel))
	if err != nil {
		t.Fatal(err)
	}
	h.ack(ctx, h.deviceA1, CanaryChannel, first.Seq, "applied", nil)
	h.ack(ctx, h.deviceA2, CanaryChannel, first.Seq, "applied", nil)

	// The first tick has no prior cursor, so it SEEDS the ladder at 5% rather than widening from it (same as TestIntegrationRolloutController).
	if err := c.Tick(ctx, h.tenantA, CanaryChannel); err != nil {
		t.Fatal(err)
	}
	if cur := h.cursor(CanaryChannel); cur.Cohort != 5 {
		t.Fatalf("first tick did not seed at 5%%: %+v", cur)
	}
	for _, want := range []int64{25, 100} {
		now = now.Add(SoakWindow + time.Minute)
		if err := c.Tick(ctx, h.tenantA, CanaryChannel); err != nil {
			t.Fatal(err)
		}
		if cur := h.cursor(CanaryChannel); cur.Cohort != want {
			t.Fatalf("did not widen to %d%%: %+v", want, cur)
		}
	}
	if h.headSeq(BootstrapChannel) != -1 {
		t.Fatal("stable must not exist yet -- nothing has promoted")
	}

	// At 100% but the soak since reaching it has not elapsed: no promotion.
	now = now.Add(time.Minute)
	if err := c.Tick(ctx, h.tenantA, CanaryChannel); err != nil {
		t.Fatal(err)
	}
	if cur := h.cursor(CanaryChannel); cur.Promoted != nil {
		t.Fatalf("promoted before the soak at 100%% elapsed: %+v", cur)
	}

	// The soak at 100% elapses cleanly: promotion.
	now = now.Add(SoakWindow)
	if err := c.Tick(ctx, h.tenantA, CanaryChannel); err != nil {
		t.Fatal(err)
	}
	cur := h.cursor(CanaryChannel)
	if cur.Promoted == nil || h.headSeq(BootstrapChannel) != *cur.Promoted {
		t.Fatalf("promotion did not land on stable: cursor %+v stable head %d", cur, h.headSeq(BootstrapChannel))
	}
	if !bytes.Equal(h.sectionsOf(BootstrapChannel, *cur.Promoted), h.sectionsOf(CanaryChannel, first.Seq)) {
		t.Fatal("promoted content differs from the canary head's sections")
	}

	// Idempotent: re-ticking, even repeatedly, never promotes a second time.
	promoted := *cur.Promoted
	for i := 0; i < 3; i++ {
		now = now.Add(TickInterval)
		if err := c.Tick(ctx, h.tenantA, CanaryChannel); err != nil {
			t.Fatal(err)
		}
	}
	if got := h.cursor(CanaryChannel); got.Promoted == nil || *got.Promoted != promoted {
		t.Fatalf("promoted_seq moved on a re-tick: %+v", got)
	}
	if h.headSeq(BootstrapChannel) != promoted {
		t.Fatalf("stable head advanced past the single promotion: %d, want %d", h.headSeq(BootstrapChannel), promoted)
	}
	if h.adminCount("policy_bundles") != 2 {
		t.Fatalf("promotion published %d bundles total (canary head + one promotion), want exactly 2", h.adminCount("policy_bundles"))
	}
}

// TestIntegrationRolloutHaltNeverPromotes: a halted rollout never forward-publishes to stable, however long it sits (05 §4.3 item 3).
func TestIntegrationRolloutHaltNeverPromotes(t *testing.T) {
	h := itSetup(t)
	ctx := context.Background()

	now := time.Now()
	salt := func(uuid.UUID) ([]byte, error) { return []byte("it-salt"), nil }
	c := NewController(h.mod, itHealthyRunner(), querychoke.MustLoadTemplates(), salt, receipts.StaticTenants([]uuid.UUID{h.tenantAID}))
	c.Clock(func() time.Time { return now }, nil)

	first, err := h.mod.Publish(ctx, h.tenantA, h.draft(CanaryChannel))
	if err != nil {
		t.Fatal(err)
	}
	code := "M1E-3005"
	h.ack(ctx, h.deviceA1, CanaryChannel, first.Seq, "rejected", &code)

	if err := c.Tick(ctx, h.tenantA, CanaryChannel); err != nil {
		t.Fatal(err)
	}
	if cur := h.cursor(CanaryChannel); cur.Halted == nil || cur.Promoted != nil {
		t.Fatalf("expected an immediate halt with no promotion: %+v", cur)
	}

	// Time keeps passing well past any soak window
	for i := 0; i < 3; i++ {
		now = now.Add(SoakWindow + time.Minute)
		if err := c.Tick(ctx, h.tenantA, CanaryChannel); err != nil {
			t.Fatal(err)
		}
	}
	if cur := h.cursor(CanaryChannel); cur.Promoted != nil {
		t.Fatalf("a halted rollout promoted after enough ticks: %+v", cur)
	}
	if h.headSeq(BootstrapChannel) != -1 {
		t.Fatal("a halted rollout must never publish anything to stable")
	}
}
