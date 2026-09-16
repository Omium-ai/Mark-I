//go:build integration

// The draft publisher against the real schema (m1_070 bundle_drafts + m1_042's
// catalog): a compiler-emitted draft becomes seq 1 with the canary plan attached,
// identical content settles against the head without a new seq, a command
// string is refused and never mints a seq, the knee gate and the hash are
// honoured, a claimed draft stays with its claimant until the lease expires,
// and tenant B's publisher cannot see tenant A's drafts. Same harness, same
// NOBYPASSRLS role, as integration_test.go.

package policydist

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/receipts"
)

type itDraft struct {
	State     string
	Reason    *string
	Seq       *int64
	Plan      []byte
	ClaimedAt *time.Time
}

func (h *itHarness) draftRow(tenant uuid.UUID, channel string, window time.Time) itDraft {
	h.t.Helper()
	var d itDraft
	if err := h.admin.QueryRow(context.Background(),
		`SELECT state, refusal_reason, published_seq, canary_plan, claimed_at FROM bundle_drafts WHERE tenant_id = $1 AND channel = $2 AND window_start = $3`,
		tenant, channel, window).Scan(&d.State, &d.Reason, &d.Seq, &d.Plan, &d.ClaimedAt); err != nil {
		h.t.Fatal(err)
	}
	return d
}

func (h *itHarness) insertDraft(tenant uuid.UUID, window time.Time, d draft, claimedAt *time.Time) {
	h.t.Helper()
	if _, err := h.admin.Exec(context.Background(), `
		INSERT INTO bundle_drafts (tenant_id, channel, window_start, verify_cbor, route_cbor, memory_cbor, cortex_cbor,
		                           gates_cbor, agent_maps_cbor, draft_hash, max_age, knee_gate_ok, knee_note, claimed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, make_interval(secs => $11), $12, $13, $14)`,
		tenant, d.Channel, window, d.Sections["verify"], d.Sections["route"], d.Sections["memory"], d.Sections["cortex"],
		d.Sections["gates"], d.Sections["agent_maps"], d.Hash, d.MaxAge.Seconds(), d.KneeOK, d.KneeNote, claimedAt); err != nil {
		h.t.Fatal(err)
	}
}

func TestIntegrationDraftPublisher(t *testing.T) {
	h := itSetup(t)
	ctx := context.Background()
	const ch = "canary"
	window := func(day int) time.Time { return time.Date(2026, 9, day, 0, 0, 0, 0, time.UTC) }

	now := time.Now()
	runner := &fakeRunner{rows: func(q querychoke.Query) *querychoke.Rows {
		return &querychoke.Rows{Columns: []string{"arm", "n", "d"}, Rows: []map[string]any{
			{"arm": "cohort", "n": uint64(1), "d": uint64(100)}, {"arm": "control", "n": uint64(1), "d": uint64(100)},
		}}
	}}
	salt := func(uuid.UUID) ([]byte, error) { return []byte("it-salt"), nil }
	ctrl := NewController(h.mod, runner, querychoke.MustLoadTemplates(), salt, receipts.StaticTenants([]uuid.UUID{h.tenantAID, h.tenantBID}))
	ctrl.Clock(func() time.Time { return now }, nil)
	pub := NewDraftPublisher(ctrl)
	pub.Clock(func() time.Time { return now }, nil)

	compiled := readCompilerFixture(t)

	t.Run("compiler_draft_publishes_at_seq_1_with_the_canary_plan", func(t *testing.T) {
		h.insertDraft(h.tenantAID, window(1), draftOf(t, compiled, ch), nil)
		if err := pub.RunOnce(ctx); err != nil {
			t.Fatal(err)
		}
		row := h.draftRow(h.tenantAID, ch, window(1))
		if row.State != "published" || row.Seq == nil || *row.Seq != 1 || row.Reason != nil {
			t.Fatalf("draft after tick: %+v", row)
		}
		if h.headSeq(ch) != 1 || string(h.sectionsOf(ch, 1)) != string(compiled) {
			t.Fatalf("head %d; published sections are not the compiler's bytes", h.headSeq(ch))
		}
		var plan CanaryPlan
		if err := json.Unmarshal(row.Plan, &plan); err != nil {
			t.Fatalf("canary_plan: %v (%s)", err, row.Plan)
		}
		if plan.Seq != 1 || plan.CanaryCohort.Percent != WidenSteps[0] || plan.WidenCriteria.AckCoverageMin != WidenCoverage || plan.Rollback == "" {
			t.Fatalf("plan: %+v", plan)
		}
		// The cohort is the controller's own assignment over the active fleet (06 §10.4: the OPE unit).
		want := 0
		for _, dev := range []uuid.UUID{h.deviceA1, h.deviceA2} {
			if InCohort([]byte("it-salt"), dev, WidenSteps[0]) {
				want++
			}
		}
		if len(plan.CanaryCohort.Devices) != want {
			t.Fatalf("cohort devices %v, want %d of A1/A2", plan.CanaryCohort.Devices, want)
		}
		if h.adminCount("policy_bundles") != 1 || h.adminCount("tlog_leaves") != 1 {
			t.Fatalf("publication must land in the catalog and the log exactly once")
		}
	})

	t.Run("identical_content_settles_against_the_head_without_a_new_seq", func(t *testing.T) {
		h.insertDraft(h.tenantAID, window(2), draftOf(t, compiled, ch), nil)
		if err := pub.Tick(ctx, h.tenantA); err != nil {
			t.Fatal(err)
		}
		row := h.draftRow(h.tenantAID, ch, window(2))
		if row.State != "published" || row.Seq == nil || *row.Seq != 1 || row.Plan != nil {
			t.Fatalf("unchanged draft: %+v", row)
		}
		if h.headSeq(ch) != 1 || h.adminCount("policy_bundles") != 1 {
			t.Fatal("identical content must not republish")
		}
	})

	t.Run("command_string_is_refused_and_mints_no_seq", func(t *testing.T) {
		evil := validSections()
		evil.Route.CPVS[0].ModelID = "claude; rm -rf /"
		h.insertDraft(h.tenantAID, window(3), draftOfUnchecked(t, evil, ch), nil)
		if err := pub.Tick(ctx, h.tenantA); err != nil {
			t.Fatal(err)
		}
		row := h.draftRow(h.tenantAID, ch, window(3))
		if row.State != "refused" || row.Reason == nil || !strings.Contains(*row.Reason, "M1E-3005") || row.Seq != nil {
			t.Fatalf("command-string draft: %+v", row)
		}
		if h.headSeq(ch) != 1 || h.adminCount("policy_bundles") != 1 {
			t.Fatal("a refused draft burned a seq")
		}
	})

	t.Run("knee_gate_and_hash_are_honoured", func(t *testing.T) {
		gated := draftOfUnchecked(t, validSections(), ch)
		gated.KneeOK, gated.KneeNote = false, "implied knee 2 vs k*=4: VIOLATED"
		h.insertDraft(h.tenantAID, window(4), gated, nil)
		forged := draftOfUnchecked(t, validSections(), ch)
		forged.Hash[3] ^= 0x01
		h.insertDraft(h.tenantAID, window(5), forged, nil)
		if err := pub.Tick(ctx, h.tenantA); err != nil {
			t.Fatal(err)
		}
		if row := h.draftRow(h.tenantAID, ch, window(4)); row.State != "refused" || !strings.Contains(*row.Reason, "VIOLATED") {
			t.Fatalf("knee-gated draft: %+v", row)
		}
		if row := h.draftRow(h.tenantAID, ch, window(5)); row.State != "refused" || !strings.Contains(*row.Reason, "draft_hash") {
			t.Fatalf("forged-hash draft: %+v", row)
		}
		if h.headSeq(ch) != 1 {
			t.Fatal("a refused draft burned a seq")
		}
	})

	t.Run("a_claimed_draft_waits_for_the_lease_then_publishes_forward", func(t *testing.T) {
		claimed := now
		h.insertDraft(h.tenantAID, window(6), draftOfUnchecked(t, validSections(), ch), &claimed)
		if err := pub.Tick(ctx, h.tenantA); err != nil {
			t.Fatal(err)
		}
		if row := h.draftRow(h.tenantAID, ch, window(6)); row.State != "pending" {
			t.Fatalf("a sibling's claim was stolen inside the lease: %+v", row)
		}
		now = now.Add(draftLease + time.Second)
		if err := pub.Tick(ctx, h.tenantA); err != nil {
			t.Fatal(err)
		}
		row := h.draftRow(h.tenantAID, ch, window(6))
		if row.State != "published" || row.Seq == nil || *row.Seq != 2 || row.ClaimedAt == nil || !row.ClaimedAt.Equal(now.Truncate(time.Microsecond)) {
			t.Fatalf("after lease expiry: %+v", row)
		}
		if h.headSeq(ch) != 2 {
			t.Fatalf("head %d, want the forward publication at 2", h.headSeq(ch))
		}
	})

	t.Run("rls_keeps_tenant_b_off_tenant_a_drafts", func(t *testing.T) {
		h.insertDraft(h.tenantAID, window(7), draftOf(t, compiled, ch), nil)
		if err := pub.Tick(ctx, h.tenantB); err != nil {
			t.Fatal(err)
		}
		if row := h.draftRow(h.tenantAID, ch, window(7)); row.State != "pending" || row.ClaimedAt != nil {
			t.Fatalf("tenant B's tick touched tenant A's draft: %+v", row)
		}
		var pending int64
		if err := h.admin.QueryRow(ctx, `SELECT count(*) FROM bundle_drafts WHERE state = 'pending'`).Scan(&pending); err != nil || pending != 1 {
			t.Fatalf("admin sees %d pending (%v); the zero above must be RLS, not emptiness", pending, err)
		}
	})
}
