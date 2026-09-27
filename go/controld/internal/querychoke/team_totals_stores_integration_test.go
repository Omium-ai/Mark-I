//go:build integration

package querychoke_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/chproj"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

type teamViewer struct{}

func (teamViewer) Viewer(context.Context, querychoke.TenantID, auth.Claims) (querychoke.Viewer, error) {
	return querychoke.Viewer{Team: true, Devices: []uuid.UUID{uuid.New()}}, nil
}

// team_device_totals.v2 over the real projection: one row per device with app_sessions' counting rules (a replayed batch counted once), another tenant's rows absent, and a team member's scoped read refused unless the caller marked it TenantWide.
func TestIntegrationTeamDeviceTotals(t *testing.T) {
	r := setupApp(t)
	tenant, other := uuid.New(), uuid.New()
	a, b := plant(t, r, tenant, 100), plant(t, r, tenant, 7)
	plant(t, r, other, 987_654)
	tid, err := querychoke.FromClaims(auth.Claims{TenantID: tenant})
	if err != nil {
		t.Fatal(err)
	}
	tpl, err := r.reg.Lookup("team_device_totals")
	if err != nil {
		t.Fatal(err)
	}
	today := time.Now().UTC()
	q, err := querychoke.Build(tid, tpl, querychoke.Params{"from": today.AddDate(0, 0, -2), "to": today})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := r.runner.Run(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]map[string]any{}
	for _, row := range rows.Rows {
		got[row["device_id"].(uuid.UUID).String()] = row
	}
	if len(got) != 2 {
		t.Fatalf("want one row per device of this tenant, got %v", rows.Rows)
	}
	for _, p := range []planted{a, b} {
		row := got[p.device.String()]
		if row["sessions"] != uint64(1) || row["tasks_verified"] != uint64(2) || row["tokens"] != p.tokens+35 || row["tokens_saved"] != int64(0) {
			t.Fatalf("device %s: %v", p.device, row)
		}
	}

	claims := auth.Claims{TenantID: tenant, DeviceID: uuid.New()}
	scoped := querychoke.Scoped(r.runner, teamViewer{})
	if _, err := scoped.Run(auth.WithClaims(context.Background(), claims), q); !errors.Is(err, querychoke.ErrTeamScope) {
		t.Fatalf("a member's scoped read of a deviceless template must refuse, got %v", err)
	}
	if _, err := scoped.Run(querychoke.TenantWide(auth.WithClaims(context.Background(), claims)), q); err != nil {
		t.Fatalf("TenantWide read: %v", err)
	}
}

// savings.v2's net on the Sessions row and the team totals (doc 16 ruling 4): a block on a task that then resolved credits its estimate, usage after a block on a task that did not debits, usage before a block and arrests never count.
func TestIntegrationSessionAndTeamSavedAreTheNet(t *testing.T) {
	r := setupApp(t)
	ctx := context.Background()
	tenant, device := uuid.New(), uuid.New()
	session, fixed, failed := uuid.Must(uuid.NewV7()), uuid.New(), uuid.New()
	at := time.Now().UTC().Add(-2 * time.Hour)
	idem := func(b byte) []byte { k := make([]byte, 32); k[0] = b; return k }
	ev := func(seq uint64, task uuid.UUID, body any) *m1pv1.Event { return evFor(t, session, at, seq, task, body) }
	block := func(saved uint64) *m1pv1.GuardDecision {
		return &m1pv1.GuardDecision{Outcome: m1pv1.GuardOutcome_GUARD_OUTCOME_REFUSED, SampleRate: 1, ReasonCode: "stop_gate_block", TokensSavedEstimate: saved}
	}
	batchID := uuid.Must(uuid.NewV7())
	batch := &m1pv1.Batch{BatchId: batchID[:], SessionId: session[:], Sdk: &m1pv1.SdkInfo{Agent: "claudecode"}, SentAt: timestamppb.New(at), Events: []*m1pv1.Event{
		ev(1, uuid.Nil, &m1pv1.SessionStart{Agent: "claudecode"}),
		ev(2, fixed, &m1pv1.TaskOpen{TaskSegVersion: "task_seg.v1"}),
		ev(3, fixed, block(500)),
		ev(4, fixed, &m1pv1.Usage{IdemKey: idem(1), Model: "m", InputTokens: 300}),
		ev(5, fixed, &m1pv1.VerdictEvent{Stage: m1pv1.VerdictStage_VERDICT_STAGE_CERTIFIED, Verdict: m1pv1.Verdict_VERDICT_SATISFIED, Posterior: []float64{0.9, 0.05, 0.03, 0.02}}),
		ev(6, failed, &m1pv1.TaskOpen{TaskSegVersion: "task_seg.v1"}),
		ev(7, failed, &m1pv1.Usage{IdemKey: idem(2), Model: "m", InputTokens: 1000}),
		ev(8, failed, block(400)),
		ev(9, failed, &m1pv1.Usage{IdemKey: idem(3), Model: "m", InputTokens: 250}),
		ev(10, failed, &m1pv1.GuardDecision{Outcome: m1pv1.GuardOutcome_GUARD_OUTCOME_REFUSED, SampleRate: 1, ReasonCode: "knee_arrest", TokensSavedEstimate: 9000}),
		ev(11, failed, &m1pv1.VerdictEvent{Stage: m1pv1.VerdictStage_VERDICT_STAGE_CERTIFIED, Verdict: m1pv1.Verdict_VERDICT_VIOLATED, Posterior: []float64{0.1, 0.8, 0.05, 0.05}}),
	}}
	if err := r.ingest.InsertRows(ctx, chproj.Table, chproj.Columns, chproj.RowsFromBatch(batch, tenant, device, at)); err != nil {
		t.Fatal(err)
	}
	tid, _ := querychoke.FromClaims(auth.Claims{TenantID: tenant})
	today := time.Now().UTC()
	for name, want := range map[string]int64{"app_sessions": 250, "team_device_totals": 250} {
		tpl, err := r.reg.Lookup(name)
		if err != nil {
			t.Fatal(err)
		}
		q, err := querychoke.Build(tid, tpl, querychoke.Params{"from": today.AddDate(0, 0, -2), "to": today})
		if err != nil {
			t.Fatal(err)
		}
		rows, err := r.runner.Run(ctx, q)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(rows.Rows) != 1 || rows.Rows[0]["tokens_saved"] != want {
			t.Fatalf("%s: want tokens_saved %d (credit 500 − debit 250), got %v", name, want, rows.Rows)
		}
	}
}

// ADR-0013 over the real projection: a past window's block resolves on a verdict dated after the window (the weekly digest's Sunday block, Monday's verdict), while sessions, tokens and tasks_verified stay inside [from, to]; the savings read takes the decision's cost_basis from the projected payload.
func TestIntegrationPastWindowSavingsResolveThroughToday(t *testing.T) {
	r := setupApp(t)
	ctx := context.Background()
	tenant, device := uuid.New(), uuid.New()
	session, task := uuid.Must(uuid.NewV7()), uuid.New()
	today := time.Now().UTC().Truncate(24 * time.Hour)
	in, after := today.AddDate(0, 0, -4).Add(10*time.Hour), today.AddDate(0, 0, -1).Add(10*time.Hour)
	idem := func(b byte) []byte { k := make([]byte, 32); k[0] = b; return k }
	events := []*m1pv1.Event{
		evFor(t, session, in, 1, uuid.Nil, &m1pv1.SessionStart{Agent: "claudecode"}),
		evFor(t, session, in, 2, task, &m1pv1.TaskOpen{TaskSegVersion: "task_seg.v1"}),
		evFor(t, session, in, 3, task, &m1pv1.Usage{IdemKey: idem(1), Model: "m", InputTokens: 200}),
		evFor(t, session, in, 4, task, &m1pv1.GuardDecision{Outcome: m1pv1.GuardOutcome_GUARD_OUTCOME_BLOCKED, SampleRate: 1, ReasonCode: "stop_gate_block", TokensSavedEstimate: 400, CostBasis: "quota"}),
		evFor(t, session, in, 5, task, &m1pv1.Usage{IdemKey: idem(2), Model: "m", InputTokens: 300}),
		evFor(t, session, after, 6, task, &m1pv1.Usage{IdemKey: idem(3), Model: "m", InputTokens: 100}),
		evFor(t, session, after, 7, task, &m1pv1.VerdictEvent{Stage: m1pv1.VerdictStage_VERDICT_STAGE_CERTIFIED, Verdict: m1pv1.Verdict_VERDICT_SATISFIED, Posterior: []float64{0.9, 0.05, 0.03, 0.02}}),
	}
	for _, day := range []time.Time{in, after} {
		var batch []*m1pv1.Event
		for _, e := range events {
			if e.GetOccurredAt().AsTime().Truncate(24 * time.Hour).Equal(day.Truncate(24 * time.Hour)) {
				batch = append(batch, e)
			}
		}
		batchID := uuid.Must(uuid.NewV7())
		b := &m1pv1.Batch{BatchId: batchID[:], SessionId: session[:], Sdk: &m1pv1.SdkInfo{Agent: "claudecode"}, SentAt: timestamppb.New(day), Events: batch}
		if err := r.ingest.InsertRows(ctx, chproj.Table, chproj.Columns, chproj.RowsFromBatch(b, tenant, device, day)); err != nil {
			t.Fatal(err)
		}
	}
	tid, _ := querychoke.FromClaims(auth.Claims{TenantID: tenant})
	window := querychoke.Params{"from": today.AddDate(0, 0, -5), "to": today.AddDate(0, 0, -3)}
	run := func(name string) []map[string]any {
		tpl, err := r.reg.Lookup(name)
		if err != nil {
			t.Fatal(err)
		}
		q, err := querychoke.Build(tid, tpl, window)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := r.runner.Run(ctx, q)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return rows.Rows
	}
	team := run("team_device_totals")
	if len(team) != 1 || team[0]["tokens_saved"] != int64(400) || team[0]["tokens"] != uint64(500) || team[0]["tasks_verified"] != uint64(0) || team[0]["sessions"] != uint64(1) {
		t.Fatalf("want the block credited by the later verdict (+400), and only the window's 500 tokens, 1 session, 0 verified: %v", team)
	}
	sav := run("savings")
	if len(sav) != 1 || sav[0]["decision_basis"] != "quota" || sav[0]["fused_verdict"] != "satisfied" || sav[0]["fused_verdict_at_close"] != "" || sav[0]["post_block_tokens"] != uint64(400) || sav[0]["post_block_tokens_at_close"] != uint64(300) {
		t.Fatalf("savings row: %v", sav)
	}
}
