package policydist

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
)

// TestRolloutStepSequence drives the pure transition through a fake ledger: 05 §4.3's widen ladder, then each halt shape.
func TestRolloutStepSequence(t *testing.T) {
	t0 := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	healthy := Coverage{HeadSeq: 4, ActiveDevices: 100, OnHead: 97}
	cur := cursor{Seq: 4, Cohort: 5, StepStarted: t0}

	next, d, _ := step(healthy, cur, false, t0.Add(10*time.Minute))
	if d != DecisionHold || next.Cohort != 5 {
		t.Fatalf("mid-soak: %s %+v", d, next)
	}
	next, d, _ = step(healthy, cur, false, t0.Add(SoakWindow))
	if d != DecisionWiden || next.Cohort != 25 || !next.StepStarted.Equal(t0.Add(SoakWindow)) {
		t.Fatalf("first widen: %s %+v", d, next)
	}
	cur = next
	next, d, _ = step(healthy, cur, false, cur.StepStarted.Add(SoakWindow))
	if d != DecisionWiden || next.Cohort != 100 {
		t.Fatalf("second widen: %s %+v", d, next)
	}
	next, d, _ = step(healthy, next, false, next.StepStarted.Add(24*time.Hour))
	if d != DecisionHold || next.Cohort != 100 {
		t.Fatalf("terminal: %s %+v", d, next)
	}

	// (a) one M1E-3005 halts from any step, soak or no soak.
	bad := healthy
	bad.CommandString = 1
	next, d, why := step(bad, cur, false, cur.StepStarted)
	if d != DecisionHalt || !next.Halted || !strings.Contains(next.HaltReason, "M1E-3005") || next.HaltReason != why {
		t.Fatalf("3005: %s %+v", d, next)
	}

	// (c) one regressed tick holds a widen and counts; a clean tick resets; two consecutive halt.
	soaked := cur.StepStarted.Add(SoakWindow)
	next, d, _ = step(healthy, cur, true, soaked)
	if d != DecisionHold || next.HealthTicks != 1 || next.Cohort != 25 {
		t.Fatalf("one regressed tick: %s %+v", d, next)
	}
	clean, d, _ := step(healthy, next, false, soaked)
	if d != DecisionWiden || clean.HealthTicks != 0 {
		t.Fatalf("clean tick after one regressed: %s %+v", d, clean)
	}
	if held, d, _ := step(healthy, next, false, cur.StepStarted); d != DecisionHold || held.HealthTicks != 0 {
		t.Fatalf("a clean HOLD tick must also reset the counter: %s %+v", d, held)
	}
	next, d, _ = step(healthy, next, true, soaked)
	if d != DecisionHalt || next.HealthTicks != 2 || !strings.Contains(next.HaltReason, "regressed") {
		t.Fatalf("two regressed ticks: %s %+v", d, next)
	}
}

func TestRegressedSignal(t *testing.T) {
	base := arms{cohort: arm{10, 1000}, control: arm{10, 1000}}
	cases := []struct {
		name string
		cur  arms
		want bool
	}{
		{"no cohort data is no evidence", arms{control: arm{1, 100}}, false},
		{"cohort tracks control", arms{cohort: arm{1, 100}, control: arm{1, 100}}, false},
		{"cohort 5x control over 1000 events", arms{cohort: arm{50, 1000}, control: arm{10, 1000}}, true},
		{"cohort below control", arms{cohort: arm{0, 1000}, control: arm{10, 1000}}, false},
		// σ here is sqrt(0.01/1000 + 0.01/1000) = 0.00447: 16 is +1.3σ, 22 is +2.7σ.
		{"between 1σ and 2σ holds", arms{cohort: arm{16, 1000}, control: arm{10, 1000}}, false},
		{"between 2σ and 4σ regresses", arms{cohort: arm{22, 1000}, control: arm{10, 1000}}, true},
		{"a numerator over a zero denominator is garbage, not +Inf regression", arms{cohort: arm{5, 0}, control: arm{10, 1000}}, false},
	}
	for _, tc := range cases {
		if got := regressedSignal(tc.cur, base); got != tc.want {
			t.Fatalf("%s: regressed = %v", tc.name, got)
		}
	}
	if !regressedSignal(arms{cohort: arm{1, 100}, control: arm{0, 100}}, arms{cohort: arm{0, 1000}, control: arm{0, 1000}}) {
		t.Fatal("a rise over a zero baseline has σ = 0 and must read as a regression")
	}
	if regressedSignal(arms{cohort: arm{1, 100}, control: arm{0, 100}}, arms{}) {
		t.Fatal("no baseline is no evidence")
	}
}

type fakeRunner struct {
	seen []querychoke.Query
	rows func(q querychoke.Query) *querychoke.Rows
}

func (f *fakeRunner) Run(_ context.Context, q querychoke.Query) (*querychoke.Rows, error) {
	f.seen = append(f.seen, q)
	return f.rows(q), nil
}

// TestHealthArmsUseTheRealTemplates renders each 05 §4.3(c) template through the real registry and reads the arms back positionally.
func TestHealthArmsUseTheRealTemplates(t *testing.T) {
	reg := querychoke.MustLoadTemplates()
	tenant := testTenant(t, uuid.New().String())
	fr := &fakeRunner{rows: func(q querychoke.Query) *querychoke.Rows {
		cols := []string{"arm", "n", "d"}
		return &querychoke.Rows{Columns: cols, Rows: []map[string]any{
			{"arm": "cohort", "n": uint64(3), "d": uint64(10)},
			{"arm": "control", "n": int64(1), "d": float64(20)},
		}}
	}}
	c := &Controller{runner: fr, tpl: reg}
	now := time.Now()
	for _, name := range healthSignals {
		tpl, err := reg.Lookup(name)
		if err != nil {
			t.Fatal(err)
		}
		got, err := c.arms(context.Background(), tenant, tpl, []uuid.UUID{uuid.New()}, now.Add(-TickInterval), now)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got.cohort != (arm{3, 10}) || got.control != (arm{1, 20}) {
			t.Fatalf("%s: arms = %+v", name, got)
		}
	}
	if len(fr.seen) != 3 {
		t.Fatalf("ran %d queries, want one per signal", len(fr.seen))
	}
	for i, q := range fr.seen {
		if q.Template().Name() != healthSignals[i] || !strings.Contains(q.SQL(), "tenant_id = {tid:UUID}") || q.Bind()["cohort"] == "" {
			t.Fatalf("query %d is not the rendered %s template: %s %v", i, healthSignals[i], q.SQL(), q.Bind())
		}
	}
}
