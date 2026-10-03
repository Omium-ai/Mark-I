package fabric

import (
	"bytes"
	"testing"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/hostprofile"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/verdict"
)

func recommendProfile() hostprofile.Profile {
	return hostprofile.Profile{HostID: "cem888", HostVersion: "2.0.1", OwnsExecution: true, OwnsConfigSurface: true, OwnsMemory: true, ArrestMode: hostprofile.Recommend, SuppliesIdentity: true, SchemaVersion: "m1p.v1"}
}

// TestRecommendModeNeverBlocks is FR-SPINE-044 at the gate: with a RECOMMEND
// profile, where ACT answers BLOCK below the knee the decision stays ALLOW,
// OnBlock never fires, no block is counted, and the verdict carries one
// ArrestRecommendation that OnRecommend also received, with the daemon's
// projected cost.
func TestRecommendModeNeverBlocks(t *testing.T) {
	g := blockableGate(t, stubReader{{1}: violatedEntry(false, false)})
	reg := hostprofile.NewRegistry()
	reg.Set(testSession, recommendProfile())
	g.Profiles = reg
	g.OnBlock = func([16]byte, [16]byte, verdict.KneeState, string) { t.Fatal("OnBlock fired in RECOMMEND mode") }
	g.OnArrest = func([16]byte, [16]byte, verdict.KneeState, string) { t.Fatal("OnArrest fired in RECOMMEND mode") }
	var got *m1pv1.ArrestRecommendation
	g.OnRecommend = func(session, task [16]byte, rec *m1pv1.ArrestRecommendation) { got = rec }
	g.ProjectedCost = func(_, _ [16]byte, attempts uint32, kind string) uint64 { return 1000 + uint64(attempts) }

	v := g.Answer(query(1, 0), testSession)
	if v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_ALLOW {
		t.Fatalf("RECOMMEND answered %v, want ALLOW", v.GetDecision())
	}
	rec := v.GetRecommendation()
	if rec == nil || got == nil || rec != got {
		t.Fatalf("the verdict's recommendation (%v) and OnRecommend's (%v) must be the same one", rec, got)
	}
	if rec.GetKind() != "stop_gate_block" || rec.GetKStarEstimate() != 2 || rec.GetProjectedCost() != 1002 {
		t.Fatalf("recommendation = %+v, want stop_gate_block at attempt 2 costing 1002", rec)
	}
	if !bytes.Equal(rec.GetSessionId(), testSession[:]) || len(rec.GetTaskId()) != 16 {
		t.Fatalf("recommendation does not name the session and task: %+v", rec)
	}
	if v.GetSystemMessage() != "" {
		t.Fatalf("RECOMMEND told the human: %q", v.GetSystemMessage())
	}
	// Nothing was counted as a block: a second query is still not capped
	// and still recommends rather than blocks.
	v2 := g.Answer(query(1, 0), testSession)
	if v2.GetDecision() != m1pv1.GateDecision_GATE_DECISION_ALLOW || v2.GetRecommendation() == nil {
		t.Fatalf("second answer %v recommendation=%v", v2.GetDecision(), v2.GetRecommendation())
	}
}

// TestRecommendModeAtTheKnee: the knee stop becomes a knee_arrest
// recommendation; OnArrest and the human's systemMessage stay silent.
func TestRecommendModeAtTheKnee(t *testing.T) {
	g := blockableGate(t, stubReader{{1}: violatedEntry(true, false)})
	reg := hostprofile.NewRegistry()
	reg.Set(testSession, recommendProfile())
	g.Profiles = reg
	g.OnArrest = func([16]byte, [16]byte, verdict.KneeState, string) { t.Fatal("OnArrest fired in RECOMMEND mode") }
	var got *m1pv1.ArrestRecommendation
	g.OnRecommend = func(_, _ [16]byte, rec *m1pv1.ArrestRecommendation) { got = rec }

	v := g.Answer(query(1, 0), testSession)
	if v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_ALLOW || v.GetSystemMessage() != "" {
		t.Fatalf("knee in RECOMMEND: %v %q", v.GetDecision(), v.GetSystemMessage())
	}
	if got == nil || got.GetKind() != "knee_arrest" || got.GetKStarEstimate() != 2 {
		t.Fatalf("recommendation = %+v, want knee_arrest at attempt 2", got)
	}
}

// TestActModeIsUnchangedByTheRegistry is FR-SPINE-043: a session that
// declared nothing (Default) and one that declared ACT answer exactly as
// before — BLOCK below the knee, OnBlock fired, no recommendation anywhere.
func TestActModeIsUnchangedByTheRegistry(t *testing.T) {
	for _, name := range []string{"default", "declared-act"} {
		t.Run(name, func(t *testing.T) {
			g := blockableGate(t, stubReader{{1}: violatedEntry(false, false)})
			reg := hostprofile.NewRegistry()
			if name == "declared-act" {
				p := recommendProfile()
				p.ArrestMode = hostprofile.Act
				reg.Set(testSession, p)
			}
			g.Profiles = reg
			blocked := false
			g.OnBlock = func([16]byte, [16]byte, verdict.KneeState, string) { blocked = true }
			g.OnRecommend = func(_, _ [16]byte, rec *m1pv1.ArrestRecommendation) {
				t.Fatalf("OnRecommend fired in ACT mode: %+v", rec)
			}
			v := g.Answer(query(1, 0), testSession)
			if v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_BLOCK || !blocked || v.GetRecommendation() != nil {
				t.Fatalf("ACT answered %v blocked=%v rec=%v", v.GetDecision(), blocked, v.GetRecommendation())
			}
		})
	}
}
