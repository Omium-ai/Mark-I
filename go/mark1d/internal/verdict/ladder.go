package verdict

import m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"

// Rung mirrors policy.Rung: KeepPrefix says this rung's context rides into the next on escalation (06 §10.2).
type Rung struct {
	ModelID    string
	KeepPrefix bool
}

// Ladder mirrors policy.Ladder, rungs cheapest→strongest; a single rung is 04 §2.3's built-in.
type Ladder struct {
	ID    string
	Rungs []Rung
}

type LadderAction uint8

const (
	LadderStay LadderAction = iota
	LadderEscalate
	LadderExhausted
)

// LadderStep is the rung in force after the step; KeepPrefix is set on LadderEscalate only.
type LadderStep struct {
	Action     LadderAction
	ModelID    string
	KeepPrefix bool
}

// Step climbs one rung exactly when the gate forces continuation: VIOLATED below the knee (ε=0, first match).
func (l Ladder) Step(current string, v m1pv1.Verdict, k KneeState) LadderStep {
	stay := LadderStep{Action: LadderStay, ModelID: current}
	if k.Stale || k.Stop || v != m1pv1.Verdict_VERDICT_VIOLATED {
		return stay
	}
	for i, r := range l.Rungs {
		if r.ModelID != current {
			continue
		}
		if i+1 == len(l.Rungs) {
			return LadderStep{Action: LadderExhausted, ModelID: current}
		}
		return LadderStep{Action: LadderEscalate, ModelID: l.Rungs[i+1].ModelID, KeepPrefix: r.KeepPrefix}
	}
	return stay
}

// LadderStep steps the first bundle ladder naming current (the proxy RouteTable rule); an unlisted model stays.
func (m *BundleMatrices) LadderStep(current string, v m1pv1.Verdict, k KneeState) LadderStep {
	for _, l := range m.Ladders {
		for _, r := range l.Rungs {
			if r.ModelID == current {
				return l.Step(current, v, k)
			}
		}
	}
	return LadderStep{Action: LadderStay, ModelID: current}
}
