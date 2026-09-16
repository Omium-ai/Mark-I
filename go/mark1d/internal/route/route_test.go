package route

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/capture"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/tailers"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/verdict"
)

const fixtureRoot = "../../../../conformance/hooks/claudecode/v2.1.251"

// tail runs the real tailer over the committed corpus through an Emitter and
// returns everything released, in emission order. A fresh StateDir each call
// means no cursor: the second call is a full re-tail.
func tail(t *testing.T, seq uint64) []*m1pv1.Event {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(fixtureRoot, "transcripts", "expectations.json"))
	if err != nil {
		t.Fatalf("fixture missing (08 §5 rule 3: no fixture, no adapter): %v", err)
	}
	var exp struct {
		WorkspaceRoot string `json:"workspace_root"`
	}
	if err := json.Unmarshal(raw, &exp); err != nil {
		t.Fatal(err)
	}
	set, err := tailers.NewWorkspaceSet(exp.WorkspaceRoot)
	if err != nil {
		t.Fatal(err)
	}
	var got []*m1pv1.Event
	em := &Emitter{
		Next: func(_ context.Context, ev *m1pv1.Event) error {
			got = append(got, ev)
			return nil
		},
		Seq: func() uint64 { return seq },
	}
	mgr, err := tailers.NewManager(tailers.Config{
		Dir:          filepath.Join(fixtureRoot, "transcripts", "-home-devuser-workspace-acme-app"),
		StateDir:     t.TempDir(),
		Allowed:      set.Allowed,
		UsageIdemKey: []byte("m1p-usage-idem-TEST-KEY-32bytes!"),
		Emit:         em.Emit,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	mgr.Sweep(ctx)
	if err := mgr.CloseFlush(ctx); err != nil {
		t.Fatal(err)
	}
	return got
}

// TestRouteDecisionEmittedBesideEveryUsage: one RouteDecision directly after
// every Usage the tailer releases, describing that Usage honestly, under a
// deterministic identity a full re-tail re-derives byte-for-byte.
func TestRouteDecisionEmittedBesideEveryUsage(t *testing.T) {
	got := tail(t, 42)
	usages, ids := 0, map[string]bool{}
	for i, ev := range got {
		u := ev.GetUsage()
		if u == nil {
			if ev.GetRouteDecision() == nil {
				t.Fatalf("event %d: %T — the tailer emits only Usage; the decorator only RouteDecision", i, ev.GetBody())
			}
			continue
		}
		usages++
		if i+1 >= len(got) || got[i+1].GetRouteDecision() == nil {
			t.Fatalf("Usage %d (%s) has no RouteDecision beside it", i, u.GetMessageId())
		}
		rd, r := got[i+1], got[i+1].GetRouteDecision()
		if r.GetAction() != u.GetModel() || len(r.GetCandidates()) != 1 || r.GetCandidates()[0] != u.GetModel() {
			t.Fatalf("(%s): action %q candidates %v, want the Usage's model %q", u.GetMessageId(), r.GetAction(), r.GetCandidates(), u.GetModel())
		}
		if r.GetPropensity() != 1 || r.GetFidelity() != m1pv1.RouteFidelity_ROUTE_FIDELITY_ADVISORY || r.GetBundleSeq() != 42 {
			t.Fatalf("(%s): propensity %v fidelity %v bundle_seq %d, want 1.0 ADVISORY 42", u.GetMessageId(), r.GetPropensity(), r.GetFidelity(), r.GetBundleSeq())
		}
		if string(rd.GetSessionId()) != string(ev.GetSessionId()) || !proto.Equal(rd.GetOccurredAt(), ev.GetOccurredAt()) || rd.GetOccurredAt() == nil {
			t.Fatalf("(%s): RouteDecision must ride the Usage's session_id and occurred_at", u.GetMessageId())
		}
		id, err := uuid.FromBytes(rd.GetEventId())
		if err != nil || id.Version() != 7 || string(r.GetDecisionId()) != string(rd.GetEventId()) {
			t.Fatalf("(%s): event_id %x must be a UUIDv7 (stage 6) equal to decision_id", u.GetMessageId(), rd.GetEventId())
		}
		if ids[id.String()] {
			t.Fatalf("(%s): event_id %s reused across Usages", u.GetMessageId(), id)
		}
		ids[id.String()] = true
	}
	if usages == 0 || len(got) != 2*usages {
		t.Fatalf("%d events for %d Usages — want exactly one RouteDecision per Usage", len(got), usages)
	}
	// Re-tail from nothing: the same identities, so the ledger's replacing
	// merge collapses them the way the Usage beside each collapses on idem_key.
	for _, ev := range tail(t, 42) {
		if rd := ev.GetRouteDecision(); rd != nil && !ids[uuid.Must(uuid.FromBytes(ev.GetEventId())).String()] {
			t.Fatalf("re-tail minted a NEW RouteDecision identity %x — a duplicate row the ledger cannot collapse", ev.GetEventId())
		}
	}
}

// The RouteDecision is diagnostic class: an accounted shed or quarantine of
// the row must not fail the Usage that was already admitted; any other
// failure, and the Usage's own failure, propagate unchanged.
func TestEmitterSwallowsOnlyAccountedRouteFailures(t *testing.T) {
	sid := uuid.New()
	usage := &m1pv1.Event{SessionId: sid[:], Body: &m1pv1.Event_Usage{Usage: &m1pv1.Usage{Model: "m", IdemKey: make([]byte, 32)}}}
	boom := errors.New("boom")
	for _, tc := range []struct{ routeErr, want error }{
		{capture.ErrShed, nil}, {capture.ErrQuarantined, nil}, {boom, boom},
	} {
		em := &Emitter{Next: func(_ context.Context, ev *m1pv1.Event) error {
			if ev.GetRouteDecision() != nil {
				return tc.routeErr
			}
			return nil
		}}
		if err := em.Emit(context.Background(), usage); !errors.Is(err, tc.want) {
			t.Fatalf("route %v: got %v want %v", tc.routeErr, err, tc.want)
		}
	}
	em := &Emitter{Next: func(context.Context, *m1pv1.Event) error { return boom }}
	if err := em.Emit(context.Background(), usage); !errors.Is(err, boom) {
		t.Fatalf("Usage failure must propagate, got %v", err)
	}
	// No vendor timestamp ⇒ no deterministic clock ⇒ capture mints (nil id).
	if got := Decision(usage, 0).GetEventId(); got != nil {
		t.Fatalf("event_id without occurred_at = %x, want nil for capture to mint", got)
	}
}

// three is the bundle ladder every test below applies; its entry rung is what
// the proxy serves every rung with (RouteTable, FR-ROUTE-008).
var three = &verdict.BundleMatrices{Seq: 7, Ladders: []verdict.Ladder{{ID: "three", Rungs: []verdict.Rung{
	{ModelID: "claude-haiku-4-5", KeepPrefix: true}, {ModelID: "claude-sonnet-4-5"}, {ModelID: "claude-opus-4-1", KeepPrefix: true},
}}}}

func modelRequest(model, served, reqID string) *m1pv1.Event {
	sid := uuid.New()
	return &m1pv1.Event{SessionId: sid[:], OccurredAt: timestamppb.New(time.Unix(1_700_000_000, 0)),
		Body: &m1pv1.Event_ModelRequest{ModelRequest: &m1pv1.ModelRequest{RequestId: reqID, Model: model, ServedModel: served, Stream: true}}}
}

func usageFor(model, reqID string, task []byte) *m1pv1.Event {
	sid := uuid.New()
	return &m1pv1.Event{SessionId: sid[:], TaskId: task, OccurredAt: timestamppb.New(time.Unix(1_700_000_001, 0)),
		Body: &m1pv1.Event_Usage{Usage: &m1pv1.Usage{Model: model, RequestId: reqID, IdemKey: make([]byte, 32)}}}
}

func collect(em *Emitter) (*[]*m1pv1.Event, func(*m1pv1.Event) error) {
	got := &[]*m1pv1.Event{}
	em.Next = func(_ context.Context, ev *m1pv1.Event) error { *got = append(*got, ev); return nil }
	return got, func(ev *m1pv1.Event) error { return em.Emit(context.Background(), ev) }
}

// TestProxyModelRequestIsWireEnforcedAndSuppressesTheUsageTwin: FR-ROUTE-002's
// producer half. A proxy ModelRequest served by the ladder's entry rung yields
// exactly RouteDecision{served, rungs, 1.0, WIRE_ENFORCED, seq}; the Usage the
// tailer later releases for the same vendor request_id gets no ADVISORY twin.
func TestProxyModelRequestIsWireEnforcedAndSuppressesTheUsageTwin(t *testing.T) {
	em := &Emitter{Seq: func() uint64 { return 7 }, Matrices: func() *verdict.BundleMatrices { return three }}
	got, emit := collect(em)
	if err := emit(modelRequest("claude-opus-4-1", "claude-haiku-4-5", "req_1")); err != nil {
		t.Fatal(err)
	}
	if len(*got) != 2 || (*got)[1].GetRouteDecision() == nil {
		t.Fatalf("want ModelRequest then RouteDecision, got %d events", len(*got))
	}
	r := (*got)[1].GetRouteDecision()
	if r.GetAction() != "claude-haiku-4-5" || r.GetPropensity() != 1 || r.GetBundleSeq() != 7 ||
		r.GetFidelity() != m1pv1.RouteFidelity_ROUTE_FIDELITY_WIRE_ENFORCED ||
		len(r.GetCandidates()) != 3 || r.GetCandidates()[2] != "claude-opus-4-1" {
		t.Fatalf("wire row: %+v", r)
	}
	if id, err := uuid.FromBytes((*got)[1].GetEventId()); err != nil || id.Version() != 7 {
		t.Fatalf("event_id must be a UUIDv7, got %x", (*got)[1].GetEventId())
	}
	if !proto.Equal((*got)[1].GetOccurredAt(), (*got)[0].GetOccurredAt()) || string((*got)[1].GetSessionId()) != string((*got)[0].GetSessionId()) {
		t.Fatal("the row must ride the ModelRequest's session_id and occurred_at")
	}
	// Same request, tailed: the Usage passes, its ADVISORY twin does not.
	if err := emit(usageFor("claude-haiku-4-5", "req_1", nil)); err != nil {
		t.Fatal(err)
	}
	if len(*got) != 3 || (*got)[2].GetUsage() == nil {
		t.Fatalf("the enforced request's Usage grew an ADVISORY twin: %d events", len(*got))
	}
	// A different request still gets its ADVISORY row.
	if err := emit(usageFor("claude-haiku-4-5", "req_2", nil)); err != nil {
		t.Fatal(err)
	}
	if len(*got) != 5 || (*got)[4].GetRouteDecision().GetFidelity() != m1pv1.RouteFidelity_ROUTE_FIDELITY_ADVISORY {
		t.Fatalf("an unenforced request lost its ADVISORY row: %d events", len(*got))
	}
}

// TestModelRequestThatDidNotBindEmitsNothing: served ≠ entry rung (an older
// table, the off arm, an unrewritten dialect) or a model no ladder names —
// the wire did not bind, so no WIRE_ENFORCED row is fabricated.
func TestModelRequestThatDidNotBindEmitsNothing(t *testing.T) {
	em := &Emitter{Matrices: func() *verdict.BundleMatrices { return three }}
	got, emit := collect(em)
	for _, mr := range []*m1pv1.Event{
		modelRequest("claude-opus-4-1", "claude-opus-4-1", "req_3"),
		modelRequest("gpt-5", "gpt-5", "req_4"),
	} {
		if err := emit(mr); err != nil {
			t.Fatal(err)
		}
	}
	if len(*got) != 2 {
		t.Fatalf("unbound ModelRequests grew %d RouteDecisions", len(*got)-2)
	}
	if err := emit(usageFor("claude-opus-4-1", "req_3", nil)); err != nil {
		t.Fatal(err)
	}
	if len(*got) != 4 || (*got)[3].GetRouteDecision().GetFidelity() != m1pv1.RouteFidelity_ROUTE_FIDELITY_ADVISORY {
		t.Fatal("an unbound request's Usage must still describe itself as ADVISORY")
	}
}

type cache map[verdict.TaskID]verdict.Cached

func (c cache) Get(id verdict.TaskID) (verdict.Cached, bool) { e, ok := c[id]; return e, ok }

// TestUsageUnderALadderStepsOnABelowKneeViolation: the coordinator's row — a
// below-knee VIOLATED cached verdict on a 3-rung ladder makes the ADVISORY
// action the next rung; candidates are the ladder; the deterministic id is
// unchanged from the single-rung row's derivation.
func TestUsageUnderALadderStepsOnABelowKneeViolation(t *testing.T) {
	task := uuid.New()
	violated := cache{verdict.TaskID(task): {
		Verdict: &m1pv1.VerdictEvent{Verdict: m1pv1.Verdict_VERDICT_VIOLATED},
		Knee:    verdict.KneeState{N: 2, Evaluable: true},
	}}
	em := &Emitter{Seq: func() uint64 { return 7 }, Matrices: func() *verdict.BundleMatrices { return three }, Verdicts: violated}
	got, emit := collect(em)
	u := usageFor("claude-haiku-4-5", "req_5", task[:])
	if err := emit(u); err != nil {
		t.Fatal(err)
	}
	r := (*got)[1].GetRouteDecision()
	if r.GetAction() != "claude-sonnet-4-5" || len(r.GetCandidates()) != 3 || r.GetFidelity() != m1pv1.RouteFidelity_ROUTE_FIDELITY_ADVISORY {
		t.Fatalf("below-knee VIOLATED on haiku must step to sonnet, ADVISORY: %+v", r)
	}
	if string((*got)[1].GetEventId()) != string(Decision(u, 7).GetEventId()) {
		t.Fatal("the ladder step changed the deterministic event_id")
	}
	// No verdict for the task, or a SATISFIED one: the ladder stays.
	for _, em := range []*Emitter{
		{Matrices: func() *verdict.BundleMatrices { return three }},
		{Matrices: func() *verdict.BundleMatrices { return three }, Verdicts: cache{verdict.TaskID(task): {Verdict: &m1pv1.VerdictEvent{Verdict: m1pv1.Verdict_VERDICT_SATISFIED}, Knee: verdict.KneeState{N: 2, Evaluable: true}}}},
	} {
		got, emit := collect(em)
		if err := emit(u); err != nil {
			t.Fatal(err)
		}
		if a := (*got)[1].GetRouteDecision().GetAction(); a != "claude-haiku-4-5" {
			t.Fatalf("stay case stepped to %q", a)
		}
	}
}
