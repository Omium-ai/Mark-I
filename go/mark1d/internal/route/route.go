// Package route produces RouteDecision — the OPE logging row (06 §11) — beside
// its source event, riding that event's session_id, occurred_at and admission
// path (04 §2.0). Two producers, one per fidelity: a proxy ModelRequest whose
// served model is the applied ladder's entry rung ⇒ WIRE_ENFORCED (the wire
// bound it); a tailer Usage ⇒ ADVISORY (06 §11.2 rule 3 keeps it out of
// DR/SNIPS), unless the proxy already enforced that vendor request_id.
// Propensity is 1.0 on both: ε = 0 and intelligence.proto forbids fabricating
// exploration that did not happen.
package route

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/capture"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/verdict"
)

// ponytail: FIFO cap on remembered wire request ids; a Usage tailed later than that gets an ADVISORY twin OPE drops and counts (C9).
const enforcedCap = 4096

// Emitter wraps Next (the tailer's Emit, capture.Admitter.Admit in the
// daemon): every Usage or proxy ModelRequest forwarded is followed by its
// RouteDecision through the same Next. Other events pass through untouched.
type Emitter struct {
	Next func(context.Context, *m1pv1.Event) error
	// Seq reports the applied bundle's seq — verdict.BundleMatrices.Seq as
	// published through bundle.Client.Apply. nil ⇒ 0, the built-ins'
	// provenance.
	Seq func() uint64
	// Matrices reports the applied bundle's ladders; nil ⇒ single rung, nothing WIRE_ENFORCED.
	Matrices func() *verdict.BundleMatrices
	// Verdicts is the gate cache the ADVISORY ladder step reads; nil ⇒ the ladder never steps.
	Verdicts verdict.Reader

	mu       sync.Mutex
	enforced map[string]struct{}
	order    []string
}

// Emit forwards ev, then its RouteDecision (Usage, or a WIRE_ENFORCED proxy
// ModelRequest). The source's own outcome is returned unchanged (billing-grade;
// the tailer's error path is its contract). The RouteDecision is diagnostic
// class (07 §6): a shed or quarantine is already accounted in the drop ledger
// and never surfaces as a source failure — the pair cmd/main.go's isAccounted swallows.
func (e *Emitter) Emit(ctx context.Context, ev *m1pv1.Event) error {
	if err := e.Next(ctx, ev); err != nil {
		return err
	}
	var rd *m1pv1.Event
	switch {
	case ev.GetModelRequest() != nil:
		rd = e.enforcedDecision(ev)
	case ev.GetUsage() != nil:
		if e.wasEnforced(ev.GetUsage().GetRequestId()) {
			return nil
		}
		rd = e.advisoryDecision(ev)
	default:
		return nil
	}
	if rd == nil {
		return nil
	}
	err := e.Next(ctx, rd)
	if errors.Is(err, capture.ErrShed) || errors.Is(err, capture.ErrQuarantined) {
		return nil
	}
	return err
}

func (e *Emitter) seq() uint64 {
	if e.Seq == nil {
		return 0
	}
	return e.Seq()
}

func (e *Emitter) matrices() *verdict.BundleMatrices {
	if e.Matrices == nil {
		return nil
	}
	return e.Matrices()
}

// ladderNaming is the rung ids of the first bundle ladder naming model (the proxy RouteTable rule), nil when none does.
func ladderNaming(m *verdict.BundleMatrices, model string) []string {
	if m == nil {
		return nil
	}
	for _, l := range m.Ladders {
		for _, r := range l.Rungs {
			if r.ModelID == model {
				rungs := make([]string, len(l.Rungs))
				for i, r := range l.Rungs {
					rungs[i] = r.ModelID
				}
				return rungs
			}
		}
	}
	return nil
}

// enforcedDecision is nil unless the served model is the entry rung of the ladder naming the request (else the wire did not bind: ADVISORY via Usage).
func (e *Emitter) enforcedDecision(ev *m1pv1.Event) *m1pv1.Event {
	mr := ev.GetModelRequest()
	rungs := ladderNaming(e.matrices(), mr.GetModel())
	if len(rungs) == 0 || mr.GetServedModel() != rungs[0] {
		return nil
	}
	e.remember(mr.GetRequestId())
	return decision(ev, "m1p.route.decision.wire\x00", []byte(mr.GetRequestId()),
		mr.GetServedModel(), rungs, m1pv1.RouteFidelity_ROUTE_FIDELITY_WIRE_ENFORCED, e.seq())
}

// advisoryDecision: action = the ladder step the cached verdict forces (Stay = the served model), candidates = the ladder's rungs or the served rung alone.
func (e *Emitter) advisoryDecision(ev *m1pv1.Event) *m1pv1.Event {
	u := ev.GetUsage()
	action, candidates := u.GetModel(), []string{u.GetModel()}
	m := e.matrices()
	if rungs := ladderNaming(m, u.GetModel()); rungs != nil {
		candidates = rungs
		var v m1pv1.Verdict
		var k verdict.KneeState
		if e.Verdicts != nil && len(ev.GetTaskId()) == 16 {
			if c, ok := e.Verdicts.Get(verdict.TaskID(ev.GetTaskId())); ok {
				v, k = c.Verdict.GetVerdict(), c.Knee
			}
		}
		action = m.LadderStep(u.GetModel(), v, k).ModelID
	}
	return decision(ev, "m1p.route.decision\x00", u.GetIdemKey(), action, candidates,
		m1pv1.RouteFidelity_ROUTE_FIDELITY_ADVISORY, e.seq())
}

// Decision is the ADVISORY row for one Usage under no ladder (single rung or built-ins).
func Decision(usage *m1pv1.Event, bundleSeq uint64) *m1pv1.Event {
	u := usage.GetUsage()
	return decision(usage, "m1p.route.decision\x00", u.GetIdemKey(), u.GetModel(),
		[]string{u.GetModel()}, m1pv1.RouteFidelity_ROUTE_FIDELITY_ADVISORY, bundleSeq)
}

func decision(src *m1pv1.Event, domain string, key []byte, action string, candidates []string, fidelity m1pv1.RouteFidelity, bundleSeq uint64) *m1pv1.Event {
	id := decisionID(domain, key, src.GetOccurredAt())
	return &m1pv1.Event{
		EventId:    id,
		SessionId:  src.GetSessionId(),
		TaskId:     src.GetTaskId(),
		OccurredAt: src.GetOccurredAt(),
		Body: &m1pv1.Event_RouteDecision{RouteDecision: &m1pv1.RouteDecision{
			DecisionId: id,
			Action:     action,
			Candidates: candidates,
			Propensity: 1,
			Fidelity:   fidelity,
			BundleSeq:  bundleSeq,
		}},
	}
}

func (e *Emitter) remember(requestID string) {
	if requestID == "" {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.enforced == nil {
		e.enforced = map[string]struct{}{}
	}
	if _, dup := e.enforced[requestID]; dup {
		return
	}
	e.enforced[requestID] = struct{}{}
	e.order = append(e.order, requestID)
	if len(e.order) > enforcedCap {
		delete(e.enforced, e.order[0])
		e.order = e.order[1:]
	}
}

func (e *Emitter) wasEnforced(requestID string) bool {
	if requestID == "" {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	_, ok := e.enforced[requestID]
	return ok
}

// decisionID is the row's dedupe identity: a UUIDv7 (stage 6 admits nothing
// else) whose 48-bit time is the vendor's own timestamp and whose remaining
// bits are SHA-256 over domain || key — the Usage idem_key (itself
// HMAC_tenant(session, message_id, request_id)) on the ADVISORY path, the
// vendor request_id on the wire path. A re-tail (lost cursor, rewritten
// file, a numbers correction re-emitting the same key) re-derives the SAME id
// under the same occurred_at, so the ledger's ReplacingMergeTree collapses
// the row (07 §7) exactly as the Usage beside it collapses on idem_key. The
// vendor time keeps uplink's oldest-unacked gauge honest (it reads the v7
// prefix); without one there is no deterministic clock to put there, so the
// id is left for capture to mint — that row can duplicate under re-tail,
// which is the honest degradation, not a fabricated timestamp.
func decisionID(domain string, key []byte, at *timestamppb.Timestamp) []byte {
	if len(key) == 0 || at == nil || at.AsTime().UnixMilli() < 0 {
		return nil
	}
	sum := sha256.Sum256(append([]byte(domain), key...))
	var id uuid.UUID
	copy(id[:], sum[:16])
	ms := uint64(at.AsTime().UnixMilli()) // #nosec G115 -- non-negative, guarded above
	binary.BigEndian.PutUint64(id[:8], ms<<16|uint64(binary.BigEndian.Uint16(id[6:8])))
	id[6] = 0x70 | id[6]&0x0f // version 7
	id[8] = 0x80 | id[8]&0x3f // RFC 4122 variant
	return id[:]
}
