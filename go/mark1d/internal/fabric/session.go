// The per-connection FabricFrame layer (D-U, proto/m1p/v1/fabric.proto): every
// M1PL payload is one serialized m1p.v1.FabricFrame. This file unwraps the
// oneof, enforces the 08 §4.3 handshake (first frame MUST be Hello, else close
// M1E-4003), spools the INNER Event bytes verbatim (the spool record layout
// does not change), and answers GateQuery/Flush request-reply.
package fabric

import (
	"context"
	"fmt"
	"net"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

// FabricFrame oneof field numbers (proto/m1p/v1/fabric.proto).
const (
	frameEvent              = 1
	frameHello              = 2
	frameHelloAck           = 3
	frameGateQuery          = 4
	frameGateVerdict        = 5
	frameFlush              = 6
	frameFlushAck           = 7
	frameContaminationAlert = 10
)

// isOneofArm reports whether a field number is one of FabricFrame's oneof
// arms. The set is NOT a range: 8 and 9 are reserved by D-AI for
// ContextQuery/ContextReply and are deliberately not arms yet, so a frame
// carrying one is skipped as unknown rather than mistaken for a control
// message this daemon knows how to act on.
func isOneofArm(num protowire.Number) bool {
	return (num >= frameEvent && num <= frameFlushAck) || num == frameContaminationAlert
}

// UnwrapEvent returns the INNER Event bytes of one encoded FabricFrame, for
// readers that get frames from somewhere other than a live connection — the
// spill ring, whose writer is `spill::append` on the far side of
// `m1p_wire::encode_frame` (mark1-hookshim/src/main.rs), so its records are
// whole FabricFrames exactly as the socket path's are.
//
// It exists because the alternative is silent corruption, not an error:
// FabricFrame.event and Event.event_id are BOTH field 1 wiretype 2, so
// proto.Unmarshal of a frame into an Event succeeds and yields an event whose
// id is the frame's entire encoded body. A caller that skips this step loses
// every spooled event without one failed call to show for it.
func UnwrapEvent(payload []byte) ([]byte, error) {
	field, inner, err := unwrap(payload)
	if err != nil {
		return nil, err
	}
	if field != frameEvent {
		return nil, fmt.Errorf("fabric: FabricFrame carries arm %d, want event", field)
	}
	return inner, nil
}

// CodeHandshake is 08 §4.3 step 2: any first frame other than Hello.
const CodeHandshake = "M1E-4003"

// ContaminationHandler receives the P0 OAuth-contamination kill path
// (D-AI, 04 §3.1 step 6). By the time this fires the proxy has ALREADY closed
// the session and will refuse every subsequent request for it on its own
// authority — the frame is notification, not permission, which is why it is
// one-way and why a hung handler can veto nothing. The daemon's job is the
// config rollback: revert the base-URL fragment for the agent that cred_ref
// resolves to, so the agent's next request bypasses the proxy entirely.
type ContaminationHandler interface {
	// OnContamination runs on the connection's reader goroutine, so it must
	// not block on anything slow. session is the connection's authenticated
	// Hello id (08 §4.3) — the same scope Gate.Answer resolves through, and
	// not the alert's own session_id field, because the frame's word for who
	// it is carries no more authority than the handshake that preceded it.
	OnContamination(session [16]byte, credRef, reasonCode string)
}

// unwrap scans one encoded FabricFrame and returns its single oneof arm with
// the raw sub-message bytes. Raw extraction — not proto.Unmarshal +
// re-Marshal — is the point for the Event arm: the spooled bytes must be the
// writer's exact inner Event bytes (D-U).
//
// A second occurrence of ANY oneof arm is rejected as malformed. proto3
// last-wins here and prost MERGES on the Rust end of the same socket, so the
// two ends would disagree about what a duplicating frame meant; refusing is
// the only answer both can give, and no legitimate writer emits one.
func unwrap(payload []byte) (field int, inner []byte, err error) {
	b := payload
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return 0, nil, fmt.Errorf("fabric: bad FabricFrame tag: %w", protowire.ParseError(n))
		}
		b = b[n:]
		if isOneofArm(num) {
			if typ != protowire.BytesType {
				return 0, nil, fmt.Errorf("fabric: FabricFrame field %d has wire type %d, want bytes", num, typ)
			}
			if field != 0 {
				return 0, nil, fmt.Errorf("fabric: FabricFrame carries oneof arms %d and %d; exactly one is legal (D-U)", field, num)
			}
			v, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return 0, nil, fmt.Errorf("fabric: bad FabricFrame field %d: %w", num, protowire.ParseError(n))
			}
			field, inner = int(num), v
			b = b[n:]
			continue
		}
		n = protowire.ConsumeFieldValue(num, typ, b)
		if n < 0 {
			return 0, nil, fmt.Errorf("fabric: bad FabricFrame field %d: %w", num, protowire.ParseError(n))
		}
		b = b[n:]
	}
	if field == 0 {
		return 0, nil, fmt.Errorf("fabric: FabricFrame carries no oneof arm")
	}
	return field, inner, nil
}

// session is one connection's post-framing state: the handshake bit and the
// FlushAck drained counter ("events admitted to the spool since this
// connection's Hello" — fabric.proto).
type session struct {
	s       *Server
	c       net.Conn
	helloed bool
	drained uint64
	// id is the Hello's session_id, the authenticated scope D-AA resolves an
	// empty GateQuery.task_id through. Never zero past the handshake: D-AT
	// refuses a Hello that carries no session.
	id [16]byte
}

// frame dispatches one decoded M1PL payload. A non-nil return closes the
// connection; per-event capture outcomes (shed, quarantine) are absorbed here.
func (ss *session) frame(ctx context.Context, payload []byte) error {
	field, inner, err := unwrap(payload)
	if err != nil {
		return err // undecodable envelope = desynchronized dialect, close
	}
	if !ss.helloed {
		if field != frameHello {
			return fmt.Errorf("fabric: %s: first frame is FabricFrame field %d, not Hello (08 §4.3)", CodeHandshake, field)
		}
		h := &m1pv1.Hello{}
		if err := proto.Unmarshal(inner, h); err != nil {
			return fmt.Errorf("fabric: %s: undecodable Hello: %w", CodeHandshake, err)
		}
		if sid := h.GetSessionId(); len(sid) == 16 {
			copy(ss.id[:], sid)
		}
		if ss.id == ([16]byte{}) {
			// D-AT: D-AL closed the all-zero session at every CONSUMER — capture
			// quarantines, Observe segments nothing, TaskFor misses, Gate.resolve
			// rejects before any counter is keyed. Entry was the last axis left
			// open, so a Hello with a missing, wrong-length or explicitly zero
			// session_id was accepted and then had everything it sent silently
			// dropped. Refusing here is the only answer that is not a lie.
			return fmt.Errorf("fabric: %s: Hello carries no session_id; the all-zero sentinel is not a session and everything under it is dropped (08 §4.3)", CodeHandshake)
		}
		ss.helloed = true
		// max_frame is the symbol M1PL_MAX_FRAME, never a re-typed literal.
		return ss.reply(&m1pv1.FabricFrame{Kind: &m1pv1.FabricFrame_HelloAck{
			HelloAck: &m1pv1.HelloAck{Accepted: true, MaxFrame: MaxFrame},
		}})
	}
	switch field {
	case frameEvent:
		if herr := ss.s.handle(ctx, inner); herr != nil {
			if ss.s.perEvent(herr) {
				return nil // accounted loss; the connection lives on
			}
			return herr
		}
		ss.drained++
		ss.s.Health.Delivered()
		return nil
	case frameGateQuery:
		q := &m1pv1.GateQuery{}
		if err := proto.Unmarshal(inner, q); err != nil {
			return fmt.Errorf("fabric: undecodable GateQuery: %w", err)
		}
		var v *m1pv1.GateVerdict
		if g := ss.s.gate; g != nil {
			v = g.Answer(q, ss.id)
		} else {
			// No gate wired: the M1E-5001 fail-open posture — a verdict
			// subsystem failure can never block a developer (04 §2.3).
			v = &m1pv1.GateVerdict{Decision: m1pv1.GateDecision_GATE_DECISION_ALLOW, Reason: "M1E-5001 no verdict subsystem"}
		}
		return ss.reply(&m1pv1.FabricFrame{Kind: &m1pv1.FabricFrame_GateVerdict{GateVerdict: v}})
	case frameFlush:
		// Drain before ack (NFR-DURABILITY-004): the shim sends Flush after
		// SessionEnd on the same connection and treats the ack as its only
		// delivery evidence, so an ack written off the admitted counter alone
		// attested to bytes still in the page cache. A failed sync writes no
		// ack and closes: the shim spills and replays, at-least-once (07 §6).
		if sync := ss.s.Sync; sync != nil {
			if err := sync(); err != nil {
				return fmt.Errorf("fabric: Flush: spool sync failed, ack withheld: %w", err)
			}
		}
		return ss.reply(&m1pv1.FabricFrame{Kind: &m1pv1.FabricFrame_FlushAck{FlushAck: &m1pv1.FlushAck{Drained: ss.drained}}})
	case frameContaminationAlert:
		a := &m1pv1.ContaminationAlert{}
		if err := proto.Unmarshal(inner, a); err != nil {
			return fmt.Errorf("fabric: undecodable ContaminationAlert: %w", err)
		}
		// One-way (D-AI): no reply, and no error travels back — the proxy
		// never awaits us. A nil handler is the unwired daemon; the alert is
		// dropped and the proxy's own refusal still holds, which is the
		// closed failure direction the ruling names.
		//
		// cmd/main.go installs contaminationRollback here at startup; a nil
		// handler now means an embedding that never called
		// SetContaminationHandler (the tests), not an unfinished daemon.
		if h := ss.s.contamination; h != nil {
			h.OnContamination(ss.id, a.GetCredRef(), a.GetReasonCode())
		}
		return nil
	default:
		// Hello twice, or a daemon→writer arm from a writer: dialect breach.
		return fmt.Errorf("fabric: %s: unexpected FabricFrame field %d from writer", CodeHandshake, field)
	}
}

// rejectVersion is 08 §4.3 step 3's other outcome and the only producer of
// HelloAck{accepted:false}: the daemon names the single M1PL version it speaks
// before closing. Framed at that version — a writer that cannot read it is no
// worse off than the bare EOF it used to get, and a mid-upgrade writer one
// version behind gets the diagnostic the field exists for.
func (ss *session) rejectVersion() error {
	return ss.reply(&m1pv1.FabricFrame{Kind: &m1pv1.FabricFrame_HelloAck{
		HelloAck: &m1pv1.HelloAck{Accepted: false, MaxFrame: MaxFrame, WantVer: version},
	}})
}

func (ss *session) reply(f *m1pv1.FabricFrame) error {
	b, err := proto.Marshal(f)
	if err != nil {
		return err
	}
	return WriteFrame(ss.c, b)
}
