package fabric

import (
	"context"
	"fmt"

	"google.golang.org/protobuf/encoding/protowire"
)

// FabricFrame arms 8/9 (D-AE), hand-pinned: fabric.proto reserves the tags but defines no message yet.
const (
	frameContextQuery = 8
	frameContextReply = 9
)

// ContextQuery field numbers are the byte contract TestContextFrameBytesAgreeWithTheShim pins.
type ContextQuery struct {
	Channel     uint32 // 1: m1p.v1.InjectionChannel
	ToolName    string // 2
	Error       string // 3
	DeadlineMs  uint32 // 4: GateQuery.deadline_ms semantics, 0 = unspecified
	IsInterrupt bool   // 5
}

// ContextHandler answers ContextQuery; nil means every query gets an empty reply (fail-open).
type ContextHandler interface {
	Context(ctx context.Context, q ContextQuery, session [16]byte) string
}

func (s *Server) SetContextHandler(h ContextHandler) { s.context = h }

// ContextChain answers from the first handler with something to say; each channel has one owner (Gate: CORRECTION; memory.Cache: the rest).
type ContextChain []ContextHandler

func (c ContextChain) Context(ctx context.Context, q ContextQuery, session [16]byte) string {
	for _, h := range c {
		if text := h.Context(ctx, q, session); text != "" {
			return text
		}
	}
	return ""
}

func decodeContextQuery(b []byte) (ContextQuery, error) {
	var q ContextQuery
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return q, protowire.ParseError(n)
		}
		b = b[n:]
		switch num {
		case 1, 4, 5:
			if typ != protowire.VarintType {
				return q, fmt.Errorf("ContextQuery field %d has wire type %d, want varint", num, typ)
			}
			v, n := protowire.ConsumeVarint(b)
			if n < 0 {
				return q, protowire.ParseError(n)
			}
			b = b[n:]
			switch num {
			case 1:
				q.Channel = uint32(v) // #nosec G115 -- enum-sized by contract
			case 4:
				q.DeadlineMs = uint32(v) // #nosec G115 -- ms budget, shim-bounded
			default:
				q.IsInterrupt = v != 0
			}
		case 2, 3:
			if typ != protowire.BytesType {
				return q, fmt.Errorf("ContextQuery field %d has wire type %d, want bytes", num, typ)
			}
			v, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return q, protowire.ParseError(n)
			}
			b = b[n:]
			if num == 2 {
				q.ToolName = string(v)
			} else {
				q.Error = string(v)
			}
		default:
			n := protowire.ConsumeFieldValue(num, typ, b)
			if n < 0 {
				return q, protowire.ParseError(n)
			}
			b = b[n:]
		}
	}
	return q, nil
}

// encodeContextReply yields a whole FabricFrame payload: arm 9 wrapping {1: text}; "" keeps the arm present (arm-less frames are decode errors on both ends).
func encodeContextReply(text string) []byte {
	var inner []byte
	if text != "" {
		inner = protowire.AppendTag(inner, 1, protowire.BytesType)
		inner = protowire.AppendString(inner, text)
	}
	out := protowire.AppendTag(nil, frameContextReply, protowire.BytesType)
	return protowire.AppendBytes(out, inner)
}
