package control

import (
	"encoding/hex"
	"sync"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// ponytail: a session whose end is tailer-inferred never sends SessionEnd, so it lingers until the cap evicts it; add an idle TTL if agents_live reads stale.
// ponytail: the verify ring is memory-only since boot; the spool is the durable record and is never re-read here.
const (
	subscriberBuffer = 256
	maxLiveSessions  = 64
	verifyRing       = 1024
)

var marshal = protojson.MarshalOptions{UseProtoNames: true}

type LiveSession struct {
	Agent     string `json:"agent"`
	SessionID string `json:"session_id"`
	Tokens    uint64 `json:"tokens"`
	started   time.Time
}

type frame struct {
	family string
	data   []byte
}

// Hub is the tap on capture's one admission door: SSE fan-out plus the live-session table.
type Hub struct {
	mu       sync.Mutex
	subs     map[chan frame]struct{}
	sessions map[[16]byte]*LiveSession
	verify   []frame
}

func NewHub() *Hub {
	return &Hub{subs: map[chan frame]struct{}{}, sessions: map[[16]byte]*LiveSession{}}
}

func family(ev *m1pv1.Event) string {
	switch ev.GetBody().(type) {
	case *m1pv1.Event_SessionStart:
		return "session_start"
	case *m1pv1.Event_Turn:
		return "turn"
	case *m1pv1.Event_ToolUse:
		return "tool"
	case *m1pv1.Event_Usage:
		return "usage"
	case *m1pv1.Event_VerdictEvent:
		return "verdict"
	case *m1pv1.Event_GuardDecision:
		return "arrest"
	case *m1pv1.Event_MemoryInjection, *m1pv1.Event_CortexInjection:
		return "injection"
	case *m1pv1.Event_RouteDecision:
		return "route_decision"
	case *m1pv1.Event_CoverageTransition:
		return "coverage_transition"
	case *m1pv1.Event_AnchorVote:
		if ev.GetAnchorVote().GetIntegrity().GetTamper() {
			return "tamper"
		}
	}
	return ""
}

// Publish never blocks the admitter: a subscriber subscriberBuffer frames behind loses the frame.
func (h *Hub) Publish(ev *m1pv1.Event) {
	fam := family(ev)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.track(ev)
	if fam == "" {
		return
	}
	data, err := marshal.Marshal(ev)
	if err != nil {
		return
	}
	f := frame{family: fam, data: data}
	switch fam {
	case "verdict", "arrest", "tamper":
		h.verify = append(h.verify, f)
		if len(h.verify) > verifyRing {
			h.verify = h.verify[len(h.verify)-verifyRing:]
		}
	}
	if fam == "tamper" {
		return
	}
	for ch := range h.subs {
		select {
		case ch <- f:
		default:
		}
	}
}

func (h *Hub) track(ev *m1pv1.Event) {
	if len(ev.GetSessionId()) != 16 {
		return
	}
	var sid [16]byte
	copy(sid[:], ev.GetSessionId())
	switch b := ev.GetBody().(type) {
	case *m1pv1.Event_SessionStart:
		h.sessions[sid] = &LiveSession{Agent: b.SessionStart.GetAgent(), SessionID: hex.EncodeToString(sid[:]), started: time.Now()}
		for len(h.sessions) > maxLiveSessions {
			var oldest [16]byte
			var at time.Time
			for id, s := range h.sessions {
				if at.IsZero() || s.started.Before(at) {
					oldest, at = id, s.started
				}
			}
			delete(h.sessions, oldest)
		}
	case *m1pv1.Event_SessionEnd:
		delete(h.sessions, sid)
	case *m1pv1.Event_Usage:
		if s := h.sessions[sid]; s != nil {
			u := b.Usage
			s.Tokens += u.GetInputTokens() + u.GetOutputTokens() + u.GetCacheCreationInputTokens() + u.GetCacheReadInputTokens()
		}
	}
}

func (h *Hub) subscribe() (<-chan frame, func()) {
	ch := make(chan frame, subscriberBuffer)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		delete(h.subs, ch)
		h.mu.Unlock()
	}
}

func (h *Hub) live() []LiveSession {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]LiveSession, 0, len(h.sessions))
	for _, s := range h.sessions {
		out = append(out, *s)
	}
	return out
}

func (h *Hub) verifyEvents() []frame {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]frame(nil), h.verify...)
}
