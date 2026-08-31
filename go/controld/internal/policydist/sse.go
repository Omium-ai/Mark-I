// The SSE push fan-out (08 §3.2 GET /api/v1/policy/stream).
//
// SSE IS AN OPTIMISATION, NEVER A MECHANISM. 05 §4.2: the jittered 5-minute
// ETag poll is the correctness path; the stream only shortens the window
// between publication and adoption. Every failure mode below therefore
// resolves to "close the stream" -- hub full, slow consumer, drain, write
// error -- because a closed stream costs at most one poll interval of
// staleness, while a stream held open for a client that cannot keep up costs
// a pod's memory. There is deliberately no replay, no backlog and no
// at-least-once delivery here: adding them would build a second, weaker
// correctness path beside the one that already works.
//
// The bounds are 05 §8.2's: 5,000 concurrent streams per pod (past that, new
// connections get 503 and fall back to polling), 10 s per event write, 30 s
// heartbeat.

package policydist

import (
	"fmt"
	"sync"

	"github.com/google/uuid"
)

const (
	// MaxStreamsPerPod is 05 §8.2's capacity line. Past it: 503.
	MaxStreamsPerPod = 5000
	// MaxStreamsPerTenant stops one tenant's fleet from consuming the whole
	// pod budget and 503-ing everyone else. 05 §8.2 does not size this; 10%
	// of the pod is the smallest bound that is obviously not a limit a real
	// tenant hits by polling correctly, since a tenant's devices spread
	// across replicas.
	MaxStreamsPerTenant = 500
	// streamBuffer is the per-connection queue. Two events deep: a bundle
	// hint and a revocation. A third arriving before the writer drains two
	// means the consumer is not consuming, and 05 §8.2's answer to a slow
	// consumer is to close the stream.
	streamBuffer = 2
)

// ErrHubFull is 05 §8.2's shed: the pod is at its stream budget.
var ErrHubFull = fmt.Errorf("policydist: stream capacity reached")

// Event is one SSE frame.
type Event struct {
	Name string // "bundle" | "revocation" | "ping"
	Data string // JSON, already rendered
}

// stream is one live connection.
type stream struct {
	tenant  uuid.UUID
	channel string
	out     chan Event
	// closeOnce guards out: the writer goroutine and the hub both end a
	// stream, and closing a closed channel panics the whole pod.
	closeOnce sync.Once
}

func (s *stream) close() { s.closeOnce.Do(func() { close(s.out) }) }

// Hub fans publications out to live streams. Bounded in both dimensions and
// in per-connection buffering; nothing here grows with fleet size except the
// map of live connections, which is itself capped.
type Hub struct {
	mu       sync.Mutex
	streams  map[*stream]struct{}
	perTen   map[uuid.UUID]int
	draining bool

	maxTotal  int
	maxTenant int
}

func NewHub() *Hub {
	return &Hub{
		streams:   make(map[*stream]struct{}),
		perTen:    make(map[uuid.UUID]int),
		maxTotal:  MaxStreamsPerPod,
		maxTenant: MaxStreamsPerTenant,
	}
}

// Live reports the current connection count (metrics + the §8.2 scale
// trigger at 3,500/pod).
func (h *Hub) Live() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.streams)
}

func (h *Hub) subscribe(tenant uuid.UUID, channel string) (*stream, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.draining {
		return nil, ErrHubFull
	}
	if len(h.streams) >= h.maxTotal || h.perTen[tenant] >= h.maxTenant {
		return nil, ErrHubFull
	}
	s := &stream{tenant: tenant, channel: channel, out: make(chan Event, streamBuffer)}
	h.streams[s] = struct{}{}
	h.perTen[tenant]++
	return s, nil
}

func (h *Hub) unsubscribe(s *stream) {
	h.mu.Lock()
	if _, live := h.streams[s]; live {
		delete(h.streams, s)
		if h.perTen[s.tenant]--; h.perTen[s.tenant] <= 0 {
			delete(h.perTen, s.tenant)
		}
	}
	h.mu.Unlock()
	s.close()
}

// send is the only path that writes to a stream's queue. A full queue closes
// the stream rather than blocking: blocking here would let one stalled TCP
// connection stall the publication transaction's caller.
func (h *Hub) send(s *stream, ev Event) bool {
	select {
	case s.out <- ev:
		return true
	default:
		return false
	}
}

// Publish hints every stream on (tenant, channel) that a new seq exists. Non-
// blocking; slow consumers are dropped. Called AFTER the publication
// transaction commits -- a hint for a bundle that never committed sends the
// whole fleet to fetch a seq that does not exist.
func (h *Hub) Publish(tenant uuid.UUID, channel string, seq int64, etag string) {
	h.fanout(tenant, &channel, Event{
		Name: "bundle",
		Data: fmt.Sprintf(`{"seq":%d,"etag":%s}`, seq, etag), // etag already carries its quotes
	})
}

// Revoke pushes 05 §3.4's revocation epoch to every live stream for the
// tenant, on every channel: a revocation is not channel-scoped.
func (h *Hub) Revoke(tenant uuid.UUID, epoch int64) {
	h.fanout(tenant, nil, Event{Name: "revocation", Data: fmt.Sprintf(`{"revocation_epoch":%d}`, epoch)})
}

func (h *Hub) fanout(tenant uuid.UUID, channel *string, ev Event) {
	h.mu.Lock()
	targets := make([]*stream, 0, 8)
	for s := range h.streams {
		if s.tenant != tenant || (channel != nil && s.channel != *channel) {
			continue
		}
		targets = append(targets, s)
	}
	h.mu.Unlock()

	for _, s := range targets {
		if !h.send(s, ev) {
			h.unsubscribe(s) // slow consumer; it will re-arrive on the poll
		}
	}
}

// Drain is 05 §1.5 step 2: a final `event: ping`, then close. The ping is not
// decoration -- it is the signal that lets a client distinguish an orderly
// shutdown from a network fault, and either way the client's next move is the
// poll, which is the correctness path anyway.
func (h *Hub) Drain() {
	h.mu.Lock()
	h.draining = true
	all := make([]*stream, 0, len(h.streams))
	for s := range h.streams {
		all = append(all, s)
	}
	h.mu.Unlock()

	for _, s := range all {
		h.send(s, Event{Name: "ping", Data: "{}"}) // best effort: a full queue is closing anyway
		h.unsubscribe(s)
	}
}
