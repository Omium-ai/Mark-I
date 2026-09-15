// The M1PL accept loop: one reader goroutine per connection, each connection's
// bytes fed through the incremental Decoder into the single admission door.
//
// Deliberately NOT build-tagged, and the split from listener.go is the point.
// Everything here speaks net.Listener and net.Conn and nothing else — no path,
// no mode bit, no syscall — so it is the same code on every platform that has a
// stream transport at all. It lived under `//go:build unix` only because it
// shared a file with the UDS endpoint, which made the tag-free session.go
// reference a type that did not exist on Windows: a build break that was never
// a design position. What is genuinely unix-only is the endpoint, and that is
// all listener.go now holds.
package fabric

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/obs"
)

// DefaultHandshakeTimeout is generous against the shim's 50 ms whole-invocation
// budget and the 250 ms gate budget — it is not a latency control, only a
// ceiling on how long a silent peer may hold a goroutine and an fd.
const DefaultHandshakeTimeout = 10 * time.Second

// Server owns the accept loop. handle receives each Event's INNER bytes —
// the FabricFrame oneof is unwrapped in session.frame (D-U) — and is
// capture.AdmitBytes in the daemon: the fabric stays transport, admission
// stays policy (04 §2).
type Server struct {
	handle func(ctx context.Context, payload []byte) error
	// perEvent declares which handle errors are per-event outcomes (already
	// accounted by capture — shed, quarantine) and so connection-preserving;
	// anything else (spool closed, ctx dead) ends the stream. A predicate
	// rather than an import so transport never depends on policy (04 §2).
	perEvent func(error) bool
	gate     *Gate // nil ⇒ GateQuery answered fail-open (M1E-5001)
	// contamination receives the D-AI rollback; cmd/main.go installs it at
	// startup. A nil handler (tests, embeddings) drops the alert, which is
	// safe because the proxy has already killed the session on its own
	// authority.
	contamination ContaminationHandler

	// HandshakeTimeout bounds how long a connected peer may say nothing before
	// its Hello (08 §4.3). Zero uses DefaultHandshakeTimeout; set before Serve.
	HandshakeTimeout time.Duration

	// Health counts accepted Event frames as `shim.delivered`; nil is legal.
	Health *obs.Health

	// Sync is the Flush barrier's durability half (NFR-DURABILITY-004): it
	// runs BEFORE every FlushAck, so the ack attests to fsynced records and
	// not merely written ones. cmd/main.go installs spool.Sync — the one
	// fsync path the spool has, not a second one. nil (the stub tests, an
	// embedding with no durable store) acks on admission alone.
	Sync func() error

	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
}

func NewServer(handle func(ctx context.Context, payload []byte) error, perEvent func(error) bool) *Server {
	if perEvent == nil {
		perEvent = func(error) bool { return false }
	}
	return &Server{handle: handle, perEvent: perEvent, conns: map[net.Conn]struct{}{}}
}

// SetGate wires the GateQuery handler; call before Serve.
func (s *Server) SetGate(g *Gate) { s.gate = g }

// SetContaminationHandler wires the D-AI kill-path receiver; call before
// Serve. Left unset the daemon still decodes and accepts the frame.
func (s *Server) SetContaminationHandler(h ContaminationHandler) { s.contamination = h }

// Serve accepts until the listener closes. Each connection gets one reader
// goroutine; a blocked handle (billing-grade spool backpressure) therefore
// stops that connection's reads — the TCP-style backpressure 08 §4.4 wants,
// for free from blocking I/O.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			_ = c.Close()
			return nil
		}
		s.conns[c] = struct{}{}
		s.mu.Unlock()
		go s.serveConn(ctx, c)
	}
}

// Close severs every live connection. Writers hold their own spill rings
// (08 §4.4); an abrupt close costs them a replay, never data.
func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for c := range s.conns {
		_ = c.Close()
	}
	s.conns = map[net.Conn]struct{}{}
}

func (s *Server) serveConn(ctx context.Context, c net.Conn) {
	defer func() {
		_ = c.Close()
		s.mu.Lock()
		delete(s.conns, c)
		s.mu.Unlock()
	}()
	dec := &Decoder{}
	sess := &session{s: s, c: c}
	buf := make([]byte, 64<<10)

	// The handshake gets a deadline; an established session does not. 08 §4.3
	// makes the FIRST frame mandatory, so a peer that connects and then goes
	// quiet is not a slow writer — it is a leaked or wedged process pinning a
	// goroutine and an fd on a daemon that outlives every agent session, and
	// nothing else here ever reclaims it. Past the handshake the deadline is
	// cleared, because a writer holding one connection open across a whole
	// session is exactly what the fabric is for.
	hsTimeout := s.HandshakeTimeout
	if hsTimeout <= 0 {
		hsTimeout = DefaultHandshakeTimeout
	}
	if c.SetReadDeadline(time.Now().Add(hsTimeout)) != nil {
		return
	}
	handshaken := false

	for {
		n, err := c.Read(buf)
		if n > 0 {
			dec.Push(buf[:n])
			for {
				payload, _, derr := dec.Next()
				if derr != nil {
					// Reject means the stream is desynchronized or hostile:
					// close, never resynchronize on attacker-chosen bytes (07 §5).
					var rej *RejectError
					if errors.As(derr, &rej) && rej.Code == CodeVersion {
						_ = sess.rejectVersion()
					}
					return
				}
				if payload == nil {
					break
				}
				if herr := sess.frame(ctx, payload); herr != nil {
					return
				}
				if !handshaken {
					handshaken = true
					if c.SetReadDeadline(time.Time{}) != nil {
						return
					}
				}
			}
		}
		if err != nil {
			return
		}
	}
}
