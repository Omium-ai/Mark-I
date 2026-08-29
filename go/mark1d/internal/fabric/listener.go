//go:build unix

// The M1PL server half of 07 §5: socket-path resolution, the 0600/0700
// permission boundary, and the accept loop that feeds each connection's bytes
// through the incremental Decoder into the single admission door. Windows
// named pipes (\\.\pipe\omium-mark1-<user-SID>, 07 §5) are their own row;
// this file is deliberately unix-only.
package fabric

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

// SocketPath resolves 07 §5's transport endpoint: $XDG_RUNTIME_DIR/omium-mark1/m1p.sock,
// falling back to ~/.omium/mark1/m1p.sock. (08 §4.1's older mark1d.sock name
// lost the R-2 reconciliation, 04 §0.4 — 07 is authoritative.)
func SocketPath() (string, error) {
	if rd := os.Getenv("XDG_RUNTIME_DIR"); rd != "" {
		return filepath.Join(rd, "omium-mark1", "m1p.sock"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".omium", "mark1", "m1p.sock"), nil
}

// Listen creates the UDS with 07 §5's boundary: parent directory 0700 owned
// by this user, socket 0600, and a hard refusal — not a chmod-and-continue —
// when an existing parent grants group/world anything or belongs to someone
// else. The fabric's threat model is other users; a permissive parent is the
// one hole the mode bits exist to close.
func Listen(path string) (net.Listener, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("fabric: %s is not a directory", dir)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("fabric: refusing socket dir %s with mode %o — 07 §5 requires 0700, no group or world grant, ever", dir, fi.Mode().Perm())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		return nil, fmt.Errorf("fabric: socket dir %s owned by uid %d, not this user", dir, st.Uid)
	}
	// A stale socket from a dead daemon blocks bind; anything else at the
	// path is not ours to delete.
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("fabric: %s exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// Server owns the accept loop. handle receives each decoded frame payload —
// one encoded m1p.v1.Event (07 §5) — and is capture.AdmitBytes in the daemon:
// the fabric stays transport, admission stays policy (04 §2).
type Server struct {
	handle func(ctx context.Context, payload []byte) error
	// perEvent declares which handle errors are per-event outcomes (already
	// accounted by capture — shed, quarantine) and so connection-preserving;
	// anything else (spool closed, ctx dead) ends the stream. A predicate
	// rather than an import so transport never depends on policy (04 §2).
	perEvent func(error) bool

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
			c.Close()
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
		c.Close()
	}
	s.conns = map[net.Conn]struct{}{}
}

func (s *Server) serveConn(ctx context.Context, c net.Conn) {
	defer func() {
		c.Close()
		s.mu.Lock()
		delete(s.conns, c)
		s.mu.Unlock()
	}()
	dec := &Decoder{}
	buf := make([]byte, 64<<10)
	for {
		n, err := c.Read(buf)
		if n > 0 {
			dec.Push(buf[:n])
			for {
				payload, _, derr := dec.Next()
				if derr != nil {
					// Reject means the stream is desynchronized or hostile:
					// close, never resynchronize on attacker-chosen bytes (07 §5).
					return
				}
				if payload == nil {
					break
				}
				if herr := s.handle(ctx, payload); herr != nil && !s.perEvent(herr) {
					return
				}
			}
		}
		if err != nil {
			return
		}
	}
}
