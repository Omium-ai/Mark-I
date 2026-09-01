// The 08 §4.5 fallback door (FR-SPINE-005). Where an agent surface cannot exec
// the shim and can only speak HTTP, mark1d offers a loopback listener instead
// of the UDS — a constrained entrance to the SAME single-writer admission path
// (04 §1), not a second fabric and not a second trust class (07 §801).
//
// It is a different shape from listener.go on purpose. The UDS carries M1PL
// frames and its whole admission control is the 0600/0700 mode bits: a file
// only this uid can open. A TCP port has no mode bits — every process on the
// machine can connect, and so can a browser page the user is merely visiting.
// So the three checks below are not defense in depth over a filesystem
// permission; they ARE the permission, and each one independently kills the
// DNS-rebinding shape (10 §threats, F-39). They therefore fail CLOSED: a
// missing bearer is a refusal, never a fall back to unauthenticated.
//
// Deliberately untagged. TCP is portable, and listener_windows.go's refusal is
// about 07 §5's named pipe — the transport whose security model this file does
// not have and does not claim.
package fabric

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// Loopback is the 08 §4.5 listener: POST /m1pl, one JSON m1p.v1.Event per
// request, behind the Host/Origin/bearer wall.
type Loopback struct {
	l    net.Listener
	http *http.Server
	s    *Server

	// host is the EXACT bound literal ("127.0.0.1:<port>") the Host header must
	// equal. Held as the string the listener itself reports, so it can never
	// drift from what was actually bound.
	host string
	// token is this listener's bearer. One per construction, i.e. per boot of
	// the daemon that constructs it.
	//
	// ponytail: single token, not a per-session table. 08 §4.5 says the door
	// "accepts events only for sessions whose token it issued", and with one
	// issued token that sentence is satisfied but not scalable — the upgrade is
	// a map[token][16]byte session id, and it is owed by the same wave that
	// adds POST /m1pl/gate, which cannot exist without it (see below).
	token string
}

// ListenLoopback binds 127.0.0.1 on a kernel-chosen high port — never 0.0.0.0,
// never :: (08 §4.5) — and mints this listener's bearer token. Nothing is
// served until Serve; nothing is discoverable until a caller publishes Addr and
// Token, which is what keeps the door OFF unless an adapter asks for it.
func ListenLoopback(s *Server) (*Loopback, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		_ = l.Close()
		return nil, err
	}
	lb := &Loopback{l: l, s: s, host: l.Addr().String(), token: hex.EncodeToString(raw[:])}
	// ReadHeaderTimeout, not just because gosec asks: an unauthenticated peer
	// gets to hold a connection until it has said enough for the wall to judge
	// it, and no longer. Same reasoning as server.go's handshake deadline.
	lb.http = &http.Server{Handler: lb, ReadHeaderTimeout: DefaultHandshakeTimeout}
	return lb, nil
}

// Addr is the bound literal, which is also the only legal Host.
func (lb *Loopback) Addr() string { return lb.host }

// Token is the bearer every request must carry. The caller publishes it —
// 08 §4.5's ~/.omium/mark1/loopback.json, 0600 — which is a wiring step, not
// this listener's: it does not know where the daemon keeps its state.
func (lb *Loopback) Token() string { return lb.token }

// Serve runs until Close. ErrServerClosed is the ordinary shutdown, matching
// Server.Serve's treatment of net.ErrClosed.
func (lb *Loopback) Serve() error {
	if err := lb.http.Serve(lb.l); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Close severs the listener and every live connection, whether or not Serve
// ever ran (http.Server only tracks a listener from Serve onward).
func (lb *Loopback) Close() error {
	err := lb.http.Close()
	_ = lb.l.Close()
	return err
}

func (lb *Loopback) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// The three walls run in 08 §4.5 order, BEFORE the route match and before
	// any body byte is read — a refused caller must not reach the decoder.
	//
	// WHY the Host must be the literal and not merely resolve to loopback:
	// DNS rebinding points attacker.example at 127.0.0.1, so the browser
	// connects here quite legitimately and the Host header carries the
	// attacker's name. Comparing against the bound literal makes the whole
	// class structurally inert; comparing against "does it resolve to
	// loopback" would accept every rebind.
	if r.Host != lb.host {
		refuse(w, http.StatusForbidden, "M1E-4004", "Host is not the bound loopback literal")
		return
	}
	// ANY Origin, including an empty or "null" one, is a browser and is
	// refused: no CORS, no preflight answer. Read from the map rather than
	// Header.Get because Get cannot tell `Origin:` (present, empty — what a
	// sandboxed or file:// page sends) from absent, and 08 §4.5 rejects on
	// presence.
	if _, ok := r.Header[http.CanonicalHeaderKey("Origin")]; ok {
		refuse(w, http.StatusForbidden, "M1E-4005", "loopback requests carry no Origin; a local process is not a browser page")
		return
	}
	if !lb.authorized(r.Header.Get("Authorization")) {
		refuse(w, http.StatusUnauthorized, "M1E-1002", "missing or wrong session bearer token")
		return
	}

	if r.URL.Path != "/m1pl" {
		refuse(w, http.StatusNotFound, "M1E-2001", "the loopback door serves /m1pl only")
		return
	}
	if r.Method != http.MethodPost {
		refuse(w, http.StatusMethodNotAllowed, "M1E-2001", "POST /m1pl")
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxFrame))
	if err != nil {
		refuse(w, http.StatusBadRequest, "M1E-2001", "unreadable body")
		return
	}
	ev := &m1pv1.Event{}
	if err := protojson.Unmarshal(body, ev); err != nil {
		refuse(w, http.StatusBadRequest, "M1E-2001", "body is not one JSON m1p.v1.Event")
		return
	}
	// Re-encoded to the wire form the spool stores, because on this route the
	// caller never sent wire bytes — there is no writer's-exact-bytes property
	// (D-U) to preserve, only the same Event entering the same door.
	inner, err := proto.Marshal(ev)
	if err != nil {
		refuse(w, http.StatusBadRequest, "M1E-2001", "event does not re-encode")
		return
	}
	if herr := lb.s.handle(r.Context(), inner); herr != nil && !lb.s.perEvent(herr) {
		refuse(w, http.StatusServiceUnavailable, "M1E-9500", "admission unavailable")
		return
	}
	// A per-event outcome (shed, quarantine) answers 204 like an admitted one:
	// perEvent is the Server's own declaration that capture has ALREADY
	// accounted the loss, so the caller has nothing left to do about it.
	w.WriteHeader(http.StatusNoContent)
}

// authorized is constant-time past the scheme: no timing oracle on a port every
// local process can reach. The scheme match is exact, mirroring the Rust wall
// in cortexd (rust/cortexd/src/mcp/mod.rs) — one dialect, both ends.
func (lb *Loopback) authorized(header string) bool {
	tok, ok := strings.CutPrefix(header, "Bearer ")
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(tok), []byte(lb.token)) == 1
}

// refuse writes 08 §9's machine-readable envelope. No detail beyond the code:
// a refused caller learns that it was refused and which wall, never anything
// that helps it guess the token.
func refuse(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]map[string]string{
		"error": {"code": code, "message": message},
	})
}
