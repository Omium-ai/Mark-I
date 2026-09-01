package fabric

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// The 08 §4.5 wall (FR-SPINE-005), one test per check. Every negative case
// asserts THREE things — the status, the 08 §9 code, and that nothing reached
// the admission path — because "403" alone is also what a listener that fell
// over would produce, and a refusal that still admitted the event is the exact
// bug the row exists to prevent.
//
// Each test carries its own positive control for the same reason: a suite where
// every request is refused passes just as well against a listener that refuses
// everything, which would be no security property at all.

type loopbackHarness struct {
	lb *Loopback

	mu       sync.Mutex
	admitted [][]byte
}

func startLoopback(t *testing.T) *loopbackHarness {
	t.Helper()
	h := &loopbackHarness{}
	srv := NewServer(func(_ context.Context, payload []byte) error {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.admitted = append(h.admitted, payload)
		return nil
	}, nil)
	lb, err := ListenLoopback(srv)
	if err != nil {
		t.Fatal(err)
	}
	h.lb = lb
	go func() { _ = lb.Serve() }()
	t.Cleanup(func() { _ = lb.Close() })
	return h
}

func (h *loopbackHarness) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.admitted)
}

func (h *loopbackHarness) last(t *testing.T) *m1pv1.Event {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.admitted) == 0 {
		t.Fatal("nothing reached the admission path")
	}
	ev := &m1pv1.Event{}
	if err := proto.Unmarshal(h.admitted[len(h.admitted)-1], ev); err != nil {
		t.Fatalf("admitted bytes are not an Event: %v", err)
	}
	return ev
}

// req is one loopback request. Zero values mean "well-formed": the bound
// literal Host, the issued bearer, no Origin at all.
type req struct {
	host   string
	auth   string
	origin *string // non-nil ⇒ the header is SENT, even when empty
	tokens uint64
	noAuth bool
}

// do sends one JSON-encoded Event and returns the status and the 08 §9 error
// code (empty when the body carries none).
func (h *loopbackHarness) do(t *testing.T, r req) (int, string) {
	t.Helper()
	body, err := protojson.Marshal(&m1pv1.Event{
		SessionId: testSession[:],
		Body:      &m1pv1.Event_Usage{Usage: &m1pv1.Usage{IdemKey: make([]byte, 32), OutputTokens: r.tokens}},
	})
	if err != nil {
		t.Fatal(err)
	}
	hr, err := http.NewRequest(http.MethodPost, "http://"+h.lb.Addr()+"/m1pl", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	// req.Host, not a header set: this is what the client puts on the wire, and
	// it is how a rebound browser reaches a loopback port under a foreign name.
	if r.host != "" {
		hr.Host = r.host
	}
	switch {
	case r.noAuth: // send nothing
	case r.auth != "":
		hr.Header.Set("Authorization", r.auth)
	default:
		hr.Header.Set("Authorization", "Bearer "+h.lb.Token())
	}
	if r.origin != nil {
		hr.Header["Origin"] = []string{*r.origin}
	}
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Do(hr)
	if err != nil {
		t.Fatalf("loopback request failed at the transport, not the wall: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var env struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&env)
	return resp.StatusCode, env.Error.Code
}

// accepts is the positive control: literal Host, issued bearer, no Origin ⇒
// 204 AND the event lands in the admission path with its payload intact. Every
// refusal test runs it, so no refusal can be an unrelated connection failure.
func (h *loopbackHarness) accepts(t *testing.T, tokens uint64) {
	t.Helper()
	before := h.count()
	st, code := h.do(t, req{tokens: tokens})
	if st != http.StatusNoContent || code != "" {
		t.Fatalf("positive control refused: %d %q — the wall is rejecting a well-formed caller", st, code)
	}
	if h.count() != before+1 {
		t.Fatalf("204 returned but admission saw %d events, want %d", h.count(), before+1)
	}
	if got := h.last(t).GetUsage().GetOutputTokens(); got != tokens {
		t.Fatalf("admitted event carries output_tokens %d, want %d", got, tokens)
	}
	if got := h.last(t).GetSessionId(); !bytes.Equal(got, testSession[:]) {
		t.Fatalf("admitted event session_id %x, want %x", got, testSession[:])
	}
}

// TestLoopbackRequiresSessionBearer: 08 §4.5's bearer is REQUIRED, and every
// non-answer collapses to the same refusal — fail-closed, no unauthenticated
// fallback (FR-SPINE-005: "No unauthenticated localhost-HTTP fallback may
// exist").
func TestLoopbackRequiresSessionBearer(t *testing.T) {
	h := startLoopback(t)
	h.accepts(t, 11) // the door does open for the issued token

	good := h.lb.Token()
	// One hex digit off, deterministically: flipping the last character to a
	// FIXED "0" passes ~15 runs in 16 and then fails on the token that already
	// ends in 0, which is how this test first went red — a wrong-token case
	// that is sometimes the right token is worse than none.
	wrong := good[:len(good)-1] + "0"
	if strings.HasSuffix(good, "0") {
		wrong = good[:len(good)-1] + "1"
	}
	for _, tc := range []struct {
		name string
		r    req
	}{
		{"absent", req{noAuth: true}},
		{"wrong token", req{auth: "Bearer " + wrong}},
		{"truncated token", req{auth: "Bearer " + good[:16]}},
		{"bare token, no scheme", req{auth: good}},
		{"wrong scheme", req{auth: "Basic " + good}},
		{"empty bearer", req{auth: "Bearer x"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := h.count()
			st, code := h.do(t, tc.r)
			if st != http.StatusUnauthorized || code != "M1E-1002" {
				t.Fatalf("got %d %q, want 401 M1E-1002 — a %s bearer must be refused, never accepted", st, code, tc.name)
			}
			if h.count() != before {
				t.Fatal("refused with 401 and admitted the event anyway")
			}
		})
	}

	h.accepts(t, 12) // and still opens afterwards: the refusals wedged nothing
}

// TestLoopbackRejectsNonLiteralHost: the Host must be the exact bound literal.
// "localhost" resolves here and is still refused — that is the entire point,
// because a DNS-rebound browser also resolves here, and only the literal
// distinguishes them (08 §4.5, threat "rogue browser page / DNS rebinding").
func TestLoopbackRejectsNonLiteralHost(t *testing.T) {
	h := startLoopback(t)
	h.accepts(t, 21)

	_, port, ok := strings.Cut(h.lb.Addr(), ":")
	if !ok {
		t.Fatalf("bound literal %q is not host:port", h.lb.Addr())
	}
	for _, host := range []string{
		"localhost:" + port,            // resolves to 127.0.0.1 and is STILL not the literal
		"attacker.example:" + port,     // the rebinding shape verbatim
		"127.0.0.1.nip.io:" + port,     // a name that resolves to loopback by construction
		"127.0.0.1",                    // literal address, port dropped
		"127.0.0.1:1",                  // literal address, wrong port
		"[::1]:" + port,                // loopback, but not the interface we bound
		"127.000.000.001:" + port,      // same address, different spelling
		"0177.0.0.1:" + port,           // octal spelling of 127.0.0.1
		h.lb.Addr() + ".attacker.test", // the literal as a prefix
	} {
		t.Run(host, func(t *testing.T) {
			before := h.count()
			st, code := h.do(t, req{host: host})
			if st != http.StatusForbidden || code != "M1E-4004" {
				t.Fatalf("Host %q got %d %q, want 403 M1E-4004", host, st, code)
			}
			if h.count() != before {
				t.Fatalf("Host %q was refused and the event was admitted anyway", host)
			}
		})
	}

	h.accepts(t, 22)
}

// TestLoopbackRejectsForeignOrigin: ANY Origin is a browser, and a browser is
// never a legitimate caller here (08 §4.5). Including an Origin naming this
// very listener — there is no CORS story to get right, so there is no
// same-origin exception to get wrong.
func TestLoopbackRejectsForeignOrigin(t *testing.T) {
	h := startLoopback(t)
	h.accepts(t, 31)

	for _, origin := range []string{
		"https://evil.example",
		"http://" + h.lb.Addr(), // the listener's own address: still refused
		"null",                  // what a sandboxed iframe / file:// page sends
		"",                      // present but empty — Header.Get cannot see this one
	} {
		t.Run("origin="+origin, func(t *testing.T) {
			before := h.count()
			o := origin
			st, code := h.do(t, req{origin: &o})
			if st != http.StatusForbidden || code != "M1E-4005" {
				t.Fatalf("Origin %q got %d %q, want 403 M1E-4005", origin, st, code)
			}
			if h.count() != before {
				t.Fatalf("Origin %q was refused and the event was admitted anyway", origin)
			}
		})
	}

	h.accepts(t, 32)
}

// TestLoopbackBindsLoopbackOnly pins the bind itself: 08 §4.5 says
// "never 0.0.0.0, never ::", and a listener that got that wrong would pass
// every test above while being reachable from the network.
func TestLoopbackBindsLoopbackOnly(t *testing.T) {
	h := startLoopback(t)
	ta, ok := h.lb.l.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("bound %T, want *net.TCPAddr", h.lb.l.Addr())
	}
	if !ta.IP.IsLoopback() {
		t.Fatalf("bound %s — 08 §4.5 requires the loopback interface, never a wildcard", ta.IP)
	}
	if h.lb.Addr() != ta.String() {
		t.Fatalf("the Host literal %q is not what was bound (%s)", h.lb.Addr(), ta)
	}
}
