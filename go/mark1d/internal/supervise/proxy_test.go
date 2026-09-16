package supervise

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/claudecode"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/capture"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/coverage"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/redact"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/spool"
	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"google.golang.org/protobuf/proto"
)

// The two halves of the stale-port control are tested together because they are
// one control: the supervisor stops `proxy.port` outliving the process it
// describes, and the provisioner refuses to believe the file when it does
// anyway (a SIGKILLed mark1d leaves one behind and no shutdown path runs).
// Proving either half alone proves nothing about the exposure.

const userSettings = `{
  "model": "opus"
}
`

// apiKeyMachine is the only shape in which the base-URL fragment may be
// written: a home with an agent settings file, an API-key credential, and a
// state dir laid out where mark1-proxy would derive it ($HOME/.omium/mark1).
func apiKeyMachine(t *testing.T) (home, state string) {
	t.Helper()
	home = t.TempDir()
	state = filepath.Join(home, ".omium", "mark1")
	for _, d := range []string{filepath.Join(home, ".claude"), state} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, ".claude", "settings.json"), []byte(userSettings), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-test-key")
	return home, state
}

// guardStub answers the way the real guard answers a request carrying no
// M1-Cred-Ref: 403 with M1E-8001 in the frozen error body
// (rust/mark1-proxy/src/router.rs `handle`, the Decision::Refused arm; body
// shape from lib.rs `error_body`).
func guardStub(t *testing.T) int {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The probe must never carry the thing it exists to protect.
		for _, h := range []string{"x-api-key", "Authorization", "M1-Cred-Ref"} {
			if v := r.Header.Get(h); v != "" {
				t.Errorf("liveness probe sent %s: %q", h, v)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"M1E-8001","message":"request without a valid M1-Cred-Ref"}}`))
	}))
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().(*net.TCPAddr).Port
}

func writePort(t *testing.T, state string, port int) {
	t.Helper()
	if err := os.WriteFile(claudecode.ProxyPortPath(state), []byte(strconv.Itoa(port)), 0o600); err != nil {
		t.Fatal(err)
	}
}

// deadPort is a port nothing holds: bound, then released. This is exactly the
// state a crashed proxy leaves behind, and the kernel is free to hand it to any
// other local process the moment it is free.
func deadPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func TestProxyPointerRefusesUnlessTheGuardAnswers(t *testing.T) {
	for _, tc := range []struct {
		name    string
		listen  func(t *testing.T) int
		wantErr bool
	}{
		{
			name:   "a live guard is provisioned",
			listen: guardStub,
		},
		{
			name:    "a port nobody holds is refused",
			listen:  deadPort,
			wantErr: true,
		},
		{
			// The case a bare TCP connect cannot see, and the whole reason the
			// probe reads the body: the squatter IS listening.
			name: "a listener that is not the guard is refused",
			listen: func(t *testing.T) int {
				t.Helper()
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte("hello"))
				}))
				t.Cleanup(srv.Close)
				return srv.Listener.Addr().(*net.TCPAddr).Port
			},
			wantErr: true,
		},
		{
			// A 403 alone is not the fingerprint: plenty of local servers refuse
			// an unauthenticated GET, and one of them inheriting the port must
			// not be read as our guard.
			name: "a 403 without the guard's code is refused",
			listen: func(t *testing.T) int {
				t.Helper()
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusForbidden)
					_, _ = w.Write([]byte(`{"error":"forbidden"}`))
				}))
				t.Cleanup(srv.Close)
				return srv.Listener.Addr().(*net.TCPAddr).Port
			},
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home, state := apiKeyMachine(t)
			writePort(t, state, tc.listen(t))
			a := &claudecode.Adapter{Home: home, StateDir: state}

			_, err := a.ApplyProxyPointer()
			if tc.wantErr {
				if !errors.Is(err, claudecode.ErrNotEligible) {
					t.Fatalf("err = %v, want ErrNotEligible", err)
				}
				// The settings file must not have been opened for write: the
				// refusal precedes it (04 §3.1, ApplyProxyPointer's contract).
				b, rerr := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
				if rerr != nil {
					t.Fatal(rerr)
				}
				if string(b) != userSettings {
					t.Errorf("settings written for a port with no guard behind it:\n%s", b)
				}
				return
			}
			if err != nil {
				t.Fatalf("ApplyProxyPointer against a live guard: %v", err)
			}
			b, rerr := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
			if rerr != nil {
				t.Fatal(rerr)
			}
			if !bytes.Contains(b, []byte("ANTHROPIC_BASE_URL")) {
				t.Errorf("live guard was not provisioned:\n%s", b)
			}
		})
	}
}

// The ordinary death: the supervisor knows the instant the child stopped, so
// the file naming its port stops existing before anything can read it.
func TestProxyPortDoesNotSurviveTheProxysDeath(t *testing.T) {
	home, state := apiKeyMachine(t)
	t.Setenv(childEnvVar, "port")
	child, err := ProxyChild(ProxyConfig{StateDir: state, Binary: os.Args[0], Log: (&logCapture{}).logger()})
	if err != nil {
		t.Fatal(err)
	}
	child.Backoff = fastBackoff()
	s := New((&logCapture{}).logger())
	s.Add(child)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		s.Run(ctx)
		close(done)
	}()

	// The child derives the path from $HOME, so its appearance also proves the
	// HOME override put the proxy's base where the provisioner reads it.
	port := claudecode.ProxyPortPath(state)
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := os.Stat(port); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("child never published %s (home=%s)", port, home)
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	<-done
	if _, err := os.Stat(port); !os.IsNotExist(err) {
		t.Fatalf("%s outlived the process it describes: %v", port, err)
	}
}

// The FAILED path, end to end: 04 :81's two obligations and the one it cannot
// meet. This is also the state that lasts — there is no seventh restart to
// clean up after it — so a surviving proxy.port would name a freed ephemeral
// port for as long as the daemon runs.
func TestProxyFailedRevertsTheFragmentAndAnnouncesTheMissingReceipt(t *testing.T) {
	home, state := apiKeyMachine(t)
	writePort(t, state, guardStub(t))
	a := &claudecode.Adapter{Home: home, StateDir: state}
	if _, err := a.ApplyProxyPointer(); err != nil {
		t.Fatalf("setup: %v", err)
	}
	settings := filepath.Join(home, ".claude", "settings.json")
	provisioned, err := os.ReadFile(settings)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(provisioned, []byte("ANTHROPIC_BASE_URL")) {
		t.Fatal("setup: the fragment was not provisioned")
	}

	t.Setenv(childEnvVar, "port-then-crash")
	logs := &logCapture{}
	child, err := ProxyChild(ProxyConfig{StateDir: state, Binary: os.Args[0], Log: logs.logger()})
	if err != nil {
		t.Fatal(err)
	}
	child.Backoff = fastBackoff()
	child.Breaker = Breaker{Max: 1, Window: time.Minute}
	s := New(logs.logger())
	s.Add(child)
	s.Run(t.Context()) // returns when the breaker trips: FAILED is terminal

	// (i) The developer is never blocked: traffic goes direct.
	after, err := os.ReadFile(settings)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != userSettings {
		t.Errorf("base-URL fragment not reverted on FAILED:\n%s", after)
	}
	if _, err := os.Stat(claudecode.ProxyPortPath(state)); !os.IsNotExist(err) {
		t.Errorf("proxy.port survived FAILED: %v", err)
	}
	// (ii) The receipt that cannot be emitted must at least be announced.
	if !bytes.Contains([]byte(logs.String()), []byte("COVERAGE BYPASS NOT RECEIPTED")) {
		t.Errorf("the missing CoverageTransition{BYPASS} was not announced:\n%s", logs.String())
	}
	if !bytes.Contains([]byte(logs.String()), []byte("proxy_failed")) {
		t.Errorf("the 04 :655 reason code was not named:\n%s", logs.String())
	}
}

// realSpool builds the actual admit path — spool, redactor, Admitter — because
// a fake admit func would prove only that proxyFailed calls something. What is
// under test is that the event survives capture's pipeline (normalize,
// redact-admit, seq-stamp, class-tag) and lands as bytes a server could read.
func realSpool(t *testing.T, state string) (*spool.Spool, *capture.Admitter) {
	t.Helper()
	sp, err := spool.Open(spool.Config{Dir: filepath.Join(state, "spool")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sp.Close() })
	sc, err := redact.NewScanner(nil)
	if err != nil {
		t.Fatal(err)
	}
	adm, err := capture.New(sp, capture.Config{
		EpochPath: filepath.Join(state, "session_epoch"),
		Redact:    sc.RedactEvent,
	})
	if err != nil {
		t.Fatal(err)
	}
	return sp, adm
}

// spooledTransitions decodes rather than counts: "a record exists" is satisfied
// by any bytes, including a quarantined envelope.
func spooledTransitions(t *testing.T, sp *spool.Spool) []*m1pv1.CoverageTransition {
	t.Helper()
	if err := sp.Sync(); err != nil { // Records exposes the durable region only
		t.Fatal(err)
	}
	ack, _ := sp.Cursors()
	recs, _, err := sp.Records(ack)
	if err != nil {
		t.Fatal(err)
	}
	var out []*m1pv1.CoverageTransition
	for _, r := range recs {
		ev := &m1pv1.Event{}
		if err := proto.Unmarshal(r.Payload, ev); err != nil {
			t.Fatalf("a spooled record did not decode as an Event: %v", err)
		}
		if b, ok := ev.GetBody().(*m1pv1.Event_CoverageTransition); ok {
			out = append(out, b.CoverageTransition)
		}
	}
	return out
}

// TestProxyFailedReceiptsTheBypassWindow is the wired half of the test above,
// and the half that makes it mean something: with a coverage plane present the
// announcement must stop being an announcement and become an event on the
// spool. Without this, "NOT RECEIPTED was logged" is equally satisfied by a
// proxyFailed that can never receipt anything at all.
//
// It runs through ProxyChild and the supervisor rather than calling proxyFailed
// directly, because the defect this guards is a ProxyConfig.Coverage that never
// reaches the FAILED arm — which a direct call could not see.
func TestProxyFailedReceiptsTheBypassWindow(t *testing.T) {
	home, state := apiKeyMachine(t)
	writePort(t, state, guardStub(t))
	a := &claudecode.Adapter{Home: home, StateDir: state}
	if _, err := a.ApplyProxyPointer(); err != nil {
		t.Fatalf("setup: %v", err)
	}
	sp, adm := realSpool(t, state)

	t.Setenv(childEnvVar, "port-then-crash")
	logs := &logCapture{}
	child, err := ProxyChild(ProxyConfig{
		StateDir: state, Binary: os.Args[0], Log: logs.logger(),
		Coverage: coverage.New(adm.Admit, nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	child.Backoff = fastBackoff()
	child.Breaker = Breaker{Max: 1, Window: time.Minute}
	s := New(logs.logger())
	s.Add(child)
	s.Run(t.Context()) // returns when the breaker trips: FAILED is terminal

	got := spooledTransitions(t, sp)
	if len(got) != 1 {
		t.Fatalf("coverage transitions = %d, want exactly 1 — FAILED opened an unreceipted bypass window\nlogs:\n%s",
			len(got), logs.String())
	}
	if got[0].GetReasonCode() != coverage.ReasonProxyFailed {
		t.Errorf("reason_code = %q, want %q", got[0].GetReasonCode(), coverage.ReasonProxyFailed)
	}
	if got[0].GetKind() != m1pv1.CoverageKind_COVERAGE_KIND_BYPASS {
		t.Errorf("kind = %v, want BYPASS — a dead proxy is a bypass window, not a disable", got[0].GetKind())
	}
	// Zero files it as bypass_start server-side (sidefx.coverageKind). FAILED is
	// terminal for this daemon's proxy, so the window has no in-process close.
	if got[0].GetDurationMs() != 0 {
		t.Errorf("duration_ms = %d, want 0 (bypass_start)", got[0].GetDurationMs())
	}
	// m1_043 CHECKs octet_length(workspace_digest) = 32 inside AppendCheckpoint's
	// transaction: a wrong-length digest does not drop a row, it stalls the chain.
	if len(got[0].GetWorkspaceId()) != coverage.WorkspaceIDLen {
		t.Errorf("workspace_id is %d bytes, want %d", len(got[0].GetWorkspaceId()), coverage.WorkspaceIDLen)
	}
	if strings.Contains(logs.String(), "COVERAGE BYPASS NOT RECEIPTED") {
		t.Errorf("a receipted window still reported itself as a gap:\n%s", logs.String())
	}
	// The other obligation still holds — receipting the window must not have
	// replaced reverting the fragment.
	after, err := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != userSettings {
		t.Errorf("base-URL fragment not reverted on FAILED:\n%s", after)
	}
}

func TestProxyChildRefusesLegibly(t *testing.T) {
	t.Run("a state dir the proxy cannot derive", func(t *testing.T) {
		_, err := ProxyChild(ProxyConfig{StateDir: t.TempDir(), Binary: os.Args[0]})
		if err == nil {
			t.Fatal("supervised a proxy that would publish its port somewhere else")
		}
	})
	t.Run("a missing binary", func(t *testing.T) {
		home := t.TempDir()
		state := filepath.Join(home, ".omium", "mark1")
		_, err := ProxyChild(ProxyConfig{StateDir: state, Binary: filepath.Join(home, "nope")})
		if !errors.Is(err, ErrNoProxyBinary) {
			t.Fatalf("ProxyChild() = %v, want ErrNoProxyBinary", err)
		}
	})
	t.Run("MARK1_PROXY pointing at nothing is an error, not a fallthrough", func(t *testing.T) {
		bad := filepath.Join(t.TempDir(), "nope")
		t.Setenv(proxyBinaryEnv, bad)
		_, err := FindProxy()
		if !errors.Is(err, ErrNoProxyBinary) {
			t.Fatalf("FindProxy() = %v, want ErrNoProxyBinary", err)
		}
		// The path must be IN the message. ErrNoProxyBinary alone would also be
		// returned by a silent fallthrough that searched on and found nothing —
		// which is the bug this asserts against, since falling through runs a
		// different binary than the operator named.
		if !strings.Contains(err.Error(), bad) {
			t.Errorf("FindProxy() = %v; the operator's own path is not named, so a silent fallthrough is indistinguishable", err)
		}
	})
}

// TestGatewayFlagsPassThroughVerbatim: the daemon's only gateway duty is to
// hand the proxy exactly the flags main.rs parses, in sidecar mode exactly
// `--mode sidecar` and nothing else.
func TestGatewayFlagsPassThroughVerbatim(t *testing.T) {
	var nilFlags *GatewayFlags
	if got := strings.Join(nilFlags.args(), " "); got != "--mode sidecar" {
		t.Fatalf("sidecar args = %q", got)
	}
	g := &GatewayFlags{Bind: "0.0.0.0:8443", TLSCert: "/etc/mark1/gw.pem", TLSKey: "/etc/mark1/gw.key", ClientCA: "/etc/mark1/clients.pem", CredDir: "/run/mark1/creds"}
	want := "--mode gateway --bind 0.0.0.0:8443 --tls-cert /etc/mark1/gw.pem --tls-key /etc/mark1/gw.key --client-ca /etc/mark1/clients.pem --cred-dir /run/mark1/creds"
	if got := strings.Join(g.args(), " "); got != want {
		t.Fatalf("gateway args =\n%s\nwant\n%s", got, want)
	}
	// And the child actually runs with them.
	home := t.TempDir()
	state := filepath.Join(home, ".omium", "mark1")
	child, err := ProxyChild(ProxyConfig{StateDir: state, Binary: os.Args[0], Gateway: g})
	if err != nil {
		t.Fatal(err)
	}
	cmd, err := child.Start(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(cmd.Args[1:], " "); got != want {
		t.Fatalf("child argv = %q", got)
	}
}
