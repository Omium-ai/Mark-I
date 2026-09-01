// Revocation at the ROUTE, not at the verifier.
//
// auth/verify_test.go and auth/token_test.go already prove the verifier
// returns auth.ErrRevoked, and server/middleware.go already proves ErrRevoked
// maps to 403 M1E-1003. What was untested is the wiring: that all three
// policydist routes are actually behind that chain. Deleting m.verifier from
// the server.Chain(...) call in RegisterRoutes, or registering one route bare,
// left the package green while every policy route served revoked devices.
//
// Nothing here needs Postgres: a 403 is decided before any handler touches a
// store, and the live-device control uses a DB seam that fails, which is
// enough to prove the handler was REACHED.

package policydist

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
)

var revTokenKey = []byte("policydist-revocation-test-hmac-key")

// revDB is the WithTenant seam, always failing. Latest maps ErrNoChannel to
// 404 M1E-3004 and RecordAck maps any error to 400 M1E-2001 — both are codes
// only the handler can emit, so they are proof the request got past auth
// rather than proof of a mux miss.
type revDB struct{}

func (revDB) WithTenant(context.Context, querychoke.TenantID, func(pgx.Tx) error) error {
	return ErrNoChannel
}

// revServer mounts the real RegisterRoutes with the real middleware chain. The
// ONLY difference between the revoked and live cases is the revocation set —
// same token, same routes, same store — so a difference in outcome can only be
// revocation.
func revServer(t *testing.T, revoked bool) (*httptest.Server, string) {
	t.Helper()
	tenant, device := uuid.New(), uuid.New()
	set := auth.StaticRevocations{}
	if revoked {
		set[device] = true
	}
	m := NewModule(ModuleDeps{
		Store:    NewStore(revDB{}, nil, nil, nil),
		Verifier: auth.NewHMACVerifier(revTokenKey, set),
		ObsCfg:   obs.Config{ServiceName: "controld-policydist-revocation-test"},
	})
	mux := http.NewServeMux()
	m.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, auth.Mint(revTokenKey, tenant, device, time.Hour)
}

// policyRoute is every route RegisterRoutes mounts. All three, because they
// share one chain today and a refactor that gives one route its own chain is
// exactly the regression worth catching.
type policyRoute struct {
	name, method, path, body string
}

func policyRoutes() []policyRoute {
	ack := `{"channel":"stable","seq":1,"bundle_hash":"` + strings.Repeat("ab", 32) + `","result":"applied"}`
	return []policyRoute{
		{"bundle", http.MethodGet, "/api/v1/policy/bundle?channel=stable", ""},
		{"stream", http.MethodGet, "/api/v1/policy/stream?channel=stable", ""},
		{"ack", http.MethodPost, "/api/v1/policy/ack", ack},
	}
}

func (r policyRoute) do(t *testing.T, ctx context.Context, srv *httptest.Server, token string) *http.Response {
	t.Helper()
	var body *strings.Reader
	if r.body != "" {
		body = strings.NewReader(r.body)
	} else {
		body = strings.NewReader("")
	}
	req, err := http.NewRequestWithContext(ctx, r.method, srv.URL+r.path, body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Mark1-Edge-Version", "mark1d/0.1.0")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", r.method, r.path, err)
	}
	return resp
}

// revErrCode decodes the 08 §9 envelope. It deliberately FAILS on a body that
// is not that envelope: net/http's own 404 for an unmatched route is
// text/plain, so "the mux never saw this path" cannot masquerade as a refusal.
func revErrCode(t *testing.T, resp *http.Response) string {
	t.Helper()
	var env struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatalf("response body is not the M1E error envelope (%v); a bare mux 404 is not a refusal", err)
	}
	if env.Error.Code == "" {
		t.Fatal("response carries no error code")
	}
	return env.Error.Code
}

// TestPolicyRoutesRefuseRevokedDevice is FR-ENROLL-004's bundle-fetch refusal:
// every policydist route must answer a revoked device with 403 M1E-1003
// (08 §9, terminal — re-enroll).
func TestPolicyRoutesRefuseRevokedDevice(t *testing.T) {
	srv, token := revServer(t, true)
	routes := policyRoutes()
	if len(routes) != 3 {
		t.Fatalf("the route table covers %d routes; RegisterRoutes mounts 3", len(routes))
	}
	for _, r := range routes {
		t.Run(r.name, func(t *testing.T) {
			resp := r.do(t, context.Background(), srv, token)
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("%s %s served a revoked device %d, want 403", r.method, r.path, resp.StatusCode)
			}
			if code := revErrCode(t, resp); code != "M1E-1003" {
				t.Fatalf("%s %s refused with %s, want M1E-1003", r.method, r.path, code)
			}
		})
	}
}

// TestPolicyRoutesServeLiveDevice is the positive control. Without it, a route
// the mux never matched and a handler that panicked on the way in are both
// indistinguishable from "it refused": the obs middleware turns a panic into a
// 500, and an unmounted path into a 404 — neither is a 403, so a
// "must not 403" assertion alone would pass on both. Each route is therefore
// checked for a specific outcome only its own handler can produce.
func TestPolicyRoutesServeLiveDevice(t *testing.T) {
	srv, token := revServer(t, false)
	for _, r := range policyRoutes() {
		t.Run(r.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			resp := r.do(t, ctx, srv, token)
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode == http.StatusForbidden {
				t.Fatalf("%s %s refused a device that is NOT revoked", r.method, r.path)
			}
			switch r.name {
			case "bundle":
				// revDB has no bundle: the one server-side 3xxx (08 §3.2).
				if resp.StatusCode != http.StatusNotFound || revErrCode(t, resp) != "M1E-3004" {
					t.Fatalf("bundle handler was not reached: %d", resp.StatusCode)
				}
			case "stream":
				// The hub is in-process, so the stream really opens.
				if resp.StatusCode != http.StatusOK ||
					resp.Header.Get("Content-Type") != "text/event-stream" {
					t.Fatalf("stream handler was not reached: %d %q",
						resp.StatusCode, resp.Header.Get("Content-Type"))
				}
			case "ack":
				// A well-formed ACK that reaches a failing ledger: 400 M1E-2001
				// is emitted only after parseAck and the store call.
				if resp.StatusCode != http.StatusBadRequest || revErrCode(t, resp) != "M1E-2001" {
					t.Fatalf("ack handler was not reached: %d", resp.StatusCode)
				}
			}
		})
	}
}
