package memory

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
)

const (
	testHMACKey  = "memory-module-test-key"
	serviceToken = "intel-service-secret"
	artifactsDoc = `{"artifacts":[{"artifact_id":"0195a000-0000-7000-8000-000000000001","kind":"pitfall","trigger":"t","guidance":"g","utility_lcb":0.3,"error_sig_digest":"ab"}]}`
	matchDoc     = `{"artifacts":[{"artifact_id":"0195a000-0000-7000-8000-000000000001","kind":"pitfall","trigger":"t","guidance":"g","utility_lcb":0.3,"error_sig_digest":"ab","distance":0.05}],"signature_digest":"ab"}`
)

type intelCall struct {
	method, path, auth, edgeVersion string
	body                            []byte
}

type fakeIntel struct {
	*httptest.Server
	mu     sync.Mutex
	calls  []intelCall
	status int
	reply  string
	delay  time.Duration
}

func newFakeIntel(t *testing.T) *fakeIntel {
	t.Helper()
	f := &fakeIntel{status: http.StatusOK}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.calls = append(f.calls, intelCall{r.Method, r.URL.RequestURI(), r.Header.Get("Authorization"), r.Header.Get("X-Mark1-Edge-Version"), raw})
		status, reply, delay := f.status, f.reply, f.delay
		f.mu.Unlock()
		if delay > 0 {
			time.Sleep(delay)
		}
		if reply == "" {
			reply = map[string]string{intelArtifacts: artifactsDoc, intelMatch: matchDoc}[r.URL.Path]
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, reply)
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeIntel) set(status int, reply string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status, f.reply = status, reply
}

func (f *fakeIntel) last(t *testing.T) intelCall {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) == 0 {
		t.Fatal("intel was never called")
	}
	return f.calls[len(f.calls)-1]
}

func (f *fakeIntel) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

type rig struct {
	mux    *http.ServeMux
	intel  *fakeIntel
	tenant uuid.UUID
	device uuid.UUID
	bearer string
}

func newRig(t *testing.T, revoked auth.StaticRevocations) *rig {
	t.Helper()
	intel := newFakeIntel(t)
	tenant, device := uuid.New(), uuid.New()
	if revoked == nil {
		revoked = auth.StaticRevocations{}
	}
	m := New(Deps{
		Verifier:          auth.NewHMACVerifier([]byte(testHMACKey), revoked),
		ObsCfg:            obs.Config{ServiceName: "test"},
		IntelBaseURL:      intel.URL + "/",
		IntelServiceToken: serviceToken,
	})
	mux := http.NewServeMux()
	m.RegisterRoutes(mux)
	return &rig{mux: mux, intel: intel, tenant: tenant, device: device, bearer: auth.Mint([]byte(testHMACKey), tenant, device, time.Hour)}
}

func (r *rig) do(method, path, bearer, body string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.mux.ServeHTTP(w, req)
	return w
}

func errCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var e struct {
		Error struct{ Code string }
	}
	if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil {
		t.Fatalf("non-envelope error body: %s", w.Body.String())
	}
	return e.Error.Code
}

func TestMissingTokenIs401AndNeverReachesIntel(t *testing.T) {
	r := newRig(t, nil)
	for _, c := range []struct{ method, path string }{{"GET", "/api/v1/memory/artifacts"}, {"POST", "/api/v1/memory/match"}} {
		w := r.do(c.method, c.path, "", `{"error":"x","limit":3}`, nil)
		if w.Code != http.StatusUnauthorized || errCode(t, w) != "M1E-1002" {
			t.Fatalf("%s %s without token: %d %s", c.method, c.path, w.Code, w.Body.String())
		}
		w = r.do(c.method, c.path, "m1dev.v1.bogus.sig", `{"error":"x","limit":3}`, nil)
		if w.Code != http.StatusUnauthorized || errCode(t, w) != "M1E-1002" {
			t.Fatalf("%s %s with a forged token: %d %s", c.method, c.path, w.Code, w.Body.String())
		}
	}
	if n := r.intel.count(); n != 0 {
		t.Fatalf("intel called %d times by unauthenticated requests", n)
	}
}

func TestRevokedDeviceIs403AndNeverReachesIntel(t *testing.T) {
	intel := newFakeIntel(t)
	tenant, device := uuid.New(), uuid.New()
	m := New(Deps{
		Verifier:          auth.NewHMACVerifier([]byte(testHMACKey), auth.StaticRevocations{device: true}),
		ObsCfg:            obs.Config{ServiceName: "test"},
		IntelBaseURL:      intel.URL,
		IntelServiceToken: serviceToken,
	})
	mux := http.NewServeMux()
	m.RegisterRoutes(mux)
	r := &rig{mux: mux, intel: intel, tenant: tenant, device: device, bearer: auth.Mint([]byte(testHMACKey), tenant, device, time.Hour)}
	for _, c := range []struct{ method, path string }{{"GET", "/api/v1/memory/artifacts"}, {"POST", "/api/v1/memory/match"}} {
		w := r.do(c.method, c.path, r.bearer, `{"error":"x","limit":3}`, nil)
		if w.Code != http.StatusForbidden || errCode(t, w) != "M1E-1003" {
			t.Fatalf("%s %s revoked: %d %s", c.method, c.path, w.Code, w.Body.String())
		}
	}
	if n := r.intel.count(); n != 0 {
		t.Fatalf("intel called %d times for a revoked device", n)
	}
}

func TestArtifactsStampsTenantFromClaimsAndPassesBodyThrough(t *testing.T) {
	r := newRig(t, nil)
	w := r.do("GET", "/api/v1/memory/artifacts?tenant_id="+uuid.New().String(), r.bearer, "", map[string]string{"X-Mark1-Edge-Version": "mark1d/0.1.0"})
	if w.Code != http.StatusOK {
		t.Fatalf("artifacts: %d %s", w.Code, w.Body.String())
	}
	call := r.intel.last(t)
	if call.method != "GET" || call.path != intelArtifacts+"?tenant_id="+r.tenant.String() {
		t.Fatalf("intel saw %s %s, want the claims tenant only", call.method, call.path)
	}
	if call.auth != "Bearer "+serviceToken {
		t.Fatalf("intel saw credential %q, want the service token", call.auth)
	}
	if call.edgeVersion != "mark1d/0.1.0" {
		t.Fatalf("edge version not forwarded: %q", call.edgeVersion)
	}
	if w.Body.String() != artifactsDoc {
		t.Fatalf("body not passed through byte-for-byte:\n%s", w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type %q", ct)
	}
	if strings.Contains(w.Body.String(), "tenant") {
		t.Fatalf("tenant field on the public wire: %s", w.Body.String())
	}
}

func TestArtifactsETagRoundTrip(t *testing.T) {
	r := newRig(t, nil)
	first := r.do("GET", "/api/v1/memory/artifacts", r.bearer, "", nil)
	etag := first.Header().Get("ETag")
	if first.Code != http.StatusOK || !strings.HasPrefix(etag, `"`) {
		t.Fatalf("first: %d etag=%q", first.Code, etag)
	}
	again := r.do("GET", "/api/v1/memory/artifacts", r.bearer, "", map[string]string{"If-None-Match": `W/"stale", ` + etag})
	if again.Code != http.StatusNotModified || again.Body.Len() != 0 || again.Header().Get("ETag") != etag {
		t.Fatalf("matching If-None-Match: %d body=%d etag=%q", again.Code, again.Body.Len(), again.Header().Get("ETag"))
	}
	r.intel.set(http.StatusOK, `{"artifacts":[]}`)
	changed := r.do("GET", "/api/v1/memory/artifacts", r.bearer, "", map[string]string{"If-None-Match": etag})
	if changed.Code != http.StatusOK || changed.Header().Get("ETag") == etag || changed.Body.String() != `{"artifacts":[]}` {
		t.Fatalf("changed upstream under the old ETag: %d etag=%q body=%s", changed.Code, changed.Header().Get("ETag"), changed.Body.String())
	}
	if r.intel.count() != 3 {
		t.Fatalf("intel called %d times; the 304 is computed from a fresh upstream read, never a cache", r.intel.count())
	}
}

func TestMatchTenantComesFromClaimsNeverTheBody(t *testing.T) {
	r := newRig(t, nil)
	other := uuid.New()
	w := r.do("POST", "/api/v1/memory/match", r.bearer, `{"tenant_id":"`+other.String()+`","error":"boom","limit":3}`, nil)
	if w.Code != http.StatusBadRequest || errCode(t, w) != "M1E-2001" {
		t.Fatalf("tenant_id in the body: %d %s", w.Code, w.Body.String())
	}
	if r.intel.count() != 0 {
		t.Fatal("a body asserting a tenant reached intel")
	}
	w = r.do("POST", "/api/v1/memory/match", r.bearer, `{"error":"Exit code 1\nFAIL x","limit":3}`, nil)
	if w.Code != http.StatusOK || w.Body.String() != matchDoc {
		t.Fatalf("match: %d %s", w.Code, w.Body.String())
	}
	call := r.intel.last(t)
	var up struct {
		TenantID string `json:"tenant_id"`
		Error    string `json:"error"`
		Limit    int    `json:"limit"`
	}
	if err := json.Unmarshal(call.body, &up); err != nil || call.method != "POST" || call.path != intelMatch {
		t.Fatalf("intel saw %s %s %s (%v)", call.method, call.path, call.body, err)
	}
	if up.TenantID != r.tenant.String() || up.Error != "Exit code 1\nFAIL x" || up.Limit != 3 {
		t.Fatalf("upstream body %+v, want claims tenant %s with the edge's error and limit", up, r.tenant)
	}
	if call.auth != "Bearer "+serviceToken {
		t.Fatalf("intel saw credential %q", call.auth)
	}
}

func TestMatchBodyIsBounded(t *testing.T) {
	r := newRig(t, nil)
	big := `{"error":"` + strings.Repeat("x", maxMatchBody) + `","limit":3}`
	for name, body := range map[string]string{"oversize": big, "empty": "", "not json": "{", "array": "[]"} {
		w := r.do("POST", "/api/v1/memory/match", r.bearer, body, nil)
		if w.Code != http.StatusBadRequest || errCode(t, w) != "M1E-2001" {
			t.Fatalf("%s body: %d %s", name, w.Code, w.Body.String())
		}
	}
	if r.intel.count() != 0 {
		t.Fatal("a refused body reached intel")
	}
}

func TestIntelFailureIs502WithoutUpstreamBytes(t *testing.T) {
	r := newRig(t, nil)
	r.intel.set(http.StatusInternalServerError, `{"artifacts":[{"guidance":"LEAKED-SECRET-ARTIFACT"}],"trace":"pg://intel_app@db"}`)
	for _, c := range []struct{ method, path string }{{"GET", "/api/v1/memory/artifacts"}, {"POST", "/api/v1/memory/match"}} {
		w := r.do(c.method, c.path, r.bearer, `{"error":"x","limit":3}`, nil)
		if w.Code != http.StatusBadGateway || errCode(t, w) != "M1E-9500" {
			t.Fatalf("%s %s on intel 500: %d %s", c.method, c.path, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "LEAKED") || strings.Contains(w.Body.String(), "intel_app") {
			t.Fatalf("upstream error bytes leaked: %s", w.Body.String())
		}
	}
	r.intel.set(http.StatusForbidden, `{"error":{"code":"M1E-1001"}}`)
	if w := r.do("GET", "/api/v1/memory/artifacts", r.bearer, "", nil); w.Code != http.StatusBadGateway || errCode(t, w) != "M1E-9500" {
		t.Fatalf("intel refusing the service credential is a deployment fault, want 502: %d %s", w.Code, w.Body.String())
	}
	r.intel.set(http.StatusUnprocessableEntity, `{"detail":[{"loc":["body","limit"]}]}`)
	w := r.do("POST", "/api/v1/memory/match", r.bearer, `{"error":"x","limit":9}`, nil)
	if w.Code != http.StatusBadRequest || errCode(t, w) != "M1E-2001" || strings.Contains(w.Body.String(), "detail") {
		t.Fatalf("intel 422: %d %s", w.Code, w.Body.String())
	}
	r.intel.set(http.StatusOK, `{"artifacts":[{"guidance":"`+strings.Repeat("x", 9<<20)+`"}]}`)
	if w := r.do("GET", "/api/v1/memory/artifacts", r.bearer, "", nil); w.Code != http.StatusBadGateway || errCode(t, w) != "M1E-9500" {
		t.Fatalf("intel body over the 8 MiB read cap: %d (%d bytes)", w.Code, w.Body.Len())
	}
	r.intel.Close()
	if w := r.do("GET", "/api/v1/memory/artifacts", r.bearer, "", nil); w.Code != http.StatusBadGateway || errCode(t, w) != "M1E-9500" {
		t.Fatalf("intel unreachable: %d %s", w.Code, w.Body.String())
	}
}

func TestMatchIsDeadlineBounded(t *testing.T) {
	old := matchDeadline
	matchDeadline = 60 * time.Millisecond
	t.Cleanup(func() { matchDeadline = old })
	r := newRig(t, nil)
	r.intel.mu.Lock()
	r.intel.delay = 600 * time.Millisecond
	r.intel.mu.Unlock()
	start := time.Now()
	w := r.do("POST", "/api/v1/memory/match", r.bearer, `{"error":"x","limit":3}`, nil)
	if took := time.Since(start); w.Code != http.StatusBadGateway || errCode(t, w) != "M1E-9500" || took > 400*time.Millisecond {
		t.Fatalf("slow intel: %d %s after %v", w.Code, w.Body.String(), took)
	}
}

func TestUnconfiguredIntelIs503(t *testing.T) {
	m := New(Deps{Verifier: auth.NewHMACVerifier([]byte(testHMACKey), auth.StaticRevocations{}), ObsCfg: obs.Config{ServiceName: "test"}})
	mux := http.NewServeMux()
	m.RegisterRoutes(mux)
	r := &rig{mux: mux, bearer: auth.Mint([]byte(testHMACKey), uuid.New(), uuid.New(), time.Hour)}
	w := r.do("GET", "/api/v1/memory/artifacts", r.bearer, "", nil)
	if w.Code != http.StatusServiceUnavailable || errCode(t, w) != "M1E-9500" {
		t.Fatalf("no intel URL: %d %s", w.Code, w.Body.String())
	}
}
