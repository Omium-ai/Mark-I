package memory

// 15-teams §Memory: every intel call names the viewer as the viewer_subject query parameter, and intel's ownership refusals cross unchanged.

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
)

type fakeViewers struct {
	v   querychoke.Viewer
	err error
}

func (f fakeViewers) Viewer(context.Context, querychoke.TenantID, auth.Claims) (querychoke.Viewer, error) {
	return f.v, f.err
}

func viewerRig(t *testing.T, v querychoke.Viewers) *rig {
	t.Helper()
	intel := newFakeIntel(t)
	tenant, device := uuid.New(), uuid.New()
	m := New(Deps{
		Verifier:          auth.NewHMACVerifier([]byte(testHMACKey), auth.StaticRevocations{}),
		ObsCfg:            obs.Config{ServiceName: "test"},
		IntelBaseURL:      intel.URL,
		IntelServiceToken: serviceToken,
		Viewers:           v,
	})
	mux := http.NewServeMux()
	m.RegisterRoutes(mux)
	return &rig{mux: mux, intel: intel, tenant: tenant, device: device, bearer: auth.Mint([]byte(testHMACKey), tenant, device, time.Hour)}
}

var memoryCalls = []struct{ method, path, body string }{
	{"GET", "/api/v1/memory/artifacts", ""},
	{"POST", "/api/v1/memory/match", `{"error":"x","limit":3}`},
	{"GET", "/api/v1/memory/outcomes", ""},
	{"POST", "/api/v1/memory/artifacts/0195a000-0000-7000-8000-000000000001/retire", `{"reason":"stale"}`},
	{"POST", "/api/v1/memory/artifacts/0195a000-0000-7000-8000-000000000001/pin", ""},
	{"POST", "/api/v1/memory/artifacts/0195a000-0000-7000-8000-000000000001/unpin", ""},
	{"POST", "/api/v1/memory/artifacts/0195a000-0000-7000-8000-000000000001/share", ""},
	{"POST", "/api/v1/memory/artifacts/0195a000-0000-7000-8000-000000000001/unshare", ""},
}

func viewerParam(t *testing.T, c intelCall) (string, bool) {
	t.Helper()
	u, err := url.ParseRequestURI(c.path)
	if err != nil {
		t.Fatal(err)
	}
	vs, ok := u.Query()["viewer_subject"]
	if !ok {
		return "", false
	}
	return vs[0], true
}

func TestEveryIntelCallNamesTheViewer(t *testing.T) {
	r := viewerRig(t, fakeViewers{v: querychoke.Viewer{Subject: "omium:user|1&x=y"}})
	for _, c := range memoryCalls {
		if w := r.do(c.method, c.path, r.bearer, c.body, nil); w.Code != http.StatusOK {
			t.Fatalf("%s %s: %d %s", c.method, c.path, w.Code, w.Body.String())
		}
		call := r.intel.last(t)
		if vs, ok := viewerParam(t, call); !ok || vs != "omium:user|1&x=y" {
			t.Fatalf("%s %s reached intel as %s", c.method, c.path, call.path)
		}
	}
}

func TestViewerSubjectAbsentOnlyForASoloSubjectlessDevice(t *testing.T) {
	r := viewerRig(t, fakeViewers{v: querychoke.Viewer{}})
	r.do("GET", "/api/v1/memory/artifacts", r.bearer, "", nil)
	if _, ok := viewerParam(t, r.intel.last(t)); ok {
		t.Fatal("a solo tenant's subject-less device must read as today (no viewer_subject)")
	}
	r = viewerRig(t, fakeViewers{v: querychoke.Viewer{Team: true}})
	r.do("GET", "/api/v1/memory/artifacts", r.bearer, "", nil)
	if vs, ok := viewerParam(t, r.intel.last(t)); !ok || vs != "" {
		t.Fatal("a team device without a subject must send an empty viewer_subject (owns nothing), never widen")
	}
	r = viewerRig(t, fakeViewers{err: errors.New("pg down")})
	if w := r.do("GET", "/api/v1/memory/artifacts", r.bearer, "", nil); w.Code != http.StatusServiceUnavailable || r.intel.count() != 0 {
		t.Fatalf("a failed viewer lookup must not reach intel: %d", w.Code)
	}
}

func TestIntelOwnershipRefusalsCrossUnchanged(t *testing.T) {
	r := viewerRig(t, fakeViewers{v: querychoke.Viewer{Subject: "omium:a", Team: true}})
	for _, reason := range []string{"not_owner", "consent_required"} {
		body := `{"error":{"code":"M1E-2003","message":"` + reason + `","reason":"` + reason + `"}}`
		r.intel.set(http.StatusForbidden, body)
		w := r.do("POST", "/api/v1/memory/artifacts/0195a000-0000-7000-8000-000000000001/share", r.bearer, "", nil)
		if w.Code != http.StatusForbidden || w.Body.String() != body {
			t.Fatalf("%s: %d %s", reason, w.Code, w.Body.String())
		}
	}
	r.intel.set(http.StatusForbidden, `{"error":{"code":"M1E-1001","message":"service credential required"}}`)
	if w := r.do("GET", "/api/v1/memory/artifacts", r.bearer, "", nil); w.Code != http.StatusBadGateway {
		t.Fatalf("a service-credential 403 stays a deployment fault: %d", w.Code)
	}
}
