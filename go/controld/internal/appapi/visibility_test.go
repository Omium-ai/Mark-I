package appapi

// 15-teams per-person visibility on the app read surface, wired as main.go wires it (querychoke.Scoped runner + the report module's Viewers): a solo tenant's every body is byte-identical to the unscoped surface, and a team member's every ClickHouse read is narrowed to their devices.

import (
	"context"
	"net/http"
	"regexp"
	"testing"

	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
)

type fakeViewers struct{ v querychoke.Viewer }

func (f fakeViewers) Viewer(context.Context, querychoke.TenantID, auth.Claims) (querychoke.Viewer, error) {
	return f.v, nil
}

// scopedMux serves the same fake rows as r through the production wiring with the given viewer.
func scopedMux(t *testing.T, r *rig, v querychoke.Viewer) *http.ServeMux {
	t.Helper()
	reg, err := querychoke.LoadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	verifier := auth.NewHMACVerifier([]byte(testKey), auth.StaticRevocations{})
	obsCfg := obs.Config{ServiceName: "appapi-test"}
	viewers := fakeViewers{v}
	reports := querychoke.New(querychoke.Deps{Registry: reg, Runner: r.run, Verifier: verifier, ObsCfg: obsCfg, Viewers: viewers})
	m := New(Deps{Verifier: verifier, ObsCfg: obsCfg, Registry: reg, Runner: querychoke.Scoped(r.run, viewers), Reports: reports})
	mux := http.NewServeMux()
	m.RegisterRoutes(mux)
	reports.RegisterRoutes(mux)
	return mux
}

func serve(mux *http.ServeMux, path, token string) (int, string) {
	req, _ := http.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := &memWriter{header: http.Header{}, code: http.StatusOK}
	mux.ServeHTTP(w, req)
	return w.code, w.body.String()
}

// nowSince is /moments' default since (now − 24 h), the one field two requests a moment apart cannot share.
var nowSince = regexp.MustCompile(`"since":"[^"]*"`)

func TestSoloTenantReadsAreUnchanged(t *testing.T) {
	r, session := goldenRig(t)
	solo := scopedMux(t, r, querychoke.Viewer{Subject: "omium:owner", Devices: []uuid.UUID{uuid.New()}})
	for _, g := range goldens(session) {
		want := r.get(g.path, r.tokenA)
		code, got := serve(solo, g.path, r.tokenA)
		if code != want.Code || nowSince.ReplaceAllString(got, "") != nowSince.ReplaceAllString(want.Body.String(), "") {
			t.Fatalf("GET %s changed for a solo tenant:\nwas %d %s\nnow %d %s", g.path, want.Code, want.Body.String(), code, got)
		}
	}
	for _, q := range r.run.seen {
		if _, ok := q.Bind()["device_ids"]; ok {
			t.Fatalf("%s carried a device filter for a solo tenant", q.Template().Name())
		}
	}
}

func TestTeamMemberReadsOnlyTheirDevices(t *testing.T) {
	r, session := goldenRig(t)
	mine := uuid.New()
	team := scopedMux(t, r, querychoke.Viewer{Subject: "omium:member", Team: true, Devices: []uuid.UUID{mine}})
	r.run.seen = nil
	for _, g := range goldens(session) {
		code, body := serve(team, g.path, r.tokenA)
		if code != http.StatusOK && (g.file != "cloud-sessions-detail" || code != http.StatusNotFound) {
			t.Fatalf("GET %s for a member: %d %s", g.path, code, body)
		}
		if g.schema != "" && code == http.StatusOK {
			r.schemas.Validate(g.schema, []byte(body))
		}
	}
	if len(r.run.seen) == 0 {
		t.Fatal("no reads ran")
	}
	for _, q := range r.run.seen {
		if q.Bind()["device_ids"] != "['"+mine.String()+"']" {
			t.Fatalf("%s ran for a team member without their device filter: %v", q.Template().Name(), q.Bind())
		}
		if q.Template().Name() == "tvo_report" {
			t.Fatal("a member's honesty fields must not read the tenant rollup")
		}
	}
	empty := scopedMux(t, r, querychoke.Viewer{Subject: "omium:new", Team: true, Devices: []uuid.UUID{}})
	r.run.seen = nil
	if code, body := serve(empty, "/api/v1/sessions", r.tokenA); code != http.StatusOK {
		t.Fatalf("empty device list: %d %s", code, body)
	}
	for _, q := range r.run.seen {
		if q.Bind()["device_ids"] != "[]" {
			t.Fatalf("a member with no devices must read nothing, got %s %v", q.Template().Name(), q.Bind())
		}
	}
}
