//go:build integration

package querychoke_test

// 15-teams per-person visibility on real ClickHouse: two teammates' sessions in one tenant, read back through the production wiring (querychoke.Scoped + the report module's Viewers). A member sees only their device's rows, an empty device list sees nothing, and a solo tenant sees both.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/appapi"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
)

type staticViewers struct{ v querychoke.Viewer }

func (s staticViewers) Viewer(context.Context, querychoke.TenantID, auth.Claims) (querychoke.Viewer, error) {
	return s.v, nil
}

func (r *appRig) scoped(v querychoke.Viewer) *appRig {
	verifier := auth.NewHMACVerifier([]byte(appKey), auth.StaticRevocations{})
	obsCfg := obs.Config{ServiceName: "appapi-ch-it"}
	viewers := staticViewers{v}
	reports := querychoke.New(querychoke.Deps{Registry: r.reg, Runner: r.runner, Verifier: verifier, ObsCfg: obsCfg, Viewers: viewers})
	m := appapi.New(appapi.Deps{Verifier: verifier, ObsCfg: obsCfg, Registry: r.reg, Runner: querychoke.Scoped(r.runner, viewers), Reports: reports})
	mux := http.NewServeMux()
	m.RegisterRoutes(mux)
	reports.RegisterRoutes(mux)
	api := httptest.NewServer(mux)
	r.t.Cleanup(api.Close)
	out := *r
	out.api = api
	return &out
}

func sessionIDs(t *testing.T, body []byte) []string {
	t.Helper()
	var out struct {
		Sessions []struct {
			SessionID string `json:"session_id"`
		} `json:"sessions"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	ids := []string{}
	for _, s := range out.Sessions {
		ids = append(ids, s.SessionID)
	}
	return ids
}

func TestIntegrationTeamMemberSeesOnlyTheirDevices(t *testing.T) {
	r := setupApp(t)
	tenant := uuid.New()
	mine, theirs := plant(t, r, tenant, 100), plant(t, r, tenant, 200)

	solo := r.scoped(querychoke.Viewer{Subject: "omium:owner", Devices: []uuid.UUID{mine.device}})
	code, body := solo.get("/api/v1/sessions?window=7d", tenant)
	if ids := sessionIDs(t, body); code != http.StatusOK || len(ids) != 2 {
		t.Fatalf("a solo tenant reads every session: %d %v", code, ids)
	}

	member := r.scoped(querychoke.Viewer{Subject: "omium:member", Team: true, Devices: []uuid.UUID{mine.device}})
	code, body = member.get("/api/v1/sessions?window=7d", tenant)
	if ids := sessionIDs(t, body); code != http.StatusOK || len(ids) != 1 || ids[0] != mine.session.String() {
		t.Fatalf("a member reads only their own session: %d %v", code, ids)
	}
	if code, _ := member.get("/api/v1/sessions/"+theirs.session.String(), tenant); code != http.StatusNotFound {
		t.Fatalf("a teammate's session detail: %d", code)
	}
	if code, _ := member.get("/api/v1/sessions/"+mine.session.String(), tenant); code != http.StatusOK {
		t.Fatalf("own session detail: %d", code)
	}
	code, body = member.get("/api/v1/moments", tenant)
	if code != http.StatusOK || strings.Contains(string(body), theirs.session.String()) || !strings.Contains(string(body), mine.session.String()) {
		t.Fatalf("a member's moments: %d %s", code, body)
	}
	code, body = member.raw("/api/v1/reports/tvo?window=7d", tenant)
	if code != http.StatusOK || !strings.Contains(string(body), "per-person report") {
		t.Fatalf("a member's live report: %d %s", code, body)
	}

	nobody := r.scoped(querychoke.Viewer{Subject: "omium:new", Team: true, Devices: []uuid.UUID{}})
	code, body = nobody.get("/api/v1/sessions?window=7d", tenant)
	if ids := sessionIDs(t, body); code != http.StatusOK || len(ids) != 0 {
		t.Fatalf("an empty device list must read nothing, never everything: %d %v", code, ids)
	}
	code, body = nobody.get("/api/v1/moments", tenant)
	if code != http.StatusOK || strings.Contains(string(body), mine.session.String()) || strings.Contains(string(body), theirs.session.String()) {
		t.Fatalf("an empty device list leaked moments: %s", body)
	}
}
