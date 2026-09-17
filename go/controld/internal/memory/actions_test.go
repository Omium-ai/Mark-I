package memory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/appapi/schemacheck"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
)

const (
	retireDoc   = `{"artifact_id":"0195a000-0000-7000-8000-000000000001","state":"retired","receipt_id":"0195a000-0000-7000-8000-0000000000aa"}`
	pinDoc      = `{"artifact_id":"0195a000-0000-7000-8000-000000000001","pinned":true}`
	outcomesDoc = `{"outcomes":[{"artifact_id":"0195a000-0000-7000-8000-000000000001","verified_outcomes":11,"uplift_lcb":0.34,"n":11}]}`
	artID       = "0195a000-0000-7000-8000-000000000001"
)

var actions = []string{"retire", "pin", "unpin", "share", "unshare"}

func actionBody(action string) string {
	if action == "retire" {
		return `{"reason":"stale advice"}`
	}
	return ""
}

func TestActionsProxyWithTenantAndActorOnTheInternalWire(t *testing.T) {
	r := newRig(t, nil)
	schemas := schemacheck.Load(t, "../appapi/schema")
	for _, action := range actions {
		reply := pinDoc
		if action == "retire" {
			reply = retireDoc
		}
		r.intel.set(http.StatusOK, reply)
		w := r.do(http.MethodPost, "/api/v1/memory/artifacts/"+artID+"/"+action, r.bearer, actionBody(action), nil)
		if w.Code != http.StatusOK || w.Body.String() != reply {
			t.Fatalf("%s: %d %s", action, w.Code, w.Body.String())
		}
		schemas.Validate("memory_action.json", w.Body.Bytes())
		call := r.intel.last(t)
		if call.method != http.MethodPost || call.path != "/v1/memory/artifacts/"+artID+"/"+action || call.auth != "Bearer "+serviceToken {
			t.Fatalf("%s: intel saw %s %s %q", action, call.method, call.path, call.auth)
		}
		var wire map[string]string
		if err := json.Unmarshal(call.body, &wire); err != nil {
			t.Fatal(err)
		}
		want := map[string]string{"tenant_id": r.tenant.String()}
		if action == "retire" {
			want["reason"], want["by"] = "stale advice", "device:"+r.device.String()
		}
		if len(wire) != len(want) {
			t.Fatalf("%s: upstream body %s, want exactly %v", action, call.body, want)
		}
		for k, v := range want {
			if wire[k] != v {
				t.Fatalf("%s: upstream %s=%q, want %q", action, k, wire[k], v)
			}
		}
	}
	r.intel.set(http.StatusOK, outcomesDoc)
	w := r.do(http.MethodGet, "/api/v1/memory/outcomes", r.bearer, "", nil)
	if w.Code != http.StatusOK || w.Body.String() != outcomesDoc {
		t.Fatalf("outcomes: %d %s", w.Code, w.Body.String())
	}
	schemas.Validate("memory_outcomes.json", w.Body.Bytes())
	if call := r.intel.last(t); call.method != http.MethodGet || call.path != intelOutcomes+"?tenant_id="+r.tenant.String() {
		t.Fatalf("outcomes upstream: %s %s", call.method, call.path)
	}
}

type subjectVerifier struct{ claims auth.Claims }

func (v subjectVerifier) Verify(context.Context, string) (auth.Claims, error) { return v.claims, nil }

func TestUserTokenSubjectIsTheReceiptedActor(t *testing.T) {
	intel := newFakeIntel(t)
	intel.set(http.StatusOK, retireDoc)
	tenant := uuid.New()
	m := New(Deps{Verifier: subjectVerifier{auth.Claims{TenantID: tenant, Subject: "omium:alice"}}, ObsCfg: obs.Config{ServiceName: "test"}, IntelBaseURL: intel.URL, IntelServiceToken: serviceToken})
	mux := http.NewServeMux()
	m.RegisterRoutes(mux)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/memory/artifacts/"+artID+"/retire", strings.NewReader(`{"reason":"wrong"}`))
	req.Header.Set("Authorization", "Bearer user")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if body := string(intel.last(t).body); !strings.Contains(body, `"by":"omium:alice"`) || !strings.Contains(body, `"tenant_id":"`+tenant.String()+`"`) {
		t.Fatalf("upstream %s", body)
	}
}

func TestRetireBodyIsValidatedBeforeIntel(t *testing.T) {
	r := newRig(t, nil)
	for name, body := range map[string]string{
		"empty":         ``,
		"no reason":     `{}`,
		"blank reason":  `{"reason":"   "}`,
		"unknown field": `{"reason":"x","tenant_id":"` + uuid.NewString() + `"}`,
		"too long":      `{"reason":"` + strings.Repeat("r", maxReason+1) + `"}`,
		"not json":      `reason=x`,
	} {
		w := r.do(http.MethodPost, "/api/v1/memory/artifacts/"+artID+"/retire", r.bearer, body, nil)
		if w.Code != http.StatusBadRequest || errCode(t, w) != "M1E-2001" {
			t.Fatalf("%s: %d %s", name, w.Code, w.Body.String())
		}
	}
	w := r.do(http.MethodPost, "/api/v1/memory/artifacts/"+artID+"/retire", r.bearer, `{"reason":"`+strings.Repeat("r", maxReason)+`"}`, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("reason at the cap: %d %s", w.Code, w.Body.String())
	}
	if r.intel.count() != 1 {
		t.Fatalf("intel called %d times, want only the valid body", r.intel.count())
	}
}

func TestMalformedOrForeignArtifactIs404NotAnOracle(t *testing.T) {
	r := newRig(t, nil)
	for _, id := range []string{"not-a-uuid", uuid.Nil.String(), "0195a000-0000-7000-8000-00000000000"} {
		for _, action := range actions {
			w := r.do(http.MethodPost, "/api/v1/memory/artifacts/"+id+"/"+action, r.bearer, actionBody(action), nil)
			if w.Code != http.StatusNotFound || errCode(t, w) != "M1E-2009" {
				t.Fatalf("%s %s: %d %s", action, id, w.Code, w.Body.String())
			}
		}
	}
	if r.intel.count() != 0 {
		t.Fatalf("intel called %d times for malformed ids", r.intel.count())
	}
	// intel's own 404 (a foreign or unknown id under RLS) is the same answer.
	r.intel.set(http.StatusNotFound, `{"error":{"code":"M1E-2009","message":"artifact not found"}}`)
	for _, action := range actions {
		w := r.do(http.MethodPost, "/api/v1/memory/artifacts/"+artID+"/"+action, r.bearer, actionBody(action), nil)
		if w.Code != http.StatusNotFound || errCode(t, w) != "M1E-2009" {
			t.Fatalf("%s upstream 404: %d %s", action, w.Code, w.Body.String())
		}
	}
	r.intel.set(http.StatusInternalServerError, `{"error":{"code":"M1E-9500","message":"x"}}`)
	if w := r.do(http.MethodPost, "/api/v1/memory/artifacts/"+artID+"/pin", r.bearer, "", nil); w.Code != http.StatusBadGateway || errCode(t, w) != "M1E-9500" {
		t.Fatalf("upstream 500: %d %s", w.Code, w.Body.String())
	}
}

func TestActionsAndOutcomesNeedAToken(t *testing.T) {
	r := newRig(t, nil)
	for _, action := range actions {
		w := r.do(http.MethodPost, "/api/v1/memory/artifacts/"+artID+"/"+action, "", actionBody(action), nil)
		if w.Code != http.StatusUnauthorized || errCode(t, w) != "M1E-1002" {
			t.Fatalf("%s without token: %d %s", action, w.Code, w.Body.String())
		}
	}
	if w := r.do(http.MethodGet, "/api/v1/memory/outcomes", "", "", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("outcomes without token: %d", w.Code)
	}
	if w := r.do(http.MethodPost, "/api/v1/memory/artifacts/"+artID+"/bless", r.bearer, "", nil); w.Code != http.StatusNotFound {
		t.Fatalf("unknown action routed: %d", w.Code)
	}
	if r.intel.count() != 0 {
		t.Fatalf("intel called %d times by refused requests", r.intel.count())
	}
}
