package querychoke

// 15-teams per-person visibility at the chokepoint: the optional device_ids filter (absent = the pre-teams render byte for byte, empty = no rows, never a widening), the scoped runner that narrows a team member's reads, and the per-person TVO report.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
)

type fakeViewers struct {
	v     Viewer
	err   error
	calls int
}

func (f *fakeViewers) Viewer(context.Context, TenantID, auth.Claims) (Viewer, error) {
	f.calls++
	return f.v, f.err
}

type recRunner struct{ seen []Query }

func (r *recRunner) Run(_ context.Context, q Query) (*Rows, error) {
	r.seen = append(r.seen, q)
	return &Rows{}, nil
}

func TestDeviceFilterIsOptionalAndNeverWidens(t *testing.T) {
	reg, err := LoadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	tid := testTenant(t)
	scoped := 0
	for name, tpl := range reg.byName {
		if !tpl.devices {
			continue
		}
		scoped++
		plain, err := Build(tid, Template{t: tpl}, dummyParams(tpl))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if strings.Contains(plain.SQL(), "device_ids") || plain.Bind()[deviceParam] != "" {
			t.Fatalf("%s: absent device_ids must render the tenant predicate alone:\n%s", name, plain.SQL())
		}
		if want := strings.Replace(tpl.body, tenantMarker, tenantPredSQL, 1); !strings.HasPrefix(plain.SQL(), want) {
			t.Fatalf("%s: absent device_ids changed the render", name)
		}
		d := uuid.New()
		p := dummyParams(tpl)
		p[deviceParam] = []uuid.UUID{d}
		q, err := Build(tid, Template{t: tpl}, p)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if strings.Count(q.SQL(), devicePredSQL) != 1 || q.Bind()[deviceParam] != "['"+d.String()+"']" || q.Bind()["tid"] != tid.String() {
			t.Fatalf("%s: device filter not rendered and bound: %v\n%s", name, q.Bind(), q.SQL())
		}
		p[deviceParam] = []uuid.UUID{}
		q, err = Build(tid, Template{t: tpl}, p)
		if err != nil || q.Bind()[deviceParam] != "[]" || !strings.Contains(q.SQL(), devicePredSQL) {
			t.Fatalf("%s: an empty device list must still render the filter (no rows), got %v %v", name, err, q.Bind())
		}
	}
	if scoped < 11 {
		t.Fatalf("only %d device-scoped templates; the app's reads lost their filter", scoped)
	}
	tpl, _ := reg.Lookup("tvo_report")
	if _, err := Build(tid, tpl, Params{"from": "2026-09-01", "to": "2026-09-02", deviceParam: []uuid.UUID{uuid.New()}}); !errors.Is(err, ErrBadParams) {
		t.Fatalf("device_ids on a rollup template must refuse, got %v", err)
	}
}

func TestDeviceParamIsReservedAtLoad(t *testing.T) {
	good := template{name: "x", version: "x.v1", body: "SELECT 1 FROM m1p_events WHERE {{tenant_pred}}", readSet: []string{"m1p_events"}, rowLimit: 1, timeout: time.Second}
	for name, bad := range map[string]func(*template){
		"declared":       func(t *template) { t.params = map[string]paramSpec{deviceParam: {kind: pUUIDArray}} },
		"body reference": func(t *template) { t.body += " AND has({device_ids:Array(UUID)}, device_id)" },
		"rollup devices": func(t *template) {
			t.body, t.readSet, t.devices = "SELECT 1 FROM tvo_tenant_day WHERE {{tenant_pred}}", []string{"tvo_tenant_day"}, true
		},
	} {
		tpl := good
		bad(&tpl)
		if err := validate(&tpl); err == nil {
			t.Errorf("%s: validate admitted it", name)
		}
	}
}

func TestNarrowReplacesCallerDevicesAndRefusesTenantWideTemplates(t *testing.T) {
	reg, _ := LoadTemplates()
	tid := testTenant(t)
	tpl, _ := reg.Lookup("app_sessions")
	mine, theirs := uuid.New(), uuid.New()
	q, err := Build(tid, tpl, Params{"from": "2026-09-01", "to": "2026-09-02", deviceParam: []uuid.UUID{theirs}})
	if err != nil {
		t.Fatal(err)
	}
	n, err := narrow(q, []uuid.UUID{mine})
	if err != nil || n.Bind()[deviceParam] != "['"+mine.String()+"']" || strings.Count(n.SQL(), devicePredSQL) != 1 {
		t.Fatalf("a caller-bound list must be replaced by the viewer's: %v %v", err, n.Bind())
	}
	if q.Bind()[deviceParam] != "['"+theirs.String()+"']" {
		t.Fatal("narrow mutated the built query")
	}
	rollup, _ := reg.Lookup("tvo_report")
	q, _ = Build(tid, rollup, Params{"from": "2026-09-01", "to": "2026-09-02"})
	if _, err := narrow(q, []uuid.UUID{mine}); !errors.Is(err, ErrTeamScope) {
		t.Fatalf("narrowing a deviceless template must refuse, got %v", err)
	}
}

func TestScopedRunnerNarrowsOnlyTeamViewers(t *testing.T) {
	reg, _ := LoadTemplates()
	tenant, device := uuid.New(), uuid.New()
	tid, _ := FromClaims(auth.Claims{TenantID: tenant, DeviceID: device})
	tpl, _ := reg.Lookup("app_moments")
	q, _ := Build(tid, tpl, Params{"from": "2026-09-01", "to": "2026-09-02"})
	withClaims := auth.WithClaims(context.Background(), auth.Claims{TenantID: tenant, DeviceID: device})
	for name, c := range map[string]struct {
		ctx     context.Context
		v       Viewer
		narrows bool
	}{
		"solo tenant":     {withClaims, Viewer{Subject: "omium:a", Devices: []uuid.UUID{device}}, false},
		"team member":     {withClaims, Viewer{Subject: "omium:a", Team: true, Devices: []uuid.UUID{device}}, true},
		"team, no device": {withClaims, Viewer{Team: true, Devices: []uuid.UUID{}}, true},
		"tenant-wide":     {TenantWide(withClaims), Viewer{Team: true}, false},
		"service read":    {context.Background(), Viewer{Team: true}, false},
	} {
		run := &recRunner{}
		if _, err := Scoped(run, &fakeViewers{v: c.v}).Run(c.ctx, q); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got := run.seen[0]
		if !c.narrows {
			if got.SQL() != q.SQL() || len(got.Bind()) != len(q.Bind()) {
				t.Fatalf("%s: query changed:\n%s", name, got.SQL())
			}
			continue
		}
		want := "[]"
		if len(c.v.Devices) == 1 {
			want = "['" + device.String() + "']"
		}
		if got.Bind()[deviceParam] != want || got.Bind()["tid"] != tenant.String() {
			t.Fatalf("%s: bind %v", name, got.Bind())
		}
	}
	if _, err := Scoped(&recRunner{}, &fakeViewers{err: errors.New("pg down")}).Run(withClaims, q); err == nil {
		t.Fatal("a failed viewer lookup must fail the read, not serve it tenant-wide")
	}
}

func TestSubjectOfMatchesEnrollment(t *testing.T) {
	if got := SubjectOf(auth.Claims{Subject: "u-1"}); got != "omium:u-1" {
		t.Fatalf("got %q", got)
	}
	if got := SubjectOf(auth.Claims{DeviceID: uuid.New()}); got != "" {
		t.Fatalf("a device token has no user subject, got %q", got)
	}
}

func TestTVOReportIsPerPersonInATeam(t *testing.T) {
	reg, _ := LoadTemplates()
	run := &recRunner{}
	device := uuid.New()
	viewers := &fakeViewers{v: Viewer{Subject: "omium:a", Team: true, Devices: []uuid.UUID{device}}}
	m := New(Deps{Registry: reg, Runner: run, Verifier: auth.NewHMACVerifier([]byte(testHMACKey), auth.StaticRevocations{}), ObsCfg: obs.Config{ServiceName: "test"}, Viewers: viewers})
	mux := http.NewServeMux()
	m.RegisterRoutes(mux)
	bearer := auth.Mint([]byte(testHMACKey), uuid.New(), device, time.Hour)
	w := do(mux, "GET", "/api/v1/reports/tvo?window=30d", bearer, "")
	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	names := map[string]int{}
	for _, q := range run.seen {
		names[q.Template().Name()]++
		if q.Bind()[deviceParam] != "['"+device.String()+"']" {
			t.Fatalf("%s ran unnarrowed for a team member: %v", q.Template().Name(), q.Bind())
		}
	}
	if names["tvo_report"] != 0 || names["tvo_task_window"] != 1 || names["coverage_band"] != 1 {
		t.Fatalf("a member's report reads the ledger once over the window, never the tenant rollup: %v", names)
	}
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["guarantee_grade"] != false || !strings.Contains(body["refusal"].(string), "per-person report") {
		t.Fatalf("a per-person report is labelled live, never guarantee grade: %v", body)
	}
	if w := do(mux, "POST", "/api/v1/query", bearer, `{"template":"tvo_report","params":{"from":"2026-09-01","to":"2026-09-02"}}`); w.Code != http.StatusForbidden || errCode(t, w) != "M1E-1001" {
		t.Fatalf("a member querying the tenant rollup: %d %s", w.Code, w.Body.String())
	}
	if w := do(mux, "POST", "/api/v1/query", bearer, `{"template":"app_sessions","params":{"from":"2026-09-01","to":"2026-09-02","device_ids":["`+uuid.NewString()+`"]}}`); w.Code != http.StatusOK || run.seen[len(run.seen)-1].Bind()[deviceParam] != "['"+device.String()+"']" {
		t.Fatalf("a member naming a teammate's device must read only their own: %d %v", w.Code, run.seen[len(run.seen)-1].Bind())
	}
}
