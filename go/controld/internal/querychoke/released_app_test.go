package querychoke

import (
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/appapi/schemacheck"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
)

// The released app (Mark1-GUI v0.1.14, appapi/testdata/app-v0.1.14) parses GET /reports/tvo with trend[].tvo a number: a day with work and no verified outcome is left out of the trend, so the app parses every report this cloud can write — verified days, a zero-verified window, and a member's per-day read.
func TestTVOReportParsesInTheReleasedApp(t *testing.T) {
	old := schemacheck.Load(t, filepath.Join("..", "appapi", "testdata", "app-v0.1.14"))
	for name, run := range map[string]*fakeRunner{"verified day": coveredDay(), "zero verified": coveredDayFake(0)} {
		_, mux, _, bearer := newTestModule(t, run, false)
		w := do(mux, "GET", "/api/v1/reports/tvo?window=7d", bearer, "")
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", name, w.Code, w.Body.String())
		}
		old.Validate("tvo_report.json", w.Body.Bytes())
	}
	reg, _ := LoadTemplates()
	now := time.Now().UTC()
	day := func(d int, task string, word string, pS float64) map[string]any {
		return map[string]any{
			"day": now.AddDate(0, 0, d), "task_id": task, "attempt_n": uint64(1), "gen_tokens": uint64(400), "verifier_tokens": uint64(0),
			"fused_verdict": word, "verdict_stage": "revised", "task_seg_version": "task_seg.v1",
			"p_satisfied": pS, "p_violated": 1 - pS, "p_refused": 0.0, "p_error": 0.0,
		}
	}
	run := &fakeRunner{rows: &Rows{}, byTemplate: map[string]*Rows{"tvo_task_day": {Rows: []map[string]any{
		day(-2, "a", "satisfied", 0.9), day(-1, "b", "violated", 0.1),
	}}}}
	device := uuid.New()
	m := New(Deps{Registry: reg, Runner: run, Verifier: auth.NewHMACVerifier([]byte(testHMACKey), auth.StaticRevocations{}), ObsCfg: obs.Config{ServiceName: "test"}, Viewers: &fakeViewers{v: Viewer{Team: true, Devices: []uuid.UUID{device}}}})
	mux := http.NewServeMux()
	m.RegisterRoutes(mux)
	w := do(mux, "GET", "/api/v1/reports/tvo?window=7d", auth.Mint([]byte(testHMACKey), uuid.New(), device, time.Hour), "")
	if w.Code != http.StatusOK {
		t.Fatalf("member report: %d %s", w.Code, w.Body.String())
	}
	old.Validate("tvo_report.json", w.Body.Bytes())
}
