package appapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/appapi/schemacheck"
)

// releasedAppSchemas are Mark1-GUI v0.1.14's zod response schemas (src/shared/endpoints.ts at that tag) transcribed to the schemacheck subset: what the app users have installed demands of the same routes. Extra fields pass (zod strips them); a missing, retyped or newly-null field is a parse failure in every un-updated app.
const releasedAppSchemas = "testdata/app-v0.1.14"

// releasedApp holds body to the released app's schema for the same route, when that app reads it.
func releasedApp(t *testing.T, schema string, body []byte) {
	t.Helper()
	s := schemacheck.Load(t, releasedAppSchemas)
	if _, ok := s.Docs()[schema]; ok {
		s.Validate(schema, body)
	}
}

// The transcription reds on the two shapes this release would have shipped to v0.1.14: a trend point with tvo null and a session whose net savings went negative.
func TestReleasedAppSchemasRedOnTheBreaksTheyGuard(t *testing.T) {
	s := schemacheck.Load(t, releasedAppSchemas)
	for schema, body := range map[string]string{
		"tvo_report.json": `{"tvo":null,"trend":[{"day":"2026-09-01","tvo":null}],"coverage_band":{"observed_fraction":1,"floor":0.95},"cost_basis":"quota","task_seg_version":"task_seg.v1","waste":{},"guarantee_grade":false}`,
		"team.json":       `{"members":[],"invite_link":null,"shared_memory":false,"fleet_status":null,"tvo":{"tvo":null,"coverage_band":{"observed_fraction":1,"floor":0.95},"cost_basis":"quota","guarantee_grade":false,"trend":[{"day":"2026-09-01","tvo":null}]}}`,
		"sessions.json":   `{"window":{"from":"a","to":"b"},"next_cursor":null,"honesty":null,"sessions":[{"session_id":"s","agent":"claudecode","project":"","started_at":"a","ended_at":"b","tokens":{"input":0,"output":0,"cache_read":0,"cache_create":0},"tasks":0,"verified_outcomes":0,"arrests":0,"tokens_saved":-5,"injections":0,"route_decisions":0,"coverage":{"capture_paths":[],"proxy_in_path":false,"transcript_tailed":false,"dropped_billing":0},"checkpoint_seq":0}]}`,
	} {
		var inst any
		dec := json.NewDecoder(bytes.NewReader([]byte(body)))
		dec.UseNumber()
		if err := dec.Decode(&inst); err != nil {
			t.Fatal(err)
		}
		var errs []string
		s.Walk(schema, s.Docs()[schema], inst, "$", &errs)
		if len(errs) == 0 {
			t.Errorf("%s passed a body v0.1.14 cannot parse: %s", schema, body)
		}
	}
}

// A session whose blocks cost more than they saved: v0.1.14 reads tokens_saved as a count, so the net rides tokens_saved_net and tokens_saved floors at 0.
func TestNegativeSessionSavingsStayParseableByTheReleasedApp(t *testing.T) {
	r := newRig(t)
	lossy := sessionRowFor(v7(), "claudecode", projA, []string{"CAPTURE_PATH_HOOKS"}, time.Now().UTC().Add(-time.Hour))
	lossy["tokens_saved"] = int64(-4200)
	r.run.add("app_sessions", r.tenantA, lossy)
	body := r.ok("/api/v1/sessions?window=7d", r.tokenA, "sessions.json")
	s := body["sessions"].([]any)[0].(map[string]any)
	if s["tokens_saved"] != float64(0) || s["tokens_saved_net"] != float64(-4200) {
		t.Fatalf("tokens_saved %v net %v, want 0 and -4200", s["tokens_saved"], s["tokens_saved_net"])
	}
	w := r.get("/api/v1/sessions?window=7d", r.tokenA)
	if w.Code != http.StatusOK {
		t.Fatal(w.Code)
	}
	releasedApp(t, "sessions.json", w.Body.Bytes())
}
