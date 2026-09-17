package appapi

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func b64(id uuid.UUID) string { return base64.StdEncoding.EncodeToString(id[:]) }

func TestInjectionsLogFoldsOutcomeAtClose(t *testing.T) {
	r := newRig(t)
	at := time.Now().UTC().Add(-3 * time.Hour)
	session := v7()
	task1, task2 := uuid.New(), uuid.New()
	art1, art2, art3 := uuid.New(), uuid.New(), uuid.New()
	r.run.add("app_session_events", r.tenantA,
		eventRow(session, task1, 1, at, "TaskOpen", 0, `{}`, nil),
		eventRow(session, task1, 2, at, "MemoryInjection", 0, `{"artifact_ids":["`+b64(art1)+`","`+b64(art2)+`"],"channel":"INJECTION_CHANNEL_HOOK_CONTEXT","tokens_used":12}`, nil),
		eventRow(session, task1, 3, at, "VerdictEvent", 0, `{}`, map[string]any{"verdict": "violated", "verdict_stage": "provisional"}),
		eventRow(session, task1, 4, at, "VerdictEvent", 0, `{}`, map[string]any{"verdict": "satisfied", "verdict_stage": "certified"}),
		eventRow(session, task2, 5, at, "MemoryInjection", 0, `{"artifact_ids":["`+b64(art3)+`"],"channel":"INJECTION_CHANNEL_MCP_PULL","tokens_used":40}`, nil),
		eventRow(session, task2, 6, at, "VerdictEvent", 0, `{}`, map[string]any{"verdict": "violated", "verdict_stage": "provisional"}),
		eventRow(session, uuid.Nil, 7, at, "MemoryInjection", 0, `{"artifact_ids":["AAEC"],"channel":"INJECTION_CHANNEL_REACTIVE_PITFALL","tokens_used":3}`, nil),
		eventRow(session, task1, 8, at, "Usage", 30, `{}`, nil),
	)
	r.run.add("app_session_events", r.tenantB,
		eventRow(v7(), uuid.New(), 1, at, "MemoryInjection", 0, `{"artifact_ids":["`+b64(art1)+`"],"channel":"INJECTION_CHANNEL_MCP_PULL","tokens_used":1}`, nil),
	)
	r.refused("/api/v1/memory/injections?window=0d", r.tokenA, http.StatusBadRequest, "M1E-2001")
	r.refused("/api/v1/memory/injections?limit=0", r.tokenA, http.StatusBadRequest, "M1E-2001")
	r.refused("/api/v1/memory/injections", "", http.StatusUnauthorized, "M1E-1002")
	r.run.seen = nil

	body := r.ok("/api/v1/memory/injections", r.tokenA, "memory_injections.json")
	r.boundTenants(r.tenantA)
	rows := body["injections"].([]any)
	if len(rows) != 4 {
		t.Fatalf("want 4 rows (2+1+1 artifacts), got %d: %v", len(rows), rows)
	}
	got := map[string]map[string]any{}
	for _, raw := range rows {
		row := raw.(map[string]any)
		got[row["artifact_id"].(string)] = row
	}
	if got[art1.String()]["outcome"] != "satisfied" || got[art2.String()]["outcome"] != "satisfied" || got[art1.String()]["channel"] != "hook_context" || got[art1.String()]["tokens_used"].(float64) != 12 {
		t.Fatalf("task1 injection rows: %v", got)
	}
	if got[art1.String()]["task_id"] != task1.String() || got[art1.String()]["session_id"] != session.String() {
		t.Fatalf("task1 row identity: %v", got[art1.String()])
	}
	if got[art3.String()]["outcome"] != "pending" || got[art3.String()]["channel"] != "mcp_pull" {
		t.Fatalf("provisional-only task is pending: %v", got[art3.String()])
	}
	if got["000102"]["outcome"] != "pending" || got["000102"]["task_id"] != nil {
		t.Fatalf("task-less reactive row: %v", got["000102"])
	}
	// newest first: seq 7 then 5 then 2 (two rows).
	if rows[0].(map[string]any)["artifact_id"] != "000102" || rows[1].(map[string]any)["artifact_id"] != art3.String() {
		t.Fatalf("order: %v", rows)
	}
	if rows[2].(map[string]any)["id"] == rows[3].(map[string]any)["id"] {
		t.Fatalf("two artifacts of one event share an id: %v", rows[2:])
	}
	if _, ok := body["honesty"].(map[string]any)["coverage_band"]; !ok {
		t.Fatalf("honesty missing: %v", body)
	}
	if page := r.ok("/api/v1/memory/injections?limit=1", r.tokenA, "memory_injections.json"); len(page["injections"].([]any)) != 1 {
		t.Fatalf("limit not applied: %v", page)
	}
	if bodyB := r.ok("/api/v1/memory/injections", r.tokenB, "memory_injections.json"); len(bodyB["injections"].([]any)) != 1 {
		t.Fatalf("tenant B sees its own single row: %v", bodyB)
	}
}

func TestArtifactIDDecodesTheProtojsonBytes(t *testing.T) {
	id := uuid.New()
	if got := artifactID(b64(id)); got != id.String() {
		t.Fatalf("16 bytes: %s", got)
	}
	if got := artifactID("AAEC"); got != "000102" {
		t.Fatalf("short bytes: %s", got)
	}
	if got := artifactID("not base64!"); got != "not base64!" {
		t.Fatalf("garbage: %s", got)
	}
}

func TestTeamSchemasCoverTheContract(t *testing.T) {
	s := loadSchemas(t)
	s.Validate("team.json", []byte(`{"members":[{"id":"usr_1","name":null,"email":null,"role":"owner","joined_at":"2026-09-16T00:00:00Z","status":"active"},{"id":"invite:0191c7a0-5b1e-7c2d-9e4f-0123456789a0","name":null,"email":"a@b.example","role":"member","joined_at":"2026-09-16T00:00:00Z","status":"invited"}],"invite_link":null,"shared_memory":false,"tvo":{"tvo":100,"coverage_band":{"observed_fraction":0.97,"coverage_lower":0.96,"floor":0.95},"cost_basis":"usd","guarantee_grade":true},"fleet_status":null}`))
	s.Validate("team.json", []byte(`{"members":[],"invite_link":null,"shared_memory":true,"tvo":null,"fleet_status":null}`))
	s.Validate("team_invite.json", []byte(`{"sent":true,"invite_link":"https://app.omium.ai/invite/0191c7a0-5b1e-7c2d-9e4f-0123456789a0/`+base64.RawURLEncoding.EncodeToString(make([]byte, 32))+`","invited_email":null,"status":"sent","expires_at":"2026-09-23T00:00:00Z"}`))
	s.Validate("team_update.json", []byte(`{"shared_memory":true}`))
	s.Validate("memory_action.json", []byte(`{"artifact_id":"0191c7a0-5b1e-7c2d-9e4f-0123456789a0","state":"retired","receipt_id":"0191c7a0-5b1e-7c2d-9e4f-0123456789a1"}`))
	s.Validate("memory_action.json", []byte(`{"artifact_id":"0191c7a0-5b1e-7c2d-9e4f-0123456789a0","pinned":true}`))
	s.Validate("memory_outcomes.json", []byte(`{"outcomes":[{"artifact_id":"0191c7a0-5b1e-7c2d-9e4f-0123456789a0","verified_outcomes":11,"uplift_lcb":0.34,"n":11}]}`))
	for file, bad := range map[string]string{
		"team.json":              `{"members":[{"id":"x","name":"n","email":null,"role":"owner","joined_at":"2026-09-16T00:00:00Z","status":"active"}],"invite_link":null,"shared_memory":false,"tvo":null,"fleet_status":null}`,
		"team_invite.json":       `{"sent":false,"invite_link":"https://evil.example/x","invited_email":null,"status":"sent","expires_at":"2026-09-23T00:00:00Z"}`,
		"memory_action.json":     `{"artifact_id":"0191c7a0-5b1e-7c2d-9e4f-0123456789a0","state":"admitted"}`,
		"memory_outcomes.json":   `{"outcomes":[{"artifact_id":"0191c7a0-5b1e-7c2d-9e4f-0123456789a0","verified_outcomes":-1,"uplift_lcb":0.34,"n":11}]}`,
		"memory_injections.json": `{"window":{"from":"2026-09-01","to":"2026-09-16"},"injections":[{"id":"x","artifact_id":"a","at":"2026-09-16T00:00:00Z","session_id":"0191c7a0-5b1e-7c2d-9e4f-0123456789a0","task_id":null,"channel":"hook_context","tokens_used":1,"outcome":"maybe"}],"honesty":{"coverage_band":{"observed_fraction":1,"coverage_lower":1,"floor":0.95},"cost_basis":"usd","guarantee_grade":true,"task_seg_version":"task_seg.v1"}}`,
	} {
		var errs []string
		var inst any
		dec := json.NewDecoder(strings.NewReader(bad))
		dec.UseNumber()
		if err := dec.Decode(&inst); err != nil {
			t.Fatal(err)
		}
		s.Walk(file, s.Docs()[file], inst, "$", &errs)
		if len(errs) == 0 {
			t.Errorf("%s: validator passed %s", file, bad)
		}
	}
}
