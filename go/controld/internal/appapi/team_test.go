package appapi

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	s.Validate("team.json", []byte(`{"members":[{"id":"usr_1","name":null,"email":"o@b.example","role":"owner","joined_at":"2026-09-16T00:00:00Z","last_active":"2026-09-17T00:00:00Z","status":"active","totals":{"sessions":3,"tasks_verified":2,"tokens":1200,"tokens_saved":-40}},{"id":"invite:0191c7a0-5b1e-7c2d-9e4f-0123456789a0","name":null,"email":"a@b.example","role":"member","joined_at":"2026-09-16T00:00:00Z","last_active":null,"status":"invited","totals":null}],"you":{"role":"owner"},"max_members":10,"invite_link":null,"shared_memory":false,"tvo":{"tvo":100,"coverage_band":{"observed_fraction":0.97,"coverage_lower":0.96,"floor":0.95},"cost_basis":"usd","guarantee_grade":true},"totals":{"window":{"from":"2026-08-28","to":"2026-09-26"},"team":{"sessions":3,"tasks_verified":2,"tokens":1200,"tokens_saved":-40},"unattributed":{"sessions":0,"tasks_verified":0,"tokens":0,"tokens_saved":0}},"fleet_status":null}`))
	s.Validate("team.json", []byte(`{"members":[],"you":{"role":"member"},"max_members":10,"invite_link":null,"shared_memory":true,"tvo":null,"totals":null,"fleet_status":null}`))
	s.Validate("team_invite.json", []byte(`{"sent":false,"invite_link":"https://mark.omium.ai/join#`+base64.RawURLEncoding.EncodeToString(make([]byte, 32))+`","invited_email":null,"status":"invited","expires_at":"2026-09-23T00:00:00Z"}`))
	s.Validate("team_invite.json", []byte(`{"sent":true,"invite_link":"https://mark.omium.ai/join#`+base64.RawURLEncoding.EncodeToString(make([]byte, 32))+`","invited_email":"a@b.example","status":"invited","expires_at":"2026-09-23T00:00:00Z"}`))
	s.Validate("team_invite_cancel.json", []byte(`{"id":"invite:0191c7a0-5b1e-7c2d-9e4f-0123456789a0","status":"cancelled"}`))
	s.Validate("notifications.json", []byte(`{"weekly_digest":false,"email":null}`))
	s.Validate("team_accept.json", []byte(`{"tenant_id":"0191c7a0-5b1e-7c2d-9e4f-0123456789a0","role":"member"}`))
	s.Validate("team_leave.json", []byte(`{"tenant_id":"0191c7a0-5b1e-7c2d-9e4f-0123456789a0"}`))
	s.Validate("team_member_remove.json", []byte(`{"id":"usr_2","status":"removed","revoked_devices":2}`))
	s.Validate("error.json", []byte(`{"error":{"code":"M1E-2011","message":"the team is full","reason":"team_full"}}`))
	s.Validate("team_update.json", []byte(`{"shared_memory":true}`))
	s.Validate("memory_action.json", []byte(`{"artifact_id":"0191c7a0-5b1e-7c2d-9e4f-0123456789a0","state":"retired","receipt_id":"0191c7a0-5b1e-7c2d-9e4f-0123456789a1"}`))
	s.Validate("memory_action.json", []byte(`{"artifact_id":"0191c7a0-5b1e-7c2d-9e4f-0123456789a0","pinned":true}`))
	s.Validate("memory_outcomes.json", []byte(`{"outcomes":[{"artifact_id":"0191c7a0-5b1e-7c2d-9e4f-0123456789a0","verified_outcomes":11,"uplift_lcb":0.34,"n":11}]}`))
	for file, bad := range map[string]string{
		"team.json":               `{"members":[{"id":"x","name":"n","email":null,"role":"owner","joined_at":"2026-09-16T00:00:00Z","last_active":null,"status":"active","totals":null}],"you":{"role":"owner"},"max_members":10,"invite_link":null,"shared_memory":false,"tvo":null,"totals":null,"fleet_status":null}`,
		"team_invite_cancel.json": `{"id":"0191c7a0-5b1e-7c2d-9e4f-0123456789a0","status":"cancelled"}`,
		"notifications.json":      `{"weekly_digest":"yes","email":null}`,
		"team_invite.json":        `{"sent":true,"invite_link":"https://app.omium.ai/invite/x","invited_email":null,"status":"sent","expires_at":"2026-09-23T00:00:00Z"}`,
		"team_accept.json":        `{"tenant_id":"0191c7a0-5b1e-7c2d-9e4f-0123456789a0","role":"owner"}`,
		"memory_action.json":      `{"artifact_id":"0191c7a0-5b1e-7c2d-9e4f-0123456789a0","state":"admitted"}`,
		"memory_outcomes.json":    `{"outcomes":[{"artifact_id":"0191c7a0-5b1e-7c2d-9e4f-0123456789a0","verified_outcomes":-1,"uplift_lcb":0.34,"n":11}]}`,
		"memory_injections.json":  `{"window":{"from":"2026-09-01","to":"2026-09-16"},"injections":[{"id":"x","artifact_id":"a","at":"2026-09-16T00:00:00Z","session_id":"0191c7a0-5b1e-7c2d-9e4f-0123456789a0","task_id":null,"channel":"hook_context","tokens_used":1,"outcome":"maybe"}],"honesty":{"coverage_band":{"observed_fraction":1,"coverage_lower":1,"floor":0.95},"cost_basis":"usd","guarantee_grade":true,"task_seg_version":"task_seg.v1"}}`,
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

func TestInviteTokenTakesTheLinkOrTheToken(t *testing.T) {
	for in, want := range map[string]string{
		"abc_-9":                            "abc_-9",
		"  https://mark.omium.ai/join#abc ": "abc",
		"https://app.omium.ai/invite/0191c7a0-5b1e-7c2d-9e4f-0123456789a0/abc": "abc",
		"https://mark.omium.ai/join#":                                          "",
		"":                                                                     "",
	} {
		if got := inviteToken(in); got != want {
			t.Errorf("inviteToken(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTeamTotalsCreditMembersAndKeepTheRestUnattributed(t *testing.T) {
	owner, mate, stranger := uuid.New(), uuid.New(), uuid.New()
	members := []member{
		{ID: "alice", Status: "active"}, {ID: "bob", Status: "active"}, {ID: "invite:x", Status: "invited"},
	}
	owners := map[string]string{owner.String(): "omium:alice", mate.String(): "omium:bob", stranger.String(): "omium:left"}
	byDevice := map[string]totals{
		owner.String():    {Sessions: 2, TasksVerified: 1, Tokens: 100, TokensSaved: 10},
		mate.String():     {Sessions: 1, Tokens: 50},
		stranger.String(): {Sessions: 4, Tokens: 7, TokensSaved: 3},
		uuid.NewString():  {Sessions: 1, Tokens: 1},
	}
	from, to, _ := parseWindow("")
	out := foldTotals(members, owners, byDevice, from, to)
	if *members[0].Totals != (totals{2, 1, 100, 10}) || *members[1].Totals != (totals{1, 0, 50, 0}) || members[2].Totals != nil {
		t.Fatalf("members: %+v %+v %+v", members[0].Totals, members[1].Totals, members[2].Totals)
	}
	if out["team"] != (totals{8, 1, 158, 13}) || out["unattributed"] != (totals{5, 0, 8, 3}) {
		t.Fatalf("team/unattributed: %+v", out)
	}
	raw, _ := json.Marshal(out)
	for _, id := range []uuid.UUID{owner, mate, stranger} {
		if strings.Contains(string(raw), id.String()) {
			t.Fatalf("a device id left the fold: %s", raw)
		}
	}

}

func TestInviteMailCarriesTheLinkUntracked(t *testing.T) {
	at := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	m := inviteMail("bob@b.example", "<alice>@a.example", "https://mark.omium.ai/join#tok_-9", at, "Omium, 1 Main St")
	if m.To != "bob@b.example" || !strings.Contains(m.Subject, "<alice>@a.example") {
		t.Fatalf("envelope: %+v", m)
	}
	for _, part := range []string{m.Text, m.HTML} {
		if !strings.Contains(part, "https://mark.omium.ai/join#tok_-9") || !strings.Contains(part, "3 October 2026") || !strings.Contains(part, "Omium, 1 Main St") {
			t.Fatalf("body: %s", part)
		}
	}
	if strings.Contains(m.HTML, "<alice>") || !strings.Contains(m.HTML, "&lt;alice&gt;") {
		t.Fatalf("html not escaped: %s", m.HTML)
	}
	if n := inviteMail("x@b.example", "", "l", at, ""); !strings.HasPrefix(n.Text, "A teammate invited you") || strings.Contains(n.HTML, "font-size:12px") {
		t.Fatalf("no inviter/postal: %+v", n)
	}
}

func TestUnsubscribeRefusesMalformedTokensWithoutAStore(t *testing.T) {
	r := newRig(t)
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		for _, tok := range []string{"short", strings.Repeat("G", 64), strings.Repeat("a", 65)} {
			req := httptest.NewRequest(method, "/api/v1/unsubscribe/"+tok, nil)
			w := httptest.NewRecorder()
			r.mux.ServeHTTP(w, req)
			if w.Code != http.StatusNotFound || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("%s %s: %d %v", method, tok, w.Code, w.Header())
			}
		}
	}
}

// An invite names one bare address, lowercased; a list, a display name, an angle-bracketed or a group address is a 400 before anything is minted or mailed.
func TestInviteAddressIsOneBareAddress(t *testing.T) {
	if got, err := inviteAddress("Bob@It.Example"); err != nil || got != "bob@it.example" {
		t.Fatalf("plain address: %q %v", got, err)
	}
	for _, bad := range []string{"a@b.example, c@d.example", "Eve <e@b.example>", "<e@b.example>", "team: a@b.example;", "nope", "a@", strings.Repeat("a", 250) + "@b.example"} {
		if got, err := inviteAddress(bad); err == nil {
			t.Errorf("%q accepted as %q", bad, got)
		}
	}
}
