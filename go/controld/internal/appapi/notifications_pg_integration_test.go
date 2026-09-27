//go:build integration

package appapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/mail"
)

type fakeMailer struct {
	sent []mail.Message
	fail error
}

func (f *fakeMailer) send(ctx context.Context, m mail.Message) (string, error) {
	if _, ok := ctx.Deadline(); !ok {
		return "", errors.New("invite send without a deadline")
	}
	if f.fail != nil {
		return "", f.fail
	}
	f.sent = append(f.sent, m)
	return "d-1", nil
}

// 16-release L3 under FORCE RLS: the invite is emailed after commit (a failed send keeps it), the owner cancels a live invite, GET /team credits per-member totals from team_device_totals with the rest unattributed, the digest opt-in round-trips, and the public unsubscribe flips only its own row.
func TestIntegrationTeamRoundedAndDigestPrefs(t *testing.T) {
	r := setupPG(t)
	ctx := context.Background()
	mailer := &fakeMailer{}
	r.api = r.teamAPI(10, mailer.send)
	tenantA, tenantB := r.personal("alice"), r.personal("bob")
	alice, bob := r.userToken("alice", tenantA), r.userToken("bob", tenantB)

	// invite email: sent after commit, the #token in the body, the footer carries the postal address
	code, raw := r.send(http.MethodPost, "/api/v1/team/invites", alice, `{"email":"bob@it.example"}`)
	inv := r.decode("team_invite.json", raw)
	if code != http.StatusOK || inv["sent"] != true || len(mailer.sent) != 1 {
		t.Fatalf("invite with email: %d %s (%d sent)", code, raw, len(mailer.sent))
	}
	if m := mailer.sent[0]; m.To != "bob@it.example" || !strings.Contains(m.Text, inv["invite_link"].(string)) || !strings.Contains(m.HTML, "Omium, 1 Test St") {
		t.Fatalf("invite mail: %+v", m)
	}
	if _, raw = r.send(http.MethodPost, "/api/v1/team/invites", alice, `{}`); r.decode("team_invite.json", raw)["sent"] != false || len(mailer.sent) != 1 {
		t.Fatalf("a link-only invite is never emailed: %s", raw)
	}
	mailer.fail = errors.New("customer.io: 401")
	_, raw = r.send(http.MethodPost, "/api/v1/team/invites", alice, `{"email":"carol@it.example"}`)
	if failed := r.decode("team_invite.json", raw); failed["sent"] != false {
		t.Fatalf("a failed send answers sent:false: %s", raw)
	}
	var live int
	if err := r.admin.QueryRow(ctx, `SELECT count(*) FROM m1_team_invites WHERE tenant_id = $1 AND accepted_at IS NULL AND expires_at > now()`, tenantA).Scan(&live); err != nil || live != 3 {
		t.Fatalf("a failed send keeps the invite: %d %v", live, err)
	}

	// accept bob so there is a member, then cancel: owner only, a second cancel and another team's id are invite_invalid
	accept := strings.TrimPrefix(inv["invite_link"].(string), inviteBase)
	if code, raw := r.send(http.MethodPost, "/api/v1/team/invites/accept", bob, `{"token":"`+accept+`"}`); code != http.StatusOK {
		t.Fatalf("accept: %d %s", code, raw)
	}
	var carolInvite uuid.UUID
	if err := r.admin.QueryRow(ctx, `SELECT id FROM m1_team_invites WHERE tenant_id = $1 AND invited_email = 'carol@it.example'`, tenantA).Scan(&carolInvite); err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/team/invites/invite:" + carolInvite.String()
	r.refusedTeam(http.MethodDelete, path, bob, ``, http.StatusForbidden, "not_owner")
	r.refusedTeam(http.MethodDelete, path, auth.Mint([]byte(testKey), tenantA, r.approvedEnrollment(tenantA, "omium:alice", time.Now().UTC()), time.Hour), ``, http.StatusForbidden, "user_token_required")
	r.refusedTeam(http.MethodDelete, path, auth.Mint([]byte(testKey), tenantA, uuid.New(), time.Hour), ``, http.StatusForbidden, "not_member")
	code, raw = r.send(http.MethodDelete, path, alice, "")
	if code != http.StatusOK || r.decode("team_invite_cancel.json", raw)["status"] != "cancelled" {
		t.Fatalf("cancel: %d %s", code, raw)
	}
	r.refusedTeam(http.MethodDelete, "/api/v1/team/invites/"+carolInvite.String(), alice, ``, http.StatusNotFound, "invite_invalid")
	eve := r.userToken("eve", r.personal("eve"))
	if code, raw := r.send(http.MethodPost, "/api/v1/team/invites", eve, `{}`); code != http.StatusOK {
		t.Fatalf("eve's invite: %d %s", code, raw)
	}
	var eveInvite uuid.UUID
	if err := r.admin.QueryRow(ctx, `SELECT id FROM m1_team_invites WHERE invited_by = 'omium:eve'`).Scan(&eveInvite); err != nil {
		t.Fatal(err)
	}
	r.refusedTeam(http.MethodDelete, "/api/v1/team/invites/"+eveInvite.String(), alice, ``, http.StatusNotFound, "invite_invalid")
	if code, _ := r.send(http.MethodGet, "/api/v1/team", eve, ""); code != http.StatusOK {
		t.Fatal("eve's team")
	}

	// totals: alice's and bob's devices credit their rows, a stranger's device is unattributed, no device id leaves
	aliceDev := r.approvedEnrollment(tenantA, "omium:alice", time.Now().UTC())
	bobDev := r.approvedEnrollment(tenantA, "omium:bob", time.Now().UTC())
	ghost := r.approvedEnrollment(tenantA, "omium:ghost", time.Now().UTC())
	row := func(d uuid.UUID, s, v, tok, saved uint64) map[string]any {
		return map[string]any{"device_id": d.String(), "sessions": s, "tasks_verified": v, "tokens": tok, "tokens_saved": saved}
	}
	r.run.add("team_device_totals", tenantA, row(aliceDev, 2, 1, 100, 10), row(bobDev, 3, 2, 300, 0), row(ghost, 1, 0, 5, 1))
	r.run.seen = nil
	code, raw = r.send(http.MethodGet, "/api/v1/team", bob, "")
	team := r.decode("team.json", raw)
	if code != http.StatusOK {
		t.Fatalf("team: %d %s", code, raw)
	}
	byID := map[string]any{}
	for _, m := range team["members"].([]any) {
		mm := m.(map[string]any)
		byID[mm["id"].(string)] = mm["totals"]
	}
	if a := byID["alice"].(map[string]any); a["sessions"] != float64(2) || a["tokens_saved"] != float64(10) {
		t.Fatalf("alice totals: %v", byID)
	}
	if b := byID["bob"].(map[string]any); b["tasks_verified"] != float64(2) || b["tokens"] != float64(300) {
		t.Fatalf("bob totals: %v", byID)
	}
	sums := team["totals"].(map[string]any)
	if sums["team"].(map[string]any)["sessions"] != float64(6) || sums["unattributed"].(map[string]any)["tokens"] != float64(5) {
		t.Fatalf("team sums: %v", sums)
	}
	for _, d := range []uuid.UUID{aliceDev, bobDev, ghost} {
		if strings.Contains(string(raw), d.String()) {
			t.Fatalf("a device id reached the app: %s", raw)
		}
	}
	ran := 0
	for _, q := range r.run.seen {
		if q.Template().Name() == "team_device_totals" {
			if ran++; q.Bind()["tid"] != tenantA.String() {
				t.Fatalf("a member's GET /team read totals for %s", q.Bind()["tid"])
			}
		}
	}
	if ran != 1 {
		t.Fatalf("team_device_totals ran %d times", ran)
	}

	// the digest opt-in: off by default, needs the user token, round-trips, and is per tenant
	code, raw = r.send(http.MethodGet, "/api/v1/me/notifications", alice, "")
	if p := r.decode("notifications.json", raw); code != http.StatusOK || p["weekly_digest"] != false || p["email"] != "alice@it.example" {
		t.Fatalf("default prefs: %d %s", code, raw)
	}
	for _, bad := range []string{`{}`, `{"weekly_digest":true,"x":1}`, `{"weekly_digest":"on"}`} {
		if code, _ := r.send(http.MethodPut, "/api/v1/me/notifications", alice, bad); code != http.StatusBadRequest {
			t.Fatalf("PUT %s: %d", bad, code)
		}
	}
	r.refusedTeam(http.MethodGet, "/api/v1/me/notifications", auth.Mint([]byte(testKey), tenantA, r.approvedEnrollment(tenantA, "omium:alice", time.Now().UTC()), time.Hour), ``, http.StatusForbidden, "user_token_required")
	for _, who := range []string{alice, bob} {
		if code, raw = r.send(http.MethodPut, "/api/v1/me/notifications", who, `{"weekly_digest":true}`); code != http.StatusOK || r.decode("notifications.json", raw)["weekly_digest"] != true {
			t.Fatalf("opt in: %d %s", code, raw)
		}
	}
	var rows int
	if err := r.admin.QueryRow(ctx, `SELECT count(*) FROM m1_notification_prefs WHERE tenant_id = $1 AND weekly_digest`, tenantA).Scan(&rows); err != nil || rows != 2 {
		t.Fatalf("bob's opt-in lands in the team tenant he works in: %d %v", rows, err)
	}

	// public unsubscribe: GET only confirms, POST (one-click body) flips that row alone, a stranger token is a 404 page
	var token string
	if err := r.admin.QueryRow(ctx, `SELECT unsub_token FROM m1_notification_prefs WHERE tenant_id = $1 AND subject = 'omium:alice'`, tenantA).Scan(&token); err != nil {
		t.Fatal(err)
	}
	page := func(method, tok, body string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(method, r.api.URL+"/api/v1/unsubscribe/"+tok, strings.NewReader(body))
		if body != "" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		var b strings.Builder
		buf := make([]byte, 4096)
		for {
			n, err := resp.Body.Read(buf)
			b.Write(buf[:n])
			if err != nil {
				break
			}
		}
		return resp.StatusCode, b.String()
	}
	if code, body := page(http.MethodGet, token, ""); code != http.StatusOK || !strings.Contains(body, `<form method="post">`) {
		t.Fatalf("confirm page: %d %s", code, body)
	}
	digest := func(subject string) (on bool) {
		t.Helper()
		if err := r.admin.QueryRow(ctx, `SELECT weekly_digest FROM m1_notification_prefs WHERE tenant_id = $1 AND subject = $2`, tenantA, subject).Scan(&on); err != nil {
			t.Fatal(err)
		}
		return on
	}
	if !digest("omium:alice") {
		t.Fatal("GET unsubscribed")
	}
	if code, body := page(http.MethodPost, token, url.Values{"List-Unsubscribe": {"One-Click"}}.Encode()); code != http.StatusOK || !strings.Contains(body, "unsubscribed") {
		t.Fatalf("one-click: %d %s", code, body)
	}
	if digest("omium:alice") || !digest("omium:bob") {
		t.Fatal("unsubscribe flipped the wrong row")
	}
	if code, _ := page(http.MethodPost, token, ""); code != http.StatusOK {
		t.Fatal("a repeat unsubscribe is idempotent")
	}
	if code, _ := page(http.MethodPost, strings.Repeat("a", 64), ""); code != http.StatusNotFound {
		t.Fatal("unknown token")
	}
	if _, raw = r.send(http.MethodGet, "/api/v1/me/notifications", alice, ""); r.decode("notifications.json", raw)["weekly_digest"] != false {
		t.Fatalf("prefs after unsubscribe: %s", raw)
	}
}

// m1_091's grants and definer: controld reads/writes prefs and runs the lookup, intel reads prefs and owns the send ledger, nobody else runs the lookup; the file re-runs clean.
func TestIntegrationNotificationMigration(t *testing.T) {
	r := setupPG(t)
	ctx := context.Background()
	sql, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "migrations", "m1_091_notification_prefs.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.admin.Exec(ctx, string(sql)); err != nil {
		t.Fatalf("m1_091 re-run: %v", err)
	}
	for q, want := range map[string]bool{
		`has_table_privilege('controld_app', 'm1_notification_prefs', 'SELECT')`:                                                                                    true,
		`has_table_privilege('controld_app', 'm1_notification_prefs', 'INSERT')`:                                                                                    true,
		`has_column_privilege('controld_app', 'm1_notification_prefs', 'weekly_digest', 'UPDATE')`:                                                                  true,
		`has_column_privilege('controld_app', 'm1_notification_prefs', 'unsub_token', 'UPDATE')`:                                                                    false,
		`has_table_privilege('controld_app', 'm1_notification_sends', 'SELECT')`:                                                                                    false,
		`has_function_privilege('controld_app', 'm1_notification_unsub_lookup(text)', 'EXECUTE')`:                                                                   true,
		`has_function_privilege('intel_app', 'm1_notification_unsub_lookup(text)', 'EXECUTE')`:                                                                      false,
		`has_table_privilege('intel_app', 'm1_notification_prefs', 'SELECT')`:                                                                                       true,
		`has_table_privilege('intel_app', 'm1_notification_prefs', 'UPDATE')`:                                                                                       false,
		`has_table_privilege('intel_app', 'm1_notification_sends', 'INSERT')`:                                                                                       true,
		`has_table_privilege('intel_app', 'm1_notification_sends', 'UPDATE')`:                                                                                       true,
		`(SELECT relforcerowsecurity FROM pg_class WHERE relname = 'm1_notification_prefs')`:                                                                        true,
		`(SELECT relforcerowsecurity FROM pg_class WHERE relname = 'm1_notification_sends')`:                                                                        true,
		`(SELECT prosecdef FROM pg_proc WHERE proname = 'm1_notification_unsub_lookup')`:                                                                            true,
		`(SELECT length(unsub_token) = 64 FROM (SELECT (replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', '')) AS unsub_token) t)`: true,
	} {
		var got bool
		if err := r.admin.QueryRow(ctx, `SELECT `+q).Scan(&got); err != nil || got != want {
			t.Errorf("%s = %v (%v), want %v", q, got, err, want)
		}
	}
}
