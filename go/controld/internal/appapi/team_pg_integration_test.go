//go:build integration

package appapi

// The team routes under FORCE RLS on the scratch migration tree (m1_090 included), through main.go's composition: the user token resolved by teams.EffectiveTenant, DELETE wired to enroll's revocation path. Invite, every accept refusal, the cap on both sides, one active membership, leave, rejoin, remove, and tenant E seeing none of A's rows.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/enroll"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/userauth"
)

func (r *pgRig) send(method, path, bearer, body string) (int, []byte) {
	r.t.Helper()
	req, err := http.NewRequest(method, r.api.URL+path, strings.NewReader(body))
	if err != nil {
		r.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		out.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return resp.StatusCode, []byte(out.String())
}

func (r *pgRig) decode(schema string, body []byte) map[string]any {
	r.t.Helper()
	r.schema.Validate(schema, body)
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		r.t.Fatal(err)
	}
	return out
}

// approvedEnrollment plants what /enroll/device/approve leaves behind: a device and its approved grant naming the approver.
func (r *pgRig) approvedEnrollment(tenant uuid.UUID, approver string, at time.Time) uuid.UUID {
	r.t.Helper()
	ctx := context.Background()
	host, code, tok, pub := make([]byte, 32), make([]byte, 32), make([]byte, 32), make([]byte, 32)
	for _, b := range [][]byte{host, code, tok, pub} {
		_, _ = rand.Read(b)
	}
	var device uuid.UUID
	if err := r.admin.QueryRow(ctx, `INSERT INTO m1_devices (tenant_id, platform, hostname_hmac, last_seen_at) VALUES ($1, 'linux', $2, $3) RETURNING id`, tenant, host, at).Scan(&device); err != nil {
		r.t.Fatal(err)
	}
	if _, err := r.admin.Exec(ctx, `INSERT INTO m1_device_enrollments (tenant_id, device_id, device_code_hash, token_hash, device_pubkey, oidc_subject, status, started_at, token_expires_at) VALUES ($1, $2, $3, $4, $5, $6, 'approved', $7, $8)`,
		tenant, device, code, tok, pub, approver, at, at.Add(time.Hour)); err != nil {
		r.t.Fatal(err)
	}
	return device
}

// teamAPI is setupPG's module wired the way main.go wires it for teams, capped at max.
func (r *pgRig) teamAPI(max int) *httptest.Server {
	r.t.Helper()
	jwks, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: r.userKey.Public(), Algorithm: "ES256", Use: "sig", KeyID: "it"}}})
	users, err := userauth.New("https://issuer.it", string(jwks))
	if err != nil {
		r.t.Fatal(err)
	}
	reg, err := querychoke.LoadTemplates()
	if err != nil {
		r.t.Fatal(err)
	}
	verifier := auth.Multi(auth.NewHMACVerifier([]byte(testKey), auth.StaticRevocations{}), users.TeamVerifier(r.db))
	obsCfg := obs.Config{ServiceName: "appapi-team-it"}
	m := New(Deps{
		Verifier: verifier, ObsCfg: obsCfg, Registry: reg, Runner: r.run,
		Reports: querychoke.New(querychoke.Deps{Registry: reg, Runner: r.run, Verifier: verifier, ObsCfg: obsCfg}),
		PG:      r.db, TeamMaxMembers: max,
		RevokeSubject: enroll.New(enroll.Deps{DB: r.db}).RevokeSubjectDevices,
	})
	mux := http.NewServeMux()
	m.RegisterRoutes(mux)
	api := httptest.NewServer(mux)
	r.t.Cleanup(api.Close)
	return api
}

func (r *pgRig) refusedTeam(method, path, bearer, body string, status int, reason string) {
	r.t.Helper()
	code, raw := r.send(method, path, bearer, body)
	r.schema.Validate("error.json", raw)
	if code != status || !strings.Contains(string(raw), `"reason":"`+reason+`"`) {
		r.t.Fatalf("%s %s: want %d %s, got %d %s", method, path, status, reason, code, raw)
	}
}

// meTenant reads /me's tenant id without me.json: these subs are names, not the platform's uuids.
func meTenant(body []byte) any {
	var me struct {
		Tenant struct {
			ID string `json:"id"`
		} `json:"tenant"`
	}
	_ = json.Unmarshal(body, &me)
	return me.Tenant.ID
}

func memberIDs(team map[string]any) []string {
	var ids []string
	for _, m := range team["members"].([]any) {
		ids = append(ids, m.(map[string]any)["id"].(string))
	}
	return ids
}

func (r *pgRig) personal(owner string) uuid.UUID {
	r.t.Helper()
	id := r.tenant(owner, "eu-west-1")
	if _, err := r.admin.Exec(context.Background(), `UPDATE m1_tenants SET owner_subject = $2 WHERE id = $1`, id, "omium:"+owner); err != nil {
		r.t.Fatal(err)
	}
	return id
}

func TestIntegrationTeamUnderRLS(t *testing.T) {
	r := setupPG(t)
	ctx := context.Background()
	r.api = r.teamAPI(3)
	tenantA, tenantB, tenantC, tenantD, tenantE := r.personal("alice"), r.personal("bob"), r.personal("carol"), r.personal("dave"), r.personal("eve")
	alice, bob, carol, dave, eve := r.userToken("alice", tenantA), r.userToken("bob", tenantB), r.userToken("carol", tenantC), r.userToken("dave", tenantD), r.userToken("eve", tenantE)
	team := func(bearer string) map[string]any {
		t.Helper()
		code, body := r.send(http.MethodGet, "/api/v1/team", bearer, "")
		if code != http.StatusOK {
			t.Fatalf("GET /team: %d %s", code, body)
		}
		return r.decode("team.json", body)
	}
	invite := func(bearer, body string) string {
		t.Helper()
		code, raw := r.send(http.MethodPost, "/api/v1/team/invites", bearer, body)
		if code != http.StatusOK {
			t.Fatalf("POST /team/invites %s: %d %s", body, code, raw)
		}
		out := r.decode("team_invite.json", raw)
		if out["sent"] != false || out["status"] != "invited" || !strings.HasPrefix(out["invite_link"].(string), inviteBase) {
			t.Fatalf("invite: %v", out)
		}
		return out["invite_link"].(string)
	}
	accept := func(bearer, token string) map[string]any {
		t.Helper()
		code, raw := r.send(http.MethodPost, "/api/v1/team/invites/accept", bearer, `{"token":"`+token+`"}`)
		if code != http.StatusOK {
			t.Fatalf("accept: %d %s", code, raw)
		}
		return r.decode("team_accept.json", raw)
	}

	// A solo owner: the owner row appears on first read, carrying the token email; ids are /me's.
	solo := team(alice)
	if strings.Join(memberIDs(solo), ",") != "alice" || solo["you"].(map[string]any)["role"] != "owner" || solo["members"].([]any)[0].(map[string]any)["email"] != "alice@it.example" {
		t.Fatalf("solo owner: %v", solo)
	}
	if tvo := solo["tvo"].(map[string]any); tvo["guarantee_grade"] != false || !strings.Contains(tvo["refusal"].(string), "M1E-5004") {
		t.Fatalf("tvo: %v", tvo)
	}

	for _, bad := range []string{`{"email":"nope"}`, `{"email":"a@b.example","extra":1}`} {
		if code, _ := r.send(http.MethodPost, "/api/v1/team/invites", alice, bad); code != http.StatusBadRequest {
			t.Fatalf("invite body %s: %d", bad, code)
		}
	}
	bobLink := invite(alice, `{"email":"BOB@it.example"}`)
	token := strings.TrimPrefix(bobLink, inviteBase)
	hash := sha256.Sum256([]byte(token))
	var stored uuid.UUID
	if err := r.admin.QueryRow(ctx, `SELECT tenant_id FROM m1_team_invites WHERE token_hash = $1`, hash[:]).Scan(&stored); err != nil || stored != tenantA {
		t.Fatalf("hash row: %s %v", stored, err)
	}

	// Every accept refusal, none of which consumes the invite or names A.
	r.refusedTeam(http.MethodPost, "/api/v1/team/invites/accept", carol, `{"token":"`+bobLink+`"}`, http.StatusForbidden, "invite_email_mismatch")
	r.refusedTeam(http.MethodPost, "/api/v1/team/invites/accept", alice, `{"token":"`+token+`"}`, http.StatusConflict, "own_team")
	r.refusedTeam(http.MethodPost, "/api/v1/team/invites/accept", carol, `{"token":"`+strings.Repeat("A", 43)+`"}`, http.StatusNotFound, "invite_invalid")
	if code, _ := r.send(http.MethodPost, "/api/v1/team/invites/accept", carol, `{"token":""}`); code != http.StatusBadRequest {
		t.Fatalf("empty token: %d", code)
	}

	// Accept (email case-insensitive, the whole link): bob now reads A.
	if got := accept(bob, bobLink); got["tenant_id"] != tenantA.String() || got["role"] != "member" {
		t.Fatalf("accept: %v", got)
	}
	var acceptedBy string
	if err := r.admin.QueryRow(ctx, `SELECT accepted_by FROM m1_team_invites WHERE token_hash = $1 AND accepted_at IS NOT NULL`, hash[:]).Scan(&acceptedBy); err != nil || acceptedBy != "omium:bob" {
		t.Fatalf("accepted_by: %q %v", acceptedBy, err)
	}
	r.refusedTeam(http.MethodPost, "/api/v1/team/invites/accept", carol, `{"token":"`+token+`"}`, http.StatusNotFound, "invite_invalid")
	code, body := r.send(http.MethodGet, "/api/v1/me", bob, "")
	if code != http.StatusOK || meTenant(body) != tenantA.String() {
		t.Fatalf("bob's /me after accept: %d %s", code, body)
	}
	bobDevice := r.approvedEnrollment(tenantA, "omium:bob", time.Now().UTC().Add(-time.Hour))
	r.approvedEnrollment(tenantA, "omium:bob", time.Now().UTC().Add(-2*time.Hour))
	bobsView := team(bob)
	if strings.Join(memberIDs(bobsView), ",") != "alice,bob" || bobsView["you"].(map[string]any)["role"] != "member" {
		t.Fatalf("bob's view: %v", bobsView)
	}
	if m := bobsView["members"].([]any)[1].(map[string]any); m["email"] != "bob@it.example" || m["last_active"] == nil || m["role"] != "member" {
		t.Fatalf("bob's row: %v", m)
	}
	r.refusedTeam(http.MethodPost, "/api/v1/team/invites", bob, `{}`, http.StatusForbidden, "not_owner")
	// Tenant-wide settings are the owner's: a member cannot share the team's memory or send teammates' evidence to the cloud judge.
	r.refusedTeam(http.MethodPut, "/api/v1/team", bob, `{"shared_memory":true}`, http.StatusForbidden, "not_owner")
	r.refusedTeam(http.MethodPut, "/api/v1/verify/cloud-judge", bob, `{"enabled":true}`, http.StatusForbidden, "not_owner")
	if code, body := r.send(http.MethodPut, "/api/v1/team", alice, `{"shared_memory":true}`); code != http.StatusOK {
		t.Fatalf("the owner flips shared memory: %d %s", code, body)
	}

	// One active membership: eve's invite cannot take bob while he is in A (the DB's partial unique index).
	eveLink := invite(eve, ``)
	r.refusedTeam(http.MethodPost, "/api/v1/team/invites/accept", bob, `{"token":"`+eveLink+`"}`, http.StatusConflict, "already_in_team")
	// An owner whose team has members cannot strand it by joining another team.
	r.refusedTeam(http.MethodPost, "/api/v1/team/invites/accept", alice, `{"token":"`+eveLink+`"}`, http.StatusConflict, "owner_of_team")

	// The cap (3 = owner + bob + one live invite).
	open := invite(alice, ``)
	r.refusedTeam(http.MethodPost, "/api/v1/team/invites", alice, ``, http.StatusConflict, "team_full")
	accept(dave, open)
	r.refusedTeam(http.MethodPost, "/api/v1/team/invites/accept", dave, `{"token":"`+eveLink+`"}`, http.StatusConflict, "already_in_team")

	// Leave: the owner cannot, a member's answer is their own token tenant, and a second leave is from their personal tenant.
	r.refusedTeam(http.MethodPost, "/api/v1/team/leave", alice, ``, http.StatusConflict, "owner_cannot_leave")
	code, body = r.send(http.MethodPost, "/api/v1/team/leave", dave, "")
	if code != http.StatusOK || r.decode("team_leave.json", body)["tenant_id"] != tenantD.String() {
		t.Fatalf("leave: %d %s", code, body)
	}
	r.refusedTeam(http.MethodPost, "/api/v1/team/leave", dave, ``, http.StatusConflict, "owner_cannot_leave")
	r.refusedTeam(http.MethodPost, "/api/v1/team/leave", carol, ``, http.StatusConflict, "owner_cannot_leave")

	// The cap is re-checked at accept under the row lock: an invite minted under 3 cannot land under 2.
	again := invite(alice, ``)
	r.api = r.teamAPI(2)
	r.refusedTeam(http.MethodPost, "/api/v1/team/invites/accept", dave, `{"token":"`+again+`"}`, http.StatusConflict, "team_full")
	r.api = r.teamAPI(3)

	// Rejoin reuses the primary key.
	accept(dave, again)
	var rows int64
	var left *time.Time
	if err := r.admin.QueryRow(ctx, `SELECT count(*), max(left_at) FROM m1_team_members WHERE tenant_id = $1 AND subject = 'omium:dave'`, tenantA).Scan(&rows, &left); err != nil || rows != 1 || left != nil {
		t.Fatalf("rejoin: rows=%d left=%v %v", rows, left, err)
	}

	// Remove: owner only, never the owner, 404 for strangers; the member's team devices are revoked and their reads fall back to their own tenant.
	r.refusedTeam(http.MethodDelete, "/api/v1/team/members/alice", dave, ``, http.StatusForbidden, "not_owner")
	r.refusedTeam(http.MethodDelete, "/api/v1/team/members/alice", alice, ``, http.StatusConflict, "owner_cannot_leave")
	r.refusedTeam(http.MethodDelete, "/api/v1/team/members/mallory", alice, ``, http.StatusNotFound, "member_not_found")
	code, body = r.send(http.MethodDelete, "/api/v1/team/members/bob", alice, "")
	if code != http.StatusOK || r.decode("team_member_remove.json", body)["revoked_devices"] != float64(2) {
		t.Fatalf("remove bob: %d %s", code, body)
	}
	var revoked int64
	if err := r.admin.QueryRow(ctx, `SELECT count(*) FROM m1_devices d JOIN m1_device_enrollments e ON e.device_id = d.id WHERE d.tenant_id = $1 AND e.oidc_subject = 'omium:bob' AND d.revoked_at IS NOT NULL AND d.revoked_by = 'omium:alice' AND e.status = 'revoked'`, tenantA).Scan(&revoked); err != nil || revoked != 2 {
		t.Fatalf("bob's devices revoked: %d %v (device %s)", revoked, err, bobDevice)
	}
	if code, body = r.send(http.MethodDelete, "/api/v1/team/members/bob", alice, ""); code != http.StatusOK || r.decode("team_member_remove.json", body)["revoked_devices"] != float64(0) {
		t.Fatalf("remove is idempotent: %d %s", code, body)
	}
	if code, body = r.send(http.MethodGet, "/api/v1/me", bob, ""); meTenant(body) != tenantB.String() {
		t.Fatalf("bob's /me after removal: %d %s", code, body)
	}
	final := team(alice)
	if strings.Join(memberIDs(final), ",") != "alice,dave" {
		t.Fatalf("A after remove: %v", memberIDs(final))
	}

	// E sees none of A's rows; a tampered token is a 401.
	raw, _ := json.Marshal(team(eve))
	if strings.Contains(string(raw), "alice") || strings.Contains(string(raw), "dave") {
		t.Fatalf("E saw A: %s", raw)
	}
	if code, _ := r.send(http.MethodGet, "/api/v1/team", alice+"x", ""); code != http.StatusUnauthorized {
		t.Fatalf("tampered token: %d", code)
	}

	// shared_memory: a tenant flips only its own row.
	code, body = r.send(http.MethodPut, "/api/v1/team", alice, `{"shared_memory":true}`)
	if code != http.StatusOK || r.decode("team_update.json", body)["shared_memory"] != true || team(eve)["shared_memory"] != false || team(dave)["shared_memory"] != true {
		t.Fatalf("PUT /team: %d %s", code, body)
	}
}

// m1_090's grants and backfill: the app roles can read what 15-teams says they read and nothing wider; memory_artifacts.owner_subject resolves through the provenance device's enrollment, else the tenant owner; the file re-runs clean.
func TestIntegrationTeamsMigration(t *testing.T) {
	r := setupPG(t)
	ctx := context.Background()
	tenant := r.personal("olga")
	device := r.approvedEnrollment(tenant, "omium:pat", time.Now().UTC())
	var owned, orphan uuid.UUID
	insert := `INSERT INTO memory_artifacts (tenant_id, abstraction, kind, body) VALUES ($1, 'instance', 'pitfall', $2) RETURNING id`
	if err := r.admin.QueryRow(ctx, insert, tenant, `{"provenance":{"device_id":"`+device.String()+`"}}`).Scan(&owned); err != nil {
		t.Fatal(err)
	}
	if err := r.admin.QueryRow(ctx, insert, tenant, `{"provenance":{"device_id":"`+uuid.NewString()+`"}}`).Scan(&orphan); err != nil {
		t.Fatal(err)
	}
	sql, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "migrations", "m1_090_teams.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.admin.Exec(ctx, string(sql)); err != nil {
		t.Fatalf("m1_090 re-run: %v", err)
	}
	for id, want := range map[uuid.UUID]string{owned: "omium:pat", orphan: "omium:olga"} {
		var got string
		if err := r.admin.QueryRow(ctx, `SELECT owner_subject FROM memory_artifacts WHERE id = $1`, id).Scan(&got); err != nil || got != want {
			t.Fatalf("owner_subject %s: %q %v, want %q", id, got, err, want)
		}
	}
	for q, want := range map[string]bool{
		`has_table_privilege('intel_app', 'm1_team_members', 'SELECT')`:                        true,
		`has_table_privilege('intel_app', 'm1_device_consents', 'SELECT')`:                     true,
		`has_table_privilege('intel_app', 'm1_tenants', 'SELECT')`:                             true,
		`has_table_privilege('intel_app', 'memory_artifacts', 'UPDATE')`:                       true,
		`has_column_privilege('intel_app', 'm1_device_enrollments', 'oidc_subject', 'SELECT')`: true,
		`has_column_privilege('intel_app', 'm1_device_enrollments', 'device_id', 'SELECT')`:    true,
		`has_column_privilege('intel_app', 'm1_device_enrollments', 'status', 'SELECT')`:       true,
		`has_column_privilege('intel_app', 'm1_device_enrollments', 'started_at', 'SELECT')`:   true,
		`has_column_privilege('intel_app', 'm1_device_enrollments', 'token_hash', 'SELECT')`:   false,
		`has_table_privilege('intel_app', 'm1_team_members', 'INSERT')`:                        false,
		`has_function_privilege('intel_app', 'm1_team_invite_lookup(bytea)', 'EXECUTE')`:       false,
		`has_table_privilege('controld_app', 'm1_team_members', 'UPDATE')`:                     true,
		`has_column_privilege('controld_app', 'm1_team_invites', 'accepted_by', 'UPDATE')`:     true,
		`has_function_privilege('controld_app', 'm1_team_effective_tenant(text)', 'EXECUTE')`:  true,
	} {
		var got bool
		if err := r.admin.QueryRow(ctx, `SELECT `+q).Scan(&got); err != nil || got != want {
			t.Errorf("%s = %v (%v), want %v", q, got, err, want)
		}
	}
}
