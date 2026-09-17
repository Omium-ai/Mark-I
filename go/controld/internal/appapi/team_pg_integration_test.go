//go:build integration

package appapi

// The team routes under FORCE RLS on the scratch migration tree (m1_081 included): members from the schema's principals, an invite minted once and listed as invited, the shared-memory flag, and tenant B seeing none of A's rows through any of the three.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
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
func (r *pgRig) approvedEnrollment(tenant uuid.UUID, approver string, at time.Time) {
	r.t.Helper()
	ctx := context.Background()
	host, code, tok, pub := make([]byte, 32), make([]byte, 32), make([]byte, 32), make([]byte, 32)
	for _, b := range [][]byte{host, code, tok, pub} {
		_, _ = rand.Read(b)
	}
	var device uuid.UUID
	if err := r.admin.QueryRow(ctx, `INSERT INTO m1_devices (tenant_id, platform, hostname_hmac) VALUES ($1, 'linux', $2) RETURNING id`, tenant, host).Scan(&device); err != nil {
		r.t.Fatal(err)
	}
	if _, err := r.admin.Exec(ctx, `INSERT INTO m1_device_enrollments (tenant_id, device_id, device_code_hash, token_hash, device_pubkey, oidc_subject, status, started_at, token_expires_at) VALUES ($1, $2, $3, $4, $5, $6, 'approved', $7, $8)`,
		tenant, device, code, tok, pub, approver, at, at.Add(time.Hour)); err != nil {
		r.t.Fatal(err)
	}
}

func memberIDs(team map[string]any) []string {
	var ids []string
	for _, m := range team["members"].([]any) {
		ids = append(ids, m.(map[string]any)["id"].(string))
	}
	return ids
}

func TestIntegrationTeamUnderRLS(t *testing.T) {
	r := setupPG(t)
	ctx := context.Background()
	tenantA, tenantB := r.tenant("Acme", "eu-west-1"), r.tenant("Globex", "us-east-1")
	if _, err := r.admin.Exec(ctx, `UPDATE m1_tenants SET owner_subject = 'omium:alice' WHERE id = $1`, tenantA); err != nil {
		t.Fatal(err)
	}
	early := time.Now().UTC().Add(-48 * time.Hour)
	r.approvedEnrollment(tenantA, "omium:bob", early)
	r.approvedEnrollment(tenantA, "omium:bob", early.Add(time.Hour))
	r.approvedEnrollment(tenantA, "omium:carol", early.Add(2*time.Hour))
	r.approvedEnrollment(tenantB, "omium:mallory", early)
	alice, dave, eve := r.userToken("omium:alice", tenantA), r.userToken("omium:dave", tenantA), r.userToken("omium:eve", tenantB)

	code, body := r.send(http.MethodGet, "/api/v1/team", alice, "")
	if code != http.StatusOK {
		t.Fatalf("GET /team: %d %s", code, body)
	}
	team := r.decode("team.json", body)
	if got := strings.Join(memberIDs(team), ","); got != "omium:alice,omium:bob,omium:carol" {
		t.Fatalf("members: %s", got)
	}
	members := team["members"].([]any)
	if members[0].(map[string]any)["role"] != "owner" || members[1].(map[string]any)["role"] != "member" {
		t.Fatalf("roles: %v", members)
	}
	if joined := members[1].(map[string]any)["joined_at"].(string); !strings.HasPrefix(joined, early.Format("2006-01-02T15:04")) {
		t.Fatalf("bob joined at his first approval, got %s", joined)
	}
	if team["shared_memory"] != false || team["invite_link"] != nil || team["fleet_status"] != nil {
		t.Fatalf("flags: %v", team)
	}
	// The team TVO is the tenant's own 30d report summary: with no rollup rows it still answers, refusals stated (06 §8.5), never a fabricated number.
	if tvo := team["tvo"].(map[string]any); tvo["guarantee_grade"] != false || !strings.Contains(tvo["refusal"].(string), "M1E-5004") {
		t.Fatalf("tvo: %v", tvo)
	}
	// A caller the schema has no row for is still a principal of its tenant: listed, never invented for another tenant.
	code, body = r.send(http.MethodGet, "/api/v1/team", dave, "")
	if code != http.StatusOK || strings.Join(memberIDs(r.decode("team.json", body)), ",") != "omium:alice,omium:bob,omium:carol,omium:dave" {
		t.Fatalf("dave's view: %d %s", code, body)
	}
	code, body = r.send(http.MethodGet, "/api/v1/team", eve, "")
	if code != http.StatusOK || strings.Join(memberIDs(r.decode("team.json", body)), ",") != "omium:mallory,omium:eve" {
		t.Fatalf("B's view carried A: %d %s", code, body)
	}

	// Invite: minted once, hash stored under A, listed as invited for A only.
	for _, bad := range []string{`{"email":"nope"}`, `{"email":"a@b.example","extra":1}`, `{"email":"` + strings.Repeat("a", 250) + `@b.example"}`} {
		if code, _ := r.send(http.MethodPost, "/api/v1/team/invites", alice, bad); code != http.StatusBadRequest {
			t.Fatalf("invite body %s: %d", bad, code)
		}
	}
	if n := r.adminCount("m1_team_invites"); n != 0 {
		t.Fatalf("refused bodies minted %d invites", n)
	}
	code, body = r.send(http.MethodPost, "/api/v1/team/invites", alice, `{"email":"teammate@example.com"}`)
	if code != http.StatusOK {
		t.Fatalf("POST /team/invites: %d %s", code, body)
	}
	invite := r.decode("team_invite.json", body)
	link := invite["invite_link"].(string)
	if !strings.HasPrefix(link, inviteBase+tenantA.String()+"/") || invite["invited_email"] != "teammate@example.com" {
		t.Fatalf("invite: %v", invite)
	}
	token := strings.TrimPrefix(link, inviteBase+tenantA.String()+"/")
	hash := sha256.Sum256([]byte(token))
	var storedTenant uuid.UUID
	var by string
	var expires time.Time
	if err := r.admin.QueryRow(ctx, `SELECT tenant_id, invited_by, expires_at FROM m1_team_invites WHERE token_hash = $1`, hash[:]).Scan(&storedTenant, &by, &expires); err != nil {
		t.Fatalf("hash row: %v", err)
	}
	if storedTenant != tenantA || by != "omium:alice" || expires.Before(time.Now().Add(6*24*time.Hour)) {
		t.Fatalf("stored invite: %s %s %s", storedTenant, by, expires)
	}
	if n := r.adminCount("m1_team_invites WHERE position($$" + token + "$$ IN encode(token_hash, 'escape')) > 0"); n != 0 {
		t.Fatal("raw token stored")
	}
	if code, _ := r.send(http.MethodPost, "/api/v1/team/invites", alice, ""); code != http.StatusOK {
		t.Fatalf("invite without email: %d", code)
	}
	_, body = r.send(http.MethodGet, "/api/v1/team", alice, "")
	team = r.decode("team.json", body)
	invited := 0
	for _, m := range team["members"].([]any) {
		if mm := m.(map[string]any); mm["status"] == "invited" {
			invited++
			if mm["email"] != nil && mm["email"] != "teammate@example.com" {
				t.Fatalf("invite row: %v", mm)
			}
		}
	}
	if invited != 2 || len(team["members"].([]any)) != 5 {
		t.Fatalf("invites listed: %v", team)
	}
	if _, err := r.admin.Exec(ctx, `UPDATE m1_team_invites SET expires_at = now() - interval '1 second' WHERE token_hash = $1`, hash[:]); err != nil {
		t.Fatal(err)
	}
	_, body = r.send(http.MethodGet, "/api/v1/team", alice, "")
	if len(r.decode("team.json", body)["members"].([]any)) != 4 {
		t.Fatalf("expired invite still listed: %s", body)
	}
	_, body = r.send(http.MethodGet, "/api/v1/team", eve, "")
	if strings.Contains(string(body), "invite:") || strings.Contains(string(body), "teammate") {
		t.Fatalf("B saw A's invites: %s", body)
	}

	// shared_memory: a tenant flips only its own row.
	for _, bad := range []string{``, `{}`, `{"shared_memory":"yes"}`, `{"shared_memory":true,"x":1}`} {
		if code, _ := r.send(http.MethodPut, "/api/v1/team", alice, bad); code != http.StatusBadRequest {
			t.Fatalf("PUT body %q: %d", bad, code)
		}
	}
	code, body = r.send(http.MethodPut, "/api/v1/team", alice, `{"shared_memory":true}`)
	if code != http.StatusOK || r.decode("team_update.json", body)["shared_memory"] != true {
		t.Fatalf("PUT /team: %d %s", code, body)
	}
	var sharedA, sharedB bool
	if err := r.admin.QueryRow(ctx, `SELECT a.shared_memory, b.shared_memory FROM m1_tenants a, m1_tenants b WHERE a.id = $1 AND b.id = $2`, tenantA, tenantB).Scan(&sharedA, &sharedB); err != nil {
		t.Fatal(err)
	}
	if !sharedA || sharedB {
		t.Fatalf("shared_memory A=%v B=%v", sharedA, sharedB)
	}
	_, body = r.send(http.MethodGet, "/api/v1/team", alice, "")
	if r.decode("team.json", body)["shared_memory"] != true {
		t.Fatalf("GET after PUT: %s", body)
	}
	if _, body = r.send(http.MethodGet, "/api/v1/team", eve, ""); r.decode("team.json", body)["shared_memory"] != false {
		t.Fatalf("B's flag moved: %s", body)
	}
	if code, _ := r.send(http.MethodGet, "/api/v1/team", alice+"x", ""); code != http.StatusUnauthorized {
		t.Fatalf("tampered token: %d", code)
	}
}
