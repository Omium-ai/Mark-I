//go:build integration

package appapi

// querychoke.PGViewers under FORCE RLS on the real migration tree (m1_090 included), as the NOBYPASSRLS controld_app role: a tenant is a team only while it has an active member, a person's devices are every device their subject enrolled (revoked ones kept), a device token reads as its enrollment's subject, and nothing crosses tenants.

import (
	"context"
	"crypto/rand"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
)

func (r *pgRig) enrollDevice(tenant uuid.UUID, subject any, status string) uuid.UUID {
	r.t.Helper()
	host, code, tok, pub := make([]byte, 32), make([]byte, 32), make([]byte, 32), make([]byte, 32)
	for _, b := range [][]byte{host, code, tok, pub} {
		_, _ = rand.Read(b)
	}
	var device uuid.UUID
	ctx := context.Background()
	if err := r.admin.QueryRow(ctx, `INSERT INTO m1_devices (tenant_id, platform, hostname_hmac) VALUES ($1, 'linux', $2) RETURNING id`, tenant, host).Scan(&device); err != nil {
		r.t.Fatal(err)
	}
	at := time.Now().UTC()
	if _, err := r.admin.Exec(ctx, `INSERT INTO m1_device_enrollments (tenant_id, device_id, device_code_hash, token_hash, device_pubkey, oidc_subject, status, started_at, token_expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		tenant, device, code, tok, pub, subject, status, at, at.Add(time.Hour)); err != nil {
		r.t.Fatal(err)
	}
	return device
}

func sameDevices(got []uuid.UUID, want ...uuid.UUID) bool {
	w := slices.Clone(want)
	slices.SortFunc(w, func(a, b uuid.UUID) int { return slices.Compare(a[:], b[:]) })
	return slices.Equal(got, w)
}

func TestIntegrationViewersUnderRLS(t *testing.T) {
	r := setupPG(t)
	ctx := context.Background()
	tenantA, tenantB := r.tenant("Acme", "eu-west-1"), r.tenant("Globex", "us-east-1")
	aliceDev := r.enrollDevice(tenantA, "omium:alice", "approved")
	bobDev, bobOld := r.enrollDevice(tenantA, "omium:bob", "approved"), r.enrollDevice(tenantA, "omium:bob", "revoked")
	r.enrollDevice(tenantA, "omium:bob", "pending")
	anon := r.enrollDevice(tenantA, nil, "revoked") // approved rows always name a subject (ck_m1_enroll_approved_shape)
	bobElsewhere := r.enrollDevice(tenantB, "omium:bob", "approved")
	user := func(sub string) auth.Claims { return auth.Claims{TenantID: tenantA, Subject: sub} }
	device := func(d uuid.UUID) auth.Claims { return auth.Claims{TenantID: tenantA, DeviceID: d} }

	v, err := querychoke.NewPGViewers(r.db).Viewer(ctx, r.tid(tenantA), user("alice"))
	if err != nil || v.Team || v.Subject != "omium:alice" || !sameDevices(v.Devices, aliceDev) {
		t.Fatalf("solo tenant: %+v %v", v, err)
	}
	if _, err := r.admin.Exec(ctx, `INSERT INTO m1_team_members (tenant_id, subject, role) VALUES ($1, 'omium:alice', 'owner'), ($1, 'omium:bob', 'member')`, tenantA); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		claims  auth.Claims
		subject string
		devices []uuid.UUID
	}{
		"member user token":        {user("bob"), "omium:bob", []uuid.UUID{bobDev, bobOld}},
		"member device token":      {device(bobDev), "omium:bob", []uuid.UUID{bobDev, bobOld}},
		"owner in a team":          {user("alice"), "omium:alice", []uuid.UUID{aliceDev}},
		"subject-less device":      {device(anon), "", []uuid.UUID{anon}},
		"person with no device":    {user("dave"), "omium:dave", nil},
		"other tenant's device id": {device(bobElsewhere), "", []uuid.UUID{bobElsewhere}},
	} {
		v, err := querychoke.NewPGViewers(r.db).Viewer(ctx, r.tid(tenantA), c.claims)
		if err != nil || !v.Team || v.Subject != c.subject || !sameDevices(v.Devices, c.devices...) {
			t.Fatalf("%s: %+v %v", name, v, err)
		}
	}
	v, err = querychoke.NewPGViewers(r.db).Viewer(ctx, r.tid(tenantB), auth.Claims{TenantID: tenantB, Subject: "bob"})
	if err != nil || v.Team || !sameDevices(v.Devices, bobElsewhere) {
		t.Fatalf("tenant B sees only its own enrollments and no team: %+v %v", v, err)
	}
	if _, err := r.admin.Exec(ctx, `UPDATE m1_team_members SET left_at = now() WHERE tenant_id = $1 AND subject = 'omium:bob'`, tenantA); err != nil {
		t.Fatal(err)
	}
	// 15-teams: once a tenant has had a member it stays per-person, so a leaver's last token never reads tenant-wide
	if v, err := querychoke.NewPGViewers(r.db).Viewer(ctx, r.tid(tenantA), user("alice")); err != nil || !v.Team {
		t.Fatalf("a tenant whose last member left stays a team: %+v %v", v, err)
	}
}
