//go:build integration

package appapi

// The cloud-judge consent route under FORCE RLS (m1_065): GET discloses the static judge with enabled=false absent a live row, PUT enabled=true inserts one and is idempotent under the partial unique index, PUT enabled=false revokes it (never deletes), and tenant B never sees A's row.

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
)

func TestCloudJudgeConsentUnderRLS(t *testing.T) {
	r := setupPG(t)
	tenantA, tenantB := r.tenant("cloud-judge-a", "us-east-1"), r.tenant("cloud-judge-b", "us-east-1")
	deviceA := uuid.New()
	tokA := auth.Mint([]byte(testKey), tenantA, deviceA, time.Hour)
	tokB := auth.Mint([]byte(testKey), tenantB, uuid.New(), time.Hour)

	code, out := r.send(http.MethodGet, "/api/v1/verify/cloud-judge", tokA, "")
	if code != http.StatusOK {
		t.Fatalf("GET before consent: %d %s", code, out)
	}
	p := r.decode("cloud_judge.json", out)
	if p["enabled"] != false || p["judge_id"] != "judge:grounded-rubric@1" || p["subprocessor"] != "anthropic" ||
		p["region"] != "us" || p["max_tier"] != "E1" || p["consented_at"] != nil || p["consented_by"] != nil {
		t.Fatalf("disclosure absent consent: %s", out)
	}

	code, out = r.send(http.MethodPut, "/api/v1/verify/cloud-judge", tokA, `{"enabled":true}`)
	if code != http.StatusOK {
		t.Fatalf("PUT enable: %d %s", code, out)
	}
	p = r.decode("cloud_judge.json", out)
	if p["enabled"] != true || p["consented_by"] != "device:"+deviceA.String() || p["consented_at"] == nil {
		t.Fatalf("enabled row: %s", out)
	}
	firstAt := p["consented_at"]

	// Idempotent: a second enable leaves the original row untouched, never a second consent.
	code, out = r.send(http.MethodPut, "/api/v1/verify/cloud-judge", tokA, `{"enabled":true}`)
	if code != http.StatusOK {
		t.Fatalf("PUT enable again: %d %s", code, out)
	}
	if p2 := r.decode("cloud_judge.json", out); p2["consented_at"] != firstAt {
		t.Fatalf("re-enable minted a second row: first=%v second=%v", firstAt, p2["consented_at"])
	}
	var n int
	if err := r.admin.QueryRow(context.Background(), `SELECT count(*) FROM m1_cloud_judge_consents WHERE tenant_id = $1`, tenantA).Scan(&n); err != nil || n != 1 {
		t.Fatalf("exactly one row after two enables: n=%d err=%v", n, err)
	}

	// GET reflects the live row too.
	code, out = r.send(http.MethodGet, "/api/v1/verify/cloud-judge", tokA, "")
	if code != http.StatusOK || r.decode("cloud_judge.json", out)["enabled"] != true {
		t.Fatalf("GET after enable: %d %s", code, out)
	}

	// Disable: revokes, never deletes.
	code, out = r.send(http.MethodPut, "/api/v1/verify/cloud-judge", tokA, `{"enabled":false}`)
	if code != http.StatusOK {
		t.Fatalf("PUT disable: %d %s", code, out)
	}
	p = r.decode("cloud_judge.json", out)
	if p["enabled"] != false || p["consented_at"] != nil || p["consented_by"] != nil {
		t.Fatalf("disabled row: %s", out)
	}
	var revoked time.Time
	var reason string
	if err := r.admin.QueryRow(context.Background(), `SELECT revoked_at, revoked_reason FROM m1_cloud_judge_consents WHERE tenant_id = $1`, tenantA).Scan(&revoked, &reason); err != nil || revoked.IsZero() || reason != "settings" {
		t.Fatalf("revocation row: revoked=%v reason=%s err=%v", revoked, reason, err)
	}

	// Tenant B: never sees A's row.
	code, out = r.send(http.MethodGet, "/api/v1/verify/cloud-judge", tokB, "")
	if code != http.StatusOK {
		t.Fatalf("GET B: %d %s", code, out)
	}
	if p = r.decode("cloud_judge.json", out); p["enabled"] != false || p["consented_by"] != nil {
		t.Fatalf("B must not see A's consent: %s", out)
	}

	// Bad bodies refused, nothing written.
	for _, bad := range []string{``, `{}`, `{"enabled":"yes"}`, `{"enabled":true,"x":1}`} {
		if code, _ := r.send(http.MethodPut, "/api/v1/verify/cloud-judge", tokA, bad); code != http.StatusBadRequest {
			t.Fatalf("bad body %q: %d", bad, code)
		}
	}
}
