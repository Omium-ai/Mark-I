//go:build integration

package appapi

// The three register routes under FORCE RLS (m1_065, m1_073, m1_092): GET discloses the static key with enabled=false absent a live row, PUT enabled=true inserts one and is idempotent under the partial unique index, PUT enabled=false revokes it (never deletes), tenant B never sees A's row, and neither route touches the other's key.

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
)

func TestCloudJudgeConsentUnderRLS(t *testing.T) {
	testConsentRoute(t, "/api/v1/verify/cloud-judge", "cloud_judge.json", cloudJudgeConsent)
}

func TestMemoryExtractConsentUnderRLS(t *testing.T) {
	testConsentRoute(t, "/api/v1/memory/extract-consent", "memory_extract_consent.json", memoryExtractConsent)
}

func TestCloudRMConsentUnderRLS(t *testing.T) {
	testConsentRoute(t, "/api/v1/verify/cloud-rm", "cloud_rm.json", cloudRMConsent)
}

func testConsentRoute(t *testing.T, route, schema string, k consentKey) {
	key := k.id
	r := setupPG(t)
	tenantA, tenantB := r.tenant("consent-a", "us-east-1"), r.tenant("consent-b", "us-east-1")
	deviceA := uuid.New()
	tokA := auth.Mint([]byte(testKey), tenantA, deviceA, time.Hour)
	tokB := auth.Mint([]byte(testKey), tenantB, uuid.New(), time.Hour)

	code, out := r.send(http.MethodGet, route, tokA, "")
	if code != http.StatusOK {
		t.Fatalf("GET before consent: %d %s", code, out)
	}
	p := r.decode(schema, out)
	if p["enabled"] != false || p["judge_id"] != key || p["subprocessor"] != k.subprocessor ||
		p["region"] != k.region || p["max_tier"] != k.maxTier || p["consented_at"] != nil || p["consented_by"] != nil {
		t.Fatalf("disclosure absent consent: %s", out)
	}

	// An app whose copy names another key (v0.1.14 sends a bare {enabled:true} under "Anthropic, US") never enables this one.
	for _, stale := range []string{`{"enabled":true}`, `{"enabled":true,"judge_id":"judge:grounded-rubric@1"}`, `{"enabled":true,"judge_id":""}`} {
		r.refusedTeam(http.MethodPut, route, tokA, stale, http.StatusConflict, "consent_copy_outdated")
	}
	if n := r.adminCount("m1_cloud_judge_consents"); n != 0 {
		t.Fatalf("a refused enable wrote %d consent rows", n)
	}
	enable := `{"enabled":true,"judge_id":"` + key + `"}`
	code, out = r.send(http.MethodPut, route, tokA, enable)
	if code != http.StatusOK {
		t.Fatalf("PUT enable: %d %s", code, out)
	}
	p = r.decode(schema, out)
	if p["enabled"] != true || p["consented_by"] != "device:"+deviceA.String() || p["consented_at"] == nil {
		t.Fatalf("enabled row: %s", out)
	}
	firstAt := p["consented_at"]

	// Idempotent: a second enable leaves the original row untouched, never a second consent.
	code, out = r.send(http.MethodPut, route, tokA, enable)
	if code != http.StatusOK {
		t.Fatalf("PUT enable again: %d %s", code, out)
	}
	if p2 := r.decode(schema, out); p2["consented_at"] != firstAt {
		t.Fatalf("re-enable minted a second row: first=%v second=%v", firstAt, p2["consented_at"])
	}
	var n int
	if err := r.admin.QueryRow(context.Background(), `SELECT count(*) FROM m1_cloud_judge_consents WHERE tenant_id = $1`, tenantA).Scan(&n); err != nil || n != 1 {
		t.Fatalf("exactly one row after two enables: n=%d err=%v", n, err)
	}

	// GET reflects the live row too.
	code, out = r.send(http.MethodGet, route, tokA, "")
	if code != http.StatusOK || r.decode(schema, out)["enabled"] != true {
		t.Fatalf("GET after enable: %d %s", code, out)
	}

	// Disable: revokes, never deletes; an old app's bare body turns it off.
	code, out = r.send(http.MethodPut, route, tokA, `{"enabled":false}`)
	if code != http.StatusOK {
		t.Fatalf("PUT disable: %d %s", code, out)
	}
	p = r.decode(schema, out)
	if p["enabled"] != false || p["consented_at"] != nil || p["consented_by"] != nil {
		t.Fatalf("disabled row: %s", out)
	}
	var revoked time.Time
	var reason string
	if err := r.admin.QueryRow(context.Background(), `SELECT revoked_at, revoked_reason FROM m1_cloud_judge_consents WHERE tenant_id = $1 AND judge_id = $2`, tenantA, key).Scan(&revoked, &reason); err != nil || revoked.IsZero() || reason != "settings" {
		t.Fatalf("revocation row: revoked=%v reason=%s err=%v", revoked, reason, err)
	}

	// Tenant B: never sees A's row.
	code, out = r.send(http.MethodGet, route, tokB, "")
	if code != http.StatusOK {
		t.Fatalf("GET B: %d %s", code, out)
	}
	if p = r.decode(schema, out); p["enabled"] != false || p["consented_by"] != nil {
		t.Fatalf("B must not see A's consent: %s", out)
	}

	// Bad bodies refused, nothing written.
	for _, bad := range []string{``, `{}`, `{"enabled":"yes"}`, `{"enabled":true,"x":1}`} {
		if code, _ := r.send(http.MethodPut, route, tokA, bad); code != http.StatusBadRequest {
			t.Fatalf("bad body %q: %d", bad, code)
		}
	}
	var other int
	if err := r.admin.QueryRow(context.Background(), `SELECT count(*) FROM m1_cloud_judge_consents WHERE tenant_id = $1 AND judge_id <> $2`, tenantA, key).Scan(&other); err != nil || other != 0 {
		t.Fatalf("the route wrote another register key: n=%d err=%v", other, err)
	}
}
