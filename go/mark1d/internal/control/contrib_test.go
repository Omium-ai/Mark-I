package control

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/consents"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/contrib"
)

func TestContributeOutcomesWithdrawalPurgesPendingUploads(t *testing.T) {
	s, dir := newServer(t)
	resp, body := call(t, s, http.MethodPut, "/v1/optins", map[string]any{"consents": map[string]bool{"contribute_outcomes": true}})
	want(t, resp, body, http.StatusOK, "")
	if !consents.Read(dir).ContributeOutcomes || !contrib.Decided(dir) {
		t.Fatalf("contribute_outcomes on: %s (decided %v)", body, contrib.Decided(dir))
	}
	if err := os.MkdirAll(contrib.Dir(dir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(contrib.Dir(dir), "task.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	resp, body = call(t, s, http.MethodPut, "/v1/optins", map[string]any{"consents": map[string]bool{"contribute_outcomes": false}})
	want(t, resp, body, http.StatusOK, "")
	if consents.Read(dir).ContributeOutcomes {
		t.Fatalf("withdrawal not recorded: %s", body)
	}
	if _, err := os.Stat(contrib.Dir(dir)); !os.IsNotExist(err) {
		t.Fatalf("withdrawal left pending contributions on disk: %v", err)
	}
}

func TestDogfoodDefaultAppliesOnceAndNeverOverridesTheChoice(t *testing.T) {
	s, dir := newServer(t)
	resp, body := call(t, s, http.MethodPost, "/v1/enroll/keygen", nil)
	want(t, resp, body, http.StatusOK, "")
	var kg struct {
		KeyID string `json:"key_id"`
	}
	decodeTo(t, body, &kg)

	customer := activeFor(tenantA, deviceA, kg.KeyID)
	resp, body = call(t, s, http.MethodPost, "/v1/enroll", customer)
	want(t, resp, body, http.StatusOK, "")
	if consents.Read(dir).ContributeOutcomes {
		t.Fatal("a body without the dogfood flag turned contribution on")
	}

	unmarked := activeFor(tenantA, deviceA, kg.KeyID)
	unmarked["contribute_outcomes_default"] = true
	resp, body = call(t, s, http.MethodPost, "/v1/enroll", unmarked)
	want(t, resp, body, http.StatusOK, "")
	if consents.Read(dir).ContributeOutcomes {
		t.Fatal("a default the enrollment does not mark as the staff default turned contribution on")
	}

	dogfood := activeFor(tenantA, deviceA, kg.KeyID)
	dogfood["contribute_outcomes_default"] = true
	dogfood["contribute_outcomes_default_reason"] = contrib.StaffDefaultReason
	resp, body = call(t, s, http.MethodPost, "/v1/enroll", dogfood)
	want(t, resp, body, http.StatusOK, "")
	if !consents.Read(dir).ContributeOutcomes {
		t.Fatal("dogfood tenant: contribute_outcomes should default on")
	}
	if contrib.Decided(dir) {
		t.Fatal("the staff default was recorded as the person's own choice")
	}

	resp, body = call(t, s, http.MethodPut, "/v1/optins", map[string]any{"consents": map[string]bool{"contribute_outcomes": false}})
	want(t, resp, body, http.StatusOK, "")
	resp, body = call(t, s, http.MethodPost, "/v1/enroll", dogfood)
	want(t, resp, body, http.StatusOK, "")
	if consents.Read(dir).ContributeOutcomes {
		t.Fatal("a re-enrollment's dogfood default overrode the person's withdrawal")
	}
}

// TestStaffDefaultNeverFollowsTheDeviceIntoAnotherTenant (M2): a staff default, and equally a choice made under the staff tenant, is off and undecided once the device enrolls elsewhere — directly, or after signing out — and nothing it queued survives.
func TestStaffDefaultNeverFollowsTheDeviceIntoAnotherTenant(t *testing.T) {
	for _, signOut := range []bool{false, true} {
		for _, chose := range []bool{false, true} {
			s, dir := newServer(t)
			resp, body := call(t, s, http.MethodPost, "/v1/enroll/keygen", nil)
			want(t, resp, body, http.StatusOK, "")
			var kg struct {
				KeyID string `json:"key_id"`
			}
			decodeTo(t, body, &kg)
			staff := activeFor(tenantA, deviceA, kg.KeyID)
			staff["contribute_outcomes_default"] = true
			staff["contribute_outcomes_default_reason"] = contrib.StaffDefaultReason
			resp, body = call(t, s, http.MethodPost, "/v1/enroll", staff)
			want(t, resp, body, http.StatusOK, "")
			if chose {
				for _, v := range []bool{false, true} {
					resp, body = call(t, s, http.MethodPut, "/v1/optins", map[string]any{"consents": map[string]bool{"contribute_outcomes": v}})
					want(t, resp, body, http.StatusOK, "")
				}
			}
			if !consents.Read(dir).ContributeOutcomes || contrib.Decided(dir) != chose {
				t.Fatalf("staff tenant: on=%v decided=%v", consents.Read(dir).ContributeOutcomes, contrib.Decided(dir))
			}
			if err := os.MkdirAll(contrib.Dir(dir), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(contrib.Dir(dir), "task.json"), []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
			if signOut {
				resp, body = call(t, s, http.MethodDelete, "/v1/enroll", nil)
				want(t, resp, body, http.StatusOK, "")
			}
			resp, body = call(t, s, http.MethodPost, "/v1/enroll", activeFor(tenantB, deviceB, kg.KeyID))
			want(t, resp, body, http.StatusOK, "")
			_, perr := os.Stat(contrib.Dir(dir))
			if consents.Read(dir).ContributeOutcomes || contrib.Decided(dir) || !os.IsNotExist(perr) || !consents.Pending(dir) {
				t.Fatalf("signOut=%v chose=%v: personal tenant inherited contribution: on=%v decided=%v pending uploads=%v relay pending=%v",
					signOut, chose, consents.Read(dir).ContributeOutcomes, contrib.Decided(dir), perr, consents.Pending(dir))
			}
		}
	}
}
