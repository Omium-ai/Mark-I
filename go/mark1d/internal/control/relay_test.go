package control

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/consents"
)

// TestConsentsRelayToControldUnderTheDeviceToken: PUT /v1/optins{consents}
// writes the local record first (the truth) and relays the whole triple to
// controld's PUT /api/v1/consents under the enrollment's device token; before
// enrollment nothing is sent and the record stays pending; a controld outage
// leaves a revocation pending until the loop's next attempt lands it.
func TestConsentsRelayToControldUnderTheDeviceToken(t *testing.T) {
	s, dir := newServer(t)
	var mu sync.Mutex
	var got []map[string]any
	var bearer []string
	down := false
	controld := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if down {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		if r.Method != http.MethodPut || r.URL.Path != "/api/v1/consents" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		got = append(got, m)
		bearer = append(bearer, r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(`{"recorded_at":"2026-09-17T00:00:00Z"}`))
	}))
	defer controld.Close()
	sent := func() int { mu.Lock(); defer mu.Unlock(); return len(got) }
	waitFor := func(n int) {
		deadline := time.Now().Add(5 * time.Second)
		for sent() < n && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
	}

	resp, body := call(t, s, http.MethodPut, "/v1/optins", map[string]any{"consents": map[string]bool{"training": true}}, currentCopy)
	want(t, resp, body, http.StatusOK, "")
	if !consents.Read(dir).Training {
		t.Fatal("the local record is written first")
	}
	if err := s.relayConsents(context.Background()); err != nil || !consents.Pending(dir) || sent() != 0 {
		t.Fatalf("not enrolled: err=%v pending=%v sent=%d — nothing leaves before enrollment", err, consents.Pending(dir), sent())
	}

	resp, body = call(t, s, http.MethodPost, "/v1/enroll/keygen", nil)
	want(t, resp, body, http.StatusOK, "")
	var kg struct {
		KeyID string `json:"key_id"`
	}
	decodeTo(t, body, &kg)
	active := activeFor(tenantA, deviceA, kg.KeyID)
	active["endpoints"] = map[string]string{"ingest": controld.URL + "/m1p/v1/ingest"}
	resp, body = call(t, s, http.MethodPost, "/v1/enroll", active)
	want(t, resp, body, http.StatusOK, "")
	if err := s.relayConsents(context.Background()); err != nil || consents.Pending(dir) {
		t.Fatalf("enrolled: err=%v pending=%v", err, consents.Pending(dir))
	}
	mu.Lock()
	if len(got) != 1 || got[0]["training"] != true || got[0]["e1"] != false || got[0]["cloud_judge"] != false || got[0]["team"] != false || bearer[0] != "Bearer "+active["device_token"].(string) {
		t.Fatalf("relayed %v under %v", got, bearer)
	}
	mu.Unlock()

	resp, body = call(t, s, http.MethodPut, "/v1/optins", map[string]any{"consents": map[string]bool{"e1": true, "team": true}})
	want(t, resp, body, http.StatusOK, "")
	waitFor(2)
	mu.Lock()
	if len(got) != 2 || got[1]["e1"] != true || got[1]["training"] != true || got[1]["team"] != true {
		t.Fatalf("PUT /v1/optins relays the whole record off the request path: %v", got)
	}
	down = true
	mu.Unlock()
	resp, body = call(t, s, http.MethodPut, "/v1/optins", map[string]any{"consents": map[string]bool{"training": false}})
	want(t, resp, body, http.StatusOK, "")
	if consents.Read(dir).Training {
		t.Fatal("a revocation is local truth immediately, whatever the cloud says")
	}
	time.Sleep(50 * time.Millisecond)
	if !consents.Pending(dir) {
		t.Fatal("a revocation controld did not acknowledge stays pending")
	}
	mu.Lock()
	down = false
	mu.Unlock()
	s.relayNow()
	mu.Lock()
	last := got[len(got)-1]["training"]
	mu.Unlock()
	if consents.Pending(dir) || last != false {
		t.Fatalf("the retry must land the revocation: pending=%v last=%v", consents.Pending(dir), last)
	}
	if _, body := call(t, s, http.MethodPut, "/v1/optins", map[string]any{"stop_gate": true}); consents.Pending(dir) {
		t.Fatalf("an opt-in write without consents relays nothing: %s", body)
	}

	// An expired enrollment is not a live device: the record stays pending and nothing is sent under a stale token.
	raw, err := os.ReadFile(s.enrollmentPath())
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	decodeTo(t, raw, &doc)
	doc["token_expires_at"] = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	stale, _ := json.Marshal(doc)
	if err := writeAtomic(s.enrollmentPath(), stale); err != nil {
		t.Fatal(err)
	}
	resp, body = call(t, s, http.MethodPut, "/v1/optins", map[string]any{"consents": map[string]bool{"cloud_judge": true}}, currentCopy)
	want(t, resp, body, http.StatusOK, "")
	before := sent()
	if err := s.relayConsents(context.Background()); err != nil || !consents.Pending(dir) || sent() != before {
		t.Fatalf("expired enrollment: err=%v pending=%v sent=%d (was %d)", err, consents.Pending(dir), sent(), before)
	}
}

// controld keys consents by device: a re-enroll under a new device id relays the record again; the same device does not.
func TestConsentsRelayAgainForANewDevice(t *testing.T) {
	s, dir := newServer(t)
	var mu sync.Mutex
	var got []map[string]any
	var bearer []string
	controld := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		mu.Lock()
		got, bearer = append(got, m), append(bearer, r.Header.Get("Authorization"))
		mu.Unlock()
	}))
	defer controld.Close()
	resp, body := call(t, s, http.MethodPut, "/v1/optins", map[string]any{"consents": map[string]bool{"team": true}})
	want(t, resp, body, http.StatusOK, "")
	resp, body = call(t, s, http.MethodPost, "/v1/enroll/keygen", nil)
	want(t, resp, body, http.StatusOK, "")
	var kg struct {
		KeyID string `json:"key_id"`
	}
	decodeTo(t, body, &kg)
	enroll := func(tenant, device string) map[string]any {
		a := activeFor(tenant, device, kg.KeyID)
		a["endpoints"] = map[string]string{"ingest": controld.URL + "/m1p/v1/ingest"}
		resp, body := call(t, s, http.MethodPost, "/v1/enroll", a)
		want(t, resp, body, http.StatusOK, "")
		return a
	}
	enroll(tenantA, deviceA)
	if err := s.relayConsents(context.Background()); err != nil || consents.Pending(dir) {
		t.Fatalf("first relay: err=%v", err)
	}
	enroll(tenantA, deviceA)
	if consents.Pending(dir) {
		t.Fatal("a same-device re-enroll does not re-relay")
	}
	b := enroll(tenantB, deviceB)
	deadline := time.Now().Add(5 * time.Second)
	for consents.Pending(dir) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 || got[1]["team"] != true || bearer[1] != "Bearer "+b["device_token"].(string) {
		t.Fatalf("new device: relayed %v under %v", got, bearer)
	}
}

func TestAdoptNeverTurnsAFieldOn(t *testing.T) {
	on := consents.Consents{E1: true, CloudJudge: true, Training: true, Team: true, LocalRM: true, CloudRM: true, ContributeOutcomes: true}
	if got := consents.Adopt(consents.Consents{}, on, consents.Consents{}); got != (consents.Consents{}) {
		t.Fatalf("the cloud turned %+v on", got)
	}
	if got := consents.Adopt(on, on, on); got != on {
		t.Fatalf("an all-on row turned %+v off", got)
	}
	if got := consents.Adopt(on, consents.Consents{}, on); got != (consents.Consents{}) {
		t.Fatalf("an all-off row left %+v on", got)
	}
}

// currentCopy is the header the current app (lane X3) sends on every consent write.
func currentCopy(r *http.Request) { r.Header.Set(consentCopyHeader, consentCopy) }

// TestOutdatedConsentCopyCannotEnable: an app without the current consent copy (v0.1.14 shows "Anthropic, US" for the cloud judge) cannot turn cloud_judge, cloud_rm or training on through the control API: a typed 409 it can show, nothing written or journalled. Turning anything off, re-sending an on already held, and the consents whose copy did not change still work; the current app (X-Mark1-Consent-Copy: 2) turns them on.
func TestOutdatedConsentCopyCannotEnable(t *testing.T) {
	s, dir := newServer(t)
	for _, f := range []string{"cloud_judge", "cloud_rm", "training"} {
		for _, hdr := range []string{"", "1", "3"} {
			resp, body := call(t, s, http.MethodPut, "/v1/optins", map[string]any{"consents": map[string]bool{"e1": true, f: true}, "stop_gate": true},
				func(r *http.Request) {
					if hdr != "" {
						r.Header.Set(consentCopyHeader, hdr)
					}
				})
			var e struct {
				Error map[string]string `json:"error"`
			}
			decodeTo(t, body, &e)
			if resp.StatusCode != http.StatusConflict || e.Error["code"] != "M1E-2014" || e.Error["reason"] != "consent_copy_outdated" || !strings.Contains(e.Error["message"], f) {
				t.Fatalf("%s under copy %q: %d %s", f, hdr, resp.StatusCode, body)
			}
		}
	}
	if _, err := os.Stat(consents.Path(dir)); err == nil {
		t.Fatal("a refused enable wrote the record")
	}
	if _, err := os.Stat(filepath.Join(dir, "consent.jsonl")); err == nil {
		t.Fatal("a refused enable was journalled")
	}
	resp, body := call(t, s, http.MethodPut, "/v1/optins", map[string]any{"consents": map[string]bool{"e1": true, "team": true, "local_rm": true, "contribute_outcomes": true}})
	want(t, resp, body, http.StatusOK, "")
	resp, body = call(t, s, http.MethodPut, "/v1/optins", map[string]any{"consents": map[string]bool{"cloud_judge": true, "cloud_rm": true, "training": true}}, currentCopy)
	want(t, resp, body, http.StatusOK, "")
	resp, body = call(t, s, http.MethodPut, "/v1/optins", map[string]any{"consents": map[string]bool{"cloud_judge": true, "training": false}})
	want(t, resp, body, http.StatusOK, "")
	if c := consents.Read(dir); !c.CloudJudge || !c.CloudRM || c.Training || !c.E1 {
		t.Fatalf("record %+v", c)
	}
	resp, body = call(t, s, http.MethodPut, "/v1/optins", map[string]any{"consents": map[string]bool{"cloud_judge": false, "cloud_rm": false}})
	want(t, resp, body, http.StatusOK, "")
	if c := consents.Read(dir); c.CloudJudge || c.CloudRM {
		t.Fatalf("an old app's off must always land: %+v", c)
	}
}

// TestCloseWaitsForBackgroundWork: a background relay in flight when Close is called is cancelled and finishes before Close returns (it wrote the state dir after the test's TempDir cleanup began); none starts after Close.
func TestCloseWaitsForBackgroundWork(t *testing.T) {
	s, dir := newServer(t)
	started, out := make(chan struct{}), filepath.Join(dir, "late")
	s.background(func() {
		close(started)
		<-s.ctx.Done()
		time.Sleep(50 * time.Millisecond)
		_ = os.WriteFile(out, []byte("x"), 0o600)
	})
	<-started
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatal("Close returned before the background work finished")
	}
	ran := false
	s.background(func() { ran = true })
	s.bg.Wait()
	if ran {
		t.Fatal("background work started after Close")
	}
}
