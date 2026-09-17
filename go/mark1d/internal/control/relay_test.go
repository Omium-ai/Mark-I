package control

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
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

	resp, body := call(t, s, http.MethodPut, "/v1/optins", map[string]any{"consents": map[string]bool{"training": true}})
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
	if len(got) != 1 || got[0]["training"] != true || got[0]["e1"] != false || got[0]["cloud_judge"] != false || bearer[0] != "Bearer "+active["device_token"].(string) {
		t.Fatalf("relayed %v under %v", got, bearer)
	}
	mu.Unlock()

	resp, body = call(t, s, http.MethodPut, "/v1/optins", map[string]any{"consents": map[string]bool{"e1": true}})
	want(t, resp, body, http.StatusOK, "")
	waitFor(2)
	mu.Lock()
	if len(got) != 2 || got[1]["e1"] != true || got[1]["training"] != true {
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
	resp, body = call(t, s, http.MethodPut, "/v1/optins", map[string]any{"consents": map[string]bool{"cloud_judge": true}})
	want(t, resp, body, http.StatusOK, "")
	before := sent()
	if err := s.relayConsents(context.Background()); err != nil || !consents.Pending(dir) || sent() != before {
		t.Fatalf("expired enrollment: err=%v pending=%v sent=%d (was %d)", err, consents.Pending(dir), sent(), before)
	}
}
