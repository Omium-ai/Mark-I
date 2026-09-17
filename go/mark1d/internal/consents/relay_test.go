package consents

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

type fixed string

func (f fixed) Token(context.Context) (string, error) { return string(f), nil }

// TestRelaySendsTheWholeRecordAndStaysPendingUntilAcknowledged: nothing to
// relay before a consent exists; a recorded consent is pending until controld
// answers 2xx to the whole triple under the device token; a refusal or an
// outage leaves it pending; a later change (a revocation) is pending again.
func TestRelaySendsTheWholeRecordAndStaysPendingUntilAcknowledged(t *testing.T) {
	dir := t.TempDir()
	if Pending(dir) {
		t.Fatal("no record: nothing to relay")
	}
	if err := Write(dir, Consents{E1: true, CloudJudge: true, Training: true}); err != nil {
		t.Fatal(err)
	}
	if !Pending(dir) {
		t.Fatal("a fresh record is pending")
	}
	var got []map[string]any
	var auth []string
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/api/v1/consents" || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected %s %s %s", r.Method, r.URL.Path, r.Header.Get("Content-Type"))
		}
		auth = append(auth, r.Header.Get("Authorization"))
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Error(err)
		}
		got = append(got, m)
		w.WriteHeader(status)
	}))
	defer srv.Close()
	ctx := context.Background()
	status = http.StatusServiceUnavailable
	if err := Relay(ctx, dir, srv.URL, fixed("tok")); err == nil || !Pending(dir) {
		t.Fatalf("a refused relay must stay pending: err=%v pending=%v", err, Pending(dir))
	}
	status = http.StatusOK
	if err := Relay(ctx, dir, srv.URL, fixed("tok")); err != nil || Pending(dir) {
		t.Fatalf("acknowledged relay: err=%v pending=%v", err, Pending(dir))
	}
	if len(got) != 2 || got[1]["e1"] != true || got[1]["cloud_judge"] != true || got[1]["training"] != true || len(got[1]) != 3 || auth[1] != "Bearer tok" {
		t.Fatalf("relayed %v under %v", got, auth)
	}
	if err := Write(dir, Consents{E1: true, CloudJudge: true, Training: false}); err != nil {
		t.Fatal(err)
	}
	if !Pending(dir) {
		t.Fatal("a revocation is pending until acknowledged")
	}
	srv.Close()
	if err := Relay(ctx, dir, srv.URL, fixed("tok")); err == nil || !Pending(dir) {
		t.Fatalf("controld down: err=%v pending=%v", err, Pending(dir))
	}
	if err := os.WriteFile(Path(dir), []byte("{garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Relay(ctx, dir, srv.URL, fixed("tok")); err == nil {
		t.Fatal("a corrupt local record is never relayed as consent")
	}
}
