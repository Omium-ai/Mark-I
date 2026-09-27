package control

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/consents"
)

func TestRewardModelChoiceAndDoctorRow(t *testing.T) {
	s, dir := newServer(t)
	resp, body := call(t, s, http.MethodPut, "/v1/optins", map[string]any{"consents": map[string]bool{"local_rm": true}})
	want(t, resp, body, http.StatusOK, "")
	if c := consents.Read(dir); !c.LocalRM || c.CloudRM {
		t.Fatalf("local_rm not recorded: %+v", c)
	}
	_, body = call(t, s, http.MethodGet, "/v1/doctor", nil)
	if !strings.Contains(string(body), `"name":"rm_runtime","ok":true,"detail":"not started`) || !strings.Contains(string(body), `"reward_models":null`) {
		t.Fatalf("doctor lacks the rm_runtime row: %s", body)
	}
	if err := os.MkdirAll(filepath.Join(dir, "rm"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rm", "status.json"), []byte(`{"state":"failed","model_id":"rm:m1-a@1","detail":"runtime crash-looped"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, body = call(t, s, http.MethodGet, "/v1/doctor", nil)
	if !strings.Contains(string(body), `"name":"rm_runtime","ok":false,"detail":"failed rm:m1-a@1: runtime crash-looped"`) || !strings.Contains(string(body), `"ok":false`) {
		t.Fatalf("a crash-looped runtime must fail doctor: %s", body)
	}
	if err := os.WriteFile(filepath.Join(dir, "rm", "status.json"), []byte(`{"state":"refused","model_id":"rm:mark1-rm-a@1,rm:mark1-rm-b@1","detail":"x","models":[{"model_id":"rm:mark1-rm-a@1","state":"ready","size_bytes":1646572512},{"model_id":"rm:mark1-rm-b@1","state":"refused","detail":"execution hash differs","size_bytes":1737784416}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, body = call(t, s, http.MethodGet, "/v1/doctor", nil)
	if !strings.Contains(string(body), `"reward_models":{"state":"refused"`) || !strings.Contains(string(body), `{"model_id":"rm:mark1-rm-b@1","state":"refused","detail":"execution hash differs","size_bytes":1737784416}`) {
		t.Fatalf("doctor must carry each model's own state for the app's status rows: %s", body)
	}
}
