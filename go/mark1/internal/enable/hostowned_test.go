package enable

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/provision"
)

// TestEnableSurfacesAHostOwnedSurface is FR-SPINE-042 for `mark1 enable`: for
// a session whose declared host owns the config surface every walked adapter
// is refused with M1E-7105 (rendered as NOT PROVISIONED, the existing style),
// nothing is written under the vendor's home, and enable itself succeeds —
// Mark 1 is attached through the fabric, not through the file.
func TestEnableSurfacesAHostOwnedSurface(t *testing.T) {
	cem := provision.Profile{HostID: "cem888", HostVersion: "2.0.1", OwnsExecution: true, OwnsConfigSurface: true, OwnsMemory: true, ArrestMode: "recommend", SuppliesIdentity: true, SchemaVersion: "m1p.v1"}
	env, out, home := enrolledEnv(t)
	if err := Run(env, Options{Path: t.TempDir(), Home: home, Profile: &cem}); err != nil {
		t.Fatalf("enable with a host-owned surface failed: %v", err)
	}
	var res Result
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if len(res.AgentsProvisioned) != 0 || len(res.AgentsRefused) == 0 {
		t.Fatalf("want every walked adapter refused and none provisioned: %+v", res)
	}
	for _, r := range res.AgentsRefused {
		if r.Code != provision.CodeHostOwnsSurface || !strings.Contains(r.Detail, "cem888") || !strings.Contains(r.Detail, "attached through the fabric") {
			t.Fatalf("refusal %+v, want M1E-7105 naming the host with the one-line reason", r)
		}
	}
	if _, err := os.Stat(filepath.Join(home, ".claude")); err == nil {
		t.Fatal("enable wrote into the host-owned config surface")
	}
}
