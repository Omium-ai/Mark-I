package doctor

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	prov "github.com/Omium-ai/omium-mark1/go/mark1d/adapters/provision"
)

// TestDoctorSurfacesAHostOwnedSurface is FR-SPINE-042 for `mark1 doctor`: for
// a session whose declared host owns the config surface, the report carries
// the M1E-7107 reason as host_owned and the human form prints the one line;
// with no declared host there is no such line.
func TestDoctorSurfacesAHostOwnedSurface(t *testing.T) {
	cem := prov.Profile{HostID: "cem888", HostVersion: "2.0.1", OwnsExecution: true, OwnsConfigSurface: true, OwnsMemory: true, ArrestMode: "recommend", SuppliesIdentity: true, SchemaVersion: "m1p.v1"}
	env, out := enrolledEnv(t)
	_ = Run(env, Options{ClaudeSettings: noRetention(t), Socket: filepath.Join(t.TempDir(), "no.sock"), Profile: &cem})
	var rep Report
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("doctor --json is not one object: %v\n%s", err, out.String())
	}
	if !strings.HasPrefix(rep.HostOwned, prov.CodeHostOwnsSurface) || !strings.Contains(rep.HostOwned, "cem888") {
		t.Fatalf("host_owned = %q, want the M1E-7107 reason naming the host", rep.HostOwned)
	}

	henv, _ := enrolledEnv(t)
	var human bytes.Buffer
	henv.JSON, henv.Stdout = false, &human
	_ = Run(henv, Options{ClaudeSettings: noRetention(t), Socket: filepath.Join(t.TempDir(), "no.sock"), Profile: &cem})
	if !strings.Contains(human.String(), "host          "+prov.CodeHostOwnsSurface) || !strings.Contains(human.String(), "attached through the fabric") {
		t.Fatalf("human output lacks the one-line explanation:\n%s", human.String())
	}

	denv, dout := enrolledEnv(t)
	_ = Run(denv, Options{ClaudeSettings: noRetention(t), Socket: filepath.Join(t.TempDir(), "no.sock")})
	var def Report
	if err := json.Unmarshal(dout.Bytes(), &def); err != nil {
		t.Fatal(err)
	}
	if def.HostOwned != "" {
		t.Fatalf("Default produced a host_owned line: %q", def.HostOwned)
	}
}
