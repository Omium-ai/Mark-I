package off

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Omium-ai/omium-mark1/go/mark1/internal/cli"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/provision"
)

// TestOffSurfacesAHostOwnedSurface is FR-SPINE-042 for `mark1 off`: for a
// session whose declared host owns the config surface, off reverts nothing
// (there is nothing of ours there), reports M1E-7105 in --json as host_owned,
// and prints the one explanatory line in human form. Off itself still
// succeeds: the marker is written, the daemon is observed as usual.
func TestOffSurfacesAHostOwnedSurface(t *testing.T) {
	cem := provision.Profile{HostID: "cem888", HostVersion: "2.0.1", OwnsExecution: true, OwnsConfigSurface: true, OwnsMemory: true, ArrestMode: "recommend", SuppliesIdentity: true, SchemaVersion: "m1p.v1"}
	env, out := testEnv(t)
	if err := Run(env, Options{Socket: shortSocket(t), ObserveGrace: 50 * time.Millisecond, Profile: &cem}); err != nil {
		t.Fatalf("off with a host-owned surface failed: %v", err)
	}
	var res Result
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(res.HostOwned, provision.CodeHostOwnsSurface) || !strings.Contains(res.HostOwned, "cem888") {
		t.Fatalf("host_owned = %q, want the M1E-7105 reason naming the host", res.HostOwned)
	}
	if len(res.Reverted) != 0 || len(res.NotReverted) != 0 {
		t.Fatalf("a host-owned surface was reverted or reported partial: %+v", res)
	}

	var human bytes.Buffer
	henv := &cli.Env{StateDir: t.TempDir(), Stdout: &human, Stderr: os.Stderr}
	if err := Run(henv, Options{Socket: shortSocket(t), ObserveGrace: 50 * time.Millisecond, Profile: &cem}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(human.String(), "host          "+provision.CodeHostOwnsSurface) || !strings.Contains(human.String(), "attached through the fabric") {
		t.Fatalf("human output lacks the one-line explanation:\n%s", human.String())
	}
}
