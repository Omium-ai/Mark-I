package provision

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/hostprofile"
)

// TestApplyRefusesAHostOwnedSurface is FR-SPINE-041: a declared host that
// owns the config surface gets nothing written — every walked adapter is
// refused with M1E-7105 naming the host — while hostprofile.Default walks
// exactly as before; RevertUnless is the matching no-op.
func TestApplyRefusesAHostOwnedSurface(t *testing.T) {
	home, state := t.TempDir(), t.TempDir()
	settings := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settings), 0o700); err != nil {
		t.Fatal(err)
	}
	original := []byte("{\n  \"theme\": \"dark\"\n}\n")
	if err := os.WriteFile(settings, original, 0o600); err != nil {
		t.Fatal(err)
	}

	cem := hostprofile.Profile{HostID: "cem888", HostVersion: "2.0.1", OwnsExecution: true, OwnsConfigSurface: true, OwnsMemory: true, ArrestMode: hostprofile.Recommend, SuppliesIdentity: true, SchemaVersion: "m1p.v1"}
	res, err := Apply(Options{Home: home, StateDir: state, Only: []string{"claudecode"}, Profile: &cem})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Provisioned) != 0 || len(res.Refused) != 1 || res.Refused[0].Code != CodeHostOwnsSurface || res.Refused[0].Agent != "claudecode" {
		t.Fatalf("host-owned surface: %+v, want one M1E-7105 refusal for claudecode and nothing provisioned", res)
	}
	if !strings.Contains(res.Refused[0].Detail, "cem888") || !strings.Contains(res.Refused[0].Detail, "attached through the fabric") {
		t.Fatalf("refusal must name the host and say why: %q", res.Refused[0].Detail)
	}
	got, err := os.ReadFile(settings)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(original) {
		t.Fatalf("the host's settings.json was written: %s", got)
	}
	if entries, _ := os.ReadDir(filepath.Join(state, "provisioned")); len(entries) != 0 {
		t.Fatalf("a manifest was written for a refused walk: %v", entries)
	}
	if _, _, refused := RevertUnless(cem, state); !strings.HasPrefix(refused, CodeHostOwnsSurface) {
		t.Fatalf("RevertUnless for a host-owned surface: %q, want the M1E-7105 reason", refused)
	}

	// Default: Mark 1 owns the surface and provisions as it always has.
	res, err = Apply(Options{Home: home, StateDir: state, Only: []string{"claudecode"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range res.Refused {
		if r.Code == CodeHostOwnsSurface {
			t.Fatalf("Default tripped the host-owned refusal: %+v", r)
		}
	}
	if len(res.Provisioned) != 1 || res.Provisioned[0] != "claudecode" {
		t.Fatalf("Default did not provision claudecode: %+v", res)
	}
	if got, _ := os.ReadFile(settings); string(got) == string(original) {
		t.Fatal("Default wrote nothing; the fence should be in the file now")
	}
	if _, _, refused := RevertUnless(hostprofile.Default, state, "claudecode"); refused != "" {
		t.Fatalf("RevertUnless for Default refused: %q", refused)
	}
	if got, _ := os.ReadFile(settings); string(got) != string(original) {
		t.Fatalf("revert did not restore the original: %s", got)
	}
}

// TestHostOwnsSurfaceSemantics pins ADR-0014 §4's reading of the flag.
func TestHostOwnsSurfaceSemantics(t *testing.T) {
	if HostOwnsSurface(hostprofile.Default) {
		t.Fatal("Default must never read as a host owning the surface")
	}
	if HostOwnsSurface(hostprofile.Profile{HostID: "x", OwnsConfigSurface: false}) {
		t.Fatal("a declared host that does not own the surface must not refuse")
	}
	if !HostOwnsSurface(hostprofile.Profile{HostID: "x", OwnsConfigSurface: true}) {
		t.Fatal("a declared host that owns the surface must refuse")
	}
}
