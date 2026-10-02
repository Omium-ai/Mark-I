package hostprofile

import "testing"

// TestRegistryParsesAndLooksUp: the embedded hosts.json loads, cem888 is the
// first entry with the manifest ADR-0013 §5 states, and an unknown host is a
// miss — not an error, because the registry enforces nothing.
func TestRegistryParsesAndLooksUp(t *testing.T) {
	h, ok := Lookup("cem888")
	if !ok {
		t.Fatal("cem888 is not in the registry")
	}
	want := Profile{HostID: "cem888", HostVersion: "2.0.1", OwnsExecution: true, OwnsConfigSurface: true, OwnsMemory: true, ArrestMode: Recommend, SuppliesIdentity: true, SchemaVersion: "m1p.v1"}
	if h.Expected != want || h.DisplayName != "CEM888" {
		t.Fatalf("cem888 entry = %+v, want %+v / CEM888", h, want)
	}
	if _, ok := Lookup("stranger"); ok {
		t.Fatal("an unlisted host must be a miss")
	}
	if _, ok := Lookup(""); ok {
		t.Fatal("an empty host_id must be a miss")
	}
}
