package hostprofile

import (
	"strings"
	"testing"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

func validManifest() *m1pv1.HostManifest {
	return &m1pv1.HostManifest{
		HostId: "cem888", HostVersion: "2.0.1",
		OwnsExecution: true, OwnsConfigSurface: true, OwnsMemory: true,
		ArrestMode: m1pv1.ArrestMode_ARREST_MODE_RECOMMEND, SuppliesIdentity: true,
		SchemaVersion: "m1p.v1",
	}
}

// TestDefaultIsTodaysBehaviour pins the one constant: a solo developer's
// daemon, with no manifest anywhere, must resolve to exactly this.
func TestDefaultIsTodaysBehaviour(t *testing.T) {
	want := Profile{OwnsConfigSurface: true, OwnsMemory: true, ArrestMode: Act}
	if Default != want {
		t.Fatalf("Default = %+v, want %+v", Default, want)
	}
	if !Default.IsDefault() {
		t.Fatal("Default.IsDefault() false")
	}
	p, err := FromManifest(nil, true)
	if err != nil || p != Default {
		t.Fatalf("absent manifest: %+v, %v; want Default", p, err)
	}
	p, err = FromManifest(nil, false)
	if err != nil || p != Default {
		t.Fatalf("absent manifest on a first-party connection: %+v, %v; want Default", p, err)
	}
}

func TestFromManifestValid(t *testing.T) {
	p, err := FromManifest(validManifest(), true)
	if err != nil {
		t.Fatal(err)
	}
	want := Profile{HostID: "cem888", HostVersion: "2.0.1", OwnsExecution: true, OwnsConfigSurface: true, OwnsMemory: true, ArrestMode: Recommend, SuppliesIdentity: true, SchemaVersion: "m1p.v1"}
	if p != want {
		t.Fatalf("got %+v, want %+v", p, want)
	}
	if p.IsDefault() {
		t.Fatal("a declared profile reads as Default")
	}
}

// TestFromManifestRefusals: one case per rule in 08 §4.3 step 2b, every
// refusal carrying M1E-4007 and resolving to Default so a caller that
// ignores the error still has the safe posture.
func TestFromManifestRefusals(t *testing.T) {
	for _, tc := range []struct {
		name string
		ext  bool
		mut  func(*m1pv1.HostManifest)
		want string
	}{
		{"arrest_mode unspecified", true, func(m *m1pv1.HostManifest) { m.ArrestMode = m1pv1.ArrestMode_ARREST_MODE_UNSPECIFIED }, "arrest_mode must be ACT or RECOMMEND"},
		{"arrest_mode unknown value", true, func(m *m1pv1.HostManifest) { m.ArrestMode = 9 }, "arrest_mode must be ACT or RECOMMEND"},
		{"owns_execution false on ext", true, func(m *m1pv1.HostManifest) { m.OwnsExecution = false }, "owns_execution must be true"},
		{"schema_version unknown", true, func(m *m1pv1.HostManifest) { m.SchemaVersion = "m1p.v2" }, "schema_version"},
		{"schema_version empty", true, func(m *m1pv1.HostManifest) { m.SchemaVersion = "" }, "schema_version"},
		{"host_id empty", true, func(m *m1pv1.HostManifest) { m.HostId = "" }, "host_id is empty"},
		{"host_version empty", true, func(m *m1pv1.HostManifest) { m.HostVersion = "" }, "host_version is empty"},
		{"manifest from a non-ext writer", false, func(*m1pv1.HostManifest) {}, "non-ext: writer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := validManifest()
			tc.mut(m)
			p, err := FromManifest(m, tc.ext)
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.HasPrefix(err.Error(), CodeInvalid) {
				t.Fatalf("want an %s error containing %q, got %v", CodeInvalid, tc.want, err)
			}
			if p != Default {
				t.Fatalf("a refused manifest resolved to %+v, want Default", p)
			}
		})
	}
}

// TestCanonicalIsPinned is the golden: these bytes are what a later feature
// hashes into receipts, so they are stated verbatim and never derived.
func TestCanonicalIsPinned(t *testing.T) {
	const wantDefault = `{"arrest_mode":"act","host_id":"","host_version":"","owns_config_surface":true,"owns_execution":false,"owns_memory":true,"schema_version":"","supplies_identity":false}`
	if got := string(Canonical(Default)); got != wantDefault {
		t.Fatalf("Canonical(Default) drifted:\n got %s\nwant %s", got, wantDefault)
	}
	p, err := FromManifest(validManifest(), true)
	if err != nil {
		t.Fatal(err)
	}
	const wantCEM = `{"arrest_mode":"recommend","host_id":"cem888","host_version":"2.0.1","owns_config_surface":true,"owns_execution":true,"owns_memory":true,"schema_version":"m1p.v1","supplies_identity":true}`
	if got := string(Canonical(p)); got != wantCEM {
		t.Fatalf("Canonical(cem888) drifted:\n got %s\nwant %s", got, wantCEM)
	}
}

func TestRegistryDefaultsUnknownSessions(t *testing.T) {
	r := NewRegistry()
	sid := [16]byte{1}
	if r.Known(sid) || r.Get(sid) != Default {
		t.Fatal("an unregistered session must read as Default and not Known")
	}
	p, _ := FromManifest(validManifest(), true)
	r.Set(sid, p)
	if !r.Known(sid) || r.Get(sid) != p {
		t.Fatal("a registered session must read back its profile")
	}
	if r.Get([16]byte{2}) != Default {
		t.Fatal("another session must still be Default")
	}
}
