package adapters

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

// TestNoEventFamilyCarriesAnAdapterDiscriminant is FR-AGENT-005's schema
// clause (conf_one_schema_all_agents): every adapter emits the same m1p.v1
// families, so no family, field, oneof, enum or enum value reachable from
// Event.body may be named for an agent. SessionStart.agent is the one place
// an agent is named, and it is a VALUE ("codex"), never a type.
func TestNoEventFamilyCarriesAnAdapterDiscriminant(t *testing.T) {
	body := m1pv1.File_m1p_v1_envelope_proto.Messages().ByName("Event").Oneofs().ByName("body")
	if body == nil || body.Fields().Len() == 0 {
		t.Fatal("Event.body oneof not found — the walk below would be vacuous")
	}
	seen := map[protoreflect.FullName]bool{}
	var names []protoreflect.FullName
	var walk func(md protoreflect.MessageDescriptor)
	walk = func(md protoreflect.MessageDescriptor) {
		if seen[md.FullName()] {
			return
		}
		seen[md.FullName()] = true
		names = append(names, md.FullName())
		for i := 0; i < md.Oneofs().Len(); i++ {
			names = append(names, md.Oneofs().Get(i).FullName())
		}
		for i := 0; i < md.Fields().Len(); i++ {
			f := md.Fields().Get(i)
			names = append(names, f.FullName())
			// Dialect names WIRE formats (04 §4: the Gemini API is one), which any
			// adapter's proxy path may carry; it is not an agent discriminant.
			if f.Enum() != nil && f.Enum().FullName() != "m1p.v1.Dialect" {
				names = append(names, f.Enum().FullName())
				for j := 0; j < f.Enum().Values().Len(); j++ {
					names = append(names, f.Enum().Values().Get(j).FullName())
				}
			}
			if f.Message() != nil {
				walk(f.Message())
			}
		}
	}
	families := 0
	for i := 0; i < body.Fields().Len(); i++ {
		families++
		walk(body.Fields().Get(i).Message())
	}
	if families < 20 || len(names) < 100 {
		t.Fatalf("walked %d families / %d names — not the m1p.v1 schema", families, len(names))
	}
	for _, slot := range Roster {
		for _, n := range names {
			if strings.Contains(strings.ToLower(string(n)), slot.Name) {
				t.Errorf("%s names the %q adapter: one schema across all agents forbids a per-adapter family or field", n, slot.Name)
			}
		}
	}
	// The one sanctioned agent reference is a string value on SessionStart.
	if f := m1pv1.File_m1p_v1_events_proto.Messages().ByName("SessionStart").Fields().ByName("agent"); f == nil || f.Kind() != protoreflect.StringKind {
		t.Fatal("SessionStart.agent must stay a plain string — an enum of agents would be a discriminant")
	}
}

// TestRosterNamesAreTheDiscriminantVocabulary: the names the test above
// forbids inside the schema are exactly the seven 08 §5 slots, so a slot
// added to the roster is automatically forbidden as a schema name.
func TestRosterNamesAreTheDiscriminantVocabulary(t *testing.T) {
	want := []string{"claudecode", "codex", "gemini", "opencode", "copilot", "cursor", "crush"}
	if len(Roster) != len(want) {
		t.Fatalf("roster has %d slots, 08 §5 enumerates %d", len(Roster), len(want))
	}
	for i, s := range Roster {
		if s.Name != want[i] {
			t.Fatalf("slot %d is %q, want %q (08 §5 section order)", i, s.Name, want[i])
		}
		if s.Name != strings.ToLower(s.Name) {
			t.Fatalf("slot %q must be lower-case: the schema check compares lower-cased names", s.Name)
		}
	}
}
