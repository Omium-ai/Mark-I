package policydist

import (
	"bytes"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func bootstrapFor(t *testing.T, basis string, v float64) Sections {
	t.Helper()
	raw, err := BootstrapSections(bootstrapRegime{CostBasis: basis, VDefault: v})
	if err != nil {
		t.Fatalf("BootstrapSections(%s): %v", basis, err)
	}
	s, err := DecodeSections(raw)
	if err != nil {
		t.Fatalf("the bootstrap must survive the strict publish-side decoder: %v", err)
	}
	return s
}

func TestBootstrapSectionsAreHonestPriors(t *testing.T) {
	s := bootstrapFor(t, "quota", 1)
	ids := make([]string, 0, len(s.Verify.Verifiers))
	for _, v := range s.Verify.Verifiers {
		ids = append(ids, v.VerifierID)
		if !strings.HasSuffix(v.VerifierID, "@cat-1") {
			t.Fatalf("verifier %q is not a catalog id the edge derives", v.VerifierID)
		}
	}
	if len(ids) != len(bootstrapAnchors) {
		t.Fatalf("%d verifiers, want one per catalog anchor (%d)", len(ids), len(bootstrapAnchors))
	}
	if s.Verify.Priors != bootstrapPriors {
		t.Fatalf("priors %v, want 06 §3.2's %v", s.Verify.Priors, bootstrapPriors)
	}
	if len(s.Verify.CorrelationGroups) != 1 || s.Verify.CorrelationGroups[0].GroupID != "syntactic" ||
		len(s.Verify.CorrelationGroups[0].Members) != len(ids) {
		t.Fatalf("06 §4.1: syntactic ∪ tests is ONE clique over every anchor; got %+v", s.Verify.CorrelationGroups)
	}
	if len(s.Verify.Anchors) != 0 || len(s.Verify.Quarantine) != 0 || len(s.Route.CPVS) != 0 || len(s.Route.Ladders) != 0 {
		t.Fatal("nothing is enabled, quarantined, priced or laddered by a bootstrap")
	}
	if got, want := s.Gates, (GatesSection{StopGateEnabled: true, MaxConsecutiveBlocks: 3, HourlyBlockCeiling: maxHourlyBlockCeiling}); got != want {
		t.Fatalf("gates %+v, want %+v", got, want)
	}
	if len(s.AgentMaps.Agents) != 6 {
		t.Fatalf("%d agent maps, want the six shipped adapters", len(s.AgentMaps.Agents))
	}
	for _, v := range s.Verify.Verifiers {
		for kind, want := range map[string][4][3]float64{"ruff@cat-1": syntacticRows, "cargo-check@cat-1": anchorRows, "pytest@cat-1": anchorRows, "tsc@cat-1": syntacticRows} {
			if v.VerifierID == kind && v.Confusion != want {
				t.Fatalf("%s rows %v, want %v", kind, v.Confusion, want)
			}
		}
	}
}

// impliedKnee is knee.py's implied_knee, the Python twin of mark1d kneeFor: first n with p_lcb·V ≤ c_n.
func impliedKnee(k KneeTable) int {
	for _, r := range k.Rows {
		if r.PLCB != nil && *r.PLCB*k.VDefault <= r.CN {
			return int(r.N)
		}
	}
	return 0
}

func TestBootstrapKneeStopsAtThreeUnderEitherBasis(t *testing.T) {
	kStar := 1 + int(math.Floor(math.Log(kneeRho)/math.Log(kneeGamma)))
	for _, tc := range []struct {
		basis string
		v     float64
	}{{"quota", 1}, {"usd", 25}} {
		k := bootstrapFor(t, tc.basis, tc.v).Route.Knee
		if k.CostBasis != tc.basis || k.VDefault != tc.v || len(k.Rows) != kneeRows {
			t.Fatalf("%s: knee %+v", tc.basis, k)
		}
		for i, r := range k.Rows {
			if r.PLCB == nil || int(r.N) != i+1 || r.CN != kneeRho*kneeP1*tc.v {
				t.Fatalf("%s row %d: %+v — every row carries p_lcb (D-Z) and the flat prior cost", tc.basis, i, r)
			}
		}
		if got := impliedKnee(k); got != 3 {
			t.Fatalf("%s: implied knee %d, want 3", tc.basis, got)
		}
		if got := impliedKnee(k); got < kStar-1 || got > kStar+1 {
			t.Fatalf("%s: implied knee %d is not within ±1 of k*=%d (06 §10.3)", tc.basis, got, kStar)
		}
	}
	if _, err := BootstrapSections(bootstrapRegime{CostBasis: "tokens", VDefault: 1}); err == nil {
		t.Fatal("a basis outside usd|quota must refuse, never publish")
	}
}

// TestBootstrapAnchorsMirrorTheEdgeCatalog reads the detector table the daemon derives ids from; a tool added to one side without the other fails here.
func TestBootstrapAnchorsMirrorTheEdgeCatalog(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "..", "mark1d", "internal", "anchors", "catalog.go"))
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`tool: "([a-z-]+)"`)
	var edge []string
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		edge = append(edge, m[1])
	}
	sort.Strings(edge)
	var here []string
	for _, a := range bootstrapAnchors {
		here = append(here, a.tool)
	}
	sort.Strings(here)
	if strings.Join(edge, ",") != strings.Join(here, ",") {
		t.Fatalf("edge catalog tools %v != bootstrap anchors %v", edge, here)
	}
}

// TestBootstrapRowsMirrorTheAdjudicator parses likelihoods.py's two calibrated tables so the Go copies cannot drift from the source of the numbers.
func TestBootstrapRowsMirrorTheAdjudicator(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "python", "adjudicator", "app", "adjudicate", "likelihoods.py"))
	if err != nil {
		t.Fatal(err)
	}
	py := strings.ReplaceAll(string(src), "EPSILON_ANCHOR", "0.02")
	row := regexp.MustCompile(`\(([0-9.]+), ([0-9.]+), ([0-9.]+)\),`)
	table := func(name string) [4][3]float64 {
		i := strings.Index(py, name+": Confusion = (")
		if i < 0 {
			t.Fatalf("%s not found in likelihoods.py", name)
		}
		var out [4][3]float64
		for r, m := range row.FindAllStringSubmatch(py[i:], 4) {
			for c := 0; c < 3; c++ {
				f, err := strconv.ParseFloat(m[c+1], 64)
				if err != nil {
					t.Fatal(err)
				}
				out[r][c] = f
			}
		}
		return out
	}
	if got := table("_ANCHOR_DEFAULT"); got != anchorRows {
		t.Fatalf("_ANCHOR_DEFAULT %v != anchorRows %v", got, anchorRows)
	}
	if got := table("_SYNTACTIC_DEFAULT"); got != syntacticRows {
		t.Fatalf("_SYNTACTIC_DEFAULT %v != syntacticRows %v", got, syntacticRows)
	}
}

// TestBootstrapMapsMirrorTheShim: the embedded copies are byte-identical to rust/mark1-hookshim/maps, and every shim event rule lands in hook_fields.
func TestBootstrapMapsMirrorTheShim(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "..", "rust", "mark1-hookshim", "maps")
	shipped, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil || len(shipped) != 6 {
		t.Fatalf("shim maps: %v (%d)", err, len(shipped))
	}
	for _, p := range shipped {
		want, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		got, err := shimMaps.ReadFile("maps/" + filepath.Base(p))
		if err != nil || !bytes.Equal(want, got) {
			t.Fatalf("policydist/maps/%s differs from the shim's copy (%v); re-copy it", filepath.Base(p), err)
		}
	}
	agents, err := shimAgentMaps()
	if err != nil {
		t.Fatal(err)
	}
	for i, a := range agents {
		raw, _ := shimMaps.ReadFile("maps/" + a.AgentID + ".json")
		var m shimMap
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		if a.AgentVersion != m.AgentVersion || a.HookFields["event"] != "/"+m.EventField || a.HookFields["session_id"] != "/"+m.SessionIDField[0] {
			t.Fatalf("agents[%d] %s: %+v", i, a.AgentID, a)
		}
		if a.AgentID == "cursor" && (len(m.SessionIDField) != 2 || a.HookFields["session_id.1"] != "/conversation_id") {
			t.Fatalf("cursor session_id fallback: %+v", a.HookFields)
		}
		for event, rule := range m.Events {
			for logical, vendor := range rule.Fields {
				if got := a.HookFields[strings.ToLower(event)+"."+logical]; got != "/"+vendor {
					t.Fatalf("%s %s.%s = %q, want /%s", a.AgentID, event, logical, got, vendor)
				}
			}
		}
	}
	if pointerOf("a/b~c") != "/a~1b~0c" {
		t.Fatal("RFC 6901 escaping")
	}
}
