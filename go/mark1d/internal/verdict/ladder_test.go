package verdict

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/policy"
	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

var (
	single = Ladder{ID: "single", Rungs: []Rung{{"claude-haiku-4-5", true}}}
	three  = Ladder{ID: "three", Rungs: []Rung{{"claude-haiku-4-5", true}, {"claude-sonnet-4-5", false}, {"claude-opus-4-1", true}}}

	below = KneeState{N: 2, Evaluable: true}             // p̂_LCB·V > c(n): the gate forces continuation
	atK   = KneeState{N: 2, Evaluable: true, Stop: true} // at the knee: the gate lets the agent stop
	stale = KneeState{N: 2, Stale: true}
)

// TestLaddersKeepPrefix is FR-ROUTE-006's golden table: hand-computed escalations (unit_ladders_keep_prefix).
func TestLaddersKeepPrefix(t *testing.T) {
	for _, tc := range []struct {
		name    string
		ladder  Ladder
		current string
		v       m1pv1.Verdict
		k       KneeState
		want    LadderStep
	}{
		{"single rung never escalates: below-knee violated is exhausted", single, "claude-haiku-4-5", m1pv1.Verdict_VERDICT_VIOLATED, below, LadderStep{LadderExhausted, "claude-haiku-4-5", false}},
		{"single rung satisfied stays", single, "claude-haiku-4-5", m1pv1.Verdict_VERDICT_SATISFIED, below, LadderStep{LadderStay, "claude-haiku-4-5", false}},
		{"three: haiku below knee escalates to sonnet keeping haiku's prefix", three, "claude-haiku-4-5", m1pv1.Verdict_VERDICT_VIOLATED, below, LadderStep{LadderEscalate, "claude-sonnet-4-5", true}},
		{"three: sonnet below knee escalates to opus dropping the prefix", three, "claude-sonnet-4-5", m1pv1.Verdict_VERDICT_VIOLATED, below, LadderStep{LadderEscalate, "claude-opus-4-1", false}},
		{"three: opus below knee is exhausted at the top", three, "claude-opus-4-1", m1pv1.Verdict_VERDICT_VIOLATED, below, LadderStep{LadderExhausted, "claude-opus-4-1", false}},
		{"three: violated at the knee stays (the gate allows stop)", three, "claude-haiku-4-5", m1pv1.Verdict_VERDICT_VIOLATED, atK, LadderStep{LadderStay, "claude-haiku-4-5", false}},
		{"three: stale never climbs (04 §2.3 single-rung built-in)", three, "claude-haiku-4-5", m1pv1.Verdict_VERDICT_VIOLATED, stale, LadderStep{LadderStay, "claude-haiku-4-5", false}},
		{"three: satisfied stays", three, "claude-haiku-4-5", m1pv1.Verdict_VERDICT_SATISFIED, below, LadderStep{LadderStay, "claude-haiku-4-5", false}},
		{"three: refused stays", three, "claude-haiku-4-5", m1pv1.Verdict_VERDICT_REFUSED, below, LadderStep{LadderStay, "claude-haiku-4-5", false}},
		{"three: error stays (Thm 5.2: infra failure is not a failed rung)", three, "claude-haiku-4-5", m1pv1.Verdict_VERDICT_ERROR, below, LadderStep{LadderStay, "claude-haiku-4-5", false}},
		{"three: a model the ladder does not name stays", three, "gpt-5", m1pv1.Verdict_VERDICT_VIOLATED, below, LadderStep{LadderStay, "gpt-5", false}},
	} {
		if got := tc.ladder.Step(tc.current, tc.v, tc.k); got != tc.want {
			t.Errorf("%s: got %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

// TestFromBundleLadders: the seam carries every ladder verbatim and LadderStep takes the first naming a model.
func TestFromBundleLadders(t *testing.T) {
	b := bundleWith()
	b.Route.Ladders = []policy.Ladder{
		{LadderID: "three", Rungs: []policy.Rung{{ModelID: "claude-haiku-4-5", KeepPrefix: true}, {ModelID: "claude-sonnet-4-5"}, {ModelID: "claude-opus-4-1", KeepPrefix: true}}},
		{LadderID: "dup", Rungs: []policy.Rung{{ModelID: "claude-sonnet-4-5", KeepPrefix: true}, {ModelID: "gpt-5"}}},
	}
	m, err := FromBundle(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Ladders) != 2 || m.Ladders[0].ID != "three" || m.Ladders[0].Rungs[1] != (Rung{"claude-sonnet-4-5", false}) || !m.Ladders[1].Rungs[0].KeepPrefix {
		t.Fatalf("ladders not carried verbatim: %+v", m.Ladders)
	}
	if got := m.LadderStep("claude-sonnet-4-5", m1pv1.Verdict_VERDICT_VIOLATED, below); got != (LadderStep{LadderEscalate, "claude-opus-4-1", false}) {
		t.Fatalf("first ladder naming the model must win: %+v", got)
	}
	if got := m.LadderStep("gpt-5", m1pv1.Verdict_VERDICT_VIOLATED, below); got != (LadderStep{LadderExhausted, "gpt-5", false}) {
		t.Fatalf("second ladder serves its own model: %+v", got)
	}
	if got := m.LadderStep("mistral", m1pv1.Verdict_VERDICT_VIOLATED, below); got != (LadderStep{LadderStay, "mistral", false}) {
		t.Fatalf("a model on no ladder stays: %+v", got)
	}
}

// TestFromBundleLadderFullVector pins the frozen full.cbor ladder (haiku→sonnet, both keep_prefix) through the seam.
func TestFromBundleLadderFullVector(t *testing.T) {
	dir := "../../../../conformance/vectors/bundle"
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var man struct {
		Keys map[string]struct {
			PublicHex string `json:"public_hex"`
		} `json:"keys"`
		Vectors []struct {
			Name     string  `json:"name"`
			LastSeq  *uint64 `json:"last_applied_seq"`
			TlogHead struct {
				RootHex  string `json:"root_hex"`
				TreeSize uint64 `json:"tree_size"`
			} `json:"tlog_head"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &man); err != nil {
		t.Fatal(err)
	}
	keys := policy.NewSectionKeys()
	for _, s := range policy.AllSections() {
		pub, _ := hex.DecodeString(man.Keys[s.Name()].PublicHex)
		keys.Insert(s, policy.KeyEntry{Public: ed25519.PublicKey(pub)})
	}
	var head policy.TlogHead
	var last *uint64
	for _, v := range man.Vectors {
		if v.Name == "full" {
			root, _ := hex.DecodeString(v.TlogHead.RootHex)
			head, last = policy.TlogHead{TreeSize: v.TlogHead.TreeSize, Root: [32]byte(root)}, v.LastSeq
		}
	}
	cbor, err := os.ReadFile(filepath.Join(dir, "full.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	b, rej := policy.VerifyAndDecode(cbor, keys, last, &head)
	if rej != nil {
		t.Fatalf("full.cbor must accept: %v", rej)
	}
	m, err := FromBundle(b)
	if err != nil {
		t.Fatal(err)
	}
	want := []Ladder{{ID: "default", Rungs: []Rung{{"claude-haiku-4-5", true}, {"claude-sonnet-4-5", true}}}}
	if len(m.Ladders) != 1 || m.Ladders[0].ID != want[0].ID || len(m.Ladders[0].Rungs) != 2 || m.Ladders[0].Rungs[0] != want[0].Rungs[0] || m.Ladders[0].Rungs[1] != want[0].Rungs[1] {
		t.Fatalf("full.cbor ladder = %+v, want %+v", m.Ladders, want)
	}
	if got := m.LadderStep("claude-haiku-4-5", m1pv1.Verdict_VERDICT_VIOLATED, below); got != (LadderStep{LadderEscalate, "claude-sonnet-4-5", true}) {
		t.Fatalf("full.cbor haiku below knee: %+v", got)
	}
	if got := m.LadderStep("claude-sonnet-4-5", m1pv1.Verdict_VERDICT_VIOLATED, below); got != (LadderStep{LadderExhausted, "claude-sonnet-4-5", false}) {
		t.Fatalf("full.cbor sonnet is the top: %+v", got)
	}
}
