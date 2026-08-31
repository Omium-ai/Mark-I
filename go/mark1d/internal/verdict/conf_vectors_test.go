// TestConfVectorsFusion drives conformance/vectors/fusion/manifest.json — the
// cross-language lock on ADJUDICATE, which 06 §3 declares runs in exactly two
// places ("one algorithm, two deployment points ... divergence between them is
// a CI failure"). The other implementation is python/adjudicator; both are
// driven by these vectors, whose expectations are derived in exact rational
// arithmetic, not recorded from whichever side ran first.
//
// The `ConfVectors` name prefix is load-bearing: conformance_crosslang.sh
// selects Go tests with -run ConfVectors and counts this family via
// ConfVectorsFusion.

package verdict

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

const fusionVectorsDir = "../../../../conformance/vectors/fusion"

type fusionVerifier struct {
	Kind      string        `json:"kind"`
	Group     string        `json:"group"`
	Confusion [4][3]float64 `json:"confusion"`
	// Quarantined is 07's quarantine list. encoding/json ignores keys it has no
	// field for, so without this the driver silently readmits a verifier the
	// vector explicitly distrusts and fuses its vote.
	Quarantined bool `json:"quarantined"`
}

type fusionVote struct {
	VerifierID string `json:"verifier_id"`
	Verdict    string `json:"verdict"`
	Tamper     bool   `json:"tamper"`
}

type fusionInput struct {
	Name      string                    `json:"name"`
	Priors    [4]float64                `json:"priors"`
	Verifiers map[string]fusionVerifier `json:"verifiers"`
	Votes     []fusionVote              `json:"votes"`
}

type fusionExpect struct {
	Name           string    `json:"name"`
	File           string    `json:"file"`
	FileSHA256Hex  string    `json:"file_sha256_hex"`
	Expect         string    `json:"expect"`
	Verdict        string    `json:"verdict"`
	Posterior      []float64 `json:"posterior"`
	VoteCount      uint32    `json:"vote_count"`
	UnknownVoters  uint32    `json:"unknown_voters"`
	BitIdenticalTo string    `json:"bit_identical_to"`
	// Boundary is D-AQ: the generator placed this case within a few ulps of a Chow
	// threshold, so the exact-rational oracle is NOT authoritative on its verdict —
	// it rounds once, a float64 leg rounds per multiply. Cross-leg identity is
	// asserted instead, by conformance_crosslang.sh's hex diff.
	Boundary bool `json:"boundary"`
}

type fusionManifest struct {
	Classes   []string       `json:"classes"`
	Tolerance float64        `json:"tolerance"`
	Vectors   []fusionExpect `json:"vectors"`
}

var fusionVerdictName = map[m1pv1.Verdict]string{
	m1pv1.Verdict_VERDICT_SATISFIED: "satisfied",
	m1pv1.Verdict_VERDICT_VIOLATED:  "violated",
	m1pv1.Verdict_VERDICT_REFUSED:   "refused",
	m1pv1.Verdict_VERDICT_ERROR:     "error",
}

var fusionWireVerdict = map[string]m1pv1.Verdict{
	"satisfied": m1pv1.Verdict_VERDICT_SATISFIED,
	"violated":  m1pv1.Verdict_VERDICT_VIOLATED,
	"refused":   m1pv1.Verdict_VERDICT_REFUSED,
	"error":     m1pv1.Verdict_VERDICT_ERROR,
}

func loadFusionInput(t *testing.T, v fusionExpect) fusionInput {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(fusionVectorsDir, v.File))
	if err != nil {
		t.Fatalf("%s: reading vector: %v", v.Name, err)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != v.FileSHA256Hex {
		t.Fatalf("%s: vector bytes drifted from the frozen manifest digest", v.Name)
	}
	var in fusionInput
	if err := json.Unmarshal(raw, &in); err != nil {
		t.Fatalf("%s: parsing vector: %v", v.Name, err)
	}
	return in
}

func (in fusionInput) matrices() BundleMatrices {
	m := BundleMatrices{Priors: in.Priors, Verifiers: map[string]VerifierParams{}}
	for id, spec := range in.Verifiers {
		// FromBundle drops quarantined rows rather than zeroing them; the
		// vectors are written against that, so the driver must do the same.
		if spec.Quarantined {
			continue
		}
		m.Verifiers[id] = VerifierParams{Confusion: Confusion(spec.Confusion), Group: spec.Group}
	}
	return m
}

func (in fusionInput) anchorVotes(t *testing.T) []AnchorVote {
	t.Helper()
	out := make([]AnchorVote, 0, len(in.Votes))
	for _, v := range in.Votes {
		w, ok := fusionWireVerdict[v.Verdict]
		if !ok {
			t.Fatalf("%s: vector names unknown wire verdict %q", in.Name, v.Verdict)
		}
		out = append(out, AnchorVote{AnchorID: v.VerifierID, Vote: w, Tamper: v.Tamper})
	}
	return out
}

// dumpPosterior is D-AP's cross-leg bit-identity control. The manifest cannot carry
// this claim: its 1e-12 tolerance is ~4 orders looser than an ulp at these magnitudes,
// and the oracle is exact-rational while both legs are float64 — an independent
// generator and a bit-comparable manifest are mutually exclusive. So the bit assertion
// moves to where BOTH operands are floats: each leg appends the raw IEEE-754 bits of
// every posterior it computed and tools/ci/conformance_crosslang.sh diffs the files.
// Raw bits rather than %x formatting, which does not agree with Python's float.hex().
func dumpPosterior(t *testing.T, name, verdict string, post []float64) {
	t.Helper()
	path := os.Getenv("M1_POSTHEX_OUT")
	if path == "" {
		return
	}
	line := name + " " + verdict
	for _, x := range post {
		line += " " + hex.EncodeToString(binary.BigEndian.AppendUint64(nil, math.Float64bits(x)))
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("opening %s: %v", path, err)
	}
	if _, err := f.WriteString(line + "\n"); err != nil {
		_ = f.Close()
		t.Fatalf("writing %s: %v", path, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

func TestConfVectorsFusion(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(fusionVectorsDir, "manifest.json"))
	if err != nil {
		t.Fatalf("reading manifest: %v", err)
	}
	var man fusionManifest
	if err := json.Unmarshal(raw, &man); err != nil {
		t.Fatalf("parsing manifest: %v", err)
	}
	// A truncated manifest would pass every remaining assertion vacuously.
	if len(man.Vectors) == 0 || man.Tolerance <= 0 {
		t.Fatalf("manifest is empty or has no tolerance: %d vectors, tol %g", len(man.Vectors), man.Tolerance)
	}

	posteriors := map[string][]float64{}
	for _, want := range man.Vectors {
		t.Run(want.Name, func(t *testing.T) {
			in := loadFusionInput(t, want)
			m := in.matrices()
			f := &Fuser{m: m}
			got := f.Fuse(TaskID{}, in.anchorVotes(t))

			if want.Expect == "zero_mass" {
				// The bundle assigns probability 0 to every class: a broken
				// bundle, not a verdict. The cloud raises; this signature
				// cannot, so it answers the latent error class — both refuse,
				// neither invents a posterior (README, "Refusals").
				if got.Verdict != m1pv1.Verdict_VERDICT_ERROR || got.Posterior[ixError] != 1.0 {
					t.Fatalf("zero-mass bundle: verdict %v posterior %v, want degenerate error", got.Verdict, got.Posterior)
				}
				return
			}
			if len(got.Posterior) != 4 {
				t.Fatalf("posterior arity %d, want exactly 4 (frozen wire invariant)", len(got.Posterior))
			}
			for i, w := range want.Posterior {
				if math.IsNaN(got.Posterior[i]) {
					t.Fatalf("posterior[%s] is NaN", man.Classes[i])
				}
				if math.Abs(got.Posterior[i]-w) > man.Tolerance {
					t.Fatalf("posterior[%s] = %.17g, want %.17g (Δ %.3g > tol %g)", man.Classes[i], got.Posterior[i], w, got.Posterior[i]-w, man.Tolerance)
				}
			}
			dumpPosterior(t, want.Name, fusionVerdictName[got.Verdict], got.Posterior)
			// D-AQ: at a case built to sit ON a threshold, "float64 cannot reach the
			// exact rational answer" is not "the two legs disagree", and one red for
			// both is one number for two defects. The verdict of a boundary vector is
			// asserted ACROSS the legs (conformance_crosslang.sh), not against the
			// oracle. Interior vectors keep both.
			if !want.Boundary && fusionVerdictName[got.Verdict] != want.Verdict {
				t.Fatalf("verdict %s, want %s", fusionVerdictName[got.Verdict], want.Verdict)
			}
			if got.VoteCount != want.VoteCount {
				t.Fatalf("vote_count %d, want %d", got.VoteCount, want.VoteCount)
			}
			if n := unknownVoters(&m, in.anchorVotes(t)); n != want.UnknownVoters {
				t.Fatalf("unknown_voters %d, want %d (D-X accounting)", n, want.UnknownVoters)
			}
			posteriors[want.Name] = got.Posterior
		})
	}

	// Bit-exactness within the language: the sorted-group rule, which a
	// tolerance can never police — reordering the log-sum moves the posterior
	// by one ulp, which is enough to flip a verdict on a Chow threshold.
	for _, want := range man.Vectors {
		if want.BitIdenticalTo == "" {
			continue
		}
		a, b := posteriors[want.Name], posteriors[want.BitIdenticalTo]
		if a == nil || b == nil {
			t.Fatalf("%s: bit_identical_to names a vector that did not run", want.Name)
		}
		for i := range a {
			if a[i] != b[i] {
				t.Fatalf("%s vs %s: posterior[%s] %.17g != %.17g — groups are not summed in sorted id order", want.Name, want.BitIdenticalTo, man.Classes[i], a[i], b[i])
			}
		}
	}
}
