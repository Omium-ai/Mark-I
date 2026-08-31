// TestConfVectorsBundle* drive conformance/vectors/bundle/manifest.json —
// the frozen cross-language byte contract for PolicyBundle v1 (12 §3.4;
// vectors README). The `ConfVectors` name prefix is load-bearing:
// conformance_crosslang.sh selects Go tests with -run ConfVectors and counts
// this family via ConfVectorsBundle, and a run that executes zero vector
// tests is a failed run, not a passed one.

package policy

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const bundleVectorsDir = "../../../../conformance/vectors/bundle"

type bundleVectorKey struct {
	SeedHex   string `json:"seed_hex"`
	PublicHex string `json:"public_hex"`
	KeyID     string `json:"key_id"`
}

type bundleTlogHead struct {
	RootHex  string `json:"root_hex"`
	TreeSize uint64 `json:"tree_size"`
}

type bundleSummary struct {
	Agents               int     `json:"agents"`
	Anchors              int     `json:"anchors"`
	Channel              string  `json:"channel"`
	CorrelationGroups    int     `json:"correlation_groups"`
	ExplorationEpsilon   float64 `json:"exploration_epsilon"`
	IssuedAtEpochS       uint64  `json:"issued_at_epoch_s"`
	KneeRows             int     `json:"knee_rows"`
	MaxAgeS              uint64  `json:"max_age_s"`
	MaxConsecutiveBlocks uint8   `json:"max_consecutive_blocks"`
	Quarantined          int     `json:"quarantined"`
	Seq                  uint64  `json:"seq"`
	StopGateEnabled      bool    `json:"stop_gate_enabled"`
	Verifiers            int     `json:"verifiers"`
}

type bundleVector struct {
	Name           string          `json:"name"`
	File           string          `json:"file"`
	FileSHA256Hex  string          `json:"file_sha256_hex"`
	Expect         string          `json:"expect"`
	BodySHA256Hex  string          `json:"body_sha256_hex"`
	Code           string          `json:"code"`
	Kind           string          `json:"kind"`
	LastAppliedSeq *uint64         `json:"last_applied_seq"`
	TlogHead       *bundleTlogHead `json:"tlog_head"`
	Summary        *bundleSummary  `json:"summary"`
}

type bundleManifest struct {
	Schema     string                     `json:"schema"`
	TenantHex  string                     `json:"tenant_id_hex"`
	Keys       map[string]bundleVectorKey `json:"keys"`
	ExpiredKey struct {
		bundleVectorKey
		Section  string `json:"section"`
		NotAfter string `json:"not_after"`
	} `json:"expired_key"`
	Vectors []bundleVector `json:"vectors"`
}

func loadBundleManifest(t *testing.T) *bundleManifest {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(bundleVectorsDir, "manifest.json"))
	if err != nil {
		t.Fatalf("reading manifest: %v", err)
	}
	var m bundleManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("parsing manifest: %v", err)
	}
	// Guard against a truncated or hand-edited manifest: a family with
	// missing entries would pass every remaining assertion vacuously.
	if len(m.Keys) != int(numSections) || len(m.Vectors) == 0 {
		t.Fatalf("manifest families empty: keys=%d vectors=%d", len(m.Keys), len(m.Vectors))
	}
	if m.Schema != Schema {
		t.Fatalf("manifest schema %q != decoder schema %q", m.Schema, Schema)
	}
	return &m
}

func bundleUnhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex in manifest: %v", err)
	}
	return b
}

// bundleKeys publishes the manifest's six section-class keys plus the
// rotated-out expired_key into the ring of its section, asserting each
// derived key_id against the manifest's.
func bundleKeys(t *testing.T, m *bundleManifest) *SectionKeys {
	t.Helper()
	sk := NewSectionKeys()
	for _, section := range AllSections() {
		k, ok := m.Keys[section.Name()]
		if !ok {
			t.Fatalf("manifest has no key for section %s", section.Name())
		}
		pub := ed25519.PublicKey(bundleUnhex(t, k.PublicHex))
		if got := sk.Insert(section, KeyEntry{Public: pub}); got != k.KeyID {
			t.Fatalf("section %s: derived key_id %s != manifest %s", section.Name(), got, k.KeyID)
		}
		// The seeds are TEST-ONLY and published; prove they derive the
		// published public key so a corrupted manifest cannot pass silently.
		priv := ed25519.NewKeyFromSeed(bundleUnhex(t, k.SeedHex))
		if !pub.Equal(priv.Public().(ed25519.PublicKey)) {
			t.Fatalf("section %s: seed does not derive public key", section.Name())
		}
	}
	var expiredSection Section
	found := false
	for _, s := range AllSections() {
		if s.Name() == m.ExpiredKey.Section {
			expiredSection, found = s, true
		}
	}
	if !found {
		t.Fatalf("expired_key names unknown section %q", m.ExpiredKey.Section)
	}
	pub := ed25519.PublicKey(bundleUnhex(t, m.ExpiredKey.PublicHex))
	if got := sk.Insert(expiredSection, KeyEntry{Public: pub, NotAfter: m.ExpiredKey.NotAfter}); got != m.ExpiredKey.KeyID {
		t.Fatalf("expired_key: derived key_id %s != manifest %s", got, m.ExpiredKey.KeyID)
	}
	return sk
}

func readVectorFile(t *testing.T, v *bundleVector) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(bundleVectorsDir, v.File))
	if err != nil {
		t.Fatalf("reading %s: %v", v.File, err)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != v.FileSHA256Hex {
		t.Fatalf("%s: file bytes do not match manifest file_sha256_hex — vectors are frozen", v.File)
	}
	return raw
}

func vectorHead(v *bundleVector) *TlogHead {
	if v.TlogHead == nil {
		return nil
	}
	root, err := hex.DecodeString(v.TlogHead.RootHex)
	if err != nil || len(root) != 32 {
		panic("manifest tlog_head root_hex is not 32 bytes")
	}
	return &TlogHead{TreeSize: v.TlogHead.TreeSize, Root: [32]byte(root)}
}

// TestConfVectorsBundle drives EVERY manifest entry: accepts assert
// body_sha256_hex plus all summary fields against the decode; rejects assert
// code AND kind — a negative that fails for the wrong reason is a failure.
func TestConfVectorsBundle(t *testing.T) {
	m := loadBundleManifest(t)
	keys := bundleKeys(t, m)

	accepts, rejects := 0, 0
	kindsSeen := map[string]bool{}
	for i := range m.Vectors {
		v := &m.Vectors[i]
		t.Run(v.Name, func(t *testing.T) {
			raw := readVectorFile(t, v)
			b, rej := VerifyAndDecode(raw, keys, v.LastAppliedSeq, vectorHead(v))
			switch v.Expect {
			case "accept":
				if rej != nil {
					t.Fatalf("expected accept, got %s/%s (%v)", rej.Code(), rej.Kind(), rej)
				}
				if got := hex.EncodeToString(b.BodySHA256[:]); got != v.BodySHA256Hex {
					t.Fatalf("body_sha256 %s != manifest %s", got, v.BodySHA256Hex)
				}
				if v.Summary == nil {
					t.Fatal("accept vector missing summary")
				}
				assertSummary(t, b, v.Summary)
				if v.Seq() == 0 {
					if b.Tlog != nil {
						t.Fatal("seq 0 must surface no inclusion (D-P)")
					}
				} else if b.Tlog == nil || b.Tlog.Root != vectorHead(v).Root || b.Tlog.TreeSize != vectorHead(v).TreeSize {
					t.Fatal("verified inclusion must surface the pinned head's coordinates (D-S)")
				}
			case "reject":
				if rej == nil {
					t.Fatalf("expected reject %s/%s, got accept", v.Code, v.Kind)
				}
				if rej.Code() != v.Code || rej.Kind() != v.Kind {
					t.Fatalf("expected %s/%s, got %s/%s (%v)", v.Code, v.Kind, rej.Code(), rej.Kind(), rej)
				}
			default:
				t.Fatalf("unknown expect %q", v.Expect)
			}
		})
		if v.Expect == "accept" {
			accepts++
		} else {
			rejects++
			kindsSeen[v.Kind] = true
		}
	}
	// The frozen contract: 4 accepts, 20 rejects covering all 10 kinds. A
	// shrunken manifest must fail loudly, not pass vacuously.
	if accepts != 4 || rejects != 20 {
		t.Fatalf("manifest shape changed: accepts=%d rejects=%d", accepts, rejects)
	}
	for _, k := range kindNames {
		if k == "seq_replay" || k == "prev_hash_mismatch" || k == "too_large" ||
			k == "schema" || k == "command_string" || k == "non_canonical" ||
			k == "bad_signature" || k == "unknown_key" || k == "outside_validity" ||
			k == "inclusion_invalid" {
			if !kindsSeen[k] {
				t.Fatalf("manifest no longer exercises reject kind %q", k)
			}
		}
	}
}

// Seq reads the summary seq for accepts; rejects never call it.
func (v *bundleVector) Seq() uint64 { return v.Summary.Seq }

func assertSummary(t *testing.T, b *Bundle, s *bundleSummary) {
	t.Helper()
	check := func(name string, got, want any) {
		if got != want {
			t.Errorf("summary.%s: got %v, want %v", name, got, want)
		}
	}
	check("agents", len(b.AgentMaps.Agents), s.Agents)
	check("anchors", len(b.Verify.Anchors), s.Anchors)
	check("channel", b.Channel, s.Channel)
	check("correlation_groups", len(b.Verify.CorrelationGroups), s.CorrelationGroups)
	check("exploration_epsilon", b.Route.ExplorationEpsilon, s.ExplorationEpsilon)
	check("issued_at_epoch_s", b.IssuedAtEpochS, s.IssuedAtEpochS)
	check("knee_rows", len(b.Route.Knee.Rows), s.KneeRows)
	check("max_age_s", b.MaxAgeS, s.MaxAgeS)
	check("max_consecutive_blocks", b.Gates.MaxConsecutiveBlocks, s.MaxConsecutiveBlocks)
	quarantined := 0
	for _, q := range b.Verify.Quarantined {
		if q {
			quarantined++
		}
	}
	check("quarantined", quarantined, s.Quarantined)
	check("seq", b.Seq, s.Seq)
	check("stop_gate_enabled", b.Gates.StopGateEnabled, s.StopGateEnabled)
	check("verifiers", len(b.Verify.Verifiers), s.Verifiers)
}

func vectorByName(t *testing.T, m *bundleManifest, name string) *bundleVector {
	t.Helper()
	for i := range m.Vectors {
		if m.Vectors[i].Name == name {
			return &m.Vectors[i]
		}
	}
	t.Fatalf("manifest has no vector %q", name)
	return nil
}

// TestConfVectorsBundleSeqZeroReplay: D-P's waiver never re-admits bundle
// zero — once ANY bundle has been applied (last_applied_seq = 0 included),
// seq 0 is a replay (M1E-3002), not a fresh boot.
func TestConfVectorsBundleSeqZeroReplay(t *testing.T) {
	m := loadBundleManifest(t)
	keys := bundleKeys(t, m)
	raw := readVectorFile(t, vectorByName(t, m, "bundle_zero"))
	last := uint64(0)
	_, rej := VerifyAndDecode(raw, keys, &last, nil)
	if rej == nil || rej.Code() != "M1E-3002" || rej.Kind() != "seq_replay" {
		t.Fatalf("expected M1E-3002/seq_replay, got %v", rej)
	}
}

// TestConfVectorsBundleSeqZeroProofPresent: the OTHER half of D-P's
// structural waiver — a seq-0 bundle CARRYING a proof rejects. `inclusion`
// is outside the D-Q signature (a leaf cannot commit to its own proof), so
// splicing one into the signed bundle_zero bytes exercises exactly the
// structural check and nothing else.
func TestConfVectorsBundleSeqZeroProofPresent(t *testing.T) {
	m := loadBundleManifest(t)
	keys := bundleKeys(t, m)
	raw := readVectorFile(t, vectorByName(t, m, "bundle_zero"))
	v, err := decodeCanonical(raw)
	if err != nil {
		t.Fatal(err)
	}
	entries := v.(vmap)
	for i := range entries {
		if entries[i].k == "inclusion" {
			entries[i].v = vmap{
				{"leaf_index", uint64(0)},
				{"path", []any{}},
				{"root", make([]byte, 32)},
				{"tree_size", uint64(1)},
			}
		}
	}
	spliced, err := encodeCanonical(entries)
	if err != nil {
		t.Fatal(err)
	}
	_, rej := VerifyAndDecode(spliced, keys, nil, nil)
	if rej == nil || rej.Code() != "M1E-3003" || rej.Kind() != "inclusion_invalid" {
		t.Fatalf("expected M1E-3003/inclusion_invalid, got %v", rej)
	}
}

// TestConfVectorsBundleKneePLCB: the accept alone only proves the key is
// tolerated. D-Z needs the three states to stay distinct through the decode,
// so assert the values — a decoder that swallowed p_lcb and dropped it would
// still accept the vector.
func TestConfVectorsBundleKneePLCB(t *testing.T) {
	m := loadBundleManifest(t)
	raw := readVectorFile(t, vectorByName(t, m, "knee_p_lcb"))
	b, rej := VerifyAndDecode(raw, bundleKeys(t, m), nil, nil)
	if rej != nil {
		t.Fatalf("knee_p_lcb must accept: %v", rej)
	}
	want := []*float64{nil, ptr(0.0), ptr(0.75)}
	for i, w := range want {
		got := b.Route.Knee.Rows[i].PLCB
		if (got == nil) != (w == nil) || got != nil && *got != *w {
			t.Fatalf("row %d p_lcb: got %v, want %v", i, got, w)
		}
	}
}

func ptr(f float64) *float64 { return &f }

// TestConfVectorsBundleFreshness: the is_fresh staleness twin (04 §7.3) on
// the decoded bundle_zero — boundary INCLUSIVE (age == max_age is fresh),
// clock skew (now < issued_at) is zero age, and the arithmetic saturates.
func TestConfVectorsBundleFreshness(t *testing.T) {
	m := loadBundleManifest(t)
	keys := bundleKeys(t, m)
	raw := readVectorFile(t, vectorByName(t, m, "bundle_zero"))
	b, rej := VerifyAndDecode(raw, keys, nil, nil)
	if rej != nil {
		t.Fatalf("bundle_zero must accept: %v", rej)
	}
	edge := b.IssuedAtEpochS + b.MaxAgeS
	for _, tc := range []struct {
		now  uint64
		want bool
	}{
		{b.IssuedAtEpochS, true},
		{edge, true},      // boundary inclusive: the CDDL says "past it"
		{edge + 1, false}, // one second past is stale
		{0, true},         // now before issued_at: negative age is zero age
	} {
		if got := b.IsFresh(tc.now); got != tc.want {
			t.Errorf("IsFresh(%d) = %v, want %v", tc.now, got, tc.want)
		}
	}
}
