// Typed, allocation-final PolicyBundle structs (04 §7.3) — the Go rendering
// of rust/mark1-policy/src/types.rs. Field shapes restate 07 §"PolicyBundle
// v1" CDDL; this file adds nothing the CDDL does not carry.

package policy

// Section is one of the six section classes — one Ed25519 signing key per
// class (05 §4.5), so this enum is also the index into SectionKeys.
type Section int

const (
	SectionVerify Section = iota
	SectionRoute
	SectionMemory
	SectionCortex
	SectionGates
	SectionAgentMaps
	numSections
)

var sectionNames = [numSections]string{"verify", "route", "memory", "cortex", "gates", "agent_maps"}

// Name is the CDDL `section-name` production, verbatim.
func (s Section) Name() string { return sectionNames[s] }

// AllSections in envelope order — signature checks walk this.
func AllSections() [numSections]Section {
	return [numSections]Section{
		SectionVerify, SectionRoute, SectionMemory,
		SectionCortex, SectionGates, SectionAgentMaps,
	}
}

// Posterior4 is a base-rate/likelihood row over the FIXED verdict order
// (satisfied, violated, refused, error) — 07's `posterior4`.
type Posterior4 [4]float64

// Signal3 is a distribution over the OBSERVED SIGNAL order (accept, reject,
// abstain) — 07's `signal3` (D-R): the vote vocabulary ADJUDICATE consumes.
type Signal3 [3]float64

// TlogHead is a pinned transparency-log head — the caller-held evidence D-S
// makes the inclusion check verify AGAINST (05 §4.4 "against the PINNED log
// head"). This package only compares; pinning is the caller's.
type TlogHead struct {
	TreeSize uint64
	Root     [32]byte
}

// TlogInclusion is the bundle's own inclusion claim, surfaced
// post-verification so a caller can audit. Nil exactly at seq == 0 — D-P's
// pre-log waiver.
type TlogInclusion struct {
	LeafIndex uint64
	TreeSize  uint64
	Root      [32]byte
}

// Bundle is the verified, decoded bundle (04 §7.3), plus the envelope fields
// a caller needs for the ACK, max_age staleness math and next-bundle
// prev_hash linkage.
type Bundle struct {
	TenantID [16]byte
	Channel  string
	Seq      uint64
	// Tag-1 epoch seconds, as signed-adjacent metadata for max_age math.
	IssuedAtEpochS uint64
	// Seconds, not time.Duration: max_age is a CDDL uint whose full u64
	// range must survive parse (a hostile u64::MAX would overflow a
	// nanosecond Duration before the signature check could kill it).
	MaxAgeS  uint64
	PrevHash [32]byte
	// SHA-256 of this bundle's canonical body bytes (the map minus
	// `inclusion` — m1_009's body_sha256): the ACK bundle_hash, the tlog
	// leaf, and the value the NEXT bundle's prev_hash must equal.
	BodySHA256 [32]byte
	// The verified inclusion coordinates (D-S) — nil at seq == 0 only.
	Tlog      *TlogInclusion
	Verify    VerifySection
	Route     RouteSection
	Memory    MemorySection
	Cortex    CortexSection
	Gates     GatesSection
	AgentMaps AgentMaps
}

// IsFresh is the fail-static staleness EVALUATION (04 §7.3), the twin of
// types.rs Bundle::is_fresh: true = within max_age at nowEpochS (boundary
// inclusive: the CDDL says "past it", so age == max_age is still fresh);
// false = STALE, and the caller falls to its conservative built-in defaults —
// never to a newer unverified bundle. now before issued_at (clock skew, a
// stepped clock) counts as fresh: staleness measures age, and a negative age
// is zero age. LKG persistence is deliberately NOT here — a verify+decode
// package has no filesystem; the pure function is the shared half.
func (b *Bundle) IsFresh(nowEpochS uint64) bool {
	if nowEpochS < b.IssuedAtEpochS {
		return true
	}
	return nowEpochS-b.IssuedAtEpochS <= b.MaxAgeS
}

// ── verify: everything C3's fusion needs ────────────────────────────────

type VerifySection struct {
	Anchors []AnchorEnable
	// Index order is the verifier handle everywhere below — fusion never
	// touches a verifier_id string after decode.
	Verifiers         []VerifierModel
	Priors            Posterior4
	CorrelationGroups []CorrelationGroup
	// Parallel to Verifiers: true = fusion must ignore this verifier's
	// votes (07's `quarantine` list, resolved to indices at decode).
	Quarantined []bool
}

type AnchorEnable struct {
	// An ID into the LOCAL consented catalog — never a command (07 rule 2).
	CatalogID  string
	Enabled    bool
	Thresholds []Threshold
	// Nil = absent.
	DebounceMs *uint64
}

type Threshold struct {
	Key   string
	Value float64
}

type VerifierModel struct {
	VerifierID string
	// D-R (07 `confusion4x3`): row = TRUE verdict (satisfied, violated,
	// refused, error — order fixed), column = OBSERVED SIGNAL (accept,
	// reject, abstain).
	Confusion [4]Signal3
}

type CorrelationGroup struct {
	GroupID string
	// Indices into VerifySection.Verifiers; a group counts once in fusion.
	Members []uint32
}

// ── route: ladders, knees, exploration ──────────────────────────────────

type RouteSection struct {
	Cpvs    []CpvsRow
	Ladders []Ladder
	Knee    KneeTable
	// `exploration.epsilon`, defaulted to 0.0 when the map is absent —
	// ε>0 is per-tenant contractual opt-in (07 CDDL comment).
	// D-EF: refused at decode under a signed `exploration_opt_in: false`; the edge applies ε>0 only via fabric.ExplorationEpsilon.
	ExplorationEpsilon float64
}

type CpvsRow struct {
	TaskClass string
	ModelID   string
	PPass     float64
	TokensEst uint64
}

type Ladder struct {
	LadderID string
	Rungs    []Rung
}

type Rung struct {
	ModelID    string
	KeepPrefix bool
}

// CostBasis is 07's DUAL cost basis: usd for API-key tenants, quota for
// subscription tenants — a closed enum, so a typo'd basis is a decode reject.
type CostBasis int

const (
	CostBasisUsd CostBasis = iota
	CostBasisQuota
)

type KneeTable struct {
	CostBasis CostBasis
	// c(n) at attempt n; the gate stops when p̂_LCB(n)·V(task) ≤ c(n).
	Rows     []KneeRow
	VDefault float64
}

type KneeRow struct {
	N  uint64
	CN float64
	// D-Z: p_lcb is OPTIONAL on the wire and 0.0 is a legitimate lower bound,
	// so absent and zero MUST stay distinguishable — absent means the knee is
	// not evaluable at that n (never stop), zero means it always is.
	PLCB *float64
}

// ── memory / cortex / gates ─────────────────────────────────────────────

type MemorySection struct {
	InjectionRules []InjectionRule
	PackTokensMax  uint64
}

type InjectionRule struct {
	Facet    string
	MaxItems *uint64 // nil = absent
}

type CortexChannel int

const (
	CortexSessionStart CortexChannel = iota
	CortexPromptSubmit
	CortexBeforeModel
)

type CortexSection struct {
	// Budget-binary-search bounds; decode enforces min ≤ max.
	MapBudgetTokensMin uint64
	MapBudgetTokensMax uint64
	Channels           []CortexChannel
	// nil = absent: no learned ranker, cortexd serves PPR order (06 §12.4).
	LearnedRanker *LearnedRanker
}

// RankerStage is the closed enum on the wire; decode admits only the three.
type RankerStage string

const (
	RankerProbation RankerStage = "probation"
	RankerShadow    RankerStage = "shadow"
	RankerActive    RankerStage = "active"
)

// LearnedRanker's 4 coefficients are cortexd's file features
// [fan_in, recency, path_depth, tag_count].
type LearnedRanker struct {
	Stage RankerStage
	// Blend weight in [0,1]; decode refuses outside it (M1E-3001).
	Weight       float64
	Bias         float64
	Coefficients [4]float64
}

type GatesSection struct {
	StopGateEnabled bool
	// CDDL `.le 3`: a bundle may LOWER the local hard cap, never raise it.
	MaxConsecutiveBlocks uint8
	HourlyBlockCeiling   uint64
}

// ── agent_maps: vendor formats as DATA ──────────────────────────────────

type AgentMaps struct {
	Agents []AgentMap
}

type AgentMap struct {
	AgentID      string
	AgentVersion string
	// m1p field → RFC 6901 pointer into the vendor hook payload. A pointer
	// is structurally incapable of naming a command (07 CDDL comment).
	HookFields []FieldMap
	// Transcript extraction rules, same pointer discipline.
	TailerRules []FieldMap
}

type FieldMap struct {
	Key     string
	Pointer string
}
