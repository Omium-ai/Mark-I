//! Typed, allocation-final PolicyBundle structs (04 §7.3): what the gate and
//! route paths evaluate after `verify_and_decode` — no map lookups and no
//! string compares on the hot path. Field shapes restate 07 §"PolicyBundle v1"
//! CDDL; this file adds nothing the CDDL does not carry.

use std::time::Duration;

/// The six section classes — one Ed25519 signing key per class (05 §4.5), so
/// this enum is also the index into [`crate::SectionKeys`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    Verify,
    Route,
    Memory,
    Cortex,
    Gates,
    AgentMaps,
}

impl Section {
    pub const ALL: [Section; 6] = [
        Section::Verify,
        Section::Route,
        Section::Memory,
        Section::Cortex,
        Section::Gates,
        Section::AgentMaps,
    ];

    /// The CDDL `section-name` production, verbatim.
    pub fn name(self) -> &'static str {
        match self {
            Section::Verify => "verify",
            Section::Route => "route",
            Section::Memory => "memory",
            Section::Cortex => "cortex",
            Section::Gates => "gates",
            Section::AgentMaps => "agent_maps",
        }
    }

    pub(crate) fn index(self) -> usize {
        self as usize
    }
}

/// Base-rate / likelihood row over the FIXED verdict order
/// (satisfied, violated, refused, error) — 07's `posterior4`.
pub type Posterior4 = [f64; 4];

/// Distribution over the OBSERVED SIGNAL order (accept, reject, abstain) —
/// 07's `signal3` (D-R): the vote vocabulary ADJUDICATE actually consumes.
pub type Signal3 = [f64; 3];

/// A pinned transparency-log head — the caller-held evidence D-S makes the
/// inclusion check verify AGAINST (05 §4.4 "against the PINNED log head").
/// `mark1d.policy` pins heads from `/.well-known/mark1-keys` (08 §7); this
/// crate only compares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlogHead {
    pub tree_size: u64,
    pub root: [u8; 32],
}

/// The bundle's own inclusion claim, surfaced post-verification so a caller
/// can audit (log the witnessed coordinates, cross-check heads out of band).
/// `None` exactly at `seq == 0` — D-P's pre-log waiver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlogInclusion {
    pub leaf_index: u64,
    pub tree_size: u64,
    pub root: [u8; 32],
}

/// The verified, decoded bundle (04 §7.3's `Bundle`, plus the envelope fields
/// a caller needs for the ACK, `max_age` staleness math and next-bundle
/// `prev_hash` linkage).
#[derive(Debug, Clone, PartialEq)]
pub struct Bundle {
    pub tenant_id: [u8; 16],
    pub channel: String,
    pub seq: u64,
    /// Tag-1 epoch seconds, as signed-adjacent metadata for `max_age` math.
    pub issued_at_epoch_s: u64,
    pub max_age: Duration,
    pub prev_hash: [u8; 32],
    /// SHA-256 of this bundle's canonical body bytes (the map minus
    /// `inclusion` — m1_009's `body_sha256`): the ACK `bundle_hash`, the tlog
    /// leaf, and the value the NEXT bundle's `prev_hash` must equal.
    pub body_sha256: [u8; 32],
    /// The verified inclusion coordinates (D-S) — `None` at `seq == 0` only.
    pub tlog: Option<TlogInclusion>,
    pub verify: VerifySection,
    pub route: RouteSection,
    pub memory: MemorySection,
    pub cortex: CortexSection,
    pub gates: GatesSection,
    pub agent_maps: AgentMaps,
}

impl Bundle {
    /// The fail-static staleness EVALUATION (04 §7.3/§807), implemented once
    /// here so cortexd, the proxy and — via the Go twin — mark1d share one
    /// answer instead of three reimplementations of `max_age` arithmetic.
    /// `true` = within `max_age` at `now_epoch_s` (boundary inclusive: the
    /// CDDL says "past it", so age == max_age is still fresh); `false` =
    /// STALE, and the caller falls to its conservative built-in defaults —
    /// never to a newer unverified bundle. `now` before `issued_at` (clock
    /// skew, a stepped clock) counts as fresh: staleness measures age, and a
    /// negative age is zero age. LKG *persistence* is deliberately NOT here —
    /// a verify+decode library has no filesystem; the pure function is the
    /// shared half.
    pub fn is_fresh(&self, now_epoch_s: u64) -> bool {
        now_epoch_s.saturating_sub(self.issued_at_epoch_s) <= self.max_age.as_secs()
    }
}

// ── verify: everything C3's fusion needs ────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct VerifySection {
    pub anchors: Vec<AnchorEnable>,
    /// Index order is the verifier handle everywhere below — fusion never
    /// touches a verifier_id string after decode.
    pub verifiers: Vec<VerifierModel>,
    pub priors: Posterior4,
    pub correlation_groups: Vec<CorrelationGroup>,
    /// Parallel to `verifiers`: `true` = fusion must ignore this verifier's
    /// votes (07's `quarantine` list, resolved to indices at decode).
    pub quarantined: Vec<bool>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AnchorEnable {
    /// An ID into the LOCAL consented catalog — never a command (07 rule 2).
    pub catalog_id: String,
    pub enabled: bool,
    pub thresholds: Vec<(String, f64)>,
    pub debounce_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VerifierModel {
    /// D-R (07 `confusion4x3`): row = TRUE verdict (satisfied, violated,
    /// refused, error — order fixed), column = OBSERVED SIGNAL (accept,
    /// reject, abstain). No verifier emits a verdict — anchors emit signals
    /// and judges are normalized to signals before fusion, so a 4x4
    /// verdict×verdict matrix parameterised an observation model nothing
    /// produces. The former separate `abstention` model is DELETED, not
    /// merged: P(abstain | t) is exactly the third column, and specifying
    /// one quantity in two places is how the Rust and Python halves diverged.
    pub verifier_id: String,
    pub confusion: [Signal3; 4],
}

#[derive(Debug, Clone, PartialEq)]
pub struct CorrelationGroup {
    pub group_id: String,
    /// Indices into `VerifySection::verifiers`; a group counts once in fusion.
    pub members: Vec<u32>,
}

// ── route: ladders, knees, exploration ──────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct RouteSection {
    pub cpvs: Vec<CpvsRow>,
    pub ladders: Vec<Ladder>,
    pub knee: KneeTable,
    /// `exploration.epsilon`, defaulted to 0.0 when the map is absent —
    /// ε>0 is per-tenant contractual opt-in (07 CDDL comment).
    /// D-EF: refused at decode under a signed `exploration_opt_in: false`; the edge applies ε>0 only with the local opt-in artifact.
    pub exploration_epsilon: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CpvsRow {
    pub task_class: String,
    pub model_id: String,
    pub p_pass: f64,
    pub tokens_est: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Ladder {
    pub ladder_id: String,
    pub rungs: Vec<Rung>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rung {
    pub model_id: String,
    pub keep_prefix: bool,
}

/// DUAL cost basis (07): usd for API-key tenants, quota for subscription
/// tenants — a closed enum, so a typo'd basis is a decode reject.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CostBasis {
    Usd,
    Quota,
}

#[derive(Debug, Clone, PartialEq)]
pub struct KneeTable {
    pub cost_basis: CostBasis,
    /// `c(n)` at attempt `n`; the gate stops when `p̂_LCB(n)·V(task) ≤ c(n)`.
    pub rows: Vec<KneeRow>,
    pub v_default: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct KneeRow {
    pub n: u64,
    pub c_n: f64,
    /// D-Z: OPTIONAL on the wire, and 0.0 is a legitimate lower bound, so
    /// absent and zero MUST stay distinguishable — absent means the knee is
    /// not evaluable at that n (never stop), zero means it always is.
    pub p_lcb: Option<f64>,
}

// ── memory / cortex / gates ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct MemorySection {
    pub injection_rules: Vec<InjectionRule>,
    pub pack_tokens_max: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct InjectionRule {
    pub facet: String,
    pub max_items: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CortexChannel {
    SessionStart,
    PromptSubmit,
    BeforeModel,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CortexSection {
    /// Budget-binary-search bounds; decode enforces min ≤ max.
    pub map_budget_tokens_min: u64,
    pub map_budget_tokens_max: u64,
    pub channels: Vec<CortexChannel>,
    /// Absent ⇒ no learned ranker: cortexd serves PPR order (06 §12.4).
    pub learned_ranker: Option<LearnedRanker>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RankerStage {
    Probation,
    Shadow,
    Active,
}

impl RankerStage {
    pub fn name(self) -> &'static str {
        match self {
            RankerStage::Probation => "probation",
            RankerStage::Shadow => "shadow",
            RankerStage::Active => "active",
        }
    }
}

/// The 4 coefficients are cortexd's file features `[fan_in, recency, path_depth, tag_count]`.
#[derive(Debug, Clone, PartialEq)]
pub struct LearnedRanker {
    pub stage: RankerStage,
    /// Blend weight in [0,1]; decode refuses outside it (M1E-3001).
    pub weight: f64,
    pub bias: f64,
    pub coefficients: [f64; 4],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatesSection {
    pub stop_gate_enabled: bool,
    /// CDDL `.le 3`: a bundle may LOWER the local hard cap, never raise it.
    pub max_consecutive_blocks: u8,
    pub hourly_block_ceiling: u64,
}

// ── agent_maps: vendor formats as DATA ──────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct AgentMaps {
    pub agents: Vec<AgentMap>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AgentMap {
    pub agent_id: String,
    pub agent_version: String,
    /// m1p field → RFC 6901 pointer into the vendor hook payload. A pointer
    /// is structurally incapable of naming a command (07 CDDL comment).
    pub hook_fields: Vec<(String, String)>,
    /// Transcript extraction rules, same pointer discipline.
    pub tailer_rules: Vec<(String, String)>,
}
