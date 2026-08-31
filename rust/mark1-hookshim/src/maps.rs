//! Per-agent field maps AS DATA (04 §5, 08 §5 rule 1): the vendor-name →
//! `m1p.v1` mapping ships in bundle data so a vendor field rename is an
//! `agent_maps` push reaching the fleet in minutes, not a shim release. The
//! binary fixes only the *kinds* (which body a hook becomes); every vendor
//! string is table data.

use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;

/// The shipped default: the claudecode map, pinned to the fixture corpus at
/// `conformance/hooks/claudecode@2.1.251` (08 §5 rule 3: the fixture
/// produces the field map; nothing is authored from memory).
const BUILTIN_CLAUDECODE: &str = include_str!("../maps/claudecode.json");

/// ponytail: claudecode is the only Phase-1 agent, so agent selection is a
/// constant; the daemon-materialized cache path is keyed by it so the
/// multi-agent selection lands as data when more maps exist (04 §2.10).
const AGENT: &str = "claudecode";

#[derive(Deserialize)]
pub struct FieldMap {
    pub agent: String,
    pub agent_version: String,
    /// Vendor field naming the hook event (`hook_event_name` on claudecode).
    pub event_field: String,
    pub session_id_field: String,
    pub events: HashMap<String, EventRule>,
}

#[derive(Deserialize)]
pub struct EventRule {
    /// Binary-fixed semantic: which `m1p.v1` body this hook becomes — see
    /// `emit::build`. Unknown kinds map to nothing (never guess, 08 §5).
    pub kind: String,
    /// Present ⇒ this hook is a gate (04 §5 step 5); absent ⇒ pure observer.
    /// WHICH hooks gate is bundle data for the same reason the field names
    /// are: 08 §5.1 makes `Stop` the stop-gate and `SubagentStop`
    /// observer-only, and that is a vendor fact, not a shim semantic.
    #[serde(default)]
    pub gate: Option<GateRule>,
    /// logical name (binary-fixed) → vendor JSON field (bundle data).
    pub fields: HashMap<String, String>,
}

#[derive(Deserialize)]
pub struct GateRule {
    /// `m1p.v1.GateKind`, named in data: "stop" | "tool".
    pub kind: String,
    /// The shim's own wall budget for the whole gate round trip, in ms. 08
    /// §4.4 bounds it from ABOVE by the fragment's hook timeout minus 10 ms
    /// (`timeout: 30` for Stop, 08 §5.1) — an upper bound, not the value. The
    /// value is what the round trip actually costs: 04 §2.3 makes the daemon's
    /// side a ≤5 ms cache read, so 250 ms is the whole exchange getting what
    /// 08 §4.4 already grants ONE event write, and 50x the documented read.
    ///
    /// Sized this way because the fragment's number is a kill deadline, not a
    /// budget: at 30 s a daemon that accepts the connection and never answers
    /// cost 31.4 s per turn end against 217 ms for a daemon that was not
    /// running at all — a half-dead Mark 1 145x worse than an absent one, on
    /// the hook that fires every turn. The shim subtracts 08 §4.4's 10 ms
    /// margin to get the agent-facing deadline it states on the wire.
    pub budget_ms: u32,
}

impl FieldMap {
    /// The rule this payload's hook maps to, or None when the hook is
    /// unmapped (04 §5 step 2: emit nothing speculative).
    pub fn rule(&self, payload: &serde_json::Value) -> Option<&EventRule> {
        self.events.get(payload.get(&self.event_field)?.as_str()?)
    }
}

/// The daemon-materialized cache wins over the builtin so a bundle push
/// updates behavior with no binary change (FR-AGENT-001); any read or parse
/// failure falls back to the shipped map rather than guessing.
pub fn load(home: Option<&Path>) -> FieldMap {
    if let Some(h) = home {
        // 04 §5: ~/.omium/mark1/maps/<agent>.bin, pre-compiled by mark1d.
        // ponytail: "pre-compiled" is JSON bytes in v1 — parse cost on a
        // ~1 KiB map is microseconds; a binary format buys nothing until a
        // map is large enough to measure.
        let cached = h.join(".omium/mark1/maps").join(format!("{AGENT}.bin"));
        if let Ok(bytes) = std::fs::read(cached) {
            if let Ok(map) = serde_json::from_slice::<FieldMap>(&bytes) {
                return map;
            }
        }
    }
    // The builtin is compiled from a committed fixture-derived file; if it
    // ever failed to parse the binary itself is broken, and emitting nothing
    // (empty map) is the only honest fallback — never a panic (04 §5).
    serde_json::from_str(BUILTIN_CLAUDECODE).unwrap_or(FieldMap {
        agent: AGENT.to_owned(),
        agent_version: String::new(),
        event_field: String::new(),
        session_id_field: String::new(),
        events: HashMap::new(),
    })
}
