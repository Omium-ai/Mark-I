//! Session scoping, `index_clock`, and the memory-artifact recall cache
//! (04 §6 tree). One `Shared` per workspace: the writer task mutates `Index`
//! behind the lock, MCP query tasks read snapshots + the atomic clock
//! (04 §6.3 single-writer discipline).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64};
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use rand::RngCore;

use crate::l0_merkle::MerkleTree;
use crate::l1_tags::Tag;
use crate::l2_graph::SymbolGraph;
use crate::map::MapRender;

/// 04 §6.4: session-start map token budget — default 2k, ceiling 8k,
/// bundle-tunable via the `cortex` section (constants until bundle plumbing).
pub const DEFAULT_BUDGET_TOKENS: u32 = 2_000;
/// 08 §6: per-call floor/ceiling on `max_tokens`, and the per-turn cap.
pub const MIN_CALL_TOKENS: u32 = 256;
pub const MAX_CALL_TOKENS: u32 = 8_000;
pub const TURN_BUDGET_TOKENS: u32 = 8_000;

/// How many recent-edit paths seed the session-map PPR (04 §6.4 "live
/// recent-edit set"). ponytail: fixed cap; capture-fed recency lands with
/// mark1d integration.
const RECENT_EDIT_CAP: usize = 32;

pub struct Shared {
    /// Canonicalized workspace root — the scoping prefix for every MCP path
    /// argument (08 §6, M1E-6402).
    pub root: PathBuf,
    /// `~/.omium/mark1/cortex/<workspace_id>/` (04 §6.2).
    pub store: PathBuf,
    pub index: RwLock<Index>,
    /// Monotonic index generation (04 §6.1); stamped on every answer.
    pub index_clock: AtomicU64,
    /// Set during initial index / overflow rescan: queries refuse M1E-6401
    /// with `retry_after_ms` — refusal beats fabrication (04 §6.3).
    pub stale: AtomicBool,
    /// Set on shard corruption until reindexed: queries refuse M1E-6404.
    pub broken: AtomicBool,
    /// Per-boot loopback bearer token (08 §4.5), hex; written to the 0600
    /// discovery file, compared constant-time, never logged.
    pub token: String,
    /// Session-turn budget spent across calls (08 §6 "8,000 per session turn").
    pub turn_used: AtomicU32,
    /// Wall-clock millis of the last MCP call — the mcp module's turn-boundary
    /// heuristic (a ≥30 s gap resets `turn_used`).
    pub last_call_ms: AtomicU64,
    pub default_budget: u32,
    /// Dropped fabric pushes (08 §4.4: recomputable, counted, never blocking).
    /// Nobody listening only — a refusal is a different fact and gets its own
    /// counter below.
    pub fabric_dropped: AtomicU64,
    /// Pushes mark1d refused with M1E-4003 (08 §4.3). Today that is every push
    /// against a live daemon: D-AT requires a 16-byte non-zero `session_id`
    /// and cortexd has no session identity to give until the MCP surface
    /// carries one (D-AV). Counting it is what makes that gap a number.
    pub fabric_handshake_refused: AtomicU64,
}

impl Shared {
    pub fn new(root: PathBuf, store: PathBuf, default_budget: u32) -> Self {
        Shared {
            root,
            store,
            index: RwLock::new(Index::default()),
            index_clock: AtomicU64::new(0),
            stale: AtomicBool::new(true), // honest until the first settle
            broken: AtomicBool::new(false),
            token: fresh_token(),
            turn_used: AtomicU32::new(0),
            last_call_ms: AtomicU64::new(0),
            default_budget: default_budget.clamp(MIN_CALL_TOKENS, MAX_CALL_TOKENS),
            fabric_dropped: AtomicU64::new(0),
            fabric_handshake_refused: AtomicU64::new(0),
        }
    }
}

/// Lock helpers: a poisoned lock means a reader panicked mid-read; the index
/// itself is only mutated under the single writer, so the data is intact —
/// recover the guard instead of panicking the daemon (no-panic rule, 13 §7.2).
pub trait LockExt<T> {
    fn read_recover(&self) -> RwLockReadGuard<'_, T>;
    fn write_recover(&self) -> RwLockWriteGuard<'_, T>;
}

impl<T> LockExt<T> for RwLock<T> {
    fn read_recover(&self) -> RwLockReadGuard<'_, T> {
        self.read().unwrap_or_else(|e| e.into_inner())
    }
    fn write_recover(&self) -> RwLockWriteGuard<'_, T> {
        self.write().unwrap_or_else(|e| e.into_inner())
    }
}

// Ergonomics: `shared.index.read()` in the rest of the crate means the
// recovering variants above.
impl Shared {
    pub fn snapshot(&self) -> RwLockReadGuard<'_, Index> {
        self.index.read_recover()
    }
}

#[derive(Default)]
pub struct Index {
    pub merkle: MerkleTree,
    /// rel path → tags; the L1 plane (04 §6.1).
    pub tags: BTreeMap<String, Vec<Tag>>,
    pub graph: SymbolGraph,
    /// Most-recent-first, deduped — the PPR seed for the session map.
    pub recent_edits: Vec<String>,
    /// Precomputed at settle (04 §6.4); a SessionStart serve is a read.
    pub session_map: Option<MapRender>,
}

impl Index {
    pub fn note_edit(&mut self, path: String) {
        self.recent_edits.retain(|p| p != &path);
        self.recent_edits.insert(0, path);
        self.recent_edits.truncate(RECENT_EDIT_CAP);
    }
}

/// 256 bits of OS randomness, hex-encoded. blake3's hex encoder is reused so
/// no hex dependency is added; hashing does not reduce the entropy drawn.
fn fresh_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    blake3::hash(&bytes).to_hex().to_string()
}

/// `memory_recall` (08 §6.6) serves from the locally-synced tenant artifact
/// cache maintained by `mark1-intel.memory`. No sync path exists at Phase 2,
/// so the cache is honestly empty: `{ "artifacts": [] }` is the specified
/// honest-empty, never a refusal and never fabricated content.
pub fn recall_artifacts(_query: &str, _kinds: &[String], _limit: u32) -> Vec<serde_json::Value> {
    Vec::new()
}

// Index poisoning note: the `RwLock` import list above intentionally excludes
// PoisonError — recovery goes through LockExt only, so a grep for
// `.unwrap()` in src stays empty (workspace lints deny it anyway).

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_fresh_and_hex() {
        let a = fresh_token();
        let b = fresh_token();
        assert_ne!(a, b);
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn recent_edits_dedupe_and_cap() {
        let mut idx = Index::default();
        for i in 0..40 {
            idx.note_edit(format!("f{i}.rs"));
        }
        idx.note_edit("f5.rs".into());
        assert_eq!(idx.recent_edits[0], "f5.rs");
        assert_eq!(idx.recent_edits.len(), RECENT_EDIT_CAP);
        assert_eq!(idx.recent_edits.iter().filter(|p| *p == "f5.rs").count(), 1);
    }
}
