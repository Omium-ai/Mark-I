//! Session scoping, `index_clock`, and the memory-artifact recall cache
//! (04 §6 tree). One `Shared` per workspace: the writer task mutates `Index`
//! behind the lock, MCP query tasks read snapshots + the atomic clock
//! (04 §6.3 single-writer discipline).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64};
use std::sync::{Mutex, OnceLock, RwLock, RwLockReadGuard, RwLockWriteGuard};

use m1p_wire::pb;
use rand::RngCore;
use serde::Deserialize;

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
    /// Pushes mark1d refused with M1E-4003 (08 §4.3): a Hello it would not
    /// accept — a mid-upgrade version, or a session the daemon no longer holds.
    /// Counting it is what makes that a number instead of a silent success.
    pub fabric_handshake_refused: AtomicU64,
    /// Where mark1d publishes this workspace's live agent session
    /// (`--session-file`; go/mark1d/internal/cortex). Unset (a hand-run
    /// cortexd) means no session can ever be read, so every push is held.
    pub session_file: OnceLock<PathBuf>,
    /// Pushes waiting for a session (04 §6.7 root pushes, 04 §6.4 serve
    /// accounting). A held push is NOT a drop: it lands on the next flush
    /// once the daemon publishes a session. Bounded — see `hold`.
    pub pending: Mutex<Vec<pb::Event>>,
    /// L1 CAS probe accounting (04 §6.1: a hit skips the parse). What makes
    /// "a key bump invalidates exactly the affected entries" a number.
    pub cas_hits: AtomicU64,
    pub cas_misses: AtomicU64,
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
            session_file: OnceLock::new(),
            pending: Mutex::new(Vec::new()),
            cas_hits: AtomicU64::new(0),
            cas_misses: AtomicU64::new(0),
        }
    }

    /// The live agent session for this workspace, as mark1d last published it,
    /// or `None` while there is none. Read per push (one small file, ~100
    /// bytes — far inside the 08 §4.4 push budget, so no mtime cache).
    pub fn live_session(&self) -> Option<[u8; 16]> {
        read_live_session(self.session_file.get()?)
    }
}

/// How many pushes wait for a session before the oldest is dropped (counted
/// in `fabric_dropped`, because at that point it IS a loss). Root pushes
/// never accumulate — `hold` keeps only the newest — so this bounds the
/// per-call serve accounting of a tool-calling agent the daemon has not yet
/// attributed to a workspace.
pub const PENDING_CAP: usize = 64;

/// The file mark1d writes at `<state>/run/sessions/<workspace-id>.json`
/// (go/mark1d/internal/cortex sessionFile) — one contract, two decoders.
#[derive(Deserialize)]
struct LiveSession {
    /// 32 hex chars. `started_at` is also on disk and is display-grade; serde
    /// skips what is not declared, so the id is the only field that acts.
    session_id_hex: String,
}

/// D-AT's rule applied at the reader: only a 16-byte non-zero id is a session.
/// A missing file is the ordinary "no agent session in this workspace" state;
/// an unparseable one is treated the same way rather than guessed at.
fn read_live_session(path: &Path) -> Option<[u8; 16]> {
    let bytes = std::fs::read(path).ok()?;
    let ls: LiveSession = serde_json::from_slice(&bytes).ok()?;
    let id = *uuid::Uuid::parse_str(&ls.session_id_hex).ok()?.as_bytes();
    (id != [0u8; 16]).then_some(id)
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
    fn live_session_reads_the_daemons_file_and_refuses_non_sessions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ws.json");
        let shared = Shared::new(PathBuf::from("."), PathBuf::from("."), 2_000);
        assert_eq!(
            shared.live_session(),
            None,
            "no file configured: no session"
        );
        shared.session_file.set(path.clone()).unwrap();
        assert_eq!(shared.live_session(), None, "no file yet: no session");

        std::fs::write(
            &path,
            br#"{"session_id_hex":"0190a1b2c3d4e5f60708090a0b0c0d0e","started_at":"2026-09-15T10:00:00Z"}"#,
        )
        .unwrap();
        assert_eq!(
            shared.live_session(),
            Some([
                0x01, 0x90, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                0x0d, 0x0e
            ])
        );
        for bad in [
            r#"{"session_id_hex":"00000000000000000000000000000000","started_at":""}"#,
            r#"{"session_id_hex":"abc","started_at":""}"#,
            "not json",
        ] {
            std::fs::write(&path, bad).unwrap();
            assert_eq!(shared.live_session(), None, "{bad}");
        }
        std::fs::remove_file(&path).unwrap();
        assert_eq!(shared.live_session(), None, "SessionEnd removed it");
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
