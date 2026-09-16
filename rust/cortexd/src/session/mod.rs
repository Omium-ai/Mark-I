//! Session scoping, `index_clock`, and the memory-artifact recall cache
//! (04 §6 tree). One `Shared` per workspace: the writer task mutates `Index`
//! behind the lock, MCP query tasks read snapshots + the atomic clock
//! (04 §6.3 single-writer discipline).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock, RwLockReadGuard, RwLockWriteGuard};

use m1p_wire::pb;
use rand::RngCore;
use serde::Deserialize;

use crate::l0_merkle::MerkleTree;
use crate::l1_tags::Tag;
use crate::l2_graph::{RankerStage, RankerWeights, SymbolGraph, FEATURES};
use crate::map::MapRender;

/// 04 §6.4: session-start map token budget — default 2k, ceiling 8k,
/// bundle-tunable via the `cortex` section (constants until bundle plumbing).
pub const DEFAULT_BUDGET_TOKENS: u32 = 2_000;
/// 08 §6: per-call floor/ceiling on `max_tokens`, and the per-turn cap.
pub const MIN_CALL_TOKENS: u32 = 256;
pub const MAX_CALL_TOKENS: u32 = 8_000;
pub const TURN_BUDGET_TOKENS: u32 = 8_000;
/// D-AF (04 §6.4): the effective injection ceiling on the hook surface.
pub const DAF_INJECTION_TOKENS: u32 = 2_500;
/// The edge cache's fail-static clock (cache.go defaultMaxAge): older syncs serve nothing.
pub const MEMORY_MAX_AGE_SECS: u64 = 7 * 24 * 3600;
/// Twin of retrieve.INJECTABLE_KINDS / cache.go `injectable`: `preference` never renders.
const INJECTABLE_KINDS: [&str; 3] = ["pitfall", "fix_pattern", "invariant"];

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
    /// `<state>/memory/artifacts.json` (`--memory-file`), the cache mark1d syncs
    /// (go/mark1d/internal/memory/cache.go). Unset ⇒ `memory_recall` is empty.
    pub memory_file: OnceLock<PathBuf>,
    /// Recalls that found the cache present but unreadable or malformed (served empty).
    pub memory_unreadable: AtomicU64,
    /// Phase 6 learned re-ranker (06 §12.4): bundle-delivered only, via the file
    /// mark1d writes at `--ranker-file` (go/mark1d/internal/cortex RankerFile).
    /// `None` (PPR order) whenever that file is absent, malformed or out of range.
    pub ranker: RwLock<Option<RankerWeights>>,
    pub ranker_file: OnceLock<PathBuf>,
    /// Ranker files refused by `RankerWeights::new` or the parser (served PPR order).
    pub ranker_rejected: AtomicU64,
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
            memory_file: OnceLock::new(),
            memory_unreadable: AtomicU64::new(0),
            ranker: RwLock::new(None),
            ranker_file: OnceLock::new(),
            ranker_rejected: AtomicU64::new(0),
        }
    }

    /// Installs the ranker the file's bytes describe, through `RankerWeights::new`
    /// only; `None` (absent file) or anything it refuses leaves PPR order in force.
    pub fn set_ranker(&self, bytes: Option<&[u8]>) {
        let next = bytes.and_then(|b| match parse_ranker(b) {
            Ok(w) => Some(w),
            Err(e) => {
                self.ranker_rejected.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(error = %e, "ranker file refused; serving PPR order");
                None
            }
        });
        *self.ranker.write_recover() = next;
    }

    /// `memory_recall` (08 §6.6): allowlisted kinds, normalized-substring trigger match
    /// (the 0.15 fuzz stays server-side, FR-REMEMBER-008), LCB order, fail-open empty.
    pub fn recall_artifacts(
        &self,
        query: &str,
        kinds: &[String],
        limit: usize,
        now_secs: u64,
    ) -> Vec<Artifact> {
        let Some(path) = self.memory_file.get() else {
            return Vec::new();
        };
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
            Err(_) => {
                self.memory_unreadable.fetch_add(1, Ordering::Relaxed);
                return Vec::new();
            }
        };
        let parsed = serde_json::from_slice::<MemoryCustody>(&bytes)
            .ok()
            .and_then(|c| Some((rfc3339_utc_secs(&c.synced_at)?, c.artifacts)));
        let Some((synced, artifacts)) = parsed else {
            self.memory_unreadable.fetch_add(1, Ordering::Relaxed);
            return Vec::new();
        };
        if now_secs.saturating_sub(synced) > MEMORY_MAX_AGE_SECS {
            return Vec::new();
        }
        let q = normalize(query);
        let want: Vec<&str> = kinds.iter().map(|k| canonical_kind(k)).collect();
        let mut out: Vec<Artifact> = artifacts
            .into_iter()
            .filter(|a| INJECTABLE_KINDS.contains(&a.kind.as_str()))
            .filter(|a| uuid::Uuid::parse_str(&a.artifact_id).is_ok())
            .filter(|a| want.is_empty() || want.contains(&a.kind.as_str()))
            .filter(|a| {
                let t = normalize(&a.trigger);
                !t.is_empty() && (t.contains(&q) || q.contains(&t))
            })
            .collect();
        out.sort_by(|a, b| {
            b.utility_lcb
                .partial_cmp(&a.utility_lcb)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        out.truncate(limit);
        out
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

/// The file mark1d writes at `<state>/run/ranker.json` (cortex.go rankerFile) —
/// one contract, two decoders. JSON cannot spell NaN/∞, so `new` sees finite floats
/// and its checks are the range check plus a wrong-arity `coefficients`.
#[derive(Deserialize)]
struct RankerFile {
    stage: RankerStage,
    weight: f64,
    bias: f64,
    coefficients: [f64; FEATURES],
}

fn parse_ranker(bytes: &[u8]) -> Result<RankerWeights, String> {
    let f: RankerFile = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    RankerWeights::new(f.stage, f.weight, f.bias, f.coefficients).map_err(|e| e.to_string())
}

/// Boot load + change detection for `--ranker-file`. ponytail: a byte-compare poll
/// of a ~100-byte file every `every` (5 s in main); notify lands if it ever matters.
pub async fn ranker_watch(shared: Arc<Shared>, every: std::time::Duration) {
    let mut seen: Option<Vec<u8>> = None;
    loop {
        let now = shared.ranker_file.get().and_then(|p| std::fs::read(p).ok());
        if now != seen {
            shared.set_ranker(now.as_deref());
            seen = now;
        }
        tokio::time::sleep(every).await;
    }
}

/// One row of the synced cache (cache.go `Artifact`) — one contract, two decoders.
#[derive(Debug, Clone, Deserialize)]
pub struct Artifact {
    pub artifact_id: String,
    pub kind: String,
    #[serde(default)]
    pub trigger: String,
    #[serde(default)]
    pub guidance: String,
    #[serde(default)]
    pub utility_lcb: f64,
}

/// The file's envelope (cache.go `custody`); `synced_at` is Go's RFC 3339 UTC.
#[derive(Deserialize)]
struct MemoryCustody {
    synced_at: String,
    artifacts: Vec<Artifact>,
}

/// 06 §9.2 reconciliation: 08 §6.6 still uses the pre-DDL spellings.
fn canonical_kind(kind: &str) -> &str {
    match kind {
        "pitfall_remedy" => "pitfall",
        "workflow_template" => "fix_pattern",
        other => other,
    }
}

fn normalize(text: &str) -> String {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

/// `YYYY-MM-DDTHH:MM:SS[.frac]Z` (Go's UTC shape) → epoch seconds; else None.
fn rfc3339_utc_secs(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    match (b[19], b.last()?) {
        (b'Z', _) if b.len() == 20 => {}
        (b'.', b'Z') if b.len() > 21 && b[20..b.len() - 1].iter().all(u8::is_ascii_digit) => {}
        _ => return None,
    }
    let num = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    // Days from civil (Hinnant): the March-based year makes leap days trailing.
    let (y, m) = if mo <= 2 {
        (y - 1, mo + 9)
    } else {
        (y, mo - 3)
    };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + (153 * m + 2) / 5 + d - 1;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(days * 86_400 + h * 3_600 + mi * 60 + sec).ok()
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

    /// Ranker-seam features `[fan_in, recency, path_depth, tag_count]`, all index-held.
    pub fn file_features(&self, path: &str) -> [f64; FEATURES] {
        let fan_in = self.graph.node_of.get(path).map_or(0, |n| {
            self.graph
                .graph
                .neighbors_directed(*n, petgraph::Direction::Incoming)
                .count()
        });
        let recency = self
            .recent_edits
            .iter()
            .position(|p| p == path)
            .map_or(0.0, |i| 1.0 / (1.0 + i as f64));
        let depth = path.matches('/').count();
        let tags = self.tags.get(path).map_or(0, Vec::len);
        [fan_in as f64, recency, depth as f64, tags as f64]
    }
}

/// 256 bits of OS randomness, hex-encoded. blake3's hex encoder is reused so
/// no hex dependency is added; hashing does not reduce the entropy drawn.
fn fresh_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    blake3::hash(&bytes).to_hex().to_string()
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
    fn synced_at_parses_gos_utc_shape_only() {
        assert_eq!(rfc3339_utc_secs("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            rfc3339_utc_secs("2026-08-29T12:00:00Z"),
            Some(1_788_004_800)
        );
        assert_eq!(
            rfc3339_utc_secs("2026-08-29T12:00:00.123456789Z"),
            Some(1_788_004_800),
            "Go's RFC3339Nano fraction"
        );
        assert_eq!(
            rfc3339_utc_secs("2024-02-29T00:00:00Z"),
            Some(1_709_164_800)
        );
        for bad in [
            "2026-08-29T12:00:00",
            "2026-08-29T12:00:00+05:00",
            "2026-08-29T12:00:00.Z",
            "2026-08-29 12:00:00Z",
            "1969-12-31T23:59:59Z",
            "",
        ] {
            assert_eq!(rfc3339_utc_secs(bad), None, "{bad}");
        }
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

    const SHADOW: &str =
        r#"{"stage":"shadow","weight":0.5,"bias":0.05,"coefficients":[0.6,0.25,-0.1,0.15]}"#;
    const ACTIVE: &str =
        r#"{"stage":"active","weight":0.25,"bias":0.05,"coefficients":[0.6,0.25,-0.1,0.15]}"#;

    fn with_ranker_file(dir: &Path) -> Arc<Shared> {
        let shared = Shared::new(PathBuf::from("."), PathBuf::from("."), 2_000);
        shared.ranker_file.set(dir.join("ranker.json")).unwrap();
        Arc::new(shared)
    }

    fn stage_of(shared: &Shared) -> Option<RankerStage> {
        shared.ranker.read_recover().as_ref().map(|w| w.stage())
    }

    #[test]
    fn ranker_file_installs_through_ranker_weights_new_only() {
        let shared = Shared::new(PathBuf::from("."), PathBuf::from("."), 2_000);
        shared.set_ranker(Some(SHADOW.as_bytes()));
        assert_eq!(
            shared.ranker.read_recover().clone(),
            Some(
                RankerWeights::new(RankerStage::Shadow, 0.5, 0.05, [0.6, 0.25, -0.1, 0.15])
                    .unwrap()
            )
        );
        shared.set_ranker(Some(ACTIVE.as_bytes()));
        assert_eq!(stage_of(&shared), Some(RankerStage::Active));
        shared.set_ranker(None);
        assert_eq!(stage_of(&shared), None, "absent file is PPR order");
        assert_eq!(shared.ranker_rejected.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn malformed_or_out_of_range_ranker_file_is_none_and_counted() {
        let shared = Shared::new(PathBuf::from("."), PathBuf::from("."), 2_000);
        let bad: [&[u8]; 8] = [
            b"{not json",
            br#"{"stage":"shadow","weight":1.5,"bias":0.0,"coefficients":[0,0,0,0]}"#,
            br#"{"stage":"shadow","weight":-0.1,"bias":0.0,"coefficients":[0,0,0,0]}"#,
            br#"{"stage":"canary","weight":0.5,"bias":0.0,"coefficients":[0,0,0,0]}"#,
            br#"{"stage":"shadow","weight":0.5,"bias":0.0,"coefficients":[0,0,0]}"#,
            br#"{"stage":"shadow","weight":0.5,"bias":0.0,"coefficients":[0,0,0,0,0]}"#,
            br#"{"stage":"shadow","weight":0.5,"bias":0.0}"#,
            br#"{"stage":"shadow","weight":"0.5","bias":0.0,"coefficients":[0,0,0,0]}"#,
        ];
        for (i, b) in bad.iter().enumerate() {
            shared.set_ranker(Some(SHADOW.as_bytes()));
            shared.set_ranker(Some(b));
            assert_eq!(
                stage_of(&shared),
                None,
                "bad file #{i} left a ranker installed"
            );
            assert_eq!(
                shared.ranker_rejected.load(Ordering::Relaxed),
                i as u64 + 1,
                "bad file #{i} not counted"
            );
        }
        // The boundary weights are inside the range, exactly as `new` bounds them.
        for edge in [
            br#"{"stage":"active","weight":0.0,"bias":0.0,"coefficients":[0,0,0,0]}"#.as_slice(),
            br#"{"stage":"active","weight":1.0,"bias":0.0,"coefficients":[0,0,0,0]}"#.as_slice(),
        ] {
            shared.set_ranker(Some(edge));
            assert_eq!(stage_of(&shared), Some(RankerStage::Active));
        }
        assert_eq!(
            shared.ranker_rejected.load(Ordering::Relaxed),
            bad.len() as u64
        );
    }

    #[tokio::test]
    async fn ranker_watch_loads_at_boot_and_reloads_on_change() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ranker.json");
        // mark1d's write is tmp + rename; mirror it so the poll never sees a torn file.
        let publish = |body: &str| {
            std::fs::write(path.with_extension("tmp"), body).unwrap();
            std::fs::rename(path.with_extension("tmp"), &path).unwrap();
        };
        let settle = |shared: Arc<Shared>, want: Option<RankerStage>| async move {
            for _ in 0..300 {
                if stage_of(&shared) == want {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            panic!("ranker never became {want:?} (is {:?})", stage_of(&shared));
        };
        publish(SHADOW);
        let shared = with_ranker_file(dir.path());
        tokio::spawn(ranker_watch(
            Arc::clone(&shared),
            std::time::Duration::from_millis(10),
        ));
        settle(Arc::clone(&shared), Some(RankerStage::Shadow)).await;
        publish(ACTIVE);
        settle(Arc::clone(&shared), Some(RankerStage::Active)).await;
        std::fs::remove_file(&path).unwrap();
        settle(Arc::clone(&shared), None).await;
        publish(SHADOW);
        settle(Arc::clone(&shared), Some(RankerStage::Shadow)).await;
        assert_eq!(shared.ranker_rejected.load(Ordering::Relaxed), 0);
        publish("{broken");
        settle(Arc::clone(&shared), None).await;
        assert_eq!(shared.ranker_rejected.load(Ordering::Relaxed), 1);
        // A watcher with no file configured (hand-run cortexd) installs nothing.
        let bare = Arc::new(Shared::new(PathBuf::from("."), PathBuf::from("."), 2_000));
        tokio::spawn(ranker_watch(
            Arc::clone(&bare),
            std::time::Duration::from_millis(10),
        ));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(stage_of(&bare), None);
    }
}
