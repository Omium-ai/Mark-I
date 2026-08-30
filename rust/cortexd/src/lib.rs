//! cortexd — per-workspace repo intelligence (04 §6).
//!
//! Library target exists so the L0–L2 pipeline, the ignore matcher, PPR and
//! the MCP auth wall are integration-testable; `main.rs` stays the thin bind
//! per 13 §1. Module set is 04 §6 / 13 §1 verbatim; the L0→L2 writer
//! pipeline (04 §6.1) is orchestrated here because it spans every module.

pub mod cas;
pub mod fabric;
pub mod l0_merkle;
pub mod l1_tags;
pub mod l2_graph;
pub mod l3_scip;
pub mod map;
pub mod mcp;
pub mod session;
pub mod shards;

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::Arc;
use std::time::Duration;

use session::{LockExt, Shared};

/// One error type for the daemon's fallible plumbing. MCP-facing failures are
/// NOT errors — they are the 08 §6 refusal envelope (refusal beats
/// fabrication); this type covers IO/storage faults only.
#[derive(Debug, thiserror::Error)]
pub enum CortexError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("cas: {0}")]
    Cas(#[from] rusqlite::Error),
    #[error("artifact encoding: {0}")]
    Encoding(#[from] serde_json::Error),
    #[error("workspace root is not a directory: {0}")]
    BadRoot(PathBuf),
}

/// 04 §6.1: notify event → debounce 50 ms → L0 → L1 → L2 → clock bump.
pub const DEBOUNCE: Duration = Duration::from_millis(50);

/// What the notify callback hands the writer task (04 §6.3: one writer owns
/// all index mutation; this channel is its only inbox).
#[derive(Debug)]
pub enum WatchMsg {
    /// Paths the OS reported as touched (created/modified/removed/renamed).
    Changed(Vec<PathBuf>),
    /// Watcher overflow (04 §6.6): the only honest response is a full rescan —
    /// never guess which events were lost.
    Overflow,
}

/// Build the shared state and run the initial index synchronously so the MCP
/// server never serves against an empty tree without the stale flag set.
pub fn bootstrap(
    root: PathBuf,
    store: PathBuf,
    default_budget: u32,
) -> Result<(Arc<Shared>, cas::Cas), CortexError> {
    // Canonicalized once here; every MCP path argument is later resolved
    // against this exact prefix (08 §6 session scoping).
    let root = root.canonicalize()?;
    if !root.is_dir() {
        return Err(CortexError::BadRoot(root));
    }
    secure_store_dir(&store)?;
    std::fs::create_dir_all(store.join("graph"))?;
    let cas = cas::Cas::open(&store.join("cas.sqlite"))?;
    let shared = Arc::new(Shared::new(root, store, default_budget));
    Ok((shared, cas))
}

/// Store-dir boundary, mirroring mark1d's fabric listener posture
/// (go/mark1d/internal/fabric/listener.go): create 0700, HARD-REFUSE an
/// existing dir with any group/world bit — never chmod-and-continue. The
/// store holds repo-derived index content (cas.sqlite, l0.merkle, shards)
/// and the MCP bearer token file; the threat model is other users.
#[cfg(unix)]
fn secure_store_dir(store: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(store)?;
    // Lstat: a symlink planted at the store path must refuse, not be followed.
    let meta = std::fs::symlink_metadata(store)?;
    if !meta.is_dir() {
        return Err(std::io::Error::other(format!(
            "store path {} is not a directory",
            store.display()
        )));
    }
    let mode = meta.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(std::io::Error::other(format!(
            "refusing store dir {} with mode {:o} — 0700 required, no group or world grant, ever",
            store.display(),
            mode & 0o777
        )));
    }
    Ok(())
}

/// ponytail: Windows store ACLs land with the named-pipe fabric row (the Go
/// listener is unix-only for the same reason); mode bits mean nothing there.
#[cfg(not(unix))]
fn secure_store_dir(store: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(store)
}

/// Full L0→L2 pass (initial index and the watcher-overflow rescan path).
/// Returns the set of paths whose content changed vs the previous merkle.
pub fn full_index(shared: &Arc<Shared>, cas: &cas::Cas) -> Result<Vec<String>, CortexError> {
    shared.stale.store(true, Ordering::SeqCst);
    let ignore = l0_merkle::IgnoreSet::load(&shared.root)?;

    // Warm restart (04 §6.2): persisted l0.merkle lets an unchanged file skip
    // rehashing (size+mtime match); the CAS makes re-tagging a probe, not a parse.
    let prev = l0_merkle::MerkleTree::load(&shared.store.join("l0.merkle"));
    let merkle = l0_merkle::MerkleTree::full_scan(&shared.root, &ignore, prev.as_ref())?;

    // Shard warm-load; a corrupt shard is deleted, never repaired in place
    // (04 §6.2) — the L1 pass below re-derives whatever the shard lost.
    let warm_tags = shards::load_all(&shared.store.join("graph"));
    let mut tags = warm_tags.unwrap_or_default();
    tags.retain(|p, _| merkle.file_hash(p).is_some());

    let mut changed = Vec::new();
    for (path, entry) in merkle.files() {
        let up_to_date = tags.contains_key(path)
            && prev
                .as_ref()
                .and_then(|t| t.file_hash(path))
                .is_some_and(|h| h == entry.hash);
        if !up_to_date {
            changed.push(path.clone());
        }
    }
    retag(shared, cas, &merkle, &mut tags, &changed)?;

    let graph = l2_graph::SymbolGraph::build(&tags);
    settle(shared, merkle, tags, graph, changed.clone());
    Ok(changed)
}

/// Incremental pass for a debounced changed-set (04 §6.1): L0 path update,
/// L1 on changed files only, L2 rebuild, clock bump.
pub fn incremental_index(
    shared: &Arc<Shared>,
    cas: &cas::Cas,
    changed_paths: &[String],
) -> Result<(), CortexError> {
    let ignore = l0_merkle::IgnoreSet::load(&shared.root)?;
    let (mut merkle, mut tags) = {
        let idx = shared.index.read_recover();
        (idx.merkle.clone(), idx.tags.clone())
    };
    let touched = merkle.update_paths(&shared.root, &ignore, changed_paths)?;
    if touched.is_empty() {
        return Ok(()); // e.g. ignored paths — no index state changed
    }
    tags.retain(|p, _| merkle.file_hash(p).is_some());
    retag(shared, cas, &merkle, &mut tags, &touched)?;
    let graph = l2_graph::SymbolGraph::build(&tags);
    settle(shared, merkle, tags, graph, touched);
    Ok(())
}

/// L1 over exactly the changed set — CAS hit skips the parse (04 §6.1).
fn retag(
    shared: &Shared,
    cas: &cas::Cas,
    merkle: &l0_merkle::MerkleTree,
    tags: &mut std::collections::BTreeMap<String, Vec<l1_tags::Tag>>,
    changed: &[String],
) -> Result<(), CortexError> {
    for path in changed {
        let Some(hash) = merkle.file_hash(path) else {
            tags.remove(path); // deleted
            continue;
        };
        let Some(lang) = l1_tags::lang_of(path) else {
            tags.remove(path); // not one of the 5 pinned grammars — L0-only file
            continue;
        };
        if let Some(hit) = cas.get_tags(
            path,
            &hash,
            l1_tags::grammar_rev(),
            l1_tags::QUERY_REV,
            l1_tags::INDEXER_REV,
        )? {
            tags.insert(path.clone(), hit);
            continue;
        }
        let source = std::fs::read(shared.root.join(path))?;
        match l1_tags::extract(lang, &source) {
            Ok(file_tags) => {
                cas.put_tags(
                    path,
                    &hash,
                    l1_tags::grammar_rev(),
                    l1_tags::QUERY_REV,
                    l1_tags::INDEXER_REV,
                    &file_tags,
                )?;
                tags.insert(path.clone(), file_tags);
            }
            Err(e) => {
                // Grammar/query unavailable ⇒ the file stays L0-only and symbol
                // queries touching it refuse M1E-6403 — degrade loudly, never fake.
                tracing::warn!(path, error = %e, "l1 extract failed; file stays untagged");
                tags.remove(path);
            }
        }
    }
    Ok(())
}

/// Publish a new index generation: swap state, bump the clock, clear stale,
/// persist for warm restart, precompute the session map, push the L0 root.
fn settle(
    shared: &Arc<Shared>,
    merkle: l0_merkle::MerkleTree,
    tags: std::collections::BTreeMap<String, Vec<l1_tags::Tag>>,
    graph: l2_graph::SymbolGraph,
    changed: Vec<String>,
) {
    let root_hash = merkle.root();
    if let Err(e) = merkle.save(&shared.store.join("l0.merkle")) {
        tracing::warn!(error = %e, "l0.merkle persist failed; warm restart will rescan");
    }
    if let Err(e) = shards::save_all(&shared.store.join("graph"), &tags) {
        tracing::warn!(error = %e, "shard persist failed; warm restart will re-derive");
    }
    {
        let mut idx = shared.index.write_recover();
        idx.merkle = merkle;
        idx.tags = tags;
        idx.graph = graph;
        for p in changed {
            idx.note_edit(p);
        }
        // 04 §6.4: the session-start map is precomputed at index settle, not at
        // query time — the SessionStart serve is then a read.
        let seeds: Vec<String> = idx.recent_edits.clone();
        idx.session_map = Some(map::assemble(&idx, &seeds, shared.default_budget));
    }
    let clock = shared.index_clock.fetch_add(1, Ordering::SeqCst) + 1;
    shared.stale.store(false, Ordering::SeqCst);
    shared.broken.store(false, Ordering::SeqCst);
    // 04 §6.7: the L0 root is pushed to mark1d on every index-clock bump —
    // droppable (recomputable), counted when the fabric is away (08 §4.4).
    fabric::spawn_root_push(shared, root_hash, clock);
}

/// The single writer task (04 §6.3). Runs on its own OS thread at idle
/// priority (04 §6.6) so full passes never starve a foreground MCP query.
pub fn run_indexer(shared: Arc<Shared>, cas: cas::Cas, rx: Receiver<WatchMsg>) {
    set_idle_priority();
    if let Err(e) = full_index(&shared, &cas) {
        // Stale stays set: every query refuses M1E-6401 rather than serving an
        // empty fabricated index (04 §6.3).
        tracing::error!(error = %e, "initial index failed; serving refusals");
    }
    loop {
        let first = match rx.recv() {
            Ok(m) => m,
            Err(_) => return, // watcher gone: daemon is shutting down
        };
        let mut rescan = false;
        let mut paths: BTreeSet<PathBuf> = BTreeSet::new();
        let mut absorb = |m: WatchMsg| match m {
            WatchMsg::Changed(p) => paths.extend(p),
            WatchMsg::Overflow => rescan = true,
        };
        absorb(first);
        // Debounce 50 ms (04 §6.1): coalesce the burst, then run one pass.
        loop {
            match rx.recv_timeout(DEBOUNCE) {
                Ok(m) => absorb(m),
                Err(RecvTimeoutError::Timeout) => break,
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
        let result = if rescan {
            full_index(&shared, &cas).map(|_| ())
        } else {
            let rels: Vec<String> = paths
                .iter()
                .filter_map(|p| {
                    p.strip_prefix(&shared.root)
                        .ok()
                        .and_then(|r| r.to_str())
                        .map(|r| r.replace('\\', "/"))
                })
                .collect();
            if rels.is_empty() {
                continue;
            }
            incremental_index(&shared, &cas, &rels)
        };
        if let Err(e) = result {
            tracing::error!(error = %e, "index pass failed; scheduling full rescan");
            shared.stale.store(true, Ordering::SeqCst);
            if let Err(e2) = full_index(&shared, &cas) {
                tracing::error!(error = %e2, "rescan failed; refusals until next event");
            }
        }
    }
}

/// 04 §6.6: full-index passes run at idle priority. Best-effort, Linux gets
/// nice 19 + IOPRIO_CLASS_IDLE for the writer thread; failure to lower
/// priority is never an error (it can only make us politer).
#[cfg(target_os = "linux")]
fn set_idle_priority() {
    // SAFETY: plain syscalls on the calling thread with no pointer arguments.
    unsafe {
        let tid = libc::syscall(libc::SYS_gettid) as libc::id_t;
        libc::setpriority(libc::PRIO_PROCESS, tid, 19);
        // ioprio_set(IOPRIO_WHO_PROCESS=1, tid, IOPRIO_CLASS_IDLE<<13)
        libc::syscall(libc::SYS_ioprio_set, 1, tid, 3u64 << 13);
    }
}

/// ponytail: macOS QOS_CLASS_BACKGROUND / Windows IDLE_PRIORITY_CLASS land
/// with their platform CI lanes (04 §6.6); until then the writer runs at
/// default priority there — correctness is unaffected.
#[cfg(not(target_os = "linux"))]
fn set_idle_priority() {}
