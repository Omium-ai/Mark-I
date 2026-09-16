//! Golden tests over the committed 3-language fixture repo (12 §7.1):
//! L0 root, L1 tags, L2 top-k ranking, plus the incremental-update property
//! (touch one file ⇒ exactly one rehash, sibling subtrees untouched).

// clippy.toml's allow-*-in-tests exempts #[test] fns; the helpers here are
// plain fns, so the exemption is restated at file scope (house style).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

use cortexd::l0_merkle::{IgnoreSet, MerkleTree};
use cortexd::session::LockExt;

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixture")
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let dst = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &dst);
        } else {
            std::fs::copy(entry.path(), &dst).unwrap();
        }
    }
}

/// Golden L0 root of the committed fixture: content-addressed, so this hex is
/// stable across machines and checkouts (mtime/size play no part in hashing).
const GOLDEN_L0_ROOT: &str = "fc57c87ae5491141d30e4a0f296df381440136ab1a4dc9b509047f972a048c2f";

#[test]
fn golden_l0_root() {
    let ignore = IgnoreSet::load(&fixture()).unwrap();
    let tree = MerkleTree::full_scan(&fixture(), &ignore, None).unwrap();
    // .gitignore rules hold: the ignored dir and the log never enter the tree.
    assert!(tree.file_hash("ignored/skip.py").is_none());
    assert!(tree.file_hash("notes.log").is_none());
    assert_eq!(tree.len(), 7, "7 indexable files: .gitignore + 6 sources");
    assert_eq!(tree.root_hex(), GOLDEN_L0_ROOT);
}

#[test]
fn golden_l1_tags_and_l2_topk() {
    let store = tempfile::tempdir().unwrap();
    // bootstrap owns store creation (0700 + mode refusal); hand it a fresh path.
    let (shared, cas) = cortexd::bootstrap(fixture(), store.path().join("store"), 2000).unwrap();
    cortexd::full_index(&shared, &cas).unwrap();
    let idx = shared.index.read_recover();

    // L1 goldens — (name, kind) per file, defs only.
    let defs = |path: &str| -> Vec<(String, String)> {
        idx.tags[path]
            .iter()
            .filter(|t| t.role == cortexd::l1_tags::Role::Def)
            .map(|t| (t.name.clone(), t.kind.clone()))
            .collect()
    };
    assert_eq!(
        defs("core/util.py"),
        vec![
            ("fmt".to_string(), "function".to_string()),
            ("Registry".to_string(), "class".to_string()),
            ("lookup".to_string(), "function".to_string()),
        ]
    );
    assert_eq!(
        defs("app/main.py"),
        vec![("main".to_string(), "function".to_string())]
    );
    assert_eq!(
        defs("rustlib/parse.rs"),
        vec![
            ("Frame".to_string(), "struct".to_string()),
            ("parse_str".to_string(), "function".to_string()),
        ]
    );
    assert_eq!(
        defs("rustlib/lib.rs"),
        vec![("load".to_string(), "function".to_string())]
    );
    assert_eq!(
        defs("web/render.ts"),
        vec![
            ("Frame".to_string(), "interface".to_string()),
            ("render".to_string(), "function".to_string()),
        ]
    );
    assert_eq!(
        defs("web/index.ts"),
        vec![("page".to_string(), "function".to_string())]
    );
    assert!(
        !idx.tags.contains_key(".gitignore"),
        "no grammar => L0-only file"
    );

    // L2 goldens — each importer wires an edge into its definition file.
    let g = &idx.graph;
    for (from, to) in [
        ("app/main.py", "core/util.py"),
        ("rustlib/lib.rs", "rustlib/parse.rs"),
        ("web/index.ts", "web/render.ts"),
    ] {
        assert!(
            g.graph.find_edge(g.node_of[from], g.node_of[to]).is_some(),
            "missing edge {from} -> {to}"
        );
    }

    // Top-k global ranking: the three definition files (each with one inbound
    // edge) outrank every importer (zero inbound).
    let mut ranked: Vec<(&str, f64)> = g
        .graph
        .node_indices()
        .map(|n| (g.graph[n].as_str(), g.global_ranks[n.index()]))
        .collect();
    ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
    let top3: std::collections::BTreeSet<&str> = ranked.iter().take(3).map(|(p, _)| *p).collect();
    assert_eq!(
        top3,
        ["core/util.py", "rustlib/parse.rs", "web/render.ts"]
            .into_iter()
            .collect()
    );

    // Seeded PPR: seeding at the app entrypoint pulls its import target above
    // the unrelated rust/web files.
    let seeds = [g.node_of["app/main.py"]];
    let ppr = g
        .ranks_for(&seeds, std::time::Duration::from_secs(5), 1)
        .unwrap();
    assert!(ppr.exact);
    let score = |p: &str| ppr.scores[g.node_of[p].index()];
    assert!(score("core/util.py") > score("rustlib/parse.rs"));
    assert!(score("core/util.py") > score("web/render.ts"));
}

#[test]
fn incremental_touch_rehashes_only_the_affected_subtree() {
    let work = tempfile::tempdir().unwrap();
    copy_dir(&fixture(), work.path());
    let store = tempfile::tempdir().unwrap();
    let (shared, cas) =
        cortexd::bootstrap(work.path().to_path_buf(), store.path().join("store"), 2000).unwrap();
    cortexd::full_index(&shared, &cas).unwrap();
    let (root_before, web_before, rehashed_before, clock_before) = {
        let idx = shared.index.read_recover();
        (
            idx.merkle.root(),
            idx.merkle.dir_hash("web").unwrap(),
            idx.merkle.files_rehashed,
            shared.index_clock.load(Ordering::SeqCst),
        )
    };

    std::fs::write(
        work.path().join("app/main.py"),
        b"def main():\n    return 'changed'\n",
    )
    .unwrap();
    cortexd::incremental_index(&shared, &cas, &["app/main.py".to_string()]).unwrap();

    let idx = shared.index.read_recover();
    assert_eq!(
        idx.merkle.files_rehashed,
        rehashed_before + 1,
        "exactly one file content rehash on a one-file touch"
    );
    assert_ne!(
        idx.merkle.root(),
        root_before,
        "root must move with content"
    );
    assert_eq!(
        idx.merkle.dir_hash("web").unwrap(),
        web_before,
        "sibling subtree untouched"
    );
    assert_eq!(shared.index_clock.load(Ordering::SeqCst), clock_before + 1);
    // The edit dropped main.py's call to fmt, so its L2 edge is gone.
    let g = &idx.graph;
    assert!(g
        .graph
        .find_edge(g.node_of["app/main.py"], g.node_of["core/util.py"])
        .is_none());
}

/// FR-CORTEX-007 / 04 §6.1: the CAS `grammar_rev` component is the rev of the
/// grammar that produced the row, so a bump of one grammar pin misses exactly
/// that language's rows and every other language still hits. The bump is
/// staged on disk (rows re-keyed under the old Python pin), then a cold-merkle
/// pass re-probes every file with the live revs and the counters do the sum.
#[test]
fn grammar_rev_bump_misses_only_that_language() {
    use cortexd::l1_tags::{grammar_rev, Lang};
    let store = tempfile::tempdir().unwrap();
    let (shared, cas) = cortexd::bootstrap(fixture(), store.path().join("store"), 2000).unwrap();
    cortexd::full_index(&shared, &cas).unwrap();
    let hits_misses = || {
        (
            shared.cas_hits.load(Ordering::Relaxed),
            shared.cas_misses.load(Ordering::Relaxed),
        )
    };
    assert_eq!(
        hits_misses(),
        (0, 6),
        "cold CAS: every source file is a miss"
    );
    assert_ne!(grammar_rev(Lang::Python), grammar_rev(Lang::Rust));

    // Stage a Python pin bump: the two .py rows were derived under an older
    // grammar_rev. Rust and TypeScript rows are untouched by definition.
    let db = rusqlite::Connection::open(shared.store.join("cas.sqlite")).unwrap();
    let rekeyed = db
        .execute(
            "UPDATE artifacts SET grammar_rev = 'py0.22' WHERE grammar_rev = ?1",
            [grammar_rev(Lang::Python)],
        )
        .unwrap();
    assert_eq!(rekeyed, 2, "exactly the Python rows carry the Python pin");

    // Cold merkle + shards, warm CAS: every file is re-probed (04 §6.1 "one
    // CAS probe + one re-parse" for the bumped grammar only).
    std::fs::remove_file(shared.store.join("l0.merkle")).unwrap();
    std::fs::remove_dir_all(shared.store.join("graph")).unwrap();
    cortexd::full_index(&shared, &cas).unwrap();
    assert_eq!(
        hits_misses(),
        (4, 8),
        "4 hits (2 .rs + 2 .ts), 2 new misses (the .py rows under the bumped pin)"
    );
}

/// FR-CORTEX-006 / 04 §6.6: `.mark1ignore` scopes the index itself — an
/// ignored file never enters L0 or L1 while its sibling does — and neither
/// the walk nor the incremental path follows a symlink, so a link out of the
/// root cannot pull foreign bytes into the tree.
#[test]
fn mark1ignore_and_symlink_escape_never_enter_the_index() {
    let work = tempfile::tempdir().unwrap();
    copy_dir(&fixture(), work.path());
    std::fs::write(work.path().join(".mark1ignore"), "web/index.ts\n").unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("leak.py"), b"def leaked():\n    pass\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        symlink(
            outside.path().join("leak.py"),
            work.path().join("core/leak.py"),
        )
        .unwrap();
        symlink(outside.path(), work.path().join("core/escape")).unwrap();
    }

    let store = tempfile::tempdir().unwrap();
    let (shared, cas) =
        cortexd::bootstrap(work.path().to_path_buf(), store.path().join("store"), 2000).unwrap();
    cortexd::full_index(&shared, &cas).unwrap();
    // The watcher path too: a symlinked dir arriving whole must not be walked.
    cortexd::incremental_index(
        &shared,
        &cas,
        &["core/escape".to_string(), "core/leak.py".to_string()],
    )
    .unwrap();

    let idx = shared.index.read_recover();
    assert!(
        idx.merkle.file_hash("web/index.ts").is_none(),
        "mark1ignored: absent from L0"
    );
    assert!(
        !idx.tags.contains_key("web/index.ts"),
        "mark1ignored: absent from L1"
    );
    assert!(
        idx.merkle.file_hash("web/render.ts").is_some(),
        "sibling present in L0"
    );
    assert!(
        idx.tags.contains_key("web/render.ts"),
        "sibling present in L1"
    );
    for escaped in ["core/leak.py", "core/escape/leak.py"] {
        assert!(
            idx.merkle.file_hash(escaped).is_none(),
            "{escaped} must not be indexed"
        );
        assert!(!idx.tags.contains_key(escaped));
    }
    assert!(
        !idx.tags.values().flatten().any(|t| t.name == "leaked"),
        "no symbol from outside the root"
    );
}

#[test]
fn watcher_delivers_changed_paths() {
    let work = tempfile::tempdir().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let _watcher = cortexd::l0_merkle::start_watcher(work.path(), tx).unwrap();
    std::fs::write(work.path().join("fresh.py"), b"def f():\n    pass\n").unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        match rx.recv_timeout(remaining) {
            Ok(cortexd::WatchMsg::Changed(paths))
                if paths.iter().any(|p| p.ends_with("fresh.py")) =>
            {
                return; // the notify -> writer inbox path works end to end
            }
            Ok(_) => continue, // unrelated event (dir metadata etc.)
            Err(e) => panic!("watcher never delivered the touch: {e}"),
        }
    }
}

/// Phase 6 learned-ranker seam (06 §12.4, 10 §11.3) on the real fixture
/// graph: probation/shadow weights leave `ranked_files` bit-identical to no
/// weights at all; `active` reorders only inside PPR's top-`limit`, never
/// admits a file PPR left out, and every score stays in [0,1].
#[test]
fn learned_ranker_shadow_is_bit_identical_and_active_keeps_pprs_top_k() {
    use cortexd::l2_graph::{RankerStage, RankerWeights, FEATURES};
    use cortexd::session::LockExt;
    let store = tempfile::tempdir().unwrap();
    let (shared, cas) = cortexd::bootstrap(fixture(), store.path().join("store"), 2000).unwrap();
    cortexd::full_index(&shared, &cas).unwrap();
    let ranked = |limit: u64| {
        cortexd::mcp::call_tool(
            &shared,
            "ranked_files",
            &serde_json::json!({ "query": "render", "limit": limit }),
        )
        .unwrap()
    };
    let paths = |out: &serde_json::Value| -> Vec<String> {
        out["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["path"].as_str().unwrap().to_string())
            .collect()
    };
    let baseline3 = ranked(3);
    let baseline2 = ranked(2);
    assert_eq!(
        paths(&baseline3),
        ["core/util.py", "rustlib/parse.rs", "web/render.ts"],
        "PPR: the three definition files tie at 1.0, path order breaks it"
    );
    assert_eq!(paths(&baseline2), paths(&baseline3)[..2]);

    // Recency is the feature that separates the tied top-3 (render.ts was
    // the last settle's freshest edit) and that prefers a file outside top-2.
    let recency = [0.0, 1.0, 0.0, 0.0];
    for stage in [RankerStage::Probation, RankerStage::Shadow] {
        *shared.ranker.write_recover() =
            Some(RankerWeights::new(stage, 1.0, 0.0, recency).unwrap());
        assert_eq!(
            ranked(3),
            baseline3,
            "{stage:?} must not change the served answer"
        );
        assert_eq!(ranked(2), baseline2);
    }

    *shared.ranker.write_recover() =
        Some(RankerWeights::new(RankerStage::Active, 1.0, 0.0, recency).unwrap());
    let active3 = ranked(3);
    assert_eq!(
        paths(&active3),
        ["web/render.ts", "rustlib/parse.rs", "core/util.py"],
        "active reorders inside PPR's top-3 by (ppr + learned) / 2"
    );
    for f in active3["files"].as_array().unwrap() {
        let s = f["score"].as_f64().unwrap();
        assert!((0.0..=1.0).contains(&s), "{f}");
    }
    assert_eq!(active3["files"][0]["score"], 1.0, "(1 + 1·1) / (1 + 1)");
    // Top-k protection: with limit 2 the file the learned model prefers most
    // (web/render.ts) sits outside PPR's top-2 and must stay out.
    let active2 = ranked(2);
    assert_eq!(
        paths(&active2),
        ["rustlib/parse.rs", "core/util.py"],
        "same set as PPR's top-2, reordered; render.ts cannot enter: {active2}"
    );

    *shared.ranker.write_recover() =
        Some(RankerWeights::new(RankerStage::Active, 0.0, 0.0, recency).unwrap());
    assert_eq!(paths(&ranked(3)), paths(&baseline3), "w = 0 is PPR order");
    assert_eq!(FEATURES, recency.len());
}
