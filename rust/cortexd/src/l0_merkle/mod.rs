//! L0 — notify watcher + BLAKE3 file-plane merkle tree (04 §6.1).
//!
//! The root hash double-serves (04 §6.7): cortex provenance on every answer,
//! and the anchors' anti-tamper envelope via the fabric push. Leaves are
//! BLAKE3(file bytes); directory nodes hash their sorted child (kind, name,
//! hash) triples, so an unchanged sibling subtree is never rehashed.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Ignore rules — .gitignore + .mark1ignore, gitignore syntax (04 §0.3 inv. 3)
// ---------------------------------------------------------------------------

/// Root-level `.gitignore` + `.mark1ignore` matcher over the gitignore subset
/// that matters for scope: comments/blanks, `dir/` dir-only, leading-`/`
/// anchoring, `*`/`?` segment globs, `**` cross-segment.
///
/// Negation (`!`) is deliberately unsupported: honoring the ignore without the
/// un-ignore can only make cortexd read LESS than git would — the failure
/// direction the privacy invariant wants ("nothing outside enrolled roots is
/// read", 04 §0.3). ponytail: nested per-directory ignore files,
/// `.git/info/exclude`, and the global `core.excludesFile` are all unread —
/// only the two root-level files scope the walk; the rest land with the
/// monorepo lane. Root-level files cover the Phase-2 fixture sizes.
#[derive(Debug, Default, Clone)]
pub struct IgnoreSet {
    rules: Vec<Rule>,
}

#[derive(Debug, Clone)]
struct Rule {
    /// Leading `/` in the pattern: match from the root only.
    anchored: bool,
    /// Trailing `/`: directories only.
    dir_only: bool,
    segs: Vec<String>,
}

impl IgnoreSet {
    pub fn load(root: &Path) -> std::io::Result<IgnoreSet> {
        let mut rules = Vec::new();
        for name in [".gitignore", ".mark1ignore"] {
            let path = root.join(name);
            match std::fs::read_to_string(&path) {
                Ok(text) => {
                    for line in text.lines() {
                        if let Some(rule) = Rule::parse(line) {
                            rules.push(rule);
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        Ok(IgnoreSet { rules })
    }

    #[cfg(test)]
    pub fn from_lines(lines: &[&str]) -> IgnoreSet {
        IgnoreSet {
            rules: lines.iter().filter_map(|l| Rule::parse(l)).collect(),
        }
    }

    /// `rel` uses `/` separators, no leading slash. `.git` is always ignored.
    pub fn matches(&self, rel: &str, is_dir: bool) -> bool {
        let segs: Vec<&str> = rel.split('/').filter(|s| !s.is_empty()).collect();
        if segs.first() == Some(&".git") {
            return true;
        }
        // A path is ignored if any of its ancestors is an ignored directory —
        // git semantics: an ignored dir's contents are unconditionally out.
        for end in 1..=segs.len() {
            let prefix_is_dir = if end == segs.len() { is_dir } else { true };
            for rule in &self.rules {
                if rule.matches(&segs[..end], prefix_is_dir) {
                    return true;
                }
            }
        }
        false
    }
}

impl Rule {
    fn parse(line: &str) -> Option<Rule> {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        if line.starts_with('!') {
            // See IgnoreSet doc: negation is unsupported by design; dropping
            // the un-ignore is the conservative (read-less) direction.
            return None;
        }
        let mut pat = line;
        let dir_only = pat.ends_with('/');
        if dir_only {
            pat = &pat[..pat.len() - 1];
        }
        // gitignore: a pattern with a slash anywhere (not just leading) is
        // anchored to the root.
        let anchored = pat.starts_with('/') || pat.contains('/');
        let pat = pat.strip_prefix('/').unwrap_or(pat);
        let segs: Vec<String> = pat.split('/').map(str::to_string).collect();
        if segs.is_empty() || segs.iter().all(|s| s.is_empty()) {
            return None;
        }
        Some(Rule {
            anchored,
            dir_only,
            segs,
        })
    }

    fn matches(&self, path: &[&str], is_dir: bool) -> bool {
        if self.dir_only && !is_dir {
            return false;
        }
        if self.anchored {
            segs_match(&self.segs, path)
        } else {
            // Unanchored single-segment pattern matches the basename at any depth.
            path.last()
                .is_some_and(|last| segs_match(&self.segs, &[last]))
        }
    }
}

/// Segment-list glob match: `**` spans segments, `*`/`?` glob within one.
fn segs_match(pat: &[String], path: &[&str]) -> bool {
    match (pat.first(), path.first()) {
        (None, None) => true,
        (None, Some(_)) => false,
        (Some(p), _) if p == "**" => {
            // `**` matches zero or more whole segments.
            segs_match(&pat[1..], path) || (!path.is_empty() && segs_match(pat, &path[1..]))
        }
        (Some(_), None) => false,
        (Some(p), Some(s)) => glob_match(p, s) && segs_match(&pat[1..], &path[1..]),
    }
}

fn glob_match(pat: &str, s: &str) -> bool {
    fn inner(p: &[u8], s: &[u8]) -> bool {
        match (p.first(), s.first()) {
            (None, None) => true,
            (Some(b'*'), _) => inner(&p[1..], s) || (!s.is_empty() && inner(p, &s[1..])),
            (None, Some(_)) | (Some(_), None) => false,
            (Some(b'?'), Some(_)) => inner(&p[1..], &s[1..]),
            (Some(a), Some(b)) => a == b && inner(&p[1..], &s[1..]),
        }
    }
    inner(pat.as_bytes(), s.as_bytes())
}

// ---------------------------------------------------------------------------
// Merkle tree
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FileEntry {
    /// BLAKE3 of the file bytes — the leaf.
    pub hash: [u8; 32],
    /// stat pair for warm-restart change detection (04 §6.2 `l0.merkle`).
    pub size: u64,
    pub mtime_ns: u128,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct MerkleTree {
    /// rel path (`/`-separated) → leaf entry. BTreeMap so child enumeration
    /// is an ordered range scan and hashing is deterministic.
    files: BTreeMap<String, FileEntry>,
    /// dir rel path (`""` = worktree root) → node hash.
    dirs: BTreeMap<String, [u8; 32]>,
    /// Files whose CONTENT was (re)hashed since construction/update —
    /// instrumentation proving the incremental path touches only the changed
    /// subtree (12 §7.1 incremental property).
    #[serde(skip)]
    pub files_rehashed: u64,
}

impl MerkleTree {
    pub fn root(&self) -> [u8; 32] {
        self.dirs.get("").copied().unwrap_or([0u8; 32])
    }

    pub fn root_hex(&self) -> String {
        blake3::Hash::from_bytes(self.root()).to_hex().to_string()
    }

    pub fn file_hash(&self, rel: &str) -> Option<[u8; 32]> {
        self.files.get(rel).map(|e| e.hash)
    }

    pub fn dir_hash(&self, rel: &str) -> Option<[u8; 32]> {
        self.dirs.get(rel).copied()
    }

    pub fn files(&self) -> impl Iterator<Item = (&String, &FileEntry)> {
        self.files.iter()
    }

    pub fn len(&self) -> usize {
        self.files.len()
    }

    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// Warm-restart load; a missing/corrupt persisted tree is None — the full
    /// scan re-derives it (persistence is an optimization, never truth).
    pub fn load(path: &Path) -> Option<MerkleTree> {
        let bytes = std::fs::read(path).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let bytes = serde_json::to_vec(self).map_err(std::io::Error::other)?;
        // Atomic replace: a crash mid-write must not leave a torn l0.merkle.
        let tmp = path.with_extension("merkle.tmp");
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, path)
    }

    /// Full worktree scan. `prev` (warm restart) lets an unchanged file
    /// (size + mtime match) reuse its hash without reading the bytes.
    pub fn full_scan(
        root: &Path,
        ignore: &IgnoreSet,
        prev: Option<&MerkleTree>,
    ) -> std::io::Result<MerkleTree> {
        let mut tree = MerkleTree::default();
        walk(root, root, ignore, &mut |rel, meta, abs| {
            let entry = match prev.and_then(|t| t.files.get(rel)) {
                Some(e) if e.size == meta.0 && e.mtime_ns == meta.1 => e.clone(),
                _ => {
                    tree.files_rehashed += 1;
                    FileEntry {
                        hash: hash_file(abs)?,
                        size: meta.0,
                        mtime_ns: meta.1,
                    }
                }
            };
            tree.files.insert(rel.to_string(), entry);
            Ok(())
        })?;
        tree.recompute_dirs(None);
        Ok(tree)
    }

    /// Incremental path (04 §6.1): rehash exactly the changed files, update
    /// merkle path to the root. Returns the rel paths whose content actually
    /// changed (including deletions). Directories arriving whole (e.g. a
    /// `mv dir/` in) are walked; everything else is one stat + one hash.
    pub fn update_paths(
        &mut self,
        root: &Path,
        ignore: &IgnoreSet,
        changed: &[String],
    ) -> std::io::Result<Vec<String>> {
        let mut touched = Vec::new();
        let mut dirty_dirs: BTreeSet<String> = BTreeSet::new();
        for rel in changed {
            let abs = root.join(rel);
            // Lstat: `is_dir()` follows symlinks, and a link to a directory
            // outside the root would otherwise be walked as if it were inside.
            let is_dir_hint = std::fs::symlink_metadata(&abs).is_ok_and(|m| m.is_dir());
            if ignore.matches(rel, is_dir_hint) {
                continue;
            }
            if is_dir_hint {
                // New/renamed-in directory: walk just that subtree.
                walk(root, &abs, ignore, &mut |r, meta, a| {
                    let known = self
                        .files
                        .get(r)
                        .is_some_and(|e| e.size == meta.0 && e.mtime_ns == meta.1);
                    if !known {
                        self.files_rehashed += 1;
                        let entry = FileEntry {
                            hash: hash_file(a)?,
                            size: meta.0,
                            mtime_ns: meta.1,
                        };
                        self.files.insert(r.to_string(), entry);
                        touched.push(r.to_string());
                        dirty_dirs.extend(ancestors(r));
                    }
                    Ok(())
                })?;
                continue;
            }
            match std::fs::symlink_metadata(&abs) {
                Ok(meta) if meta.is_file() => {
                    let size = meta.len();
                    let mtime_ns = mtime_nanos(&meta);
                    self.files_rehashed += 1;
                    let hash = hash_file(&abs)?;
                    let prev = self.files.insert(
                        rel.clone(),
                        FileEntry {
                            hash,
                            size,
                            mtime_ns,
                        },
                    );
                    if prev.map(|e| e.hash) != Some(hash) {
                        touched.push(rel.clone());
                        dirty_dirs.extend(ancestors(rel));
                    }
                }
                _ => {
                    // Deleted (or a symlink — never followed: a link out of the
                    // root must not pull out-of-scope bytes into the tree).
                    if self.files.remove(rel).is_some() {
                        touched.push(rel.clone());
                        dirty_dirs.extend(ancestors(rel));
                    }
                }
            }
        }
        if !touched.is_empty() {
            self.recompute_dirs(Some(&dirty_dirs));
        }
        Ok(touched)
    }

    /// Rebuild directory node hashes. `only` limits recomputation to the
    /// given dirs (the changed files' ancestor chains); None rebuilds all.
    fn recompute_dirs(&mut self, only: Option<&BTreeSet<String>>) {
        // Dir set is derived from the file set — sorted deepest-first so
        // children are final before their parent hashes them.
        let mut all_dirs: BTreeSet<String> = BTreeSet::new();
        for path in self.files.keys() {
            all_dirs.extend(ancestors(path));
        }
        self.dirs.retain(|d, _| all_dirs.contains(d));
        let mut order: Vec<&String> = all_dirs
            .iter()
            .filter(|d| only.is_none_or(|set| set.contains(*d)))
            .collect();
        order.sort_by_key(|d| std::cmp::Reverse(depth(d)));
        let mut new_hashes: Vec<(String, [u8; 32])> = Vec::with_capacity(order.len());
        for dir in order {
            let mut hasher = blake3::Hasher::new();
            // Immediate children: files then dirs, each sorted by the BTreeMap.
            // Kind byte disambiguates "file x" from "dir x"; NUL terminates
            // names so (ab, c) never collides with (a, bc).
            let prefix = if dir.is_empty() {
                String::new()
            } else {
                format!("{dir}/")
            };
            for (path, entry) in self.files.range(prefix.clone()..) {
                let Some(rest) = path.strip_prefix(&prefix) else {
                    break;
                };
                if rest.contains('/') {
                    continue; // deeper than an immediate child
                }
                hasher.update(b"f");
                hasher.update(rest.as_bytes());
                hasher.update(b"\0");
                hasher.update(&entry.hash);
            }
            let staged: BTreeMap<&str, &[u8; 32]> =
                new_hashes.iter().map(|(d, h)| (d.as_str(), h)).collect();
            for sub in all_dirs.iter() {
                let Some(rest) = sub.strip_prefix(&prefix) else {
                    continue;
                };
                if rest.is_empty() || rest.contains('/') {
                    continue;
                }
                // Prefer a hash staged this pass; else the retained old one.
                let hash = staged
                    .get(sub.as_str())
                    .copied()
                    .or(self.dirs.get(sub))
                    .copied()
                    .unwrap_or([0u8; 32]);
                hasher.update(b"d");
                hasher.update(rest.as_bytes());
                hasher.update(b"\0");
                hasher.update(&hash);
            }
            new_hashes.push((dir.clone(), *hasher.finalize().as_bytes()));
        }
        for (dir, hash) in new_hashes {
            self.dirs.insert(dir, hash);
        }
    }
}

/// All ancestor dirs of a rel path, root ("") included, deepest last.
fn ancestors(rel: &str) -> Vec<String> {
    let mut out = vec![String::new()];
    let mut acc = String::new();
    let mut parts = rel.split('/').peekable();
    while let Some(part) = parts.next() {
        if parts.peek().is_none() {
            break; // last segment is the file itself
        }
        if !acc.is_empty() {
            acc.push('/');
        }
        acc.push_str(part);
        out.push(acc.clone());
    }
    out
}

fn depth(dir: &str) -> usize {
    if dir.is_empty() {
        0
    } else {
        dir.split('/').count()
    }
}

fn hash_file(path: &Path) -> std::io::Result<[u8; 32]> {
    // ponytail: whole-file read; blake3 mmap/rayon when multi-GB artifacts in
    // worktrees show up in profiles. Hashing is bounded by the walk skipping
    // nothing — L0 covers every non-ignored byte by contract (04 §6.7).
    let bytes = std::fs::read(path)?;
    Ok(*blake3::hash(&bytes).as_bytes())
}

fn mtime_nanos(meta: &std::fs::Metadata) -> u128 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// Recursive walk under `from` (within `root`), ignore-aware, symlinks never
/// followed (a symlink out of the worktree must not widen the read surface).
/// Non-UTF-8 paths are skipped loudly — the wire schemas are UTF-8 (08 §6).
fn walk(
    root: &Path,
    from: &Path,
    ignore: &IgnoreSet,
    f: &mut impl FnMut(&str, (u64, u128), &Path) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let entries = match std::fs::read_dir(from) {
        Ok(e) => e,
        // A dir deleted mid-walk is a race, not a fault: the watcher will
        // deliver the deletion and the next pass converges.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    for entry in entries {
        let entry = entry?;
        let abs = entry.path();
        let rel_os = match abs.strip_prefix(root) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let Some(rel) = rel_os.to_str().map(|r| r.replace('\\', "/")) else {
            tracing::warn!(path = %abs.display(), "non-UTF-8 path skipped from index");
            continue;
        };
        let meta = entry.metadata()?;
        if meta.is_symlink() {
            continue;
        }
        if meta.is_dir() {
            if !ignore.matches(&rel, true) {
                walk(root, &abs, ignore, f)?;
            }
        } else if meta.is_file() && !ignore.matches(&rel, false) {
            f(&rel, (meta.len(), mtime_nanos(&meta)), &abs)?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// notify watcher → WatchMsg channel (04 §6.1 head of the pipeline)
// ---------------------------------------------------------------------------

/// Start the recursive watcher; events land on `tx` for the single writer
/// task to debounce. Overflow maps to WatchMsg::Overflow (04 §6.6: full
/// rescan, never guess which events were lost).
pub fn start_watcher(
    root: &Path,
    tx: std::sync::mpsc::Sender<crate::WatchMsg>,
) -> notify::Result<notify::RecommendedWatcher> {
    use notify::Watcher;
    let mut watcher =
        notify::recommended_watcher(move |res: notify::Result<notify::Event>| match res {
            Ok(event) => {
                let overflow = event.need_rescan();
                let msg = if overflow {
                    crate::WatchMsg::Overflow
                } else {
                    crate::WatchMsg::Changed(event.paths)
                };
                let _ = tx.send(msg); // receiver gone ⇒ shutting down
            }
            Err(e) => {
                let _ = tx.send(crate::WatchMsg::Overflow);
                tracing::warn!(error = %e, "watcher error; full rescan scheduled");
            }
        })?;
    watcher.watch(root, notify::RecursiveMode::Recursive)?;
    Ok(watcher)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ignore_subset_semantics() {
        let ig = IgnoreSet::from_lines(&[
            "# comment",
            "",
            "target/",
            "*.log",
            "/secret.txt",
            "docs/**/gen",
            "!keep.log", // negation: dropped by design
        ]);
        assert!(ig.matches("target", true));
        assert!(ig.matches("target/debug/foo", false)); // ignored dir contents
        assert!(!ig.matches("src/target.rs", false));
        assert!(ig.matches("a/b/x.log", false));
        assert!(ig.matches("secret.txt", false));
        assert!(!ig.matches("sub/secret.txt", false)); // anchored
        assert!(ig.matches("docs/a/b/gen", true));
        assert!(ig.matches("keep.log", false)); // *.log wins; negation unsupported
        assert!(ig.matches(".git/config", false)); // always
    }

    #[test]
    fn merkle_root_changes_iff_content_changes() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("a/b")).unwrap();
        std::fs::write(dir.path().join("a/b/x.txt"), b"one").unwrap();
        std::fs::write(dir.path().join("top.txt"), b"two").unwrap();
        let ig = IgnoreSet::default();
        let t1 = MerkleTree::full_scan(dir.path(), &ig, None).unwrap();
        let t2 = MerkleTree::full_scan(dir.path(), &ig, None).unwrap();
        assert_eq!(t1.root(), t2.root()); // deterministic
        assert_ne!(t1.root(), [0u8; 32]);

        std::fs::write(dir.path().join("a/b/x.txt"), b"changed").unwrap();
        let t3 = MerkleTree::full_scan(dir.path(), &ig, None).unwrap();
        assert_ne!(t1.root(), t3.root());
    }

    #[test]
    fn incremental_update_matches_full_scan() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("a")).unwrap();
        std::fs::create_dir_all(dir.path().join("b")).unwrap();
        std::fs::write(dir.path().join("a/x.txt"), b"one").unwrap();
        std::fs::write(dir.path().join("b/y.txt"), b"two").unwrap();
        let ig = IgnoreSet::default();
        let mut tree = MerkleTree::full_scan(dir.path(), &ig, None).unwrap();

        std::fs::write(dir.path().join("a/x.txt"), b"three").unwrap();
        let touched = tree
            .update_paths(dir.path(), &ig, &["a/x.txt".into()])
            .unwrap();
        assert_eq!(touched, vec!["a/x.txt".to_string()]);

        let full = MerkleTree::full_scan(dir.path(), &ig, None).unwrap();
        assert_eq!(tree.root(), full.root());
        assert_eq!(tree.dir_hash("b"), full.dir_hash("b"));
    }

    #[test]
    fn deletion_updates_root() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("x.txt"), b"one").unwrap();
        std::fs::write(dir.path().join("y.txt"), b"two").unwrap();
        let ig = IgnoreSet::default();
        let mut tree = MerkleTree::full_scan(dir.path(), &ig, None).unwrap();
        std::fs::remove_file(dir.path().join("x.txt")).unwrap();
        let touched = tree
            .update_paths(dir.path(), &ig, &["x.txt".into()])
            .unwrap();
        assert_eq!(touched, vec!["x.txt".to_string()]);
        let full = MerkleTree::full_scan(dir.path(), &ig, None).unwrap();
        assert_eq!(tree.root(), full.root());
    }
}
