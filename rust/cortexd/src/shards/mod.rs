//! redb graph shards (04 §6.2): tag artifacts persisted per TOP-LEVEL
//! DIRECTORY hash, bounding the blast radius of one corrupt shard to one
//! subtree. A corrupt shard is DELETED and its subtree reindexed (M1E-6404
//! refusals until rebuilt) — never repaired in place.

use std::collections::BTreeMap;
use std::path::Path;

use redb::{Database, ReadableTable, TableDefinition};

use crate::l1_tags::Tag;
use crate::CortexError;

const TAGS: TableDefinition<&str, &[u8]> = TableDefinition::new("tags.v1");

/// Shard key for a rel path: its top-level directory (root-level files share
/// the `""` shard).
fn topdir(rel: &str) -> &str {
    match rel.find('/') {
        Some(i) => &rel[..i],
        None => "",
    }
}

fn shard_file(dir: &Path, top: &str) -> std::path::PathBuf {
    // Hash, not the raw name: shard filenames stay fixed-width and never leak
    // path bytes into a store directory listing (04 §6.2 "keyed by top-level
    // directory hash").
    let hex = blake3::hash(top.as_bytes()).to_hex();
    dir.join(format!("{}.redb", &hex.as_str()[..16]))
}

/// Persist all tags, one shard per top-level dir. Existing shard files not in
/// the current set are removed (a deleted top-level dir leaves no orphan).
pub fn save_all(dir: &Path, tags: &BTreeMap<String, Vec<Tag>>) -> Result<(), CortexError> {
    std::fs::create_dir_all(dir)?;
    let mut by_shard: BTreeMap<&str, Vec<(&String, &Vec<Tag>)>> = BTreeMap::new();
    for (path, file_tags) in tags {
        by_shard
            .entry(topdir(path))
            .or_default()
            .push((path, file_tags));
    }
    let mut live_files = Vec::new();
    for (top, entries) in &by_shard {
        let file = shard_file(dir, top);
        live_files.push(file.clone());
        // Rewrite-whole-shard: delete-then-create keeps every shard write a
        // fresh, verifiable file. ponytail: per-file delta upserts when shard
        // rewrite shows up in the settle profile.
        let _ = std::fs::remove_file(&file);
        let db = Database::create(&file).map_err(shard_io)?;
        let tx = db.begin_write().map_err(shard_io)?;
        {
            let mut table = tx.open_table(TAGS).map_err(shard_io)?;
            for (path, file_tags) in entries {
                let body = serde_json::to_vec(file_tags)?;
                table
                    .insert(path.as_str(), body.as_slice())
                    .map_err(shard_io)?;
            }
        }
        tx.commit().map_err(shard_io)?;
    }
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().is_some_and(|e| e == "redb") && !live_files.contains(&path) {
            let _ = std::fs::remove_file(&path);
        }
    }
    Ok(())
}

/// Warm-restart load of every shard. Any unreadable shard is deleted on the
/// spot and the whole warm set is discarded (None) — the caller's full L1
/// pass re-derives from the CAS, which is cheap and cannot be torn.
pub fn load_all(dir: &Path) -> Option<BTreeMap<String, Vec<Tag>>> {
    let mut out = BTreeMap::new();
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "redb") {
            continue;
        }
        match load_shard(&path) {
            Ok(shard) => out.extend(shard),
            Err(e) => {
                tracing::warn!(shard = %path.display(), error = %e,
                    "corrupt shard deleted; reindexing (04 §6.2)");
                let _ = std::fs::remove_file(&path);
                return None;
            }
        }
    }
    Some(out)
}

fn load_shard(path: &Path) -> Result<BTreeMap<String, Vec<Tag>>, CortexError> {
    let db = Database::open(path).map_err(shard_io)?;
    let tx = db.begin_read().map_err(shard_io)?;
    let table = tx.open_table(TAGS).map_err(shard_io)?;
    let mut out = BTreeMap::new();
    for row in table.iter().map_err(shard_io)? {
        let (key, value) = row.map_err(shard_io)?;
        let tags: Vec<Tag> = serde_json::from_slice(value.value())?;
        out.insert(key.value().to_string(), tags);
    }
    Ok(out)
}

/// redb's error taxonomy collapsed to io for CortexError — the caller's only
/// decision is delete-and-reindex, which needs no finer grain.
fn shard_io(e: impl std::fmt::Display) -> CortexError {
    CortexError::Io(std::io::Error::other(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l1_tags::Role;

    fn tags_fixture() -> BTreeMap<String, Vec<Tag>> {
        let mut m = BTreeMap::new();
        m.insert(
            "a/x.rs".to_string(),
            vec![Tag {
                name: "x".into(),
                line: 1,
                role: Role::Def,
                kind: "function".into(),
                signature: "fn x()".into(),
            }],
        );
        m.insert("b/y.py".to_string(), Vec::new());
        m.insert("top.go".to_string(), Vec::new());
        m
    }

    #[test]
    fn roundtrip_and_shard_split() {
        let dir = tempfile::tempdir().unwrap();
        let tags = tags_fixture();
        save_all(dir.path(), &tags).unwrap();
        // three topdirs ("a", "b", "") → three shard files
        let count = std::fs::read_dir(dir.path()).unwrap().count();
        assert_eq!(count, 3);
        assert_eq!(load_all(dir.path()).unwrap(), tags);
    }

    #[test]
    fn corrupt_shard_is_deleted_not_repaired() {
        let dir = tempfile::tempdir().unwrap();
        save_all(dir.path(), &tags_fixture()).unwrap();
        let victim = shard_file(dir.path(), "a");
        std::fs::write(&victim, b"garbage, not a redb file").unwrap();
        assert!(load_all(dir.path()).is_none());
        assert!(!victim.exists(), "corrupt shard must be deleted");
    }
}
