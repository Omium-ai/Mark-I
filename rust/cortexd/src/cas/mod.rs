//! CAS — SQLite content-addressed store of derived artifacts (04 §6.1/§6.2).
//!
//! Key is the full provenance 5-tuple `(path, content_hash, grammar_rev,
//! query_rev, indexer_rev)`: bumping a grammar, a tags query, or the indexer
//! invalidates exactly the derived layers, never the content hashes — an
//! unchanged file after a grammar bump costs one CAS probe + one re-parse,
//! not a merkle recompute.

use std::path::Path;
use std::sync::Mutex;

use crate::l1_tags::Tag;
use crate::CortexError;

pub struct Cas {
    // ponytail: one connection behind a mutex — the writer task is the only
    // steady-state caller (04 §6.3), so a pool buys nothing at Phase 2.
    conn: Mutex<rusqlite::Connection>,
}

impl Cas {
    pub fn open(path: &Path) -> Result<Cas, CortexError> {
        let conn = rusqlite::Connection::open(path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS artifacts (
               path         TEXT    NOT NULL,
               content_hash BLOB    NOT NULL,
               grammar_rev  TEXT    NOT NULL,
               query_rev    INTEGER NOT NULL,
               indexer_rev  INTEGER NOT NULL,
               body         BLOB    NOT NULL,
               PRIMARY KEY (path, content_hash, grammar_rev, query_rev, indexer_rev)
             );",
        )?;
        Ok(Cas {
            conn: Mutex::new(conn),
        })
    }

    pub fn get_tags(
        &self,
        path: &str,
        content_hash: &[u8; 32],
        grammar_rev: &str,
        query_rev: u32,
        indexer_rev: u32,
    ) -> Result<Option<Vec<Tag>>, CortexError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare_cached(
            "SELECT body FROM artifacts
             WHERE path=?1 AND content_hash=?2 AND grammar_rev=?3
               AND query_rev=?4 AND indexer_rev=?5",
        )?;
        let body: Option<Vec<u8>> = stmt
            .query_row(
                rusqlite::params![
                    path,
                    content_hash.as_slice(),
                    grammar_rev,
                    query_rev,
                    indexer_rev
                ],
                |row| row.get(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })?;
        let Some(body) = body else { return Ok(None) };
        // A CAS row that fails to decode is treated as a miss, not a fault:
        // the caller re-derives and overwrites — self-healing, never trusted.
        let decoded = zstd::decode_all(body.as_slice())
            .ok()
            .and_then(|json| serde_json::from_slice(&json).ok());
        Ok(decoded)
    }

    pub fn put_tags(
        &self,
        path: &str,
        content_hash: &[u8; 32],
        grammar_rev: &str,
        query_rev: u32,
        indexer_rev: u32,
        tags: &[Tag],
    ) -> Result<(), CortexError> {
        let json = serde_json::to_vec(tags)?;
        let body = zstd::encode_all(json.as_slice(), 1).map_err(CortexError::Io)?;
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "INSERT OR REPLACE INTO artifacts
               (path, content_hash, grammar_rev, query_rev, indexer_rev, body)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                path,
                content_hash.as_slice(),
                grammar_rev,
                query_rev,
                indexer_rev,
                body
            ],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l1_tags::Role;

    fn tag() -> Tag {
        Tag {
            name: "f".into(),
            line: 1,
            role: Role::Def,
            kind: "function".into(),
            signature: "fn f()".into(),
        }
    }

    #[test]
    fn grammar_rev_bump_is_a_miss() {
        let dir = tempfile::tempdir().unwrap();
        let cas = Cas::open(&dir.path().join("cas.sqlite")).unwrap();
        let hash = [7u8; 32];
        cas.put_tags("a.rs", &hash, "rs0.24", 1, 1, &[tag()])
            .unwrap();

        assert!(cas
            .get_tags("a.rs", &hash, "rs0.24", 1, 1)
            .unwrap()
            .is_some());
        // FR-CORTEX-007: any single component bump invalidates.
        assert!(cas
            .get_tags("a.rs", &hash, "rs0.25", 1, 1)
            .unwrap()
            .is_none());
        assert!(cas
            .get_tags("a.rs", &hash, "rs0.24", 2, 1)
            .unwrap()
            .is_none());
        assert!(cas
            .get_tags("a.rs", &hash, "rs0.24", 1, 2)
            .unwrap()
            .is_none());
        assert!(cas
            .get_tags("a.rs", &[8u8; 32], "rs0.24", 1, 1)
            .unwrap()
            .is_none());
        assert!(cas
            .get_tags("b.rs", &hash, "rs0.24", 1, 1)
            .unwrap()
            .is_none());
    }
}
