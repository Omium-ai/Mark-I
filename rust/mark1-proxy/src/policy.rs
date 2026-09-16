//! Route section from mark1d's custody (`<base>/policy/lkg.cbor`, `bundle/client.go` persist), re-verified as `loadLKG` does: a 0700 dir is a boundary, not a proof.

use std::path::Path;
use std::sync::{Arc, Weak};
use std::time::{Duration, SystemTime};

use mark1_policy::{verify_and_decode, Section, SectionKeys, TlogHead};
use mark1_receipt::{KeyEntry, KeyRole};

use crate::guard::provenance::parse_fingerprint_hex;
use crate::router::{Proxy, RouteTable};

/// Stat cadence for `lkg.json`; the daemon's own apply is a 5-minute poll (04 §2.6).
pub const POLL_EVERY: Duration = Duration::from_secs(5);

#[derive(serde::Deserialize)]
struct TrustFile {
    bundle_section_keys: Vec<TrustKey>,
}

/// One `keys.json` entry (`trustFile`, `bundle/client.go`); an empty window side is unbounded.
#[derive(serde::Deserialize)]
struct TrustKey {
    section: String,
    pubkey_hex: String,
    #[serde(default)]
    not_before: String,
    #[serde(default)]
    not_after: String,
}

#[derive(serde::Deserialize)]
struct LkgMeta {
    seq: u64,
    #[serde(default)]
    tlog_head_tree_size: u64,
    #[serde(default)]
    tlog_head_root_hex: String,
}

fn keys(dir: &Path) -> Option<SectionKeys> {
    let tf: TrustFile = serde_json::from_slice(&std::fs::read(dir.join("keys.json")).ok()?).ok()?;
    let mut keys = SectionKeys::new();
    let mut n = 0;
    for k in tf.bundle_section_keys {
        let section = Section::ALL.into_iter().find(|s| s.name() == k.section)?;
        let mut entry = KeyEntry::new(parse_fingerprint_hex(&k.pubkey_hex)?, KeyRole::ServerChain);
        entry.not_before = Some(k.not_before).filter(|s| !s.is_empty());
        entry.not_after = Some(k.not_after).filter(|s| !s.is_empty());
        keys.insert(section, entry);
        n += 1;
    }
    (n > 0).then_some(keys)
}

/// `loadLKG`'s checks in its order (keys, meta, head, verify, seq agreement), then freshness and ε=0.
pub fn load_route_table(base: &Path, now_epoch_s: u64) -> Option<RouteTable> {
    let dir = base.join("policy");
    let keys = keys(&dir)?;
    let meta: LkgMeta = serde_json::from_slice(&std::fs::read(dir.join("lkg.json")).ok()?).ok()?;
    let head = if meta.tlog_head_root_hex.is_empty() && meta.tlog_head_tree_size == 0 {
        None
    } else {
        Some(TlogHead {
            tree_size: meta.tlog_head_tree_size,
            root: parse_fingerprint_hex(&meta.tlog_head_root_hex)?,
        })
    };
    let raw = std::fs::read(dir.join("lkg.cbor")).ok()?;
    let bundle = match verify_and_decode(&raw, &keys, None, head.as_ref()) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(target: "mark1_proxy::policy", code = e.code(), "last-known-good bundle does not verify; route stays ADVISORY");
            return None;
        }
    };
    if bundle.seq != meta.seq || !bundle.is_fresh(now_epoch_s) {
        return None;
    }
    RouteTable::from_route(&bundle.route, bundle.seq).map(|t| {
        t.fresh_until(
            bundle
                .issued_at_epoch_s
                .saturating_add(bundle.max_age.as_secs()),
        )
    })
}

fn now_epoch_s() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn stamp(dir: &Path) -> Option<SystemTime> {
    std::fs::metadata(dir.join("lkg.json"))
        .ok()?
        .modified()
        .ok()
}

/// Boot load, then reload on an `lkg.json` mtime change and drop past `max_age`; ends with the proxy.
pub async fn watch(base: std::path::PathBuf, proxy: Weak<Proxy>) {
    let dir = base.join("policy");
    let mut seen = stamp(&dir);
    if let Some(p) = proxy.upgrade() {
        p.set_route(load_route_table(&base, now_epoch_s()).map(Arc::new));
    }
    loop {
        tokio::time::sleep(POLL_EVERY).await;
        let Some(p) = proxy.upgrade() else { return };
        let now = now_epoch_s();
        let current = stamp(&dir);
        if current != seen {
            seen = current;
            let table = load_route_table(&base, now);
            tracing::info!(target: "mark1_proxy::policy", seq = table.as_ref().map(RouteTable::bundle_seq), "route table reloaded");
            p.set_route(table.map(Arc::new));
        } else if p.route_stale(now) {
            tracing::warn!(target: "mark1_proxy::policy", "route table past max_age; every request ADVISORY (M1E-3006)");
            p.set_route(None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTORS: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/vectors/bundle"
    );

    /// mark1d's custody for the frozen `bundle_zero` vector, keys from the manifest.
    fn custody(base: &Path, meta: &str) {
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(format!("{VECTORS}/manifest.json")).unwrap())
                .unwrap();
        let keys: Vec<serde_json::Value> = manifest["keys"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(section, k)| {
                serde_json::json!({ "section": section, "pubkey_hex": k["public_hex"], "not_before": "", "not_after": "" })
            })
            .collect();
        let dir = base.join("policy");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("keys.json"),
            serde_json::to_vec(&serde_json::json!({ "bundle_section_keys": keys })).unwrap(),
        )
        .unwrap();
        std::fs::copy(format!("{VECTORS}/bundle_zero.cbor"), dir.join("lkg.cbor")).unwrap();
        std::fs::write(dir.join("lkg.json"), meta).unwrap();
    }

    /// `issued_at` of every frozen vector (manifest `issued_at_epoch_s`).
    const ISSUED: u64 = 1_787_961_600;

    #[test]
    fn loads_the_daemons_verified_lkg_and_nothing_else() {
        let tmp = tempfile::tempdir().unwrap();
        custody(
            tmp.path(),
            r#"{"seq":0,"etag":"","applied_at":"","body_sha256_hex":""}"#,
        );
        let table = load_route_table(tmp.path(), ISSUED + 60).expect("bundle_zero verifies");
        assert_eq!(table.bundle_seq(), 0);
        assert!(
            table.served("claude-haiku-4-5").is_some(),
            "bundle_zero carries a ladder"
        );

        // Past max_age (1 y): stale ⇒ no table, the M1E-3006 posture.
        assert!(load_route_table(tmp.path(), ISSUED + 31_536_001).is_none());
        // Meta disagreeing with the bundle it describes: ignored, as loadLKG ignores it.
        custody(tmp.path(), r#"{"seq":9}"#);
        assert!(load_route_table(tmp.path(), ISSUED + 60).is_none());
    }

    /// One flipped byte in custody must leave every request ADVISORY.
    #[test]
    fn a_tampered_lkg_yields_no_table() {
        let tmp = tempfile::tempdir().unwrap();
        custody(tmp.path(), r#"{"seq":0}"#);
        let path = tmp.path().join("policy/lkg.cbor");
        let mut raw = std::fs::read(&path).unwrap();
        let i = raw.len() / 2;
        raw[i] ^= 0x01;
        std::fs::write(&path, raw).unwrap();
        assert!(load_route_table(tmp.path(), ISSUED + 60).is_none());
        // And no keys at all is no table, not a table under a key we made up.
        std::fs::remove_file(tmp.path().join("policy/keys.json")).unwrap();
        custody(tmp.path(), r#"{"seq":0}"#);
        std::fs::write(
            tmp.path().join("policy/keys.json"),
            b"{\"bundle_section_keys\":[]}",
        )
        .unwrap();
        assert!(load_route_table(tmp.path(), ISSUED + 60).is_none());
    }
}
