//! conf_vectors_bundle — the Rust leg of the cross-language bundle lock
//! (07 §"PolicyBundle v1": "`mark1-policy` (Rust) is the reference decoder;
//! the Go decoder in `mark1d` is validated against shared conformance
//! vectors").
//!
//! Drives EVERY entry in conformance/vectors/bundle/manifest.json, positives
//! and negatives, asserting the NAMED code and kind for each negative — a
//! negative that fails for the wrong reason is a failure. `conf_vectors_`
//! prefixes are load-bearing: conformance_crosslang.sh selects Rust tests by
//! that filter and treats a filter matching nothing as a FAILED run (12 §3.4).

// clippy.toml's allow-*-in-tests exempts #[test] fns; the vector-driver
// helpers here are plain fns, so the same exemption is restated at file scope.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use mark1_policy::{verify_and_decode, Section, SectionKeys, TlogHead};
use mark1_receipt::{hex, Ed25519Signer, KeyEntry, KeyRole, Signer};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/vectors/bundle")
}

fn manifest() -> Value {
    let m: Value =
        serde_json::from_str(&fs::read_to_string(dir().join("manifest.json")).unwrap()).unwrap();
    // A truncated or hand-emptied family passes every remaining loop
    // vacuously — a suite that goes green while asserting nothing.
    assert!(
        !m["vectors"].as_array().unwrap().is_empty(),
        "manifest vectors empty"
    );
    m
}

fn key_set(m: &Value) -> SectionKeys {
    let mut keys = SectionKeys::new();
    for s in Section::ALL {
        let k = &m["keys"][s.name()];
        let public: [u8; 32] = hex::decode_array(k["public_hex"].as_str().unwrap()).unwrap();
        let key_id = keys.insert_public(s, public);
        assert_eq!(
            key_id,
            k["key_id"].as_str().unwrap(),
            "{} key_id drift",
            s.name()
        );
    }
    // The rotated-out verify key (outside_validity's signer): published WITH
    // its window, exactly as a real driver would load a historical ring.
    let ek = &m["expired_key"];
    assert_eq!(ek["section"].as_str().unwrap(), "verify");
    let public: [u8; 32] = hex::decode_array(ek["public_hex"].as_str().unwrap()).unwrap();
    let mut entry = KeyEntry::new(public, KeyRole::ServerChain);
    entry.not_after = Some(ek["not_after"].as_str().unwrap().to_string());
    let key_id = keys.insert(Section::Verify, entry);
    assert_eq!(key_id, ek["key_id"].as_str().unwrap(), "expired key_id");
    keys
}

/// The pinned log head a vector's driving caller holds (D-S): null in the
/// manifest = no head pinned.
fn tlog_head(entry: &Value) -> Option<TlogHead> {
    let h = &entry["tlog_head"];
    if h.is_null() {
        return None;
    }
    Some(TlogHead {
        tree_size: h["tree_size"].as_u64().unwrap(),
        root: hex::decode_array(h["root_hex"].as_str().unwrap()).unwrap(),
    })
}

#[test]
fn conf_vectors_bundle_keys_derive_from_published_seeds() {
    let m = manifest();
    for s in Section::ALL {
        let k = &m["keys"][s.name()];
        let seed: [u8; 32] = hex::decode_array(k["seed_hex"].as_str().unwrap()).unwrap();
        let signer = Ed25519Signer::from_seed(seed);
        assert_eq!(
            hex::encode(&signer.public_key()),
            k["public_hex"].as_str().unwrap()
        );
        assert_eq!(signer.key_id(), k["key_id"].as_str().unwrap());
    }
}

#[test]
fn conf_vectors_bundle_disk_matches_manifest() {
    // Manifest/disk drift — a vector added without a contract line, or a
    // frozen file deleted — is a failure of the family, not of one test.
    let m = manifest();
    let listed: BTreeSet<String> = m["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["file"].as_str().unwrap().to_string())
        .collect();
    let on_disk: BTreeSet<String> = fs::read_dir(dir())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".cbor"))
        .collect();
    assert_eq!(listed, on_disk);
}

#[test]
fn conf_vectors_bundle_every_entry() {
    let m = manifest();
    let keys = key_set(&m);
    for entry in m["vectors"].as_array().unwrap() {
        let name = entry["name"].as_str().unwrap();
        let raw = fs::read(dir().join(entry["file"].as_str().unwrap())).unwrap();
        // The frozen bytes themselves are part of the contract.
        assert_eq!(
            hex::encode(&Sha256::digest(&raw)),
            entry["file_sha256_hex"].as_str().unwrap(),
            "{name}: vector file bytes drifted from the frozen manifest"
        );
        let last = entry["last_applied_seq"].as_u64();
        let head = tlog_head(entry);
        let outcome = verify_and_decode(&raw, &keys, last, head.as_ref());
        match entry["expect"].as_str().unwrap() {
            "accept" => {
                let bundle = match outcome {
                    Ok(b) => b,
                    Err(e) => panic!("{name}: accept vector rejected: {e}"),
                };
                assert_eq!(
                    hex::encode(&bundle.body_sha256),
                    entry["body_sha256_hex"].as_str().unwrap(),
                    "{name}: body hash"
                );
                let s = &entry["summary"];
                assert_eq!(bundle.seq, s["seq"].as_u64().unwrap(), "{name}: seq");
                assert_eq!(
                    bundle.channel,
                    s["channel"].as_str().unwrap(),
                    "{name}: channel"
                );
                assert_eq!(
                    bundle.issued_at_epoch_s,
                    s["issued_at_epoch_s"].as_u64().unwrap(),
                    "{name}: issued_at"
                );
                assert_eq!(bundle.max_age.as_secs(), s["max_age_s"].as_u64().unwrap());
                assert_eq!(
                    bundle.verify.anchors.len() as u64,
                    s["anchors"].as_u64().unwrap()
                );
                assert_eq!(
                    bundle.verify.verifiers.len() as u64,
                    s["verifiers"].as_u64().unwrap()
                );
                assert_eq!(
                    bundle.verify.quarantined.iter().filter(|q| **q).count() as u64,
                    s["quarantined"].as_u64().unwrap(),
                    "{name}: quarantined"
                );
                assert_eq!(
                    bundle.verify.correlation_groups.len() as u64,
                    s["correlation_groups"].as_u64().unwrap()
                );
                assert_eq!(
                    bundle.route.knee.rows.len() as u64,
                    s["knee_rows"].as_u64().unwrap()
                );
                assert_eq!(
                    bundle.route.exploration_epsilon,
                    s["exploration_epsilon"].as_f64().unwrap(),
                    "{name}: epsilon"
                );
                assert_eq!(
                    bundle.gates.stop_gate_enabled,
                    s["stop_gate_enabled"].as_bool().unwrap()
                );
                assert_eq!(
                    u64::from(bundle.gates.max_consecutive_blocks),
                    s["max_consecutive_blocks"].as_u64().unwrap()
                );
                assert_eq!(
                    bundle.agent_maps.agents.len() as u64,
                    s["agents"].as_u64().unwrap()
                );
                // D-S's exposure: the verified inclusion coordinates ride the
                // Bundle so a caller can audit — present exactly when a head
                // was pinned (i.e. seq > 0), and matching it.
                match (&head, &bundle.tlog) {
                    (None, None) => {}
                    (Some(h), Some(t)) => {
                        assert_eq!(t.root, h.root, "{name}: tlog root exposure");
                        assert_eq!(t.tree_size, h.tree_size, "{name}: tlog tree_size");
                    }
                    (h, t) => panic!("{name}: head {h:?} vs exposed tlog {t:?}"),
                }
            }
            "reject" => {
                let reject = match outcome {
                    Err(e) => e,
                    Ok(_) => panic!("{name}: negative vector accepted"),
                };
                // The NAMED reject, code and kind — wrong-reason failures are
                // failures (receipt-family README rule, kept).
                assert_eq!(
                    reject.code(),
                    entry["code"].as_str().unwrap(),
                    "{name}: code"
                );
                assert_eq!(
                    reject.kind(),
                    entry["kind"].as_str().unwrap(),
                    "{name}: kind"
                );
            }
            other => panic!("{name}: unknown expect {other}"),
        }
    }
}

#[test]
fn bundle_staleness_boundary_is_inclusive() {
    // The shared fail-static evaluation (04 §7.3), against the frozen
    // bundle_zero fixture: issued_at 2026-08-29T00:00:00Z, max_age one year.
    let m = manifest();
    let keys = key_set(&m);
    let raw = fs::read(dir().join("bundle_zero.cbor")).unwrap();
    let bundle = verify_and_decode(&raw, &keys, None, None).unwrap();
    let issued = bundle.issued_at_epoch_s;
    let max_age = bundle.max_age.as_secs();
    assert!(bundle.is_fresh(issued)); // age zero
    assert!(bundle.is_fresh(issued + max_age)); // "past it" ⇒ boundary is fresh
    assert!(!bundle.is_fresh(issued + max_age + 1)); // one second past ⇒ built-ins
    assert!(bundle.is_fresh(issued - 1)); // clock skew: negative age is zero age
    assert!(bundle.is_fresh(0)); // even a stepped-to-epoch clock
}

#[test]
fn conf_vectors_bundle_zero_turns_fusion_on() {
    // D-P's whole point: the committed bundle-zero fixture enables Phase 2
    // fusion — anchors on, verifier models present, knee rows present —
    // through the REAL decoder, seq 0, channel "local", waiver structural.
    let m = manifest();
    let keys = key_set(&m);
    let raw = fs::read(dir().join("bundle_zero.cbor")).unwrap();
    // D-P × D-S: bundle zero is pre-log, so no head is needed — and holding
    // one changes nothing (the waiver is structural, not head-dependent).
    let bundle = verify_and_decode(&raw, &keys, None, None).unwrap();
    assert_eq!(bundle.seq, 0);
    assert_eq!(bundle.channel, "local");
    assert_eq!(bundle.prev_hash, [0u8; 32]);
    assert!(bundle.tlog.is_none());
    assert!(bundle.verify.anchors.iter().any(|a| a.enabled));
    assert!(!bundle.verify.verifiers.is_empty());
    assert!(!bundle.verify.correlation_groups.is_empty());
    assert!(!bundle.route.knee.rows.is_empty());
    let stray_head = TlogHead {
        tree_size: 1,
        root: [0x5a; 32],
    };
    assert!(verify_and_decode(&raw, &keys, None, Some(&stray_head)).is_ok());
    // And the replay guard still applies to bundle zero itself: once ANY
    // bundle is applied, seq 0 is dead forever.
    assert!(verify_and_decode(&raw, &keys, Some(0), None).is_err());
}
