//! conf_vectors — the Rust leg of the three-language receipt lock.
//!
//! Drives EVERY entry in conformance/vectors/receipt/manifest.json, positives
//! and negatives, asserting the NAMED defect for each negative (README: a
//! negative that fails for the wrong reason is a failure). `conf_vectors_`
//! prefixes are load-bearing: `conformance_crosslang.sh` selects Rust tests by
//! that filter and treats a filter matching nothing as a FAILED run (12 §3.4).

// clippy.toml's allow-*-in-tests exempts #[test] fns; the vector-driver
// helpers here are plain fns, so the same exemption is restated at file scope.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use mark1_receipt::{
    canonical_bytes, canonical_json, derive_key_id, dual_sign, hex, inclusion_path, merkle_root,
    receipt_hash, signing_input_of, verify_chain, verify_inclusion, verify_merkle_root,
    CheckpointPayload, Ed25519Signer, KeyEntry, KeyRing, KeyRole, ReceiptRow, Signer,
    DOMAIN_PREFIX, GENESIS_HASH,
};
use serde_json::Value;

fn manifest() -> Value {
    // Path-relative to the crate so the test runs from any cwd; the manifest
    // is the frozen cross-language contract (README: "the referee").
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/vectors/receipt/manifest.json");
    let m: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    // A truncated or hand-emptied family would pass every remaining loop
    // vacuously — a suite that goes green while asserting nothing about
    // tamper detection (the Go leg's loadManifest guard, ported).
    for family in ["canonical", "chain", "negatives"] {
        assert!(
            !m[family].as_array().unwrap().is_empty(),
            "manifest family {family} is empty"
        );
    }
    assert!(!m["merkle"]["cases"].as_array().unwrap().is_empty());
    m
}

fn hex_n<const N: usize>(v: &Value) -> [u8; N] {
    hex::decode_array(v.as_str().unwrap()).unwrap()
}

fn key_ring(m: &Value) -> KeyRing {
    let mut ring = KeyRing::new();
    // Role binding is part of the contract under test (README "Signatures"):
    // the device key verifies origin claims ONLY, the server key
    // countersignatures ONLY.
    for (role, key_role) in [
        ("device", KeyRole::DeviceOrigin),
        ("server", KeyRole::ServerChain),
    ] {
        ring.insert(KeyEntry::new(
            hex_n(&m["keys"][role]["public_hex"]),
            key_role,
        ));
    }
    ring
}

fn signer(m: &Value, role: &str) -> Ed25519Signer {
    Ed25519Signer::from_seed(hex_n(&m["keys"][role]["seed_hex"]))
}

/// Manifest receipt object → m1_002 row shape.
///
/// The stored payload text is the `canonical_json` field when it parses back
/// to the entry's `payload` object (the text-level tamper vectors keep the two
/// consistent that way), else the payload object's own canonicalisation (the
/// object-level tamper vectors mutate the object and leave the text stale on
/// purpose) — the same rule as the Python leg's `_row`, kept so the two suites
/// feed their walkers identical bytes.
fn row(entry: &Value) -> ReceiptRow {
    let text = entry["canonical_json"].as_str().unwrap();
    let consistent = serde_json::from_str::<Value>(text)
        .map(|v| v == entry["payload"])
        .unwrap_or(false);
    let payload = if consistent {
        text.to_string()
    } else {
        canonical_json(&entry["payload"]).unwrap()
    };
    ReceiptRow {
        seq: entry["seq"].as_u64().unwrap(),
        payload,
        receipt_hash: hex_n(&entry["receipt_hash_hex"]),
        // null on server-only rows and the stripped-signature negative.
        device_key_id: entry["device_key_id"].as_str().map(String::from),
        device_signature: entry["device_signature_hex"]
            .as_str()
            .map(|s| hex::decode_array(s).unwrap()),
        server_key_id: entry["server_key_id"].as_str().unwrap().to_string(),
        server_signature: hex_n(&entry["server_signature_hex"]),
    }
}

fn leaves_of(v: &Value) -> Vec<[u8; 16]> {
    v.as_array().unwrap().iter().map(hex_n::<16>).collect()
}

#[test]
fn conf_vectors_domain_prefix_and_genesis() {
    let m = manifest();
    assert_eq!(
        hex::encode(DOMAIN_PREFIX),
        m["domain_prefix_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(&GENESIS_HASH),
        m["genesis_hash_hex"].as_str().unwrap()
    );
}

#[test]
fn conf_vectors_key_derivation() {
    let m = manifest();
    for role in ["device", "server"] {
        let k = &m["keys"][role];
        let s = signer(&m, role);
        assert_eq!(
            hex::encode(&s.public_key()),
            k["public_hex"].as_str().unwrap(),
            "{role}"
        );
        assert_eq!(s.key_id(), k["key_id"].as_str().unwrap(), "{role}");
        assert_eq!(
            derive_key_id(&s.public_key()),
            k["key_id"].as_str().unwrap(),
            "{role}"
        );
    }
}

#[test]
fn conf_vectors_canonical() {
    let m = manifest();
    for case in m["canonical"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        assert_eq!(
            canonical_json(&case["payload"]).unwrap(),
            case["canonical_json"].as_str().unwrap(),
            "{name}"
        );
        assert_eq!(
            hex::encode(&canonical_bytes(&case["payload"]).unwrap()),
            case["canonical_bytes_hex"].as_str().unwrap(),
            "{name}"
        );
        assert_eq!(
            hex::encode(&receipt_hash(&case["payload"]).unwrap()),
            case["receipt_hash_hex"].as_str().unwrap(),
            "{name}"
        );
    }
}

#[test]
fn conf_vectors_canonical_refuses_non_integer_numbers() {
    // README "Numbers: integers only": a float is REFUSED, never rendered —
    // no vector can carry one, so the refusal arm is asserted directly.
    assert!(canonical_json(&serde_json::json!({ "x": 1.5 })).is_err());
}

#[test]
fn conf_vectors_merkle() {
    let m = manifest();
    for case in m["merkle"]["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let leaves = leaves_of(&case["leaves_hex"]);
        let root: [u8; 32] = hex_n(&case["root_hex"]);
        assert_eq!(merkle_root(&leaves).unwrap(), root, "{name}");
        for (idx_str, path_hex) in case["inclusion_paths"].as_object().unwrap() {
            let idx: usize = idx_str.parse().unwrap();
            let path: Vec<[u8; 32]> = path_hex
                .as_array()
                .unwrap()
                .iter()
                .map(hex_n::<32>)
                .collect();
            assert_eq!(inclusion_path(&leaves, idx).unwrap(), path, "{name}[{idx}]");
            assert!(
                verify_inclusion(&leaves[idx], idx, &path, &root, leaves.len()),
                "{name}[{idx}]"
            );
        }
    }
}

#[test]
fn conf_vectors_chain_assembly_reproduces_frozen_bytes() {
    // Ed25519 is deterministic, so the WHOLE row — bytes, hash, both
    // signatures — must reproduce from the seeds; any drift in
    // canonicalisation or signing input lands here.
    let m = manifest();
    let device = signer(&m, "device");
    let server = signer(&m, "server");
    for entry in m["chain"].as_array().unwrap() {
        let p = &entry["payload"];
        let seq = entry["seq"].as_u64().unwrap();
        if p["type"].as_str().unwrap() != "checkpoint" {
            // Server-only classes have no device-side builder: reproduce the
            // canonical bytes and the server countersignature directly —
            // Ed25519 determinism still locks every byte.
            let text = canonical_json(p).unwrap();
            assert_eq!(text, entry["canonical_json"].as_str().unwrap(), "seq{seq}");
            let signing_input = signing_input_of(&text);
            assert_eq!(
                hex::encode(&server.sign(&signing_input)),
                entry["server_signature_hex"].as_str().unwrap(),
                "seq{seq}"
            );
            assert_eq!(
                hex::encode(&receipt_hash(p).unwrap()),
                entry["receipt_hash_hex"].as_str().unwrap(),
                "seq{seq}"
            );
            assert!(entry["device_signature_hex"].is_null(), "seq{seq}");
            continue;
        }
        let device_key_id = device.key_id();
        let payload = CheckpointPayload {
            tenant_id: p["tenant_id"].as_str().unwrap(),
            seq: p["seq"].as_u64().unwrap(),
            prev_receipt_hash: hex_n(&p["prev_receipt_hash"]),
            device_id: p["device_id"].as_str().unwrap(),
            device_key_id: &device_key_id,
            issued_at: p["issued_at"].as_str().unwrap(),
            checkpoint_seq: p["checkpoint_seq"].as_u64().unwrap(),
            merkle_root: hex_n(&p["merkle_root"]),
            leaf_count: p["leaf_count"].as_u64().unwrap(),
        };
        let built = dual_sign(&payload.to_value(), &device, &server).unwrap();
        assert_eq!(
            built.payload,
            entry["canonical_json"].as_str().unwrap(),
            "seq{seq}"
        );
        assert_eq!(
            hex::encode(&built.receipt_hash),
            entry["receipt_hash_hex"].as_str().unwrap(),
            "seq{seq}"
        );
        assert_eq!(
            hex::encode(&built.device_signature.unwrap()),
            entry["device_signature_hex"].as_str().unwrap(),
            "seq{seq}"
        );
        assert_eq!(
            hex::encode(&built.server_signature),
            entry["server_signature_hex"].as_str().unwrap(),
            "seq{seq}"
        );
    }
}

#[test]
fn conf_vectors_chain_verifies_from_genesis() {
    let m = manifest();
    let rows: Vec<ReceiptRow> = m["chain"].as_array().unwrap().iter().map(row).collect();
    let report = verify_chain(&key_ring(&m), &rows, 1, None);
    assert!(report.valid, "{:?}", report.defects);
    assert!(report.defects.is_empty());
    assert_eq!(report.checked, rows.len());
    let last = m["chain"].as_array().unwrap().last().unwrap();
    let last_seq = last["seq"].as_u64().unwrap();
    let last_hash = last["receipt_hash_hex"].as_str().unwrap();
    assert_eq!(report.intact_prefix_seq, last_seq);
    assert_eq!(report.last_good_seq, last_seq);
    assert_eq!(hex::encode(&report.intact_prefix_hash), last_hash);
    assert_eq!(hex::encode(&report.last_good_hash), last_hash);
}

#[test]
fn conf_vectors_negative_receipts() {
    let m = manifest();
    let ring = key_ring(&m);
    let vocabulary: BTreeSet<&str> = m["defect_vocabulary"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    for neg in m["negatives"].as_array().unwrap() {
        let Some(receipt) = neg.get("receipt") else {
            continue;
        };
        let name = neg["name"].as_str().unwrap();
        let r = row(receipt);
        let anchor = neg.get("verify_against_prev_hash_hex").map(hex_n::<32>);
        let report = verify_chain(&ring, std::slice::from_ref(&r), r.seq, anchor);
        assert!(!report.valid, "{name}");
        let found: BTreeSet<&str> = report.defects.iter().map(|d| d.kind.as_str()).collect();
        assert!(
            found.contains(neg["expect_defect"].as_str().unwrap()),
            "{name}: expected {}, found {found:?}",
            neg["expect_defect"]
        );
        // Every reported defect must be vocabulary — an off-vocabulary name is drift.
        assert!(found.is_subset(&vocabulary), "{name}: {found:?}");
    }
}

#[test]
fn conf_vectors_negative_merkle() {
    let m = manifest();
    for neg in m["negatives"].as_array().unwrap() {
        let Some(mk) = neg.get("merkle") else {
            continue;
        };
        let name = neg["name"].as_str().unwrap();
        let leaves = leaves_of(&mk["leaves_hex"]);
        match neg["expect_defect"].as_str().unwrap() {
            "merkle_mismatch" => {
                assert!(
                    !verify_merkle_root(&leaves, &hex_n(&mk["claimed_root_hex"])),
                    "{name}"
                );
            }
            "inclusion_path_invalid" => {
                let idx = mk["leaf_index"].as_u64().unwrap() as usize;
                let path: Vec<[u8; 32]> = mk["path_hex"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(hex_n::<32>)
                    .collect();
                assert!(
                    !verify_inclusion(
                        &leaves[idx],
                        idx,
                        &path,
                        &hex_n(&mk["root_hex"]),
                        leaves.len()
                    ),
                    "{name}"
                );
            }
            other => panic!("{name}: unexpected merkle defect {other}"),
        }
    }
}

#[test]
fn conf_vectors_defect_vocabulary_is_complete() {
    let m = manifest();
    let vocabulary: BTreeSet<&str> = m["defect_vocabulary"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    let expected: BTreeSet<&str> = [
        "broken_link",
        "payload_mismatch",
        "unknown_key",
        "bad_signature",
        "non_canonical_payload",
        "bad_countersignature",
        "merkle_mismatch",
        "inclusion_path_invalid",
    ]
    .into();
    assert_eq!(vocabulary, expected);
}
