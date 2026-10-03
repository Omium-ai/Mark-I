//! conformance/vectors/hostchain — ADR-0017 host-bound receipts, the Rust leg.
//! `CheckpointPayload::to_value_bound` must reproduce every frozen v2 row
//! byte for byte (and `to_value` the v1 row); the profile and identity hashes
//! are the vectors'; the chain verifies from genesis; each negative fails for
//! the named reason.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use mark1_receipt::{
    canonical_json, dual_sign, hex, identity_hash, profile_hash, verify_chain, CheckpointPayload,
    Ed25519Signer, HostBinding, KeyEntry, KeyRing, KeyRole, ReceiptRow, Signer, TaskBinding,
    HOST_IDENTITY_DOMAIN,
};
use serde_json::Value;

fn manifest() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/vectors/hostchain/manifest.json");
    let m: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    for family in ["chain", "negatives"] {
        assert!(
            !m[family].as_array().unwrap().is_empty(),
            "manifest family {family} is empty"
        );
    }
    m
}

fn hex_n<const N: usize>(v: &Value) -> [u8; N] {
    hex::decode_array(v.as_str().unwrap()).unwrap()
}

fn key_ring(m: &Value) -> KeyRing {
    let mut ring = KeyRing::new();
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
        device_key_id: entry["device_key_id"].as_str().map(String::from),
        device_signature: entry["device_signature_hex"]
            .as_str()
            .map(|s| hex::decode_array(s).unwrap()),
        server_key_id: entry["server_key_id"].as_str().unwrap().to_string(),
        server_signature: hex_n(&entry["server_signature_hex"]),
    }
}

fn hosts_of(p: &Value) -> Vec<HostBinding> {
    p["hosts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| HostBinding {
            session_id: hex_n(&h["session_id"]),
            transport: h["transport"].as_str().unwrap().to_string(),
            host_id: h["host_id"].as_str().unwrap().to_string(),
            host_version: h["host_version"].as_str().unwrap().to_string(),
            profile_hash: hex_n(&h["profile_hash"]),
            host_correlation_id: h["host_correlation_id"].as_str().unwrap().to_string(),
            tasks: h["tasks"]
                .as_array()
                .unwrap()
                .iter()
                .map(|t| TaskBinding {
                    task_id: hex_n(&t["task_id"]),
                    identity_hash: t.get("identity_hash").map(hex_n::<32>),
                })
                .collect(),
        })
        .collect()
}

#[test]
fn conf_vectors_hostchain_profile_and_identity_hashes() {
    let m = manifest();
    assert_eq!(
        hex::encode(HOST_IDENTITY_DOMAIN),
        m["identity_domain_hex"].as_str().unwrap()
    );
    for (name, p) in m["profiles"].as_object().unwrap() {
        assert_eq!(
            hex::encode(&profile_hash(p["canonical"].as_str().unwrap().as_bytes())),
            p["hash_hex"].as_str().unwrap(),
            "{name}"
        );
    }
    for entry in m["chain"].as_array().unwrap() {
        let p = &entry["payload"];
        if p["v"].as_u64() != Some(2) {
            continue;
        }
        for h in p["hosts"].as_array().unwrap() {
            for t in h["tasks"].as_array().unwrap() {
                if let Some(ih) = t.get("identity_hash") {
                    let got = identity_hash(
                        h["host_id"].as_str().unwrap(),
                        h["host_correlation_id"].as_str().unwrap(),
                        &hex_n::<16>(&t["task_id"]),
                    );
                    assert_eq!(hex::encode(&got), ih.as_str().unwrap());
                }
            }
        }
    }
}

#[test]
fn conf_vectors_hostchain_assembly_reproduces_frozen_bytes() {
    let m = manifest();
    let device = Ed25519Signer::from_seed(hex_n(&m["keys"]["device"]["seed_hex"]));
    let server = Ed25519Signer::from_seed(hex_n(&m["keys"]["server"]["seed_hex"]));
    let device_key_id = device.key_id();
    let mut saw_v2 = false;
    for entry in m["chain"].as_array().unwrap() {
        let p = &entry["payload"];
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
        let value = if p["v"].as_u64() == Some(2) {
            saw_v2 = true;
            payload.to_value_bound(
                &hosts_of(p),
                p["arrests_acted"].as_u64().unwrap(),
                p["arrests_recommended"].as_u64().unwrap(),
            )
        } else {
            payload.to_value()
        };
        let r = dual_sign(&value, &device, &server).unwrap();
        assert_eq!(
            r.payload,
            entry["canonical_json"].as_str().unwrap(),
            "seq {}",
            r.seq
        );
        assert_eq!(
            hex::encode(&r.receipt_hash),
            entry["receipt_hash_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(&r.device_signature.unwrap()),
            entry["device_signature_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(&r.server_signature),
            entry["server_signature_hex"].as_str().unwrap()
        );
    }
    assert!(saw_v2, "manifest has no v2 row");
}

#[test]
fn conf_vectors_hostchain_verifies_from_genesis() {
    let m = manifest();
    let rows: Vec<ReceiptRow> = m["chain"].as_array().unwrap().iter().map(row).collect();
    let report = verify_chain(&key_ring(&m), &rows, 1, None);
    assert!(report.valid, "{:?}", report.defects);
    assert_eq!(report.checked, rows.len());
}

#[test]
fn conf_vectors_hostchain_negative_receipts() {
    let m = manifest();
    let ring = key_ring(&m);
    for neg in m["negatives"].as_array().unwrap() {
        let name = neg["name"].as_str().unwrap();
        let r = row(&neg["receipt"]);
        let report = verify_chain(&ring, std::slice::from_ref(&r), r.seq, None);
        assert!(!report.valid, "{name}");
        let found: BTreeSet<&str> = report.defects.iter().map(|d| d.kind.as_str()).collect();
        assert!(
            found.contains(neg["expect_defect"].as_str().unwrap()),
            "{name}: expected {}, found {found:?}",
            neg["expect_defect"]
        );
    }
}
