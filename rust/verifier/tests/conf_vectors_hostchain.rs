//! The offline verifier accepts ADR-0017's v2 checkpoint rows exactly as it
//! accepts v1: conformance/vectors/hostchain's v1→v2→v2 chain verifies end
//! to end through `verify()` — chain walk, both signatures, the Merkle root
//! over the exported leaves — and its negatives fail for the named reason.
//! The host block is carried, not judged: that is the auditor's job.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use mark1_verifier::receipt::{canonical_json, hex, KeyEntry, KeyRing, KeyRole};
use mark1_verifier::{verify, ExportRow, Options};
use serde_json::Value;

fn manifest() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/vectors/hostchain/manifest.json");
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

fn key_ring(m: &Value) -> KeyRing {
    let mut ring = KeyRing::new();
    for (role, key_role) in [
        ("device", KeyRole::DeviceOrigin),
        ("server", KeyRole::ServerChain),
    ] {
        ring.insert(KeyEntry::new(
            hex::decode_array(m["keys"][role]["public_hex"].as_str().unwrap()).unwrap(),
            key_role,
        ));
    }
    ring
}

fn export_row(entry: &Value, leaves_hex: Option<Vec<String>>) -> ExportRow {
    let text = entry["canonical_json"].as_str().unwrap();
    let consistent = serde_json::from_str::<Value>(text)
        .map(|v| v == entry["payload"])
        .unwrap_or(false);
    let payload = if consistent {
        text.to_string()
    } else {
        canonical_json(&entry["payload"]).unwrap()
    };
    ExportRow {
        seq: entry["seq"].as_u64().unwrap(),
        payload,
        receipt_hash_hex: entry["receipt_hash_hex"].as_str().unwrap().to_string(),
        device_key_id: entry["device_key_id"].as_str().map(String::from),
        device_signature_hex: entry["device_signature_hex"].as_str().map(String::from),
        server_key_id: entry["server_key_id"].as_str().unwrap().to_string(),
        server_signature_hex: entry["server_signature_hex"].as_str().unwrap().to_string(),
        leaves_hex,
        inclusions: None,
    }
}

fn leaves(m: &Value, seq: u64) -> Vec<String> {
    m["leaves_hex"][(seq - 1) as usize]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect()
}

#[test]
fn conf_vectors_hostchain_verifier_accepts_v1_and_v2_rows() {
    let m = manifest();
    let export: Vec<ExportRow> = m["chain"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| export_row(e, Some(leaves(&m, e["seq"].as_u64().unwrap()))))
        .collect();
    assert!(export
        .iter()
        .any(|r| serde_json::from_str::<Value>(&r.payload).unwrap()["v"] == 2));
    let report = verify(
        &export,
        &key_ring(&m),
        None,
        &Options {
            start_seq: 1,
            anchor_prev: None,
        },
    )
    .unwrap();
    assert!(report.ok, "{:?}", report.defects);
    assert_eq!(report.checked.checkpoints, export.len());
}

#[test]
fn conf_vectors_hostchain_verifier_names_the_defect() {
    let m = manifest();
    let ring = key_ring(&m);
    for neg in m["negatives"].as_array().unwrap() {
        let name = neg["name"].as_str().unwrap();
        let r = export_row(&neg["receipt"], None);
        let report = verify(
            std::slice::from_ref(&r),
            &ring,
            None,
            &Options {
                start_seq: r.seq,
                anchor_prev: None,
            },
        )
        .unwrap();
        assert!(!report.ok, "{name}");
        let found: BTreeSet<&str> = report.defects.iter().map(|d| d.kind.as_str()).collect();
        assert!(
            found.contains(neg["expect_defect"].as_str().unwrap()),
            "{name}: expected {}, found {found:?}",
            neg["expect_defect"]
        );
    }
}
