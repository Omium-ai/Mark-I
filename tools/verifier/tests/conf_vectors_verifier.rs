//! Verifier leg of the receipt vector lock (13 §1 row C7): the frozen chain
//! must come out VALID through the verifier's own surface — export-row
//! mapping, checkpoint evidence, witness cross-check — and a tampered byte
//! must come out as the NAMED defect. `conf_vectors_` prefixes are
//! load-bearing (`conformance_crosslang.sh` filter, 12 §3.4).

// clippy.toml's allow-*-in-tests exempts #[test] fns; the vector-driver
// helpers here are plain fns, so the same exemption is restated at file scope.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::PathBuf;

use mark1_verifier::receipt::hex;
use mark1_verifier::{
    load_keys, verify, ExportRow, InclusionClaim, Options, WitnessFile, WitnessHead,
    WITNESS_MISMATCH,
};
use serde_json::{json, Value};

fn manifest() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/vectors/receipt/manifest.json");
    let m: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    // An emptied family passes every loop below vacuously — guard here so a
    // hand-edited manifest fails loudly (the Go leg's loadManifest rule).
    for family in ["canonical", "chain", "negatives"] {
        assert!(
            !m[family].as_array().unwrap().is_empty(),
            "manifest family {family} is empty"
        );
    }
    m
}

/// Manifest receipt object → one export line (08 §7.7 JSONL shape): the
/// stored payload column is the canonical text, everything else rides hex.
/// Same text-vs-object rule as the other legs' row builders, so a mutated
/// payload object re-serialises and a text-level tamper stays as-is.
fn export_row(entry: &Value) -> Value {
    let text = entry["canonical_json"].as_str().unwrap();
    let consistent = serde_json::from_str::<Value>(text)
        .map(|v| v == entry["payload"])
        .unwrap_or(false);
    let payload = if consistent {
        text.to_string()
    } else {
        mark1_verifier::receipt::canonical_json(&entry["payload"]).unwrap()
    };
    // device fields ride through as-is: null on server-only rows and the
    // stripped-signature negative deserialises to None.
    json!({
        "seq": entry["seq"],
        "payload": payload,
        "receipt_hash_hex": entry["receipt_hash_hex"],
        "device_key_id": entry["device_key_id"],
        "device_signature_hex": entry["device_signature_hex"],
        "server_key_id": entry["server_key_id"],
        "server_signature_hex": entry["server_signature_hex"],
    })
}

fn export_rows(m: &Value) -> Vec<ExportRow> {
    m["chain"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| serde_json::from_value(export_row(e)).unwrap())
        .collect()
}

/// KeyRing via `load_keys`, so the manifest-shape parse and the derived-vs-
/// claimed key_id check run on every use (08 §3.5's local key manifest).
fn ring_from_files(m: &Value) -> mark1_verifier::receipt::KeyRing {
    let keys_json = json!({
        "server_chain_keys": [{
            "pubkey_hex": m["keys"]["server"]["public_hex"],
            "key_id": m["keys"]["server"]["key_id"],
        }],
        "device_keys": [{
            "pubkey_hex": m["keys"]["device"]["public_hex"],
            "key_id": m["keys"]["device"]["key_id"],
        }],
    });
    // Unique per call, not per process: the harness runs tests in parallel
    // and a shared name lets one test delete the file under another.
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "mark1_verifier_keys_{}_{}.json",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    fs::write(&path, keys_json.to_string()).unwrap();
    let ring = load_keys(&path);
    fs::remove_file(&path).ok();
    ring.unwrap()
}

#[test]
fn conf_vectors_verifier_accepts_frozen_chain() {
    let m = manifest();
    let mut export = export_rows(&m);

    // chain[0] seals the five_leaves batch (its merkle_root IS that case's
    // root), so attach the leaves and both frozen inclusion paths as the
    // export's checkpoint evidence.
    let five = &m["merkle"]["cases"][0];
    assert_eq!(five["name"], "five_leaves");
    assert_eq!(
        m["chain"][0]["payload"]["merkle_root"], five["root_hex"],
        "vector layout drifted: chain[0] no longer seals five_leaves"
    );
    export[0].leaves_hex = Some(
        five["leaves_hex"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect(),
    );
    let mut with_claims: Vec<InclusionClaim> = Vec::new();
    for (idx, path) in five["inclusion_paths"].as_object().unwrap() {
        with_claims.push(
            serde_json::from_value(json!({
                "leaf_hex": five["leaves_hex"][idx.parse::<usize>().unwrap()],
                "leaf_index": idx.parse::<u64>().unwrap(),
                "path_hex": path,
            }))
            .unwrap(),
        );
    }
    let claims = with_claims.len();
    export[0].inclusions = Some(with_claims);

    // The witness holds the head Omium cannot edit (m1_003): the last row.
    let last = m["chain"].as_array().unwrap().last().unwrap();
    let witness = WitnessFile {
        heads: vec![WitnessHead {
            witnessed_seq: last["seq"].as_u64().unwrap(),
            witnessed_hash_hex: last["receipt_hash_hex"].as_str().unwrap().to_string(),
        }],
    };

    let report = verify(
        &export,
        &ring_from_files(&m),
        Some(&witness),
        &Options::default(),
    )
    .unwrap();
    assert!(report.ok, "{:?}", report.defects);
    assert_eq!(report.checked.receipts, export.len());
    assert_eq!(report.checked.checkpoints, 1);
    assert_eq!(report.checked.inclusion_proofs, claims);
    assert_eq!(report.checked.witness_heads, 1);
    assert_eq!(report.intact_prefix_seq, last["seq"].as_u64().unwrap());
    assert_eq!(
        report.intact_prefix_hash,
        last["receipt_hash_hex"].as_str().unwrap()
    );
}

#[test]
fn conf_vectors_verifier_names_the_tampered_byte() {
    let m = manifest();
    for neg in m["negatives"].as_array().unwrap() {
        let Some(receipt) = neg.get("receipt") else {
            continue;
        };
        let row: ExportRow = serde_json::from_value(export_row(receipt)).unwrap();
        let opts = Options {
            start_seq: row.seq,
            anchor_prev: neg
                .get("verify_against_prev_hash_hex")
                .and_then(|v| mark1_verifier::parse_anchor(v.as_str().unwrap())),
        };
        let report = verify(
            std::slice::from_ref(&row),
            &ring_from_files(&m),
            None,
            &opts,
        )
        .unwrap();
        let name = neg["name"].as_str().unwrap();
        assert!(!report.ok, "{name}");
        assert!(
            report
                .defects
                .iter()
                .any(|d| d.kind == neg["expect_defect"].as_str().unwrap()),
            "{name}: expected {}, got {:?}",
            neg["expect_defect"],
            report.defects
        );
    }
}

#[test]
fn conf_vectors_verifier_flags_rewritten_witness_head() {
    let m = manifest();
    let export = export_rows(&m);
    // A head whose hash the chain does not carry: rewritten after witnessing.
    let witness = WitnessFile {
        heads: vec![WitnessHead {
            witnessed_seq: 1,
            witnessed_hash_hex: hex::encode(&[0xabu8; 32]),
        }],
    };
    let report = verify(
        &export,
        &ring_from_files(&m),
        Some(&witness),
        &Options::default(),
    )
    .unwrap();
    assert!(!report.ok);
    assert!(report.defects.iter().any(|d| d.kind == WITNESS_MISMATCH));
}

#[test]
fn conf_vectors_verifier_refuses_lying_key_manifest() {
    // key_id is DERIVED, never configured (m1_002): a manifest that labels a
    // key with another key's id is malformed INPUT, not a chain defect.
    let m = manifest();
    let keys_json = json!({
        "server_chain_keys": [{
            "pubkey_hex": m["keys"]["server"]["public_hex"],
            "key_id": m["keys"]["device"]["key_id"],
        }],
        "device_keys": [],
    });
    let path = std::env::temp_dir().join(format!(
        "mark1_verifier_badkeys_{}.json",
        std::process::id()
    ));
    fs::write(&path, keys_json.to_string()).unwrap();
    let result = load_keys(&path);
    fs::remove_file(&path).ok();
    assert!(result.is_err());
}
