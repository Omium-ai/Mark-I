//! Row C7's exit criterion, executed (13 §1): build a 3-receipt dual-signed
//! checkpoint chain from the published test seeds with NO server running,
//! write it to local files, and the shipped binary — not just the library —
//! must pass it offline; then flip ONE byte and the verdict must be the
//! NAMED defect with exit 5 (08 §7.7's exit contract).

// clippy.toml's allow-*-in-tests exempts #[test] fns; the fixture-builder
// helpers here are plain fns, so the same exemption is restated at file scope.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use mark1_verifier::receipt::{
    dual_sign, hex, inclusion_path, merkle_root, CheckpointPayload, Ed25519Signer, ReceiptRow,
    Signer, GENESIS_HASH,
};
use serde_json::{json, Value};

// The vectors' TEST-ONLY seeds (conformance/vectors/receipt/README.md):
// anything signed by these keys is by definition worthless outside tests.
const DEVICE_SEED: [u8; 32] = [0x11; 32];
const SERVER_SEED: [u8; 32] = [0x22; 32];

fn run_verifier(dir: &Path, chain: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mark1-verifier"))
        .args([
            "verify",
            "--chain",
            chain,
            "--keys",
            "keys.json",
            "--witness",
            "witness.json",
            "--json",
        ])
        .current_dir(dir)
        .output()
        .unwrap()
}

/// One export line per row (08 §7.7 JSONL); row 1 carries its sealed batch
/// as checkpoint evidence.
fn export_line(row: &ReceiptRow, evidence: Option<(&[[u8; 16]], usize)>) -> String {
    let mut line = json!({
        "seq": row.seq,
        "payload": row.payload,
        "receipt_hash_hex": hex::encode(&row.receipt_hash),
        "device_key_id": row.device_key_id,
        "device_signature_hex": row.device_signature.as_ref().map(|s| hex::encode(s)),
        "server_key_id": row.server_key_id,
        "server_signature_hex": hex::encode(&row.server_signature),
    });
    if let Some((leaves, index)) = evidence {
        line["leaves_hex"] = leaves.iter().map(|l| hex::encode(l)).collect();
        line["inclusions"] = json!([{
            "leaf_hex": hex::encode(&leaves[index]),
            "leaf_index": index,
            "path_hex": inclusion_path(leaves, index)
                .unwrap()
                .iter()
                .map(|h| hex::encode(h))
                .collect::<Vec<_>>(),
        }]);
    }
    line.to_string()
}

fn checkpoint_row(
    seq: u64,
    prev: [u8; 32],
    leaves: &[[u8; 16]],
    device: &Ed25519Signer,
    server: &Ed25519Signer,
) -> ReceiptRow {
    let device_key_id = device.key_id();
    let payload = CheckpointPayload {
        tenant_id: "tenant-e2e",
        seq,
        prev_receipt_hash: prev,
        device_id: "device-e2e",
        device_key_id: &device_key_id,
        issued_at: "2026-08-29T00:00:00Z",
        checkpoint_seq: seq,
        merkle_root: merkle_root(leaves).unwrap(),
        leaf_count: leaves.len() as u64,
    };
    dual_sign(&payload.to_value(), device, server).unwrap()
}

#[test]
fn e2e_offline_chain_verifies_then_one_flipped_byte_names_the_defect() {
    let device = Ed25519Signer::from_seed(DEVICE_SEED);
    let server = Ed25519Signer::from_seed(SERVER_SEED);

    // Three checkpoints sealing batches of 5, 1 and 2 event_ids — the same
    // batch shapes the frozen Merkle vectors exercise (odd, single, even).
    let batches: [Vec<[u8; 16]>; 3] = [
        (1u8..=5).map(|i| [i; 16]).collect(),
        vec![[6; 16]],
        vec![[7; 16], [8; 16]],
    ];
    let mut rows: Vec<ReceiptRow> = Vec::new();
    let mut prev = GENESIS_HASH;
    for (i, leaves) in batches.iter().enumerate() {
        let row = checkpoint_row(i as u64 + 1, prev, leaves, &device, &server);
        prev = row.receipt_hash;
        rows.push(row);
    }

    let dir = std::env::temp_dir().join(format!("mark1_verifier_e2e_{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("keys.json"),
        json!({
            "server_chain_keys": [{ "pubkey_hex": hex::encode(&server.public_key()) }],
            "device_keys": [{ "pubkey_hex": hex::encode(&device.public_key()) }],
        })
        .to_string(),
    )
    .unwrap();
    // The witness holds the head Omium cannot edit (m1_003): the last row.
    fs::write(
        dir.join("witness.json"),
        json!({ "heads": [{
            "witnessed_seq": 3,
            "witnessed_hash_hex": hex::encode(&rows[2].receipt_hash),
        }]})
        .to_string(),
    )
    .unwrap();
    let lines: Vec<String> = rows
        .iter()
        .enumerate()
        .map(|(i, row)| export_line(row, (i == 0).then_some((batches[0].as_slice(), 2))))
        .collect();
    fs::write(dir.join("chain.jsonl"), lines.join("\n")).unwrap();

    // Untampered: exit 0, ok:true, everything counted.
    let out = run_verifier(&dir, "chain.jsonl");
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(out.status.success(), "{report}");
    assert_eq!(report["ok"], json!(true));
    assert_eq!(report["checked"]["receipts"], json!(3));
    assert_eq!(report["checked"]["checkpoints"], json!(1));
    assert_eq!(report["checked"]["inclusion_proofs"], json!(1));
    assert_eq!(report["checked"]["witness_heads"], json!(1));
    assert_eq!(report["intact_prefix_seq"], json!(3));

    // One flipped byte in row 2's signed payload ("tenant" → "tenznt": the
    // text stays canonical JSON, so exactly ONE defect can fire): the stored
    // hash no longer covers the bytes — payload_mismatch, exit 5.
    let mut tampered = lines.clone();
    tampered[1] = tampered[1].replacen("tenant-e2e", "tenznt-e2e", 1);
    assert_ne!(tampered[1], lines[1], "the tamper must actually land");
    fs::write(dir.join("tampered.jsonl"), tampered.join("\n")).unwrap();

    let out = run_verifier(&dir, "tampered.jsonl");
    assert_eq!(out.status.code(), Some(5));
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["ok"], json!(false));
    let defects = report["defects"].as_array().unwrap();
    assert_eq!(defects.len(), 1, "{report}");
    assert_eq!(defects[0]["kind"], json!("payload_mismatch"));
    assert_eq!(defects[0]["seq"], json!(2));
    // The intact prefix stops BEFORE the tampered row (estate chain.py's
    // customer number); the last good row is still seq 3.
    assert_eq!(report["intact_prefix_seq"], json!(1));
    assert_eq!(report["last_good_seq"], json!(3));

    // A missing input file is I/O (exit 1), never a chain verdict.
    let out = run_verifier(&dir, "no-such-file.jsonl");
    assert_eq!(out.status.code(), Some(1));

    // A zero-row export (empty or all-whitespace) is malformed input (exit
    // 1), never "chain VALID": a truncated-to-nothing history must not share
    // a verdict with a verified one.
    for (name, contents) in [("empty.jsonl", ""), ("blank.jsonl", "\n\n   \n")] {
        fs::write(dir.join(name), contents).unwrap();
        let out = run_verifier(&dir, name);
        assert_eq!(out.status.code(), Some(1), "{name}: {out:?}");
    }

    // The server key alone must not be able to mint a "device-attested" row:
    // payload names the SERVER key as its device origin, both signatures by
    // the server seed, every byte self-consistent — only role binding rejects
    // it (m1_002 header: server-only would let Omium mint history).
    let forged = checkpoint_row(1, GENESIS_HASH, &batches[1], &server, &server);
    fs::write(dir.join("forged.jsonl"), export_line(&forged, None)).unwrap();
    let out = run_verifier(&dir, "forged.jsonl");
    assert_eq!(out.status.code(), Some(5));
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["defects"][0]["kind"], json!("unknown_key"));

    fs::remove_dir_all(&dir).ok();
}
