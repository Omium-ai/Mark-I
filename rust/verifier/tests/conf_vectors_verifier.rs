//! Verifier leg of the receipt vector lock (13 §1 row C7): the frozen chain
//! must come out VALID through the verifier's own surface — export-row
//! mapping, checkpoint evidence, witness cross-check — and a tampered byte
//! must come out as the NAMED defect. `conf_vectors_` prefixes are
//! load-bearing (`conformance_crosslang.sh` filter, 12 §3.4).

// clippy.toml's allow-*-in-tests exempts #[test] fns; the vector-driver
// helpers here are plain fns, so the same exemption is restated at file scope.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use mark1_verifier::receipt::{
    dual_sign, hex, CheckpointPayload, Ed25519Signer, Signer, GENESIS_HASH,
};
use mark1_verifier::{
    cross_sign_input, load_keys, verify, ExportRow, InclusionClaim, Options, WitnessFile,
    WitnessHead, CROSS_SIGN_DOMAIN, WITNESS_MISMATCH,
};
use serde_json::{json, Value};

/// Unique per call, not per process: the harness runs tests in parallel and a
/// shared name lets one test delete another's files mid-run.
fn scratch_dir(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "mark1_verifier_{tag}_{}_{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

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

/// The manifest's two keys as the CLI's local key manifest (08 §3.5). The two
/// lists ARE the role split, so device and server stay in their own.
fn keys_file(m: &Value) -> Value {
    json!({
        "server_chain_keys": [{
            "pubkey_hex": m["keys"]["server"]["public_hex"],
            "key_id": m["keys"]["server"]["key_id"],
        }],
        "device_keys": [{
            "pubkey_hex": m["keys"]["device"]["public_hex"],
            "key_id": m["keys"]["device"]["key_id"],
        }],
    })
}

/// KeyRing via `load_keys`, so the manifest-shape parse and the derived-vs-
/// claimed key_id check run on every use (08 §3.5's local key manifest).
fn ring_from_files(m: &Value) -> mark1_verifier::receipt::KeyRing {
    let dir = scratch_dir("keys");
    let path = dir.join("keys.json");
    fs::write(&path, keys_file(m).to_string()).unwrap();
    let ring = load_keys(&path);
    fs::remove_dir_all(&dir).ok();
    ring.unwrap()
}

/// Drive the SHIPPED BINARY over an export, not the library: `verify()` is
/// what the other tests here exercise, and a defect kind proven only through
/// the library is a defect kind never proven against the artifact a customer
/// actually runs.
fn verify_via_binary(m: &Value, rows: &[Value], args: &[String]) -> (Option<i32>, Value) {
    verify_via_binary_with_keys(&keys_file(m), rows, args)
}

fn verify_via_binary_with_keys(
    keys: &Value,
    rows: &[Value],
    args: &[String],
) -> (Option<i32>, Value) {
    let dir = scratch_dir("neg");
    fs::write(dir.join("keys.json"), keys.to_string()).unwrap();
    let lines: Vec<String> = rows.iter().map(Value::to_string).collect();
    fs::write(dir.join("chain.jsonl"), lines.join("\n")).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_mark1-verifier"))
        .args([
            "verify",
            "--chain",
            "chain.jsonl",
            "--keys",
            "keys.json",
            "--json",
        ])
        .args(args)
        .current_dir(&dir)
        .output()
        .unwrap();
    let code = out.status.code();
    // Exit 1 means the binary called the input malformed and printed no
    // report. That is a real finding for a negative that should have earned a
    // VERDICT, so it fails loudly here rather than as a confusing parse error.
    let report: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|_| {
        panic!(
            "verifier exited {code:?} with no report on stdout: {}",
            String::from_utf8_lossy(&out.stderr)
        )
    });
    fs::remove_dir_all(&dir).ok();
    (code, report)
}

/// The export row a `merkle` negative describes. These two carry no receipt —
/// they are a leaves/root pair — which is exactly why the old loop stepped
/// over them; the checkpoint evidence they belong to has to be built here.
fn merkle_negative_row(m: &Value, mk: &Value) -> Value {
    let leaves_hex: Vec<&str> = mk["leaves_hex"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();

    let Some(claimed) = mk.get("claimed_root_hex") else {
        // truncated_inclusion_path: chain[0] already seals these five leaves
        // under this very root, so it is the carrier and the short path is
        // the only thing wrong.
        assert_eq!(
            m["chain"][0]["payload"]["merkle_root"], mk["root_hex"],
            "vector layout drifted: chain[0] no longer seals these leaves"
        );
        let mut row = export_row(&m["chain"][0]);
        let idx = mk["leaf_index"].as_u64().unwrap();
        row["inclusions"] = json!([{
            "leaf_hex": leaves_hex[usize::try_from(idx).unwrap()],
            "leaf_index": idx,
            "path_hex": mk["path_hex"],
        }]);
        return row;
    };

    // wrong_merkle_root: the claimed root sits INSIDE the signed payload, and
    // every frozen chain row claims its true one — so the carrier has to be
    // dual-signed here, under the frozen seeds, or the row would fail for a
    // signature reason instead of the Merkle one under test.
    let seed = |role: &str| -> [u8; 32] {
        hex::decode_array(m["keys"][role]["seed_hex"].as_str().unwrap()).unwrap()
    };
    let device = Ed25519Signer::from_seed(seed("device"));
    let server = Ed25519Signer::from_seed(seed("server"));
    let device_key_id = device.key_id();
    let payload = CheckpointPayload {
        tenant_id: "11111111-1111-1111-1111-111111111111",
        seq: 1,
        prev_receipt_hash: GENESIS_HASH,
        device_id: "33333333-3333-3333-3333-333333333333",
        device_key_id: &device_key_id,
        issued_at: "2026-08-29T00:00:01Z",
        checkpoint_seq: 1,
        merkle_root: hex::decode_array(claimed.as_str().unwrap()).unwrap(),
        // Matches the exported leaves, so the ROOT is the sole disagreement.
        leaf_count: leaves_hex.len() as u64,
    };
    let row = dual_sign(&payload.to_value(), &device, &server).unwrap();
    json!({
        "seq": row.seq,
        "payload": row.payload,
        "receipt_hash_hex": hex::encode(&row.receipt_hash),
        "device_key_id": row.device_key_id,
        "device_signature_hex": row.device_signature.as_ref().map(|s| hex::encode(s)),
        "server_key_id": row.server_key_id,
        "server_signature_hex": hex::encode(&row.server_signature),
        "leaves_hex": leaves_hex,
    })
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

/// A rotation case's keys file: the device key as frozen, the server chain
/// list exactly as the case publishes it (cross_sig present or not).
fn rotation_keys_file(m: &Value, case: &Value) -> Value {
    json!({
        "server_chain_keys": case["server_chain_keys"],
        "device_keys": [{
            "pubkey_hex": m["keys"]["device"]["public_hex"],
            "key_id": m["keys"]["device"]["key_id"],
        }],
    })
}

fn rotation_rows(case: &Value) -> Vec<Value> {
    case["chain"]
        .as_array()
        .unwrap()
        .iter()
        .map(export_row)
        .collect()
}

#[test]
fn conf_vectors_verifier_follows_rotation() {
    let m = manifest();
    let rot = &m["rotation"];
    assert_eq!(
        hex::encode(CROSS_SIGN_DOMAIN),
        rot["cross_sign_domain_hex"].as_str().unwrap()
    );
    // The byte contract itself: the frozen cross-signature re-derives from
    // the frozen seed through THIS crate's cross_sign_input.
    let old = Ed25519Signer::from_seed(
        hex::decode_array(m["keys"]["server"]["seed_hex"].as_str().unwrap()).unwrap(),
    );
    let successor: [u8; 32] =
        hex::decode_array(rot["successor"]["public_hex"].as_str().unwrap()).unwrap();
    assert_eq!(
        hex::encode(&old.sign(&cross_sign_input("server_chain", &successor))),
        rot["successor"]["cross_sig_hex"].as_str().unwrap()
    );

    let case = &rot["accept"];
    let (code, report) =
        verify_via_binary_with_keys(&rotation_keys_file(&m, case), &rotation_rows(case), &[]);
    assert_eq!(code, Some(0), "{}: {report}", case["name"]);
    assert_eq!(report["ok"], json!(true), "{report}");
    assert_eq!(
        report["intact_prefix_seq"],
        case["chain"].as_array().unwrap().last().unwrap()["seq"]
    );
}

#[test]
fn conf_vectors_verifier_names_the_tampered_byte() {
    let m = manifest();
    let mut vocabulary: BTreeSet<&str> = m["defect_vocabulary"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    let mut exercised: BTreeSet<&str> = BTreeSet::new();

    // The rotation family's negatives ride the same loop: a manifest-level
    // kind the chain walk cannot emit, so it is proven through the binary
    // exactly like the frozen eight.
    let rot = &m["rotation"];
    vocabulary.extend(
        rot["defect_vocabulary"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap()),
    );
    for neg in rot["negatives"].as_array().unwrap() {
        let name = neg["name"].as_str().unwrap();
        let expect = neg["expect_defect"].as_str().unwrap();
        let (code, report) =
            verify_via_binary_with_keys(&rotation_keys_file(&m, neg), &rotation_rows(neg), &[]);
        assert_eq!(code, Some(5), "{name}: {report}");
        let kinds: Vec<&str> = report["defects"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["kind"].as_str().unwrap())
            .collect();
        assert_eq!(kinds, vec![expect], "{name}: {report}");
        exercised.insert(expect);
    }

    for neg in m["negatives"].as_array().unwrap() {
        let name = neg["name"].as_str().unwrap();
        let expect = neg["expect_defect"].as_str().unwrap();

        let mut args: Vec<String> = Vec::new();
        let row = if let Some(receipt) = neg.get("receipt") {
            // Mid-chain negatives are judged against their own position, so
            // the anchor rides as the CLI flags an operator would pass.
            args.push("--start-seq".into());
            args.push(receipt["seq"].to_string());
            if let Some(prev) = neg.get("verify_against_prev_hash_hex") {
                args.push("--prev-hash".into());
                args.push(prev.as_str().unwrap().into());
            }
            export_row(receipt)
        } else if let Some(mk) = neg.get("merkle") {
            merkle_negative_row(&m, mk)
        } else {
            // A shape this loop cannot drive is a defect kind going
            // unexercised. It used to be a `continue`, which is a skip with
            // no output — the failure mode this whole test exists to deny.
            panic!("{name}: negative has neither a receipt nor a merkle body");
        };

        let (code, report) = verify_via_binary(&m, std::slice::from_ref(&row), &args);
        // 5 is the defect verdict; 1 would mean the binary rejected the file
        // rather than judging the chain (08 §7.7's exit contract).
        assert_eq!(code, Some(5), "{name}: {report}");
        assert_eq!(report["ok"], json!(false), "{name}: {report}");
        let kinds: Vec<&str> = report["defects"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["kind"].as_str().unwrap())
            .collect();
        // A negative that fails for the WRONG reason is a failure (vectors
        // README), and nothing outside the frozen vocabulary may be emitted
        // (no witness file rides here, so witness_mismatch cannot appear).
        assert!(
            kinds.contains(&expect),
            "{name}: expected {expect}, got {kinds:?}"
        );
        for kind in &kinds {
            assert!(
                vocabulary.contains(kind),
                "{name}: emitted {kind}, which is not in the frozen vocabulary"
            );
        }
        exercised.insert(expect);
    }

    // The loop asserts its own coverage: every kind the manifest names must
    // have reached the binary. Without this a negative silently dropped from
    // the manifest — or a shape the loop stops handling — leaves a defect
    // kind unproven while the suite stays green.
    assert_eq!(
        exercised, vocabulary,
        "defect kinds in the manifest that never reached the binary"
    );
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
