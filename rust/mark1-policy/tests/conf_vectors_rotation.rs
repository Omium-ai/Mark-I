//! The rotation family of conformance/vectors/bundle (ADR-0004): a section
//! key rotates in through a cross-signature by the pinned predecessor, and a
//! bundle signed by the successor goes from unknown_key to accepted on
//! exactly that admission — while a self-signed, mis-signed or R5-violating
//! manifest admits nothing. `conf_vectors_` prefix is load-bearing (12 §3.4).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::PathBuf;

use mark1_policy::{
    apply_rotation, cross_sign_input, verify_and_decode, RotationEntry, Section, SectionKeys,
    TlogHead, CROSS_SIGN_DOMAIN,
};
use mark1_receipt::{hex, CrossSig, Ed25519Signer, KeyEntry, KeyRole, Signer};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/vectors/bundle")
}

fn manifest() -> Value {
    let m: Value =
        serde_json::from_str(&fs::read_to_string(dir().join("manifest.json")).unwrap()).unwrap();
    assert!(
        !m["rotation"]["vectors"].as_array().unwrap().is_empty(),
        "rotation family empty"
    );
    m
}

/// The pinned ring exactly as conf_vectors_bundle builds it.
fn pinned(m: &Value) -> SectionKeys {
    let mut keys = SectionKeys::new();
    for s in Section::ALL {
        let public: [u8; 32] =
            hex::decode_array(m["keys"][s.name()]["public_hex"].as_str().unwrap()).unwrap();
        keys.insert_public(s, public);
    }
    let ek = &m["expired_key"];
    let mut entry = KeyEntry::new(
        hex::decode_array(ek["public_hex"].as_str().unwrap()).unwrap(),
        KeyRole::ServerChain,
    );
    entry.not_after = Some(ek["not_after"].as_str().unwrap().to_string());
    keys.insert(Section::Verify, entry);
    keys
}

fn read_checked(entry: &Value) -> Vec<u8> {
    let raw = fs::read(dir().join(entry["file"].as_str().unwrap())).unwrap();
    assert_eq!(
        hex::encode(&Sha256::digest(&raw)),
        entry["file_sha256_hex"].as_str().unwrap(),
        "{}: bytes drifted from the frozen manifest",
        entry["file"]
    );
    raw
}

/// The manifest as the edge parses it (08 §3.5's two lists).
fn parse(raw: &[u8]) -> (Vec<RotationEntry>, Vec<[u8; 32]>) {
    let v: Value = serde_json::from_slice(raw).unwrap();
    let entries = v["bundle_section_keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| RotationEntry {
            section: *Section::ALL
                .iter()
                .find(|s| s.name() == k["section"].as_str().unwrap())
                .unwrap(),
            public_key: hex::decode_array(k["pubkey_hex"].as_str().unwrap()).unwrap(),
            not_before: None,
            not_after: None,
            cross_sig: k.get("cross_sig").map(|cs| CrossSig {
                by_key_id: cs["by_key_id"].as_str().unwrap().to_string(),
                signature: hex::decode_array(cs["signature_hex"].as_str().unwrap()).unwrap(),
            }),
        })
        .collect();
    let updates = v["update_keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| hex::decode_array(k["pubkey_hex"].as_str().unwrap()).unwrap())
        .collect();
    (entries, updates)
}

#[test]
fn conf_vectors_bundle_rotation_cross_sign_input() {
    let m = manifest();
    let rot = &m["rotation"];
    assert_eq!(
        hex::encode(CROSS_SIGN_DOMAIN),
        rot["cross_sign_domain_hex"].as_str().unwrap()
    );
    // The frozen accept manifest's cross-signature re-derives from the frozen
    // seeds through THIS crate's input construction.
    let old = Ed25519Signer::from_seed(
        hex::decode_array(m["keys"]["verify"]["seed_hex"].as_str().unwrap()).unwrap(),
    );
    let successor = Ed25519Signer::from_seed(
        hex::decode_array(rot["successor"]["seed_hex"].as_str().unwrap()).unwrap(),
    );
    assert_eq!(
        successor.key_id(),
        rot["successor"]["key_id"].as_str().unwrap()
    );
    let accept = rot["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == "rotation_accepted")
        .unwrap();
    let (entries, _) = parse(&read_checked(accept));
    let cs = entries
        .iter()
        .find_map(|e| (e.public_key == successor.public_key()).then(|| e.cross_sig.clone()))
        .flatten()
        .unwrap();
    assert_eq!(cs.by_key_id, old.key_id());
    assert_eq!(
        cs.signature,
        old.sign(&cross_sign_input("bundle:verify", &successor.public_key()))
    );
}

#[test]
fn conf_vectors_bundle_rotation_every_manifest() {
    let m = manifest();
    let rot = &m["rotation"];
    let bundle = &rot["bundle"];
    let raw = read_checked(bundle);
    let head = TlogHead {
        tree_size: bundle["tlog_head"]["tree_size"].as_u64().unwrap(),
        root: hex::decode_array(bundle["tlog_head"]["root_hex"].as_str().unwrap()).unwrap(),
    };
    let last = bundle["last_applied_seq"].as_u64();
    let unknown = |keys: &SectionKeys| {
        let e = verify_and_decode(&raw, keys, last, Some(&head)).unwrap_err();
        assert_eq!((e.code(), e.kind()), ("M1E-3001", "unknown_key"));
    };
    unknown(&pinned(&m));

    for entry in rot["vectors"].as_array().unwrap() {
        let name = entry["name"].as_str().unwrap();
        let (entries, updates) = parse(&read_checked(entry));
        let mut keys = pinned(&m);
        let outcome = apply_rotation(&mut keys, &entries, &updates);
        match entry["expect"].as_str().unwrap() {
            "accept" => {
                let admitted = outcome.unwrap_or_else(|e| panic!("{name}: refused: {e}"));
                assert_eq!(admitted, vec![rot["successor"]["key_id"].as_str().unwrap()]);
                let b = verify_and_decode(&raw, &keys, last, Some(&head))
                    .unwrap_or_else(|e| panic!("{name}: rotated bundle rejected: {e}"));
                assert_eq!(
                    hex::encode(&b.body_sha256),
                    bundle["body_sha256_hex"].as_str().unwrap()
                );
            }
            "reject" => {
                let e = outcome.expect_err(name);
                assert_eq!(e.kind(), entry["kind"].as_str().unwrap(), "{name}: {e}");
                unknown(&keys); // a refusal admitted nothing
            }
            other => panic!("{name}: unknown expect {other}"),
        }
    }
}
