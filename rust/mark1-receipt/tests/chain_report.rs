//! Chain-walk behaviors the frozen vectors cannot express: the vacuous-walk
//! verdict, the mid-chain anchor's intact hash, and tenant binding of device
//! keys. TEST-ONLY seeds per the vectors' README — worthless by definition.

// clippy.toml's allow-*-in-tests exempts #[test] fns; the fixture helpers
// here are plain fns, so the same exemption is restated at file scope.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use mark1_receipt::{
    dual_sign, hex, merkle_root, verify_chain, CheckpointPayload, DefectKind, Ed25519Signer,
    KeyEntry, KeyRing, KeyRole, ReceiptRow, Signer, GENESIS_HASH,
};

const DEVICE_SEED: [u8; 32] = [0x11; 32];
const SERVER_SEED: [u8; 32] = [0x22; 32];
const TENANT: &str = "11111111-1111-1111-1111-111111111111";

fn signers() -> (Ed25519Signer, Ed25519Signer) {
    (
        Ed25519Signer::from_seed(DEVICE_SEED),
        Ed25519Signer::from_seed(SERVER_SEED),
    )
}

fn ring(device_tenant: Option<&str>) -> KeyRing {
    let (device, server) = signers();
    let mut ring = KeyRing::new();
    let mut dev = KeyEntry::new(device.public_key(), KeyRole::DeviceOrigin);
    dev.tenant_id = device_tenant.map(String::from);
    ring.insert(dev);
    ring.insert(KeyEntry::new(server.public_key(), KeyRole::ServerChain));
    ring
}

fn one_row() -> ReceiptRow {
    let (device, server) = signers();
    let device_key_id = device.key_id();
    let payload = CheckpointPayload {
        tenant_id: TENANT,
        seq: 1,
        prev_receipt_hash: GENESIS_HASH,
        device_id: "device-unit",
        device_key_id: &device_key_id,
        issued_at: "2026-08-29T00:00:00Z",
        checkpoint_seq: 1,
        merkle_root: merkle_root(&[[0x01; 16]]).unwrap(),
        leaf_count: 1,
    };
    dual_sign(&payload.to_value(), &device, &server).unwrap()
}

#[test]
fn empty_walk_is_not_valid() {
    // Zero rows walked is a vacuous walk: no defects, but never the verdict a
    // verified history earns — a truncated-to-nothing export must not pass.
    let report = verify_chain(&ring(None), &[], 1, None);
    assert!(!report.valid);
    assert!(report.defects.is_empty());
    assert_eq!(report.checked, 0);
}

#[test]
fn mid_chain_anchor_is_the_intact_hash_when_nothing_verifies() {
    // A suffix walk that verifies nothing is intact up to its ANCHOR — the
    // genesis hash would be a hash the chain never had at that position.
    let anchor = [0xab; 32];
    let report = verify_chain(&ring(None), &[], 6, Some(anchor));
    assert_eq!(report.intact_prefix_seq, 5);
    assert_eq!(
        hex::encode(&report.intact_prefix_hash),
        hex::encode(&anchor)
    );
}

#[test]
fn tenant_scoped_device_key_answers_only_its_tenant() {
    let row = one_row();
    // Bound to the payload's tenant: verifies.
    let report = verify_chain(&ring(Some(TENANT)), std::slice::from_ref(&row), 1, None);
    assert!(report.valid, "{:?}", report.defects);
    // Bound to another tenant: the key is not published for this chain
    // (m1_001 scopes m1_device_keys per tenant) — unknown_key.
    let report = verify_chain(
        &ring(Some("99999999-9999-9999-9999-999999999999")),
        std::slice::from_ref(&row),
        1,
        None,
    );
    assert!(!report.valid);
    assert!(report
        .defects
        .iter()
        .any(|d| d.kind == DefectKind::UnknownKey));
}
