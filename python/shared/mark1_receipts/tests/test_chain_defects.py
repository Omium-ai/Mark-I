"""Unit tests for the chain walk's defect reporting and the Merkle edge cases.

Everything the frozen vectors do NOT exercise: seq gaps, the two-good-numbers
divergence, missing signatures, in-chain merkle_mismatch, float refusal, and the odd
Merkle shapes. TEST-ONLY seeds per the vectors' README — worthless by definition.
"""

from __future__ import annotations

import pytest
from mark1_receipts import canonical, chain, checkpoint, keys

DEVICE = keys.Ed25519Signer(bytes([0x11]) * 32)
SERVER = keys.Ed25519Signer(bytes([0x22]) * 32)
KEY_RING = {
    DEVICE.key_id: keys.PublishedKey(DEVICE.public_raw, keys.ROLE_DEVICE_ORIGIN),
    SERVER.key_id: keys.PublishedKey(SERVER.public_raw, keys.ROLE_SERVER_CHAIN),
}

TENANT = "11111111-1111-1111-1111-111111111111"
DEVICE_ID = "33333333-3333-3333-3333-333333333333"


def _chain(n: int) -> list[dict]:
    rows = []
    prev = canonical.GENESIS_HASH
    for seq in range(1, n + 1):
        leaves = [bytes([seq]) * 16, bytes([seq, seq]) * 8]
        root, _ = checkpoint.build_checkpoint(leaves)
        payload = checkpoint.build_checkpoint_payload(
            tenant_id=TENANT,
            seq=seq,
            prev_receipt_hash=prev,
            device_id=DEVICE_ID,
            device_key_id=DEVICE.key_id,
            issued_at=f"2026-08-29T00:00:{seq:02d}Z",
            checkpoint_seq=seq,
            merkle_root_hash=root,
            leaf_count=len(leaves),
        )
        row = checkpoint.dual_sign(payload, DEVICE, SERVER)
        row["leaves"] = leaves
        rows.append(row)
        prev = row["receipt_hash"]
    return rows


def _defects(report: dict) -> set[str]:
    return {d["defect"] for d in report["defects"]}


def test_healthy_chain_two_good_numbers_agree():
    report = chain.verify_chain(_chain(4), KEY_RING)
    assert report["valid"]
    assert report["intact_prefix_seq"] == report["last_good_seq"] == 4


def test_seq_gap_reports_broken_link_once():
    rows = _chain(4)
    del rows[1]  # seq 2 vanishes
    report = chain.verify_chain(rows, KEY_RING)
    gap = [d for d in report["defects"] if d["defect"] == "broken_link"]
    # The re-anchor rule: one deletion is ONE broken_link, not a cascade down the tail.
    assert len(gap) == 1 and gap[0]["seq"] == 3
    assert report["intact_prefix_seq"] == 1
    assert report["last_good_seq"] == 4


def test_mid_chain_tamper_splits_customer_and_operator_numbers():
    rows = _chain(4)
    rows[1]["payload"] = rows[1]["payload"].replace('"leaf_count":2', '"leaf_count":9')
    report = chain.verify_chain(rows, KEY_RING)
    assert "payload_mismatch" in _defects(report)
    # Customer's number stops before the damage; operator's number reaches the head.
    assert report["intact_prefix_seq"] == 1
    assert report["last_good_seq"] == 4


def test_missing_device_signature_on_origin_class_is_bad_signature():
    rows = _chain(1)
    rows[0]["device_signature"] = None
    report = chain.verify_chain(rows, KEY_RING)
    assert "bad_signature" in _defects(report)


def test_relabelled_row_column_cannot_waive_the_device_signature():
    # The unsigned record_type column must not out-vote the SIGNED payload's
    # "type": stripping the device signature and relabelling the row is the
    # cheapest way to launder a device-originated record into a server act.
    rows = _chain(1)
    rows[0]["device_signature"] = None
    rows[0]["record_type"] = "noise_certificate"
    report = chain.verify_chain(rows, KEY_RING)
    assert "bad_signature" in _defects(report)


def test_empty_walk_is_not_valid():
    # Zero rows checked is a vacuous walk, not a verified history.
    report = chain.verify_chain([], KEY_RING)
    assert not report["valid"]
    assert report["defects"] == []
    assert report["checked"] == 0


def test_server_key_cannot_answer_a_device_origin_claim():
    # Both signatures minted by the server key, payload naming the server key
    # as its device origin: self-consistent bytes that only key-ROLE binding
    # (05 §4.5) rejects — otherwise Omium could mint history alone.
    payload = checkpoint.build_checkpoint_payload(
        tenant_id=TENANT,
        seq=1,
        prev_receipt_hash=canonical.GENESIS_HASH,
        device_id=DEVICE_ID,
        device_key_id=SERVER.key_id,
        issued_at="2026-08-29T00:00:01Z",
        checkpoint_seq=1,
        merkle_root_hash=checkpoint.merkle_root([b"\x01" * 16]),
        leaf_count=1,
    )
    report = chain.verify_chain([checkpoint.dual_sign(payload, SERVER, SERVER)], KEY_RING)
    assert not report["valid"]
    assert "unknown_key" in _defects(report)


def test_tenant_scoped_device_key_answers_only_its_tenant():
    ring = dict(KEY_RING)
    ring[DEVICE.key_id] = keys.PublishedKey(
        DEVICE.public_raw, keys.ROLE_DEVICE_ORIGIN, tenant_id=TENANT
    )
    assert chain.verify_chain(_chain(1), ring)["valid"]
    ring[DEVICE.key_id] = keys.PublishedKey(
        DEVICE.public_raw, keys.ROLE_DEVICE_ORIGIN, tenant_id="another-tenant"
    )
    report = chain.verify_chain(_chain(1), ring)
    assert not report["valid"]
    assert "unknown_key" in _defects(report)


def test_missing_server_countersignature_is_bad_countersignature():
    rows = _chain(1)
    rows[0]["server_signature"] = None
    report = chain.verify_chain(rows, KEY_RING)
    assert "bad_countersignature" in _defects(report)


def test_genesis_must_point_at_zero_hash():
    rows = _chain(2)
    report = chain.verify_chain(rows[1:], KEY_RING, start_seq=1)
    # A mid-chain row renumbered as a chain start — truncation's exact leftover shape.
    assert "broken_link" in _defects(report)


def test_suffix_walk_anchors_on_prev_hash():
    rows = _chain(3)
    report = chain.verify_chain(rows[1:], KEY_RING, start_seq=2, prev_hash=rows[0]["receipt_hash"])
    assert report["valid"]
    report = chain.verify_chain(rows[1:], KEY_RING, start_seq=2, prev_hash=b"\xab" * 32)
    assert "broken_link" in _defects(report)


def test_checkpoint_with_wrong_leaves_is_merkle_mismatch():
    rows = _chain(1)
    rows[0]["leaves"] = [b"\xff" * 16, b"\xee" * 16]
    report = chain.verify_chain(rows, KEY_RING)
    assert "merkle_mismatch" in _defects(report)


def test_unparseable_payload_is_non_canonical_and_payload_mismatch():
    rows = _chain(1)
    rows[0]["payload"] = "not json at all"
    report = chain.verify_chain(rows, KEY_RING)
    assert {"non_canonical_payload", "payload_mismatch"} <= _defects(report)


def test_float_payload_is_refused():
    with pytest.raises(canonical.NonCanonicalNumberError):
        canonical.canonical_json({"nested": [{"x": 0.5}]})


def test_merkle_single_leaf_root_is_leaf_hash():
    leaf = bytes(16)
    root, paths = checkpoint.build_checkpoint([leaf])
    assert root == checkpoint.leaf_hash(leaf)
    assert paths == [[]]
    assert checkpoint.verify_inclusion(leaf, 0, [], root, leaf_count=1)


def test_merkle_empty_batch_is_refused():
    with pytest.raises(ValueError):
        checkpoint.merkle_root([])
    assert not checkpoint.verify_merkle_root([], b"\x00" * 32)


@pytest.mark.parametrize("n", [2, 3, 5, 6, 7, 8, 9])
def test_merkle_every_leaf_proves_inclusion(n):
    leaves = [bytes([i]) * 16 for i in range(n)]
    root, paths = checkpoint.build_checkpoint(leaves)
    for i, path in enumerate(paths):
        assert checkpoint.verify_inclusion(leaves[i], i, path, root, leaf_count=n)
        # The path must not prove any OTHER position or leaf.
        assert not checkpoint.verify_inclusion(leaves[i], (i + 1) % n, path, root, leaf_count=n)
        assert not checkpoint.verify_inclusion(b"\xfe" * 16, i, path, root, leaf_count=n)


def test_merkle_overlong_path_is_invalid():
    leaves = [bytes([i]) * 16 for i in range(3)]
    root, paths = checkpoint.build_checkpoint(leaves)
    padded = paths[0] + [b"\x00" * 32]
    assert not checkpoint.verify_inclusion(leaves[0], 0, padded, root, leaf_count=3)


def test_merkle_wrong_leaf_count_is_invalid():
    leaves = [bytes([i]) * 16 for i in range(5)]
    root, paths = checkpoint.build_checkpoint(leaves)
    assert not checkpoint.verify_inclusion(leaves[4], 4, paths[4], root, leaf_count=4)
    assert not checkpoint.verify_inclusion(leaves[4], 4, paths[4], root, leaf_count=6)
