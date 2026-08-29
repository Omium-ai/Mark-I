"""conf_vectors — the Python leg of the three-language receipt lock.

Drives EVERY entry in conformance/vectors/receipt/manifest.json, positives and
negatives, asserting the NAMED defect for each negative (README: a negative that fails
for the wrong reason is a failure). Test names contain ``conf_vectors`` because
tools/ci/conformance_crosslang.sh collects this suite with ``pytest -k conf_vectors``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from mark1_receipts import canonical, chain, checkpoint, keys

_MANIFEST = Path(__file__).resolve().parents[4] / "conformance/vectors/receipt/manifest.json"
MANIFEST = json.loads(_MANIFEST.read_text())

# An emptied family would turn every parametrize below into a SKIP and the
# plain loops into vacuous passes — fail collection instead (the Go leg's
# loadManifest guard, ported).
for _family in ("canonical", "chain", "negatives"):
    if not MANIFEST[_family]:
        raise RuntimeError(f"manifest family {_family} is empty")
if not MANIFEST["merkle"]["cases"]:
    raise RuntimeError("manifest family merkle is empty")

# Role binding is part of the contract under test (README "Signatures"): the
# device key answers origin claims ONLY, the server key countersignatures ONLY.
KEY_RING = {
    MANIFEST["keys"][role]["key_id"]: keys.PublishedKey(
        public_key=bytes.fromhex(MANIFEST["keys"][role]["public_hex"]),
        role=ring_role,
    )
    for role, ring_role in (
        ("device", keys.ROLE_DEVICE_ORIGIN),
        ("server", keys.ROLE_SERVER_CHAIN),
    )
}


def _row(entry: dict) -> dict:
    """Manifest receipt object → m1_002 row shape.

    The stored payload text is the ``canonical_json`` field when it parses back to the
    entry's ``payload`` object (the text-level tamper vectors keep the two consistent
    that way), else the payload object's own canonicalisation (the object-level tamper
    vectors mutate the object and leave the text stale on purpose).
    """
    text = entry["canonical_json"]
    try:
        consistent = json.loads(text) == entry["payload"]
    except ValueError:
        consistent = False
    if not consistent:
        text = canonical.canonical_json(entry["payload"])
    device_sig = entry["device_signature_hex"]  # null on server-only rows and n10
    return {
        "seq": entry["seq"],
        "payload": text,
        "receipt_hash": bytes.fromhex(entry["receipt_hash_hex"]),
        "record_type": entry["payload"].get("type"),
        "device_key_id": entry["device_key_id"],
        "device_signature": bytes.fromhex(device_sig) if device_sig else None,
        "server_key_id": entry["server_key_id"],
        "server_signature": bytes.fromhex(entry["server_signature_hex"]),
    }


def test_conf_vectors_domain_prefix_and_genesis():
    assert canonical.DOMAIN_PREFIX.hex() == MANIFEST["domain_prefix_hex"]
    assert canonical.GENESIS_HASH.hex() == MANIFEST["genesis_hash_hex"]


@pytest.mark.parametrize("role", ["device", "server"])
def test_conf_vectors_key_derivation(role):
    k = MANIFEST["keys"][role]
    signer = keys.Ed25519Signer(bytes.fromhex(k["seed_hex"]))
    assert signer.public_raw.hex() == k["public_hex"]
    assert signer.key_id == k["key_id"]
    assert keys.derive_key_id(signer.public_raw) == k["key_id"]


@pytest.mark.parametrize("case", MANIFEST["canonical"], ids=lambda c: c["name"])
def test_conf_vectors_canonical(case):
    assert canonical.canonical_json(case["payload"]) == case["canonical_json"]
    assert canonical.canonical_bytes(case["payload"]).hex() == case["canonical_bytes_hex"]
    assert canonical.receipt_hash(case["payload"]).hex() == case["receipt_hash_hex"]


@pytest.mark.parametrize("case", MANIFEST["merkle"]["cases"], ids=lambda c: c["name"])
def test_conf_vectors_merkle(case):
    leaves = [bytes.fromhex(h) for h in case["leaves_hex"]]
    root = bytes.fromhex(case["root_hex"])
    built_root, built_paths = checkpoint.build_checkpoint(leaves)
    assert built_root == root
    for idx_str, path_hex in case["inclusion_paths"].items():
        idx = int(idx_str)
        path = [bytes.fromhex(h) for h in path_hex]
        assert checkpoint.inclusion_path(leaves, idx) == path
        assert built_paths[idx] == path
        assert checkpoint.verify_inclusion(leaves[idx], idx, path, root, leaf_count=len(leaves))


@pytest.mark.parametrize("entry", MANIFEST["chain"], ids=lambda e: f"seq{e['seq']}")
def test_conf_vectors_chain_assembly_reproduces_frozen_bytes(entry):
    # Ed25519 is deterministic, so the WHOLE row — bytes, hash, both signatures — must
    # reproduce from the seeds; any drift in canonicalisation or signing input lands here.
    device = keys.Ed25519Signer(bytes.fromhex(MANIFEST["keys"]["device"]["seed_hex"]))
    server = keys.Ed25519Signer(bytes.fromhex(MANIFEST["keys"]["server"]["seed_hex"]))
    p = entry["payload"]
    if p["type"] != "checkpoint":
        # Server-only classes have no device-side builder: reproduce the
        # canonical bytes and the server countersignature directly — Ed25519
        # determinism still locks every byte.
        assert canonical.canonical_json(p) == entry["canonical_json"]
        assert canonical.receipt_hash(p).hex() == entry["receipt_hash_hex"]
        assert server.sign(canonical.canonical_bytes(p)).hex() == entry["server_signature_hex"]
        assert entry["device_signature_hex"] is None
        return
    payload = checkpoint.build_checkpoint_payload(
        tenant_id=p["tenant_id"],
        seq=p["seq"],
        prev_receipt_hash=bytes.fromhex(p["prev_receipt_hash"]),
        device_id=p["device_id"],
        device_key_id=device.key_id,
        issued_at=p["issued_at"],
        checkpoint_seq=p["checkpoint_seq"],
        merkle_root_hash=bytes.fromhex(p["merkle_root"]),
        leaf_count=p["leaf_count"],
    )
    row = checkpoint.dual_sign(payload, device, server)
    assert row["payload"] == entry["canonical_json"]
    assert row["receipt_hash"].hex() == entry["receipt_hash_hex"]
    assert row["device_signature"].hex() == entry["device_signature_hex"]
    assert row["server_signature"].hex() == entry["server_signature_hex"]


def test_conf_vectors_chain_verifies_from_genesis():
    report = chain.verify_chain([_row(e) for e in MANIFEST["chain"]], KEY_RING)
    assert report["valid"], report["defects"]
    assert report["defects"] == []
    assert report["checked"] == len(MANIFEST["chain"])
    assert report["intact_prefix_seq"] == MANIFEST["chain"][-1]["seq"]
    assert report["last_good_seq"] == MANIFEST["chain"][-1]["seq"]
    assert report["intact_prefix_hash"] == MANIFEST["chain"][-1]["receipt_hash_hex"]
    assert report["last_good_hash"] == MANIFEST["chain"][-1]["receipt_hash_hex"]


_RECEIPT_NEGATIVES = [n for n in MANIFEST["negatives"] if "receipt" in n]
_MERKLE_NEGATIVES = [n for n in MANIFEST["negatives"] if "merkle" in n]


@pytest.mark.parametrize("neg", _RECEIPT_NEGATIVES, ids=lambda n: n["name"])
def test_conf_vectors_negative_receipt(neg):
    row = _row(neg["receipt"])
    anchor = neg.get("verify_against_prev_hash_hex")
    report = chain.verify_chain(
        [row],
        KEY_RING,
        start_seq=row["seq"],
        prev_hash=bytes.fromhex(anchor) if anchor else None,
    )
    assert not report["valid"]
    found = {d["defect"] for d in report["defects"]}
    assert neg["expect_defect"] in found, (neg["name"], report["defects"])
    # Every reported defect must be vocabulary — an off-vocabulary name is drift.
    assert found <= set(MANIFEST["defect_vocabulary"])


@pytest.mark.parametrize("neg", _MERKLE_NEGATIVES, ids=lambda n: n["name"])
def test_conf_vectors_negative_merkle(neg):
    m = neg["merkle"]
    leaves = [bytes.fromhex(h) for h in m["leaves_hex"]]
    if neg["expect_defect"] == "merkle_mismatch":
        assert not checkpoint.verify_merkle_root(leaves, bytes.fromhex(m["claimed_root_hex"]))
    else:
        assert neg["expect_defect"] == "inclusion_path_invalid"
        assert not checkpoint.verify_inclusion(
            leaves[m["leaf_index"]],
            m["leaf_index"],
            [bytes.fromhex(h) for h in m["path_hex"]],
            bytes.fromhex(m["root_hex"]),
            leaf_count=len(leaves),
        )


def test_conf_vectors_defect_vocabulary_is_complete():
    assert set(MANIFEST["defect_vocabulary"]) == {
        "broken_link",
        "payload_mismatch",
        "unknown_key",
        "bad_signature",
        "non_canonical_payload",
        "bad_countersignature",
        "merkle_mismatch",
        "inclusion_path_invalid",
    }
