"""conformance/vectors/hostchain — ADR-0017 host-bound receipts, the Python leg.

The builder (``build_checkpoint_payload`` with ``hosts``) must reproduce every frozen
v1 and v2 row byte for byte; the profile and identity hashes are the vectors'; the
chain verifies from genesis and each negative fails for the named reason.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from mark1_receipts import canonical, chain, checkpoint, keys

_MANIFEST = Path(__file__).resolve().parents[4] / "conformance/vectors/hostchain/manifest.json"
MANIFEST = json.loads(_MANIFEST.read_text())
for _family in ("chain", "negatives"):
    if not MANIFEST[_family]:
        raise RuntimeError(f"manifest family {_family} is empty")

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
    text = entry["canonical_json"]
    try:
        consistent = json.loads(text) == entry["payload"]
    except ValueError:
        consistent = False
    if not consistent:
        text = canonical.canonical_json(entry["payload"])
    device_sig = entry["device_signature_hex"]
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


@pytest.mark.parametrize("name", sorted(MANIFEST["profiles"]))
def test_conf_vectors_hostchain_profile_hash(name):
    p = MANIFEST["profiles"][name]
    assert checkpoint.profile_hash(p["canonical"].encode()).hex() == p["hash_hex"]


def test_conf_vectors_hostchain_identity_domain():
    assert checkpoint.HOST_IDENTITY_DOMAIN.hex() == MANIFEST["identity_domain_hex"]


@pytest.mark.parametrize("entry", MANIFEST["chain"], ids=lambda e: f"seq{e['seq']}")
def test_conf_vectors_hostchain_assembly_reproduces_frozen_bytes(entry):
    device = keys.Ed25519Signer(bytes.fromhex(MANIFEST["keys"]["device"]["seed_hex"]))
    server = keys.Ed25519Signer(bytes.fromhex(MANIFEST["keys"]["server"]["seed_hex"]))
    p = entry["payload"]
    extra = {}
    if p["v"] == 2:
        # The host block is rebuilt from its parts — the builder's shape, not a copy.
        hosts = []
        for h in p["hosts"]:
            tasks = []
            for t in h["tasks"]:
                ih = t.get("identity_hash")
                if ih is not None:
                    recomputed = checkpoint.identity_hash(
                        h["host_id"], h["host_correlation_id"], bytes.fromhex(t["task_id"])
                    )
                    assert recomputed.hex() == ih, (h["host_id"], t["task_id"])
                tasks.append((bytes.fromhex(t["task_id"]), bytes.fromhex(ih) if ih else None))
            hosts.append(
                checkpoint.host_binding(
                    session_id=bytes.fromhex(h["session_id"]),
                    transport=h["transport"],
                    host_id=h["host_id"],
                    host_version=h["host_version"],
                    profile_hash_bytes=bytes.fromhex(h["profile_hash"]),
                    host_correlation_id=h["host_correlation_id"],
                    tasks=tasks,
                )
            )
        extra = {
            "hosts": hosts,
            "arrests_acted": p["arrests_acted"],
            "arrests_recommended": p["arrests_recommended"],
        }
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
        **extra,
    )
    assert payload["v"] == p["v"]
    row = checkpoint.dual_sign(payload, device, server)
    assert row["payload"] == entry["canonical_json"]
    assert row["receipt_hash"].hex() == entry["receipt_hash_hex"]
    assert row["device_signature"].hex() == entry["device_signature_hex"]
    assert row["server_signature"].hex() == entry["server_signature_hex"]


def test_conf_vectors_hostchain_verifies_from_genesis():
    report = chain.verify_chain([_row(e) for e in MANIFEST["chain"]], KEY_RING)
    assert report["valid"], report["defects"]
    assert report["checked"] == len(MANIFEST["chain"])
    assert report["intact_prefix_seq"] == MANIFEST["chain"][-1]["seq"]


@pytest.mark.parametrize("neg", MANIFEST["negatives"], ids=lambda n: n["name"])
def test_conf_vectors_hostchain_negative_receipt(neg):
    row = _row(neg["receipt"])
    report = chain.verify_chain([row], KEY_RING, start_seq=row["seq"])
    assert not report["valid"]
    found = {d["defect"] for d in report["defects"]}
    assert neg["expect_defect"] in found, (neg["name"], report["defects"])
