"""Deterministic generator for the hostchain conformance vectors — see README.md.

The family freezes the v2 checkpoint payload of ADR-0017 (host-bound receipts) across
Go (mark1d sealer, controld countersign), Rust (mark1-receipt, the offline verifier) and
Python (mark1_receipts): the exact `hosts` / `arrests_acted` / `arrests_recommended`
shape inside the signed bytes, the profile hash, the per-task identity hash, and that
a v1 row and a v2 row chain together. Keys, domain prefix, canonical form and the
negative shapes are the receipt family's (../receipt/gen_vectors.py); nothing here
is a second definition of any of them.

Run from this directory: `uv run --frozen --all-packages python gen_vectors.py`.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "receipt"))
from gen_vectors import (  # noqa: E402
    DEVICE_SEED,
    GENESIS_HASH,
    SERVER_SEED,
    canonical_bytes,
    canonical_json,
    key_of,
    merkle_root,
    receipt_hash,
)

IDENTITY_DOMAIN = b"m1p.v1/host-identity\x00"


def profile_canonical(profile: dict) -> bytes:
    """hostprofile.Canonical: compact JSON, keys sorted (ADR-0013 §4)."""
    return json.dumps(profile, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def profile_hash(profile: dict) -> str:
    return hashlib.sha256(profile_canonical(profile)).hexdigest()


def identity_hash(host_id: str, host_correlation_id: str, task_hex: str) -> str:
    h = hashlib.sha256()
    h.update(IDENTITY_DOMAIN)
    h.update(host_id.encode())
    h.update(b"\x00")
    h.update(host_correlation_id.encode())
    h.update(b"\x00")
    h.update(task_hex.encode())
    return h.hexdigest()


CEM888 = {
    "arrest_mode": "recommend",
    "host_id": "cem888",
    "host_version": "2.0.1",
    "owns_config_surface": True,
    "owns_execution": True,
    "owns_memory": True,
    "schema_version": "m1p.v1",
    "supplies_identity": True,
}
TAILHOST = {
    "arrest_mode": "act",
    "host_id": "tailhost",
    "host_version": "0.9",
    "owns_config_surface": False,
    "owns_execution": True,
    "owns_memory": False,
    "schema_version": "m1p.v1",
    "supplies_identity": False,
}
DEFAULT = {
    "arrest_mode": "act",
    "host_id": "",
    "host_version": "",
    "owns_config_surface": True,
    "owns_execution": False,
    "owns_memory": True,
    "schema_version": "",
    "supplies_identity": False,
}


def main() -> None:
    dev_priv, dev_pub, dev_kid = key_of(DEVICE_SEED)
    srv_priv, srv_pub, srv_kid = key_of(SERVER_SEED)

    tenant = "11111111-1111-1111-1111-111111111111"
    device = "33333333-3333-3333-3333-333333333333"
    leaves = [[bytes([0xA0 + i]) * 16 for i in range(3)], [bytes([0xB0]) * 16], [bytes([0xC0]) * 16, bytes([0xC1]) * 16]]

    sess_cem = "aa" * 16
    sess_native = "0b" * 16
    sess_tail = "cc" * 16
    task1, task2, task3 = "01" * 16, "02" * 16, "03" * 16
    corr = "cem888-run-7f3a"

    hosts_v2 = [
        # sorted by session_id: 0b.. before aa..
        {
            "session_id": sess_native,
            "transport": "native",
            "host_id": "",
            "host_version": "",
            "profile_hash": profile_hash(DEFAULT),
            "host_correlation_id": "",
            "tasks": [{"task_id": task3}],
        },
        {
            "session_id": sess_cem,
            "transport": "fabric",
            "host_id": "cem888",
            "host_version": "2.0.1",
            "profile_hash": profile_hash(CEM888),
            "host_correlation_id": corr,
            "tasks": [
                {"task_id": task1, "identity_hash": identity_hash("cem888", corr, task1)},
                {"task_id": task2, "identity_hash": identity_hash("cem888", corr, task2)},
            ],
        },
    ]
    hosts_v2_tail = [
        {
            "session_id": sess_tail,
            "transport": "jsonl",
            "host_id": "tailhost",
            "host_version": "0.9",
            "profile_hash": profile_hash(TAILHOST),
            "host_correlation_id": "",
            "tasks": [],
        }
    ]

    chain = []
    prev = GENESIS_HASH
    for seq, extra in (
        (1, None),
        (2, {"hosts": hosts_v2, "arrests_acted": 1, "arrests_recommended": 2}),
        (3, {"hosts": hosts_v2_tail, "arrests_acted": 0, "arrests_recommended": 0}),
    ):
        payload = {
            "v": 1 if extra is None else 2,
            "type": "checkpoint",
            "tenant_id": tenant,
            "seq": seq,
            "prev_receipt_hash": prev.hex(),
            "device_id": device,
            "device_key_id": dev_kid,
            "issued_at": f"2026-10-03T00:00:0{seq}Z",
            "checkpoint_seq": seq,
            "merkle_root": merkle_root(leaves[seq - 1]).hex(),
            "leaf_count": len(leaves[seq - 1]),
        }
        if extra:
            payload.update(extra)
        signing_input = canonical_bytes(payload)
        h = receipt_hash(payload)
        chain.append(
            {
                "seq": seq,
                "payload": payload,
                "canonical_json": canonical_json(payload),
                "receipt_hash_hex": h.hex(),
                "device_key_id": dev_kid,
                "device_signature_hex": dev_priv.sign(signing_input).hex(),
                "server_key_id": srv_kid,
                "server_signature_hex": srv_priv.sign(signing_input).hex(),
            }
        )
        prev = h

    def clone(i):
        return json.loads(json.dumps(chain[i]))

    # The host block is INSIDE the signed bytes: changing it after the fact is the
    # receipt family's payload_mismatch (object-level: the stored text goes stale).
    n1 = clone(1)
    n1["payload"]["hosts"][1]["host_id"] = "someone-else"
    # A device that signed a different host block than it presents: bad_signature.
    n2 = clone(1)
    altered = json.loads(json.dumps(n2["payload"]))
    altered["arrests_acted"] = 0
    n2["device_signature_hex"] = dev_priv.sign(canonical_bytes(altered)).hex()
    # Counting a recommendation as an act is a tamper, not a rounding: the text and
    # the object agree, the hash does not.
    n3 = clone(1)
    n3["payload"]["arrests_acted"] = 3
    n3["payload"]["arrests_recommended"] = 0
    n3["canonical_json"] = canonical_json(n3["payload"])
    negatives = [
        {"name": "host_block_rewritten", "receipt": n1, "expect_defect": "payload_mismatch"},
        {"name": "signed_a_different_host_block", "receipt": n2, "expect_defect": "bad_signature"},
        {"name": "recommended_counted_as_acted", "receipt": n3, "expect_defect": "payload_mismatch"},
    ]

    manifest = {
        "_readme": "Frozen hostchain-family conformance contract (ADR-0017). README.md is normative; this file is the referee.",
        "keys": {
            "device": {"seed_hex": DEVICE_SEED.hex(), "public_hex": dev_pub.hex(), "key_id": dev_kid},
            "server": {"seed_hex": SERVER_SEED.hex(), "public_hex": srv_pub.hex(), "key_id": srv_kid},
        },
        "profiles": {
            "cem888": {"profile": CEM888, "canonical": profile_canonical(CEM888).decode(), "hash_hex": profile_hash(CEM888)},
            "tailhost": {"profile": TAILHOST, "canonical": profile_canonical(TAILHOST).decode(), "hash_hex": profile_hash(TAILHOST)},
            "default": {"profile": DEFAULT, "canonical": profile_canonical(DEFAULT).decode(), "hash_hex": profile_hash(DEFAULT)},
        },
        "identity_domain_hex": IDENTITY_DOMAIN.hex(),
        "leaves_hex": [[l.hex() for l in ls] for ls in leaves],
        "chain": chain,
        "negatives": negatives,
    }
    with open("manifest.json", "w", newline="\n") as f:
        json.dump(manifest, f, indent=1, sort_keys=False)
        f.write("\n")
    print(f"manifest.json written: {len(chain)} chain, {len(negatives)} negatives")


if __name__ == "__main__":
    main()
