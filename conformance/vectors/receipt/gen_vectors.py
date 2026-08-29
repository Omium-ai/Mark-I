#!/usr/bin/env python3
"""Deterministic generator for the receipt conformance vectors — see README.md.

Run:  uv run --with blake3 --with cryptography python gen_vectors.py
It rewrites manifest.json in place. Committed so the vectors are re-derivable,
but the MANIFEST is the frozen contract — if regeneration ever changes a byte,
that is a finding against this script, not a license to update the manifest.

Everything here is pinned by README.md; the load-bearing choices, restated:
  * canonical bytes  = b"mark1-label-v1\\x00" + json(sort_keys, (",",":"), ensure_ascii)
  * receipt_hash     = SHA-256 over those SAME bytes (estate canonical.py rule:
                       verify-the-hash and verify-the-signature share one input)
  * both signatures  (device origin + server countersign) are Ed25519 over the
                       same signing input — m1_002's column comment, verbatim
  * Merkle           = RFC 6962 shape with BLAKE3: leaf = blake3(0x00 || leaf16),
                       node = blake3(0x01 || L || R), split at largest power of
                       two < n; inclusion path = bottom-up siblings
  * keys             = fixed 32-byte seeds, TEST-ONLY, spelled out in README.md
"""

from __future__ import annotations

import hashlib
import json

import blake3
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

DOMAIN_PREFIX = b"mark1-label-v1\x00"
GENESIS_HASH = b"\x00" * 32

DEVICE_SEED = bytes([0x11]) * 32
SERVER_SEED = bytes([0x22]) * 32


def canonical_json(payload) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def canonical_bytes(payload) -> bytes:
    return DOMAIN_PREFIX + canonical_json(payload).encode("utf-8")


def receipt_hash(payload) -> bytes:
    return hashlib.sha256(canonical_bytes(payload)).digest()


def key_of(seed: bytes):
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    key_id = "ed25519:" + hashlib.sha256(pub).hexdigest()[:16]
    return priv, pub, key_id


def leaf_hash(leaf16: bytes) -> bytes:
    return blake3.blake3(b"\x00" + leaf16).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return blake3.blake3(b"\x01" + left + right).digest()


def merkle_root(leaves: list[bytes]) -> bytes:
    n = len(leaves)
    if n == 1:
        return leaf_hash(leaves[0])
    k = 1
    while k * 2 < n:
        k *= 2
    return node_hash(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


def inclusion_path(leaves: list[bytes], index: int) -> list[bytes]:
    n = len(leaves)
    if n == 1:
        return []
    k = 1
    while k * 2 < n:
        k *= 2
    if index < k:
        return inclusion_path(leaves[:k], index) + [merkle_root(leaves[k:])]
    return inclusion_path(leaves[k:], index - k) + [merkle_root(leaves[:k])]


def main() -> None:
    dev_priv, dev_pub, dev_kid = key_of(DEVICE_SEED)
    srv_priv, srv_pub, srv_kid = key_of(SERVER_SEED)

    # ---- canonical family: the bytes three languages must reproduce exactly ----
    canonical_cases = [
        {"name": "simple", "payload": {"b": 1, "a": "x"}},
        {
            "name": "unicode",
            # ensure_ascii turns every non-ASCII char into \uXXXX (astral chars
            # into surrogate PAIRS), and key order is code-point order — which
            # UTF-8 byte order agrees with, so Go/Rust byte sorts match Python.
            "payload": {"é": "café", "a": "\u0000ctrl\n\t", "z": "\U0001f600", "à": "sorts-after-z"},
        },
        {
            "name": "nested_empty",
            "payload": {"outer": {"y": [], "x": {}}, "empty": "", "none": None, "list": [1, "two", None, {"k": [0]}]},
        },
        {
            # 2**53+1: exact in int64/uint64, silently rounded by any float path.
            # A language whose JSON layer detours through f64 fails HERE, not in prod.
            "name": "big_int",
            "payload": {"big": 9007199254740993, "neg": -1, "zero": 0},
        },
        {
            # Outside BOTH machine ranges (2**64 and int64_min - 1): big_int only
            # catches an f64 detour, not a leg that refuses what the other two
            # render — Python ints and Go's json.Number are unbounded, so the
            # canonical bytes must be too, or a correctly signed receipt reads
            # as non_canonical_payload in exactly one language.
            "name": "huge_int",
            "payload": {"pos": 18446744073709551616, "neg": -9223372036854775809},
        },
    ]
    canonical_vectors = [
        {
            "name": c["name"],
            "payload": c["payload"],
            "canonical_json": canonical_json(c["payload"]),
            "canonical_bytes_hex": canonical_bytes(c["payload"]).hex(),
            "receipt_hash_hex": receipt_hash(c["payload"]).hex(),
        }
        for c in canonical_cases
    ]

    # ---- merkle family ----
    leaves5 = [bytes.fromhex(f"01912f3a00007000800000000000000{i}") for i in range(5)]
    leaves1 = [leaves5[0]]
    leaves2 = leaves5[:2]
    merkle_vectors = {
        "construction": "rfc6962-blake3: leaf=blake3(0x00||leaf16), node=blake3(0x01||L||R), split at largest power of two < n",
        "cases": [
            {
                "name": "five_leaves",
                "leaves_hex": [l.hex() for l in leaves5],
                "root_hex": merkle_root(leaves5).hex(),
                "inclusion_paths": {
                    str(i): [h.hex() for h in inclusion_path(leaves5, i)] for i in (0, 3, 4)
                },
            },
            {
                "name": "single_leaf",
                "leaves_hex": [l.hex() for l in leaves1],
                "root_hex": merkle_root(leaves1).hex(),
                "inclusion_paths": {"0": []},
            },
            {
                "name": "two_leaves",
                "leaves_hex": [l.hex() for l in leaves2],
                "root_hex": merkle_root(leaves2).hex(),
                "inclusion_paths": {"0": [merkle_root([leaves2[1]]).hex()], "1": [merkle_root([leaves2[0]]).hex()]},
            },
        ],
    }

    # ---- chain family: 3 dual-signed checkpoint receipts ----
    tenant = "11111111-1111-1111-1111-111111111111"
    device = "33333333-3333-3333-3333-333333333333"
    chain = []
    prev = GENESIS_HASH
    roots = [merkle_root(leaves5), merkle_root(leaves1), merkle_root(leaves2)]
    counts = [5, 1, 2]
    for seq in (1, 2, 3):
        payload = {
            "v": 1,
            "type": "checkpoint",
            "tenant_id": tenant,
            "seq": seq,
            "prev_receipt_hash": prev.hex(),
            "device_id": device,
            "device_key_id": dev_kid,
            "issued_at": f"2026-08-29T00:00:0{seq}Z",
            "checkpoint_seq": seq,
            "merkle_root": roots[seq - 1].hex(),
            "leaf_count": counts[seq - 1],
        }
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

    # Row 4 is a SERVER-ONLY class (m1_002 ck_m1_receipts_origin: only the three
    # device-originated classes carry a device signature). Without it every chain
    # vector is a checkpoint, and a leg that wrongly demands a device key on every
    # row — unable to verify the discontinuity/noise_certificate face of the
    # chain — passes the lock anyway.
    server_only_payload = {
        "v": 1,
        "type": "noise_certificate",
        "tenant_id": tenant,
        "seq": 4,
        "prev_receipt_hash": prev.hex(),
        "issued_at": "2026-08-29T00:00:04Z",
        "subject_id": "55555555-5555-5555-5555-555555555555",
    }
    chain.append(
        {
            "seq": 4,
            "payload": server_only_payload,
            "canonical_json": canonical_json(server_only_payload),
            "receipt_hash_hex": receipt_hash(server_only_payload).hex(),
            "device_key_id": None,
            "device_signature_hex": None,
            "server_key_id": srv_kid,
            "server_signature_hex": srv_priv.sign(canonical_bytes(server_only_payload)).hex(),
        }
    )

    # ---- negatives: each is a full receipt object + the expected named defect ----
    def clone(i):
        return json.loads(json.dumps(chain[i]))

    n1 = clone(1)
    n1["payload"]["leaf_count"] = 999  # payload no longer matches its stored hash
    n1_defect = "payload_mismatch"

    n2 = clone(1)
    n2["payload"]["prev_receipt_hash"] = "ab" * 32  # re-parented
    # re-sign+re-hash so ONLY the link is wrong — broken_link, not payload_mismatch
    n2["canonical_json"] = canonical_json(n2["payload"])
    n2["receipt_hash_hex"] = receipt_hash(n2["payload"]).hex()
    n2["device_signature_hex"] = dev_priv.sign(canonical_bytes(n2["payload"])).hex()
    n2["server_signature_hex"] = srv_priv.sign(canonical_bytes(n2["payload"])).hex()
    n2_defect = "broken_link"

    n3 = clone(2)
    n3["device_signature_hex"] = srv_priv.sign(canonical_bytes(n3["payload"])).hex()
    n3_defect = "bad_signature"  # right bytes, wrong key: the origin claim fails

    n4 = clone(2)
    sig = bytearray(bytes.fromhex(n4["server_signature_hex"]))
    sig[0] ^= 0xFF
    n4["server_signature_hex"] = sig.hex()
    n4_defect = "bad_countersignature"

    n5 = clone(0)
    n5["canonical_json"] = " " + n5["canonical_json"]  # one leading space
    n5_defect = "non_canonical_payload"

    n6 = clone(0)
    n6["device_key_id"] = "ed25519:deadbeefdeadbeef"
    n6["payload"]["device_key_id"] = "ed25519:deadbeefdeadbeef"
    n6["canonical_json"] = canonical_json(n6["payload"])
    n6["receipt_hash_hex"] = receipt_hash(n6["payload"]).hex()
    n6["device_signature_hex"] = dev_priv.sign(canonical_bytes(n6["payload"])).hex()
    n6["server_signature_hex"] = srv_priv.sign(canonical_bytes(n6["payload"])).hex()
    n6_defect = "unknown_key"

    n7 = {
        "leaves_hex": [l.hex() for l in leaves5],
        "claimed_root_hex": merkle_root(leaves2).hex(),  # wrong tree's root
    }
    n7_defect = "merkle_mismatch"

    n8 = {
        "leaves_hex": [l.hex() for l in leaves5],
        "leaf_index": 3,
        "root_hex": merkle_root(leaves5).hex(),
        "path_hex": [h.hex() for h in inclusion_path(leaves5, 3)][:-1],  # truncated
    }
    n8_defect = "inclusion_path_invalid"

    # The server key minting BOTH signatures, with the payload naming the server
    # key as its device origin. Every byte self-consistent — only key-ROLE binding
    # (05 §4.5's key-class split) can reject it, which is m1_002's whole reason
    # for dual-signing: server-only must not be able to mint history.
    n9 = clone(0)
    n9["payload"]["device_key_id"] = srv_kid
    n9["device_key_id"] = srv_kid
    n9["canonical_json"] = canonical_json(n9["payload"])
    n9["receipt_hash_hex"] = receipt_hash(n9["payload"]).hex()
    n9["device_signature_hex"] = srv_priv.sign(canonical_bytes(n9["payload"])).hex()
    n9["server_signature_hex"] = srv_priv.sign(canonical_bytes(n9["payload"])).hex()
    n9_defect = "unknown_key"

    # Device signature deleted, everything else untouched: the SIGNED payload
    # still claims a device origin, so "the device could not have originated
    # this" must be the verdict regardless of any unsigned row column.
    n10 = clone(0)
    n10["device_signature_hex"] = None
    n10_defect = "bad_signature"

    negatives = [
        {"name": "tampered_payload", "receipt": n1, "expect_defect": n1_defect},
        {"name": "broken_prev_link", "receipt": n2, "expect_defect": n2_defect,
         "verify_against_prev_hash_hex": chain[0]["receipt_hash_hex"]},
        {"name": "wrong_origin_key", "receipt": n3, "expect_defect": n3_defect},
        {"name": "corrupt_countersign", "receipt": n4, "expect_defect": n4_defect},
        {"name": "non_canonical_text", "receipt": n5, "expect_defect": n5_defect},
        {"name": "unknown_key_id", "receipt": n6, "expect_defect": n6_defect},
        {"name": "wrong_merkle_root", "merkle": n7, "expect_defect": n7_defect},
        {"name": "truncated_inclusion_path", "merkle": n8, "expect_defect": n8_defect},
        {"name": "server_key_as_device_origin", "receipt": n9, "expect_defect": n9_defect},
        {"name": "stripped_device_signature", "receipt": n10, "expect_defect": n10_defect},
    ]

    manifest = {
        "_readme": "Frozen receipt-family conformance contract. README.md is normative; this file is the referee.",
        "domain_prefix_hex": DOMAIN_PREFIX.hex(),
        "genesis_hash_hex": GENESIS_HASH.hex(),
        "keys": {
            "device": {"seed_hex": DEVICE_SEED.hex(), "public_hex": dev_pub.hex(), "key_id": dev_kid},
            "server": {"seed_hex": SERVER_SEED.hex(), "public_hex": srv_pub.hex(), "key_id": srv_kid},
        },
        "canonical": canonical_vectors,
        "merkle": merkle_vectors,
        "chain": chain,
        "negatives": negatives,
        "defect_vocabulary": [
            "broken_link", "payload_mismatch", "unknown_key", "bad_signature",
            "non_canonical_payload",
            "bad_countersignature", "merkle_mismatch", "inclusion_path_invalid",
        ],
    }
    with open("manifest.json", "w") as f:
        json.dump(manifest, f, indent=1, sort_keys=False)
        f.write("\n")
    print(f"manifest.json written: {len(canonical_vectors)} canonical, "
          f"{len(merkle_vectors['cases'])} merkle, {len(chain)} chain, {len(negatives)} negative")


if __name__ == "__main__":
    main()
