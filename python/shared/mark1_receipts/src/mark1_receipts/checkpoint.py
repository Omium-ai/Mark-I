"""Checkpoints: the Merkle tree over event_ids and the dual-signed sealing payload.

NEW relative to the vendor source (docs/13 §4.2): a checkpoint seals a batch of events
into one chained, dual-signed receipt (07 "The receipt chain", m1_002's checkpoint
columns); individual events then need only ``checkpoint_seq + inclusion_path`` to be
provable, so per-event receipts stay reserved for the six named classes.

The tree is RFC 6962's shape with BLAKE3 — 04 §7.2 names BLAKE3, and 05 §4.4's
transparency log is already 6962, so there is one tree discipline product-wide. The
construction is frozen by conformance/vectors/receipt/README.md (12 §3.4: the vector
commit fixes what the prose left open):

    leaf_hash(leaf)  = blake3(0x00 || leaf)         # leaves are 16-byte event_ids
    node_hash(L, R)  = blake3(0x01 || L || R)
    root([x])        = leaf_hash(x)
    root(D[n])       = node_hash(root(D[0:k]), root(D[k:n])), k = largest power of 2 < n
    inclusion_path   = bottom-up sibling subtree hashes; leaf index decides left/right

The 0x00/0x01 prefixes are second-preimage domain separation — an interior node can
never replay as a leaf. Odd counts split unbalanced, never by duplicating a leaf:
duplication is the CVE-2012-2459 shape.

ponytail: recursive O(n log n) tree, recomputed per call — checkpoints seal hundreds of
leaves, not millions. Memoise subtree roots if batch sizes ever grow past ~10^5.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from typing import Any

import blake3

from mark1_receipts import canonical
from mark1_receipts.keys import Signer

HASH_LEN = 32

# The verifier's shared defect vocabulary — the two Merkle members of
# conformance/vectors/receipt/README.md's table; chain.py owns the other six.
DEFECT_MERKLE_MISMATCH = "merkle_mismatch"
DEFECT_INCLUSION_PATH_INVALID = "inclusion_path_invalid"


def leaf_hash(leaf: bytes) -> bytes:
    return blake3.blake3(b"\x00" + leaf).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return blake3.blake3(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def merkle_root(leaves: Sequence[bytes]) -> bytes:
    if not leaves:
        # An empty checkpoint is refused, not given a sentinel root: m1_002 CHECKs
        # event_count > 0, and a root "over nothing" is a signable claim about nothing.
        raise ValueError("a checkpoint must seal at least one event")
    if len(leaves) == 1:
        return leaf_hash(leaves[0])
    k = _split(len(leaves))
    return node_hash(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


def inclusion_path(leaves: Sequence[bytes], index: int) -> list[bytes]:
    """RFC 6962 audit path for ``leaves[index]``: bottom-up sibling subtree hashes."""
    if not 0 <= index < len(leaves):
        raise IndexError(f"leaf index {index} outside 0..{len(leaves) - 1}")
    if len(leaves) == 1:
        return []
    k = _split(len(leaves))
    if index < k:
        return inclusion_path(leaves[:k], index) + [merkle_root(leaves[k:])]
    return inclusion_path(leaves[k:], index - k) + [merkle_root(leaves[:k])]


def build_checkpoint(event_ids: Sequence[bytes]) -> tuple[bytes, list[list[bytes]]]:
    """Root + per-leaf inclusion paths for a batch of event_ids, in spool order."""
    root = merkle_root(event_ids)
    return root, [inclusion_path(event_ids, i) for i in range(len(event_ids))]


def verify_inclusion(
    leaf: bytes, index: int, path: Sequence[bytes], root: bytes, *, leaf_count: int
) -> bool:
    """Does ``path`` carry ``leaf`` (at ``index``) up to ``root``?

    RFC 9162 §2.1.3.2's walk, because 6962's unbalanced split means a leaf's side at
    each level depends on the TREE SIZE, not on the index's bits alone (leaf 4 of 5 has
    an even index but is a right child) — which is why ``leaf_count`` is a required
    input and why every checkpoint payload carries it. Bool with no early raise,
    chain.py's posture: the caller records ``inclusion_path_invalid`` and keeps walking.
    A wrong-LENGTH path fails structurally: the walk must consume the whole path AND
    exhaust the tree (``sn == 0``) to accept.
    """
    if not 0 <= index < leaf_count:
        return False
    fn, sn = index, leaf_count - 1
    node = leaf_hash(leaf)
    for sibling in path:
        if len(sibling) != HASH_LEN or sn == 0:
            return False
        if fn & 1 or fn == sn:
            node = node_hash(sibling, node)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            node = node_hash(node, sibling)
        fn >>= 1
        sn >>= 1
    return sn == 0 and node == root


def verify_merkle_root(leaves: Sequence[bytes], claimed_root: bytes) -> bool:
    return bool(leaves) and merkle_root(leaves) == claimed_root


def build_checkpoint_payload(
    *,
    tenant_id: str,
    seq: int,
    prev_receipt_hash: bytes,
    device_id: str,
    device_key_id: str,
    issued_at: str,
    checkpoint_seq: int,
    merkle_root_hash: bytes,
    leaf_count: int,
    hosts: Sequence[Mapping[str, Any]] | None = None,
    arrests_acted: int = 0,
    arrests_recommended: int = 0,
) -> dict[str, Any]:
    """The checkpoint record's signed payload — field set frozen by the chain vectors.

    ``device_key_id`` rides INSIDE the payload (the origin claim is signed);
    ``server_key_id`` rides alongside as a row column, a lookup hint and not a trust
    input (vectors README "Signatures"). ``prev_receipt_hash`` is inside for ro_012's
    reason: signing the link is what makes position part of the claim.
    """
    payload: dict[str, Any] = {
        "v": canonical.PAYLOAD_VERSION,
        "type": "checkpoint",
        "tenant_id": tenant_id,
        "seq": int(seq),
        "prev_receipt_hash": prev_receipt_hash.hex(),
        "device_id": device_id,
        "device_key_id": device_key_id,
        "issued_at": issued_at,
        "checkpoint_seq": int(checkpoint_seq),
        "merkle_root": merkle_root_hash.hex(),
        "leaf_count": int(leaf_count),
    }
    if hosts is not None:
        # ADR-0017 payload v2: the host block and the two arrest counters ride INSIDE
        # the signed bytes. ``hosts`` is None for v1 — today's bytes, unchanged.
        payload["v"] = 2
        payload["hosts"] = [dict(h) for h in hosts]
        payload["arrests_acted"] = int(arrests_acted)
        payload["arrests_recommended"] = int(arrests_recommended)
    return payload


def dual_sign(payload: Mapping[str, Any], device: Signer, server: Signer) -> dict[str, Any]:
    """Sign one payload twice over ONE signing input (m1_002's column comment).

    Device-only would let Omium disown a receipt; server-only would let Omium mint
    history — dual signatures close both directions (m1_002 header). Returns the row
    shape chain.verify_chain consumes, payload as the exact signed text.
    """
    message = canonical.canonical_bytes(payload)
    return {
        "seq": int(payload["seq"]),
        "record_type": str(payload["type"]),
        "payload": canonical.canonical_json(payload),
        "receipt_hash": canonical.receipt_hash(payload),
        "device_key_id": device.key_id,
        "device_signature": device.sign(message),
        "server_key_id": server.key_id,
        "server_signature": server.sign(message),
    }


HOST_IDENTITY_DOMAIN = b"m1p.v1/host-identity\x00"


def profile_hash(canonical_profile: bytes) -> bytes:
    """sha256 over a host profile's canonical JSON (ADR-0013 §4) — the payload's profile_hash."""
    return hashlib.sha256(canonical_profile).digest()


def identity_hash(host_id: str, host_correlation_id: str, task_id: bytes) -> bytes:
    """ADR-0017 per-task identity hash.

    sha256(domain ‖ host_id ‖ 0 ‖ host_correlation_id ‖ 0 ‖ task_id hex).
    """
    h = hashlib.sha256()
    h.update(HOST_IDENTITY_DOMAIN)
    h.update(host_id.encode())
    h.update(b"\x00")
    h.update(host_correlation_id.encode())
    h.update(b"\x00")
    h.update(task_id.hex().encode())
    return h.digest()


def host_binding(
    *,
    session_id: bytes,
    transport: str,
    host_id: str,
    host_version: str,
    profile_hash_bytes: bytes,
    host_correlation_id: str,
    tasks: Sequence[tuple[bytes, bytes | None]],
) -> dict[str, Any]:
    """One ``hosts`` entry in the exact shape the hostchain vectors freeze.

    ``tasks`` are ``(task_id, identity_hash | None)`` pairs; the caller sorts hosts by
    session_id and tasks by task_id, as the sealer does.
    """
    task_values: list[dict[str, Any]] = []
    for task_id, ih in tasks:
        tv: dict[str, Any] = {"task_id": task_id.hex()}
        if ih is not None:
            tv["identity_hash"] = ih.hex()
        task_values.append(tv)
    return {
        "session_id": session_id.hex(),
        "transport": transport,
        "host_id": host_id,
        "host_version": host_version,
        "profile_hash": profile_hash_bytes.hex(),
        "host_correlation_id": host_correlation_id,
        "tasks": task_values,
    }
