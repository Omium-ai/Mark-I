"""Verifying a tenant's receipt chain: every defect named, none swallowed.

ADAPTED from Omium-platform/core-services/recovery-orchestrator/app/receipts/chain.py
(copied 2026-08-29, per docs/13 §4.2), with the estate's five defect kinds and its
two-good-numbers semantics kept verbatim, extended for what m1_002 added to ro_012's
design: the server COUNTERSIGNATURE (dual-signed rows) and the checkpoint columns.

The estate's append path (append_verdict_receipts and its locked head row) is
deliberately NOT carried: in Mark 1 exactly ONE writer appends — controld, in Go,
holding the head lock and the server key (m1_002 §5: "a service that could append
receipts about its own output could certify itself"). Python services only ever READ
the chain, so this module is a pure function over rows, which is also what makes it the
same code path an offline auditor runs: no connection, no clock, no config.

Both signatures are over the SAME signing input — domain prefix || the stored payload
bytes AS THEY SIT, never a re-serialisation (m1_002's column comment; ro_012's rule).
``device_key_id`` is read from inside the signed payload (the origin claim is signed);
``server_key_id`` is the row's lookup hint, safe to trust as a LOOKUP because a
signature only verifies under the key that actually made it.

The defect vocabulary is the estate's five plus three, frozen by
conformance/vectors/receipt/README.md:

    broken_link             seq gap, or the payload's prev_receipt_hash does not match
                            the predecessor's receipt_hash
    payload_mismatch        stored receipt_hash is not SHA-256 of the stored signing input
    unknown_key             a named key_id absent from the published key set — also what
                            an unpublished retired key looks like, which is an
                            operational failure that must not be reported as fraud
    bad_signature           device origin signature fails (or is missing on a
                            device-originated class — ck_m1_receipts_origin's shape)
    non_canonical_payload   stored payload text is not its own canonical re-serialisation
    bad_countersignature    server countersignature fails over the signing input
    merkle_mismatch         a checkpoint's merkle_root is not the root of its leaves
    inclusion_path_invalid  owned by checkpoint.verify_inclusion (standalone vectors);
                            named here so the vocabulary lives in one table
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any

from mark1_receipts import canonical, checkpoint, keys

# ck_m1_receipts_origin's equivalence: the classes that ORIGINATE on a device carry the
# device signature; everything else is a server act and must not dress up as attested.
DEVICE_ORIGIN_TYPES = frozenset({"checkpoint", "coverage_transition", "guard_contamination"})


def _parse_payload(payload_text: str) -> dict[str, Any] | None:
    try:
        parsed = json.loads(payload_text)
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None


def verify_chain(
    receipts: Sequence[Mapping[str, Any]],
    key_ring: Mapping[str, keys.PublishedKey],
    *,
    start_seq: int = 1,
    prev_hash: bytes | None = None,
) -> dict[str, Any]:
    """Walk chain rows in seq order and report every defect found, not just the first.

    ``receipts`` rows carry m1_002's column names: ``seq``, ``payload`` (the exact
    stored text), ``receipt_hash``, ``record_type``, ``server_key_id``,
    ``server_signature``, ``device_key_id``/``device_signature`` (origin classes), and
    optionally ``leaves`` — the checkpoint's event_id bytes, when the caller has them —
    to recompute ``merkle_root``. ``key_ring`` maps key_id → :class:`keys.PublishedKey`
    — the union of m1_server_signing_keys and m1_device_keys, retired included (ro_012:
    retired keys stop signing, never stop being published), each carrying its ROLE:
    the device leg only accepts a device origin key and the server leg only the server
    chain key (05 §4.5's key-class split — a flat roleless set would let the server
    key alone mint a "device-attested" chain, m1_002's header direction).

    ``prev_hash`` anchors a suffix walk (verify from seq N given the hash of N-1);
    at ``start_seq`` 1 the anchor is the genesis hash, exactly ro_012's equivalence.

    TWO "GOOD" NUMBERS, the estate's semantics kept because there are two questions:
    ``intact_prefix_seq`` is the CUSTOMER's number — how far an unbroken walk got, and
    nothing past it is evidence; ``last_good_seq`` is the OPERATOR's number — the
    highest self-consistent row, the position a discontinuity link anchors to. Equal on
    a healthy chain, which is why shipping only one is the easy bug.

    Never raises on a defect: the SHAPE of the damage is the diagnostic.
    """
    defects: list[dict[str, Any]] = []
    checked = 0
    last_good_seq = 0
    last_good_hash = canonical.GENESIS_HASH.hex()
    intact_prefix_seq = int(start_seq) - 1
    intact_prefix_hash = (prev_hash or canonical.GENESIS_HASH).hex()
    prefix_broken = False
    if prev_hash is not None:
        expected_prev: bytes | None = prev_hash
    else:
        expected_prev = canonical.GENESIS_HASH if int(start_seq) <= 1 else None
    expected_seq = int(start_seq)

    for r in receipts:
        checked += 1
        seq = int(r["seq"])
        stored_hash = bytes(r["receipt_hash"])
        payload_text = str(r["payload"])
        signed_bytes = canonical.DOMAIN_PREFIX + payload_text.encode("utf-8")
        parsed = _parse_payload(payload_text)
        # The SIGNED payload's "type" is the claim; the row column is unsigned
        # and only consulted when the payload does not parse (that row is
        # already named by non_canonical_payload). Preferring the column would
        # let "delete the device signature, relabel the row" pass clean.
        if parsed is not None:
            record_type = str(parsed.get("type") or "")
        else:
            record_type = str(r.get("record_type") or "")
        row_ok = True

        def flag(defect: str, detail: str, *, seq: int = seq) -> None:
            defects.append({"seq": seq, "defect": defect, "detail": detail})

        embedded_prev: bytes | None = None
        if parsed is not None:
            try:
                embedded_prev = bytes.fromhex(str(parsed.get("prev_receipt_hash", "")))
            except ValueError:
                embedded_prev = None

        if seq != expected_seq:
            row_ok = False
            flag(
                "broken_link",
                f"expected seq {expected_seq}, found {seq}; "
                f"{seq - expected_seq} receipt(s) missing",
            )
            # Re-anchor on this row's own prev so the gap is reported ONCE (estate rule):
            # without this a single deletion would look like wholesale tampering.
            expected_prev = embedded_prev

        if expected_prev is not None and embedded_prev != expected_prev:
            row_ok = False
            flag(
                "broken_link",
                "payload's prev_receipt_hash does not match the previous receipt's hash",
            )

        if hashlib.sha256(signed_bytes).digest() != stored_hash:
            row_ok = False
            flag("payload_mismatch", "stored receipt_hash is not the hash of the stored payload")
        else:
            # Origin signature — ONLY the payload's own device_key_id is the claim
            # (it is signed); the row column never is, or stripping the signature
            # and relabelling the unsigned column would pass clean.
            payload_device_key = (parsed or {}).get("device_key_id")
            claimed_tenant = (parsed or {}).get("tenant_id")
            device_sig = r.get("device_signature")
            if payload_device_key is not None:
                if device_sig is None:
                    row_ok = False
                    flag(
                        "bad_signature",
                        "payload names a device_key_id but the row carries no device signature",
                    )
                else:
                    entry = key_ring.get(str(payload_device_key))
                    if entry is None:
                        row_ok = False
                        flag(
                            "unknown_key",
                            f"device key_id {payload_device_key} is not in the published "
                            "key set; an unpublished retired key looks exactly like this",
                        )
                    elif entry.role != keys.ROLE_DEVICE_ORIGIN:
                        row_ok = False
                        flag(
                            "unknown_key",
                            f"key_id {payload_device_key} is not published as a device "
                            "origin key (key-class split, 05 §4.5) — a server key "
                            "answering an origin claim is history minted server-side",
                        )
                    elif entry.tenant_id is not None and entry.tenant_id != claimed_tenant:
                        row_ok = False
                        flag(
                            "unknown_key",
                            f"device key_id {payload_device_key} is not published for "
                            "the payload's tenant",
                        )
                    elif not keys.verify(entry.public_key, bytes(device_sig), signed_bytes):
                        row_ok = False
                        flag(
                            "bad_signature",
                            "payload is intact but the device origin signature does not "
                            "verify under the key it names",
                        )
            elif record_type in DEVICE_ORIGIN_TYPES:
                row_ok = False
                flag(
                    "bad_signature",
                    f"record_type {record_type} originates on a device but the payload "
                    "signs no device_key_id (ck_m1_receipts_origin)",
                )

            # Countersignature — server always signs (m1_002: server_signature NOT
            # NULL), and only a SERVER CHAIN key may answer for Omium.
            server_sig = r.get("server_signature")
            if server_sig is None:
                row_ok = False
                flag("bad_countersignature", "row carries no server countersignature")
            else:
                entry = key_ring.get(str(r.get("server_key_id")))
                if entry is None:
                    row_ok = False
                    flag(
                        "unknown_key",
                        f"server key_id {r.get('server_key_id')} is not in the published key set",
                    )
                elif entry.role != keys.ROLE_SERVER_CHAIN:
                    row_ok = False
                    flag(
                        "unknown_key",
                        f"key_id {r.get('server_key_id')} is not published as a server "
                        "chain key (key-class split, 05 §4.5)",
                    )
                elif not keys.verify(entry.public_key, bytes(server_sig), signed_bytes):
                    row_ok = False
                    flag(
                        "bad_countersignature",
                        "payload is intact but the server countersignature does not "
                        "verify under the key it names",
                    )

        recanonicalised: bytes | None = None
        if parsed is not None:
            try:
                recanonicalised = canonical.canonical_bytes(parsed)
            except ValueError:
                recanonicalised = None
        if recanonicalised != signed_bytes:
            row_ok = False
            flag(
                "non_canonical_payload",
                "the stored payload is not the canonical serialisation of itself; an "
                "auditor who re-serialises before hashing would reach a different "
                "verdict on this row than one who does not",
            )

        # Checkpoint extension: when the caller supplies the sealed leaves, the signed
        # merkle_root must be their root — a signature over the wrong root is a valid
        # signature over a false claim, which only this check catches.
        leaves = r.get("leaves")
        if record_type == "checkpoint" and leaves is not None and parsed is not None:
            claimed = str(parsed.get("merkle_root", ""))
            if not (leaves and checkpoint.merkle_root([bytes(x) for x in leaves]).hex() == claimed):
                row_ok = False
                flag(
                    "merkle_mismatch",
                    "payload's merkle_root is not the root recomputed from the leaves",
                )

        if row_ok:
            last_good_seq = seq
            last_good_hash = stored_hash.hex()
            if not prefix_broken:
                intact_prefix_seq = seq
                intact_prefix_hash = stored_hash.hex()
        else:
            prefix_broken = True

        expected_prev = stored_hash
        expected_seq = seq + 1

    return {
        "checked": checked,
        "start_seq": int(start_seq),
        # Zero rows walked is a vacuous walk, not a verified history — an empty
        # export must never share a verdict with an intact chain (defects stays
        # empty: there is no chain to have a defect IN).
        "valid": checked > 0 and not defects,
        "defects": defects,
        "last_good_seq": last_good_seq,
        "last_good_hash": last_good_hash,
        "intact_prefix_seq": intact_prefix_seq,
        "intact_prefix_hash": intact_prefix_hash,
    }
