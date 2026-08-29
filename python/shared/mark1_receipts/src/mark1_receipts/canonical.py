"""The exact bytes a Mark 1 receipt is signed over, and the hash derived from them.

VENDORED from Omium-platform/core-services/recovery-orchestrator/app/receipts/canonical.py
(copied 2026-08-29, per docs/13 §4.2's vendoring rule). The estate module is NORMATIVE
there and this one is normative here: every receipt this repo ever issues is verifiable
by an outside auditor only if these bytes are reproducible outside this process — in Go
(mark1d.identity), in Rust (mark1-receipt / tools/verifier), and in an auditor's own
script. conformance/vectors/receipt/manifest.json is the frozen referee.

The estate's rules, kept verbatim (docs/07 "The receipt chain"):

  * ``json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)``.
    One canonicalisation product-wide; ``ensure_ascii`` is load-bearing because \\uXXXX
    escapes are the one non-ASCII rendering every JSON implementation agrees on.
  * A domain-separation prefix with a trailing NUL — a signature minted for any other
    Omium scheme must never verify as a Mark 1 receipt. The prefix is the ONE deliberate
    change from the vendor source: ``mark1-label-v1\\x00`` (07, m1_002 header).
  * ``receipt_hash`` covers the SIGNING INPUT, prefix included: a verifier that has
    recomputed the hash has, by construction, recomputed the exact bytes it hands to the
    signature check.
  * ``prev_receipt_hash`` travels INSIDE the signed payload (hex). Re-parenting a receipt
    invalidates its signature; position is part of the claim.

One rule is new relative to the vendor source, added by the vectors' README ("Numbers:
integers only"): a payload containing a non-integer number is REFUSED. Cross-language
float rendering is not deterministic (repr vs strconv vs ryu), so a float in a payload
is a forgery generator — the refusal is the contract, not a convenience.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

DOMAIN_PREFIX = b"mark1-label-v1\x00"

PAYLOAD_VERSION = 1

GENESIS_HASH = b"\x00" * 32


class NonCanonicalNumberError(ValueError):
    """A payload carried a non-integer number. Refused, never rounded or rendered."""


def _reject_floats(value: Any) -> None:
    # bool is an int subtype and renders as true/false — only real floats are the hazard.
    if isinstance(value, float):
        raise NonCanonicalNumberError(
            f"payload contains a non-integer number ({value!r}); the receipt contract "
            "is integers-only (conformance/vectors/receipt/README.md)"
        )
    if isinstance(value, Mapping):
        for v in value.values():
            _reject_floats(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            _reject_floats(v)


def canonical_json(payload: Mapping[str, Any]) -> str:
    _reject_floats(payload)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def canonical_bytes(payload: Mapping[str, Any]) -> bytes:
    """The signing input: domain prefix || canonical JSON of the payload."""
    return DOMAIN_PREFIX + canonical_json(payload).encode("utf-8")


def receipt_hash(payload: Mapping[str, Any]) -> bytes:
    """SHA-256 over the same bytes that are signed — 32 bytes."""
    return hashlib.sha256(canonical_bytes(payload)).digest()
