"""Receipt signing keys: the Signer seam, the derived key_id, and verification.

VENDORED from Omium-platform/core-services/recovery-orchestrator/app/receipts/keys.py
(copied 2026-08-29, per docs/13 §4.2). The estate's settings-coupled surface
(get_signer / require_signer_if_sweeping / published_keys) is deliberately NOT carried:
in Mark 1 the ONE writer holding a private key is controld (Go; m1_002 §5's grants), and
the published key set is the m1_server_signing_keys / m1_device_keys tables, not an env
var. What Python needs — and what this module keeps verbatim — is:

  * the ``Signer`` protocol: the seam a KMS-backed signer implements without touching
    chain code (05 §4.5 splits the key classes; the seam is what makes the split cheap);
  * ``key_id = "ed25519:" + first 16 hex of SHA-256(public key)`` — DERIVED, never
    configured, so a rotated key cannot keep a stale label and two keys cannot collide;
  * ``verify`` returning bool, because every caller's next move is the same either way:
    record which link failed and keep walking (estate chain.py's posture).

Rotation follows ro_012's rule, enforced by m1_002's tables rather than here: retired
keys stop SIGNING and are never unpublished — dropping one is the operational
equivalent of deleting the receipts it signed.

ponytail: ed25519 only. ADR-0004 (Proposed) adds "p256:"-prefixed KMS countersign keys;
the prefix scheme already absorbs that — add a P-256 arm to ``verify`` when it signs.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass
from typing import Protocol

_KEY_ID_PREFIX = "ed25519:"
_SEED_LEN = 32
_PUBLIC_LEN = 32
_SIGNATURE_LEN = 64

# The key CLASSES 05 §4.5 splits, as far as the receipt spine sees them:
# device origin keys and the server chain key are DISJOINT sets, and a lookup
# only succeeds inside the named role's set. Without the split, the server key
# alone satisfies both legs of a dual-signed row — the "mint history"
# direction m1_002's dual-signing exists to close.
ROLE_DEVICE_ORIGIN = "device_origin"
ROLE_SERVER_CHAIN = "server_chain"


@dataclass(frozen=True)
class PublishedKey:
    """One published key: raw public bytes + role + optional tenant binding.

    ``tenant_id`` is set for device keys (m1_001 scopes m1_device_keys per
    tenant) so a device key cannot answer another tenant's chain; the server
    chain key is global (m1_002: "the key signs for Omium, not for a tenant").
    """

    public_key: bytes
    role: str
    tenant_id: str | None = None


class ReceiptKeyError(RuntimeError):
    """A signing key is missing or malformed. Never caught to continue unsigned."""


class Signer(Protocol):
    """The seam a KMS-backed signer would implement without touching the chain code."""

    @property
    def key_id(self) -> str: ...

    def sign(self, message: bytes) -> bytes: ...


class Ed25519Signer:
    """In-process Ed25519 signer built from a 32-byte seed. Test keys and edge tooling;
    production chain keys live where m1_002's grants put them, not in this package."""

    def __init__(self, seed: bytes):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        if len(seed) != _SEED_LEN:
            raise ReceiptKeyError(f"ed25519 seed is {len(seed)} bytes, expected {_SEED_LEN}")
        self._private = Ed25519PrivateKey.from_private_bytes(seed)
        self._public_raw = self._private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self._key_id = derive_key_id(self._public_raw)

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def public_raw(self) -> bytes:
        return self._public_raw

    @property
    def public_key_b64(self) -> str:
        return base64.b64encode(self._public_raw).decode("ascii")

    def sign(self, message: bytes) -> bytes:
        sig = self._private.sign(message)
        if len(sig) != _SIGNATURE_LEN:
            raise ReceiptKeyError(
                f"ed25519 signature was {len(sig)} bytes, expected {_SIGNATURE_LEN}"
            )
        return sig


def derive_key_id(public_raw: bytes) -> str:
    return _KEY_ID_PREFIX + hashlib.sha256(public_raw).hexdigest()[:16]


def decode_b64(value: str, what: str, expect_len: int) -> bytes:
    try:
        raw = base64.b64decode(value.strip(), validate=True)
    except (binascii.Error, ValueError) as e:
        raise ReceiptKeyError(f"{what} is not valid base64") from e
    if len(raw) != expect_len:
        raise ReceiptKeyError(f"{what} decoded to {len(raw)} bytes, expected {expect_len}")
    return raw


def verify(public_raw: bytes, signature: bytes, message: bytes) -> bool:
    """Signature check. Bool, not an exception — the chain walk records and continues."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        Ed25519PublicKey.from_public_bytes(public_raw).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False


def generate_seed_b64() -> str:
    """Mint a new signing key. Operator tooling only — never called at runtime."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    seed = key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return base64.b64encode(seed).decode("ascii")
