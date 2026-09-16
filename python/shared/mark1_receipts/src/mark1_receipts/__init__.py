"""mark1_receipts — the vendored receipt byte-contract, shared by both Python services.

Vendored from recovery-orchestrator's app/receipts/ (docs/13 §4.2) with the mark1
domain prefix and the checkpoint/dual-signature extensions (07 "The receipt chain").
conformance/vectors/receipt/ locks this package, rust/mark1-receipt and
go/mark1d/internal/identity together bit-identically.
"""

from mark1_receipts.canonical import (
    DOMAIN_PREFIX,
    GENESIS_HASH,
    PAYLOAD_VERSION,
    NonCanonicalNumberError,
    canonical_bytes,
    canonical_json,
    receipt_hash,
)
from mark1_receipts.chain import DEVICE_ORIGIN_TYPES, verify_chain
from mark1_receipts.checkpoint import (
    build_checkpoint,
    inclusion_path,
    leaf_hash,
    merkle_root,
    node_hash,
    verify_inclusion,
    verify_merkle_root,
)
from mark1_receipts.client import ReceiptAppendError, ReceiptRef, append_server_record
from mark1_receipts.keys import (
    ROLE_DEVICE_ORIGIN,
    ROLE_SERVER_CHAIN,
    Ed25519Signer,
    PublishedKey,
    ReceiptKeyError,
    Signer,
    derive_key_id,
    generate_seed_b64,
    verify,
)

__all__ = [
    "DEVICE_ORIGIN_TYPES",
    "DOMAIN_PREFIX",
    "GENESIS_HASH",
    "PAYLOAD_VERSION",
    "ROLE_DEVICE_ORIGIN",
    "ROLE_SERVER_CHAIN",
    "Ed25519Signer",
    "NonCanonicalNumberError",
    "PublishedKey",
    "ReceiptAppendError",
    "ReceiptKeyError",
    "ReceiptRef",
    "Signer",
    "append_server_record",
    "build_checkpoint",
    "canonical_bytes",
    "canonical_json",
    "derive_key_id",
    "generate_seed_b64",
    "inclusion_path",
    "leaf_hash",
    "merkle_root",
    "node_hash",
    "receipt_hash",
    "verify",
    "verify_chain",
    "verify_inclusion",
    "verify_merkle_root",
]
