//! mark1-receipt — receipt-chain primitives (04 §7.2), the Rust reference
//! implementation of the receipt byte contract.
//!
//! VENDORED discipline: canonical bytes, key_id derivation and the chain-walk
//! defect semantics come from
//! `Omium-platform/core-services/recovery-orchestrator/app/receipts/`
//! (canonical.py / keys.py / chain.py, copied 2026-08-29) with the mark1
//! domain prefix and the checkpoint / dual-signature / KeyRing extensions
//! (07 "The receipt chain", migrations/m1_002_receipt_chain.sql).
//! `conformance/vectors/receipt/manifest.json` locks this crate,
//! `python/shared/mark1_receipts` and `go/mark1d/internal/identity` together
//! bit-identically; the manifest is the referee, never this crate.

pub mod canonical;
pub mod chain;
pub mod checkpoint;
pub mod hex;
pub mod keys;

pub use canonical::{
    canonical_bytes, canonical_json, hash_signing_input, receipt_hash, signing_input_of,
    NonIntegerNumberError, DOMAIN_PREFIX, GENESIS_HASH, PAYLOAD_VERSION,
};
pub use chain::{verify_chain, ChainReport, Defect, DefectKind, ReceiptRow, DEVICE_ORIGIN_TYPES};
pub use checkpoint::{
    dual_sign, inclusion_path, leaf_hash, merkle_root, node_hash, verify_inclusion,
    verify_merkle_root, CheckpointPayload, MerkleError, HASH_LEN, LEAF_LEN,
};
pub use keys::{
    derive_key_id, verify, CrossSig, Ed25519Signer, KeyCheck, KeyEntry, KeyRing, KeyRole, Signer,
};
