//! Receipt signing keys: the Signer seam, the derived key_id, verification,
//! and the KeyRing that answers "is this signature from a then-valid key".
//!
//! VENDORED from recovery-orchestrator's `app/receipts/keys.py` (copied
//! 2026-08-29). The estate's settings-coupled surface (get_signer /
//! published_keys) is deliberately NOT carried — in Mark 1 the published key
//! set is the `m1_server_signing_keys` / `m1_device_keys` tables and the
//! public key manifest (08 §3.5), loaded into a [`KeyRing`]. Kept verbatim:
//!
//!   * the `Signer` seam a KMS-backed signer implements without touching
//!     chain code (05 §4.5 splits the key classes; the seam makes the split
//!     cheap);
//!   * `key_id = "ed25519:" + first 16 hex of SHA-256(public key)` — DERIVED,
//!     never configured, so a rotated key cannot keep a stale label and two
//!     keys cannot collide;
//!   * `verify` returning bool: every caller's next move is the same either
//!     way — record which link failed and keep walking (estate chain.py).
//!
//! Rotation follows ro_012's rule: retired keys stop SIGNING and are never
//! unpublished — dropping one is the operational equivalent of deleting the
//! receipts it signed. The KeyRing therefore never removes entries; validity
//! windows bound when a key may have SIGNED, not when it may verify.

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::hex;

pub const KEY_ID_PREFIX: &str = "ed25519:";
pub const PUBLIC_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;

/// The keys.py `Signer` Protocol, in Rust (04 §7.2) — the seam a KMS-backed
/// signer implements without touching the chain code.
pub trait Signer {
    fn sign(&self, message: &[u8]) -> [u8; 64];
    /// `"ed25519:" + sha256(pub)[:16]` — derived, never configured.
    fn key_id(&self) -> String;
}

/// In-process Ed25519 signer built from a 32-byte seed. Test keys and edge
/// tooling; production chain keys are KMS-resident (05 §4.5) behind the same
/// trait.
pub struct Ed25519Signer {
    key: SigningKey,
    key_id: String,
}

impl Ed25519Signer {
    /// The seed is zeroized here after key construction; the SigningKey
    /// zeroizes itself on drop (workspace ed25519-dalek `zeroize` feature).
    pub fn from_seed(mut seed: [u8; 32]) -> Self {
        let key = SigningKey::from_bytes(&seed);
        seed.zeroize();
        let key_id = derive_key_id(&key.verifying_key().to_bytes());
        Self { key, key_id }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }
}

impl Signer for Ed25519Signer {
    fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.key.sign(message).to_bytes()
    }

    fn key_id(&self) -> String {
        self.key_id.clone()
    }
}

/// `"ed25519:" + first 16 hex chars of SHA-256(public key)` — derived, so it
/// cannot lie (m1_002's key_id column comment).
pub fn derive_key_id(public_raw: &[u8; 32]) -> String {
    let digest = Sha256::digest(public_raw);
    format!("{KEY_ID_PREFIX}{}", hex::encode(&digest[..8]))
}

/// Signature check. Bool, not an error — the chain walk records which link
/// failed and keeps walking (estate keys.py's posture).
pub fn verify(public_raw: &[u8; 32], signature: &[u8; 64], message: &[u8]) -> bool {
    match VerifyingKey::from_bytes(public_raw) {
        // RFC 8032 verification (dalek `verify`), matching what the Python
        // (cryptography/OpenSSL) and Go (crypto/ed25519) legs run — the
        // stricter dalek variant would let the three languages disagree on a
        // malleable edge case, which is the drift the vectors exist to forbid.
        Ok(vk) => vk
            .verify(message, &Signature::from_bytes(signature))
            .is_ok(),
        Err(_) => false,
    }
}

/// A rotation cross-signature as published in the key manifest (08 §3.5).
///
/// ponytail: carried opaque, not yet verified — the byte contract for what
/// the predecessor key signs is ADR-0004's (Accepted 2026-09-16; ceremony at deployment) and no vector
/// fixes it; the verification arm lands with the signed ADR.
#[derive(Debug, Clone)]
pub struct CrossSig {
    pub by_key_id: String,
    pub signature: [u8; 64],
}

/// The key CLASSES 05 §4.5 splits, as far as the receipt spine sees them: a
/// device origin key and the server chain key are DISJOINT sets, and a lookup
/// only succeeds inside the named role's set. Without this the server key
/// alone could satisfy both legs of a dual-signed row — the "mint history"
/// direction m1_002's dual-signing exists to close.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRole {
    DeviceOrigin,
    ServerChain,
}

impl KeyRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DeviceOrigin => "device origin",
            Self::ServerChain => "server chain",
        }
    }
}

/// One published key: pubkey + role + validity window + cross-signature
/// (04 §7.2, 05 §4.5).
#[derive(Debug, Clone)]
pub struct KeyEntry {
    pub public_key: [u8; 32],
    pub role: KeyRole,
    /// Device keys are tenant-scoped (m1_001's m1_device_keys); `Some` binds
    /// the key to one tenant's chain. The server chain key is global (`None`).
    pub tenant_id: Option<String>,
    /// RFC 3339 UTC instants bounding when this key may have SIGNED.
    /// `None` = unbounded on that side (the vectors' test keys).
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub cross_sig: Option<CrossSig>,
}

impl KeyEntry {
    pub fn new(public_key: [u8; 32], role: KeyRole) -> Self {
        Self {
            public_key,
            role,
            tenant_id: None,
            not_before: None,
            not_after: None,
            cross_sig: None,
        }
    }
}

/// What one signature check found — the chain walk maps these onto the
/// vectors' defect vocabulary (unknown/wrong-role/wrong-tenant/outside-window
/// → `unknown_key`: the key is not in the published set FOR THAT USE; a
/// failed check → `bad_signature`/`bad_countersignature` by leg).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyCheck {
    Ok,
    /// The key_id is not in the published set.
    UnknownKey,
    /// Published, but under a different role — a server key answering a
    /// device-origin claim (or vice versa) is the forgery shape the role
    /// split exists to refuse, never a lookup convenience.
    WrongRole,
    /// A tenant-scoped device key answering another tenant's chain.
    WrongTenant,
    /// The key exists but was not valid at the claimed signing instant —
    /// rotation's failure shape, distinct from "never published".
    OutsideValidity,
    BadSignature,
}

/// key_id → published key. One implementation of "is this signature from a
/// then-valid key", shared by mark1d (via the Go mirror), the proxy, and
/// tools/verifier so "verify offline" and "sign at origin" cannot drift
/// (04 §7.2).
#[derive(Debug, Clone, Default)]
pub struct KeyRing {
    entries: BTreeMap<String, KeyEntry>,
}

impl KeyRing {
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts under the DERIVED key_id and returns it — a ring cannot hold a
    /// key under a label that is not its own.
    pub fn insert(&mut self, entry: KeyEntry) -> String {
        let key_id = derive_key_id(&entry.public_key);
        self.entries.insert(key_id.clone(), entry);
        key_id
    }

    pub fn get(&self, key_id: &str) -> Option<&KeyEntry> {
        self.entries.get(key_id)
    }

    pub fn contains(&self, key_id: &str) -> bool {
        self.entries.contains_key(key_id)
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// The rotation-aware signature check: key published UNDER `role` (05
    /// §4.5's key-class split — the caller names which set it is consulting),
    /// scoped to `claimed_tenant` when the key is tenant-bound, valid at `at`
    /// (the receipt's signed `issued_at`), and the signature verifies over
    /// `message`.
    pub fn check(
        &self,
        key_id: &str,
        role: KeyRole,
        claimed_tenant: Option<&str>,
        message: &[u8],
        signature: &[u8; 64],
        at: Option<&str>,
    ) -> KeyCheck {
        let Some(entry) = self.entries.get(key_id) else {
            return KeyCheck::UnknownKey;
        };
        if entry.role != role {
            return KeyCheck::WrongRole;
        }
        if let Some(bound) = entry.tenant_id.as_deref() {
            // A tenant-scoped key with NO tenant claim in the payload fails
            // too: the binding cannot be waived by omitting the claim.
            if claimed_tenant != Some(bound) {
                return KeyCheck::WrongTenant;
            }
        }
        if let Some(at) = at {
            // ponytail: RFC 3339 UTC strings compare correctly as bytes only
            // at uniform precision (m1_002 stores and the vectors emit
            // second-precision Z). Parse into real instants if ADR-0004's
            // manifest ever mixes precisions.
            if entry.not_before.as_deref().is_some_and(|nb| at < nb)
                || entry.not_after.as_deref().is_some_and(|na| at > na)
            {
                return KeyCheck::OutsideValidity;
            }
        }
        if verify(&entry.public_key, signature, message) {
            KeyCheck::Ok
        } else {
            KeyCheck::BadSignature
        }
    }
}
