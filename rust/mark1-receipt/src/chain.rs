//! Walking a tenant's receipt chain and reporting every defect found, never
//! just the first.
//!
//! VENDORED semantics from recovery-orchestrator's `app/receipts/chain.py`
//! `verify_chain` (copied 2026-08-29): the estate's five defect kinds,
//! verbatim, plus the three the dual-signature/checkpoint extensions require
//! (vectors README "Defect vocabulary"). The hash and both signatures are
//! checked against the STORED BYTES, not a re-serialisation of the parsed
//! payload — `payload` is the exact input that was signed (m1_002), so
//! verifying the bytes as they sit is what an outside auditor does with an
//! export, and this walk cannot pass a row an auditor would fail.
//!
//! TWO "good" numbers, because there are two questions (estate chain.py):
//! `intact_prefix_seq` is the CUSTOMER's number — everything up to it is
//! evidence and nothing past it is; `last_good_seq` is the OPERATOR's number,
//! the position a discontinuity anchors to. Equal on a healthy chain, which
//! is why shipping only one would quietly answer the customer's question with
//! the operator's number.

use std::fmt;

use constant_time_eq::constant_time_eq_32;
use serde_json::Value;

use crate::canonical::{self, GENESIS_HASH};
use crate::hex;
use crate::keys::{KeyCheck, KeyRing, KeyRole};

/// The three classes that ORIGINATE on the device and therefore carry the
/// device signature (m1_002 `ck_m1_receipts_origin` — equivalence, not
/// implication, so a server act cannot dress up as device-attested).
pub const DEVICE_ORIGIN_TYPES: [&str; 3] =
    ["checkpoint", "coverage_transition", "guard_contamination"];

/// The eight-kind defect vocabulary, frozen by
/// conformance/vectors/receipt/README.md — the estate's five plus three.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefectKind {
    BrokenLink,
    PayloadMismatch,
    UnknownKey,
    BadSignature,
    NonCanonicalPayload,
    BadCountersignature,
    MerkleMismatch,
    InclusionPathInvalid,
}

impl DefectKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::BrokenLink => "broken_link",
            Self::PayloadMismatch => "payload_mismatch",
            Self::UnknownKey => "unknown_key",
            Self::BadSignature => "bad_signature",
            Self::NonCanonicalPayload => "non_canonical_payload",
            Self::BadCountersignature => "bad_countersignature",
            Self::MerkleMismatch => "merkle_mismatch",
            Self::InclusionPathInvalid => "inclusion_path_invalid",
        }
    }
}

impl fmt::Display for DefectKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone)]
pub struct Defect {
    pub seq: u64,
    pub kind: DefectKind,
    pub detail: String,
}

/// One exported chain row — m1_002's chain columns as they leave the export
/// endpoint (08 §3.4: payload is the exact canonical text that was signed).
#[derive(Debug, Clone)]
pub struct ReceiptRow {
    pub seq: u64,
    /// The exact signed bytes; hashed and signature-checked AS STORED.
    pub payload: String,
    pub receipt_hash: [u8; 32],
    /// Row-column lookup hints; the SIGNED device claim lives in the payload.
    pub device_key_id: Option<String>,
    pub device_signature: Option<[u8; 64]>,
    pub server_key_id: String,
    pub server_signature: [u8; 64],
}

#[derive(Debug, Clone)]
pub struct ChainReport {
    pub checked: usize,
    pub start_seq: u64,
    pub valid: bool,
    pub defects: Vec<Defect>,
    pub last_good_seq: u64,
    pub last_good_hash: [u8; 32],
    pub intact_prefix_seq: u64,
    pub intact_prefix_hash: [u8; 32],
}

/// Walk `rows` (ordered by seq) and report every defect. Never fails early:
/// the SHAPE of the damage — one bad link, or every link after a date — is
/// the diagnostic (estate chain.py).
///
/// `anchor_prev` is the expected predecessor hash of the first row when the
/// walk starts mid-chain (the vectors' `verify_against_prev_hash_hex`);
/// `None` means genesis when `start_seq <= 1` and "no link check on the first
/// row" otherwise — the estate's `expected_prev` seeding, kept.
pub fn verify_chain(
    ring: &KeyRing,
    rows: &[ReceiptRow],
    start_seq: u64,
    anchor_prev: Option<[u8; 32]>,
) -> ChainReport {
    let mut defects: Vec<Defect> = Vec::new();
    let mut checked = 0usize;
    let mut last_good_seq = 0u64;
    let mut last_good_hash = GENESIS_HASH;
    let mut intact_prefix_seq = start_seq.saturating_sub(1);
    // A mid-chain walk that gets nowhere is intact up to its ANCHOR, not up
    // to genesis — reporting 000…0 there would hand the caller a hash the
    // chain never had at that position (Python chain.py's seeding, kept).
    let mut intact_prefix_hash = anchor_prev.unwrap_or(GENESIS_HASH);
    let mut prefix_broken = false;
    let mut expected_prev: Option<[u8; 32]> = anchor_prev.or(if start_seq <= 1 {
        Some(GENESIS_HASH)
    } else {
        None
    });
    let mut expected_seq = start_seq;

    for row in rows {
        checked += 1;
        let mut row_ok = true;
        let fail = |defects: &mut Vec<Defect>, kind: DefectKind, detail: String| {
            defects.push(Defect {
                seq: row.seq,
                kind,
                detail,
            });
        };

        // The payload parses or it does not; every check below that needs the
        // parsed form degrades gracefully because non_canonical_payload will
        // name the row regardless.
        let parsed: Option<Value> = serde_json::from_str(&row.payload).ok();
        let embedded_prev: Option<[u8; 32]> = parsed
            .as_ref()
            .and_then(|p| p.get("prev_receipt_hash"))
            .and_then(Value::as_str)
            .and_then(hex::decode_array);

        // ---- broken_link: seq continuity, then the signed prev link -------
        if row.seq != expected_seq {
            row_ok = false;
            fail(
                &mut defects,
                DefectKind::BrokenLink,
                format!(
                    "expected seq {expected_seq}, found {}; receipt(s) missing",
                    row.seq
                ),
            );
            // Re-anchor on this row's own prev so the gap is reported ONCE —
            // otherwise a single deletion looks like wholesale tampering
            // (estate chain.py).
            expected_prev = embedded_prev;
        }
        if let Some(expected) = expected_prev {
            // The link travels INSIDE the signed payload (README: the 04 §7.2
            // two-arg receipt_hash form is satisfied by asserting the
            // embedded prev equals the chain's expectation, then hashing the
            // signing input alone).
            match embedded_prev {
                Some(prev) if constant_time_eq_32(&prev, &expected) => {}
                Some(_) => {
                    row_ok = false;
                    fail(
                        &mut defects,
                        DefectKind::BrokenLink,
                        "prev_receipt_hash does not match the previous receipt's hash".into(),
                    );
                }
                // Unparseable payloads are already named by
                // non_canonical_payload; a parsed payload WITHOUT a usable
                // link is a broken link — position was never signed.
                None if parsed.is_some() => {
                    row_ok = false;
                    fail(
                        &mut defects,
                        DefectKind::BrokenLink,
                        "payload carries no decodable prev_receipt_hash".into(),
                    );
                }
                None => {}
            }
        }

        // ---- payload_mismatch, then the two signature legs ----------------
        let signing_input = canonical::signing_input_of(&row.payload);
        if !constant_time_eq_32(
            &canonical::hash_signing_input(&signing_input),
            &row.receipt_hash,
        ) {
            row_ok = false;
            fail(
                &mut defects,
                DefectKind::PayloadMismatch,
                "stored receipt_hash is not the hash of the stored payload".into(),
            );
        } else {
            // Signatures are only meaningful over bytes the hash vouches for
            // (estate gating). `issued_at` is the signed claim of WHEN, which
            // is what the KeyRing's rotation windows bound.
            let issued_at = parsed
                .as_ref()
                .and_then(|p| p.get("issued_at"))
                .and_then(Value::as_str);

            // Device leg: the SIGNED key id (payload) is the origin claim.
            let record_type = parsed
                .as_ref()
                .and_then(|p| p.get("type"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            let payload_device_key = parsed
                .as_ref()
                .and_then(|p| p.get("device_key_id"))
                .and_then(Value::as_str);
            // The signed tenant claim scopes tenant-bound device keys — a
            // device key must not be fungible across tenants (m1_001 scopes
            // m1_device_keys per tenant).
            let claimed_tenant = parsed
                .as_ref()
                .and_then(|p| p.get("tenant_id"))
                .and_then(Value::as_str);
            if let Some(key_id) = payload_device_key {
                match row.device_signature.as_ref() {
                    None => {
                        row_ok = false;
                        fail(
                            &mut defects,
                            DefectKind::BadSignature,
                            "payload names a device_key_id but the row carries no device \
                             signature"
                                .into(),
                        );
                    }
                    Some(sig) => match ring.check(
                        key_id,
                        KeyRole::DeviceOrigin,
                        claimed_tenant,
                        &signing_input,
                        sig,
                        issued_at,
                    ) {
                        KeyCheck::Ok => {}
                        KeyCheck::UnknownKey => {
                            row_ok = false;
                            fail(
                                &mut defects,
                                DefectKind::UnknownKey,
                                format!("device key_id {key_id} is not in the published key set"),
                            );
                        }
                        KeyCheck::WrongRole => {
                            row_ok = false;
                            fail(
                                &mut defects,
                                DefectKind::UnknownKey,
                                format!(
                                    "key_id {key_id} is not published as a device origin key \
                                     (key-class split, 05 §4.5) — a server key answering an \
                                     origin claim is history minted server-side"
                                ),
                            );
                        }
                        KeyCheck::WrongTenant => {
                            row_ok = false;
                            fail(
                                &mut defects,
                                DefectKind::UnknownKey,
                                format!(
                                    "device key_id {key_id} is not published for the payload's \
                                     tenant"
                                ),
                            );
                        }
                        KeyCheck::OutsideValidity => {
                            row_ok = false;
                            fail(
                                &mut defects,
                                DefectKind::UnknownKey,
                                format!(
                                    "device key_id {key_id} was not valid at the signed \
                                     issued_at (rotation window)"
                                ),
                            );
                        }
                        KeyCheck::BadSignature => {
                            row_ok = false;
                            fail(
                                &mut defects,
                                DefectKind::BadSignature,
                                "device origin signature fails over the signing input".into(),
                            );
                        }
                    },
                }
            } else if DEVICE_ORIGIN_TYPES.contains(&record_type) {
                row_ok = false;
                fail(
                    &mut defects,
                    DefectKind::BadSignature,
                    format!(
                        "record_type {record_type} is device-originated but the payload \
                             signs no device_key_id"
                    ),
                );
            }

            // Server leg: server_key_id is a lookup hint, not a trust input —
            // the countersignature only verifies under the key that made it
            // (vectors README "Signatures"), and only inside the server chain
            // key set (a device key must not countersign for Omium).
            match ring.check(
                &row.server_key_id,
                KeyRole::ServerChain,
                claimed_tenant,
                &signing_input,
                &row.server_signature,
                issued_at,
            ) {
                KeyCheck::Ok => {}
                KeyCheck::UnknownKey => {
                    row_ok = false;
                    fail(
                        &mut defects,
                        DefectKind::UnknownKey,
                        format!(
                            "server key_id {} is not in the published key set",
                            row.server_key_id
                        ),
                    );
                }
                KeyCheck::WrongRole | KeyCheck::WrongTenant => {
                    row_ok = false;
                    fail(
                        &mut defects,
                        DefectKind::UnknownKey,
                        format!(
                            "key_id {} is not published as a server chain key \
                             (key-class split, 05 §4.5)",
                            row.server_key_id
                        ),
                    );
                }
                KeyCheck::OutsideValidity => {
                    row_ok = false;
                    fail(
                        &mut defects,
                        DefectKind::UnknownKey,
                        format!(
                            "server key_id {} was not valid at the signed issued_at \
                             (rotation window)",
                            row.server_key_id
                        ),
                    );
                }
                KeyCheck::BadSignature => {
                    row_ok = false;
                    fail(
                        &mut defects,
                        DefectKind::BadCountersignature,
                        "server countersignature fails over the signing input".into(),
                    );
                }
            }
        }

        // ---- non_canonical_payload -----------------------------------------
        // Independent of the hash check: an auditor who re-serialises before
        // hashing and one who hashes the bytes as given must not reach
        // different verdicts about the same row (estate chain.py).
        let recanonicalised = parsed
            .as_ref()
            .and_then(|p| canonical::canonical_json(p).ok());
        if recanonicalised.as_deref() != Some(row.payload.as_str()) {
            row_ok = false;
            fail(
                &mut defects,
                DefectKind::NonCanonicalPayload,
                "the stored payload is not the canonical serialisation of itself".into(),
            );
        }

        if row_ok {
            last_good_seq = row.seq;
            last_good_hash = row.receipt_hash;
            if !prefix_broken {
                intact_prefix_seq = row.seq;
                intact_prefix_hash = row.receipt_hash;
            }
        } else {
            prefix_broken = true;
        }

        expected_prev = Some(row.receipt_hash);
        expected_seq = row.seq + 1;
    }

    ChainReport {
        checked,
        start_seq,
        // Zero rows walked is a vacuous walk, not a verified history — an
        // empty export must never share a verdict with an intact chain
        // (defects stays empty: there is no chain to have a defect IN).
        valid: checked > 0 && defects.is_empty(),
        defects,
        last_good_seq,
        last_good_hash,
        intact_prefix_seq,
        intact_prefix_hash,
    }
}
