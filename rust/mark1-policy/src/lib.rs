//! mark1-policy — PolicyBundle v1 verify + decode to typed eval structs
//! (04 §7.3), the Rust REFERENCE implementation; the Go decoder in `mark1d`
//! is validated against `conformance/vectors/bundle/` (07 §"PolicyBundle v1").
//!
//! Verification order (04 §7.3, 07 rule 5): canonical-form check →
//! section-split Ed25519 signatures → monotonic `seq` → transparency-log
//! inclusion proof → strict typed schema decode. Failure at ANY step rejects
//! the whole bundle — the caller keeps last-known-good (fail-static, F-27) —
//! and `Reject` carries the ACK code (M1E-3001/3002/3003/3005, 08 §9).
//!
//! BUNDLE ZERO (lead ruling D-P, RECONCILIATION): Phase 2 runs on a
//! statically-signed LOCAL bundle — `seq == 0`, channel `"local"` — through
//! THIS decoder and THIS verification order. The transparency-log inclusion
//! proof is waived at `seq == 0` only, and the waiver is the literal
//! comparison in [`verify_and_decode`], never a flag: no operator can widen
//! it under deadline pressure.
//!
//! One signing discipline product-wide (04 §7.2): key material, key_id
//! derivation and Ed25519 verification are `mark1-receipt`'s, reused — this
//! crate adds only the per-section key-class split (05 §4.5).

pub mod canon;
mod decode;
mod rotation;
mod types;

use std::time::Duration;

use ciborium::value::Value;
use mark1_receipt::{keys, KeyEntry, KeyRing};
use sha2::{Digest, Sha256};

pub use canon::{encode_canonical, CanonError, MAX_DEPTH};
pub use rotation::{
    apply_rotation, cross_sign_input, RotationEntry, RotationReject, CROSS_SIGN_DOMAIN,
};
pub use types::{
    AgentMap, AgentMaps, AnchorEnable, Bundle, CorrelationGroup, CortexChannel, CortexSection,
    CostBasis, CpvsRow, GatesSection, InjectionRule, KneeRow, KneeTable, Ladder, LearnedRanker,
    MemorySection, Posterior4, RankerStage, RouteSection, Rung, Section, Signal3, TlogHead,
    TlogInclusion, VerifierModel, VerifySection,
};

/// The closed `schema` value — anything else is a different contract
/// (forward compatibility is a new `policy_bundle.v2`, 07 rule 3).
pub const SCHEMA: &str = "policy_bundle.v1";

/// Genesis `prev_hash`: bundle zero chains from 32 zero bytes, exactly like
/// the server catalog's head default (m1_009) and the receipt chain genesis.
pub const GENESIS_PREV_HASH: [u8; 32] = [0u8; 32];

/// ponytail: no document names a bundle size ceiling, so the M1PL frame bound
/// (07 §5's 4 MiB) is borrowed — checked BEFORE any allocation so a hostile
/// length is a cheap rejection, not an OOM lottery. Raise alongside 07 if a
/// real bundle ever approaches it.
pub const MAX_BUNDLE_LEN: usize = 4 << 20;

/// Which leg of a section-signature check failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigReason {
    /// The key_id is not published for THIS section class — covers both a
    /// never-published key and a key published under another section's role
    /// (05 §4.5: a lookup only succeeds inside the named class's set; the
    /// receipt family reports role mismatch the same way).
    UnknownKey,
    /// The key exists but was not valid at the bundle's `issued_at`.
    OutsideValidity,
    BadSignature,
}

/// Why a bundle was rejected. `code()` is the ACK `reject_code` (08 §9);
/// `kind()` is the finer-grained conformance-vector vocabulary — a negative
/// vector that fails for the wrong reason is a failed vector.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum Reject {
    #[error("bundle exceeds MAX_BUNDLE_LEN ({len} bytes)")]
    TooLarge { len: usize },
    /// Malformed or non-canonical CBOR — a second byte representation of the
    /// same content would make section signatures encoder-dependent.
    #[error("non-canonical bundle encoding: {detail}")]
    NonCanonical { detail: String },
    /// A structural schema violation: missing/unknown key, wrong type, wrong
    /// size, out-of-bound numeric (07 rule 3's strict-map rule included).
    #[error("bundle schema violation at {path}: {detail}")]
    Schema { path: String, detail: String },
    #[error("section {} signature invalid: {reason:?}", section.name())]
    Signature { section: Section, reason: SigReason },
    #[error("seq {seq} <= last applied {last_applied_seq} (anti-rollback)")]
    SeqReplay { seq: u64, last_applied_seq: u64 },
    /// `prev_hash` fails the chain rule this function can prove: a seq-0
    /// bundle must chain from GENESIS_PREV_HASH. (A fork indicator — also a
    /// security event, 05 §4.6.)
    #[error("prev_hash does not chain from genesis at seq 0")]
    PrevHashMismatch,
    #[error("transparency-log inclusion proof missing or invalid: {detail}")]
    InclusionInvalid { detail: &'static str },
    /// A string failed its CDDL production — the structural command-string
    /// rejection (07 rule 1). A security event: the compiler bug is a P1.
    #[error("command-string production violation at {path}")]
    CommandString { path: String },
}

impl Reject {
    /// The ACK `reject_code` (08 §9's frozen table).
    pub fn code(&self) -> &'static str {
        match self {
            Reject::TooLarge { .. }
            | Reject::NonCanonical { .. }
            | Reject::Schema { .. }
            | Reject::Signature { .. }
            | Reject::PrevHashMismatch => "M1E-3001",
            Reject::SeqReplay { .. } => "M1E-3002",
            Reject::InclusionInvalid { .. } => "M1E-3003",
            Reject::CommandString { .. } => "M1E-3005",
        }
    }

    /// The conformance vectors' finer defect vocabulary.
    pub fn kind(&self) -> &'static str {
        match self {
            Reject::TooLarge { .. } => "too_large",
            Reject::NonCanonical { .. } => "non_canonical",
            Reject::Schema { .. } => "schema",
            Reject::Signature {
                reason: SigReason::UnknownKey,
                ..
            } => "unknown_key",
            Reject::Signature {
                reason: SigReason::OutsideValidity,
                ..
            } => "outside_validity",
            Reject::Signature {
                reason: SigReason::BadSignature,
                ..
            } => "bad_signature",
            Reject::SeqReplay { .. } => "seq_replay",
            Reject::PrevHashMismatch => "prev_hash_mismatch",
            Reject::InclusionInvalid { .. } => "inclusion_invalid",
            Reject::CommandString { .. } => "command_string",
        }
    }
}

/// The section-split key set (05 §4.5): one [`KeyRing`] per section class, so
/// a key can only ever answer for the class it was published under — a
/// compromise of the cortex-budget key cannot alter gate behavior.
///
/// 04 §7.3 sketches `keys: &KeyRing`; the receipt crate's `KeyRole` is
/// two-valued by its own doc ("as far as the receipt spine sees them"), so
/// the six bundle classes live here as six rings of the SAME KeyRing type —
/// ring membership IS the role, and the receipt discipline (derived key_id,
/// validity windows, RFC 8032 verify) is reused unchanged.
#[derive(Clone)]
pub struct SectionKeys {
    rings: [KeyRing; 6],
}

impl SectionKeys {
    pub fn new() -> Self {
        Self {
            rings: std::array::from_fn(|_| KeyRing::new()),
        }
    }

    /// Publishes `entry` for `section`; returns the DERIVED key_id.
    pub fn insert(&mut self, section: Section, entry: KeyEntry) -> String {
        self.rings[section.index()].insert(entry)
    }

    /// Publishes a bare public key (unbounded validity) for `section`.
    /// `KeyRole` is the receipt spine's two-class vocabulary; the bundle
    /// section CLASS is expressed by ring membership here, so the entry's
    /// role field is inert in this crate — stored as ServerChain, i.e.
    /// "server-published key material".
    pub fn insert_public(&mut self, section: Section, public_key: [u8; 32]) -> String {
        self.insert(
            section,
            KeyEntry::new(public_key, mark1_receipt::KeyRole::ServerChain),
        )
    }

    pub fn ring(&self, section: Section) -> &KeyRing {
        &self.rings[section.index()]
    }
}

impl Default for SectionKeys {
    fn default() -> Self {
        Self::new()
    }
}

/// D-Q's domain prefix: the bundle plane gets its OWN domain string, matching
/// the receipt plane's `mark1-label-v1\0` discipline — a bundle signature can
/// never verify as a receipt signature or vice versa.
pub const SIGNING_DOMAIN: &[u8] = b"mark1-bundle-v1\0";

/// The section signing input — DECISION D-Q (07 §"PolicyBundle v1"):
/// `b"mark1-bundle-v1\0" || canonical-CBOR(bundle-sig-input)`, a
/// domain-separated canonical-CBOR structure, never a bare concatenation.
/// The pre-D-Q form (`section || tenant_id || channel || seq`) had three
/// defects: splice ambiguity (two variable-length fields, no length
/// prefixes), an unsigned envelope (backdating `issued_at` revived
/// rotated-out keys; `max_age` — the fail-static floor — was
/// attacker-settable), and an unbound section NAME (one key in all six rings
/// let a `route` signature replay as `verify`). Canonical CBOR is
/// self-delimiting, so ambiguity is closed by construction; the nine-field
/// map covers every envelope field EXCEPT `inclusion` — a transparency-log
/// leaf cannot commit to the proof of its own inclusion.
pub fn section_signing_input(i: &SigInput<'_>) -> Result<Vec<u8>, CanonError> {
    let t = |s: &str| Value::Text(s.into());
    // encode_canonical sorts the entries; listed here in D-Q's doc order.
    let sig_input = Value::Map(vec![
        (t("schema"), t(SCHEMA)),
        (t("section_name"), t(i.section.name())),
        (t("tenant_id"), Value::Bytes(i.tenant_id.to_vec())),
        (t("channel"), t(i.channel)),
        (t("seq"), Value::Integer(i.seq.into())),
        (
            t("issued_at"),
            Value::Tag(1, Box::new(Value::Integer(i.issued_at_epoch_s.into()))),
        ),
        (t("max_age"), Value::Integer(i.max_age_s.into())),
        (t("prev_hash"), Value::Bytes(i.prev_hash.to_vec())),
        (t("section"), Value::Bytes(i.section_bytes.to_vec())),
    ]);
    let mut msg = SIGNING_DOMAIN.to_vec();
    msg.extend_from_slice(&encode_canonical(&sig_input)?);
    Ok(msg)
}

/// D-Q's `bundle-sig-input` fields (the `schema` entry is the closed
/// [`SCHEMA`] constant — a v2 schema is a new signing contract by
/// construction, not a parameter).
pub struct SigInput<'a> {
    pub section: Section,
    /// Canonical-CBOR bytes of THAT section, carried as a bstr.
    pub section_bytes: &'a [u8],
    pub tenant_id: &'a [u8; 16],
    pub channel: &'a str,
    pub seq: u64,
    pub issued_at_epoch_s: u64,
    pub max_age_s: u64,
    pub prev_hash: &'a [u8; 32],
}

fn sha256_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// RFC 6962-shape inclusion verification with SHA-256 (05 §4.4: leaves are
/// SHA-256 of the bundle's canonical body bytes; this walk is RFC 9162
/// §2.1.3.2 verbatim). `leaf_entry` is that 32-byte digest; `leaf_hash =
/// SHA-256(0x00 || leaf_entry)`, interior `= SHA-256(0x01 || L || R)` — the
/// domain split that stops an interior node replaying as a leaf.
pub fn verify_inclusion_rfc6962(
    leaf_entry: &[u8; 32],
    leaf_index: u64,
    tree_size: u64,
    path: &[[u8; 32]],
    root: &[u8; 32],
) -> bool {
    if leaf_index >= tree_size {
        return false;
    }
    let mut fnode = leaf_index;
    let mut snode = tree_size - 1;
    let mut r = sha256_parts(&[&[0x00], leaf_entry]);
    for p in path {
        if snode == 0 {
            return false; // path longer than the tree is deep
        }
        if fnode & 1 == 1 || fnode == snode {
            r = sha256_parts(&[&[0x01], p, &r]);
            if fnode & 1 == 0 {
                while fnode & 1 == 0 && fnode != 0 {
                    fnode >>= 1;
                    snode >>= 1;
                }
            }
        } else {
            r = sha256_parts(&[&[0x01], &r, p]);
        }
        fnode >>= 1;
        snode >>= 1;
    }
    snode == 0 && r == *root
}

/// SHA-256 of the bundle BODY: the canonical map minus its `inclusion` entry.
/// The proof cannot cover itself (the leaf existed before the proof did), so
/// the body is what the tlog leaf, the ACK `bundle_hash` (m1_009
/// `body_sha256`) and the next bundle's `prev_hash` all commit to.
pub fn body_sha256(raw: &[u8]) -> Result<[u8; 32], Reject> {
    let value = decode_canonical_checked(raw)?;
    let Value::Map(entries) = &value else {
        return Err(Reject::Schema {
            path: "bundle".into(),
            detail: "expected map".into(),
        });
    };
    body_sha256_of_entries(entries)
}

fn body_sha256_of_entries(entries: &[(Value, Value)]) -> Result<[u8; 32], Reject> {
    let body: Vec<(Value, Value)> = entries
        .iter()
        .filter(|(k, _)| !matches!(k, Value::Text(t) if t == "inclusion"))
        .cloned()
        .collect();
    let bytes = encode_canonical(&Value::Map(body)).map_err(|e| Reject::NonCanonical {
        detail: e.to_string(),
    })?;
    Ok(sha256_parts(&[&bytes]))
}

fn decode_canonical_checked(raw: &[u8]) -> Result<Value, Reject> {
    if raw.len() > MAX_BUNDLE_LEN {
        return Err(Reject::TooLarge { len: raw.len() });
    }
    // MAX_DEPTH on the ciborium side too: hostile deep nesting must die in
    // the reader, not in this process's stack.
    let value: Value =
        ciborium::de::from_reader_with_recursion_limit(raw, MAX_DEPTH).map_err(|e| {
            Reject::NonCanonical {
                detail: e.to_string(),
            }
        })?;
    // The whole RFC 8949 §4.2.1 check is one byte comparison: re-encode
    // deterministically and demand identity (also catches trailing bytes).
    let reencoded = encode_canonical(&value).map_err(|e| Reject::NonCanonical {
        detail: e.to_string(),
    })?;
    if reencoded != raw {
        return Err(Reject::NonCanonical {
            detail: "re-encode differs from input".into(),
        });
    }
    Ok(value)
}

/// Strict fixed-precision RFC 3339 UTC (`YYYY-MM-DDTHH:MM:SSZ`) → epoch
/// seconds — the precision `mark1-receipt`'s KeyEntry windows carry (its
/// keys.rs ponytail note: uniform second-precision Z). Any other shape is
/// None, which the caller treats as OUTSIDE validity: unparseable trust
/// metadata fails closed, never open.
fn parse_rfc3339_utc(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() != 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        s.get(r).and_then(|d| {
            d.bytes()
                .all(|c| c.is_ascii_digit())
                .then(|| d.parse().ok())?
        })
    };
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let dim = match mo {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    if !(1..=dim).contains(&d) || h > 23 || mi > 59 || sec > 59 {
        return None;
    }
    // Howard Hinnant's days_from_civil — the same integer math the estate's
    // other legs can reproduce without a date library.
    let yy = if mo <= 2 { y - 1 } else { y };
    let era = if yy >= 0 { yy } else { yy - 399 } / 400;
    let yoe = yy - era * 400;
    let doy = (153 * (if mo > 2 { mo - 3 } else { mo + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + h * 3_600 + mi * 60 + sec)
}

/// Full verification order (04 §7.3): section-split signatures against the
/// per-class key set → monotonic seq → transparency-log inclusion proof →
/// canonical-CBOR schema decode into typed, allocation-final structs.
///
/// `last_applied_seq` is `None` when no bundle has ever been accepted (the
/// only state in which bundle zero's `seq == 0` is admissible — 04 §7.3
/// sketches a bare u64, which cannot say "nothing yet" without stealing a
/// legal seq value).
///
/// DECISION D-S (04 §7.3): `tlog_head` is the caller's PINNED log head, and
/// it is REQUIRED at `seq > 0` — `None` there is an M1E-3003 refusal, and a
/// proof whose root differs from the head is an M1E-3003 rejection. Without
/// it the walk verified against a root read from the bundle's OWN `inclusion`
/// map — self-consistency, not evidence: adversarial review forged exactly
/// that with no signing key involved. Refusing on a missing head is correct
/// fail-static behaviour, not an availability risk: an edge with no fresh
/// head keeps last-known-good rather than accepting an unwitnessed bundle.
/// At `seq == 0` the D-P waiver is unchanged and the head is structurally
/// irrelevant (bundle zero is pre-log).
///
/// ponytail: for `seq > 0` this function proves `prev_hash` is WELL-FORMED
/// but cannot prove linkage — the last-accepted body hash lives in the
/// caller's LKG state (mark1d.policy), which compares it against
/// [`Bundle::body_sha256`] of its retained bundle. The seq-0 genesis rule IS
/// checked here, structurally.
pub fn verify_and_decode(
    raw: &[u8],
    keys: &SectionKeys,
    last_applied_seq: Option<u64>,
    tlog_head: Option<&TlogHead>,
) -> Result<Bundle, Reject> {
    // ── canonical form + envelope (parsing precedes signatures by necessity;
    //    nothing below trusts a byte the canonical check did not pin) ──
    let value = decode_canonical_checked(raw)?;
    let top = decode::map_of(&value, "bundle")?;
    decode::strict_keys(
        &top,
        &[
            "schema",
            "tenant_id",
            "channel",
            "seq",
            "issued_at",
            "max_age",
            "prev_hash",
            "sections",
            "signatures",
            "inclusion",
        ],
        &[],
        "bundle",
    )?;

    if decode::text(top["schema"], "bundle.schema")? != SCHEMA {
        return Err(Reject::Schema {
            path: "bundle.schema".into(),
            detail: format!("expected {SCHEMA}"),
        });
    }
    let tenant_id: [u8; 16] = match top["tenant_id"] {
        Value::Bytes(b) => b.as_slice().try_into().map_err(|_| Reject::Schema {
            path: "bundle.tenant_id".into(),
            detail: "expected 16-byte uuid".into(),
        })?,
        _ => {
            return Err(Reject::Schema {
                path: "bundle.tenant_id".into(),
                detail: "expected bstr".into(),
            })
        }
    };
    let channel = decode::check_channel(top["channel"], "bundle.channel")?;
    let seq = decode::uint(top["seq"], "bundle.seq")?;
    // CDDL `time` = tag 1 epoch seconds; non-integer time has no canonical
    // second-precision meaning here and is rejected.
    let issued_at_epoch_s = match top["issued_at"] {
        Value::Tag(1, inner) => decode::uint(inner, "bundle.issued_at")?,
        _ => {
            return Err(Reject::Schema {
                path: "bundle.issued_at".into(),
                detail: "expected tag-1 time".into(),
            })
        }
    };
    let max_age = Duration::from_secs(decode::uint(top["max_age"], "bundle.max_age")?);
    let prev_hash: [u8; 32] = match top["prev_hash"] {
        Value::Bytes(b) => b.as_slice().try_into().map_err(|_| Reject::Schema {
            path: "bundle.prev_hash".into(),
            detail: "expected 32-byte hash".into(),
        })?,
        _ => {
            return Err(Reject::Schema {
                path: "bundle.prev_hash".into(),
                detail: "expected bstr".into(),
            })
        }
    };

    let sections = decode::map_of(top["sections"], "bundle.sections")?;
    let section_names: Vec<&str> = Section::ALL.iter().map(|s| s.name()).collect();
    decode::strict_keys(&sections, &section_names, &[], "bundle.sections")?;
    let signatures = decode::map_of(top["signatures"], "bundle.signatures")?;
    decode::strict_keys(&signatures, &section_names, &[], "bundle.signatures")?;

    // ── 1. section-split signatures, each against ITS class's ring ──
    for section in Section::ALL {
        let path = format!("bundle.signatures.{}", section.name());
        let sig_map = decode::map_of(signatures[section.name()], &path)?;
        decode::strict_keys(&sig_map, &["key_id", "sig"], &[], &path)?;
        let key_id = decode::text(sig_map["key_id"], &path)?;
        let sig: [u8; 64] = match sig_map["sig"] {
            Value::Bytes(b) => b.as_slice().try_into().map_err(|_| Reject::Schema {
                path: path.clone(),
                detail: "sig must be 64 bytes".into(),
            })?,
            _ => {
                return Err(Reject::Schema {
                    path,
                    detail: "expected bstr sig".into(),
                });
            }
        };
        let Some(entry) = keys.ring(section).get(key_id) else {
            // Never published for THIS class — a wrong-role key lands here
            // too (ring membership IS the role; see SectionKeys).
            return Err(Reject::Signature {
                section,
                reason: SigReason::UnknownKey,
            });
        };
        let issued = i64::try_from(issued_at_epoch_s).unwrap_or(i64::MAX);
        let in_window = |bound: &Option<String>, after: bool| -> bool {
            match bound.as_deref().map(parse_rfc3339_utc) {
                None => true,        // unbounded side
                Some(None) => false, // unparseable trust metadata fails closed
                Some(Some(t)) => {
                    if after {
                        issued >= t
                    } else {
                        issued <= t
                    }
                }
            }
        };
        if !in_window(&entry.not_before, true) || !in_window(&entry.not_after, false) {
            return Err(Reject::Signature {
                section,
                reason: SigReason::OutsideValidity,
            });
        }
        let section_bytes =
            encode_canonical(sections[section.name()]).map_err(|e| Reject::NonCanonical {
                detail: e.to_string(),
            })?;
        // D-Q: the signed message covers the whole envelope (minus
        // `inclusion`) AND the section name — so the `issued_at` the key
        // window above was judged against is itself under the signature.
        let msg = section_signing_input(&SigInput {
            section,
            section_bytes: &section_bytes,
            tenant_id: &tenant_id,
            channel: &channel,
            seq,
            issued_at_epoch_s,
            max_age_s: max_age.as_secs(),
            prev_hash: &prev_hash,
        })
        .map_err(|e| Reject::NonCanonical {
            detail: e.to_string(),
        })?;
        if !keys::verify(&entry.public_key, &sig, &msg) {
            return Err(Reject::Signature {
                section,
                reason: SigReason::BadSignature,
            });
        }
    }

    // ── 2. monotonic seq per (tenant, channel): a single `>` with no
    //       exception path — an exception path would BE a replay hole (05
    //       §4.6: rollback is a new higher seq, never a lower one) ──
    if let Some(last) = last_applied_seq {
        if seq <= last {
            return Err(Reject::SeqReplay {
                seq,
                last_applied_seq: last,
            });
        }
    }

    // ── 3. prev_hash genesis rule + transparency-log inclusion ──
    if seq == 0 && prev_hash != GENESIS_PREV_HASH {
        return Err(Reject::PrevHashMismatch);
    }
    let body = body_sha256_of_entries(match &value {
        Value::Map(entries) => entries,
        // Unreachable: map_of above proved the shape.
        _ => &[],
    })?;
    let tlog = match (seq, top["inclusion"]) {
        // D-P's structural waiver: bundle zero is local and pre-log; the
        // carve-out is this literal `0`, never configuration.
        (0, Value::Null) => None,
        (0, _) => {
            return Err(Reject::InclusionInvalid {
                detail: "seq 0 is pre-log; inclusion must be null",
            })
        }
        (_, proof) => {
            let path = "bundle.inclusion";
            // D-S: no pinned head means no evidence to verify against —
            // refuse (the caller keeps last-known-good) rather than fall
            // back to the bundle's own root, which is what made M1E-3003
            // decorative at seq > 0.
            let Some(head) = tlog_head else {
                return Err(Reject::InclusionInvalid {
                    detail: "no pinned tlog head at seq > 0",
                });
            };
            if matches!(proof, Value::Null) {
                return Err(Reject::InclusionInvalid {
                    detail: "proof missing",
                });
            }
            let pm = decode::map_of(proof, path)?;
            decode::strict_keys(&pm, &["leaf_index", "tree_size", "path", "root"], &[], path)?;
            let leaf_index = decode::uint(pm["leaf_index"], path)?;
            let tree_size = decode::uint(pm["tree_size"], path)?;
            let root: [u8; 32] = match pm["root"] {
                Value::Bytes(b) => b.as_slice().try_into().map_err(|_| Reject::Schema {
                    path: path.into(),
                    detail: "root must be 32 bytes".into(),
                })?,
                _ => {
                    return Err(Reject::Schema {
                        path: path.into(),
                        detail: "expected bstr root".into(),
                    })
                }
            };
            let mut audit: Vec<[u8; 32]> = Vec::new();
            for hv in decode::array(pm["path"], path)? {
                match hv {
                    Value::Bytes(b) => {
                        audit.push(b.as_slice().try_into().map_err(|_| Reject::Schema {
                            path: path.into(),
                            detail: "path hash must be 32 bytes".into(),
                        })?)
                    }
                    _ => {
                        return Err(Reject::Schema {
                            path: path.into(),
                            detail: "expected bstr path hash".into(),
                        })
                    }
                }
            }
            // D-S's normative comparison: the proof must target the PINNED
            // head, not a root it carried in. Tree-size equality is subsumed
            // (two SHA-256 trees of different sizes cannot share a root) but
            // checked so a mismatched checkpoint is named, not walked.
            if root != head.root || tree_size != head.tree_size {
                return Err(Reject::InclusionInvalid {
                    detail: "proof does not target the pinned log head",
                });
            }
            if !verify_inclusion_rfc6962(&body, leaf_index, tree_size, &audit, &root) {
                return Err(Reject::InclusionInvalid {
                    detail: "audit path does not reproduce root",
                });
            }
            Some(TlogInclusion {
                leaf_index,
                tree_size,
                root,
            })
        }
    };

    // ── 4. strict typed schema decode (the M1E-3005 structural scan) ──
    Ok(Bundle {
        tenant_id,
        channel,
        seq,
        issued_at_epoch_s,
        max_age,
        prev_hash,
        body_sha256: body,
        tlog,
        verify: decode::decode_verify(sections["verify"])?,
        route: decode::decode_route(sections["route"])?,
        memory: decode::decode_memory(sections["memory"])?,
        cortex: decode::decode_cortex(sections["cortex"])?,
        gates: decode::decode_gates(sections["gates"])?,
        agent_maps: decode::decode_agent_maps(sections["agent_maps"])?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Go twin's canon reader keeps a tag verbatim, so it needed an
    /// explicit 2/3 guard to land on this kind rather than on `schema`. Pinned
    /// here so the reject TAXONOMY, not just the decision, stays shared.
    #[test]
    fn bignum_tags_are_non_canonical() {
        for raw in [[0xc2u8, 0x42, 0x01, 0x00], [0xc3u8, 0x42, 0x01, 0x00]] {
            let e = decode_canonical_checked(&raw).unwrap_err();
            assert_eq!((e.code(), e.kind()), ("M1E-3001", "non_canonical"));
        }
        // Tag 1 is the bundle's own issued_at and must still round-trip.
        assert!(decode_canonical_checked(&[0xc1, 0x1a, 0x6a, 0x8b, 0xd0, 0x00]).is_ok());
    }

    #[test]
    fn rfc3339_parse_strict() {
        assert_eq!(parse_rfc3339_utc("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_rfc3339_utc("2026-08-29T12:00:00Z"),
            Some(1_788_004_800)
        );
        assert_eq!(
            parse_rfc3339_utc("2024-02-29T00:00:00Z"),
            Some(1_709_164_800)
        );
        for bad in [
            "2026-02-29T00:00:00Z", // not a leap year
            "2026-13-01T00:00:00Z",
            "2026-08-29T24:00:00Z",
            "2026-08-29 12:00:00Z", // no T
            "2026-08-29T12:00:00",  // no Z
            "2026-08-29T12:00:00.0Z",
        ] {
            assert_eq!(parse_rfc3339_utc(bad), None, "{bad}");
        }
    }

    #[test]
    fn d_q_signing_input_binds_name_and_envelope() {
        // D-Q's three closures, at the input level: every field the old
        // concatenation left unsigned (or unbound) now changes the message,
        // so a signature over one (name, envelope) can never verify for
        // another — the vectors carry the end-to-end proofs.
        let input = |sec: Section, bytes: &[u8], channel: &str, issued: u64, age: u64, prev| {
            section_signing_input(&SigInput {
                section: sec,
                section_bytes: bytes,
                tenant_id: &[7u8; 16],
                channel,
                seq: 3,
                issued_at_epoch_s: issued,
                max_age_s: age,
                prev_hash: &prev,
            })
            .unwrap()
        };
        let base = input(Section::Verify, b"SEC", "stable", 1_000, 60, [0u8; 32]);
        assert!(base.starts_with(SIGNING_DOMAIN));
        // Section NAME bound: finding #9 — one key in all six rings must not
        // let a `route` signature replay as `verify`.
        assert_ne!(
            base,
            input(Section::Route, b"SEC", "stable", 1_000, 60, [0u8; 32])
        );
        // Envelope bound: backdating issued_at, stretching max_age, or
        // rewriting prev_hash each breaks the signature.
        assert_ne!(
            base,
            input(Section::Verify, b"SEC", "stable", 999, 60, [0u8; 32])
        );
        assert_ne!(
            base,
            input(
                Section::Verify,
                b"SEC",
                "stable",
                1_000,
                u64::MAX,
                [0u8; 32]
            )
        );
        assert_ne!(
            base,
            input(Section::Verify, b"SEC", "stable", 1_000, 60, [0x42; 32])
        );
        // Splice closure: the CBOR structure is self-delimiting, so moving a
        // byte between the section and a neighbouring variable-length field
        // cannot yield the same message.
        assert_ne!(
            input(Section::Verify, b"SECx", "stable", 1_000, 60, [0u8; 32]),
            input(Section::Verify, b"SEC", "xstable", 1_000, 60, [0u8; 32])
        );
    }

    #[test]
    fn inclusion_proof_walk() {
        // Hand-built 3-leaf RFC 6962 tree: root = H1(H1(L0,L1), L2).
        let leaves: Vec<[u8; 32]> = (0u8..3).map(|i| [i; 32]).collect();
        let lh: Vec<[u8; 32]> = leaves.iter().map(|l| sha256_parts(&[&[0x00], l])).collect();
        let n01 = sha256_parts(&[&[0x01], &lh[0], &lh[1]]);
        let root = sha256_parts(&[&[0x01], &n01, &lh[2]]);
        assert!(verify_inclusion_rfc6962(
            &leaves[0],
            0,
            3,
            &[lh[1], lh[2]],
            &root
        ));
        assert!(verify_inclusion_rfc6962(
            &leaves[1],
            1,
            3,
            &[lh[0], lh[2]],
            &root
        ));
        assert!(verify_inclusion_rfc6962(&leaves[2], 2, 3, &[n01], &root));
        // Wrong index, wrong path order, truncated path, index out of range.
        assert!(!verify_inclusion_rfc6962(
            &leaves[0],
            1,
            3,
            &[lh[1], lh[2]],
            &root
        ));
        assert!(!verify_inclusion_rfc6962(
            &leaves[0],
            0,
            3,
            &[lh[2], lh[1]],
            &root
        ));
        assert!(!verify_inclusion_rfc6962(&leaves[0], 0, 3, &[lh[1]], &root));
        assert!(!verify_inclusion_rfc6962(&leaves[0], 3, 3, &[], &root));
        // Single-leaf tree: empty path, root == leaf hash.
        assert!(verify_inclusion_rfc6962(&leaves[0], 0, 1, &[], &lh[0]));
        assert!(!verify_inclusion_rfc6962(
            &leaves[0],
            0,
            1,
            &[lh[1]],
            &lh[0]
        ));
    }
}
