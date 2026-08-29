//! mark1-verifier — the standalone OFFLINE verifier (13 §1 row C7,
//! FR-SPINE-020): chain walk, checkpoint Merkle + inclusion paths,
//! dual-signature + KeyRing rotation verification, witness-head cross-check.
//!
//! OFFLINE BY CONSTRUCTION: every input is a local file and no network code
//! is compiled in — the dependency list (Cargo.toml) is the proof, not a
//! configuration flag. "Omium's servers are unreachable" is the operating
//! assumption, not a degraded mode (08 §7.7 `--offline` semantics).
//!
//! All chain/crypto verdicts come from `mark1-receipt` — the same primitives
//! origin signing uses, so "verify offline" and "sign at origin" cannot
//! drift (04 §7.2). This crate only parses the three local files and reports.

use std::fmt;
use std::path::Path;

use mark1_receipt::{
    chain, checkpoint, hex, keys::CrossSig, keys::KeyEntry, keys::KeyRing, keys::KeyRole,
    ReceiptRow,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// I/O or malformed-input failure — exit 1 territory (08 §7.7), distinct
/// from a DEFECT, which is a verdict about a well-formed chain (exit 5).
/// Display/Error are hand-written: this crate's Cargo.toml is the audit
/// artifact (13 §1), so no derive dependency buys its way in for two arms.
#[derive(Debug)]
pub enum InputError {
    Io {
        path: String,
        source: std::io::Error,
    },
    Malformed {
        path: String,
        line: usize,
        detail: String,
    },
}

impl fmt::Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "{path}: {source}"),
            Self::Malformed { path, line, detail } => write!(f, "{path}:{line}: {detail}"),
        }
    }
}

impl std::error::Error for InputError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Malformed { .. } => None,
        }
    }
}

impl InputError {
    fn malformed(path: &Path, line: usize, detail: impl Into<String>) -> Self {
        Self::Malformed {
            path: path.display().to_string(),
            line,
            detail: detail.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// The three local input files. Hashes/keys/signatures are hex throughout,
// matching the conformance vectors' encoding; payload is the exact signed
// text (08 §3.4's export rule).
// ---------------------------------------------------------------------------

/// One line of the chain export (JSONL — 08 §7.7 `--from <export.jsonl>`).
#[derive(Debug, Deserialize)]
pub struct ExportRow {
    pub seq: u64,
    pub payload: String,
    pub receipt_hash_hex: String,
    #[serde(default)]
    pub device_key_id: Option<String>,
    #[serde(default)]
    pub device_signature_hex: Option<String>,
    pub server_key_id: String,
    pub server_signature_hex: String,
    /// Checkpoint evidence, present when the export carries the sealed batch:
    /// the 16-byte event_id leaves in spool order.
    #[serde(default)]
    pub leaves_hex: Option<Vec<String>>,
    /// Per-event inclusion claims to spot-check against this checkpoint.
    #[serde(default)]
    pub inclusions: Option<Vec<InclusionClaim>>,
}

#[derive(Debug, Deserialize)]
pub struct InclusionClaim {
    pub leaf_hex: String,
    pub leaf_index: u64,
    pub path_hex: Vec<String>,
}

/// Local snapshot of the public key manifest (08 §3.5's
/// `/.well-known/mark1-keys`, fetched ahead of time — `--offline` requires a
/// local key manifest by design).
#[derive(Debug, Deserialize)]
pub struct KeysFile {
    #[serde(default)]
    pub server_chain_keys: Vec<KeyRecord>,
    #[serde(default)]
    pub device_keys: Vec<KeyRecord>,
}

#[derive(Debug, Deserialize)]
pub struct KeyRecord {
    pub pubkey_hex: String,
    /// Optional label: when present it MUST equal the derived id — a manifest
    /// that lies about a key_id is malformed input, not a chain defect.
    #[serde(default)]
    pub key_id: Option<String>,
    /// Device keys are tenant-scoped (m1_001); when present the key only
    /// answers for that tenant's chain.
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub not_before: Option<String>,
    #[serde(default)]
    pub not_after: Option<String>,
    #[serde(default)]
    pub cross_sig: Option<CrossSigRecord>,
}

#[derive(Debug, Deserialize)]
pub struct CrossSigRecord {
    pub by_key_id: String,
    pub signature_hex: String,
}

/// Local witness snapshot: the heads the external witness holds (m1_003's
/// witnessed facts, as fetched from the log or the customer's bucket).
#[derive(Debug, Deserialize)]
pub struct WitnessFile {
    pub heads: Vec<WitnessHead>,
}

#[derive(Debug, Deserialize)]
pub struct WitnessHead {
    pub witnessed_seq: u64,
    pub witnessed_hash_hex: String,
}

// ---------------------------------------------------------------------------
// Report — 08 §7.7's shape: defects are enumerated, never summarized away.
// ---------------------------------------------------------------------------

/// Chain defects use the vectors' eight-kind vocabulary verbatim; the witness
/// cross-check adds `witness_mismatch` (08 §7.7 names it), which is not a
/// chain defect — it is the chain and the world disagreeing.
pub const WITNESS_MISMATCH: &str = "witness_mismatch";

#[derive(Debug, Serialize)]
pub struct ReportDefect {
    pub seq: u64,
    pub kind: String,
    pub detail: String,
}

#[derive(Debug, Serialize)]
pub struct Checked {
    pub receipts: usize,
    pub checkpoints: usize,
    pub inclusion_proofs: usize,
    pub witness_heads: usize,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub ok: bool,
    pub checked: Checked,
    pub intact_prefix_seq: u64,
    pub intact_prefix_hash: String,
    pub last_good_seq: u64,
    pub last_good_hash: String,
    pub defects: Vec<ReportDefect>,
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "checked: {} receipt(s), {} checkpoint(s), {} inclusion proof(s), {} witness head(s)",
            self.checked.receipts,
            self.checked.checkpoints,
            self.checked.inclusion_proofs,
            self.checked.witness_heads
        )?;
        writeln!(
            f,
            "intact_prefix_seq: {}  last_good_seq: {}",
            self.intact_prefix_seq, self.last_good_seq
        )?;
        for d in &self.defects {
            writeln!(f, "DEFECT seq={} {}: {}", d.seq, d.kind, d.detail)?;
        }
        write!(
            f,
            "{}",
            if self.ok {
                "chain VALID"
            } else {
                "chain INVALID"
            }
        )
    }
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

pub fn load_chain(path: &Path) -> Result<Vec<ExportRow>, InputError> {
    let raw = read(path)?;
    let mut rows = Vec::new();
    for (i, line) in raw.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        rows.push(
            serde_json::from_str(line)
                .map_err(|e| InputError::malformed(path, i + 1, e.to_string()))?,
        );
    }
    Ok(rows)
}

pub fn load_keys(path: &Path) -> Result<KeyRing, InputError> {
    let raw = read(path)?;
    let file: KeysFile =
        serde_json::from_str(&raw).map_err(|e| InputError::malformed(path, 0, e.to_string()))?;
    let mut ring = KeyRing::new();
    // The manifest's two lists ARE the role split (05 §4.5): which list a key
    // sits in decides which signature leg it may answer. Flattening them into
    // one roleless set is exactly what would let the server key alone mint a
    // "device-attested" chain — the direction m1_002's dual-signing closes.
    let roles = file
        .server_chain_keys
        .iter()
        .map(|r| (r, KeyRole::ServerChain))
        .chain(file.device_keys.iter().map(|r| (r, KeyRole::DeviceOrigin)));
    for (record, role) in roles {
        let public_key: [u8; 32] = hex::decode_array(&record.pubkey_hex)
            .ok_or_else(|| InputError::malformed(path, 0, "pubkey_hex is not 32 bytes of hex"))?;
        let mut entry = KeyEntry::new(public_key, role);
        entry.tenant_id.clone_from(&record.tenant_id);
        entry.not_before.clone_from(&record.not_before);
        entry.not_after.clone_from(&record.not_after);
        if let Some(cs) = &record.cross_sig {
            let signature: [u8; 64] = hex::decode_array(&cs.signature_hex).ok_or_else(|| {
                InputError::malformed(path, 0, "cross_sig.signature_hex is not 64 bytes of hex")
            })?;
            entry.cross_sig = Some(CrossSig {
                by_key_id: cs.by_key_id.clone(),
                signature,
            });
        }
        // One key, one role: m1_002 keeps the classes in disjoint tables, so
        // a manifest listing the same key bytes under two roles is lying —
        // and a silent overwrite here would let the second listing reassign
        // the first one's role.
        if ring.contains(&mark1_receipt::derive_key_id(&public_key)) {
            return Err(InputError::malformed(
                path,
                0,
                "manifest lists the same public key under more than one role",
            ));
        }
        let derived = ring.insert(entry);
        // key_id is DERIVED, never configured (m1_002) — a manifest whose
        // label disagrees with its own key bytes cannot be trusted to name
        // anything else correctly either.
        if let Some(claimed) = &record.key_id {
            if claimed != &derived {
                return Err(InputError::malformed(
                    path,
                    0,
                    format!("manifest names key_id {claimed} but the key derives to {derived}"),
                ));
            }
        }
    }
    Ok(ring)
}

pub fn load_witness(path: &Path) -> Result<WitnessFile, InputError> {
    let raw = read(path)?;
    serde_json::from_str(&raw).map_err(|e| InputError::malformed(path, 0, e.to_string()))
}

fn read(path: &Path) -> Result<String, InputError> {
    std::fs::read_to_string(path).map_err(|source| InputError::Io {
        path: path.display().to_string(),
        source,
    })
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

pub struct Options {
    pub start_seq: u64,
    /// Expected predecessor hash when the export starts mid-chain.
    pub anchor_prev: Option<[u8; 32]>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            start_seq: 1,
            anchor_prev: None,
        }
    }
}

/// The whole offline verdict: chain walk, checkpoint Merkle + inclusion
/// paths, witness cross-check. Never fails early — the shape of the damage
/// is the diagnostic (estate chain.py, kept product-wide).
pub fn verify(
    export: &[ExportRow],
    ring: &KeyRing,
    witness: Option<&WitnessFile>,
    opts: &Options,
) -> Result<Report, InputError> {
    // A zero-row export must never print "chain VALID": vacuous verification
    // is the verdict a wholesale truncation would earn, and the witness
    // cross-check that catches truncation is opt-in. There is no chain to
    // have a defect IN, so this is malformed input (exit 1), not exit 5.
    if export.is_empty() {
        return Err(InputError::Malformed {
            path: "chain export".into(),
            line: 0,
            detail: "contains no receipt rows — an empty export is not a verified history".into(),
        });
    }
    let rows = to_receipt_rows(export)?;
    let chain_report = chain::verify_chain(ring, &rows, opts.start_seq, opts.anchor_prev);

    let mut defects: Vec<ReportDefect> = chain_report
        .defects
        .iter()
        .map(|d| ReportDefect {
            seq: d.seq,
            kind: d.kind.as_str().to_string(),
            detail: d.detail.clone(),
        })
        .collect();

    let mut checkpoints = 0usize;
    let mut inclusion_proofs = 0usize;
    for row in export {
        let counted = verify_checkpoint_evidence(row, &mut defects).unwrap_or((false, 0));
        checkpoints += usize::from(counted.0);
        inclusion_proofs += counted.1;
    }

    let mut witness_heads = 0usize;
    if let Some(w) = witness {
        for head in &w.heads {
            witness_heads += 1;
            cross_check_witness_head(head, &rows, &mut defects);
        }
    }

    Ok(Report {
        ok: defects.is_empty(),
        checked: Checked {
            receipts: chain_report.checked,
            checkpoints,
            inclusion_proofs,
            witness_heads,
        },
        intact_prefix_seq: chain_report.intact_prefix_seq,
        intact_prefix_hash: hex::encode(&chain_report.intact_prefix_hash),
        last_good_seq: chain_report.last_good_seq,
        last_good_hash: hex::encode(&chain_report.last_good_hash),
        defects,
    })
}

pub fn to_receipt_rows(export: &[ExportRow]) -> Result<Vec<ReceiptRow>, InputError> {
    export
        .iter()
        .map(|row| {
            let receipt_hash = hex::decode_array(&row.receipt_hash_hex)
                .ok_or_else(|| malformed_row(row.seq, "receipt_hash_hex is not 32 bytes of hex"))?;
            let device_signature = row
                .device_signature_hex
                .as_deref()
                .map(|s| {
                    hex::decode_array(s).ok_or_else(|| {
                        malformed_row(row.seq, "device_signature_hex is not 64 bytes of hex")
                    })
                })
                .transpose()?;
            let server_signature =
                hex::decode_array(&row.server_signature_hex).ok_or_else(|| {
                    malformed_row(row.seq, "server_signature_hex is not 64 bytes of hex")
                })?;
            Ok(ReceiptRow {
                seq: row.seq,
                payload: row.payload.clone(),
                receipt_hash,
                device_key_id: row.device_key_id.clone(),
                device_signature,
                server_key_id: row.server_key_id.clone(),
                server_signature,
            })
        })
        .collect()
}

fn malformed_row(seq: u64, detail: &str) -> InputError {
    InputError::Malformed {
        path: "chain export".into(),
        line: 0,
        detail: format!("seq {seq}: {detail}"),
    }
}

/// Checkpoint Merkle checks for one export row, when it carries the evidence.
/// Returns (was_a_checkpoint_with_leaves, inclusion_proofs_checked); `None`
/// when the payload does not parse (the chain walk already named that row).
fn verify_checkpoint_evidence(
    row: &ExportRow,
    defects: &mut Vec<ReportDefect>,
) -> Option<(bool, usize)> {
    let payload: Value = serde_json::from_str(&row.payload).ok()?;
    if payload.get("type").and_then(Value::as_str) != Some("checkpoint") {
        return Some((false, 0));
    }
    let Some(claimed_root) = payload
        .get("merkle_root")
        .and_then(Value::as_str)
        .and_then(hex::decode_array::<32>)
    else {
        // The signed claim itself is undecodable — the root cannot be
        // checked against anything, which IS a Merkle defect, not an
        // input error: this is the chain's content, not the operator's file.
        defects.push(ReportDefect {
            seq: row.seq,
            kind: chain::DefectKind::MerkleMismatch.as_str().into(),
            detail: "checkpoint payload carries no decodable merkle_root".into(),
        });
        return Some((false, 0));
    };
    let leaf_count = payload
        .get("leaf_count")
        .and_then(Value::as_u64)
        .unwrap_or(0) as usize;

    let mut had_leaves = false;
    if let Some(leaves_hex) = &row.leaves_hex {
        had_leaves = true;
        match decode_leaves(leaves_hex) {
            None => defects.push(ReportDefect {
                seq: row.seq,
                kind: chain::DefectKind::MerkleMismatch.as_str().into(),
                detail: "leaves_hex contains a leaf that is not 16 bytes of hex".into(),
            }),
            Some(leaves) => {
                if leaves.len() != leaf_count
                    || !checkpoint::verify_merkle_root(&leaves, &claimed_root)
                {
                    defects.push(ReportDefect {
                        seq: row.seq,
                        kind: chain::DefectKind::MerkleMismatch.as_str().into(),
                        detail: format!(
                            "payload's merkle_root/leaf_count ({leaf_count}) do not match the \
                             root recomputed over {} exported leaf/leaves",
                            leaves.len()
                        ),
                    });
                }
            }
        }
    }

    let mut proofs = 0usize;
    if let Some(claims) = &row.inclusions {
        for claim in claims {
            proofs += 1;
            if !inclusion_claim_holds(claim, &claimed_root, leaf_count) {
                defects.push(ReportDefect {
                    seq: row.seq,
                    kind: chain::DefectKind::InclusionPathInvalid.as_str().into(),
                    detail: format!(
                        "inclusion path for leaf_index {} does not reproduce the checkpoint's \
                         merkle_root",
                        claim.leaf_index
                    ),
                });
            }
        }
    }
    Some((had_leaves, proofs))
}

fn decode_leaves(leaves_hex: &[String]) -> Option<Vec<[u8; 16]>> {
    leaves_hex.iter().map(|s| hex::decode_array(s)).collect()
}

fn inclusion_claim_holds(claim: &InclusionClaim, root: &[u8; 32], leaf_count: usize) -> bool {
    let Some(leaf) = hex::decode_array::<16>(&claim.leaf_hex) else {
        return false;
    };
    let Some(path) = claim
        .path_hex
        .iter()
        .map(|s| hex::decode_array::<32>(s))
        .collect::<Option<Vec<_>>>()
    else {
        return false;
    };
    let Ok(index) = usize::try_from(claim.leaf_index) else {
        return false;
    };
    checkpoint::verify_inclusion(&leaf, index, &path, root, leaf_count)
}

/// The witness holds (seq, hash) pairs Omium cannot edit (m1_003 header). A
/// chain that disagrees with a witnessed head — different hash, or no receipt
/// at that seq at all — has been rewritten or truncated AFTER witnessing.
fn cross_check_witness_head(
    head: &WitnessHead,
    rows: &[ReceiptRow],
    defects: &mut Vec<ReportDefect>,
) {
    let Some(expected) = hex::decode_array::<32>(&head.witnessed_hash_hex) else {
        defects.push(ReportDefect {
            seq: head.witnessed_seq,
            kind: WITNESS_MISMATCH.into(),
            detail: "witnessed_hash_hex is not 32 bytes of hex".into(),
        });
        return;
    };
    match rows.iter().find(|r| r.seq == head.witnessed_seq) {
        None => defects.push(ReportDefect {
            seq: head.witnessed_seq,
            kind: WITNESS_MISMATCH.into(),
            detail: "chain has no receipt at a witnessed seq — truncated after witnessing".into(),
        }),
        Some(row) if row.receipt_hash != expected => defects.push(ReportDefect {
            seq: head.witnessed_seq,
            kind: WITNESS_MISMATCH.into(),
            detail: "receipt_hash at witnessed seq differs from the witnessed head".into(),
        }),
        Some(_) => {}
    }
}

/// Convenience for callers that hold an anchor as hex (the CLI's --prev-hash).
pub fn parse_anchor(prev_hash_hex: &str) -> Option<[u8; 32]> {
    hex::decode_array(prev_hash_hex)
}

// Re-exported so integration tests build fixtures with the exact primitives
// the verifier judges them by.
pub use mark1_receipt as receipt;
