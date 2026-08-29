//! Checkpoints: the Merkle tree over event_ids and the dual-signed sealing
//! payload.
//!
//! NEW relative to the vendor source: a checkpoint seals a batch of N events
//! into one chained, dual-signed receipt (07 "The receipt chain", m1_002's
//! checkpoint columns); individual events then need only
//! `checkpoint_seq + inclusion_path` to be provable, so per-event receipts
//! stay reserved for the six named classes.
//!
//! The tree is RFC 6962's shape with BLAKE3 — 04 §7.2 names BLAKE3, and
//! 05 §4.4's transparency log is already 6962, so there is one tree
//! discipline product-wide. Frozen by conformance/vectors/receipt/README.md
//! (12 §3.4: the vector commit fixes what the prose left open):
//!
//! ```text
//! leaf_hash(leaf)  = blake3(0x00 || leaf)         # leaves are 16-byte event_ids
//! node_hash(L, R)  = blake3(0x01 || L || R)
//! root([x])        = leaf_hash(x)
//! root(D[n])       = node_hash(root(D[0:k]), root(D[k:n])), k = largest power of 2 < n
//! inclusion_path   = bottom-up sibling subtree hashes; leaf index decides left/right
//! ```
//!
//! The 0x00/0x01 prefixes are second-preimage domain separation — an interior
//! node can never replay as a leaf. Odd counts split unbalanced, never by
//! duplicating a leaf: duplication is the CVE-2012-2459 shape.
//!
//! ponytail: recursive O(n log n) tree, recomputed per call — checkpoints
//! seal hundreds of leaves, not millions. Memoise subtree roots if batch
//! sizes ever grow past ~10^5.

use serde_json::{json, Value};

use crate::canonical::{self, NonIntegerNumberError, PAYLOAD_VERSION};
use crate::chain::ReceiptRow;
use crate::hex;
use crate::keys::Signer;

pub const LEAF_LEN: usize = 16;
pub const HASH_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MerkleError {
    /// m1_002 CHECKs `event_count > 0`: a root "over nothing" is a signable
    /// claim about nothing, so it is refused rather than given a sentinel.
    #[error("a checkpoint must seal at least one event (m1_002 event_count > 0)")]
    EmptyLeaves,
    #[error("leaf index {index} outside 0..{leaf_count}")]
    IndexOutOfRange { index: usize, leaf_count: usize },
}

pub fn leaf_hash(leaf: &[u8; LEAF_LEN]) -> [u8; HASH_LEN] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[0x00]);
    hasher.update(leaf);
    *hasher.finalize().as_bytes()
}

pub fn node_hash(left: &[u8; HASH_LEN], right: &[u8; HASH_LEN]) -> [u8; HASH_LEN] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[0x01]);
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

// Largest power of two strictly below n (n >= 2) — 6962's unbalanced split.
fn split(n: usize) -> usize {
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

pub fn merkle_root(leaves: &[[u8; LEAF_LEN]]) -> Result<[u8; HASH_LEN], MerkleError> {
    match leaves {
        [] => Err(MerkleError::EmptyLeaves),
        [leaf] => Ok(leaf_hash(leaf)),
        _ => {
            let k = split(leaves.len());
            // Both halves are non-empty by construction, so recursion cannot
            // hit EmptyLeaves; propagating keeps the signature honest anyway.
            Ok(node_hash(
                &merkle_root(&leaves[..k])?,
                &merkle_root(&leaves[k..])?,
            ))
        }
    }
}

/// RFC 6962 audit path for `leaves[index]`: bottom-up sibling subtree hashes.
pub fn inclusion_path(
    leaves: &[[u8; LEAF_LEN]],
    index: usize,
) -> Result<Vec<[u8; HASH_LEN]>, MerkleError> {
    if index >= leaves.len() {
        return Err(MerkleError::IndexOutOfRange {
            index,
            leaf_count: leaves.len(),
        });
    }
    if leaves.len() == 1 {
        return Ok(Vec::new());
    }
    let k = split(leaves.len());
    let mut path = if index < k {
        let mut p = inclusion_path(&leaves[..k], index)?;
        p.push(merkle_root(&leaves[k..])?);
        p
    } else {
        let mut p = inclusion_path(&leaves[k..], index - k)?;
        p.push(merkle_root(&leaves[..k])?);
        p
    };
    path.shrink_to_fit();
    Ok(path)
}

/// Does `path` carry `leaf` (at `index`) up to `root`?
///
/// RFC 9162 §2.1.3.2's walk, because 6962's unbalanced split means a leaf's
/// side at each level depends on the TREE SIZE, not on the index's bits alone
/// (leaf 4 of 5 has an even index but is a right child) — which is why
/// `leaf_count` is a required input and why every checkpoint payload carries
/// it. Bool with no early error, chain.rs's posture: the caller records
/// `inclusion_path_invalid` and keeps walking. A wrong-LENGTH path fails
/// structurally: the walk must consume the whole path AND exhaust the tree
/// (`sn == 0`) to accept.
pub fn verify_inclusion(
    leaf: &[u8; LEAF_LEN],
    index: usize,
    path: &[[u8; HASH_LEN]],
    root: &[u8; HASH_LEN],
    leaf_count: usize,
) -> bool {
    if index >= leaf_count {
        return false;
    }
    let (mut fn_, mut sn) = (index, leaf_count - 1);
    let mut node = leaf_hash(leaf);
    for sibling in path {
        if sn == 0 {
            return false;
        }
        if fn_ & 1 == 1 || fn_ == sn {
            node = node_hash(sibling, &node);
            if fn_ & 1 == 0 {
                while fn_ != 0 && fn_ & 1 == 0 {
                    fn_ >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            node = node_hash(&node, sibling);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    sn == 0 && constant_time_eq::constant_time_eq_32(&node, root)
}

pub fn verify_merkle_root(leaves: &[[u8; LEAF_LEN]], claimed_root: &[u8; HASH_LEN]) -> bool {
    match merkle_root(leaves) {
        Ok(root) => constant_time_eq::constant_time_eq_32(&root, claimed_root),
        Err(MerkleError::EmptyLeaves | MerkleError::IndexOutOfRange { .. }) => false,
    }
}

/// The checkpoint record's signed payload — field set frozen by the chain
/// vectors. `device_key_id` rides INSIDE the payload (the origin claim is
/// signed); `server_key_id` rides alongside as a row column, a lookup hint
/// and not a trust input (vectors README "Signatures"). `prev_receipt_hash`
/// is inside for ro_012's reason: signing the link is what makes position
/// part of the claim.
#[derive(Debug, Clone)]
pub struct CheckpointPayload<'a> {
    pub tenant_id: &'a str,
    pub seq: u64,
    pub prev_receipt_hash: [u8; 32],
    pub device_id: &'a str,
    pub device_key_id: &'a str,
    pub issued_at: &'a str,
    pub checkpoint_seq: u64,
    pub merkle_root: [u8; HASH_LEN],
    pub leaf_count: u64,
}

impl CheckpointPayload<'_> {
    pub fn to_value(&self) -> Value {
        json!({
            "v": PAYLOAD_VERSION,
            "type": "checkpoint",
            "tenant_id": self.tenant_id,
            "seq": self.seq,
            "prev_receipt_hash": hex::encode(&self.prev_receipt_hash),
            "device_id": self.device_id,
            "device_key_id": self.device_key_id,
            "issued_at": self.issued_at,
            "checkpoint_seq": self.checkpoint_seq,
            "merkle_root": hex::encode(&self.merkle_root),
            "leaf_count": self.leaf_count,
        })
    }
}

/// Sign one payload twice over ONE signing input (m1_002's column comment).
///
/// Device-only would let Omium disown a receipt; server-only would let Omium
/// mint history — dual signatures close both directions (m1_002 header).
/// Returns the row shape `chain::verify_chain` consumes, payload as the exact
/// signed text.
pub fn dual_sign(
    payload: &Value,
    device: &dyn Signer,
    server: &dyn Signer,
) -> Result<ReceiptRow, NonIntegerNumberError> {
    let payload_text = canonical::canonical_json(payload)?;
    let signing_input = canonical::signing_input_of(&payload_text);
    let seq = payload.get("seq").and_then(Value::as_u64).unwrap_or(0);
    Ok(ReceiptRow {
        seq,
        payload: payload_text,
        receipt_hash: canonical::hash_signing_input(&signing_input),
        device_key_id: Some(device.key_id()),
        device_signature: Some(device.sign(&signing_input)),
        server_key_id: server.key_id(),
        server_signature: server.sign(&signing_input),
    })
}
