//! Key-manifest intake at the edge (ADR-0004 rotation; 08 §3.5): a section
//! key not yet pinned is admitted ONLY through a cross-signature by a key
//! already pinned for that same section, and the manifest as a whole is
//! refused when the update key coincides with any bundle key (R5, 10 §8.3).
//! A refused manifest admits nothing — the pinned ring is untouched and the
//! caller keeps last-known-good.

use mark1_receipt::{derive_key_id, keys, CrossSig, KeyEntry};

use crate::{Section, SectionKeys};

/// The cross-signature domain (Go: receipts.CrossSignDomain).
pub const CROSS_SIGN_DOMAIN: &[u8] = b"mark1-key-rotation-v1\0";

/// `domain || role || 0x00 || public key`: the role is under the signature
/// (a server-chain endorsement cannot replay as a bundle one) and the
/// fixed-width key after the NUL closes splice ambiguity. Bundle roles are
/// `bundle:<section>`.
pub fn cross_sign_input(role: &str, public_key: &[u8; 32]) -> Vec<u8> {
    let mut out = CROSS_SIGN_DOMAIN.to_vec();
    out.extend_from_slice(role.as_bytes());
    out.push(0);
    out.extend_from_slice(public_key);
    out
}

/// One `bundle_section_keys` manifest entry as the caller parsed it.
#[derive(Debug, Clone)]
pub struct RotationEntry {
    pub section: Section,
    pub public_key: [u8; 32],
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub cross_sig: Option<CrossSig>,
}

/// Why a manifest was refused; `kind()` is the vectors' vocabulary, shared
/// with the publisher-side validator (controld policydist.ManifestReject).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RotationReject {
    #[error("update key {key_id} is also a bundle section key (R5)")]
    UpdateEqualsBundle { key_id: String },
    #[error("key {key_id} for {} carries no cross-signature", section.name())]
    Unsigned { section: Section, key_id: String },
    #[error("key {key_id} cross-signs itself")]
    SelfSigned { key_id: String },
    #[error("key {key_id} is cross-signed by {by}, which is not pinned for {}", section.name())]
    UnknownSigner {
        section: Section,
        key_id: String,
        by: String,
    },
    #[error("cross-signature on {key_id} by {by} does not verify")]
    BadCrossSignature { key_id: String, by: String },
}

impl RotationReject {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::UpdateEqualsBundle { .. } => "update_equals_bundle",
            Self::Unsigned { .. } => "unsigned",
            Self::SelfSigned { .. } => "self_signed",
            Self::UnknownSigner { .. } => "unknown_signer",
            Self::BadCrossSignature { .. } => "bad_cross_signature",
        }
    }
}

/// Applies a fetched manifest to the pinned ring. Returns the DERIVED ids of
/// the keys admitted; on any refusal `pinned` is left exactly as it was.
pub fn apply_rotation(
    pinned: &mut SectionKeys,
    bundle_keys: &[RotationEntry],
    update_keys: &[[u8; 32]],
) -> Result<Vec<String>, RotationReject> {
    for u in update_keys {
        if bundle_keys.iter().any(|b| b.public_key == *u) {
            return Err(RotationReject::UpdateEqualsBundle {
                key_id: derive_key_id(u),
            });
        }
    }
    let mut staged = pinned.clone();
    let mut admitted = Vec::new();
    for e in bundle_keys {
        let key_id = derive_key_id(&e.public_key);
        if staged.ring(e.section).contains(&key_id) {
            continue;
        }
        let Some(cs) = &e.cross_sig else {
            return Err(RotationReject::Unsigned {
                section: e.section,
                key_id,
            });
        };
        if cs.by_key_id == key_id {
            return Err(RotationReject::SelfSigned { key_id });
        }
        // Against `pinned`, not `staged`: a key admitted earlier in this same
        // manifest is not yet a root anyone has run under.
        let Some(signer) = pinned.ring(e.section).get(&cs.by_key_id) else {
            return Err(RotationReject::UnknownSigner {
                section: e.section,
                key_id,
                by: cs.by_key_id.clone(),
            });
        };
        let role = format!("bundle:{}", e.section.name());
        if !keys::verify(
            &signer.public_key,
            &cs.signature,
            &cross_sign_input(&role, &e.public_key),
        ) {
            return Err(RotationReject::BadCrossSignature {
                key_id,
                by: cs.by_key_id.clone(),
            });
        }
        let mut entry = KeyEntry::new(e.public_key, mark1_receipt::KeyRole::ServerChain);
        entry.not_before.clone_from(&e.not_before);
        entry.not_after.clone_from(&e.not_after);
        entry.cross_sig = Some(cs.clone());
        admitted.push(staged.insert(e.section, entry));
    }
    *pinned = staged;
    Ok(admitted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mark1_receipt::{Ed25519Signer, Signer};

    fn ring_with(section: Section, signer: &Ed25519Signer) -> SectionKeys {
        let mut k = SectionKeys::new();
        k.insert_public(section, signer.public_key());
        k
    }

    #[test]
    fn rotation_only_through_a_pinned_key() {
        let old = Ed25519Signer::from_seed([1; 32]);
        let new = Ed25519Signer::from_seed([2; 32]);
        let stranger = Ed25519Signer::from_seed([3; 32]);
        let entry = |by: &Ed25519Signer, role: &str| RotationEntry {
            section: Section::Verify,
            public_key: new.public_key(),
            not_before: None,
            not_after: None,
            cross_sig: Some(CrossSig {
                by_key_id: by.key_id(),
                signature: by.sign(&cross_sign_input(role, &new.public_key())),
            }),
        };
        let mut pinned = ring_with(Section::Verify, &old);
        let before = pinned.ring(Section::Verify).len();

        let e = entry(&new, "bundle:verify");
        assert_eq!(
            apply_rotation(&mut pinned, &[e], &[]).unwrap_err().kind(),
            "self_signed"
        );
        let e = entry(&stranger, "bundle:verify");
        assert_eq!(
            apply_rotation(&mut pinned, &[e], &[]).unwrap_err().kind(),
            "unknown_signer"
        );
        // Right signer, wrong role under the signature: a route endorsement
        // cannot admit a verify key.
        let e = entry(&old, "bundle:route");
        assert_eq!(
            apply_rotation(&mut pinned, &[e], &[]).unwrap_err().kind(),
            "bad_cross_signature"
        );
        // R5 refuses the whole manifest before anything is admitted.
        let e = entry(&old, "bundle:verify");
        assert_eq!(
            apply_rotation(&mut pinned, std::slice::from_ref(&e), &[new.public_key()])
                .unwrap_err()
                .kind(),
            "update_equals_bundle"
        );
        assert_eq!(
            pinned.ring(Section::Verify).len(),
            before,
            "a refusal must admit nothing"
        );

        let admitted = apply_rotation(&mut pinned, &[e], &[[9; 32]]).unwrap();
        assert_eq!(admitted, vec![new.key_id()]);
        assert!(pinned.ring(Section::Verify).contains(&new.key_id()));
        assert!(pinned.ring(Section::Verify).contains(&old.key_id()));
    }
}
