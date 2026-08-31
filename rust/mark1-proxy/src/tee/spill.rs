//! The sanitized encrypted spill ring — 04 §5.4, writer half.
//!
//! Same record format and same device key as the hookshim's ring, a different file:
//! `~/.omium/mark1/spill/proxy.ring`. The two writers are separate processes with separate
//! lifetimes, and mark1d's drain reads whatever rings it finds.
//!
//! Why the proxy needs one at all, when 04 §3.5 says the observation plane fails open: the
//! contamination alert (§3.1 step 6, D-AI) is the P0 record that a subscription credential
//! reached this binary. Dropping it because the daemon happened to be restarting turns the
//! one event that must be provable into the one event that is missing. Ordinary tee reports
//! are *not* spilled — they are counted and dropped, which is what fail-open means.

use std::io::Write;
use std::path::Path;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::ChaCha20Poly1305;
use hmac::{Hmac, Mac};
use mark1_redact::{AdmitOutcome, Scanner};
use sha2::Sha256;
use zeroize::Zeroize;

const RECORD_VERSION: u8 = 1;
const SEAL_LABEL: &[u8] = b"m1p.spill.seal.v1";
const MAX_RING_BYTES: u64 = 64 * 1024 * 1024;

/// Redact, seal, append. Every internal failure drops **this record only**, silently: an
/// unsealed or unredacted byte on disk is the one outcome this function may not produce.
///
/// `base` is `~/.omium/mark1`.
pub fn append(base: &Path, mut frame: Vec<u8>) {
    // Invariant 5 (no pre-redaction plaintext persistence) has no exception for the emergency
    // path. The admit axis is not the configurable redact-in-transit axis of §3.2; it has no
    // off switch and does not consult policy.
    let Some(scanner) = scanner(base) else {
        frame.zeroize();
        return;
    };
    if scanner.admit(&mut frame) == AdmitOutcome::Quarantine {
        frame.zeroize();
        return;
    }

    let sealed = seal(base, &frame);
    frame.zeroize();
    let Some(sealed) = sealed else { return };

    let dir = base.join("spill");
    if create_private_dir(&dir).is_err() {
        return;
    }
    let Ok(mut file) = open_private_append(&dir.join("proxy.ring")) else {
        return;
    };
    // `unwrap_or(true)` — an unreadable length is treated as full. Growing a file whose size
    // we cannot see is how a 64 MiB cap becomes a disk-full incident.
    if file
        .metadata()
        .map(|m| m.len() + sealed.len() as u64 > MAX_RING_BYTES)
        .unwrap_or(true)
    {
        if let Ok(mut shed) = open_private_append(&dir.join("proxy.ring.shed")) {
            let _ = shed.write_all(&[1]);
        }
        return;
    }
    let _ = file.write_all(&sealed);
}

/// The process-wide redaction scanner. `Scanner::new` compiles the whole rule set's regexes —
/// `mark1-redact`'s own tests cache it in a `OnceLock` for the same reason — and building one
/// per record cost 36 ms and megabytes of RSS *per emitted frame*, which `benches/latency.rs`
/// is what surfaced.
///
/// ponytail: initialized from the first `base` this process spills to, so a rotated
/// `redact.key` takes effect at the next proxy start. Upgrade path is a key-mtime check, and
/// the failure it would fix is a redaction placeholder computed under a stale HMAC key — not
/// an unredacted byte, which this cache cannot cause.
fn scanner(base: &Path) -> Option<&'static Scanner> {
    static SCANNER: OnceLock<Option<Scanner>> = OnceLock::new();
    SCANNER
        .get_or_init(|| {
            let mut key = std::fs::read(base.join("redact.key")).unwrap_or_default();
            let scanner = Scanner::new(&key).ok();
            key.zeroize();
            scanner
        })
        .as_ref()
}

/// Seal to the device spill public key. No key on disk ⇒ no spill: this module must never
/// produce an unencrypted ring entry, and "the key was missing" is not a reason to.
fn seal(base: &Path, plaintext: &[u8]) -> Option<Vec<u8>> {
    let raw = std::fs::read(base.join("spill/spill.pub")).ok()?;
    let device_pub = x25519_dalek::PublicKey::from(<[u8; 32]>::try_from(raw.as_slice()).ok()?);

    let ephemeral = x25519_dalek::EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_pub = x25519_dalek::PublicKey::from(&ephemeral);
    let shared = ephemeral.diffie_hellman(&device_pub);
    let mut kdf = <Hmac<Sha256> as Mac>::new_from_slice(shared.as_bytes()).ok()?;
    kdf.update(SEAL_LABEL);
    let mut key_bytes: [u8; 32] = kdf.finalize().into_bytes().into();

    let cipher = ChaCha20Poly1305::new((&key_bytes).into());
    key_bytes.zeroize();
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, plaintext).ok()?;

    let unix_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    let record_len = 1 + 8 + 32 + 12 + ciphertext.len();
    let mut out = Vec::with_capacity(4 + record_len);
    out.extend_from_slice(&(record_len as u32).to_le_bytes());
    out.push(RECORD_VERSION);
    out.extend_from_slice(&unix_secs.to_le_bytes());
    out.extend_from_slice(ephemeral_pub.as_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Some(out)
}

#[cfg(unix)]
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    match std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
    {
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        other => other,
    }
}

#[cfg(unix)]
fn open_private_append(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    // 0600 at creation, not chmod-after: no window in which another user can open the ring.
    std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)
}

#[cfg(not(unix))]
fn open_private_append(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No `spill.pub` ⇒ nothing is written. The failure mode this rules out is the one that
    /// matters: a fallback that writes plaintext when sealing is impossible.
    #[test]
    fn without_a_device_key_nothing_is_written() {
        let tmp = tempfile::tempdir().unwrap();
        append(tmp.path(), b"contamination alert plaintext".to_vec());
        assert!(!tmp.path().join("spill/proxy.ring").exists());
    }

    #[test]
    fn sealed_record_is_framed_and_contains_no_plaintext() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("spill")).unwrap();
        let secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let public = x25519_dalek::PublicKey::from(&secret);
        std::fs::write(tmp.path().join("spill/spill.pub"), public.as_bytes()).unwrap();

        let marker = b"sk-ant-oat01-CONTAMINATIONMARKER".to_vec();
        append(tmp.path(), marker.clone());

        let ring = std::fs::read(tmp.path().join("spill/proxy.ring")).unwrap();
        let len = u32::from_le_bytes(ring[..4].try_into().unwrap()) as usize;
        assert_eq!(
            ring.len(),
            4 + len,
            "record_len must frame the record exactly"
        );
        assert_eq!(ring[4], RECORD_VERSION);
        assert!(
            !ring.windows(marker.len()).any(|w| w == marker.as_slice()),
            "plaintext survived into the ring"
        );
    }
}
