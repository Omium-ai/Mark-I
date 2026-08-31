//! The sanitized encrypted spill ring (04 §5.4): when the daemon is
//! unreachable the event is not lost — it is redacted in-process (admit
//! axis, NO off switch), sealed to the device X25519 spill public key, and
//! appended to `~/.omium/mark1/spill/hookshim.ring` (0600). The private half
//! lives only in `mark1d.identity`, so a compromised or debugged shim can
//! leak at most the single in-flight event it was handed, never the ring's
//! history.

use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::ChaCha20Poly1305;
use hmac::{Hmac, Mac};
use mark1_redact::{AdmitOutcome, Scanner};
use sha2::Sha256;
use zeroize::Zeroize;

/// Ring record: `[u32 le record_len][ver=1][u64 le unix_secs][eph_pub 32]`
/// `[nonce 12][ciphertext]`. The timestamp is what lets the daemon apply the
/// ≤24 h TTL with receipted expiry (04 §5.4) without decrypting first.
const RECORD_VERSION: u8 = 1;

/// Domain label for the seal KDF: chacha key = HMAC-SHA256(DH shared
/// secret, label), so the raw group element never keys the AEAD directly.
const SEAL_LABEL: &[u8] = b"m1p.spill.seal.v1";

/// ponytail: writer-side hard cap; a daemon down long enough to fill 64 MiB
/// of tiny hook events is a support case, not a buffering problem. The
/// oldest-diagnostic-first eviction of 04 §5.4 belongs to mark1d's drain,
/// which owns the ring's other end; the writer only refuses to grow it.
const MAX_RING_BYTES: u64 = 64 * 1024 * 1024;

/// Sanitize, seal, append. Every failure inside is a silent drop of THIS
/// event only — never a raw write, never an agent-visible error (04 §5.4:
/// scanner failure ⇒ dropped and counted, never spilled raw; the count
/// surfaces via mark1d's ring-drain accounting, the shim owning no ledger).
pub fn append(home: Option<&Path>, mut frame: Vec<u8>) {
    let Some(home) = home else {
        frame.zeroize();
        return;
    };
    let base = home.join(".omium/mark1");

    // Admit axis BEFORE any byte hits the ring — invariant 5: no
    // pre-redaction plaintext persistence exists, even in the emergency
    // path. The redaction key is the daemon-materialized tenant key when
    // present; absent, the zero key still destroys the span (the hash leg
    // then only correlates per-device, which is the lesser property).
    let hmac_key = std::fs::read(base.join("redact.key")).unwrap_or_default();
    let Ok(scanner) = Scanner::new(&hmac_key) else {
        frame.zeroize();
        return;
    };
    if scanner.admit(&mut frame) == AdmitOutcome::Quarantine {
        frame.zeroize();
        return;
    }
    // A substitution inside an encoded frame can break its length prefix;
    // the daemon then quarantines the entry at drain. Redaction outranks
    // replay fidelity by contract (invariant 5), so that trade is correct.

    let Some(sealed) = seal(&base, &frame) else {
        frame.zeroize();
        return;
    };
    frame.zeroize();

    let dir = base.join("spill");
    if create_private_dir(&dir).is_err() {
        return;
    }
    let path = dir.join("hookshim.ring");
    let Ok(mut file) = open_private_append(&path) else {
        return;
    };
    if file
        .metadata()
        .map(|m| m.len() + sealed.len() as u64 > MAX_RING_BYTES)
        .unwrap_or(true)
    {
        // Every shed must be countable (07 §3: silence is the one failure the
        // loss ledger can't price) — and the shim owns no Batch surface, so
        // the count lives beside the ring: one byte appended per refused
        // event (O_APPEND keeps concurrent shims from losing increments; the
        // sidecar's LENGTH is the count, no read-modify-write to race).
        // mark1d's drain converts it to Dropped{RING_EVICTED} — 04 §5.4's
        // reason for ring-overflow loss — and truncates the sidecar.
        if let Ok(mut shed) = open_private_append(&dir.join("hookshim.ring.shed")) {
            let _ = shed.write_all(&[1]);
        }
        return;
    }
    // One write_all per record: appends up to PIPE_BUF-ish sizes are atomic
    // enough for a single-writer-per-process file, and mark1d only ever
    // truncates after a full drain (04 §5), so torn tails are drain-skipped.
    let _ = file.write_all(&sealed);
}

/// One fail-open gate answer, counted (08 §4.4: a `GateQuery` timeout means
/// the shim returns allow AND emits `Dropped{reason: gate_timeout}`).
///
/// `Dropped` rides on `Batch.dropped`, never inside `Event.body` (07 §2), and
/// the shim owns no Batch surface — so this takes the same shape the
/// ring-overflow shed already uses (04 §5.4): one byte per event in an
/// O_APPEND sidecar, whose LENGTH is the count, no read-modify-write to race
/// between concurrent shims. mark1d's drain converts the `.shed` sidecar to
/// `Dropped{RING_EVICTED}`; the equivalent conversion of this file to
/// `Dropped{GATE_TIMEOUT}` is the daemon's half and does not exist yet — an
/// uncounted fail-open is the one thing worse than a counted one.
pub fn count_gate_timeout(home: Option<&Path>) {
    count(home, "hookshim.gate_timeout");
}

/// `M1E-4003` — mark1d refused this connection's handshake and closed it
/// (08 §4.3 steps 2-3). Same sidecar shape, because the alternative is what
/// this was before: a fleet-wide refusal after a bad rollout, every event
/// spilling, and no signal anywhere that the handshake is the reason.
pub fn count_handshake_refused(home: Option<&Path>) {
    count(home, "hookshim.handshake_refused");
}

fn count(home: Option<&Path>, name: &str) {
    let Some(home) = home else { return };
    let dir = home.join(".omium/mark1/spill");
    if create_private_dir(&dir).is_err() {
        return;
    }
    if let Ok(mut f) = open_private_append(&dir.join(name)) {
        let _ = f.write_all(&[1]);
    }
}

/// Seal to the device spill public key. No key on disk ⇒ no spill at all:
/// an unencrypted ring is the one thing this module must never produce.
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
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(unix)]
fn open_private_append(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    // 0600 at creation (07 §5 / 04 §5.4), not chmod-after: no window where
    // another user could open the ring.
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
    // Windows privacy is the profile DACL until the named pipe lands — a
    // weaker guarantee than the 0600 unix path, stated as such. Same
    // unsanctioned gap as fabric::send (D-CA/D-CD), not a scheduled lane.
    std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)
}
