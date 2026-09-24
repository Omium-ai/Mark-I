//! Lowercase hex, the encoding every hash travels in INSIDE signed payloads
//! (`prev_receipt_hash`, `merkle_root` — vectors manifest throughout).
//! In-crate rather than a dependency: the verifier's trust surface is
//! deliberately small (rust/verifier Cargo.toml "nothing else, ever"), and
//! these are the few lines that keep it that way.

/// Lowercase hex — the only encoding this crate ever EMITS (Python
/// `bytes.hex()` parity; an uppercase digest inside a payload would change
/// the signed bytes).
pub fn encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}

/// Case-insensitive on decode (Python `bytes.fromhex` parity); `None` on odd
/// length or a non-hex byte — the caller decides which defect that is.
pub fn decode(s: &str) -> Option<Vec<u8>> {
    let raw = s.as_bytes();
    if !raw.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(raw.len() / 2);
    for pair in raw.chunks_exact(2) {
        out.push(nibble(pair[0])? << 4 | nibble(pair[1])?);
    }
    Some(out)
}

/// Decode into a fixed-size array; `None` on any decode failure OR a length
/// mismatch — a truncated hash must never pass as "a hash" (m1_002's length
/// CHECKs, applied at the parse boundary).
pub fn decode_array<const N: usize>(s: &str) -> Option<[u8; N]> {
    decode(s)?.try_into().ok()
}

fn nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
