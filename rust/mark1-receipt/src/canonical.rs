//! The exact bytes a Mark 1 receipt is signed over, and the hash derived from
//! them.
//!
//! VENDORED from recovery-orchestrator's `app/receipts/canonical.py` (copied
//! 2026-08-29). The estate's rules, kept verbatim (07 "The receipt chain",
//! conformance/vectors/receipt/README.md "Canonical bytes"):
//!
//!   * `json.dumps(payload, sort_keys=True, separators=(",",":"),
//!     ensure_ascii=True)`, reproduced byte-for-byte — key order is code-point
//!     order (which UTF-8 byte order agrees with), `\uXXXX` escapes for every
//!     non-ASCII character (surrogate PAIRS for astral ones), short escapes
//!     where JSON has them, `\u00XX` for the remaining controls.
//!   * The domain prefix `mark1-label-v1\0` — the ONE deliberate change from
//!     the vendor source's `omium-receipt-v1\0`; the trailing NUL stops the
//!     prefix from prefixing a future `...-v1x` scheme.
//!   * `receipt_hash` covers the SIGNING INPUT, prefix included: a verifier
//!     that recomputed the hash has by construction recomputed the exact
//!     bytes it hands to the signature check.
//!
//! One rule is new relative to the vendor source, added by the vectors README
//! ("Numbers: integers only"): a payload carrying a non-integer number is
//! REFUSED, never rendered. Cross-language float rendering is not
//! deterministic (repr vs strconv vs ryu), so a float in a payload is a
//! forgery generator.

use serde_json::Value;
use sha2::{Digest, Sha256};

pub const DOMAIN_PREFIX: &[u8] = b"mark1-label-v1\0";

pub const PAYLOAD_VERSION: u64 = 1;

pub const GENESIS_HASH: [u8; 32] = [0u8; 32];

/// A payload carried a non-integer number. Refused, never rounded or rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "payload contains a non-integer number; the receipt contract is integers-only \
     (conformance/vectors/receipt/README.md)"
)]
pub struct NonIntegerNumberError;

/// Python's `json.dumps(payload, sort_keys=True, separators=(",",":"),
/// ensure_ascii=True)`, byte-identically — the one serialisation.
pub fn canonical_json(payload: &Value) -> Result<String, NonIntegerNumberError> {
    let mut out = String::new();
    write_value(&mut out, payload)?;
    Ok(out)
}

/// The signing input: domain prefix || canonical JSON of the payload.
pub fn canonical_bytes(payload: &Value) -> Result<Vec<u8>, NonIntegerNumberError> {
    Ok(signing_input_of(&canonical_json(payload)?))
}

/// The signing input for ALREADY-SERIALISED payload text — the stored `payload`
/// column is the exact bytes that were signed (m1_002), so the chain walk
/// prefixes the text as it sits and never re-serialises before hashing.
pub fn signing_input_of(payload_text: &str) -> Vec<u8> {
    let mut input = Vec::with_capacity(DOMAIN_PREFIX.len() + payload_text.len());
    input.extend_from_slice(DOMAIN_PREFIX);
    input.extend_from_slice(payload_text.as_bytes());
    input
}

/// SHA-256 over the same bytes that are signed — 32 bytes (estate
/// `canonical.py`'s rule: the hash covers the signing input, prefix included).
pub fn receipt_hash(payload: &Value) -> Result<[u8; 32], NonIntegerNumberError> {
    Ok(hash_signing_input(&canonical_bytes(payload)?))
}

/// SHA-256 of a signing input built from stored bytes (the chain walk's side).
pub fn hash_signing_input(signing_input: &[u8]) -> [u8; 32] {
    Sha256::digest(signing_input).into()
}

// Recursive over the Value tree. Depth is bounded in practice: values obtained
// by parsing went through serde_json's own recursion limit (128), and built
// payloads are this codebase's fixed shapes.
fn write_value(out: &mut String, value: &Value) -> Result<(), NonIntegerNumberError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => {
            // i64/u64 render identically across Python/Go/Rust. Beyond them,
            // arbitrary_precision (Cargo.toml) preserves the source text, and
            // the strict integer grammar below is the same fence Go's
            // integerForm holds: "1.0"/"1e2"/"-0"/leading zeros are forms
            // Python's int printer never emits, so letting one through would
            // sign bytes no other leg can reproduce (README "integers only";
            // the big_int and huge_int vectors are the referees).
            if let Some(i) = n.as_i64() {
                out.push_str(&i.to_string());
            } else if let Some(u) = n.as_u64() {
                out.push_str(&u.to_string());
            } else {
                let text = n.to_string();
                if !integer_form(&text) {
                    return Err(NonIntegerNumberError);
                }
                out.push_str(&text);
            }
        }
        Value::String(s) => write_escaped(out, s),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, item)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            // Keys sorted HERE, not by trusting the map's iteration order:
            // serde_json's map becomes insertion-ordered if any crate in the
            // build unifies the `preserve_order` feature, and canonical bytes
            // must not depend on a feature flag someone else flips. `str` Ord
            // is UTF-8 byte order == code-point order == Python's sort_keys
            // (README "Canonical bytes"; the `unicode` vector proves it).
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_escaped(out, key);
                out.push(':');
                // Maps cannot hold duplicate keys, so index/get cannot miss.
                if let Some(v) = map.get(*key) {
                    write_value(out, v)?;
                }
            }
            out.push('}');
        }
    }
    Ok(())
}

// Python's ensure_ascii escaper (json/encoder.py ESCAPE_ASCII): everything
// outside 0x20..=0x7E is escaped; `\b \t \n \f \r` get JSON's short escapes;
// astral characters become UTF-16 surrogate PAIRS; hex digits are lowercase.
fn write_escaped(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{0c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            '\u{20}'..='\u{7e}' => out.push(c),
            _ => {
                let cp = c as u32;
                if cp <= 0xFFFF {
                    push_u_escape(out, cp);
                } else {
                    let v = cp - 0x1_0000;
                    push_u_escape(out, 0xD800 + (v >> 10));
                    push_u_escape(out, 0xDC00 + (v & 0x3FF));
                }
            }
        }
    }
    out.push('"');
}

fn push_u_escape(out: &mut String, cp: u32) {
    out.push_str("\\u");
    out.push_str(&crate::hex::encode(&[(cp >> 8) as u8, cp as u8]));
}

// Strict integer grammar: optional '-', digits, no leading zeros, no '-0' —
// exactly what Python's int printer emits and Go's integerForm accepts.
fn integer_form(s: &str) -> bool {
    let digits = s.strip_prefix('-').unwrap_or(s);
    if s.starts_with('-') && digits == "0" {
        return false;
    }
    if digits.is_empty() || (digits.len() > 1 && digits.starts_with('0')) {
        return false;
    }
    digits.bytes().all(|b| b.is_ascii_digit())
}
