//! Canonical CBOR (RFC 8949 §4.2.1) for PolicyBundle v1 — 07 §"PolicyBundle
//! v1": definite lengths, minimal-length heads, bytewise-sorted map keys,
//! preferred (shortest lossless) float serialization.
//!
//! WHY re-encode-and-compare instead of a tolerant parse: 07 fixes canonical
//! form so "a section's bytes are a pure function of its content and section
//! signatures are stable across encoders". A decoder that accepts a
//! non-canonical encoding accepts a second byte representation of the same
//! bundle — i.e. a signature-stable content with signature-UNSTABLE bytes,
//! which is exactly the drift the vectors exist to forbid. Non-canonical input
//! is therefore an M1E-3001-class rejection, never repaired.

use ciborium::value::Value;

/// Nesting bound for the encoder walk. The deepest production in 07's CDDL is
/// ~6 levels; 32 leaves headroom for a v1.x while keeping hostile deep nesting
/// (a stack-exhaustion vector, 12 §4's fuzz posture) structurally impossible.
/// The ciborium decode side uses the same bound (`lib.rs`).
pub const MAX_DEPTH: usize = 32;

/// Why a byte buffer failed the canonical-form contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonError {
    /// Two map entries share one key — canonical maps are strictly sorted, so
    /// a duplicate cannot be expressed and must not survive decode (a dup is
    /// how "the second value wins in parser A, the first in parser B" splits
    /// two implementations on one bundle).
    DuplicateKey,
    /// Nesting beyond [`MAX_DEPTH`].
    TooDeep,
    /// An integer outside CBOR's major-0/major-1 range (unreachable from a
    /// decode of well-formed CBOR; kept as an error, not a panic, because the
    /// encoder is also fed generator-built Values).
    IntRange,
    /// A Value variant with no canonical encoding in this schema (ciborium's
    /// non-exhaustive extras).
    Unsupported,
}

impl std::fmt::Display for CanonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::DuplicateKey => "duplicate map key",
            Self::TooDeep => "nesting exceeds MAX_DEPTH",
            Self::IntRange => "integer outside CBOR range",
            Self::Unsupported => "value has no canonical encoding",
        };
        f.write_str(s)
    }
}

impl std::error::Error for CanonError {}

/// Deterministic encoding of `v` per RFC 8949 §4.2.1. Map entries are sorted
/// by the bytewise order of their encoded keys (and rejected on duplicates),
/// so `encode_canonical(decode(raw)) == raw` if and only if `raw` was
/// canonical — the whole canonical-form check is that one byte comparison.
pub fn encode_canonical(v: &Value) -> Result<Vec<u8>, CanonError> {
    let mut out = Vec::new();
    encode_into(v, &mut out, 0)?;
    Ok(out)
}

fn head(major: u8, arg: u64, out: &mut Vec<u8>) {
    let m = major << 5;
    match arg {
        0..=23 => out.push(m | arg as u8),
        24..=0xff => out.extend_from_slice(&[m | 24, arg as u8]),
        0x100..=0xffff => {
            out.push(m | 25);
            out.extend_from_slice(&(arg as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(m | 26);
            out.extend_from_slice(&(arg as u32).to_be_bytes());
        }
        _ => {
            out.push(m | 27);
            out.extend_from_slice(&arg.to_be_bytes());
        }
    }
}

fn encode_into(v: &Value, out: &mut Vec<u8>, depth: usize) -> Result<(), CanonError> {
    if depth > MAX_DEPTH {
        return Err(CanonError::TooDeep);
    }
    match v {
        Value::Integer(i) => {
            let i = i128::from(*i);
            if i >= 0 {
                head(0, u64::try_from(i).map_err(|_| CanonError::IntRange)?, out);
            } else {
                head(
                    1,
                    u64::try_from(-1 - i).map_err(|_| CanonError::IntRange)?,
                    out,
                );
            }
        }
        Value::Bytes(b) => {
            head(2, b.len() as u64, out);
            out.extend_from_slice(b);
        }
        Value::Text(t) => {
            head(3, t.len() as u64, out);
            out.extend_from_slice(t.as_bytes());
        }
        Value::Array(items) => {
            head(4, items.len() as u64, out);
            for item in items {
                encode_into(item, out, depth + 1)?;
            }
        }
        Value::Map(entries) => {
            // Sort by encoded-key bytes (§4.2.1's key order); adjacent equals
            // after the sort are the duplicate-key rejection.
            let mut encoded: Vec<(Vec<u8>, &Value)> = Vec::with_capacity(entries.len());
            for (k, val) in entries {
                let mut kb = Vec::new();
                encode_into(k, &mut kb, depth + 1)?;
                encoded.push((kb, val));
            }
            encoded.sort_by(|a, b| a.0.cmp(&b.0));
            if encoded.windows(2).any(|w| w[0].0 == w[1].0) {
                return Err(CanonError::DuplicateKey);
            }
            head(5, encoded.len() as u64, out);
            for (kb, val) in encoded {
                out.extend_from_slice(&kb);
                encode_into(val, out, depth + 1)?;
            }
        }
        Value::Tag(t, inner) => {
            head(6, *t, out);
            encode_into(inner, out, depth + 1)?;
        }
        Value::Bool(b) => out.push(if *b { 0xf5 } else { 0xf4 }),
        Value::Null => out.push(0xf6),
        Value::Float(f) => encode_float(*f, out),
        _ => return Err(CanonError::Unsupported),
    }
    Ok(())
}

/// Preferred serialization (§4.2.1): the shortest float width that preserves
/// the value exactly; NaN canonicalizes to the half-width quiet NaN 0xf97e00
/// (payloads dropped — two NaNs must not be two encodings).
fn encode_float(f: f64, out: &mut Vec<u8>) {
    if f.is_nan() {
        out.extend_from_slice(&[0xf9, 0x7e, 0x00]);
        return;
    }
    let as32 = f as f32;
    if f64::from(as32) == f {
        if let Some(h) = f32_to_f16_lossless(as32) {
            out.push(0xf9);
            out.extend_from_slice(&h.to_be_bytes());
            return;
        }
        out.push(0xfa);
        out.extend_from_slice(&as32.to_be_bytes());
        return;
    }
    out.push(0xfb);
    out.extend_from_slice(&f.to_be_bytes());
}

/// f32 → binary16 bits, only when the conversion is exact (the "preserves the
/// value" precondition for emitting the 2-byte form). NaN never reaches here.
fn f32_to_f16_lossless(x: f32) -> Option<u16> {
    let bits = x.to_bits();
    let sign = ((bits >> 16) & 0x8000) as u16;
    let exp = ((bits >> 23) & 0xff) as i32;
    let man = bits & 0x007f_ffff;
    if exp == 0 {
        // f32 zero is f16 zero; f32 subnormals (< 2^-126) are far below f16's
        // subnormal floor (2^-24) and can never be exact.
        return if man == 0 { Some(sign) } else { None };
    }
    if exp == 0xff {
        // ±infinity (NaN was handled by the caller).
        return if man == 0 { Some(sign | 0x7c00) } else { None };
    }
    let e = exp - 127;
    if (-14..=15).contains(&e) {
        // Normal f16: the 23-bit mantissa must fit in 10 bits.
        if man & 0x1fff != 0 {
            return None;
        }
        return Some(sign | (((e + 15) as u16) << 10) | (man >> 13) as u16);
    }
    if (-24..=-15).contains(&e) {
        // Subnormal f16: value = m16 * 2^-24 with the f32 significand
        // (implicit leading 1) shifted down; every dropped bit must be zero.
        let full = 0x0080_0000 | man;
        let sh = u32::try_from(-(e + 1)).unwrap_or(u32::MAX); // 14..=23
        if full & ((1u32 << sh) - 1) == 0 {
            let m16 = full >> sh;
            if (1..=0x3ff).contains(&m16) {
                return Some(sign | m16 as u16);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(raw: &[u8]) -> Value {
        ciborium::de::from_reader(raw).unwrap()
    }

    #[test]
    fn minimal_heads_and_sorted_maps_roundtrip() {
        // A canonical buffer survives decode → encode byte-identically.
        let raw: &[u8] = &[
            0xa2, // map(2)
            0x61, b'a', 0x01, // "a": 1
            0x61, b'b', 0x82, 0x18, 0x18, 0xf6, // "b": [24, null]
        ];
        assert_eq!(encode_canonical(&decode(raw)).unwrap(), raw);
    }

    #[test]
    fn non_minimal_int_head_is_detected() {
        // 0x1801 encodes 1 in two bytes; canonical is the one-byte 0x01.
        let raw: &[u8] = &[0x18, 0x01];
        assert_ne!(encode_canonical(&decode(raw)).unwrap(), raw);
    }

    #[test]
    fn unsorted_map_is_detected() {
        let raw: &[u8] = &[0xa2, 0x61, b'b', 0x01, 0x61, b'a', 0x02];
        assert_ne!(encode_canonical(&decode(raw)).unwrap(), raw);
    }

    #[test]
    fn duplicate_key_is_rejected() {
        let raw: &[u8] = &[0xa2, 0x61, b'a', 0x01, 0x61, b'a', 0x02];
        assert_eq!(
            encode_canonical(&decode(raw)),
            Err(CanonError::DuplicateKey)
        );
    }

    #[test]
    fn indefinite_length_is_detected() {
        let raw: &[u8] = &[0x9f, 0x01, 0xff]; // indefinite array [1]
        assert_ne!(encode_canonical(&decode(raw)).unwrap(), raw);
    }

    #[test]
    fn float_widths_are_shortest_lossless() {
        for (f, bytes) in [
            (0.5f64, vec![0xf9, 0x38, 0x00]),
            (f64::INFINITY, vec![0xf9, 0x7c, 0x00]),
            (f64::NAN, vec![0xf9, 0x7e, 0x00]),
            // 0.1 is not exact in f32; full f64 width required.
            (0.1f64, {
                let mut v = vec![0xfb];
                v.extend_from_slice(&0.1f64.to_be_bytes());
                v
            }),
            // 2^-140 is an f32 subnormal: exact at 4 bytes, inexpressible at 2.
            ((-140.0f64).exp2(), {
                let mut v = vec![0xfa];
                v.extend_from_slice(&((-140.0f32).exp2()).to_be_bytes());
                v
            }),
            // Smallest f16 subnormal.
            ((-24.0f64).exp2(), vec![0xf9, 0x00, 0x01]),
        ] {
            let mut out = Vec::new();
            encode_float(f, &mut out);
            assert_eq!(out, bytes, "float {f}");
        }
    }

    #[test]
    fn depth_bound_holds() {
        let mut v = Value::Integer(1.into());
        for _ in 0..(MAX_DEPTH + 2) {
            v = Value::Array(vec![v]);
        }
        assert_eq!(encode_canonical(&v), Err(CanonError::TooDeep));
    }

    proptest::proptest! {
        // decode(encode(v)) == v for schema-shaped scalars/containers, and the
        // re-encode of that decode is byte-stable — the fixpoint the canonical
        // check relies on.
        #[test]
        fn prop_encode_decode_fixpoint(ints in proptest::collection::vec(proptest::num::i64::ANY, 0..8),
                                       f in proptest::num::f64::ANY,
                                       s in "[a-z0-9_.-]{0,16}") {
            let v = Value::Map(vec![
                (Value::Text("a".into()), Value::Array(ints.iter().map(|i| Value::Integer((*i).into())).collect())),
                (Value::Text("b".into()), Value::Float(f)),
                (Value::Text("c".into()), Value::Text(s)),
            ]);
            let bytes = encode_canonical(&v).unwrap();
            let back: Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
            let again = encode_canonical(&back).unwrap();
            proptest::prop_assert_eq!(bytes, again);
        }
    }
}
