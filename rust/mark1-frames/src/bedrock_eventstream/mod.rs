//! AWS Bedrock `application/vnd.amazon.eventstream` (04 §4): `total_len u32 | headers_len u32 | prelude_crc u32 | headers | payload | message_crc u32`, CRC-32/IEEE.
//!
//! Observe-only upstream (04 §3.4): SigV4 signs the body, so the proxy never rewrites it and `RouteDecision` is never `WIRE_ENFORCED` here.
//! Two grammars ride the framing — `chunk` events (InvokeModelWithResponseStream) carry base64 Anthropic events, Converse events carry `metadata.usage`.

use serde::Deserialize;

use crate::anthropic_sse::AnthropicSse;
use crate::{DegradeReason, DialectParser, ParseDegraded, WireObservation, WireUsage};

/// Bumped with a new golden fixture on any framing or payload grammar change; independent of every other dialect's rev.
pub const DIALECT_REV: &str = "bedrock-eventstream@1";

/// One in-progress message; above the tee's own 8 MiB budget only in principle, never in practice (Bedrock chunks are ≤ KiBs).
const MAX_PENDING_BYTES: usize = 1 << 20;
const PRELUDE: usize = 12;

pub fn parser() -> impl DialectParser {
    BedrockEventstream::new()
}

pub struct BedrockEventstream {
    pending: Vec<u8>,
    /// Stream offset of `pending[0]`.
    consumed: u64,
    /// `chunk` payloads are Anthropic events; this holds the `message_start` snapshot exactly as the SSE parser does.
    anthropic: AnthropicSse,
    degraded: Option<ParseDegraded>,
}

impl Default for BedrockEventstream {
    fn default() -> Self {
        Self::new()
    }
}

impl BedrockEventstream {
    pub fn new() -> Self {
        BedrockEventstream {
            pending: Vec::new(),
            consumed: 0,
            anthropic: AnthropicSse::new(),
            degraded: None,
        }
    }

    fn degrade(&mut self, at_byte: u64, reason: DegradeReason) {
        self.degraded = Some(ParseDegraded { at_byte, reason });
    }

    /// One framed message, CRCs verified. `Err` ⇒ the frame is not one the vendor wrote.
    fn message(&mut self, msg: &[u8], out: &mut Vec<WireObservation>) -> Result<(), ()> {
        let headers_len = u32::from_be_bytes([msg[4], msg[5], msg[6], msg[7]]) as usize;
        if crc32(&msg[..8]) != be32(&msg[8..12])?
            || crc32(&msg[..msg.len() - 4]) != be32(&msg[msg.len() - 4..])?
            || PRELUDE + headers_len + 4 > msg.len()
        {
            return Err(());
        }
        let (headers, payload) = (
            &msg[PRELUDE..PRELUDE + headers_len],
            &msg[PRELUDE + headers_len..msg.len() - 4],
        );
        let (mut message_type, mut event_type, mut exception_type) = (None, None, None);
        for (name, value) in string_headers(headers)? {
            match name {
                ":message-type" => message_type = Some(value),
                ":event-type" => event_type = Some(value),
                ":exception-type" | ":error-code" => exception_type = Some(value),
                _ => {}
            }
        }
        match (message_type.ok_or(())?, event_type) {
            ("event", Some("chunk")) => {
                let c: Chunk = serde_json::from_slice(payload).map_err(|_| ())?;
                let inner = base64_decode(c.bytes.as_bytes())?;
                let ev: Typed = serde_json::from_slice(&inner).map_err(|_| ())?;
                self.anthropic.handle_event(&ev.r#type, &inner, out)
            }
            ("event", Some("metadata")) => {
                let m: Metadata = serde_json::from_slice(payload).map_err(|_| ())?;
                out.push(WireObservation::Usage(WireUsage {
                    input_tokens: m.usage.input_tokens,
                    output_tokens: m.usage.output_tokens,
                    cache_creation_input_tokens: m.usage.cache_write_input_tokens,
                    cache_read_input_tokens: m.usage.cache_read_input_tokens,
                    ..WireUsage::default()
                }));
                Ok(())
            }
            ("event", Some("messageStop")) => {
                let s: MessageStop = serde_json::from_slice(payload).map_err(|_| ())?;
                out.push(WireObservation::ResponseEnd {
                    stop_reason: s.stop_reason,
                });
                Ok(())
            }
            ("exception" | "error", _) => {
                out.push(WireObservation::UpstreamError {
                    error_type: exception_type.unwrap_or("unknown").to_owned(),
                });
                Ok(())
            }
            // Other Converse events carry no billing fact and are skipped without inspection.
            _ => Ok(()),
        }
    }
}

impl DialectParser for BedrockEventstream {
    /// Deferred degradation, as the SSE parser: found during this call, surfaced on the next, so chunking cannot change the result.
    fn feed(&mut self, chunk: &[u8]) -> Result<Vec<WireObservation>, ParseDegraded> {
        if let Some(d) = self.degraded {
            return Err(d);
        }
        if self.pending.len() + chunk.len() > MAX_PENDING_BYTES {
            self.degrade(
                self.consumed + self.pending.len() as u64,
                DegradeReason::PendingBufferOverflow,
            );
            return Ok(Vec::new());
        }
        self.pending.extend_from_slice(chunk);
        let mut out = Vec::new();
        while self.pending.len() >= PRELUDE {
            let total = u32::from_be_bytes([
                self.pending[0],
                self.pending[1],
                self.pending[2],
                self.pending[3],
            ]) as usize;
            if total < PRELUDE + 4 {
                self.degrade(self.consumed, DegradeReason::MalformedEvent);
                break;
            }
            // Refused at the prelude: a declared length past the cap is never retained.
            if total > MAX_PENDING_BYTES {
                self.degrade(self.consumed, DegradeReason::PendingBufferOverflow);
                break;
            }
            if self.pending.len() < total {
                break;
            }
            let msg: Vec<u8> = self.pending.drain(..total).collect();
            if self.message(&msg, &mut out).is_err() {
                self.degrade(self.consumed, DegradeReason::MalformedEvent);
                break;
            }
            self.consumed += total as u64;
        }
        Ok(out)
    }

    fn finish(&mut self) -> Result<Vec<WireObservation>, ParseDegraded> {
        if let Some(d) = self.degraded {
            return Err(d);
        }
        // A partial message at EOF is a cancelled or reset stream, not vendor drift.
        Ok(Vec::new())
    }

    fn dialect_rev(&self) -> &'static str {
        DIALECT_REV
    }
}

#[derive(Deserialize)]
struct Chunk {
    bytes: String,
}

#[derive(Deserialize)]
struct Typed {
    r#type: String,
}

#[derive(Deserialize)]
struct Metadata {
    usage: ConverseUsage,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConverseUsage {
    #[serde(default)]
    input_tokens: u64,
    #[serde(default)]
    output_tokens: u64,
    #[serde(default)]
    cache_read_input_tokens: u64,
    #[serde(default)]
    cache_write_input_tokens: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MessageStop {
    #[serde(default)]
    stop_reason: String,
}

fn be32(b: &[u8]) -> Result<u32, ()> {
    Ok(u32::from_be_bytes(b.try_into().map_err(|_| ())?))
}

/// String-typed (type 7) headers only; every other type is skipped by its fixed or prefixed length.
fn string_headers(mut h: &[u8]) -> Result<Vec<(&str, &str)>, ()> {
    let mut out = Vec::new();
    while !h.is_empty() {
        let name_len = h[0] as usize;
        let name = std::str::from_utf8(h.get(1..1 + name_len).ok_or(())?).map_err(|_| ())?;
        h = &h[1 + name_len..];
        let (kind, rest) = h.split_first().ok_or(())?;
        let value_len = match kind {
            0 | 1 => 0,
            2 => 1,
            3 => 2,
            4 => 4,
            5 | 8 => 8,
            9 => 16,
            6 | 7 => {
                2 + u16::from_be_bytes([*rest.first().ok_or(())?, *rest.get(1).ok_or(())?]) as usize
            }
            _ => return Err(()),
        };
        let value = rest.get(..value_len).ok_or(())?;
        if *kind == 7 {
            out.push((name, std::str::from_utf8(&value[2..]).map_err(|_| ())?));
        }
        h = &rest[value_len..];
    }
    Ok(out)
}

// ponytail: bitwise CRC-32/IEEE, no table; Bedrock messages are small and this runs on the tee thread, never the forward path.
fn crc32(data: &[u8]) -> u32 {
    !data.iter().fold(!0u32, |mut c, &b| {
        c ^= u32::from(b);
        for _ in 0..8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0xEDB8_8320
            } else {
                c >> 1
            };
        }
        c
    })
}

/// RFC 4648 standard alphabet with `=` padding; anything else is a malformed chunk.
fn base64_decode(s: &[u8]) -> Result<Vec<u8>, ()> {
    let val = |c: u8| -> Result<u32, ()> {
        Ok(match c {
            b'A'..=b'Z' => u32::from(c - b'A'),
            b'a'..=b'z' => u32::from(c - b'a') + 26,
            b'0'..=b'9' => u32::from(c - b'0') + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return Err(()),
        })
    };
    let body = s
        .iter()
        .rev()
        .position(|&c| c != b'=')
        .map_or(0, |p| s.len() - p);
    let pad = s.len() - body;
    if !s.len().is_multiple_of(4) || pad > 2 {
        return Err(());
    }
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    for quad in s[..body].chunks(4) {
        let mut acc = 0u32;
        for (i, &c) in quad.iter().enumerate() {
            acc |= val(c)? << (18 - 6 * i);
        }
        out.push((acc >> 16) as u8);
        if quad.len() > 2 {
            out.push((acc >> 8) as u8);
        }
        if quad.len() > 3 {
            out.push(acc as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_is_ieee() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn base64_round_trips_and_refuses_junk() {
        assert_eq!(base64_decode(b"aGVsbG8=").unwrap(), b"hello");
        assert_eq!(base64_decode(b"aGVsbG8gd29ybGQ=").unwrap(), b"hello world");
        assert_eq!(base64_decode(b"aGk=").unwrap(), b"hi");
        assert_eq!(base64_decode(b"aA==").unwrap(), b"h");
        assert_eq!(base64_decode(b"").unwrap(), b"");
        assert!(base64_decode(b"aGVsbG8").is_err());
        assert!(base64_decode(b"aGVs bG8=").is_err());
        assert!(base64_decode(b"====").is_err());
    }
}
