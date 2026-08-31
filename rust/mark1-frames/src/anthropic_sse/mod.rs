//! Anthropic Messages API streaming dialect (04 §4) — the Phase 3 target.
//!
//! Grammar, per the vendor's streaming reference: `message_start` (carries `message.id`,
//! `message.model` and the initial `usage` block) → repeated
//! `content_block_start`/`content_block_delta`/`content_block_stop` → one or more
//! `message_delta` (**`usage` here is cumulative, not a delta**) → `message_stop`, with
//! `ping` events interspersed, `error` events possible mid-stream inside a 200 response,
//! and a standing instruction that unknown event types must be handled gracefully.

mod sse;

use serde::Deserialize;

use crate::{DegradeReason, DialectParser, ParseDegraded, WireObservation, WireUsage};

/// Bumped on any change to the Anthropic streaming grammar this module parses, together
/// with a new golden fixture (04 §4, 12 §3.5). Independent of every other dialect's rev.
pub const DIALECT_REV: &str = "anthropic-sse@1";

pub struct AnthropicSse {
    framer: sse::Framer,
    /// The `message_start` usage block, kept so a `message_delta` that reports only
    /// `output_tokens` (the older, narrower shape) does not lose the input and cache
    /// counts. Anthropic's `message_delta.usage` is cumulative, so overlaying the fields
    /// it carries onto this snapshot is the correct merge in both shapes.
    snapshot: Option<WireUsage>,
    /// Degradation is sticky. Resuming after a framing failure means parsing from an
    /// offset the vendor never framed — that is how a parser bug becomes a wrong
    /// billing number instead of a counted loss.
    degraded: Option<ParseDegraded>,
}

impl Default for AnthropicSse {
    fn default() -> Self {
        Self::new()
    }
}

impl AnthropicSse {
    pub fn new() -> Self {
        AnthropicSse {
            framer: sse::Framer::new(),
            snapshot: None,
            degraded: None,
        }
    }

    fn degrade(&mut self, at_byte: u64, reason: DegradeReason) -> ParseDegraded {
        let d = ParseDegraded { at_byte, reason };
        self.degraded = Some(d);
        d
    }

    fn handle(&mut self, ev: &sse::Event, out: &mut Vec<WireObservation>) -> Result<(), ()> {
        match ev.name.as_str() {
            "message_start" => {
                let m: MessageStart = serde_json::from_slice(&ev.data).map_err(|_| ())?;
                let usage = WireUsage {
                    message_id: m.message.id,
                    model: m.message.model,
                    input_tokens: m.message.usage.input_tokens.unwrap_or(0),
                    output_tokens: m.message.usage.output_tokens.unwrap_or(0),
                    cache_creation_input_tokens: m
                        .message
                        .usage
                        .cache_creation_input_tokens
                        .unwrap_or(0),
                    cache_read_input_tokens: m.message.usage.cache_read_input_tokens.unwrap_or(0),
                    service_tier: m.message.usage.service_tier.unwrap_or_default(),
                };
                self.snapshot = Some(usage.clone());
                // Emitted immediately rather than held to `message_stop`: a stream cut
                // after `message_start` still owes the customer its input and cache
                // counts, and the later cumulative Usage carries the same `idem_key`,
                // so the server keeps max(event_id) and cannot double-bill (07 §7).
                out.push(WireObservation::Usage(usage));
            }
            "message_delta" => {
                let d: MessageDelta = serde_json::from_slice(&ev.data).map_err(|_| ())?;
                let u = d.usage.ok_or(())?;
                // No snapshot means `message_start` never arrived — the identity fields
                // this Usage needs are only on that event, so a Usage built here would
                // be unattributable. Refuse rather than emit an anonymous billing fact.
                let mut merged = self.snapshot.take().ok_or(())?;
                if let Some(v) = u.input_tokens {
                    merged.input_tokens = v;
                }
                if let Some(v) = u.output_tokens {
                    merged.output_tokens = v;
                }
                if let Some(v) = u.cache_creation_input_tokens {
                    merged.cache_creation_input_tokens = v;
                }
                if let Some(v) = u.cache_read_input_tokens {
                    merged.cache_read_input_tokens = v;
                }
                if let Some(v) = u.service_tier {
                    merged.service_tier = v;
                }
                self.snapshot = Some(merged.clone());
                out.push(WireObservation::Usage(merged));
                if let Some(stop_reason) = d.delta.and_then(|x| x.stop_reason) {
                    out.push(WireObservation::ResponseEnd { stop_reason });
                }
            }
            "error" => {
                let e: ErrorEvent = serde_json::from_slice(&ev.data).map_err(|_| ())?;
                out.push(WireObservation::UpstreamError {
                    error_type: e.error.r#type,
                });
            }
            // `content_block_*`, `message_stop`, `ping`, and anything the vendor adds
            // later. Carrying no billing fact, they are skipped without inspection —
            // which is also why malformed JSON on one of them is not a degradation.
            _ => {}
        }
        Ok(())
    }
}

impl DialectParser for AnthropicSse {
    /// A degradation discovered *during* this call is recorded and surfaced on the next
    /// `feed()`/`finish()`, not raised from the call that found it. The alternative
    /// discards the observations already parsed out of the same chunk, which makes the
    /// result depend on where the tee happened to split the stream — the one thing a
    /// byte-feeder must never do. `finish()` is always called, so the signal is deferred,
    /// never lost.
    fn feed(&mut self, chunk: &[u8]) -> Result<Vec<WireObservation>, ParseDegraded> {
        if let Some(d) = self.degraded {
            return Err(d);
        }
        let mut events = Vec::new();
        if self.framer.push(chunk, &mut events).is_err() {
            let at = self.framer.retained_offset();
            self.degrade(at, DegradeReason::PendingBufferOverflow);
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for ev in &events {
            if self.handle(ev, &mut out).is_err() {
                self.degrade(ev.end_offset, DegradeReason::MalformedEvent);
                break;
            }
        }
        Ok(out)
    }

    fn finish(&mut self) -> Result<Vec<WireObservation>, ParseDegraded> {
        if let Some(d) = self.degraded {
            return Err(d);
        }
        // A partial event at EOF is discarded, not degraded. Client cancellation and
        // upstream reset are ordinary, and reporting them as parse degradation would
        // make `parse_degraded_total` a measure of cancelled requests instead of a
        // measure of vendor drift. The usage already emitted from `message_start`
        // survives, and the transcript tailer covers the rest (04 §4).
        Ok(Vec::new())
    }

    fn dialect_rev(&self) -> &'static str {
        DIALECT_REV
    }
}

// --- wire shapes -----------------------------------------------------------------
// Only the fields that feed `m1p.v1.Usage`/`ModelResponse`. Unknown members are ignored
// by serde, so an additive vendor change is not a fixture break.

#[derive(Deserialize)]
struct MessageStart {
    message: StartMessage,
}

#[derive(Deserialize)]
struct StartMessage {
    id: String,
    model: String,
    usage: UsageJson,
}

#[derive(Deserialize)]
struct MessageDelta {
    #[serde(default)]
    delta: Option<StopDelta>,
    #[serde(default)]
    usage: Option<UsageJson>,
}

#[derive(Deserialize)]
struct StopDelta {
    #[serde(default)]
    stop_reason: Option<String>,
}

/// Every counter is optional because `message_delta.usage` legitimately carries a subset;
/// `Option` rather than `#[serde(default)]` so "absent" and "zero" stay distinguishable
/// at merge time — conflating them would let a delta reset a cache count to zero.
#[derive(Deserialize)]
struct UsageJson {
    #[serde(default)]
    input_tokens: Option<u64>,
    #[serde(default)]
    output_tokens: Option<u64>,
    #[serde(default)]
    cache_creation_input_tokens: Option<u64>,
    #[serde(default)]
    cache_read_input_tokens: Option<u64>,
    #[serde(default)]
    service_tier: Option<String>,
}

#[derive(Deserialize)]
struct ErrorEvent {
    error: ErrorBody,
}

#[derive(Deserialize)]
struct ErrorBody {
    r#type: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed_all(bytes: &[u8]) -> Result<Vec<WireObservation>, ParseDegraded> {
        let mut p = AnthropicSse::new();
        let mut out = p.feed(bytes)?;
        out.extend(p.finish()?);
        Ok(out)
    }

    const START: &[u8] = b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"model\":\"claude-opus-5\",\"usage\":{\"input_tokens\":10,\"output_tokens\":1,\"cache_creation_input_tokens\":2,\"cache_read_input_tokens\":3,\"service_tier\":\"standard\"}}}\n\n";

    #[test]
    fn message_delta_without_cache_fields_keeps_the_snapshot_counts() {
        let mut bytes = START.to_vec();
        bytes.extend_from_slice(
            b"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":99}}\n\n",
        );
        let out = feed_all(&bytes).unwrap();
        let WireObservation::Usage(u) = &out[1] else {
            panic!("expected Usage, got {:?}", out[1])
        };
        assert_eq!(u.output_tokens, 99);
        assert_eq!(
            u.input_tokens, 10,
            "input count must survive a narrow message_delta"
        );
        assert_eq!(u.cache_creation_input_tokens, 2);
        assert_eq!(u.cache_read_input_tokens, 3);
        assert_eq!(u.service_tier, "standard");
        assert_eq!(
            out[2],
            WireObservation::ResponseEnd {
                stop_reason: "end_turn".into()
            }
        );
    }

    #[test]
    fn unknown_event_with_garbage_json_is_not_a_degradation() {
        let mut bytes = START.to_vec();
        bytes.extend_from_slice(b"event: some_future_event\ndata: {not json at all\n\n");
        assert_eq!(feed_all(&bytes).unwrap().len(), 1);
    }

    #[test]
    fn malformed_message_start_degrades_and_stays_degraded() {
        let mut p = AnthropicSse::new();
        assert_eq!(
            p.feed(b"event: message_start\ndata: {\"message\":{}}\n\n")
                .unwrap(),
            vec![]
        );
        let err = p.feed(START).unwrap_err();
        assert_eq!(err.reason, DegradeReason::MalformedEvent);
        // Sticky: a well-formed event after the failure must not resurrect parsing.
        assert_eq!(p.feed(START).unwrap_err(), err);
        assert_eq!(p.finish().unwrap_err(), err);
    }

    /// A degradation must not depend on where the tee split the stream: the same
    /// observations precede it and the same reason follows, whole-fed or byte-fed.
    #[test]
    fn degradation_point_is_independent_of_chunking() {
        let mut bytes = START.to_vec();
        bytes.extend_from_slice(b"event: message_delta\ndata: {\"usage\":\n\n");

        let mut whole = AnthropicSse::new();
        let mut a = whole.feed(&bytes).unwrap();
        let a_err = whole.finish().unwrap_err();

        let mut byte_at_a_time = AnthropicSse::new();
        let mut b = Vec::new();
        for i in 0..bytes.len() {
            match byte_at_a_time.feed(&bytes[i..=i]) {
                Ok(v) => b.extend(v),
                Err(_) => break,
            }
        }
        let b_err = byte_at_a_time.finish().unwrap_err();

        assert_eq!(a.len(), 1);
        assert_eq!(a.pop(), b.pop());
        assert_eq!(a_err, b_err);
        assert_eq!(a_err.reason, DegradeReason::MalformedEvent);
    }

    #[test]
    fn truncated_stream_keeps_the_message_start_usage_and_does_not_degrade() {
        let mut bytes = START.to_vec();
        bytes.extend_from_slice(b"event: message_delta\ndata: {\"type\":\"messa");
        let out = feed_all(&bytes).unwrap();
        assert_eq!(out.len(), 1);
    }
}
