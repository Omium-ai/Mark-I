//! Streaming response-frame parsers, one module per upstream dialect (04 §4).
//!
//! Synchronous byte-feeders: the proxy's tee task drives them with cloned chunks and
//! they never own I/O, never allocate on the forwarding path, and never block a write.
//!
//! **The parse-tee contract (04 §4).** A parser only ever sees the tee's clone of the
//! response body. It cannot reach the client's byte stream, so a parse failure narrows
//! *observation* and nothing else: `ParseDegraded` means the wire `Usage` for that
//! response is lost and accounted via `Dropped{PARSE_DEGRADED}`, while transport-level
//! `ModelRequest`/`ModelResponse` still emit and the transcript tailer still covers
//! billing (`idem_key` collapses the overlap, 07 §7). "A parse failure never affects the
//! client" is a theorem of the topology; this crate's job is to not undermine it — hence
//! no panics on any input, a hard cap on retained bytes, and no I/O.

pub mod anthropic_sse;
pub mod azure;
pub mod bedrock_eventstream;
pub mod gemini;
pub mod openai_chat;
pub mod openai_responses;
pub mod vertex;

/// Every independently-versioned revision this crate ships: the five wire grammars plus the two host dialects that select among them.
pub const DIALECT_REVS: [&str; 7] = [
    anthropic_sse::DIALECT_REV,
    openai_responses::DIALECT_REV,
    openai_chat::DIALECT_REV,
    gemini::DIALECT_REV,
    bedrock_eventstream::DIALECT_REV,
    vertex::DIALECT_REV,
    azure::DIALECT_REV,
];

use serde::{Deserialize, Serialize};

pub trait DialectParser {
    /// Feed a teed chunk. Returns zero or more typed wire observations
    /// (ModelRequest/ModelResponse/Usage inputs). NEVER sees the client
    /// stream — only the tee's clone.
    fn feed(&mut self, chunk: &[u8]) -> Result<Vec<WireObservation>, ParseDegraded>;
    fn finish(&mut self) -> Result<Vec<WireObservation>, ParseDegraded>;
    fn dialect_rev(&self) -> &'static str;
}

/// ParseDegraded is NOT an error the request path can see.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("parse degraded at byte {at_byte}: {reason:?}")]
pub struct ParseDegraded {
    pub at_byte: u64,
    pub reason: DegradeReason,
}

/// Why observation narrowed. Every value maps to one `Dropped{PARSE_DEGRADED}` at the
/// tee; the distinction exists for the operator reading `parse_degraded_total` (11 §3),
/// not for control flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DegradeReason {
    /// The dialect module exists and is honestly not implemented yet. A wrong parser
    /// produces wrong billing numbers silently; a degrading one is counted as a loss.
    NotImplemented,
    /// An event this parser depends on for billing did not have the shape the pinned
    /// vendor grammar promises — the vendor-drift signal `DIALECT_REV` exists to answer.
    MalformedEvent,
    /// The partial-event buffer would have grown past the per-stream cap. Retaining an
    /// unbounded partial event is a denial-of-service against the proxy's ≤35 MB RSS
    /// budget (04 §3.4), so the parser refuses the bytes instead of holding them.
    PendingBufferOverflow,
}

/// What a parser can honestly read off the wire.
///
/// Non-exhaustive because five dialects land over several phases and `mark1-proxy`
/// consumes this across a crate boundary: a new observation kind must not be a breaking
/// change for the proxy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum WireObservation {
    Usage(WireUsage),
    /// `ModelResponse.stop_reason` (07 §3) — vendor grammar, passed through verbatim.
    /// Sizes, timings and status are the tee's to measure, not the parser's to guess.
    ResponseEnd {
        stop_reason: String,
    },
    /// An error delivered *inside* a 200 response body. Invisible to transport-level
    /// status, so the tee has no other way to see it.
    UpstreamError {
        error_type: String,
    },
}

/// Inputs to `m1p.v1.Usage` (07 §3), under the data model's own field names.
///
/// Two `Usage` fields are deliberately absent because they are not on this wire:
/// `request_id` is an HTTP response header, and `idem_key` is
/// `HMAC_tenant(session_id, message_id, request_id)` — it needs the tenant key and the
/// session, neither of which a body parser may see. The tee computes both; a parser that
/// invented them would be inventing a billing identity.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireUsage {
    pub message_id: String,
    pub model: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_creation_input_tokens: u64,
    pub cache_read_input_tokens: u64,
    pub service_tier: String,
}

/// The five wire dialects (04 §4). Deliberately a local enum: this crate does not link
/// `m1p-wire`, and `wire_name()` returns the proto spelling so the proxy can map to
/// `m1p.v1.Dialect` without a second copy of the tag numbers living here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Dialect {
    AnthropicSse,
    OpenaiResponses,
    OpenaiChat,
    Gemini,
    BedrockEventstream,
}

impl Dialect {
    pub const ALL: [Dialect; 5] = [
        Dialect::AnthropicSse,
        Dialect::OpenaiResponses,
        Dialect::OpenaiChat,
        Dialect::Gemini,
        Dialect::BedrockEventstream,
    ];

    /// `m1p.v1.Dialect`'s `from_str_name` input.
    pub fn wire_name(self) -> &'static str {
        match self {
            Dialect::AnthropicSse => "DIALECT_ANTHROPIC_SSE",
            Dialect::OpenaiResponses => "DIALECT_OPENAI_RESPONSES",
            Dialect::OpenaiChat => "DIALECT_OPENAI_CHAT",
            Dialect::Gemini => "DIALECT_GEMINI",
            Dialect::BedrockEventstream => "DIALECT_BEDROCK_EVENTSTREAM",
        }
    }

    /// The registry (04 §4). An exhaustive match, so a sixth dialect cannot be added
    /// without a parser — there is no table entry to forget to fill in.
    pub fn parser(self) -> Box<dyn DialectParser> {
        match self {
            Dialect::AnthropicSse => Box::new(anthropic_sse::AnthropicSse::new()),
            Dialect::OpenaiResponses => Box::new(openai_responses::parser()),
            Dialect::OpenaiChat => Box::new(openai_chat::parser()),
            Dialect::Gemini => Box::new(gemini::parser()),
            Dialect::BedrockEventstream => Box::new(bedrock_eventstream::parser()),
        }
    }
}

/// The shared body of every not-yet-implemented dialect. Each module keeps its own
/// `DIALECT_REV` so a vendor grammar change in one never forces a release of another
/// (04 §4); only the behaviour is shared, and the behaviour is "degrade, always".
pub(crate) struct Unimplemented(&'static str);

impl Unimplemented {
    pub(crate) fn new(dialect_rev: &'static str) -> Self {
        Unimplemented(dialect_rev)
    }
}

impl DialectParser for Unimplemented {
    fn feed(&mut self, _chunk: &[u8]) -> Result<Vec<WireObservation>, ParseDegraded> {
        // at_byte 0 is the truth: this parser never advanced through a single byte.
        Err(ParseDegraded {
            at_byte: 0,
            reason: DegradeReason::NotImplemented,
        })
    }

    fn finish(&mut self) -> Result<Vec<WireObservation>, ParseDegraded> {
        Err(ParseDegraded {
            at_byte: 0,
            reason: DegradeReason::NotImplemented,
        })
    }

    fn dialect_rev(&self) -> &'static str {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// The registry tripwire. A registry that silently answers for four of five dialects
    /// is exactly the "gate over zero files" defect this repo has been bitten by.
    #[test]
    fn every_dialect_has_a_parser_with_a_distinct_rev() {
        let mut revs = HashSet::new();
        let mut names = HashSet::new();
        for d in Dialect::ALL {
            let p = d.parser();
            let rev = p.dialect_rev();
            assert!(!rev.is_empty(), "{d:?} has an empty DIALECT_REV");
            assert!(
                revs.insert(rev),
                "{d:?} shares DIALECT_REV {rev} with another dialect"
            );
            assert!(names.insert(d.wire_name()), "{d:?} shares a wire name");
            assert!(
                d.wire_name().starts_with("DIALECT_"),
                "{d:?} wire name is not the proto spelling"
            );
        }
        assert_eq!(revs.len(), 5);
    }

    #[test]
    fn host_dialect_revs_are_distinct_from_every_grammar_rev() {
        let mut revs: Vec<&str> = DIALECT_REVS.to_vec();
        revs.sort_unstable();
        revs.dedup();
        assert_eq!(revs.len(), DIALECT_REVS.len(), "a DIALECT_REV is shared");
    }

    /// Anthropic SSE and Bedrock parse; the other three stubs must keep degrading. If a stub
    /// starts returning `Ok`, either it was implemented (update this test) or it silently
    /// stopped degrading (a billing bug).
    #[test]
    fn only_anthropic_sse_is_implemented() {
        for d in Dialect::ALL {
            let mut p = d.parser();
            let out = p.feed(b"data: {}\n\n");
            if d == Dialect::AnthropicSse {
                assert!(out.is_ok(), "anthropic_sse must parse");
            } else if d == Dialect::BedrockEventstream {
                assert!(
                    out.is_ok(),
                    "bedrock buffers a partial prelude without degrading"
                );
            } else {
                assert_eq!(
                    out.unwrap_err().reason,
                    DegradeReason::NotImplemented,
                    "{d:?} must degrade honestly rather than guess"
                );
            }
        }
    }
}
