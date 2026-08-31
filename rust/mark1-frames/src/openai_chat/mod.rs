//! OpenAI Chat Completions streaming dialect (04 §4).
//!
//! NOT A BUG — this module is deliberately unimplemented (04 §4 phasing; Anthropic SSE
//! is the Phase 3 dialect). `feed()` and `finish()` always return
//! `ParseDegraded{ reason: NotImplemented }`, which the tee accounts as
//! `Dropped{PARSE_DEGRADED}` and falls back to the transcript tailer for billing.
//!
//! A guessed parser would be strictly worse than this one: it would emit token counts
//! nobody checked against the real wire, and wrong billing numbers do not announce
//! themselves. A degrading parser is a counted loss.
//!
//! Implementing it means: parse, ship golden fixtures under
//! `conformance/frames/`, and bump `DIALECT_REV` below.

use crate::{DialectParser, Unimplemented};

/// Independently versioned (04 §4): a grammar change here never forces a release of
/// another dialect's parser.
pub const DIALECT_REV: &str = "openai-chat@0";

pub fn parser() -> impl DialectParser {
    Unimplemented::new(DIALECT_REV)
}
