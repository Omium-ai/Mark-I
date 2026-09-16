//! Google Vertex AI (04 §4): an endpoint host, not a grammar — Claude on Vertex (`…/publishers/anthropic/…:streamRawPredict`) streams Anthropic SSE verbatim, Gemini on Vertex streams Gemini.
//!
//! Versioned on its own (13 §"data-plane revisions"): a change in which grammar Vertex serves on which path is a rev bump here, never an Anthropic or Gemini parser release.

use crate::{Dialect, DialectParser};

pub const DIALECT_REV: &str = "vertex@1";

/// `aiplatform.googleapis.com` or a regional `{region}-aiplatform.googleapis.com`.
pub fn is_host(host: &str) -> bool {
    host == "aiplatform.googleapis.com" || host.ends_with("-aiplatform.googleapis.com")
}

pub fn dialect_for(path: &str) -> Dialect {
    if path.contains("/publishers/anthropic/") {
        Dialect::AnthropicSse
    } else {
        Dialect::Gemini
    }
}

pub fn parser(path: &str) -> Box<dyn DialectParser> {
    dialect_for(path).parser()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claude_on_vertex_is_anthropic_sse_and_the_rest_is_gemini() {
        assert_eq!(
            dialect_for("/v1/projects/p/locations/us-east5/publishers/anthropic/models/claude-opus-4-1:streamRawPredict"),
            Dialect::AnthropicSse
        );
        assert_eq!(
            dialect_for("/v1/projects/p/locations/us-central1/publishers/google/models/gemini-2.5-pro:streamGenerateContent"),
            Dialect::Gemini
        );
        assert_eq!(
            parser("/v1/projects/p/locations/x/publishers/anthropic/models/m:streamRawPredict")
                .dialect_rev(),
            crate::anthropic_sse::DIALECT_REV
        );
        assert!(
            is_host("aiplatform.googleapis.com") && is_host("us-east5-aiplatform.googleapis.com")
        );
        assert!(!is_host("evil-aiplatform.googleapis.com.example"));
    }
}
