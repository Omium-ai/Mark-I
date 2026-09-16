//! Azure OpenAI / AI Foundry (04 §4): an endpoint host, not a grammar — `/openai/…/chat/completions` streams OpenAI chat SSE, `/openai/responses` the Responses grammar, Foundry's `/anthropic/v1/messages` Anthropic SSE.
//!
//! Versioned on its own (13 §"data-plane revisions"): a path→grammar change on Azure is a rev bump here, never a parser release.

use crate::{Dialect, DialectParser};

pub const DIALECT_REV: &str = "azure@1";

/// A resource host under any of Azure's three AI endpoint domains.
pub fn is_host(host: &str) -> bool {
    [
        ".openai.azure.com",
        ".services.ai.azure.com",
        ".cognitiveservices.azure.com",
    ]
    .iter()
    .any(|s| host.ends_with(s))
}

pub fn dialect_for(path: &str) -> Dialect {
    if path.contains("/anthropic/") {
        Dialect::AnthropicSse
    } else if path.contains("/responses") {
        Dialect::OpenaiResponses
    } else {
        Dialect::OpenaiChat
    }
}

pub fn parser(path: &str) -> Box<dyn DialectParser> {
    dialect_for(path).parser()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn azure_paths_select_the_grammar_they_serve() {
        assert_eq!(
            dialect_for("/openai/deployments/gpt-5/chat/completions?api-version=2025-04-01"),
            Dialect::OpenaiChat
        );
        assert_eq!(
            dialect_for("/openai/responses?api-version=preview"),
            Dialect::OpenaiResponses
        );
        assert_eq!(dialect_for("/anthropic/v1/messages"), Dialect::AnthropicSse);
        assert_eq!(
            parser("/anthropic/v1/messages").dialect_rev(),
            crate::anthropic_sse::DIALECT_REV
        );
        assert!(is_host("acme.openai.azure.com") && is_host("acme.services.ai.azure.com"));
        assert!(!is_host("openai.azure.com.example"));
    }
}
