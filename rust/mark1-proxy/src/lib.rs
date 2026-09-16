//! API-key-only micro-proxy (04 §3). The provenance guard, not shape inspection, is what
//! makes subscription non-interception a property of the binary rather than a policy.
//!
//! # What "structural" means here, concretely
//!
//! Three things, and none of them is a runtime check you could turn off:
//!
//!   1. [`guard::ForwardTicket`] has private fields and a private constructor. The only code
//!      that can mint one is `guard::provenance`, and it mints one only past all six steps of
//!      §3.1. [`upstream::Pool::connect`] requires one by reference. There is therefore no
//!      *expressible* call that opens an upstream connection for an unverified credential —
//!      not behind a flag, not behind a `cfg`, not in a debug build.
//!   2. The tee is fed [`tee::RequestFacts`] / [`tee::ResponseFacts`], built field by field.
//!      No constructor in this crate turns a `Request`, a `HeaderMap` or a `Uri` into
//!      something the tee can hold, so the observation plane has no route to a credential.
//!   3. Nothing in this crate reads an environment variable or a feature flag to decide
//!      whether to forward. The one environment variable it reads at all (`MARK1_DISABLE`,
//!      04 §3.1 step 1) can only make the proxy do *less*.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use mark1_frames::Dialect;

pub mod fabric;
pub mod gateway;
pub mod guard;
pub mod policy;
pub mod request;
pub mod response;
pub mod router;
pub mod secret;
pub mod tee;
pub mod upstream;

pub use secret::Secret;

/// 04 §3.4. Same binary, config not code.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Sidecar,
    /// 04 §3.4: mTLS listener on customer infra, credentials by reference (`gateway.rs`).
    Gateway,
}

/// One allow-listed upstream. 04 §3.4: sidecar mode "pins upstreams to the bundle-declared
/// hostname allow-list", so a host absent from this list is not reachable through the proxy
/// by any request shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Upstream {
    pub host: String,
    pub port: u16,
    /// Plaintext is permitted **only** for loopback literals, so integration tests can stand
    /// up a fake upstream without this crate growing an `insecure` switch. Enforced in
    /// [`Upstream::new`], not at the call site.
    pub tls: bool,
    /// Declared grammar. `None` ⇒ inferred from the host by [`Upstream::dialect`].
    ///
    /// Private, so the only way to set it is [`Upstream::with_dialect`]. It exists because
    /// host inference has nothing to say about an upstream that is not a vendor endpoint — a
    /// self-hosted gateway, an egress proxy, a loopback replay of a recorded transcript — and
    /// the fallback is `OpenaiChat`, i.e. a confident wrong grammar. Nothing here can widen
    /// what the proxy carries: the dialect only selects which parser the *tee* runs.
    dialect: Option<Dialect>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NotLoopback;

impl Upstream {
    /// `tls = false` is accepted only for a loopback host.
    pub fn new(host: impl Into<String>, port: u16, tls: bool) -> Result<Self, NotLoopback> {
        let host = host.into();
        if !tls && !is_loopback_literal(&host) {
            return Err(NotLoopback);
        }
        Ok(Upstream {
            host,
            port,
            tls,
            dialect: None,
        })
    }

    pub fn with_dialect(mut self, dialect: Dialect) -> Self {
        self.dialect = Some(dialect);
        self
    }

    pub fn authority(&self) -> String {
        let default = if self.tls { 443 } else { 80 };
        if self.port == default {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// Which wire grammar `mark1-frames` should parse the response body as. Host first, then
    /// path, because one host serves several grammars.
    pub fn dialect(&self, path: &str) -> Dialect {
        if let Some(d) = self.dialect {
            return d;
        }
        match self.host.as_str() {
            "api.anthropic.com" => Dialect::AnthropicSse,
            "generativelanguage.googleapis.com" => Dialect::Gemini,
            h if h.starts_with("bedrock-runtime.") => Dialect::BedrockEventstream,
            h if mark1_frames::vertex::is_host(h) => mark1_frames::vertex::dialect_for(path),
            h if mark1_frames::azure::is_host(h) => mark1_frames::azure::dialect_for(path),
            "api.openai.com" => openai_dialect(path),
            // ponytail: an allow-listed host with no known grammar still forwards, and
            // observation degrades to transport counters (04 §4) — but only because the
            // OpenAI parser is still an `Unimplemented` stub. The day it gains a real
            // body, this line stops degrading and starts *guessing*, producing confident
            // wrong numbers on a billing-grade event. `unknown_host_fallback_must_degrade`
            // fails on that day. The answer then is a declared dialect per upstream
            // (`with_dialect`), not a better guess.
            _ => openai_dialect(path),
        }
    }
}

/// `--upstream host:port=<dialect>`, matched against `m1p.v1.Dialect`'s spelling minus its
/// prefix so there is no second copy of the dialect names to drift.
pub fn parse_dialect(s: &str) -> Option<Dialect> {
    Dialect::ALL.into_iter().find(|d| {
        d.wire_name()
            .strip_prefix("DIALECT_")
            .is_some_and(|n| n.eq_ignore_ascii_case(s))
    })
}

fn openai_dialect(path: &str) -> Dialect {
    if path.contains("/responses") {
        Dialect::OpenaiResponses
    } else {
        Dialect::OpenaiChat
    }
}

fn is_loopback_literal(host: &str) -> bool {
    matches!(host, "127.0.0.1" | "::1" | "[::1]" | "localhost")
}

#[derive(Clone, Debug)]
pub struct ProxyConfig {
    pub mode: Mode,
    pub bind: SocketAddr,
    /// Non-empty. The first entry is the default route for origin-form requests; an
    /// absolute-form request-target may select any other entry, and nothing else.
    pub upstreams: Vec<Upstream>,
    /// D-AJ: the FORWARD arm only. The refused arm is not configurable and is not here.
    pub forward_sample_rate: f64,
    /// `~/.omium/mark1`.
    pub base: PathBuf,
}

impl ProxyConfig {
    pub fn default_upstream(&self) -> Option<&Upstream> {
        self.upstreams.first()
    }

    pub fn upstream_for(&self, authority: &str) -> Option<&Upstream> {
        let host = authority.rsplit_once(':').map_or(authority, |(h, _)| h);
        self.upstreams.iter().find(|u| u.host == host)
    }
}

/// `$HOME`, or `%USERPROFILE%` on Windows.
pub fn home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
}

/// 04 §3.1 step 1 / edge invariant 2 — evaluated before any gate, and fail-**closed** in the
/// sense that matters: an unreadable off-marker means the proxy stays on, and staying on
/// means the guard still runs. `symlink_metadata` so a symlink planted at the marker path is
/// itself the marker rather than a redirect we follow.
pub fn is_off(base: &Path) -> bool {
    if std::env::var_os("MARK1_DISABLE").is_some_and(|v| v == "1") {
        return true;
    }
    std::fs::symlink_metadata(base.join("OFF")).is_ok()
}

/// The frozen 08 §9 body shape, byte-identical across every surface that raises a code.
pub fn error_body(code: &str, message: &str) -> Vec<u8> {
    let body = serde_json::json!({ "error": { "code": code, "message": message } });
    serde_json::to_vec(&body).unwrap_or_else(|_| {
        format!("{{\"error\":{{\"code\":\"{code}\",\"message\":\"\"}}}}").into_bytes()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plaintext_upstreams_are_loopback_only() {
        assert!(Upstream::new("api.anthropic.com", 80, false).is_err());
        assert!(Upstream::new("127.0.0.1", 8080, false).is_ok());
        assert!(Upstream::new("localhost", 8080, false).is_ok());
        // The bypass shape this rule exists to refuse: a hostname that merely contains a
        // loopback literal.
        assert!(Upstream::new("localhost.evil.example", 80, false).is_err());
        assert!(Upstream::new("api.anthropic.com", 443, true).is_ok());
    }

    #[test]
    fn dialect_selection_is_host_then_path() {
        let a = Upstream::new("api.anthropic.com", 443, true).unwrap();
        assert_eq!(a.dialect("/v1/messages"), Dialect::AnthropicSse);
        let o = Upstream::new("api.openai.com", 443, true).unwrap();
        assert_eq!(o.dialect("/v1/responses"), Dialect::OpenaiResponses);
        assert_eq!(o.dialect("/v1/chat/completions"), Dialect::OpenaiChat);
        let b = Upstream::new("bedrock-runtime.us-east-1.amazonaws.com", 443, true).unwrap();
        assert_eq!(b.dialect("/model/x/invoke"), Dialect::BedrockEventstream);
        // Vertex and Azure are hosts serving several grammars; the path picks the parser.
        let v = Upstream::new("us-east5-aiplatform.googleapis.com", 443, true).unwrap();
        assert_eq!(
            v.dialect(
                "/v1/projects/p/locations/us-east5/publishers/anthropic/models/m:streamRawPredict"
            ),
            Dialect::AnthropicSse
        );
        assert_eq!(
            v.dialect(
                "/v1/projects/p/locations/l/publishers/google/models/g:streamGenerateContent"
            ),
            Dialect::Gemini
        );
        let az = Upstream::new("acme.openai.azure.com", 443, true).unwrap();
        assert_eq!(
            az.dialect("/openai/deployments/d/chat/completions"),
            Dialect::OpenaiChat
        );
        assert_eq!(az.dialect("/openai/responses"), Dialect::OpenaiResponses);
        let foundry = Upstream::new("acme.services.ai.azure.com", 443, true).unwrap();
        assert_eq!(
            foundry.dialect("/anthropic/v1/messages"),
            Dialect::AnthropicSse
        );
    }

    #[test]
    fn declared_dialect_overrides_host_inference() {
        let gw = Upstream::new("127.0.0.1", 8080, false).unwrap();
        // The fallback is a guess, and this is what the guess is.
        assert_eq!(gw.dialect("/v1/messages"), Dialect::OpenaiChat);
        let gw = gw.with_dialect(Dialect::AnthropicSse);
        assert_eq!(gw.dialect("/v1/messages"), Dialect::AnthropicSse);
        assert_eq!(
            gw.dialect("/anything"),
            Dialect::AnthropicSse,
            "declared beats path too"
        );
    }

    #[test]
    fn every_dialect_is_nameable_on_the_command_line() {
        for d in Dialect::ALL {
            let name = d
                .wire_name()
                .strip_prefix("DIALECT_")
                .unwrap()
                .to_ascii_lowercase();
            assert_eq!(parse_dialect(&name), Some(d), "{name}");
        }
        assert_eq!(parse_dialect("not_a_dialect"), None);
    }

    /// The unknown-host fallback in [`Upstream::dialect`] is safe only while the OpenAI
    /// parser is a degrading stub. When it gains a real body, every allow-listed host we
    /// have no grammar for silently starts reporting usage under the wrong grammar — on the
    /// one event class that is billing-grade. This fails first.
    #[test]
    fn unknown_host_fallback_must_degrade() {
        let unknown = Upstream::new("gateway.internal.example", 443, true).unwrap();
        let mut parser = unknown.dialect("/v1/messages").parser();
        let err = parser
            .feed(b"data: {\"type\":\"message_start\"}\n\n")
            .expect_err("the fallback parsed a stream whose grammar it cannot know");
        assert_eq!(err.reason, mark1_frames::DegradeReason::NotImplemented);
    }

    #[test]
    fn error_body_is_the_frozen_shape() {
        let raw = error_body("M1E-8001", "no valid M1-Cred-Ref");
        let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(v["error"]["code"], "M1E-8001");
    }
}
