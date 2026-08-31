//! Request rewriting — 04 §3.2, "header edits are the minimum set".
//!
//! Exactly four edits happen here: hop-by-hop headers are removed (they describe the client's
//! connection to *us*, not ours to the upstream), `M1-Cred-Ref` is stripped, `Host` is
//! rewritten to the upstream authority, and the request target is normalized to origin form.
//!
//! What is deliberately *not* edited: the credential header. §3.4's "no identity masking"
//! means `x-api-key` / `Authorization` reach the upstream exactly as the agent sent them. The
//! proxy holds the bytes for the duration of one forward and owns no copy — [`crate::Secret`]
//! exists for the guard registry's key, not for a credential this module never materializes.

use http::header::{HeaderName, HeaderValue};
use http::{HeaderMap, Request, Uri};

use crate::tee::RequestFacts;
use crate::Upstream;

/// RFC 9110 §7.6.1. `Connection` is included because it *names* the rest.
const HOP_BY_HOP: &[HeaderName] = &[
    http::header::CONNECTION,
    http::header::PROXY_AUTHENTICATE,
    http::header::PROXY_AUTHORIZATION,
    http::header::TE,
    http::header::TRAILER,
    http::header::TRANSFER_ENCODING,
    http::header::UPGRADE,
];

/// Non-const because `HeaderName::from_static` is not const-callable for these.
fn extra_hop_by_hop() -> [HeaderName; 1] {
    [HeaderName::from_static("keep-alive")]
}

/// The tee's allow-list, built field by field from the parts named in §3.2. Note what is not
/// reachable from here: `req.headers()` is never touched, and the URI contributes only
/// `path()` — Google's `?key=…` means a field that kept the query would be a credential in
/// the allow-list under another name.
pub fn facts(req: &Request<hyper::body::Incoming>, up: &Upstream) -> RequestFacts {
    let path = req.uri().path().to_owned();
    RequestFacts {
        method: req.method().as_str().to_owned(),
        dialect: up.dialect(&path),
        path,
        upstream_host: up.host.clone(),
        // 04 §3.2's model rewrite is deferred this phase; see the field's doc comment.
        requested_model: None,
    }
}

/// Apply the four edits. Consumes and returns the request so a caller cannot forward the
/// un-sanitized one by mistake.
pub fn sanitize<B>(mut req: Request<B>, up: &Upstream) -> Request<B> {
    let origin_form = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_owned())
        .unwrap_or_else(|| "/".to_owned());

    strip_hop_by_hop(req.headers_mut());
    req.headers_mut().remove(crate::guard::CRED_REF_HEADER);

    if let Ok(host) = HeaderValue::from_str(&up.authority()) {
        req.headers_mut().insert(http::header::HOST, host);
    }
    if let Ok(uri) = origin_form.parse::<Uri>() {
        *req.uri_mut() = uri;
    }
    req
}

fn strip_hop_by_hop(headers: &mut HeaderMap) {
    // Names listed *inside* Connection first, while Connection is still there to read.
    // get_all, not get: a client may send several Connection lines, and reading only the
    // first leaves every name listed in the rest riding upstream as a real header.
    let listed: Vec<HeaderName> = headers
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|t| HeaderName::try_from(t.trim()).ok())
        .collect();
    for name in listed {
        headers.remove(&name);
    }
    for name in HOP_BY_HOP {
        headers.remove(name);
    }
    for name in extra_hop_by_hop() {
        headers.remove(&name);
    }
}

/// Redact-in-transit eligibility (04 §3.2), **default off**.
///
/// Two exclusions are not policy and cannot be enabled:
///
///   * **Bedrock.** SigV4 signs the body, so any mutation invalidates the signature (§3.4).
///   * **Any request with a `Content-Length`.** Redaction substitutes `⟨redacted:class:hash⟩`
///     for a span, which changes the body's length. Honouring a declared `Content-Length`
///     while rewriting the body requires buffering the whole body to recompute it, and §3.2
///     forbids full-message buffering in the same breath that it names this feature. Chunked
///     bodies have no such conflict.
///
/// This returns eligibility rather than performing the substitution because the substitution
/// belongs in the forward loop, which owns the `mark1_redact::Carry` across chunk boundaries;
/// a per-chunk call with a fresh `Carry` would miss every secret that straddles a boundary,
/// which is the failure mode a streaming redactor exists to avoid.
pub fn redact_in_transit_eligible<B>(
    enabled: bool,
    dialect: mark1_frames::Dialect,
    req: &Request<B>,
) -> bool {
    enabled
        && dialect != mark1_frames::Dialect::BedrockEventstream
        && req.headers().get(http::header::CONTENT_LENGTH).is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(headers: &[(&str, &str)], uri: &str) -> Request<()> {
        let mut b = Request::builder().uri(uri);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(()).unwrap()
    }

    #[test]
    fn cred_ref_never_reaches_the_upstream() {
        let up = Upstream::new("api.anthropic.com", 443, true).unwrap();
        let r = sanitize(
            req(
                &[("m1-cred-ref", "ref-1"), ("x-api-key", "sk-ant-api03-x")],
                "/v1/messages",
            ),
            &up,
        );
        assert!(r.headers().get("m1-cred-ref").is_none());
        // …and the credential itself is untouched: §3.4 no identity masking.
        assert_eq!(r.headers().get("x-api-key").unwrap(), "sk-ant-api03-x");
        assert_eq!(
            r.headers().get(http::header::HOST).unwrap(),
            "api.anthropic.com"
        );
    }

    #[test]
    fn connection_listed_headers_are_stripped_too() {
        let up = Upstream::new("api.anthropic.com", 443, true).unwrap();
        let r = sanitize(
            req(
                &[
                    ("connection", "keep-alive, x-custom-hop"),
                    ("x-custom-hop", "1"),
                ],
                "/v1/x",
            ),
            &up,
        );
        assert!(
            r.headers().get("x-custom-hop").is_none(),
            "Connection-listed header survived"
        );
        assert!(r.headers().get("connection").is_none());
    }

    #[test]
    fn absolute_form_targets_are_normalized_to_origin_form() {
        let up = Upstream::new("api.anthropic.com", 443, true).unwrap();
        let r = sanitize(
            req(&[], "https://api.anthropic.com/v1/messages?beta=1"),
            &up,
        );
        assert_eq!(r.uri().to_string(), "/v1/messages?beta=1");
    }

    #[test]
    fn redact_in_transit_is_off_by_default_and_never_eligible_on_signed_or_sized_bodies() {
        use mark1_frames::Dialect::{AnthropicSse, BedrockEventstream};
        let chunked = req(&[], "/v1/messages");
        let sized = req(&[("content-length", "12")], "/v1/messages");

        assert!(
            !redact_in_transit_eligible(false, AnthropicSse, &chunked),
            "default off"
        );
        assert!(redact_in_transit_eligible(true, AnthropicSse, &chunked));
        assert!(
            !redact_in_transit_eligible(true, BedrockEventstream, &chunked),
            "SigV4"
        );
        assert!(
            !redact_in_transit_eligible(true, AnthropicSse, &sized),
            "Content-Length"
        );
    }
}
