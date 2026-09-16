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

use std::ops::Range;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use http::header::{HeaderName, HeaderValue};
use http::{HeaderMap, Request, Uri};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, Incoming, SizeHint};
use m1p_wire::pb::RouteFidelity;

use crate::guard::ForwardTicket;
use crate::router::RouteTable;
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
        requested_model: None,
        served_model: None,
        route_fidelity: RouteFidelity::Advisory,
        propensity: 1.0,
        bundle_seq: 0,
    }
}

/// Bytes of request prefix scanned for a top-level `"model"` before the request is forwarded
/// unrewritten (ADVISORY). Claude Code serializes `model` first, so one frame suffices.
pub const MODEL_SCAN_MAX: usize = 64 * 1024;

/// The forwarded request body: the scanned (possibly rewritten) prefix, then the client's
/// stream untouched. `head: None` is the byte-exact pass-through.
pub struct UpstreamBody {
    head: Option<Bytes>,
    rest: Incoming,
}

impl From<Incoming> for UpstreamBody {
    fn from(rest: Incoming) -> Self {
        UpstreamBody { head: None, rest }
    }
}

impl Body for UpstreamBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        if let Some(head) = this.head.take() {
            return Poll::Ready(Some(Ok(Frame::data(head))));
        }
        Pin::new(&mut this.rest).poll_frame(cx)
    }

    fn size_hint(&self) -> SizeHint {
        let rest = self.rest.size_hint();
        let head = self.head.as_ref().map_or(0, |h| h.len() as u64);
        let mut hint = SizeHint::new();
        hint.set_lower(rest.lower() + head);
        if let Some(upper) = rest.upper() {
            hint.set_upper(upper + head);
        }
        hint
    }
}

/// 04 §3.2's one legitimate mutation, FR-ROUTE-005: rewrite the top-level `"model"` of the
/// request body to the rung the applied bundle serves it with, byte-exact everywhere else,
/// `Content-Length` recomputed. `ticket` is the provenance guard's proof of an API-key
/// credential (§3.1): there is no other way to name one, so there is no rewrite without one.
///
/// ```compile_fail
/// let forged = mark1_proxy::guard::ForwardTicket { cred_ref: String::new(), cred_identity: [0; 32], observe: true };
/// ```
pub async fn rewrite_model(
    req: Request<Incoming>,
    table: &RouteTable,
    ticket: &ForwardTicket,
    facts: &mut RequestFacts,
) -> Result<Request<UpstreamBody>, hyper::Error> {
    facts.bundle_seq = table.bundle_seq();
    let (mut parts, mut body) = req.into_parts();
    let mut head = BytesMut::new();
    let mut span = None;
    // NOOP_FORWARD (off-marker) is transport only: no mutation, so not even the prefix read.
    // ponytail: the prefix is rescanned per frame; O(n²) bounded by MODEL_SCAN_MAX.
    while ticket.observe() && span.is_none() && head.len() < MODEL_SCAN_MAX {
        let Some(frame) = body.frame().await else {
            break;
        };
        if let Ok(data) = frame?.into_data() {
            head.extend_from_slice(&data);
        }
        span = top_level_model(&head);
    }
    if let Some(range) = span {
        let requested = String::from_utf8_lossy(&head[range.clone()]).into_owned();
        facts.served_model = Some(requested.clone());
        if let Some(served) = table.served(&requested) {
            facts.route_fidelity = RouteFidelity::WireEnforced;
            facts.served_model = Some(served.to_owned());
            if served != requested {
                let mut edited = BytesMut::with_capacity(head.len() + served.len());
                edited.extend_from_slice(&head[..range.start]);
                edited.extend_from_slice(served.as_bytes());
                edited.extend_from_slice(&head[range.end..]);
                head = edited;
                let declared = parts
                    .headers
                    .get(http::header::CONTENT_LENGTH)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<u64>().ok());
                if let Some(cl) = declared {
                    let cl = cl.saturating_sub(range.len() as u64) + served.len() as u64;
                    parts
                        .headers
                        .insert(http::header::CONTENT_LENGTH, HeaderValue::from(cl));
                }
            }
        }
        facts.requested_model = Some(requested);
    }
    let head = (!head.is_empty()).then(|| head.freeze());
    Ok(Request::from_parts(
        parts,
        UpstreamBody { head, rest: body },
    ))
}

/// Byte range of the string value of a depth-1 `"model"` key. `None` for absent, non-string,
/// or not yet within `json` — nested objects and string contents are skipped, never matched.
fn top_level_model(json: &[u8]) -> Option<Range<usize>> {
    let mut depth = 0usize;
    let mut i = 0;
    while i < json.len() {
        match json[i] {
            b'"' => {
                let end = string_end(json, i + 1)?;
                if depth == 1 && &json[i + 1..end] == b"model" {
                    let colon = skip_ws(json, end + 1);
                    if json.get(colon) != Some(&b':') {
                        i = end + 1;
                        continue;
                    }
                    let start = skip_ws(json, colon + 1) + 1;
                    if json.get(start - 1) != Some(&b'"') {
                        return None;
                    }
                    return Some(start..string_end(json, start)?);
                }
                i = end + 1;
            }
            b'{' | b'[' => {
                depth += 1;
                i += 1;
            }
            b'}' | b']' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return None;
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    None
}

fn skip_ws(json: &[u8], mut i: usize) -> usize {
    while json.get(i).is_some_and(u8::is_ascii_whitespace) {
        i += 1;
    }
    i
}

/// Index of the closing quote of the string whose contents start at `from`.
fn string_end(json: &[u8], from: usize) -> Option<usize> {
    let mut i = from;
    while i < json.len() {
        match json[i] {
            b'\\' => i += 2,
            b'"' => return Some(i),
            _ => i += 1,
        }
    }
    None
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

    fn model_of(json: &[u8]) -> Option<&str> {
        top_level_model(json).map(|r| std::str::from_utf8(&json[r]).unwrap())
    }

    #[test]
    fn top_level_model_is_found_only_at_depth_one() {
        assert_eq!(
            model_of(br#"{"model":"claude-a","max_tokens":1}"#),
            Some("claude-a")
        );
        assert_eq!(
            model_of(b"{ \"stream\" : true , \"model\" :\n \"claude-b\" }"),
            Some("claude-b")
        );
        // A user message that talks about models, and a nested object keyed `model`.
        assert_eq!(
            model_of(
                br#"{"messages":[{"role":"user","content":"say \"model\": \"x\""}],"meta":{"model":"n"},"model":"claude-c"}"#
            ),
            Some("claude-c")
        );
        assert_eq!(
            model_of(br#"{"a":"model","model":"claude-d"}"#),
            Some("claude-d")
        );
        assert_eq!(model_of(br#"{"meta":{"model":"n"}}"#), None, "nested only");
        assert_eq!(model_of(br#"{"model":7}"#), None, "not a string");
        assert_eq!(model_of(br#"{"messages":[{"model":"#), None, "truncated");
        assert_eq!(model_of(br#"{"model":"clau"#), None, "truncated value");
    }
}
