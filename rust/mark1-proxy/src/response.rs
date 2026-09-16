//! Return path — 04 §3.2 (bytes-forward) and §3.1 step 6 (the subscription-marker tripwire).

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;

use bytes::Bytes;
use http::HeaderMap;
use hyper::body::{Body, Frame, Incoming};

use crate::tee::{ResponseFacts, TeeStream};
use crate::upstream::Checkout;

/// Header markers that only appear on a response served against a **subscription** (OAuth)
/// credential. A closed list, matched by prefix on the header *name* only.
///
/// Why names and not values: a value-matching rule is a rule about vendor copy, and vendor
/// copy changes without notice. `anthropic-ratelimit-unified-*` is the unified quota family
/// Anthropic returns for Claude subscription plans; the API-key families are
/// `anthropic-ratelimit-requests-*` and `anthropic-ratelimit-tokens-*`, which are absent here
/// deliberately — a false positive on this path kills a paying customer's session.
///
/// Scope, stated so it is not mistaken for completeness: §3.1 step 6 says "headers **or
/// shape**". Only the header half is implemented. A body-shape marker needs a recorded
/// contaminated transcript to be written against, and there is none in `conformance/`;
/// guessing one would produce a tripwire whose false-positive rate is unknown, attached to
/// the most destructive action in the binary.
pub const SUBSCRIPTION_MARKER_PREFIXES: &[&str] = &[
    "anthropic-ratelimit-unified",
    "anthropic-subscription",
    "x-claude-subscription",
];

/// A tripwire over an empty list scans nothing while every test below still passes. Compile
/// time, because that failure must not be discoverable only by running the suite.
const _: () = assert!(
    !SUBSCRIPTION_MARKER_PREFIXES.is_empty(),
    "no subscription markers"
);

/// `Some(marker)` ⇒ an OAuth credential got through everything: the P0 case (M1E-8002).
pub fn subscription_marker(headers: &HeaderMap) -> Option<&'static str> {
    headers.keys().find_map(|name| {
        let name = name.as_str();
        SUBSCRIPTION_MARKER_PREFIXES
            .iter()
            .copied()
            .find(|p| name.starts_with(p))
    })
}

/// The client-facing response body: forwards upstream frames verbatim, tees a refcounted
/// clone of each, and returns the pooled connection when the stream ends cleanly.
///
/// `poll_frame` does the tee work *before* handing the frame on, and every step of it is
/// O(1) and non-blocking — a `Bytes` clone is a refcount bump and `TeeStream::chunk` is a
/// byte-admission test plus a `try_send`. There is no `.await` in this function, so no
/// arrangement of the tee can delay a client write.
pub struct ForwardBody {
    inner: Incoming,
    tee: Option<TeeStream>,
    /// `Some` until the stream ends cleanly. Dropped un-released on a mid-stream abort: an
    /// http1 connection with an unread body is not reusable.
    checkout: Option<Checkout>,
    started: Instant,
    /// Pre-filled by the router; `response_bytes`/`elapsed_micros` are completed in `finish`.
    facts: ResponseFacts,
    /// The upstream body reached its end. Tracked rather than inferred from `poll_frame`
    /// returning `None`, because for a `Content-Length` response hyper's server stops polling
    /// once it has written the declared number of bytes — so the terminal `None` may never
    /// arrive, and a pool that only released there never reused a connection at all.
    /// `pool_is_keyed_by_credential_identity` is what caught that.
    complete: bool,
}

impl ForwardBody {
    /// `tee: None` is the un-observed forward — D-AJ's sampled-out FORWARD arm, and the
    /// off-marker arm. The bytes take the identical path either way; that is the point.
    pub fn new(
        inner: Incoming,
        tee: Option<TeeStream>,
        checkout: Checkout,
        started: Instant,
        facts: ResponseFacts,
    ) -> Self {
        ForwardBody {
            inner,
            tee,
            checkout: Some(checkout),
            started,
            facts,
            complete: false,
        }
    }

    /// Idempotent: called from the terminal `poll_frame` arm and again from `Drop`.
    fn finish(&mut self) {
        if let Some(tee) = self.tee.take() {
            let mut facts = self.facts.clone();
            facts.elapsed_micros = self.started.elapsed().as_micros().min(u64::MAX as u128) as u64;
            tee.close(facts);
        }
        // Only a fully-read body may go back to the pool. Returning one with bytes still on
        // it would hand the next request for this credential a connection whose next read is
        // the tail of somebody else's response.
        match self.checkout.take() {
            Some(c) if self.complete => c.release(),
            _ => {}
        }
    }
}

impl Body for ForwardBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    if this.facts.response_bytes == 0 {
                        this.facts.ttfb_micros =
                            this.started.elapsed().as_micros().min(u64::MAX as u128) as u64;
                    }
                    this.facts.response_bytes += data.len() as u64;
                    if let Some(tee) = this.tee.as_mut() {
                        // Return value ignored on purpose: a refused chunk degrades that
                        // stream's parse (04 §4) and is already counted inside the tee. It
                        // is not information this loop is allowed to act on.
                        let _ = tee.chunk(data);
                    }
                }
                // hyper's `Incoming` counts down the declared length; nothing left to read is
                // the same fact as a terminal `None`, and arrives one poll earlier.
                if this.inner.size_hint().exact() == Some(0) {
                    this.complete = true;
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => {
                this.checkout = None;
                this.finish();
                Poll::Ready(Some(Err(e)))
            }
            Poll::Ready(None) => {
                this.complete = true;
                this.finish();
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for ForwardBody {
    /// A client that hangs up mid-stream must still produce transport counters — otherwise
    /// the most interesting requests are the ones that are never observed.
    fn drop(&mut self) {
        self.finish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                http::header::HeaderName::try_from(*k).unwrap(),
                http::HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn unified_ratelimit_headers_are_the_contamination_marker() {
        assert!(subscription_marker(&headers(&[
            ("anthropic-ratelimit-unified-status", "allowed"),
            ("content-type", "application/json"),
        ]))
        .is_some());
    }

    /// The false-positive case that would kill a paying API-key customer's session.
    #[test]
    fn api_key_ratelimit_headers_are_not_a_marker() {
        assert!(subscription_marker(&headers(&[
            ("anthropic-ratelimit-requests-limit", "1000"),
            ("anthropic-ratelimit-tokens-remaining", "40000"),
            ("anthropic-organization-id", "org_x"),
            ("request-id", "req_x"),
        ]))
        .is_none());
    }

    #[test]
    fn marker_match_is_case_insensitive_because_header_names_are() {
        // http::HeaderMap lowercases on insert, so a vendor shouting the header still hits.
        assert!(
            subscription_marker(&headers(&[("ANTHROPIC-RATELIMIT-UNIFIED-RESET", "1")])).is_some()
        );
    }
}
