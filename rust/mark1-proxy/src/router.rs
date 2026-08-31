//! Listener and request flow — 04 §3.1 (order), §3.4 (sidecar rules).
//!
//! [`Proxy::handle`] is the whole request path and runs the six §3.1 steps in the order the
//! document gives them. The one thing worth reading closely is what happens between steps:
//! nothing. There is no pre-guard forward, no cache of a previous decision, and no branch
//! that reaches [`crate::upstream::Pool::connect`] without a `ForwardTicket` — the ticket is
//! unconstructable outside `guard::provenance`, so the compiler is what enforces the order,
//! not this comment.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use bytes::Bytes;
use http::{Response, StatusCode};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;

use crate::fabric::Fabric;
use crate::guard::{Decision, ForwardTicket, Guard, Refusal};
use crate::response::ForwardBody;
use crate::tee::Tee;
use crate::upstream::Pool;
use crate::{ProxyConfig, Upstream};

type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type ProxyBody = BoxBody<Bytes, BoxError>;

pub struct Proxy {
    cfg: Arc<ProxyConfig>,
    guard: Arc<Guard>,
    pool: Arc<Pool>,
    tee: Tee,
    fabric: Fabric,
    /// §3.1 step 6: "all further requests for that session refused". Keyed by `M1-Cred-Ref`
    /// rather than by connection, because the ref is what identifies the agent config whose
    /// fragment must be reverted, and it survives the client reconnecting — which a
    /// connection-keyed set would not, making the kill last exactly one TCP session.
    killed: Arc<Mutex<HashSet<String>>>,
    /// What `Host` must equal (M1E-4004).
    bound_authority: String,
}

impl Proxy {
    pub fn new(
        cfg: Arc<ProxyConfig>,
        guard: Arc<Guard>,
        pool: Arc<Pool>,
        tee: Tee,
        fabric: Fabric,
        bound: SocketAddr,
    ) -> Self {
        Proxy {
            cfg,
            guard,
            pool,
            tee,
            fabric,
            killed: Arc::default(),
            bound_authority: bound.to_string(),
        }
    }

    pub async fn serve(self: Arc<Self>, listener: tokio::net::TcpListener) {
        loop {
            let Ok((stream, _peer)) = listener.accept().await else {
                continue;
            };
            let _ = stream.set_nodelay(true);
            let me = Arc::clone(&self);
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req| {
                    let me = Arc::clone(&me);
                    async move { Ok::<_, std::convert::Infallible>(me.handle(req).await) }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(stream), svc)
                    .await;
            });
        }
    }

    pub async fn handle(&self, req: http::Request<Incoming>) -> Response<ProxyBody> {
        let started = Instant::now();

        // Step 1 — edge invariant 2: the off-check precedes every gate evaluation.
        let off = crate::is_off(&self.cfg.base);

        let absolute_form = req.uri().authority().is_some();
        if let Some(err) = self.loopback_rules(&req, absolute_form) {
            return err;
        }

        let Some(up) = self.route(&req, absolute_form) else {
            return error(
                StatusCode::FORBIDDEN,
                "M1E-8001",
                "upstream not in the allow-list",
            );
        };
        let up = up.clone();

        // The kill set is consulted before the guard: once a session is contaminated, its
        // requests are refused on this proxy's own authority (D-AI), and re-verifying a
        // credential we have already decided to stop carrying would be theatre.
        if let Some(ref_id) = req.headers().get(crate::guard::CRED_REF_HEADER) {
            let killed = ref_id
                .to_str()
                .ok()
                .is_some_and(|r| self.killed.lock().is_ok_and(|k| k.contains(r)));
            if killed {
                return killed_response();
            }
        }

        // Steps 2-5.
        let outcome = self.guard.decide(req.headers(), off);
        if let Some(record) = outcome.record {
            self.fabric.guard_decision(record);
        }
        let (ticket, observe) = match outcome.decision {
            Decision::Refused(Refusal::Contaminated) => return killed_response(),
            Decision::Refused(_) => {
                return error(
                    StatusCode::FORBIDDEN,
                    "M1E-8001",
                    "request without a valid M1-Cred-Ref",
                )
            }
            // The off-marker arm: forward, observe nothing. Reached only by a request that
            // already satisfied steps 2, 3 and 5 — `mark1 off` narrows what the proxy does,
            // it does not widen what it will carry.
            Decision::NoopForward(t) => (t, false),
            Decision::Forward(t) => {
                let observe = t.observe();
                (t, observe)
            }
        };

        self.forward(req, up, ticket, observe, started).await
    }

    /// 04 §3.4 sidecar rules. Both codes are frozen (08 §9) and both are fail-closed.
    fn loopback_rules(
        &self,
        req: &http::Request<Incoming>,
        absolute_form: bool,
    ) -> Option<Response<ProxyBody>> {
        if self.cfg.mode != crate::Mode::Sidecar {
            return None;
        }
        if req.headers().contains_key(http::header::ORIGIN) {
            // An `Origin` on a loopback API listener means a browser sent it, which means
            // some page is driving the developer's credential.
            return Some(error(
                StatusCode::FORBIDDEN,
                "M1E-4005",
                "loopback request carries Origin",
            ));
        }
        // Only meaningful for origin-form targets: in absolute form the authority IS the
        // route, and RFC 9110 requires `Host` to match it rather than the listener.
        if !absolute_form {
            let host_ok = req
                .headers()
                .get(http::header::HOST)
                .and_then(|h| h.to_str().ok())
                .is_some_and(|h| h == self.bound_authority);
            if !host_ok {
                return Some(error(
                    StatusCode::FORBIDDEN,
                    "M1E-4004",
                    "loopback Host is not the bound literal",
                ));
            }
        }
        None
    }

    fn route(&self, req: &http::Request<Incoming>, absolute_form: bool) -> Option<&Upstream> {
        if absolute_form {
            let authority = req.uri().authority()?.as_str();
            self.cfg.upstream_for(authority)
        } else {
            self.cfg.default_upstream()
        }
    }

    async fn forward(
        &self,
        req: http::Request<Incoming>,
        up: Upstream,
        ticket: ForwardTicket,
        observe: bool,
        started: Instant,
    ) -> Response<ProxyBody> {
        let facts = crate::request::facts(&req, &up);
        let dialect = facts.dialect;
        // ponytail: request byte count from Content-Length; a chunked upload reports 0. A
        // counting body wrapper would be exact — add it when a dialect ships chunked
        // requests, which none of the five currently does.
        let request_bytes = req
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        let _ = crate::request::redact_in_transit_eligible(false, dialect, &req);

        let req = crate::request::sanitize(req, &up);

        let mut checkout = match self.pool.connect(&up, &ticket).await {
            Ok(c) => c,
            // §3.5: pass the error to the client verbatim; the proxy adds no retry.
            Err(e) => {
                return error(StatusCode::BAD_GATEWAY, "M1E-9500", &e.to_string());
            }
        };
        let upstream_response = match checkout.send(req).await {
            Ok(r) => r,
            Err(e) => return error(StatusCode::BAD_GATEWAY, "M1E-9500", &e.to_string()),
        };

        // Step 6 — the tertiary tripwire, on the response, before a byte reaches the client.
        if let Some(marker) = crate::response::subscription_marker(upstream_response.headers()) {
            self.kill(ticket.cred_ref(), ticket.cred_identity(), marker);
            return killed_response();
        }

        let (parts, body) = upstream_response.into_parts();
        let status = parts.status.as_u16();
        // Sampled-out (D-AJ) and off-marker requests are forwarded byte for byte with no tee
        // stream at all. Same code path, one fewer observer.
        let tee = observe.then(|| self.tee.open(facts));
        let forward = ForwardBody::new(body, tee, checkout, started, status, request_bytes);
        Response::from_parts(parts, forward.map_err(|e| Box::new(e) as BoxError).boxed())
    }

    /// §3.1 step 6, in order: session kill, config rollback (over the fabric), receipted
    /// event. None of it is sampled and none of it waits for the daemon.
    fn kill(&self, cred_ref: &str, fingerprint: &[u8; 32], marker: &str) {
        if let Ok(mut k) = self.killed.lock() {
            k.insert(cred_ref.to_owned());
        }
        tracing::error!(target: "mark1_proxy::guard", marker, "M1E-8002 oauth_contamination");
        self.fabric.contamination_alert(cred_ref);
        self.fabric
            .guard_decision(crate::guard::provenance::refused_record(
                Refusal::Contaminated,
                Some(*fingerprint),
            ));
    }

    /// Read-only view of the kill set, for `guard_contamination_killpath`. Not `#[cfg(test)]`
    /// because integration tests are a separate crate; it can only report a refusal, never
    /// clear one, so exposing it widens nothing.
    pub fn is_killed(&self, cred_ref: &str) -> bool {
        self.killed.lock().is_ok_and(|k| k.contains(cred_ref))
    }
}

/// M1E-8002. `Connection: close` is the "client connection closed" half of the kill: hyper
/// shuts the connection after this response, so the agent must reconnect — and every
/// reconnect lands back on the kill set.
fn killed_response() -> Response<ProxyBody> {
    let mut res = error(
        StatusCode::FORBIDDEN,
        "M1E-8002",
        "subscription marker detected upstream; session killed",
    );
    res.headers_mut().insert(
        http::header::CONNECTION,
        http::HeaderValue::from_static("close"),
    );
    res
}

fn error(status: StatusCode, code: &str, message: &str) -> Response<ProxyBody> {
    let body = crate::error_body(code, message);
    let mut res = Response::new(
        Full::new(Bytes::from(body))
            .map_err(|never| match never {})
            .boxed(),
    );
    *res.status_mut() = status;
    res.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/json"),
    );
    res
}
