//! Listener and request flow — 04 §3.1 (order), §3.4 (sidecar rules).
//!
//! [`Proxy::handle`] is the whole request path and runs the six §3.1 steps in the order the
//! document gives them. The one thing worth reading closely is what happens between steps:
//! nothing. There is no pre-guard forward, no cache of a previous decision, and no branch
//! that reaches [`crate::upstream::Pool::connect`] without a `ForwardTicket` — the ticket is
//! unconstructable outside `guard::provenance`, so the compiler is what enforces the order,
//! not this comment.

use std::collections::HashSet;
use std::io::Write;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use bytes::Bytes;
use http::{Response, StatusCode};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use mark1_frames::Dialect;
use mark1_policy::RouteSection;

use crate::fabric::Fabric;
use crate::gateway::Gateway;
use crate::guard::provenance::{fingerprint_hex, parse_fingerprint_hex};
use crate::guard::{Decision, Enrollment, ForwardTicket, Guard, Refusal};
use crate::response::ForwardBody;
use crate::tee::Tee;
use crate::upstream::Pool;
use crate::{ProxyConfig, Upstream};

type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type ProxyBody = BoxBody<Bytes, BoxError>;

/// The durable half of the §3.1 step 6 kill, beside `registry` and `guard.key` under
/// `ProxyConfig.base`. One `<cred-ref> <fingerprint-hex> <reason-code>` record per line, `#`
/// comments and blank lines skipped — `registry`'s format, because the two are read together
/// and a second grammar is a second parser to get wrong.
const KILL_FILE: &str = "guard-killed";

/// FR-ROUTE-008: the applied bundle's `route` section, decoded once into `requested model →
/// served model`. Every rung of a ladder is served by that ladder's entry rung (the prefix
/// principle: the cheapest rung that earned its place runs first); the first ladder naming a
/// model wins. Only ε=0 tables exist — see [`RouteTable::from_route`].
pub struct RouteTable {
    served: std::collections::HashMap<String, String>,
    bundle_seq: u64,
    /// `issued_at + max_age` epoch seconds; `u64::MAX` for a table built without a bundle envelope.
    fresh_until: u64,
}

impl RouteTable {
    /// `None` at ε≠0: exploration is not implemented, and a rewrite whose propensity this
    /// binary cannot state honestly is not made (FR-ROUTE-003) — the table stays ADVISORY.
    pub fn from_route(route: &RouteSection, bundle_seq: u64) -> Option<Self> {
        if route.exploration_epsilon != 0.0 {
            return None;
        }
        let mut served = std::collections::HashMap::new();
        for ladder in &route.ladders {
            let Some(entry) = ladder.rungs.first() else {
                continue;
            };
            for rung in &ladder.rungs {
                served
                    .entry(rung.model_id.clone())
                    .or_insert_with(|| entry.model_id.clone());
            }
        }
        Some(RouteTable {
            served,
            bundle_seq,
            fresh_until: u64::MAX,
        })
    }

    pub fn fresh_until(mut self, epoch_s: u64) -> Self {
        self.fresh_until = epoch_s;
        self
    }

    pub fn served(&self, requested: &str) -> Option<&str> {
        self.served.get(requested).map(String::as_str)
    }

    pub fn bundle_seq(&self) -> u64 {
        self.bundle_seq
    }
}

pub struct Proxy {
    cfg: Arc<ProxyConfig>,
    guard: Arc<Guard>,
    pool: Arc<Pool>,
    tee: Tee,
    fabric: Fabric,
    /// `None` ⇒ no rewrite, every request ADVISORY. Swapped by `policy::watch` via [`Proxy::set_route`].
    route: RwLock<Option<Arc<RouteTable>>>,
    /// §3.1 step 6: "all further requests for that session refused". Keyed by `M1-Cred-Ref`
    /// rather than by connection, because the ref is what identifies the agent config whose
    /// fragment must be reverted, and it survives the client reconnecting — which a
    /// connection-keyed set would not, making the kill last exactly one TCP session.
    ///
    /// Seeded from `KILL_FILE` at construction and appended to inside [`Proxy::kill`]. In
    /// memory alone it disarmed nothing durable: mark1d's rollback reverts the base-URL
    /// fragment but "the vendor does not unset an env var in an already-running session"
    /// (`go/mark1d/cmd/main.go`), so between the kill and the agent's relaunch this set is the
    /// only thing standing between an OAuth credential and this proxy — and a restart in that
    /// window emptied it, resumed carrying the contaminated session, and logged it as normal
    /// operation.
    killed: Arc<Mutex<HashSet<String>>>,
    /// What `Host` must equal (M1E-4004).
    bound_authority: String,
    /// `Some` ⇒ 04 §3.4 gateway: mTLS accept, credentials by reference.
    gateway: Option<Gateway>,
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
        let killed = load_killed(&cfg.base, &guard);
        Proxy {
            cfg,
            guard,
            pool,
            tee,
            fabric,
            route: RwLock::new(None),
            killed: Arc::new(Mutex::new(killed)),
            bound_authority: bound.to_string(),
            gateway: None,
        }
    }

    pub fn with_gateway(mut self, gateway: Gateway) -> Self {
        self.gateway = Some(gateway);
        self
    }

    pub fn with_route(self, table: RouteTable) -> Self {
        self.set_route(Some(Arc::new(table)));
        self
    }

    pub fn set_route(&self, table: Option<Arc<RouteTable>>) {
        if let Ok(mut r) = self.route.write() {
            *r = table;
        }
    }

    fn route_table(&self) -> Option<Arc<RouteTable>> {
        self.route.read().ok().and_then(|r| r.clone())
    }

    pub fn route_stale(&self, now_epoch_s: u64) -> bool {
        self.route_table()
            .is_some_and(|t| now_epoch_s > t.fresh_until)
    }

    pub async fn serve(self: Arc<Self>, listener: tokio::net::TcpListener) {
        loop {
            let Ok((stream, _peer)) = listener.accept().await else {
                continue;
            };
            let _ = stream.set_nodelay(true);
            let me = Arc::clone(&self);
            tokio::spawn(async move {
                match me.gateway.as_ref().map(|g| g.acceptor.clone()) {
                    // The handshake is where a missing or wrong-CA client certificate is refused.
                    Some(acceptor) => match acceptor.accept(stream).await {
                        Ok(tls) => me.connection(tls).await,
                        Err(e) => {
                            tracing::warn!(target: "mark1_proxy::gateway", %e, "mTLS refused")
                        }
                    },
                    None => me.connection(stream).await,
                }
            });
        }
    }

    async fn connection<I>(self: Arc<Self>, io: I)
    where
        I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let svc = hyper::service::service_fn(move |req| {
            let me = Arc::clone(&self);
            async move { Ok::<_, std::convert::Infallible>(me.handle(req).await) }
        });
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(hyper_util::rt::TokioIo::new(io), svc)
            .await;
    }

    pub async fn handle(&self, mut req: http::Request<Incoming>) -> Response<ProxyBody> {
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

        // Gateway: the credential is fetched by reference for this one request; a client that
        // brought its own is refused before the guard runs, so no code path forwards it.
        if let Some(gw) = &self.gateway {
            if req.headers().contains_key("x-api-key")
                || req.headers().contains_key(http::header::AUTHORIZATION)
            {
                return error(
                    StatusCode::FORBIDDEN,
                    "M1E-8001",
                    "gateway takes credentials by reference; request carried one",
                );
            }
            let cred_ref = req
                .headers()
                .get(crate::guard::CRED_REF_HEADER)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            let name = crate::gateway::credential_header(up.dialect(req.uri().path()));
            let value = match cred_ref {
                Some(r) => gw
                    .source
                    .resolve(&r)
                    .await
                    .and_then(|secret| crate::gateway::credential_value(&name, &secret)),
                None => None,
            };
            // Unresolvable ⇒ no credential header ⇒ the guard refuses (M1E-8001) and records it.
            if let Some(v) = value {
                req.headers_mut().insert(name, v);
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
        let mut facts = crate::request::facts(&req, &up);
        let dialect = facts.dialect;
        let _ = crate::request::redact_in_transit_eligible(false, dialect, &req);

        let req = crate::request::sanitize(req, &up);
        // Anthropic only: the tee cannot confirm a served model on a dialect it cannot parse.
        let req = match self.route_table() {
            Some(table) if dialect == Dialect::AnthropicSse => {
                match crate::request::rewrite_model(req, &table, &ticket, &mut facts).await {
                    Ok(r) => r,
                    Err(e) => return error(StatusCode::BAD_REQUEST, "M1E-2001", &e.to_string()),
                }
            }
            _ => req.map(crate::request::UpstreamBody::from),
        };
        // ponytail: request byte count from Content-Length; a chunked upload reports 0. A
        // counting body wrapper would be exact — add it when a dialect ships chunked
        // requests, which none of the five currently does.
        let request_bytes = req
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);

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
        let header = |name: &str| {
            parts
                .headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_owned()
        };
        let response_facts = crate::tee::ResponseFacts {
            status: parts.status.as_u16(),
            request_bytes,
            response_bytes: 0,
            elapsed_micros: 0,
            ttfb_micros: 0,
            request_id: [header("request-id"), header("x-request-id")]
                .into_iter()
                .find(|v| !v.is_empty())
                .unwrap_or_default(),
            stream: header("content-type").starts_with("text/event-stream"),
        };
        // Sampled-out (D-AJ) and off-marker requests are forwarded byte for byte with no tee
        // stream at all. Same code path, one fewer observer.
        let tee = observe.then(|| self.tee.open(facts));
        let forward = ForwardBody::new(body, tee, checkout, started, response_facts);
        Response::from_parts(parts, forward.map_err(|e| Box::new(e) as BoxError).boxed())
    }

    /// §3.1 step 6, in order: session kill, config rollback (over the fabric), receipted
    /// event. None of it is sampled and none of it waits for the daemon.
    fn kill(&self, cred_ref: &str, fingerprint: &[u8; 32], marker: &str) {
        if let Ok(mut k) = self.killed.lock() {
            k.insert(cred_ref.to_owned());
        }
        // Inline and synchronous, on the one path where that is the cheap option: the request
        // this belongs to is already being refused, so the fsync-shaped cost buys durability
        // at no latency any client can observe. Spawning it would put the P0 record's survival
        // on the same runtime as the crash it exists to survive.
        record_kill(
            &self.cfg.base,
            cred_ref,
            fingerprint,
            crate::guard::REASON_OAUTH_MARKER,
        );
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

/// Seed the kill set from `KILL_FILE`, dropping the records the registry has re-armed.
///
/// # Why a loaded record can expire, and why that is not an override path
///
/// CON-001 forbids any override path in the shipped binary, so there is no un-kill flag, env
/// var or fabric command — but a kill that nothing can ever lift is a permanently-red gate,
/// and a permanently-red gate is one everybody learns to route around. The resolution is that
/// **the state which lifts a kill is the same state that authorizes forwarding in the first
/// place**: a record is live only while the registry still enrolls its ref under the *same*
/// fingerprint.
///
/// Re-provisioning is what moves that state. `mark1 enable` rewrites the ref's registry line
/// with the fingerprint of whatever credential is now enrolled (`putRegistryLine`,
/// `go/mark1d/adapters/claudecode/baseurl.go`), and only after `Detect() == apikey`. So
/// re-enabling with the *same* key leaves the kill live — that credential is the one an
/// upstream marker proved subscription-backed — and enrolling a *different* one clears it,
/// because a different credential is a different question. Nothing new to grep for in the
/// binary, and nothing an operator can reach without provisioning a credential.
///
/// Every uncertain branch keeps the kill. An unreadable registry ([`Enrollment::Unverifiable`],
/// 04 §3.5 row 1) and an unparseable fingerprint field are both states in which we cannot say a
/// different credential was enrolled, and "we could not tell" must not be spelled the same way
/// as "you re-provisioned". Otherwise corrupting or deleting one file is an un-kill switch
/// made of `dd`.
fn load_killed(base: &Path, guard: &Guard) -> HashSet<String> {
    let mut out = HashSet::new();
    // Absent is the overwhelmingly common case (no device has ever been contaminated) and is
    // not an error: no records, no kills.
    let Ok(raw) = std::fs::read_to_string(base.join(KILL_FILE)) else {
        return out;
    };
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // `split_once(' ')` exactly as `registry` splits, so a ref is "everything before the
        // first space" in both files and neither can name a ref the other cannot.
        let (cred_ref, rest) = line.split_once(' ').unwrap_or((line, ""));
        let recorded = parse_fingerprint_hex(rest.split(' ').next().unwrap_or_default());
        if recorded.is_none() {
            tracing::error!(
                target: "mark1_proxy::guard",
                cred_ref,
                "M1E-8002 kill record has no readable fingerprint (torn write?): the kill is \
                 kept and re-provisioning cannot lift it — repair or remove the guard-killed line"
            );
        }
        match guard.enrollment(cred_ref) {
            // A different credential is enrolled for this ref now. The upstream marker was
            // about the old one, and this is the only branch that may forget it.
            Enrollment::Enrolled(enrolled) if recorded.is_some_and(|fp| fp != enrolled) => {
                tracing::info!(
                    target: "mark1_proxy::guard",
                    cred_ref,
                    "kill record dropped: a different credential is enrolled for this ref"
                );
            }
            Enrollment::Enrolled(_) | Enrollment::Unverifiable => {
                out.insert(cred_ref.to_owned());
            }
            Enrollment::Absent => {
                tracing::info!(
                    target: "mark1_proxy::guard",
                    cred_ref,
                    "kill record dropped: the registry no longer enrolls this ref"
                );
            }
        }
    }
    if !out.is_empty() {
        tracing::warn!(
            target: "mark1_proxy::guard",
            count = out.len(),
            "M1E-8002 kill records loaded: these credentials stay refused (04 §3.1 step 6)"
        );
    }
    out
}

/// Append one `(cred_ref, fingerprint, reason_code)` record. Best-effort by construction —
/// every failure arm is silent because the in-memory kill has already taken effect and this
/// function may not turn a disk problem into a request path panic. The failure it accepts is
/// "the kill does not survive a restart"; the one it must not produce is "the kill did not
/// happen".
fn record_kill(base: &Path, cred_ref: &str, fingerprint: &[u8; 32], reason: &str) {
    // A ref containing a space would reload as a record for a DIFFERENT, shorter ref — a kill
    // silently retargeted by string surgery. `registry` cannot express such a ref either
    // (`split_once(' ')`), so it could never be re-armed and is not one we can have enrolled.
    if cred_ref.is_empty() || cred_ref.contains(|c: char| c.is_whitespace()) {
        tracing::error!(
            target: "mark1_proxy::guard",
            "M1E-8002 kill not persisted: cred_ref is not representable in guard-killed"
        );
        return;
    }
    let _ = std::fs::create_dir_all(base);
    let Ok(mut file) = open_kill_file(&base.join(KILL_FILE)) else {
        tracing::error!(
            target: "mark1_proxy::guard",
            "M1E-8002 kill not persisted: a restart before the agent relaunches will resume \
             carrying this session"
        );
        return;
    };
    let _ = file
        .write_all(format!("{cred_ref} {} {reason}\n", fingerprint_hex(fingerprint)).as_bytes());
}

/// 0600, appended to rather than rewritten — the file is the kill history and truncating it is
/// the un-kill switch this design refuses to have.
///
/// `mode()` applies only at creation, so it does not narrow a file that already exists: EDGE-05
/// was exactly that bug against `proxy.port`, and an inherited 0644 here would leave every
/// local user able to read which credential this device is refusing. The `set_permissions` is on
/// the handle we already hold, not on the path, so there is no window to swap a file into.
#[cfg(unix)]
fn open_kill_file(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(path)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    Ok(file)
}

#[cfg(not(unix))]
fn open_kill_file(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)
}

/// M1E-8002. `Connection: close` is the "client connection closed" half of the kill: hyper
/// shuts the connection after this response, so the agent must reconnect — and every
/// reconnect lands back on the kill set.
///
/// The message names the remedy because the kill is now durable across restarts and there is
/// deliberately no flag that lifts it (see `load_killed`): a developer who reads only "session
/// killed" has a dead agent, a refusal that survives every restart, and no way to tell that
/// re-provisioning is the intended way out rather than a workaround.
fn killed_response() -> Response<ProxyBody> {
    let mut res = error(
        StatusCode::FORBIDDEN,
        "M1E-8002",
        "subscription marker detected upstream; session killed and this credential stays \
         refused across restarts — enroll a different API key (`mark1 enable`) to clear it",
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
