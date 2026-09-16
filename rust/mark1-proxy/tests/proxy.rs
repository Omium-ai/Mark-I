//! End-to-end tests for the properties that are legal claims rather than features.
//!
//! Every test here drives the proxy over a real TCP socket against a real upstream socket.
//! Calling `Proxy::handle` directly would test the same code with none of the framing, and
//! the byte-exactness assertion (12 §3.1) is specifically about what a client *receives*.
//!
//! One file on purpose: the fake upstream and the raw client are the whole harness, and a
//! `common/` module for two structs is a directory to maintain.

// WHY: `clippy.toml` sets `allow-unwrap-in-tests`, but clippy only recognises `#[test]` fns and
// `#[cfg(test)]` modules — the harness functions in an integration-test crate are neither, and
// this whole file is test code. Threading `Result` through a fake upstream would add error
// plumbing that exists only to be discarded, and a harness that swallows its own setup failure
// is how a suite reports success while testing nothing.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use m1p_wire::pb::RouteFidelity;
use mark1_frames::{DegradeReason, Dialect};
use mark1_policy::{CostBasis, KneeTable, Ladder, RouteSection, Rung};
use mark1_proxy::fabric::Fabric;
use mark1_proxy::guard::{Guard, Sampling};
use mark1_proxy::router::{Proxy, RouteTable};
use mark1_proxy::tee::{self, RequestFacts, TeeReport, TeeRx};
use mark1_proxy::upstream::Pool;
use mark1_proxy::{Mode, ProxyConfig, Upstream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A provisioned Anthropic API key shape. Not a live credential — the guard fingerprints
/// whatever bytes it is given, so the value only has to have the right grammar.
const API_KEY: &[u8] = b"sk-ant-api03-AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz01";
/// An OAuth access token shape — the credential class this binary may never carry.
const OAUTH_TOKEN: &[u8] = b"sk-ant-oat01-AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz01";
const API_KEY_2: &[u8] = b"sk-ant-api03-ZzYyXxWwVvUuTtSsRrQqPpOoNnMmLlKkJjIiHhGgFfEeDdCcBbAa99";
const CRED_REF: &str = "ref-1";
const CRED_REF_2: &str = "ref-2";
/// The device-local guard key every `Guard` in this file fingerprints under. One constant so
/// a proxy rebuilt over an existing `base` verifies against the same enrollment the first one
/// did — two keys would make every re-load look like a fingerprint mismatch.
const GUARD_KEY: &[u8] = b"device-local-guard-key";

/// `ref → enrollment fingerprint`, computed the one way the guard computes it.
fn registry_of(pairs: &[(&str, &[u8])]) -> HashMap<String, [u8; 32]> {
    let probe = Guard::from_parts(GUARD_KEY.to_vec(), HashMap::new(), Sampling::default());
    pairs
        .iter()
        .map(|(r, cred)| ((*r).to_owned(), probe.fingerprint(cred).unwrap()))
        .collect()
}

/// The `registry`/`guard-killed` field encoding (`provenance::fingerprint_hex`), restated
/// here rather than exported: a test that writes the file by hand has to spell the format
/// itself, or it is asserting that the writer agrees with itself.
fn hex32(fp: &[u8; 32]) -> String {
    fp.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------------------
// Fake upstream: raw TCP, so the response bytes on the wire are exactly what a test says.
// ---------------------------------------------------------------------------------------

#[derive(Default)]
struct UpstreamState {
    connections: AtomicUsize,
    requests: Mutex<Vec<Vec<u8>>>,
}

struct FakeUpstream {
    addr: SocketAddr,
    state: Arc<UpstreamState>,
}

/// One full request off the socket: the head, then exactly its declared `Content-Length`.
async fn read_request(sock: &mut tokio::net::TcpStream) -> Option<Vec<u8>> {
    let mut raw = Vec::new();
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let need = raw.windows(4).position(|w| w == b"\r\n\r\n").map(|split| {
            let head = String::from_utf8_lossy(&raw[..split]).to_ascii_lowercase();
            let cl = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            split + 4 + cl
        });
        if need.is_some_and(|n| raw.len() >= n) {
            return Some(raw);
        }
        let n = sock.read(&mut buf).await.unwrap_or(0);
        if n == 0 {
            return None;
        }
        raw.extend_from_slice(&buf[..n]);
    }
}

impl FakeUpstream {
    /// `response` is written verbatim, head and all.
    async fn start(response: Vec<u8>) -> Self {
        Self::start_with(response, false).await
    }

    /// `reset = true`: read the request head and slam the connection (RST) instead of answering.
    async fn start_with(response: Vec<u8>, reset: bool) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(UpstreamState::default());
        let s = Arc::clone(&state);
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    continue;
                };
                s.connections.fetch_add(1, Ordering::SeqCst);
                let s = Arc::clone(&s);
                let response = response.clone();
                // Keep-alive, because "did the pool reuse this connection?" is only a question
                // an upstream that would accept a second request can answer.
                tokio::spawn(async move {
                    loop {
                        if reset {
                            let mut buf = [0u8; 1024];
                            let _ = sock.read(&mut buf).await;
                            // Zero linger turns the drop below into an RST, not a FIN.
                            #[allow(deprecated)]
                            let _ = sock.set_linger(Some(Duration::ZERO));
                            return;
                        }
                        let Some(req) = read_request(&mut sock).await else {
                            return;
                        };
                        s.requests.lock().unwrap().push(req);
                        if sock.write_all(&response).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        FakeUpstream { addr, state }
    }

    fn connections(&self) -> usize {
        self.state.connections.load(Ordering::SeqCst)
    }

    fn last_request(&self) -> Vec<u8> {
        self.state
            .requests
            .lock()
            .unwrap()
            .last()
            .cloned()
            .unwrap_or_default()
    }
}

fn http_response(extra_headers: &str, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\n{}\r\n",
        body.len(),
        extra_headers
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

// ---------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------

struct Ctx {
    addr: SocketAddr,
    upstream: FakeUpstream,
    proxy: Arc<Proxy>,
    tee: tee::Tee,
    reports: Option<tokio::sync::mpsc::Receiver<TeeReport>>,
    /// Held, not run, when a test wants a tee that never drains.
    _tee_rx: Option<TeeRx>,
    _base: tempfile::TempDir,
}

/// `run_tee = false` leaves the tee receiver un-polled: retained bytes are never released,
/// which is exactly the saturated state D-AH bounds. No test-only seam is needed for it.
async fn start(response: Vec<u8>, run_tee: bool) -> Ctx {
    start_with(
        FakeUpstream::start(response).await,
        run_tee,
        None,
        Dialect::AnthropicSse,
    )
    .await
}

/// The bundle a routed test applies: `ROUTED` is served by `ENTRY`, `UNROUTED` is unknown.
const ENTRY: &str = "claude-haiku-4-5";
const ROUTED: &str = "claude-opus-4-1-20250805";
const UNROUTED: &str = "claude-3-7-sonnet-latest";
const BUNDLE_SEQ: u64 = 7;

fn route_section(epsilon: f64) -> RouteSection {
    let rung = |m: &str| Rung {
        model_id: m.to_owned(),
        keep_prefix: true,
    };
    RouteSection {
        cpvs: vec![],
        ladders: vec![Ladder {
            ladder_id: "default".to_owned(),
            rungs: vec![rung(ENTRY), rung("claude-sonnet-4-5"), rung(ROUTED)],
        }],
        knee: KneeTable {
            cost_basis: CostBasis::Usd,
            rows: vec![],
            v_default: 0.0,
        },
        exploration_epsilon: epsilon,
    }
}

async fn start_routed(response: Vec<u8>, dialect: Dialect) -> Ctx {
    let table = RouteTable::from_route(&route_section(0.0), BUNDLE_SEQ).unwrap();
    start_with(
        FakeUpstream::start(response).await,
        true,
        Some(table),
        dialect,
    )
    .await
}

async fn start_with(
    upstream: FakeUpstream,
    run_tee: bool,
    route: Option<RouteTable>,
    dialect: Dialect,
) -> Ctx {
    let base = tempfile::tempdir().unwrap();

    // `ref-oauth` enrolls an OAuth token: the §3.1 step 5 case, where provenance passes and
    // shape inspection is the only thing left.
    let registry = registry_of(&[
        (CRED_REF, API_KEY),
        (CRED_REF_2, API_KEY_2),
        ("ref-oauth", OAUTH_TOKEN),
    ]);
    let guard = Arc::new(Guard::from_parts(
        GUARD_KEY.to_vec(),
        registry,
        Sampling::from_bundle(1.0),
    ));

    let cfg = Arc::new(ProxyConfig {
        mode: Mode::Sidecar,
        bind: "127.0.0.1:0".parse().unwrap(),
        // Declared, not inferred: the fixtures are Anthropic SSE, and host inference on a
        // loopback address would hand the tee the `Unimplemented` parser — which degrades
        // unconditionally and would make the degradation assertion below pass for free.
        upstreams: vec![Upstream::new("127.0.0.1", upstream.addr.port(), false)
            .unwrap()
            .with_dialect(dialect)],
        forward_sample_rate: 1.0,
        base: base.path().to_path_buf(),
    });

    let listener = tokio::net::TcpListener::bind(cfg.bind).await.unwrap();
    let addr = listener.local_addr().unwrap();

    let (tee, tee_rx) = tee::channel();
    let (reports_tx, reports_rx) = tokio::sync::mpsc::channel(64);
    let (reports, held_rx) = if run_tee {
        // Own thread + current-thread runtime: `Box<dyn DialectParser>` is not `Send`.
        std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap()
                .block_on(tee::run(tee_rx, reports_tx));
        });
        (Some(reports_rx), None)
    } else {
        (Some(reports_rx), Some(tee_rx))
    };

    let proxy = Proxy::new(
        cfg,
        guard,
        Arc::new(Pool::new().unwrap()),
        tee.clone(),
        Fabric::new(base.path()),
        addr,
    );
    let proxy = Arc::new(match route {
        Some(table) => proxy.with_route(table),
        None => proxy,
    });
    tokio::spawn(Arc::clone(&proxy).serve(listener));

    Ctx {
        addr,
        upstream,
        proxy,
        tee,
        reports,
        _tee_rx: held_rx,
        _base: base,
    }
}

struct RawResponse {
    status: u16,
    head: String,
    body: Vec<u8>,
}

impl RawResponse {
    fn error_code(&self) -> Option<String> {
        let v: serde_json::Value = serde_json::from_slice(&self.body).ok()?;
        Some(v["error"]["code"].as_str()?.to_owned())
    }
}

/// `headers` are appended verbatim; each must end with CRLF.
async fn request(addr: SocketAddr, headers: &str) -> RawResponse {
    request_with_body(addr, headers, b"").await
}

/// `headers` must not declare a length; the body's is added.
async fn request_with_body(addr: SocketAddr, headers: &str, body: &[u8]) -> RawResponse {
    request_in_frames(addr, headers, &[body]).await
}

/// The body arrives as separate TCP writes with a pause between, so hyper yields one frame each.
async fn request_in_frames(addr: SocketAddr, headers: &str, frames: &[&[u8]]) -> RawResponse {
    let len: usize = frames.iter().map(|f| f.len()).sum();
    let head = format!(
        "POST /v1/messages HTTP/1.1\r\nhost: {addr}\r\nconnection: close\r\n{headers}content-length: {len}\r\n\r\n"
    );
    let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
    sock.write_all(head.as_bytes()).await.unwrap();
    for (i, frame) in frames.iter().enumerate() {
        if i > 0 {
            tokio::time::sleep(Duration::from_millis(60)).await;
        }
        sock.write_all(frame).await.unwrap();
    }
    let mut raw = Vec::new();
    sock.read_to_end(&mut raw).await.unwrap();

    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("no header terminator");
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .expect("no status code");
    RawResponse {
        status,
        body: raw[split + 4..].to_vec(),
        head,
    }
}

/// The next tee report, or a failure. Never a silent skip: a test that would otherwise pass
/// by observing nothing is the defect this harness is trying not to be.
async fn report(ctx: &mut Ctx) -> TeeReport {
    tokio::time::timeout(Duration::from_secs(5), ctx.reports.as_mut().unwrap().recv())
        .await
        .expect("tee produced no report")
        .expect("tee channel closed")
}

/// A restarted proxy: a wholly new `Proxy` over an existing `base`, sharing no memory with
/// whatever ran there before. No listener and no upstream, because the question these tests
/// ask is what `Proxy::new` loads off disk, and sockets would only add ways for the answer to
/// be about something else.
fn rebuild(base: &std::path::Path, registry: HashMap<String, [u8; 32]>) -> Proxy {
    proxy_with(
        base,
        Guard::from_parts(GUARD_KEY.to_vec(), registry, Sampling::default()),
    )
}

fn proxy_with(base: &std::path::Path, guard: Guard) -> Proxy {
    let cfg = Arc::new(ProxyConfig {
        mode: Mode::Sidecar,
        bind: "127.0.0.1:0".parse().unwrap(),
        upstreams: vec![Upstream::new("127.0.0.1", 1, false).unwrap()],
        forward_sample_rate: 1.0,
        base: base.to_path_buf(),
    });
    // Named, not `.0`: `secret_type_gate.sh` rule 3 bans an inner-value escape by position
    // anywhere outside `secret.rs`, and it is a text rule on purpose — it cannot tell this
    // tuple from a `Secret`'s, and a rule that had to would be a rule that could be dodged.
    let (tee, _rx) = tee::channel();
    Proxy::new(
        cfg,
        Arc::new(guard),
        Arc::new(Pool::new().unwrap()),
        tee,
        Fabric::new(base),
        "127.0.0.1:1".parse().unwrap(),
    )
}

/// Plant the device spill public key so `Fabric::emit`'s no-daemon path has somewhere to put
/// a frame. Returns the matching secret, which is the only thing that can read the ring back —
/// `tee::spill` seals every record and this test asserts on content, not on file size.
fn device_spill_key(base: &std::path::Path) -> x25519_dalek::StaticSecret {
    use chacha20poly1305::aead::OsRng;
    let secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    std::fs::create_dir_all(base.join("spill")).unwrap();
    std::fs::write(
        base.join("spill/spill.pub"),
        x25519_dalek::PublicKey::from(&secret).as_bytes(),
    )
    .unwrap();
    secret
}

/// Every frame the proxy sealed into `spill/proxy.ring`, decrypted. Record layout and KDF are
/// restated from `tee::spill` deliberately: a reader that shared the writer's code would prove
/// only that the writer agrees with itself. A record that will not decrypt is skipped rather
/// than fatal — the ring is being appended to concurrently, and the caller polls.
fn spilled_frames(
    base: &std::path::Path,
    secret: &x25519_dalek::StaticSecret,
) -> Vec<m1p_wire::pb::FabricFrame> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use hmac::Mac;

    // version(1) | unix_secs(8) | ephemeral_pub(32) | nonce(12) | ciphertext
    const HEAD: usize = 1 + 8 + 32 + 12;
    let Ok(ring) = std::fs::read(base.join("spill/proxy.ring")) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut at = 0usize;
    while at + 4 <= ring.len() {
        let len = u32::from_le_bytes(ring[at..at + 4].try_into().unwrap()) as usize;
        if len <= HEAD || at + 4 + len > ring.len() {
            break;
        }
        let record = &ring[at + 4..at + 4 + len];
        at += 4 + len;

        let ephemeral: [u8; 32] = record[9..41].try_into().unwrap();
        let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(ephemeral));
        let mut kdf = <hmac::Hmac<sha2::Sha256> as Mac>::new_from_slice(shared.as_bytes()).unwrap();
        kdf.update(b"m1p.spill.seal.v1");
        let key: [u8; 32] = kdf.finalize().into_bytes().into();
        let plain = chacha20poly1305::ChaCha20Poly1305::new((&key).into()).decrypt(
            chacha20poly1305::Nonce::from_slice(&record[41..HEAD]),
            &record[HEAD..],
        );
        if let Ok(frames) = plain.and_then(|p| {
            m1p_wire::FrameDecoder::new()
                .feed_frames(&p)
                .map_err(|_| chacha20poly1305::aead::Error)
        }) {
            out.extend(frames);
        }
    }
    out
}

fn cred_headers(cred_ref: &str, cred: &[u8]) -> String {
    format!(
        "m1-cred-ref: {cred_ref}\r\nx-api-key: {}\r\n",
        String::from_utf8_lossy(cred)
    )
}

// ---------------------------------------------------------------------------------------
// 12 §9 — guard_no_forward_path
// ---------------------------------------------------------------------------------------

/// The negative test the legal claim rests on: no request bearing an unprovisioned
/// credential reaches the upstream, in any shape.
///
/// The upstream is a socket that counts *connections*. That is the assertion that matters —
/// a test which only checked the 403 would pass just as happily against a proxy that
/// forwarded first and refused afterwards.
#[tokio::test(flavor = "multi_thread")]
async fn guard_no_forward_path() {
    let ctx = start(http_response("", b"{}"), true).await;

    let oauth = String::from_utf8_lossy(OAUTH_TOKEN).to_string();
    let api = String::from_utf8_lossy(API_KEY).to_string();
    let cases: Vec<(&str, String)> = vec![
        ("no M1-Cred-Ref at all", format!("x-api-key: {api}\r\n")),
        ("M1-Cred-Ref but no credential", format!("m1-cred-ref: {CRED_REF}\r\n")),
        ("unknown ref", cred_headers("ref-does-not-exist", API_KEY)),
        ("fingerprint mismatch", cred_headers(CRED_REF, b"sk-ant-api03-someotherkey0000000000000000000000")),
        ("oauth token presented under a valid ref", cred_headers(CRED_REF, OAUTH_TOKEN)),
        (
            "oauth token that IS the enrolled credential (provisioning bug, step 5)",
            cred_headers("ref-oauth", OAUTH_TOKEN),
        ),
        (
            "x-api-key and Authorization disagree",
            format!(
                "m1-cred-ref: {CRED_REF}\r\nx-api-key: {api}\r\nauthorization: Bearer {oauth}\r\n"
            ),
        ),
        (
            "bearer-only oauth under a valid ref",
            format!("m1-cred-ref: {CRED_REF}\r\nauthorization: Bearer {oauth}\r\n"),
        ),
        // The shape that defeated the structural claim: the guard reads header value #1
        // and hyper forwards BOTH lines, so a second x-api-key smuggles an unprovisioned
        // OAuth token past a guard that verified the first one. Enrolled key first, so
        // fingerprinting and shape classification both succeed on what the guard inspects.
        (
            "duplicate x-api-key smuggling an oauth token",
            format!(
                "m1-cred-ref: {CRED_REF}\r\nx-api-key: {api}\r\nx-api-key: {oauth}\r\n"
            ),
        ),
        (
            "duplicate x-api-key, both the enrolled value",
            format!(
                "m1-cred-ref: {CRED_REF}\r\nx-api-key: {api}\r\nx-api-key: {api}\r\n"
            ),
        ),
        (
            "duplicate Authorization",
            format!(
                "m1-cred-ref: {CRED_REF}\r\nauthorization: Bearer {api}\r\nauthorization: Bearer {oauth}\r\n"
            ),
        ),
    ];
    assert!(
        cases.len() >= 11,
        "table shrank — this test's coverage is its table"
    );

    for (label, headers) in &cases {
        let res = request(ctx.addr, headers).await;
        assert_eq!(res.status, 403, "{label}: expected 403");
        assert_eq!(res.error_code().as_deref(), Some("M1E-8001"), "{label}");
    }

    assert_eq!(
        ctx.upstream.connections(),
        0,
        "an unprovisioned credential opened an upstream connection"
    );

    // Positive control: the harness CAN reach the upstream, so the zero above is a property
    // of the guard and not of a misconfigured fixture.
    let ok = request(ctx.addr, &cred_headers(CRED_REF, API_KEY)).await;
    assert_eq!(
        ok.status, 200,
        "provisioned credential must forward: {}",
        ok.head
    );
    assert_eq!(ctx.upstream.connections(), 1);
}

/// The off-marker must not become the override path §3.1 step 4 forbids. 04 §9.6 draws
/// `RECEIVED --> NOOP_FORWARD` straight off `RECEIVED`, which read literally would make
/// `~/.omium/mark1/OFF` an env-adjacent switch that forwards anything.
#[tokio::test(flavor = "multi_thread")]
async fn off_marker_is_not_an_override_path() {
    let ctx = start(http_response("", b"{}"), true).await;
    std::fs::write(ctx._base.path().join("OFF"), b"").unwrap();

    let api = String::from_utf8_lossy(API_KEY).to_string();
    let res = request(ctx.addr, &format!("x-api-key: {api}\r\n")).await;
    assert_eq!(
        res.status, 403,
        "off-marker forwarded a request with no M1-Cred-Ref"
    );
    assert_eq!(res.error_code().as_deref(), Some("M1E-8001"));
    assert_eq!(ctx.upstream.connections(), 0);

    // A provisioned credential still forwards while off — that is what "pure pass-through"
    // means — and the tee sees nothing.
    let ok = request(ctx.addr, &cred_headers(CRED_REF, API_KEY)).await;
    assert_eq!(ok.status, 200);
}

/// 08 §9 M1E-4004 / M1E-4005, both fail-closed, both ahead of the upstream.
#[tokio::test(flavor = "multi_thread")]
async fn loopback_rules_refuse_browser_and_rebound_hosts() {
    let ctx = start(http_response("", b"{}"), true).await;

    let mut headers = cred_headers(CRED_REF, API_KEY);
    headers.push_str("origin: https://evil.example\r\n");
    let res = request(ctx.addr, &headers).await;
    assert_eq!(res.status, 403);
    assert_eq!(res.error_code().as_deref(), Some("M1E-4005"));

    // `request()` always sends the correct Host, so a wrong one is built by hand.
    let head = format!(
        "POST /v1/messages HTTP/1.1\r\nhost: attacker.example\r\nconnection: close\r\n{}content-length: 0\r\n\r\n",
        cred_headers(CRED_REF, API_KEY)
    );
    let mut sock = tokio::net::TcpStream::connect(ctx.addr).await.unwrap();
    sock.write_all(head.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    sock.read_to_end(&mut raw).await.unwrap();
    assert!(
        String::from_utf8_lossy(&raw).contains("M1E-4004"),
        "wrong Host was accepted: {}",
        String::from_utf8_lossy(&raw)
    );

    assert_eq!(ctx.upstream.connections(), 0);
}

// ---------------------------------------------------------------------------------------
// 12 §9 — guard_contamination_killpath
// ---------------------------------------------------------------------------------------

/// §3.1 step 6 / D-AI. A subscription marker on the response means an OAuth credential got
/// through everything, and the proxy acts on its own authority: session killed, connection
/// closed, every later request for that ref refused without touching the upstream.
#[tokio::test(flavor = "multi_thread")]
async fn guard_contamination_killpath() {
    let contaminated = http_response(
        "anthropic-ratelimit-unified-status: allowed\r\n",
        b"{\"ok\":true}",
    );
    let ctx = start(contaminated, true).await;
    let device = device_spill_key(ctx._base.path());

    let res = request(ctx.addr, &cred_headers(CRED_REF, API_KEY)).await;
    assert_eq!(res.status, 403);
    assert_eq!(res.error_code().as_deref(), Some("M1E-8002"));
    assert!(
        res.head.to_ascii_lowercase().contains("connection: close"),
        "the kill must close the client connection: {}",
        res.head
    );
    // The upstream's body must not have reached the client.
    assert!(!res.body.windows(2).any(|w| w == b"ok"));
    assert!(ctx.proxy.is_killed(CRED_REF));
    assert_eq!(ctx.upstream.connections(), 1);

    // "all further requests for that session refused" — and refused locally.
    let again = request(ctx.addr, &cred_headers(CRED_REF, API_KEY)).await;
    assert_eq!(again.error_code().as_deref(), Some("M1E-8002"));
    assert_eq!(
        ctx.upstream.connections(),
        1,
        "a killed session reached the upstream again"
    );

    // 12 §9 row 1 names three legs: session kill + rollback + receipted `oauth_contamination`.
    // Legs 2 and 3 are mark1d's — it reverts the base-URL fragment and mints the receipt on
    // the device origin chain — and nothing in this crate can observe them. What IS this
    // crate's and was untested is the *trigger*: the `ContaminationAlert` frame, without which
    // neither of the other two legs ever happens. Asserted on the sealed spill ring, because
    // that is where `Fabric::emit` puts a frame no daemon accepted (fabric.rs, tee::spill).
    let alert = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let found = spilled_frames(ctx._base.path(), &device)
                .into_iter()
                .find_map(|f| match f.kind {
                    Some(m1p_wire::pb::fabric_frame::Kind::ContaminationAlert(a)) => Some(a),
                    _ => None,
                });
            if let Some(a) = found {
                return a;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("no ContaminationAlert frame was emitted — mark1d's rollback is never triggered");
    assert_eq!(alert.cred_ref, CRED_REF, "the alert names the wrong ref");
    assert_eq!(alert.reason_code, mark1_proxy::guard::REASON_OAUTH_MARKER);
    assert_ne!(
        alert.session_id, [0u8; 16],
        "D-AT: mark1d refuses a zero session id"
    );
}

/// The finding this whole file's kill path rested on: the set was in memory only, so a crash,
/// a supervisor restart or a machine sleep between the kill and the agent's relaunch cleared
/// it — and mark1d's own rollback comment says the running agent keeps the stale
/// `ANTHROPIC_BASE_URL` until it is relaunched, so the restarted proxy would resume carrying
/// the contaminated session and report it as normal operation.
#[tokio::test(flavor = "multi_thread")]
async fn a_kill_survives_a_proxy_restart() {
    let contaminated = http_response(
        "anthropic-ratelimit-unified-status: allowed\r\n",
        b"{\"ok\":true}",
    );
    let ctx = start(contaminated, true).await;
    let res = request(ctx.addr, &cred_headers(CRED_REF, API_KEY)).await;
    assert_eq!(res.error_code().as_deref(), Some("M1E-8002"));

    // The restart: a wholly new `Proxy` over the same `base`, sharing nothing in memory.
    let restarted = rebuild(ctx._base.path(), registry_of(&[(CRED_REF, API_KEY)]));
    assert!(
        restarted.is_killed(CRED_REF),
        "the kill did not survive a restart"
    );
    assert!(
        !restarted.is_killed(CRED_REF_2),
        "an unrelated ref was killed"
    );
}

/// The re-arm rule, both directions. CON-001 permits no override path in the binary, so there
/// is no flag that lifts a kill; what lifts it is re-provisioning, because `mark1 enable`
/// rewrites the ref's registry line with the new credential's fingerprint. Re-enabling with
/// the SAME key must leave the kill standing — that credential is the one the upstream proved
/// subscription-backed.
#[test]
fn only_enrolling_a_different_credential_lifts_a_kill() {
    let base = tempfile::tempdir().unwrap();
    let fp = registry_of(&[(CRED_REF, API_KEY)])[CRED_REF];
    std::fs::write(
        base.path().join("guard-killed"),
        format!("# killed\n\n{CRED_REF} {} oauth_marker\n", hex32(&fp)),
    )
    .unwrap();

    let same = rebuild(base.path(), registry_of(&[(CRED_REF, API_KEY)]));
    assert!(
        same.is_killed(CRED_REF),
        "re-enabling the SAME credential cleared its kill"
    );

    let different = rebuild(base.path(), registry_of(&[(CRED_REF, API_KEY_2)]));
    assert!(
        !different.is_killed(CRED_REF),
        "a different credential is enrolled for this ref: the kill is about the old one"
    );

    // A ref the registry no longer knows at all is the same answer for the same reason.
    let gone = rebuild(base.path(), registry_of(&[(CRED_REF_2, API_KEY_2)]));
    assert!(!gone.is_killed(CRED_REF));
}

/// 04 §3.5 row 1 is the state in which the proxy trusts itself least. It must not also be the
/// state in which it forgets which credentials it is refusing — otherwise deleting or
/// corrupting `registry` is an un-kill switch, and it is the one file a contaminated device's
/// user has every reason to go poking at.
#[test]
fn an_unverifiable_guard_does_not_clear_kill_records() {
    let base = tempfile::tempdir().unwrap();
    let fp = registry_of(&[(CRED_REF, API_KEY)])[CRED_REF];
    std::fs::write(
        base.path().join("guard-killed"),
        format!("{CRED_REF} {} oauth_marker\n", hex32(&fp)),
    )
    .unwrap();

    let proxy = proxy_with(base.path(), Guard::unverifiable(Sampling::default()));
    assert!(
        proxy.is_killed(CRED_REF),
        "an unreadable registry cleared a kill record"
    );
}

/// EDGE-05's shape, on a file that says which credential this device caught carrying
/// subscription traffic. `mode()` applies only at creation, so an append to an inherited 0644
/// file leaves it 0644 — the exact bug `proxy.port` already had once.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn kill_file_is_private_even_when_it_already_existed_world_readable() {
    use std::os::unix::fs::PermissionsExt;

    let contaminated = http_response(
        "anthropic-ratelimit-unified-status: allowed\r\n",
        b"{\"ok\":true}",
    );
    let ctx = start(contaminated, true).await;
    let path = ctx._base.path().join("guard-killed");
    std::fs::write(&path, "# pre-existing\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

    let res = request(ctx.addr, &cred_headers(CRED_REF, API_KEY)).await;
    assert_eq!(res.error_code().as_deref(), Some("M1E-8002"));

    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "guard-killed must not be readable by other users"
    );
    let written = std::fs::read_to_string(&path).unwrap();
    assert!(
        written.contains("# pre-existing"),
        "the kill history was truncated rather than appended to: {written}"
    );
    assert!(
        written.contains(&format!(
            "{CRED_REF} {} oauth_marker",
            hex32(&registry_of(&[(CRED_REF, API_KEY)])[CRED_REF])
        )),
        "no kill record was written: {written}"
    );
}

/// The false positive that would kill a paying customer: API-key rate-limit headers look
/// almost identical to the subscription family.
#[tokio::test(flavor = "multi_thread")]
async fn api_key_ratelimit_headers_do_not_trigger_the_killpath() {
    let normal = http_response(
        "anthropic-ratelimit-requests-limit: 1000\r\nanthropic-ratelimit-tokens-remaining: 40000\r\n",
        b"{\"ok\":true}",
    );
    let ctx = start(normal, true).await;
    let res = request(ctx.addr, &cred_headers(CRED_REF, API_KEY)).await;
    assert_eq!(res.status, 200, "{}", res.head);
    assert!(!ctx.proxy.is_killed(CRED_REF));
}

// ---------------------------------------------------------------------------------------
// 12 §9 — neg_tee_field_allowlist
// ---------------------------------------------------------------------------------------

/// The tee is handed an allow-list, never a request. This asserts the consequence: nothing
/// the tee ever holds contains the credential, the cred-ref, or any header at all.
#[tokio::test(flavor = "multi_thread")]
async fn neg_tee_field_allowlist() {
    let ctx = start(http_response("", b"{\"ok\":true}"), true).await;
    let mut ctx = ctx;
    let res = request(ctx.addr, &cred_headers(CRED_REF, API_KEY)).await;
    assert_eq!(res.status, 200, "{}", res.head);

    let report = report(&mut ctx).await;

    // Everything the tee holds, rendered. `RequestFacts`/`ResponseFacts` derive Debug (they
    // are non-secret by construction), so this covers every field including ones added later
    // — which is the point: a new field lands in this haystack automatically.
    let seen = format!("{report:?}");
    for (label, needle) in [
        ("api key", String::from_utf8_lossy(API_KEY).to_string()),
        ("cred ref", CRED_REF.to_owned()),
        ("x-api-key header name", "x-api-key".to_owned()),
    ] {
        assert!(!seen.contains(&needle), "tee observed the {label}: {seen}");
    }
    assert_eq!(report.request.path, "/v1/messages");
    assert_eq!(report.response.status, 200);
}

/// The allow-list is a closed set, asserted by exhaustive destructuring: adding a field to
/// `RequestFacts` or `ResponseFacts` stops this compiling, and the person who added it has
/// to come here and say why the tee may see it.
#[test]
fn tee_allow_list_is_exhaustively_enumerated() {
    let RequestFacts {
        method: _,
        path: _,
        upstream_host: _,
        dialect: _,
        requested_model: _,
        served_model: _,
        route_fidelity: _,
        propensity: _,
        bundle_seq: _,
    } = RequestFacts {
        method: String::new(),
        path: String::new(),
        upstream_host: String::new(),
        dialect: mark1_frames::Dialect::AnthropicSse,
        requested_model: None,
        served_model: None,
        route_fidelity: RouteFidelity::Advisory,
        propensity: 1.0,
        bundle_seq: 0,
    };
    let mark1_proxy::tee::ResponseFacts {
        status: _,
        request_bytes: _,
        response_bytes: _,
        elapsed_micros: _,
        ttfb_micros: _,
        request_id: _,
        stream: _,
    } = mark1_proxy::tee::ResponseFacts {
        status: 0,
        request_bytes: 0,
        response_bytes: 0,
        elapsed_micros: 0,
        ttfb_micros: 0,
        request_id: String::new(),
        stream: false,
    };
}

// ---------------------------------------------------------------------------------------
// D-AH — the tee provably cannot hold a client write
// ---------------------------------------------------------------------------------------

/// Saturate the tee's byte budget and assert the client stream is byte-identical and not
/// delayed. The saturating tee here is genuinely stalled: its receiver is held and never
/// polled, so no retained byte is ever released.
#[tokio::test(flavor = "multi_thread")]
async fn tee_saturated_cannot_delay_or_alter_the_client_stream() {
    let body: Vec<u8> = (0..512 * 1024).map(|i| (i % 251) as u8).collect();

    // Baseline: healthy tee.
    let healthy = start(http_response("", &body), true).await;
    let t0 = Instant::now();
    let a = request(healthy.addr, &cred_headers(CRED_REF, API_KEY)).await;
    let healthy_elapsed = t0.elapsed();
    assert_eq!(a.body, body, "baseline forward was not byte-exact");

    // Saturated: the tee task does not exist, so nothing drains it.
    let ctx = start(http_response("", &body), false).await;
    let mut filler = ctx.tee.open(RequestFacts {
        method: "POST".to_owned(),
        path: "/v1/messages".to_owned(),
        upstream_host: "127.0.0.1".to_owned(),
        dialect: mark1_frames::Dialect::AnthropicSse,
        requested_model: None,
        served_model: None,
        route_fidelity: RouteFidelity::Advisory,
        propensity: 1.0,
        bundle_seq: 0,
    });
    let chunk = bytes::Bytes::from(vec![0u8; 64 * 1024]);
    while filler.chunk(&chunk) {}
    assert!(
        ctx.tee.inflight_bytes() > tee::TEE_INFLIGHT_MAX - chunk.len(),
        "the tee is not actually saturated; this test would prove nothing"
    );

    let t1 = Instant::now();
    let b = request(ctx.addr, &cred_headers(CRED_REF, API_KEY)).await;
    let saturated_elapsed = t1.elapsed();

    assert_eq!(b.status, 200);
    assert_eq!(
        b.body, body,
        "a saturated tee perturbed the client byte stream"
    );
    assert_eq!(a.body, b.body);
    assert!(
        ctx.tee.chunks_dropped() > 0,
        "saturation dropped no chunk — budget not enforced"
    );

    // Generous, because CI machines are noisy; the failure this catches is the one that
    // matters — a tee that blocks turns milliseconds into seconds, not into +30%.
    assert!(
        saturated_elapsed < healthy_elapsed + Duration::from_millis(500),
        "saturated {saturated_elapsed:?} vs healthy {healthy_elapsed:?}"
    );
}

// ---------------------------------------------------------------------------------------
// 12 §3.1 — golden transcripts, replayed through the full proxy
// ---------------------------------------------------------------------------------------

fn fixtures() -> Vec<(String, Vec<u8>)> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/frames/anthropic_sse");
    let mut out: Vec<(String, Vec<u8>)> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "bytes"))
        .map(|p| {
            let name = p.file_stem().unwrap().to_string_lossy().to_string();
            (name, std::fs::read(&p).unwrap())
        })
        .collect();
    out.sort();
    out
}

/// 12 §3.1 assertion 1 (NFR-CORRECTNESS-003): client-received bytes ≡ upstream bytes, for
/// every recorded transcript, through the full proxy rather than the parser in isolation.
///
/// This is the assertion the tee exists to not break. Header casing and ordering are hyper's
/// to normalize; the *stream* is what must survive untouched.
#[tokio::test(flavor = "multi_thread")]
async fn golden_transcripts_forward_byte_exact() {
    let fixtures = fixtures();
    assert!(
        fixtures.len() >= 7,
        "expected the anthropic_sse corpus on disk; found {} — a golden suite with no \
         goldens reports success while asserting nothing",
        fixtures.len()
    );

    for (name, bytes) in fixtures {
        let mut ctx = start(http_response("", &bytes), true).await;
        let res = request(ctx.addr, &cred_headers(CRED_REF, API_KEY)).await;
        assert_eq!(res.status, 200, "{name}: {}", res.head);
        assert_eq!(res.body.len(), bytes.len(), "{name}: length differs");
        assert!(
            res.body == bytes,
            "{name}: forwarded stream is not byte-exact"
        );

        // Tripwire, not a second copy of assertion 2 (`mark1-frames` owns that): if the tee
        // were handed the placeholder parser, every fixture would degrade and the corrupt
        // case below would prove nothing.
        let report = report(&mut ctx).await;
        if name == "corrupt_message_delta" {
            assert!(report.degraded.is_some(), "{name} must degrade");
        } else {
            assert_eq!(report.degraded, None, "{name} parsed degraded");
            assert!(
                !report.observations.is_empty(),
                "{name} yielded no observation"
            );
        }
    }
}

/// 12 §3.1 assertion 3 (F-08/F-09): a corrupted transcript still forwards byte-exact while
/// the parse degrades. Parsing may fail; forwarding may not.
#[tokio::test(flavor = "multi_thread")]
async fn golden_corrupt_transcript_degrades_without_touching_the_stream() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/frames/anthropic_sse/corrupt_message_delta.bytes");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));

    let mut ctx = start(http_response("", &bytes), true).await;
    let res = request(ctx.addr, &cred_headers(CRED_REF, API_KEY)).await;

    assert_eq!(res.status, 200);
    assert!(
        res.body == bytes,
        "a degraded parse perturbed the forwarded stream"
    );

    let report = report(&mut ctx).await;
    // `NotImplemented` would mean the tee ran a placeholder parser rather than degrading on
    // the corruption, so the reason is asserted, not just the presence of one.
    assert_eq!(
        report.degraded.map(|d| d.reason),
        Some(DegradeReason::MalformedEvent),
        "the corrupt fixture did not degrade the way it is corrupted"
    );
    // Transport-level counters still emit (04 §4): the degradation narrows observation, it
    // does not delete it.
    assert_eq!(report.response.status, 200);
    assert_eq!(report.response.response_bytes, bytes.len() as u64);
}

// ---------------------------------------------------------------------------------------
// §3.4 — pools keyed (upstream, credential-identity)
// ---------------------------------------------------------------------------------------

/// Two halves of the same rule. Same credential ⇒ one connection reused (otherwise the pool
/// is decorative and every request pays a handshake). Different credential ⇒ never the same
/// connection, because a pooled connection is an identity the upstream can correlate.
#[tokio::test(flavor = "multi_thread")]
async fn pool_is_keyed_by_credential_identity() {
    let ctx = start(http_response("", b"{}"), true).await;

    for _ in 0..4 {
        let res = request(ctx.addr, &cred_headers(CRED_REF, API_KEY)).await;
        assert_eq!(res.status, 200, "{}", res.head);
    }
    assert_eq!(
        ctx.upstream.connections(),
        1,
        "the pool did not reuse one credential's connection"
    );

    for _ in 0..4 {
        let res = request(ctx.addr, &cred_headers(CRED_REF_2, API_KEY_2)).await;
        assert_eq!(res.status, 200, "{}", res.head);
    }
    assert_eq!(
        ctx.upstream.connections(),
        2,
        "a second credential shared the first credential's upstream connection"
    );
}

/// No identity masking: whatever credential header the agent sent arrives at the upstream
/// unchanged, and `M1-Cred-Ref` does not.
#[tokio::test(flavor = "multi_thread")]
async fn credential_passes_through_and_cred_ref_does_not() {
    let ctx = start(http_response("", b"{}"), true).await;
    let res = request(ctx.addr, &cred_headers(CRED_REF, API_KEY)).await;
    assert_eq!(res.status, 200, "{}", res.head);

    let seen = String::from_utf8_lossy(&ctx.upstream.last_request()).to_ascii_lowercase();
    assert!(seen.contains(&String::from_utf8_lossy(API_KEY).to_ascii_lowercase()));
    assert!(
        !seen.contains("m1-cred-ref"),
        "M1-Cred-Ref reached the upstream:\n{seen}"
    );
    assert!(
        !seen.contains("connection: close"),
        "hop-by-hop header reached the upstream"
    );
}

// ---------------------------------------------------------------------------------------
// FR-ROUTE-005 / FR-ROUTE-002 — wire-level model rewrite, only behind the guard
// ---------------------------------------------------------------------------------------

/// A Claude Code-shaped `/v1/messages` body: `model` first, a user message that itself
/// contains `"model":` text, a nested object keyed `model`, and `stream`. Only the top-level
/// value may change.
fn golden_request(model: &str) -> Vec<u8> {
    format!(
        concat!(
            r#"{{"model":"{}","max_tokens":32000,"messages":[{{"role":"user","content":"#,
            r#"[{{"type":"text","text":"why does \"model\": \"opus\" cost more?"}}]}}],"#,
            r#""metadata":{{"model":"not-me","user_id":"u1"}},"stream":true}}"#
        ),
        model
    )
    .into_bytes()
}

/// The body the upstream received, and the `content-length` it was told.
fn upstream_body(ctx: &Ctx) -> (Vec<u8>, usize) {
    let raw = ctx.upstream.last_request();
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&raw[..split]).to_ascii_lowercase();
    let cl = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .map(|v| v.trim().parse::<usize>().unwrap())
        .expect("upstream request declares no content-length");
    (raw[split + 4..].to_vec(), cl)
}

/// The rewrite edits exactly the top-level `"model"` value and the `Content-Length` that
/// covers it; every other byte of the body reaches the upstream as the client sent it. The tee
/// carries both models and `WIRE_ENFORCED` under the bundle's seq.
#[tokio::test(flavor = "multi_thread")]
async fn rewrite_is_byte_exact_except_the_model_field() {
    let mut ctx = start_routed(http_response("", b"{}"), Dialect::AnthropicSse).await;
    let res = request_with_body(
        ctx.addr,
        &cred_headers(CRED_REF, API_KEY),
        &golden_request(ROUTED),
    )
    .await;
    assert_eq!(res.status, 200, "{}", res.head);

    let expected = golden_request(ENTRY);
    let (body, cl) = upstream_body(&ctx);
    assert_eq!(cl, expected.len(), "Content-Length not recomputed");
    assert_eq!(
        cl,
        body.len(),
        "declared length does not cover the bytes sent"
    );
    assert!(
        body == expected,
        "rewritten body is not byte-exact:\n{}",
        String::from_utf8_lossy(&body)
    );
    assert_ne!(
        expected,
        golden_request(ROUTED),
        "fixture does not exercise the rewrite"
    );

    let report = report(&mut ctx).await;
    assert_eq!(report.request.requested_model.as_deref(), Some(ROUTED));
    assert_eq!(report.request.served_model.as_deref(), Some(ENTRY));
    assert_eq!(report.request.route_fidelity, RouteFidelity::WireEnforced);
    assert_eq!(report.request.propensity, 1.0);
    assert_eq!(report.request.bundle_seq, BUNDLE_SEQ);
    assert_eq!(report.response.request_bytes, expected.len() as u64);
}

/// A model no ladder names is forwarded untouched, and the tee says so: ADVISORY, served ==
/// requested, still under the applied bundle's seq.
#[tokio::test(flavor = "multi_thread")]
async fn unknown_model_passes_through_unrewritten_as_advisory() {
    let mut ctx = start_routed(http_response("", b"{}"), Dialect::AnthropicSse).await;
    let sent = golden_request(UNROUTED);
    let res = request_with_body(ctx.addr, &cred_headers(CRED_REF, API_KEY), &sent).await;
    assert_eq!(res.status, 200, "{}", res.head);

    let (body, cl) = upstream_body(&ctx);
    assert!(body == sent, "an unknown model was rewritten");
    assert_eq!(cl, sent.len());

    let report = report(&mut ctx).await;
    assert_eq!(report.request.requested_model.as_deref(), Some(UNROUTED));
    assert_eq!(report.request.served_model.as_deref(), Some(UNROUTED));
    assert_eq!(report.request.route_fidelity, RouteFidelity::Advisory);
    assert_eq!(report.request.bundle_seq, BUNDLE_SEQ);
}

/// FR-ROUTE-005's runtime negative. The compile-time half is the `compile_fail` doctest on
/// `request::rewrite_model`: a `ForwardTicket` cannot be written down outside the guard. At
/// runtime, a request the guard refuses never reaches the rewrite — no connection is opened —
/// and the off-marker arm (a ticket that forwards as transport) forwards the body unmutated.
#[tokio::test(flavor = "multi_thread")]
async fn rewrite_happens_only_with_a_forward_ticket() {
    let ctx = start_routed(http_response("", b"{}"), Dialect::AnthropicSse).await;
    let api = String::from_utf8_lossy(API_KEY).to_string();
    let sent = golden_request(ROUTED);

    for headers in [
        format!("x-api-key: {api}\r\n"),
        cred_headers("ref-does-not-exist", API_KEY),
        cred_headers(CRED_REF, OAUTH_TOKEN),
    ] {
        let res = request_with_body(ctx.addr, &headers, &sent).await;
        assert_eq!(res.status, 403, "{}", res.head);
    }
    assert_eq!(
        ctx.upstream.connections(),
        0,
        "refused request reached the upstream"
    );

    std::fs::write(ctx._base.path().join("OFF"), b"").unwrap();
    let res = request_with_body(ctx.addr, &cred_headers(CRED_REF, API_KEY), &sent).await;
    assert_eq!(res.status, 200, "{}", res.head);
    let (body, cl) = upstream_body(&ctx);
    assert!(body == sent, "the off-marker arm mutated the request");
    assert_eq!(cl, sent.len());
}

/// The response side of a rewritten request is the same bytes-forward path as an unrewritten
/// one: every golden SSE transcript comes back byte-exact, and the tee parses it.
#[tokio::test(flavor = "multi_thread")]
async fn rewritten_request_streams_the_response_untouched() {
    let fixtures = fixtures();
    assert!(fixtures.len() >= 7);
    for (name, bytes) in fixtures {
        let mut ctx = start_routed(http_response("", &bytes), Dialect::AnthropicSse).await;
        let res = request_with_body(
            ctx.addr,
            &cred_headers(CRED_REF, API_KEY),
            &golden_request(ROUTED),
        )
        .await;
        assert_eq!(res.status, 200, "{name}: {}", res.head);
        assert!(
            res.body == bytes,
            "{name}: response not byte-exact after a rewrite"
        );

        let (body, _) = upstream_body(&ctx);
        assert!(
            body == golden_request(ENTRY),
            "{name}: request not rewritten"
        );
        let report = report(&mut ctx).await;
        assert_eq!(
            report.request.route_fidelity,
            RouteFidelity::WireEnforced,
            "{name}"
        );
        if name != "corrupt_message_delta" {
            assert_eq!(report.degraded, None, "{name}");
        }
    }
}

/// The rewrite is an Anthropic-dialect edit: a dialect `mark1-frames` cannot parse is never
/// rewritten, whatever the table says — and Bedrock, which it CAN parse, is never rewritten
/// either (04 §3.4: SigV4 signs the body; observe-only until customer-held re-signing).
#[tokio::test(flavor = "multi_thread")]
async fn other_dialects_are_never_rewritten() {
    for dialect in [Dialect::OpenaiChat, Dialect::BedrockEventstream] {
        let mut ctx = start_routed(http_response("", b"{}"), dialect).await;
        let sent = golden_request(ROUTED);
        let res = request_with_body(ctx.addr, &cred_headers(CRED_REF, API_KEY), &sent).await;
        assert_eq!(res.status, 200, "{dialect:?}: {}", res.head);
        let (body, cl) = upstream_body(&ctx);
        assert!(body == sent, "{dialect:?}: body was rewritten");
        assert_eq!(cl, sent.len());
        let report = report(&mut ctx).await;
        assert_eq!(
            report.request.route_fidelity,
            RouteFidelity::Advisory,
            "{dialect:?}"
        );
        assert_eq!(report.request.requested_model, None);
        assert_eq!(report.request.bundle_seq, 0);
    }
}

/// Bedrock end to end: the golden eventstream forwards byte-exact and the tee parses its
/// usage out of the base64 `chunk` payloads — observation without mutation.
#[tokio::test(flavor = "multi_thread")]
async fn bedrock_golden_eventstream_is_observed_and_never_rewritten() {
    let bytes = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/frames/bedrock_eventstream/invoke_stream_anthropic.bytes"
    ))
    .unwrap();
    let mut ctx = start_routed(
        http_response(
            "content-type: application/vnd.amazon.eventstream\r\n",
            &bytes,
        ),
        Dialect::BedrockEventstream,
    )
    .await;
    let sent = golden_request(ROUTED);
    let res = request_with_body(ctx.addr, &cred_headers(CRED_REF, API_KEY), &sent).await;
    assert_eq!(res.status, 200, "{}", res.head);
    assert!(res.body == bytes, "eventstream not byte-exact");
    let (body, _) = upstream_body(&ctx);
    assert!(body == sent, "a Bedrock request was rewritten");
    let report = report(&mut ctx).await;
    assert_eq!(report.degraded, None);
    let usage = report
        .observations
        .iter()
        .rev()
        .find_map(|o| match o {
            mark1_frames::WireObservation::Usage(u) => Some(u),
            _ => None,
        })
        .expect("no usage parsed from the eventstream");
    assert_eq!(usage.model, "claude-sonnet-4-5");
    assert_eq!((usage.input_tokens, usage.output_tokens), (25, 12));
    assert_eq!(report.request.route_fidelity, RouteFidelity::Advisory);
}

/// Chaos: the upstream resets the connection after the rewritten head is sent. The client
/// gets the frozen error shape (M1E-9500, 04 §3.5 "pass the error verbatim"), not a hang and
/// not a half-written response.
#[tokio::test(flavor = "multi_thread")]
async fn upstream_reset_mid_rewrite_is_a_clean_error() {
    let table = RouteTable::from_route(&route_section(0.0), BUNDLE_SEQ).unwrap();
    let upstream = FakeUpstream::start_with(Vec::new(), true).await;
    let ctx = start_with(upstream, true, Some(table), Dialect::AnthropicSse).await;

    let res = tokio::time::timeout(
        Duration::from_secs(5),
        request_with_body(
            ctx.addr,
            &cred_headers(CRED_REF, API_KEY),
            &golden_request(ROUTED),
        ),
    )
    .await
    .expect("client hung on an upstream reset");
    assert_eq!(res.status, 502, "{}", res.head);
    assert_eq!(res.error_code().as_deref(), Some("M1E-9500"));
    assert_eq!(ctx.upstream.connections(), 1);
}

/// The scan crosses frames: a `model` key that only arrives in the second body frame is still
/// found and rewritten. A `MODEL_SCAN_MAX` mutated down to bytes fails here, because the key
/// sits past the first frame's 40 KiB of messages rather than at byte 1.
#[tokio::test(flavor = "multi_thread")]
async fn model_key_in_the_second_frame_is_still_rewritten() {
    let mut ctx = start_routed(http_response("", b"{}"), Dialect::AnthropicSse).await;
    let filler = "x".repeat(40 * 1024);
    let frame1 = format!(r#"{{"messages":[{{"role":"user","content":"{filler}"}}],"#);
    let frame2 = format!(r#""model":"{ROUTED}","stream":true}}"#);
    assert!(frame1.len() < mark1_proxy::request::MODEL_SCAN_MAX);
    let res = request_in_frames(
        ctx.addr,
        &cred_headers(CRED_REF, API_KEY),
        &[frame1.as_bytes(), frame2.as_bytes()],
    )
    .await;
    assert_eq!(res.status, 200, "{}", res.head);

    let expected = format!("{frame1}\"model\":\"{ENTRY}\",\"stream\":true}}");
    let (body, cl) = upstream_body(&ctx);
    assert_eq!(cl, expected.len());
    assert!(
        body == expected.as_bytes(),
        "second-frame model was not rewritten"
    );
    let report = report(&mut ctx).await;
    assert_eq!(report.request.requested_model.as_deref(), Some(ROUTED));
    assert_eq!(report.request.served_model.as_deref(), Some(ENTRY));
    assert_eq!(report.request.route_fidelity, RouteFidelity::WireEnforced);
}

/// The ceiling: once `MODEL_SCAN_MAX` bytes have arrived without a top-level `model`, the
/// scan stops, nothing is rewritten, and the body still reaches the upstream byte-exact.
#[tokio::test(flavor = "multi_thread")]
async fn scan_stops_at_model_scan_max_and_forwards_unrewritten() {
    let mut ctx = start_routed(http_response("", b"{}"), Dialect::AnthropicSse).await;
    let filler = "x".repeat(mark1_proxy::request::MODEL_SCAN_MAX);
    let frame1 = format!(r#"{{"messages":[{{"role":"user","content":"{filler}"}}],"#);
    let frame2 = format!(r#""model":"{ROUTED}","stream":true}}"#);
    let res = request_in_frames(
        ctx.addr,
        &cred_headers(CRED_REF, API_KEY),
        &[frame1.as_bytes(), frame2.as_bytes()],
    )
    .await;
    assert_eq!(res.status, 200, "{}", res.head);

    let sent = format!("{frame1}{frame2}");
    let (body, cl) = upstream_body(&ctx);
    assert_eq!(cl, sent.len());
    assert!(
        body == sent.as_bytes(),
        "a body past the scan cap was mutated"
    );
    let report = report(&mut ctx).await;
    assert_eq!(report.request.requested_model, None);
    assert_eq!(report.request.route_fidelity, RouteFidelity::Advisory);
}

/// FR-ROUTE-002's producer half: the tee report leaves the proxy as `Event{ModelRequest}` +
/// `Event{ModelResponse}` carrying exactly the allow-list's fields — asserted on the spill
/// ring, where `Fabric::emit` puts a frame no daemon accepted.
#[tokio::test(flavor = "multi_thread")]
async fn tee_report_is_emitted_as_model_request_and_response_events() {
    let mut ctx = start_routed(
        http_response("request-id: req_abc123\r\n", &fixtures()[0].1),
        Dialect::AnthropicSse,
    )
    .await;
    let device = device_spill_key(ctx._base.path());
    let res = request_with_body(
        ctx.addr,
        &cred_headers(CRED_REF, API_KEY),
        &golden_request(ROUTED),
    )
    .await;
    assert_eq!(res.status, 200, "{}", res.head);
    let report = report(&mut ctx).await;
    Fabric::new(ctx._base.path()).tee_report(&report);

    let events = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let found: Vec<m1p_wire::pb::Event> = spilled_frames(ctx._base.path(), &device)
                .into_iter()
                .filter_map(|f| match f.kind {
                    Some(m1p_wire::pb::fabric_frame::Kind::Event(e)) => Some(e),
                    _ => None,
                })
                .collect();
            if found.len() >= 2 {
                return found;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("no ModelRequest/ModelResponse events were emitted");
    use m1p_wire::pb::event::Body;
    let mr = events
        .iter()
        .find_map(|e| match &e.body {
            Some(Body::ModelRequest(m)) => Some(m.clone()),
            _ => None,
        })
        .expect("ModelRequest");
    assert_eq!(mr.model, ROUTED);
    assert_eq!(mr.served_model, ENTRY);
    assert_eq!(mr.request_id, "req_abc123");
    assert!(mr.stream, "an event-stream response is a streaming request");
    assert_eq!(mr.request_bytes, golden_request(ENTRY).len() as u64);
    let mres = events
        .iter()
        .find_map(|e| match &e.body {
            Some(Body::ModelResponse(m)) => Some(m.clone()),
            _ => None,
        })
        .expect("ModelResponse");
    assert_eq!(mres.status_code, 200);
    assert_eq!(mres.request_id, "req_abc123");
    assert_eq!(mres.response_bytes, fixtures()[0].1.len() as u64);
    assert_eq!(mres.stop_reason, "end_turn");
    // The tee never held the credential, so neither event can carry it.
    let rendered = format!("{events:?}");
    assert!(!rendered.contains(std::str::from_utf8(API_KEY).unwrap()));
}

/// FR-ROUTE-003: a nonzero ε has no opt-in surface in the bundle, so no table is built from
/// it and nothing is rewritten. Every rung of a ladder maps to its entry rung at ε=0.
#[test]
fn route_table_is_deterministic_at_epsilon_zero_and_absent_otherwise() {
    assert!(RouteTable::from_route(&route_section(0.03), 1).is_none());
    let table = RouteTable::from_route(&route_section(0.0), 1).unwrap();
    for rung in [ENTRY, "claude-sonnet-4-5", ROUTED] {
        assert_eq!(table.served(rung), Some(ENTRY), "{rung}");
    }
    assert_eq!(table.served(UNROUTED), None);
}

// ---------------------------------------------------------------------------------------
// 04 §3.3/§3.4 — gateway mode: mTLS, credentials by reference
// ---------------------------------------------------------------------------------------

const GITHUB_TOKEN: &[u8] = b"gho_AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTt";

/// A PKI minted for this run (gitleaks forbids a committed PEM key): one CA the gateway pins,
/// a server leaf, a client leaf under it, and a stranger's client leaf under another CA.
struct Pki {
    _dir: tempfile::TempDir,
    tls: mark1_proxy::gateway::TlsPaths,
    client: (std::path::PathBuf, std::path::PathBuf),
    stranger: (std::path::PathBuf, std::path::PathBuf),
}

fn mint_pki() -> Pki {
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose,
        IsCa, KeyPair,
    };
    let dir = tempfile::tempdir().unwrap();
    let write = |name: &str, pem: String| {
        let p = dir.path().join(name);
        std::fs::write(&p, pem).unwrap();
        p
    };
    let ca = |cn: &str| {
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.distinguished_name.push(DnType::CommonName, cn);
        CertifiedIssuer::self_signed(p, KeyPair::generate().unwrap()).unwrap()
    };
    let leaf = |issuer: &CertifiedIssuer<'_, KeyPair>,
                sans: &[&str],
                eku: ExtendedKeyUsagePurpose,
                name: &str| {
        let mut p =
            CertificateParams::new(sans.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>())
                .unwrap();
        p.extended_key_usages = vec![eku];
        let key = KeyPair::generate().unwrap();
        let cert = p.signed_by(&key, issuer).unwrap();
        (
            write(&format!("{name}.pem"), cert.pem()),
            write(&format!("{name}.key"), key.serialize_pem()),
        )
    };
    let ca_main = ca("mark1-test-ca");
    let ca_other = ca("stranger-ca");
    let (server_cert, server_key) = leaf(
        &ca_main,
        &["localhost", "127.0.0.1"],
        ExtendedKeyUsagePurpose::ServerAuth,
        "server",
    );
    let client = leaf(&ca_main, &[], ExtendedKeyUsagePurpose::ClientAuth, "client");
    let stranger = leaf(
        &ca_other,
        &[],
        ExtendedKeyUsagePurpose::ClientAuth,
        "stranger",
    );
    let client_ca = write("ca.pem", ca_main.pem());
    write("other-ca.pem", ca_other.pem());
    Pki {
        tls: mark1_proxy::gateway::TlsPaths {
            cert: server_cert,
            key: server_key,
            client_ca,
        },
        client,
        stranger,
        _dir: dir,
    }
}

/// The gateway over `source`, mTLS-pinned to `pki`; the registry enrolls the same refs the
/// source resolves, as fleet provisioning would.
async fn start_gateway(
    response: Vec<u8>,
    dialect: Dialect,
    source: mark1_proxy::gateway::MemorySource,
    pki: &Pki,
) -> Ctx {
    use mark1_proxy::gateway::{acceptor, Gateway};
    let upstream = FakeUpstream::start(response).await;
    let base = tempfile::tempdir().unwrap();
    let registry = registry_of(&[
        (CRED_REF, API_KEY),
        (CRED_REF_2, API_KEY_2),
        ("ref-gho", GITHUB_TOKEN),
    ]);
    let guard = Arc::new(Guard::from_parts(
        GUARD_KEY.to_vec(),
        registry,
        Sampling::from_bundle(1.0),
    ));
    let cfg = Arc::new(ProxyConfig {
        mode: Mode::Gateway,
        bind: "127.0.0.1:0".parse().unwrap(),
        upstreams: vec![Upstream::new("127.0.0.1", upstream.addr.port(), false)
            .unwrap()
            .with_dialect(dialect)],
        forward_sample_rate: 1.0,
        base: base.path().to_path_buf(),
    });
    let listener = tokio::net::TcpListener::bind(cfg.bind).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tee, tee_rx) = tee::channel();
    let (reports_tx, reports_rx) = tokio::sync::mpsc::channel(64);
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(tee::run(tee_rx, reports_tx));
    });
    let proxy = Arc::new(
        Proxy::new(
            cfg,
            guard,
            Arc::new(Pool::new().unwrap()),
            tee.clone(),
            Fabric::new(base.path()),
            addr,
        )
        .with_gateway(Gateway::new(acceptor(&pki.tls).unwrap(), Arc::new(source))),
    );
    tokio::spawn(Arc::clone(&proxy).serve(listener));
    Ctx {
        addr,
        upstream,
        proxy,
        tee,
        reports: Some(reports_rx),
        _tee_rx: None,
        _base: base,
    }
}

/// One request over TLS. `client = None` offers no certificate. `Err` is the handshake or
/// the server's post-handshake refusal (TLS 1.3 clients learn of a rejected certificate on
/// their first read), and both are the gateway saying no.
async fn tls_request(
    addr: SocketAddr,
    ca: &std::path::Path,
    client: Option<&(std::path::PathBuf, std::path::PathBuf)>,
    headers: &str,
    body: &[u8],
) -> Result<RawResponse, std::io::Error> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_file(ca).unwrap())
        .unwrap();
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots);
    let config = match client {
        Some((cert, key)) => builder
            .with_client_auth_cert(
                vec![CertificateDer::from_pem_file(cert).unwrap()],
                PrivateKeyDer::from_pem_file(key).unwrap(),
            )
            .unwrap(),
        None => builder.with_no_client_auth(),
    };
    let tcp = tokio::net::TcpStream::connect(addr).await?;
    let mut tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await?;
    let head = format!(
        "POST /v1/messages HTTP/1.1\r\nhost: {addr}\r\nconnection: close\r\n{headers}content-length: {}\r\n\r\n",
        body.len()
    );
    tls.write_all(head.as_bytes()).await?;
    tls.write_all(body).await?;
    let mut raw = Vec::new();
    tls.read_to_end(&mut raw).await?;
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| std::io::Error::other("no response"))?;
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap();
    Ok(RawResponse {
        status,
        body: raw[split + 4..].to_vec(),
        head,
    })
}

fn by_ref(cred_ref: &str) -> String {
    format!("m1-cred-ref: {cred_ref}\r\n")
}

/// NFR-SECURITY: the listener is mTLS or nothing. No certificate and a certificate under a CA
/// other than the pinned one are both refused before a byte of HTTP is read; the enrolled
/// client gets through and the upstream sees the credential the REFERENCE resolved to.
#[tokio::test(flavor = "multi_thread")]
async fn gateway_mtls_refuses_no_cert_and_wrong_ca() {
    let pki = mint_pki();
    let ctx = start_gateway(
        http_response("", b"{}"),
        Dialect::AnthropicSse,
        mark1_proxy::gateway::MemorySource::new(&[(CRED_REF, API_KEY)]),
        &pki,
    )
    .await;
    let ca = &pki.tls.client_ca;

    assert!(
        tls_request(ctx.addr, ca, None, &by_ref(CRED_REF), b"{}")
            .await
            .is_err(),
        "no client certificate was accepted"
    );
    assert!(
        tls_request(ctx.addr, ca, Some(&pki.stranger), &by_ref(CRED_REF), b"{}")
            .await
            .is_err(),
        "a certificate under another CA was accepted"
    );
    assert_eq!(
        ctx.upstream.connections(),
        0,
        "a refused handshake reached the upstream"
    );

    let res = tls_request(ctx.addr, ca, Some(&pki.client), &by_ref(CRED_REF), b"{}")
        .await
        .unwrap();
    assert_eq!(res.status, 200, "{}", res.head);
    let seen = String::from_utf8_lossy(&ctx.upstream.last_request()).to_string();
    assert!(
        seen.contains(&format!("x-api-key: {}", String::from_utf8_lossy(API_KEY))),
        "resolved credential not forwarded:\n{seen}"
    );
    assert!(!seen.to_ascii_lowercase().contains("m1-cred-ref"));
}

/// CON-002 / 04 §3.1 step 2 at the gateway: no reference, an unresolvable one, and a client
/// that brought its own credential are each `403 M1E-8001` — the guard's code — with no
/// upstream connection opened.
#[tokio::test(flavor = "multi_thread")]
async fn gateway_unresolvable_cred_ref_is_403_with_the_guards_code() {
    let pki = mint_pki();
    let ctx = start_gateway(
        http_response("", b"{}"),
        Dialect::AnthropicSse,
        mark1_proxy::gateway::MemorySource::new(&[(CRED_REF, API_KEY)]),
        &pki,
    )
    .await;
    for headers in [
        String::new(),
        by_ref("ref-not-in-the-secret-manager"),
        by_ref(CRED_REF_2), // enrolled in the registry, but the source has no such secret
        format!(
            "{}x-api-key: {}\r\n",
            by_ref(CRED_REF),
            String::from_utf8_lossy(API_KEY)
        ),
        format!(
            "authorization: Bearer {}\r\n",
            String::from_utf8_lossy(OAUTH_TOKEN)
        ),
    ] {
        let res = tls_request(
            ctx.addr,
            &pki.tls.client_ca,
            Some(&pki.client),
            &headers,
            b"{}",
        )
        .await
        .unwrap();
        assert_eq!(res.status, 403, "{headers:?}: {}", res.head);
        assert_eq!(res.error_code().as_deref(), Some("M1E-8001"), "{headers:?}");
    }
    assert_eq!(ctx.upstream.connections(), 0);
}

/// FR-AGENT-014's wire half: a GitHub-issued token (a GitHub-billed Copilot session) resolved
/// by reference is refused by the guard's shape tripwire even though its ref is enrolled —
/// only BYOK API keys ride the wire path.
#[tokio::test(flavor = "multi_thread")]
async fn gateway_refuses_a_github_billed_token_even_when_enrolled() {
    let pki = mint_pki();
    let ctx = start_gateway(
        http_response("", b"{}"),
        Dialect::OpenaiChat,
        mark1_proxy::gateway::MemorySource::new(&[("ref-gho", GITHUB_TOKEN), (CRED_REF, API_KEY)]),
        &pki,
    )
    .await;
    let res = tls_request(
        ctx.addr,
        &pki.tls.client_ca,
        Some(&pki.client),
        &by_ref("ref-gho"),
        b"{}",
    )
    .await
    .unwrap();
    assert_eq!(res.status, 403, "{}", res.head);
    assert_eq!(res.error_code().as_deref(), Some("M1E-8001"));
    assert_eq!(
        ctx.upstream.connections(),
        0,
        "a GitHub token reached the wire path"
    );
    // Positive control: a BYOK key at the same gateway, same dialect, is forwarded as a bearer.
    let res = tls_request(
        ctx.addr,
        &pki.tls.client_ca,
        Some(&pki.client),
        &by_ref(CRED_REF),
        b"{}",
    )
    .await
    .unwrap();
    assert_eq!(res.status, 200, "{}", res.head);
    assert!(
        String::from_utf8_lossy(&ctx.upstream.last_request()).contains(&format!(
            "authorization: Bearer {}",
            String::from_utf8_lossy(API_KEY)
        ))
    );
}

/// CON-015 at the gateway: two references resolving to two identities never share an upstream
/// connection; one identity reuses its own.
#[tokio::test(flavor = "multi_thread")]
async fn gateway_pools_separate_identities() {
    let pki = mint_pki();
    let ctx = start_gateway(
        http_response("", b"{}"),
        Dialect::AnthropicSse,
        mark1_proxy::gateway::MemorySource::new(&[(CRED_REF, API_KEY), (CRED_REF_2, API_KEY_2)]),
        &pki,
    )
    .await;
    for _ in 0..3 {
        assert_eq!(
            tls_request(
                ctx.addr,
                &pki.tls.client_ca,
                Some(&pki.client),
                &by_ref(CRED_REF),
                b"{}"
            )
            .await
            .unwrap()
            .status,
            200
        );
    }
    assert_eq!(
        ctx.upstream.connections(),
        1,
        "one identity did not reuse its connection"
    );
    for _ in 0..3 {
        assert_eq!(
            tls_request(
                ctx.addr,
                &pki.tls.client_ca,
                Some(&pki.client),
                &by_ref(CRED_REF_2),
                b"{}"
            )
            .await
            .unwrap()
            .status,
            200
        );
    }
    assert_eq!(
        ctx.upstream.connections(),
        2,
        "a second identity shared the first's connection"
    );
}

static LOG: Mutex<Vec<u8>> = Mutex::new(Vec::new());

struct LogSink;
impl std::io::Write for LogSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        LOG.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// CON-002 / NFR-SECURITY-001: with every log level open, the fetched credential appears in
/// no log line, no tee report, and no frame the proxy emits — only on the upstream socket.
/// The upstream check is the positive control that makes the three negatives mean something.
#[tokio::test(flavor = "multi_thread")]
async fn gateway_credentials_never_reach_the_tee_or_any_log() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(|| LogSink)
        .try_init();
    let pki = mint_pki();
    let mut ctx = start_gateway(
        http_response("request-id: req_gw1\r\n", &fixtures()[0].1),
        Dialect::AnthropicSse,
        mark1_proxy::gateway::MemorySource::new(&[(CRED_REF, API_KEY)]),
        &pki,
    )
    .await;
    let device = device_spill_key(ctx._base.path());
    tracing::trace!(target: "test", "gateway log capture armed");

    let res = tls_request(
        ctx.addr,
        &pki.tls.client_ca,
        Some(&pki.client),
        &by_ref(CRED_REF),
        &golden_request(UNROUTED),
    )
    .await
    .unwrap();
    assert_eq!(res.status, 200, "{}", res.head);
    let key = String::from_utf8_lossy(API_KEY).to_string();
    assert!(
        String::from_utf8_lossy(&ctx.upstream.last_request()).contains(&key),
        "positive control: the upstream never saw the credential"
    );

    let report = report(&mut ctx).await;
    assert!(
        !format!("{report:?}").contains(&key),
        "the tee saw the credential"
    );
    Fabric::new(ctx._base.path()).tee_report(&report);
    let frames = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let f = spilled_frames(ctx._base.path(), &device);
            if f.len() >= 2 {
                return f;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert!(
        !format!("{frames:?}").contains(&key),
        "an emitted frame carried the credential"
    );
    let log = String::from_utf8_lossy(&LOG.lock().unwrap()).to_string();
    assert!(
        log.contains("log capture armed"),
        "the log sink is not capturing"
    );
    assert!(
        !log.contains(&key),
        "a log line carried the credential:\n{log}"
    );
}
