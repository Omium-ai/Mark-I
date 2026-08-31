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

use mark1_frames::{DegradeReason, Dialect};
use mark1_proxy::fabric::Fabric;
use mark1_proxy::guard::{Guard, Sampling};
use mark1_proxy::router::Proxy;
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

impl FakeUpstream {
    /// `response` is written verbatim, head and all.
    async fn start(response: Vec<u8>) -> Self {
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
                    let mut buf = vec![0u8; 16 * 1024];
                    loop {
                        let n = sock.read(&mut buf).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        s.requests.lock().unwrap().push(buf[..n].to_vec());
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
    let upstream = FakeUpstream::start(response).await;
    let base = tempfile::tempdir().unwrap();

    let key = b"device-local-guard-key".to_vec();
    let probe = Guard::from_parts(key.clone(), HashMap::new(), Sampling::from_bundle(1.0));
    let mut registry = HashMap::new();
    registry.insert(CRED_REF.to_owned(), probe.fingerprint(API_KEY).unwrap());
    registry.insert(CRED_REF_2.to_owned(), probe.fingerprint(API_KEY_2).unwrap());
    // A ref whose enrollment fingerprint is an OAuth token: the §3.1 step 5 case, where
    // provenance passes and shape inspection is the only thing left.
    registry.insert(
        "ref-oauth".to_owned(),
        probe.fingerprint(OAUTH_TOKEN).unwrap(),
    );
    let guard = Arc::new(Guard::from_parts(key, registry, Sampling::from_bundle(1.0)));

    let cfg = Arc::new(ProxyConfig {
        mode: Mode::Sidecar,
        bind: "127.0.0.1:0".parse().unwrap(),
        // Declared, not inferred: the fixtures are Anthropic SSE, and host inference on a
        // loopback address would hand the tee the `Unimplemented` parser — which degrades
        // unconditionally and would make the degradation assertion below pass for free.
        upstreams: vec![Upstream::new("127.0.0.1", upstream.addr.port(), false)
            .unwrap()
            .with_dialect(Dialect::AnthropicSse)],
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

    let proxy = Arc::new(Proxy::new(
        cfg,
        guard,
        Arc::new(Pool::new().unwrap()),
        tee.clone(),
        Fabric::new(base.path()),
        addr,
    ));
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
    let head =
        format!("POST /v1/messages HTTP/1.1\r\nhost: {addr}\r\nconnection: close\r\n{headers}\r\n");
    let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
    sock.write_all(head.as_bytes()).await.unwrap();
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

fn cred_headers(cred_ref: &str, cred: &[u8]) -> String {
    format!(
        "m1-cred-ref: {cred_ref}\r\nx-api-key: {}\r\ncontent-length: 0\r\n",
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
        ("no M1-Cred-Ref at all", format!("x-api-key: {api}\r\ncontent-length: 0\r\n")),
        ("M1-Cred-Ref but no credential", format!("m1-cred-ref: {CRED_REF}\r\ncontent-length: 0\r\n")),
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
                "m1-cred-ref: {CRED_REF}\r\nx-api-key: {api}\r\nauthorization: Bearer {oauth}\r\ncontent-length: 0\r\n"
            ),
        ),
        (
            "bearer-only oauth under a valid ref",
            format!("m1-cred-ref: {CRED_REF}\r\nauthorization: Bearer {oauth}\r\ncontent-length: 0\r\n"),
        ),
        // The shape that defeated the structural claim: the guard reads header value #1
        // and hyper forwards BOTH lines, so a second x-api-key smuggles an unprovisioned
        // OAuth token past a guard that verified the first one. Enrolled key first, so
        // fingerprinting and shape classification both succeed on what the guard inspects.
        (
            "duplicate x-api-key smuggling an oauth token",
            format!(
                "m1-cred-ref: {CRED_REF}\r\nx-api-key: {api}\r\nx-api-key: {oauth}\r\ncontent-length: 0\r\n"
            ),
        ),
        (
            "duplicate x-api-key, both the enrolled value",
            format!(
                "m1-cred-ref: {CRED_REF}\r\nx-api-key: {api}\r\nx-api-key: {api}\r\ncontent-length: 0\r\n"
            ),
        ),
        (
            "duplicate Authorization",
            format!(
                "m1-cred-ref: {CRED_REF}\r\nauthorization: Bearer {api}\r\nauthorization: Bearer {oauth}\r\ncontent-length: 0\r\n"
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
    let res = request(
        ctx.addr,
        &format!("x-api-key: {api}\r\ncontent-length: 0\r\n"),
    )
    .await;
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
        "POST /v1/messages HTTP/1.1\r\nhost: attacker.example\r\nconnection: close\r\n{}\r\n",
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
    } = RequestFacts {
        method: String::new(),
        path: String::new(),
        upstream_host: String::new(),
        dialect: mark1_frames::Dialect::AnthropicSse,
        requested_model: None,
    };
    let mark1_proxy::tee::ResponseFacts {
        status: _,
        request_bytes: _,
        response_bytes: _,
        elapsed_micros: _,
    } = mark1_proxy::tee::ResponseFacts {
        status: 0,
        request_bytes: 0,
        response_bytes: 0,
        elapsed_micros: 0,
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
