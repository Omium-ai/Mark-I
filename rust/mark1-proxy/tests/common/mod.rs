//! The paired-latency harness shared by `benches/latency.rs` and `tests/latency_floor.rs`.
//!
//! One copy on purpose: the libtest asserts a relaxed CI floor on the *same* measurement the
//! criterion bench asserts the 04 §3.4 budget on. Two harnesses would let the floor and the
//! budget drift apart until one of them measured something else.
//!
//! The number that matters is a *delta*, so the same request is driven twice: once straight
//! to the upstream socket, once through the proxy on loopback, interleaved so both arms see
//! the same ambient noise. Both arms reuse one keep-alive connection, because that is what a
//! coding agent does and because per-iteration TCP setup would swamp a sub-millisecond delta.

// WHY: `clippy.toml` exempts `#[test]` fns from the workspace's unwrap/expect/panic denials;
// harness code in an integration-test crate is neither, and error plumbing through a fake
// upstream exists only to be discarded.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, dead_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use mark1_frames::Dialect;
use mark1_proxy::fabric::Fabric;
use mark1_proxy::guard::{Guard, Sampling};
use mark1_proxy::router::Proxy;
use mark1_proxy::tee;
use mark1_proxy::upstream::Pool;
use mark1_proxy::{Mode, ProxyConfig, Upstream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::runtime::Runtime;

pub const API_KEY: &[u8] = b"sk-ant-api03-AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz01";
pub const CRED_REF: &str = "bench-ref";

/// Warm-up round trips before anything is timed: the pool, the guard's HMAC state, the tee's
/// parser map and the spill scanner each allocate once, and none of that is per-request cost.
pub const WARM_ITERS: usize = 256;
/// Paired (direct, proxied) iterations behind the gated median.
pub const PAIRED_ITERS: usize = 1000;

/// A recorded transcript rather than a synthetic body: the tee's parser cost is part of the
/// added latency, and it only appears if the bytes are shaped like real SSE.
pub fn fixture() -> Vec<u8> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/frames/anthropic_sse/text_completion.bytes");
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

/// `fixture()` framed as the HTTP/1.1 response the fake upstream writes verbatim.
pub fn response_for(body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

/// Two workers, as in `main`: the proxy's accept loop and the request it is forwarding.
pub fn runtime() -> Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

pub async fn fake_upstream(response: Arc<Vec<u8>>) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                continue;
            };
            let _ = sock.set_nodelay(true);
            let response = Arc::clone(&response);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                // Keep-alive: one response per request seen.
                while let Ok(n) = sock.read(&mut buf).await {
                    if n == 0 || sock.write_all(&response).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

pub async fn start_proxy(upstream: SocketAddr, base: &std::path::Path) -> SocketAddr {
    let key = b"bench-guard-key".to_vec();
    let probe = Guard::from_parts(key.clone(), HashMap::new(), Sampling::from_bundle(1.0));
    let mut registry = HashMap::new();
    registry.insert(CRED_REF.to_owned(), probe.fingerprint(API_KEY).unwrap());
    // Sample rate 1.0: the budget must hold on the *observed* path, not on the 99% of
    // requests D-AJ lets the tee and the fabric skip. This is the expensive case by design.
    let guard = Arc::new(Guard::from_parts(key, registry, Sampling::from_bundle(1.0)));

    let cfg = Arc::new(ProxyConfig {
        mode: Mode::Sidecar,
        bind: "127.0.0.1:0".parse().unwrap(),
        upstreams: vec![Upstream::new("127.0.0.1", upstream.port(), false)
            .unwrap()
            .with_dialect(Dialect::AnthropicSse)],
        forward_sample_rate: 1.0,
        base: base.to_path_buf(),
    });
    let listener = tokio::net::TcpListener::bind(cfg.bind).await.unwrap();
    let addr = listener.local_addr().unwrap();

    let (tee, tee_rx) = tee::channel();
    let (reports_tx, mut reports_rx) = tokio::sync::mpsc::channel(256);
    // Own thread with a current-thread runtime, as in `main`: the parser is not `Send`.
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(tee::run(tee_rx, reports_tx));
    });
    tokio::spawn(async move { while reports_rx.recv().await.is_some() {} });

    let proxy = Arc::new(Proxy::new(
        cfg,
        guard,
        Arc::new(Pool::new().unwrap()),
        tee,
        Fabric::new(base),
        addr,
    ));
    tokio::spawn(Arc::clone(&proxy).serve(listener));
    addr
}

/// One keep-alive HTTP/1.1 client. Reads exactly `content-length` bytes so the socket is left
/// positioned for the next iteration.
pub struct Client {
    sock: TcpStream,
    request: Vec<u8>,
    buf: Vec<u8>,
}

impl Client {
    pub async fn connect(addr: SocketAddr, headers: &str) -> Self {
        let sock = TcpStream::connect(addr).await.unwrap();
        sock.set_nodelay(true).unwrap();
        let request = format!(
            "POST /v1/messages HTTP/1.1\r\nhost: {addr}\r\ncontent-length: 0\r\n{headers}\r\n"
        )
        .into_bytes();
        Client {
            sock,
            request,
            buf: vec![0u8; 64 * 1024],
        }
    }

    /// The timed round trip: bytes are counted, not kept.
    pub async fn round_trip(&mut self) -> usize {
        self.exchange(None).await
    }

    /// The byte-exactness round trip: the body the client received, for comparison against
    /// the upstream fixture. Not for the timed loop — the copy is not the proxy's cost.
    pub async fn round_trip_body(&mut self) -> Vec<u8> {
        let mut body = Vec::new();
        self.exchange(Some(&mut body)).await;
        body
    }

    async fn exchange(&mut self, mut sink: Option<&mut Vec<u8>>) -> usize {
        self.sock.write_all(&self.request).await.unwrap();
        let mut head_end = None;
        let mut head = Vec::new();
        let mut body_seen = 0usize;
        let mut want = 0usize;
        loop {
            let n = self.sock.read(&mut self.buf).await.unwrap();
            assert!(n > 0, "peer closed mid-response");
            if head_end.is_none() {
                head.extend_from_slice(&self.buf[..n]);
                if let Some(i) = head.windows(4).position(|w| w == b"\r\n\r\n") {
                    let text = String::from_utf8_lossy(&head[..i]).to_ascii_lowercase();
                    want = text
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse().ok())
                        .expect("harness requires a content-length response");
                    body_seen = head.len() - (i + 4);
                    head_end = Some(i);
                    if let Some(b) = sink.as_deref_mut() {
                        b.extend_from_slice(&head[i + 4..]);
                    }
                }
            } else {
                body_seen += n;
                if let Some(b) = sink.as_deref_mut() {
                    b.extend_from_slice(&self.buf[..n]);
                }
            }
            if head_end.is_some() && body_seen >= want {
                return want;
            }
        }
    }
}

/// The two arms, connected and ready. `body` is what every response carries.
pub struct Arms {
    pub direct: Client,
    pub proxied: Client,
    pub body: Vec<u8>,
}

impl Arms {
    /// Upstream + proxy over `base`, one keep-alive client on each.
    pub fn start(rt: &Runtime, base: &std::path::Path) -> Self {
        let body = fixture();
        let response = Arc::new(response_for(&body));
        let (upstream, proxy_addr) = rt.block_on(async {
            let up = fake_upstream(response).await;
            let px = start_proxy(up, base).await;
            (up, px)
        });
        let direct = rt.block_on(Client::connect(upstream, ""));
        let proxied = rt.block_on(Client::connect(
            proxy_addr,
            &format!(
                "m1-cred-ref: {CRED_REF}\r\nx-api-key: {}\r\n",
                String::from_utf8_lossy(API_KEY)
            ),
        ));
        Arms {
            direct,
            proxied,
            body,
        }
    }

    /// `WARM_ITERS` round trips on both arms, checking the proxied length every time.
    pub fn warm(&mut self, rt: &Runtime) {
        for _ in 0..WARM_ITERS {
            rt.block_on(self.direct.round_trip());
            let n = rt.block_on(self.proxied.round_trip());
            assert_eq!(
                n,
                self.body.len(),
                "proxied response length differs from upstream"
            );
        }
    }

    /// The gated measurement: `iters` interleaved (direct, proxied) round trips, returning
    /// `(direct median, proxied median)`. Added latency is the difference of the medians.
    pub fn paired_medians(&mut self, rt: &Runtime, iters: usize) -> (Duration, Duration) {
        let mut d = Vec::with_capacity(iters);
        let mut p = Vec::with_capacity(iters);
        for _ in 0..iters {
            let t = Instant::now();
            rt.block_on(self.direct.round_trip());
            d.push(t.elapsed());
            let t = Instant::now();
            rt.block_on(self.proxied.round_trip());
            p.push(t.elapsed());
        }
        assert_eq!(
            d.len(),
            iters,
            "direct arm did not complete every iteration"
        );
        assert_eq!(
            p.len(),
            iters,
            "proxied arm did not complete every iteration"
        );
        (median(&mut d), median(&mut p))
    }
}

pub fn median(samples: &mut [Duration]) -> Duration {
    samples.sort_unstable();
    samples[samples.len() / 2]
}

#[cfg(target_os = "linux")]
pub fn rss_bytes() -> u64 {
    let statm = std::fs::read_to_string("/proc/self/statm").unwrap_or_default();
    let pages: u64 = statm
        .split_whitespace()
        .nth(1)
        .and_then(|f| f.parse().ok())
        .unwrap_or(0);
    // SAFETY: sysconf takes no pointers.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    pages * page.max(4096) as u64
}

#[cfg(not(target_os = "linux"))]
pub fn rss_bytes() -> u64 {
    0
}

/// Reported next to RSS because the worst regression found here was thread-per-request, and
/// RSS alone says that memory grew without saying why.
pub fn thread_count() -> usize {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("Threads:"))
                .and_then(|v| v.trim().parse().ok())
        })
        .unwrap_or(0)
}
