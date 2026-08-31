//! Added-latency and RSS budget (04 §3.4: ≤1 ms median added latency, ≤35 MB RSS).
//!
//! The number that matters is a *delta*, so this benchmarks the same request twice: once
//! straight to the upstream socket, once through the proxy on loopback, interleaved so both
//! arms see the same ambient noise. Reporting only the proxied time would make the budget a
//! function of how fast the fake upstream is, which is not a property of this crate.
//!
//! Both arms reuse one keep-alive connection, because that is what a coding agent does and
//! because per-iteration TCP setup would swamp a sub-millisecond delta in noise.
//!
//! Three things here are assertions rather than reports, because a budget nobody can fail is
//! a budget nobody keeps. Criterion is the better estimator and prints the distributions, but
//! criterion does not fail a build:
//!
//!   * the **latency delta**, from a paired median computed below;
//!   * **RSS at warm-up**, over this process's pre-proxy baseline;
//!   * **RSS growth across sustained traffic**, which is the tripwire that found the two
//!     defects this bench was written to look for — a `spawn_blocking` per fabric emit and a
//!     `mark1_redact::Scanner` compiled per spilled record. Together they cost 240 threads and
//!     2.5 GB over 300 requests, and no unit test in the crate could see either.

// WHY: `clippy.toml` exempts `#[test]` fns from the workspace's unwrap/expect/panic denials;
// bench harnesses are not covered by that exemption, and a bench that cannot `expect` on its
// own fixture setup has to grow error plumbing that exists only to be discarded.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use criterion::{criterion_group, criterion_main, Criterion};
use mark1_frames::Dialect;
use mark1_proxy::fabric::Fabric;
use mark1_proxy::guard::{Guard, Sampling};
use mark1_proxy::router::Proxy;
use mark1_proxy::tee;
use mark1_proxy::upstream::Pool;
use mark1_proxy::{Mode, ProxyConfig, Upstream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const API_KEY: &[u8] = b"sk-ant-api03-AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz01";
const CRED_REF: &str = "bench-ref";

/// 04 §3.4.
const LATENCY_BUDGET: Duration = Duration::from_millis(1);
/// ≤35 MB (04 §3.4), measured as growth over the pre-proxy baseline of this process.
const RSS_BUDGET_BYTES: u64 = 35 * 1024 * 1024;
/// Steady-state growth allowance across `LEAK_ITERS` further requests. Not a second RSS
/// budget — a leak detector. Anything that scales with request count blows straight past it.
const LEAK_ALLOWANCE_BYTES: u64 = 8 * 1024 * 1024;
const LEAK_ITERS: usize = 2000;
const WARM_ITERS: usize = 256;
const PAIRED_ITERS: usize = 1000;

/// A recorded transcript rather than a synthetic body: the tee's parser cost is part of the
/// added latency, and it only appears if the bytes are shaped like real SSE.
fn fixture() -> Vec<u8> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/frames/anthropic_sse/text_completion.bytes");
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

async fn fake_upstream(response: Arc<Vec<u8>>) -> SocketAddr {
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

async fn start_proxy(upstream: SocketAddr, base: &std::path::Path) -> SocketAddr {
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
struct Client {
    sock: TcpStream,
    request: Vec<u8>,
    buf: Vec<u8>,
}

impl Client {
    async fn connect(addr: SocketAddr, headers: &str) -> Self {
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

    async fn round_trip(&mut self) -> usize {
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
                        .expect("bench requires a content-length response");
                    body_seen = head.len() - (i + 4);
                    head_end = Some(i);
                }
            } else {
                body_seen += n;
            }
            if head_end.is_some() && body_seen >= want {
                return want;
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn rss_bytes() -> u64 {
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
fn rss_bytes() -> u64 {
    0
}

/// Reported next to RSS because the worst regression found here was thread-per-request, and
/// RSS alone says that memory grew without saying why.
fn thread_count() -> usize {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("Threads:"))
                .and_then(|v| v.trim().parse().ok())
        })
        .unwrap_or(0)
}

fn median(samples: &mut [Duration]) -> Duration {
    samples.sort_unstable();
    samples[samples.len() / 2]
}

fn bench(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();

    let body = fixture();
    let mut response = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(&body);

    let base = tempfile::tempdir().unwrap();
    let baseline_rss = rss_bytes();

    let (upstream, proxy_addr) = rt.block_on(async {
        let up = fake_upstream(Arc::new(response)).await;
        let px = start_proxy(up, base.path()).await;
        (up, px)
    });

    let mut direct = rt.block_on(Client::connect(upstream, ""));
    let mut proxied = rt.block_on(Client::connect(
        proxy_addr,
        &format!(
            "m1-cred-ref: {CRED_REF}\r\nx-api-key: {}\r\n",
            String::from_utf8_lossy(API_KEY)
        ),
    ));

    // Warm both paths: the pool, the guard's HMAC state, the tee's parser map and the spill
    // scanner each allocate once, and none of that is per-request cost.
    for _ in 0..WARM_ITERS {
        rt.block_on(direct.round_trip());
        let n = rt.block_on(proxied.round_trip());
        assert_eq!(
            n,
            body.len(),
            "proxied response length differs from upstream"
        );
    }
    let warm_rss = rss_bytes();
    let warm_threads = thread_count();

    // --- ≤1 ms median added latency ----------------------------------------------------
    let mut d = Vec::with_capacity(PAIRED_ITERS);
    let mut p = Vec::with_capacity(PAIRED_ITERS);
    for _ in 0..PAIRED_ITERS {
        let t = Instant::now();
        rt.block_on(direct.round_trip());
        d.push(t.elapsed());
        let t = Instant::now();
        rt.block_on(proxied.round_trip());
        p.push(t.elapsed());
    }
    let (dm, pm) = (median(&mut d), median(&mut p));
    let added = pm.saturating_sub(dm);
    eprintln!("added latency: median {added:?} (direct {dm:?}, proxied {pm:?})");
    assert!(
        added < LATENCY_BUDGET,
        "04 §3.4 added-latency budget exceeded: {added:?}"
    );

    // --- ≤35 MB RSS, and no growth with request count ----------------------------------
    for _ in 0..LEAK_ITERS {
        rt.block_on(proxied.round_trip());
    }
    let steady_rss = rss_bytes();
    let warm_growth = warm_rss.saturating_sub(baseline_rss);
    let steady_growth = steady_rss.saturating_sub(warm_rss);
    eprintln!(
        "RSS: baseline {} KiB, warm {} KiB ({warm_threads} threads), after {LEAK_ITERS} more \
         {} KiB ({} threads); warm growth {} KiB (budget {} KiB), steady growth {} KiB",
        baseline_rss / 1024,
        warm_rss / 1024,
        steady_rss / 1024,
        thread_count(),
        warm_growth / 1024,
        RSS_BUDGET_BYTES / 1024,
        steady_growth / 1024,
    );
    // Charged over this process's baseline, so the fake upstream and the bench client count
    // against the proxy too — conservative in the safe direction.
    assert!(
        warm_growth < RSS_BUDGET_BYTES,
        "04 §3.4 RSS budget exceeded at warm-up: {} KiB over baseline",
        warm_growth / 1024
    );
    assert!(
        steady_growth < LEAK_ALLOWANCE_BYTES,
        "RSS grew {} KiB over {LEAK_ITERS} steady-state requests — something is per-request",
        steady_growth / 1024
    );

    // --- the reported distributions ----------------------------------------------------
    let mut group = c.benchmark_group("request");
    group.measurement_time(Duration::from_secs(5));
    group.bench_function("direct", |b| b.iter(|| rt.block_on(direct.round_trip())));
    group.bench_function("proxied", |b| b.iter(|| rt.block_on(proxied.round_trip())));
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
