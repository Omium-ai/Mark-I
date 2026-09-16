//! Added-latency and RSS budget (04 §3.4: ≤1 ms median added latency, ≤35 MB RSS).
//!
//! The harness — fake upstream, proxy, keep-alive clients, the paired-median loop — lives in
//! `tests/common/mod.rs` and is shared with `tests/latency_floor.rs`, which asserts a relaxed
//! CI floor on the same measurement under `cargo test` on every PR. This bench asserts the
//! real budget, and is gated only on the pinned runner (`bench/RUNNER.md`).
//!
//! Three things here are assertions rather than reports, because a budget nobody can fail is
//! a budget nobody keeps. Criterion is the better estimator and prints the distributions, but
//! criterion does not fail a build:
//!
//!   * the **latency delta**, from a paired median;
//!   * **RSS at warm-up**, over this process's pre-proxy baseline;
//!   * **RSS growth across sustained traffic**, which is the tripwire that found the two
//!     defects this bench was written to look for — a `spawn_blocking` per fabric emit and a
//!     `mark1_redact::Scanner` compiled per spilled record. Together they cost 240 threads and
//!     2.5 GB over 300 requests, and no unit test in the crate could see either.

// WHY: `clippy.toml` exempts `#[test]` fns from the workspace's unwrap/expect/panic denials;
// bench harnesses are not covered by that exemption, and a bench that cannot `expect` on its
// own fixture setup has to grow error plumbing that exists only to be discarded.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "../tests/common/mod.rs"]
mod common;

use std::time::Duration;

use common::{rss_bytes, thread_count, Arms, PAIRED_ITERS};
use criterion::{criterion_group, criterion_main, Criterion};

/// 04 §3.4.
const LATENCY_BUDGET: Duration = Duration::from_millis(1);
/// ≤35 MB (04 §3.4), measured as growth over the pre-proxy baseline of this process.
const RSS_BUDGET_BYTES: u64 = 35 * 1024 * 1024;
/// Steady-state growth allowance across `LEAK_ITERS` further requests. Not a second RSS
/// budget — a leak detector. Anything that scales with request count blows straight past it.
const LEAK_ALLOWANCE_BYTES: u64 = 8 * 1024 * 1024;
const LEAK_ITERS: usize = 2000;

fn bench(c: &mut Criterion) {
    let rt = common::runtime();
    let base = tempfile::tempdir().unwrap();
    let baseline_rss = rss_bytes();

    let mut arms = Arms::start(&rt, base.path());
    arms.warm(&rt);
    let warm_rss = rss_bytes();
    let warm_threads = thread_count();

    // --- ≤1 ms median added latency ----------------------------------------------------
    let (dm, pm) = arms.paired_medians(&rt, PAIRED_ITERS);
    let added = pm.saturating_sub(dm);
    eprintln!("added latency: median {added:?} (direct {dm:?}, proxied {pm:?})");
    assert!(
        added < LATENCY_BUDGET,
        "04 §3.4 added-latency budget exceeded: {added:?}"
    );

    // --- ≤35 MB RSS, and no growth with request count ----------------------------------
    for _ in 0..LEAK_ITERS {
        rt.block_on(arms.proxied.round_trip());
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
    let Arms {
        mut direct,
        mut proxied,
        ..
    } = arms;
    let mut group = c.benchmark_group("request");
    group.measurement_time(Duration::from_secs(5));
    group.bench_function("direct", |b| b.iter(|| rt.block_on(direct.round_trip())));
    group.bench_function("proxied", |b| b.iter(|| rt.block_on(proxied.round_trip())));
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
