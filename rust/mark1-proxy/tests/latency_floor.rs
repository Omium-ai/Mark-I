//! The CI floor under NFR-LATENCY-001 and NFR-FOOTPRINT-001: the bench's paired-median
//! measurement, asserted under `cargo test` on every PR at a threshold a shared runner can
//! hold honestly.
//!
//! `benches/latency.rs` asserts the real budgets (1 ms, 35 MB) but only runs on the pinned
//! runner (`docs/runbooks/bench-runner.md`), and `bench-gate` passes *as deferred* while that runner is
//! unregistered — so until it exists, no PR can go red on a hot-path regression. This test
//! closes that hole with a relaxed number: `docs/runbooks/bench-runner.md` records that a hosted runner's
//! spread is wider than the 1 ms budget, so 1 ms here would fail builds that did not regress.
//! 5 ms is an order of magnitude above the delta this harness measures (~0.3 ms) and still
//! below anything a `spawn_blocking` per request or a regex compiled per record costs. The
//! 1 ms number stays the bench's, on the pinned runner; this is the tripwire, not the budget.
//!
//! Same harness (`tests/common`), same interleaved loop, same N — only the threshold differs.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::time::Duration;

use common::{rss_bytes, thread_count, Arms, PAIRED_ITERS};

/// The CI floor. Not 04 §3.4's budget — see the module doc.
const LATENCY_BUDGET_CI: Duration = Duration::from_millis(5);
/// 04 §3.4's ≤35 MB, as the bench charges it: growth over this process's pre-proxy baseline.
/// Memory does not get noisier on a shared runner, so the real number is asserted here.
const RSS_BUDGET_BYTES: u64 = 35 * 1024 * 1024;
/// The bench's leak allowance across `LEAK_ITERS` further requests, kept for the same reason:
/// growth that scales with request count is what this harness exists to catch.
const LEAK_ALLOWANCE_BYTES: u64 = 8 * 1024 * 1024;
const LEAK_ITERS: usize = 2000;

#[test]
fn added_latency_and_rss_under_ci_floor() {
    let rt = common::runtime();
    let base = tempfile::tempdir().unwrap();
    let baseline_rss = rss_bytes();

    let mut arms = Arms::start(&rt, base.path());

    // Anti-vacuity: a proxy that short-circuits, truncates or re-encodes would post a fine
    // latency. Both arms must hand the client the upstream's body, byte for byte.
    let direct_body = rt.block_on(arms.direct.round_trip_body());
    let proxied_body = rt.block_on(arms.proxied.round_trip_body());
    assert_eq!(direct_body, arms.body, "direct arm is not the fixture");
    assert_eq!(proxied_body, arms.body, "proxied body is not byte-exact");

    arms.warm(&rt);
    let warm_rss = rss_bytes();
    let warm_threads = thread_count();

    // Both arms complete every one of PAIRED_ITERS iterations, or `paired_medians` panics.
    let (dm, pm) = arms.paired_medians(&rt, PAIRED_ITERS);
    let added = pm.saturating_sub(dm);
    eprintln!(
        "added latency: median {added:?} (direct {dm:?}, proxied {pm:?}); CI floor {LATENCY_BUDGET_CI:?}"
    );
    assert!(
        added < LATENCY_BUDGET_CI,
        "added latency {added:?} exceeds the CI floor {LATENCY_BUDGET_CI:?} \
         (direct {dm:?}, proxied {pm:?}) — the hot path regressed"
    );

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
}
