//! bench_redact_throughput (12 §7): the CI floor is ≥ 80 MB/s on a worst-case
//! mixed corpus — throughput is a budget, not a property, and the headroom is
//! what lets the admit axis sit synchronously on every path (04 §7.1).

// Benches are not #[cfg(test)], so clippy.toml's test exemption does not
// apply; the workspace denies are restated away at file scope (house style).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use mark1_redact::Scanner;

/// Mixed corpus: code-ish text, JSON, planted secrets at both density
/// extremes, and long near-miss runs that force the entropy test to run.
fn corpus(len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let blocks: [&[u8]; 4] = [
        b"fn main() { let x = compute(42); println!(\"{x}\"); } // no secrets here\n",
        b"{\"event\":\"tool_use\",\"name\":\"Bash\",\"input\":\"./run-tests.sh --all\"}\n",
        b"key=AKIAIOSFODNN7EXAMPLE token=ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789\n",
        // 64 low-entropy hex chars: shape-matches, fails the randomness test.
        b"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n",
    ];
    let mut i = 0usize;
    while out.len() < len {
        out.extend_from_slice(blocks[i % blocks.len()]);
        i += 1;
    }
    out.truncate(len);
    out
}

fn bench_redact_throughput(c: &mut Criterion) {
    let scanner = Scanner::new(b"bench-tenant-key").unwrap();
    // ponytail: 4 MiB per iteration, not 12 §7's 64 MiB corpus — criterion
    // re-runs the routine enough times that MB/s is the same statistic; move
    // to the full corpus when the CI bench job (12) lands its threshold.
    let doc = corpus(4 << 20);
    let mut group = c.benchmark_group("redact");
    group.throughput(Throughput::Bytes(doc.len() as u64));
    group.bench_function("admit_worst_case_mixed", |b| {
        b.iter(|| {
            let mut buf = doc.clone();
            scanner.admit(&mut buf)
        })
    });
    group.finish();
}

criterion_group!(benches, bench_redact_throughput);
criterion_main!(benches);
