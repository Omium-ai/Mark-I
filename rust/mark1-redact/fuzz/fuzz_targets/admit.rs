//! fuzz_redact_scanner (12 §4): arbitrary bytes into both scanner axes.
//!
//! Properties beyond not-crashing, per 12 §4's fuzz row:
//! - the admit axis returns a decision for ALL inputs — quarantine on
//!   internal error, never a raw pass-through (F-35);
//! - the admit axis is idempotent: a second pass over redacted output is
//!   Clean, so no substitution can manufacture a new finding;
//! - per-input time is bounded (rust/regex's no-catastrophic-backtracking
//!   guarantee, verified not assumed — the assert makes a pathological
//!   pattern addition a fuzz finding instead of a field incident).
#![no_main]

use std::time::{Duration, Instant};

use libfuzzer_sys::fuzz_target;
use mark1_redact::{AdmitOutcome, Carry, Scanner};

fuzz_target!(|data: &[u8]| {
    // One scanner per process would hide ruleset-compile failures from the
    // fuzzer's first run; thread_local keeps compile cost off the per-input
    // path without hiding it.
    thread_local! {
        static SCANNER: Scanner = match Scanner::new(b"fuzz-tenant-key") {
            Ok(s) => s,
            Err(e) => panic!("ruleset must compile: {e}"),
        };
    }
    SCANNER.with(|scanner| {
        let started = Instant::now();

        let mut buf = data.to_vec();
        let first = scanner.admit(&mut buf);
        match first {
            AdmitOutcome::Clean => assert_eq!(buf, data, "Clean must not mutate"),
            AdmitOutcome::Redacted { substitutions } => {
                assert!(substitutions > 0, "Redacted with zero substitutions");
                let snapshot = buf.clone();
                assert_eq!(
                    scanner.admit(&mut buf),
                    AdmitOutcome::Clean,
                    "admit must be idempotent"
                );
                assert_eq!(buf, snapshot);
            }
            AdmitOutcome::Quarantine => {}
        }

        // Detect axis on the same bytes, split in two, must not crash and
        // must respect the same time bound.
        let mid = data.len() / 2;
        let mut carry = Carry::default();
        let _ = scanner.scan(&data[..mid], &mut carry);
        let _ = scanner.scan(&data[mid..], &mut carry);

        // Generous wall bound: worst case is ~100 MB/s (04 §7.1), so even a
        // max-size fuzz input finishes orders of magnitude under a second.
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "per-input time budget exceeded: possible backtracking blowup"
        );
    });
});
