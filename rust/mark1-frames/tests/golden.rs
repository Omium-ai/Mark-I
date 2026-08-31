//! `frames_golden_per_dialect` (12 §3.1, 04 §4).
//!
//! Two obligations per recorded transcript:
//!   (a) byte-exact passthrough — feeding a fixture must leave the fed bytes bit-identical;
//!   (b) the parsed observations match the committed snapshot.
//!
//! Both are asserted under three chunkings — whole, one byte at a time, and a deterministic
//! pseudo-random split — because the tee cuts the response body wherever the network did,
//! and a parser whose output depends on that is a parser that mis-bills on a slow link.

use std::fs;
use std::path::{Path, PathBuf};

use mark1_frames::{DegradeReason, Dialect, WireObservation};
use serde::Deserialize;

/// The committed snapshot, and also the shape a run produces — comparing like to like is
/// what lets one `assert_eq!` cover "matches the golden" and "same under every chunking".
#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Transcript {
    observations: Vec<WireObservation>,
    /// Required, never defaulted: a fixture that does not state whether it degrades is a
    /// fixture nobody decided the behaviour of.
    degraded: Option<Degrade>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Degrade {
    at_byte: u64,
    reason: DegradeReason,
}

fn frames_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance/frames")
}

/// `DIALECT_ANTHROPIC_SSE` -> `anthropic_sse`, i.e. the module and fixture-directory name.
fn module_name(d: Dialect) -> String {
    d.wire_name()
        .trim_start_matches("DIALECT_")
        .to_ascii_lowercase()
}

/// Deterministic chunk sizes in 1..=23 (xorshift64). Seeded, so a failure reproduces.
fn pseudo_random_splits(mut s: u64, n: usize) -> Vec<usize> {
    (0..n)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            1 + (s % 23) as usize
        })
        .collect()
}

/// Drives a parser over `bytes`, cutting at `sizes` (cycled), and asserts obligation (a).
fn observe(dialect: Dialect, bytes: &[u8], sizes: &[usize]) -> Transcript {
    // The parser is handed a private copy by shared reference, exactly as the tee hands it
    // a clone of the response body. Comparing the copy back afterwards is the passthrough
    // assertion: nothing on the parse path may write through to the bytes it was shown.
    let fed = bytes.to_vec();

    let mut parser = dialect.parser();
    let mut observations = Vec::new();
    let mut degraded = None;
    let mut at = 0usize;
    let mut i = 0usize;
    while at < fed.len() {
        let n = sizes[i % sizes.len()].clamp(1, fed.len() - at);
        i += 1;
        match parser.feed(&fed[at..at + n]) {
            Ok(v) => observations.extend(v),
            Err(d) => {
                degraded = Some(Degrade {
                    at_byte: d.at_byte,
                    reason: d.reason,
                });
                break;
            }
        }
        at += n;
    }
    if degraded.is_none() {
        if let Err(d) = parser.finish() {
            degraded = Some(Degrade {
                at_byte: d.at_byte,
                reason: d.reason,
            });
        }
    }

    assert_eq!(fed, bytes, "the parser altered the bytes it was fed");
    Transcript {
        observations,
        degraded,
    }
}

/// Dialects the gate is armed for. See `conformance/frames/EXPECTED` for why this is a
/// committed list rather than a directory scan.
fn expected_families(manifest: &str) -> Vec<String> {
    manifest
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_owned)
        .collect()
}

#[test]
fn frames_golden_per_dialect() {
    let manifest_path = frames_dir().join("EXPECTED");
    let manifest = fs::read_to_string(&manifest_path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", manifest_path.display()));
    let families = expected_families(&manifest);
    assert!(
        !families.is_empty(),
        "conformance/frames/EXPECTED arms no dialect, so this test would pass over zero fixtures"
    );

    let mut fixtures_run = 0usize;
    let mut degrading_fixtures = 0usize;

    for family in &families {
        let dialect = Dialect::ALL
            .into_iter()
            .find(|d| module_name(*d) == *family)
            .unwrap_or_else(|| panic!("EXPECTED arms `{family}`, which is not a known dialect"));

        let dir = frames_dir().join(family);
        let mut fixtures: Vec<PathBuf> = fs::read_dir(&dir)
            .unwrap_or_else(|e| {
                panic!("{family} is armed but {} is unreadable: {e}", dir.display())
            })
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "bytes"))
            .collect();
        fixtures.sort();
        assert!(
            !fixtures.is_empty(),
            "{family} is armed in EXPECTED but has no .bytes fixtures"
        );

        for fixture in fixtures {
            let bytes = fs::read(&fixture).unwrap();
            assert!(!bytes.is_empty(), "{} is empty", fixture.display());

            // No silent skip: a transcript without a snapshot is an untested transcript.
            let snapshot_path = fixture.with_extension("expected.json");
            let snapshot = fs::read(&snapshot_path).unwrap_or_else(|e| {
                panic!(
                    "{} has no readable snapshot at {}: {e}",
                    fixture.display(),
                    snapshot_path.display()
                )
            });
            let expected: Transcript = serde_json::from_slice(&snapshot)
                .unwrap_or_else(|e| panic!("{}: {e}", snapshot_path.display()));

            for (label, sizes) in [
                ("whole", vec![usize::MAX]),
                ("one byte at a time", vec![1]),
                (
                    "pseudo-random splits",
                    pseudo_random_splits(0x5eed_1234_abcd_ef01, 64),
                ),
            ] {
                assert_eq!(
                    observe(dialect, &bytes, &sizes),
                    expected,
                    "{} mismatched its snapshot when fed {label}",
                    fixture.display()
                );
            }

            if expected.degraded.is_some() {
                degrading_fixtures += 1;
            }
            fixtures_run += 1;
        }
    }

    // Tripwires against a suite that reports success while asserting nothing.
    assert!(
        fixtures_run >= families.len(),
        "fewer fixtures ran than dialects armed"
    );
    assert!(
        degrading_fixtures > 0,
        "no fixture exercises the degrade path, so parse_degraded_total is untested"
    );
}
