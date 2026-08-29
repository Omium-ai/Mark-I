//! Cross-language conformance suite for the admit axis (12 §3.4, family
//! `redact/`). The `conf_vectors_` prefix is load-bearing:
//! `conformance_crosslang.sh` selects Rust tests by that filter and treats a
//! filter matching nothing as a FAILED run.

// clippy.toml's allow-*-in-tests exempts #[test] fns; the vector-driver code
// is inside one, but the exemption is restated at file scope (house style).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::PathBuf;

use mark1_redact::{AdmitOutcome, Scanner};
use serde_json::Value;

fn vectors_dir() -> PathBuf {
    // Crate-relative so the test runs from any cwd; the vectors are the
    // frozen Rust↔Go contract (12 §3.4).
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/vectors/redact")
}

#[test]
fn conf_vectors_redact_rust() {
    let dir = vectors_dir();
    let manifest: Value =
        serde_json::from_str(&fs::read_to_string(dir.join("manifest.json")).unwrap()).unwrap();
    let key = manifest["hmac_key_utf8"].as_str().unwrap();
    let scanner = Scanner::new(key.as_bytes()).unwrap();
    let vectors = manifest["vectors"].as_object().unwrap();
    assert!(!vectors.is_empty(), "empty manifest proves nothing");

    for (name, exp) in vectors {
        let input = fs::read(dir.join(name)).unwrap();
        let expected_out = fs::read(dir.join(name.replace(".in", ".out"))).unwrap();
        let mut buf = input.clone();
        let outcome = scanner.admit(&mut buf);
        // Bit-identical output is the whole contract: the Go twin must
        // produce these same bytes (NFR-CORRECTNESS-005).
        assert_eq!(
            buf, expected_out,
            "{name}: output bytes diverge from the frozen vector"
        );
        match exp["outcome"].as_str().unwrap() {
            "clean" => assert_eq!(outcome, AdmitOutcome::Clean, "{name}"),
            "redacted" => {
                let want = exp["substitutions"].as_u64().unwrap() as u32;
                assert_eq!(
                    outcome,
                    AdmitOutcome::Redacted {
                        substitutions: want
                    },
                    "{name}"
                );
                for planted in exp["planted"].as_array().unwrap() {
                    let secret = planted.as_str().unwrap().as_bytes();
                    assert!(
                        !buf.windows(secret.len()).any(|w| w == secret),
                        "{name}: planted secret survives (CON-008)"
                    );
                }
            }
            other => panic!("{name}: unknown outcome {other:?}"),
        }
    }
}
