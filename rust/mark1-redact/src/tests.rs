//! Unit + property suite for the two-axis scanner. Every starter rule has a
//! positive and a negative case; the three property tests are the 12 §2.4
//! rows (`prop_redact_no_secret_survives`, `prop_redact_idempotent`,
//! `prop_redact_admit_axis_total`).

// clippy.toml's allow-*-in-tests exempts #[test] fns; helpers here are plain
// fns, so the exemption is restated at file scope (house style, m1pl.rs).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use proptest::prelude::*;

use crate::{AdmitOutcome, Carry, Scanner, SecretClass};

const KEY: &[u8] = b"unit-test-tenant-key";

// Compiled once: the bounded-repetition rows (PEM, JWT) make ruleset
// compilation the dominant cost, and proptest runs hundreds of cases.
fn scanner() -> &'static Scanner {
    static SCANNER: std::sync::OnceLock<Scanner> = std::sync::OnceLock::new();
    SCANNER.get_or_init(|| Scanner::new(KEY).unwrap())
}

fn admit_str(s: &str) -> (AdmitOutcome, String) {
    let mut buf = s.as_bytes().to_vec();
    let out = scanner().admit(&mut buf);
    (out, String::from_utf8_lossy(&buf).into_owned())
}

/// A planted secret must be gone and replaced by a token of its class.
fn assert_redacts(input: &str, secret: &str, class: SecretClass) {
    let (out, text) = admit_str(input);
    assert!(
        matches!(out, AdmitOutcome::Redacted { substitutions } if substitutions >= 1),
        "expected Redacted for {input:?}, got {out:?}"
    );
    assert!(!text.contains(secret), "secret survived in {text:?}");
    assert!(
        text.contains(&format!("\u{27e8}redacted:{}:", class.label())),
        "wrong class token in {text:?}"
    );
}

fn assert_clean(input: &str) {
    let (out, text) = admit_str(input);
    assert_eq!(
        out,
        AdmitOutcome::Clean,
        "false positive on {input:?}: {text:?}"
    );
}

// ---- one positive + negative per starter rule ----

#[test]
fn rule_aws_access_key_id() {
    assert_redacts(
        "creds: AKIAIOSFODNN7EXAMPLE ok",
        "AKIAIOSFODNN7EXAMPLE",
        SecretClass::ApiKey,
    );
    // 15 trailing chars, one short of the shape.
    assert_clean("AKIAIOSFODNN7EXAMPL");
}

#[test]
fn rule_github_token() {
    assert_redacts(
        "token=ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        SecretClass::ApiKey,
    );
    assert_redacts(
        "github_pat_11ABCDEFG0abcdefghijklmnopqrstuvwxyz",
        "github_pat_11ABCDEFG0abcdefghijklmnopqrstuvwxyz",
        SecretClass::ApiKey,
    );
    assert_clean("ghp_tooShort123");
}

#[test]
fn rule_anthropic_api_key() {
    assert_redacts(
        "export ANTHROPIC_API_KEY=sk-ant-api03-AbCdEf-GhIjKlMnOpQrStUvWx",
        "sk-ant-api03-AbCdEf-GhIjKlMnOpQrStUvWx",
        SecretClass::ApiKey,
    );
}

#[test]
fn rule_openai_api_key() {
    assert_redacts(
        "OPENAI_API_KEY=sk-AbCdEfGhIjKlMnOpQrStUvWxYz12",
        "sk-AbCdEfGhIjKlMnOpQrStUvWxYz12",
        SecretClass::ApiKey,
    );
    // The Anthropic row outranks the broader sk- shape (table priority).
    let (_, text) = admit_str("sk-ant-api03-AbCdEf-GhIjKlMnOpQrStUvWx");
    assert!(text.contains("\u{27e8}redacted:api_key:"));
    assert_clean("sk-short");
}

#[test]
fn rule_pem_private_key() {
    let pem =
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA7\nqqqq\n-----END RSA PRIVATE KEY-----";
    assert_redacts(
        &format!("cat key.pem\n{pem}\ndone"),
        "MIIEowIBAAKCAQEA7",
        SecretClass::PrivateKey,
    );
    // BEGIN without END must not scan away the rest of the document.
    assert_clean("-----BEGIN RSA PRIVATE KEY-----\nno end marker here");
}

#[test]
fn rule_jwt() {
    assert_redacts(
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
        SecretClass::OauthToken,
    );
    assert_clean("eyJx.eyJy.zz");
}

#[test]
fn rule_high_entropy_hex() {
    assert_redacts(
        "sig 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 end",
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        SecretClass::HighEntropy,
    );
    // 64 hex chars of near-zero entropy: shape matches, randomness test fails.
    assert_clean("0000000000000000000000000000000000000000000000000000000000000001");
}

#[test]
fn rule_high_entropy_base64() {
    assert_redacts(
        "key: dGhpcyBpc0EvKzlSYW5kb21LZXlNYXRlcmlhbFhZWnF3ZXJ0eXVpb3A3ODkwMTIzNA==",
        "dGhpcyBpc0EvKzlSYW5kb21LZXlNYXRlcmlhbFhZWnF3ZXJ0eXVpb3A3ODkwMTIzNA==",
        SecretClass::HighEntropy,
    );
    // A long camelCase identifier: base64 alphabet, sub-threshold entropy.
    assert_clean("theQuickBrownFoxJumpedOverTheLazyDogAgainAndAgain");
}

// ---- axis invariants ----

#[test]
fn admit_clean_leaves_bytes_untouched() {
    let original = b"nothing secret here, just text".to_vec();
    let mut buf = original.clone();
    assert_eq!(scanner().admit(&mut buf), AdmitOutcome::Clean);
    assert_eq!(buf, original);
}

#[test]
fn admit_substitution_count_is_exact() {
    let (out, text) = admit_str("a AKIAIOSFODNN7EXAMPLE b AKIA0123456789ABCDEF c");
    assert_eq!(out, AdmitOutcome::Redacted { substitutions: 2 });
    // Equal secrets correlate (same token), distinct ones do not.
    let (_, twice) = admit_str("AKIAIOSFODNN7EXAMPLE AKIAIOSFODNN7EXAMPLE");
    let first = twice.split(' ').next().unwrap();
    assert_eq!(twice, format!("{first} {first}"));
    assert!(!text.is_empty());
}

#[test]
fn token_hash_is_keyed_per_tenant() {
    let mut a = b"AKIAIOSFODNN7EXAMPLE".to_vec();
    let mut b = a.clone();
    Scanner::new(b"tenant-a").unwrap().admit(&mut a);
    Scanner::new(b"tenant-b").unwrap().admit(&mut b);
    // Same secret, different tenants ⇒ different hashes (04 §7.1: correlate
    // within a tenant, reveal nothing across).
    assert_ne!(a, b);
}

#[test]
fn scan_carry_catches_split_secret() {
    let s = scanner();
    let doc = b"prefix AKIAIOSFODNN7EXAMPLE suffix";
    // Split inside the secret: the carry window must still surface it once.
    for cut in 1..doc.len() {
        let mut carry = Carry::default();
        let mut findings = s.scan(&doc[..cut], &mut carry);
        findings.extend(s.scan(&doc[cut..], &mut carry));
        let hits: Vec<_> = findings
            .iter()
            .filter(|f| f.class == SecretClass::ApiKey)
            .collect();
        assert_eq!(hits.len(), 1, "cut at {cut}");
        assert_eq!(hits[0].span, 7..27, "cut at {cut}: absolute stream span");
    }
}

// ---- 12 §2.4 property rows ----

/// Secrets planted at arbitrary offsets never survive the admit axis.
#[test]
fn prop_redact_no_secret_survives() {
    let secrets = [
        "AKIAIOSFODNN7EXAMPLE",
        "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        "sk-ant-api03-AbCdEf-GhIjKlMnOpQrStUvWx",
        "sk-AbCdEfGhIjKlMnOpQrStUvWxYz12",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N",
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    ];
    proptest!(|(pre in "[ -~]{0,64}", post in "[ -~]{0,64}", idx in 0..secrets.len())| {
        let secret = secrets[idx];
        // A word char butted against the secret can legitimately extend the
        // match; separators isolate what "planted" means.
        let doc = format!("{pre} {secret} {post}");
        let mut buf = doc.into_bytes();
        let out = scanner().admit(&mut buf);
        let redacted = matches!(out, AdmitOutcome::Redacted { .. });
        prop_assert!(redacted);
        let text = String::from_utf8_lossy(&buf);
        prop_assert!(!text.contains(secret));
    });
}

/// Already-redacted output is stable: redact(redact(x)) == redact(x).
#[test]
fn prop_redact_idempotent() {
    proptest!(|(doc in "[ -~]{0,128}")| {
        let mut once = doc.clone().into_bytes();
        scanner().admit(&mut once);
        let mut twice = once.clone();
        let second = scanner().admit(&mut twice);
        prop_assert_eq!(second, AdmitOutcome::Clean);
        prop_assert_eq!(once, twice);
    });
}

/// The admit axis is total: every input maps to one of the three outcomes
/// and never panics out (F-35).
#[test]
fn prop_redact_admit_axis_total() {
    proptest!(|(bytes in proptest::collection::vec(any::<u8>(), 0..2048))| {
        let mut buf = bytes;
        let out = scanner().admit(&mut buf);
        let total = matches!(
            out,
            AdmitOutcome::Clean | AdmitOutcome::Redacted { .. } | AdmitOutcome::Quarantine
        );
        prop_assert!(total);
    });
}
