//! The starter ruleset, as DATA (04 §7.1: prefilter literals → regex confirm
//! → entropy test). A rule is a table row, not code: adding a detector is a
//! reviewable one-row diff, and the conformance vectors freeze the observable
//! behavior of every row (12 §3.4 `redact/` family).

use crate::SecretClass;

/// One detector row. `anchors` feeds the aho-corasick prefilter; every anchor
/// MUST be a byte-prefix of any text its `pattern` can match, because the
/// confirm step requires the regex match to start exactly at the anchor hit.
/// `anchors` empty ⇒ the rule has no stable literal (the entropy classes) and
/// runs as a full-buffer regex pass instead — see `Scanner::find_all`.
pub(crate) struct Rule {
    /// Stable identity for vectors and triage (12 §9 row 3 wants distinct
    /// rule IDs proving ruleset independence from the ingest twin).
    pub id: &'static str,
    pub class: SecretClass,
    pub anchors: &'static [&'static str],
    pub pattern: &'static str,
    /// Shannon-entropy floor in bits/byte over the matched span; a match
    /// below the floor is discarded. `None` = structural match is enough.
    pub min_entropy: Option<f32>,
}

/// Table order is priority order: when two rules match overlapping spans the
/// earlier row wins (so `sk-ant-…` classifies Anthropic before the broader
/// `sk-…` OpenAI shape claims it). Bounded repetitions everywhere — an
/// unbounded `{40,}` would let one hostile input drag a single match across
/// the whole buffer, and the ~100 MB/s worst-case budget (04 §7.1) is only
/// real while every match is O(bounded).
pub(crate) const RULES: &[Rule] = &[
    Rule {
        id: "aws_access_key_id",
        class: SecretClass::ApiKey,
        anchors: &["AKIA", "ASIA"],
        pattern: r"(?:AKIA|ASIA)[0-9A-Z]{16}",
        min_entropy: None,
    },
    Rule {
        id: "github_token",
        class: SecretClass::ApiKey,
        // All five classic prefixes plus the fine-grained PAT form.
        anchors: &["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"],
        pattern: r"(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})",
        min_entropy: None,
    },
    Rule {
        id: "anthropic_api_key",
        class: SecretClass::ApiKey,
        anchors: &["sk-ant-"],
        pattern: r"sk-ant-[A-Za-z0-9_\-]{24,512}",
        min_entropy: None,
    },
    Rule {
        id: "openai_api_key",
        class: SecretClass::ApiKey,
        // Broader than the Anthropic row on purpose; priority order above
        // keeps `sk-ant-…` out of this class.
        anchors: &["sk-"],
        pattern: r"sk-[A-Za-z0-9_\-]{20,512}",
        min_entropy: None,
    },
    Rule {
        id: "pem_private_key",
        class: SecretClass::PrivateKey,
        anchors: &["-----BEGIN "],
        // (?s) so the body's newlines match; the {0,8192} body bound is what
        // keeps a BEGIN with no END from scanning to end-of-buffer.
        pattern: r"(?s)-----BEGIN [A-Z0-9 ]{0,32}PRIVATE KEY-----.{0,8192}?-----END [A-Z0-9 ]{0,32}PRIVATE KEY-----",
        min_entropy: None,
    },
    Rule {
        id: "jwt",
        class: SecretClass::OauthToken,
        // Every JOSE header starts `{"` ⇒ base64url `eyJ`.
        anchors: &["eyJ"],
        pattern: r"eyJ[A-Za-z0-9_\-]{8,2048}\.[A-Za-z0-9_\-]{8,4096}\.[A-Za-z0-9_\-]{8,1024}",
        min_entropy: None,
    },
    Rule {
        id: "high_entropy_hex",
        class: SecretClass::HighEntropy,
        anchors: &[],
        pattern: r"[0-9a-fA-F]{40,128}",
        // Max for hex is 4 bits/byte; random key material sits near it, prose
        // and repeated padding fall well under.
        min_entropy: Some(3.4),
    },
    Rule {
        id: "high_entropy_base64",
        class: SecretClass::HighEntropy,
        anchors: &[],
        pattern: r"[A-Za-z0-9+/]{40,512}={0,2}",
        // Max for base64 is 6 bits/byte; identifiers and English-in-b64 runs
        // stay under ~4.5, random 32-byte keys encode to ~5.9.
        min_entropy: Some(4.8),
    },
];

/// Carry-over window: max secret length the ruleset can match, minus one
/// (04 §7.1 — a secret split across chunks is still caught). The PEM row is
/// the longest possible match: header(~40) + body bound 8192 + footer(~38).
pub(crate) const MAX_SECRET_LEN: usize = 8320;
