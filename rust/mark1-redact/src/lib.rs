//! mark1-redact — the two-axis secret scanner (04 §7.1).
//!
//! Axis 1 (`scan`): detect-in-transit findings for callers that mutate their
//! own streams (default OFF at the policy layer; this crate only reports).
//! Axis 2 (`admit`): admit-to-upload — fail-closed, and the absence of an off
//! switch is an API property: no config field, feature flag, or parameter of
//! this crate bypasses it (CON-008). Flagged spans become
//! `⟨redacted:class:hash⟩` in place, hash = per-tenant HMAC of the span, so
//! equal secrets correlate within a tenant and reveal nothing (04 §7.1).
//!
//! Linked by the proxy (both axes) and the hookshim (admit axis, 04 §5.4);
//! `mark1d` carries the Go twin validated against the same
//! `conformance/vectors/redact/` family (12 §3.4).

use std::ops::Range;
use std::panic::{catch_unwind, AssertUnwindSafe};

use aho_corasick::AhoCorasick;
use hmac::{Hmac, Mac};
use regex::bytes::Regex;
use sha2::Sha256;
use zeroize::Zeroize;

mod rules;
use rules::{MAX_SECRET_LEN, RULES};

/// 04 §7.1's classes. `Password` has no starter rule yet — context-keyed
/// password detection is a bundle-era ruleset addition, but the class is part
/// of the frozen vocabulary so the token grammar never changes when it lands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretClass {
    ApiKey,
    OauthToken,
    PrivateKey,
    Password,
    HighEntropy,
}

impl SecretClass {
    /// The `class` leg of the `⟨redacted:class:hash⟩` token. Frozen by the
    /// redact conformance vectors — renaming a label is a vector break.
    pub fn label(self) -> &'static str {
        match self {
            SecretClass::ApiKey => "api_key",
            SecretClass::OauthToken => "oauth_token",
            SecretClass::PrivateKey => "private_key",
            SecretClass::Password => "password",
            SecretClass::HighEntropy => "high_entropy",
        }
    }
}

/// Structural rules confirm on shape alone; the entropy classes are
/// statistical, and downstream consumers may weigh them differently.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Confidence {
    High,
    Medium,
}

/// One detected span. `span` is in the coordinates of the buffer handed to
/// the axis that produced it: absolute stream offsets from `scan` (the carry
/// keeps the stream position), plain buffer offsets from `admit`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub class: SecretClass,
    pub span: Range<usize>,
    pub confidence: Confidence,
}

/// AdmitOutcome exactly as 04 §7.1 declares it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmitOutcome {
    Clean,
    Redacted {
        substitutions: u32,
    },
    /// Any internal failure (ruleset load, regex engine, panic-caught) lands
    /// here: the event is quarantined locally, never admitted raw (F-35).
    Quarantine,
}

/// Streaming carry: the last `MAX_SECRET_LEN − 1` bytes of the stream plus
/// the absolute offset where the retained tail begins, so a secret split
/// across chunk boundaries is still caught and reported once (04 §7.1).
#[derive(Default)]
pub struct Carry {
    tail: Vec<u8>,
    /// Absolute stream offset of `tail[0]`.
    tail_start: usize,
    /// Absolute end of the region already reported by earlier `scan` calls;
    /// a finding is new iff it ends past this watermark.
    reported_end: usize,
}

impl Drop for Carry {
    fn drop(&mut self) {
        // The tail is pre-redaction stream bytes — wiped, never left in
        // freed memory (invariant 5, 04 §0.3).
        self.tail.zeroize();
    }
}

/// Ruleset failed to compile. Constructing a Scanner is the only fallible
/// step; callers that cannot construct one must quarantine, not pass through
/// (the admit axis has no "scannerless" mode).
#[derive(Debug, thiserror::Error)]
#[error("mark1-redact ruleset failed to compile: {0}")]
pub struct RulesetError(String);

struct CompiledRule {
    class: SecretClass,
    regex: Regex,
    min_entropy: Option<f32>,
    confidence: Confidence,
}

/// Compiled ruleset: aho-corasick prefilter over the anchored rules' literal
/// prefixes, regex confirm at each anchor hit, full-buffer regex pass for the
/// anchor-less entropy rules, Shannon-entropy filter last (04 §7.1).
pub struct Scanner {
    prefilter: AhoCorasick,
    /// anchor-pattern index (prefilter space) → rule index.
    anchor_rule: Vec<usize>,
    compiled: Vec<CompiledRule>,
    /// Indices of rules with no anchor literal.
    unanchored: Vec<usize>,
    hmac_key: Vec<u8>,
}

impl Scanner {
    /// Compile the builtin ruleset. `hmac_key` is the per-tenant redaction
    /// key: the `hash` leg of every token is HMAC-SHA256(key, span), so equal
    /// secrets correlate within one tenant and nowhere else (04 §7.1).
    pub fn new(hmac_key: &[u8]) -> Result<Self, RulesetError> {
        let mut compiled = Vec::with_capacity(RULES.len());
        let mut anchors: Vec<&str> = Vec::new();
        let mut anchor_rule = Vec::new();
        let mut unanchored = Vec::new();
        for (idx, rule) in RULES.iter().enumerate() {
            compiled.push(CompiledRule {
                class: rule.class,
                regex: Regex::new(rule.pattern)
                    .map_err(|e| RulesetError(format!("{}: {e}", rule.id)))?,
                min_entropy: rule.min_entropy,
                confidence: if rule.min_entropy.is_some() {
                    Confidence::Medium
                } else {
                    Confidence::High
                },
            });
            if rule.anchors.is_empty() {
                unanchored.push(idx);
            } else {
                for a in rule.anchors {
                    anchors.push(a);
                    anchor_rule.push(idx);
                }
            }
        }
        let prefilter = AhoCorasick::new(&anchors).map_err(|e| RulesetError(e.to_string()))?;
        Ok(Self {
            prefilter,
            anchor_rule,
            compiled,
            unanchored,
            hmac_key: hmac_key.to_vec(),
        })
    }

    /// All findings over one complete buffer, overlap-resolved: findings are
    /// kept greedily by (start, longest, table priority), so no two kept
    /// spans overlap and substitution offsets stay well-defined — the dedupe
    /// invariant the vectors pin.
    fn find_all(&self, buf: &[u8]) -> Vec<Finding> {
        // (start, end, rule idx) candidates before overlap resolution.
        let mut cand: Vec<(usize, usize, usize)> = Vec::new();
        for hit in self.prefilter.find_overlapping_iter(buf) {
            let rule_idx = self.anchor_rule[hit.pattern().as_usize()];
            let rule = &self.compiled[rule_idx];
            // Anchors are match prefixes by table contract, so the confirm
            // is "regex match starting exactly at the anchor hit".
            if let Some(m) = rule.regex.find_at(buf, hit.start()) {
                if m.start() == hit.start() && self.entropy_ok(rule, &buf[m.range()]) {
                    cand.push((m.start(), m.end(), rule_idx));
                }
            }
        }
        for &rule_idx in &self.unanchored {
            let rule = &self.compiled[rule_idx];
            for m in rule.regex.find_iter(buf) {
                if self.entropy_ok(rule, &buf[m.range()]) {
                    cand.push((m.start(), m.end(), rule_idx));
                }
            }
        }
        cand.sort_by(|a, b| {
            let (a_start, a_end, a_rule) = *a;
            let (b_start, b_end, b_rule) = *b;
            a_start
                .cmp(&b_start)
                .then(b_end.cmp(&a_end))
                .then(a_rule.cmp(&b_rule))
        });
        let mut kept: Vec<Finding> = Vec::new();
        let mut covered_end = 0usize;
        for (start, end, rule_idx) in cand {
            if start < covered_end {
                continue;
            }
            covered_end = end;
            let rule = &self.compiled[rule_idx];
            kept.push(Finding {
                class: rule.class,
                span: start..end,
                confidence: rule.confidence,
            });
        }
        kept
    }

    fn entropy_ok(&self, rule: &CompiledRule, span: &[u8]) -> bool {
        match rule.min_entropy {
            None => true,
            Some(floor) => shannon_bits_per_byte(span) >= floor,
        }
    }

    /// DETECT axis (04 §7.1): streaming scan with a carry-over window of
    /// `MAX_SECRET_LEN − 1` bytes. Findings carry absolute stream offsets;
    /// a finding is reported by exactly one call — the first whose buffer
    /// contains its final byte (re-detections wholly inside the carried tail
    /// were already reported and are suppressed by the watermark).
    pub fn scan(&self, chunk: &[u8], carry: &mut Carry) -> Vec<Finding> {
        let mut buf = Vec::with_capacity(carry.tail.len() + chunk.len());
        buf.extend_from_slice(&carry.tail);
        buf.extend_from_slice(chunk);
        let base = carry.tail_start;
        let findings: Vec<Finding> = self
            .find_all(&buf)
            .into_iter()
            .map(|f| Finding {
                span: base + f.span.start..base + f.span.end,
                ..f
            })
            .filter(|f| f.span.end > carry.reported_end)
            .collect();
        let stream_end = base + buf.len();
        carry.reported_end = stream_end;
        let keep = MAX_SECRET_LEN.saturating_sub(1).min(buf.len());
        carry.tail.zeroize();
        carry.tail.clear();
        carry.tail.extend_from_slice(&buf[buf.len() - keep..]);
        carry.tail_start = stream_end - keep;
        buf.zeroize();
        findings
    }

    /// ADMIT-TO-UPLOAD axis — fail-closed, NO off switch (04 §7.1, CON-008).
    /// Flagged spans are replaced in place with `⟨redacted:class:hash⟩`
    /// before any caller persists a byte; the pre-image is wiped from this
    /// buffer, never persisted anywhere. Any internal failure returns
    /// Quarantine — the caller drops the event, never admits it raw (F-35).
    pub fn admit(&self, event_bytes: &mut Vec<u8>) -> AdmitOutcome {
        // catch_unwind is the "panic-caught" leg 04 names: a regex-engine or
        // substitution bug must land in Quarantine, not unwind into a caller
        // that might treat the unwind as "no findings".
        match catch_unwind(AssertUnwindSafe(|| self.admit_inner(event_bytes))) {
            Ok(outcome) => outcome,
            Err(_) => AdmitOutcome::Quarantine,
        }
    }

    fn admit_inner(&self, event_bytes: &mut Vec<u8>) -> AdmitOutcome {
        let findings = self.find_all(event_bytes);
        if findings.is_empty() {
            return AdmitOutcome::Clean;
        }
        let mut out = Vec::with_capacity(event_bytes.len());
        let mut cursor = 0usize;
        for f in &findings {
            out.extend_from_slice(&event_bytes[cursor..f.span.start]);
            out.extend_from_slice(&self.token(f.class, &event_bytes[f.span.clone()]));
            cursor = f.span.end;
        }
        out.extend_from_slice(&event_bytes[cursor..]);
        // The pre-image is wiped in place before the buffer is swapped, so
        // no caller — and no allocator reuse — ever sees it again.
        event_bytes.zeroize();
        *event_bytes = out;
        // Kept spans never overlap and one substitution each: the count is
        // exact, and u32 cannot overflow before the buffer itself would.
        AdmitOutcome::Redacted {
            substitutions: findings.len() as u32,
        }
    }

    /// `⟨redacted:class:hash⟩` — hash = first 8 bytes of HMAC-SHA256(tenant
    /// key, span) as lowercase hex. Truncation keeps tokens short; 64 bits
    /// still make in-tenant correlation collisions negligible.
    fn token(&self, class: SecretClass, span: &[u8]) -> Vec<u8> {
        let mut tag = [0u8; 8];
        // HMAC accepts any key length; new_from_slice on HMAC is total.
        if let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(&self.hmac_key) {
            mac.update(span);
            tag.copy_from_slice(&mac.finalize().into_bytes()[..8]);
        }
        let mut hex = String::with_capacity(16);
        for b in tag {
            // Infallible for u8; write! would demand an unused error path.
            hex.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
            hex.push(char::from_digit(u32::from(b & 0xf), 16).unwrap_or('0'));
        }
        format!("\u{27e8}redacted:{}:{}\u{27e9}", class.label(), hex).into_bytes()
    }
}

/// Shannon entropy in bits per byte over the span — the "randomness test"
/// leg of 04 §7.1's pipeline.
fn shannon_bits_per_byte(span: &[u8]) -> f32 {
    if span.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in span {
        counts[usize::from(b)] += 1;
    }
    let n = span.len() as f32;
    let mut bits = 0.0f32;
    for c in counts {
        if c > 0 {
            let p = c as f32 / n;
            bits -= p * p.log2();
        }
    }
    bits
}

#[cfg(test)]
mod tests;
