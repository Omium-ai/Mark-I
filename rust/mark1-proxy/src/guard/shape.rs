//! Step 5 of 04 §3.1 — the credential shape-inspection tripwire.
//!
//! A **secondary** signal. The provenance guard (step 3) is what makes subscription
//! non-interception structural; this classifier catches the case where a credential passed
//! the fingerprint check and is nevertheless OAuth-shaped, which means the provisioning path
//! has a bug (04 §3.1 step 5: refuse + P1).
//!
//! Two properties are deliberate:
//!
//!   * **`Unknown` refuses.** "Any parse ambiguity ⇒ 403" (§3.1 step 3). A classifier that
//!     defaults to "probably an API key" ages silently into an OAuth forwarder; one that
//!     defaults to refusal ages into a support ticket. Only one of those is a legal event.
//!   * **The rule table is data with names**, so `canary_oauth_shape_classifier` (12 §3.3)
//!     can point at a specific rule, and so `with_rule_disabled` can plant a miss and prove
//!     the canary harness detects it. That seam is `#[cfg(test)]` and does not exist in a
//!     release build — nothing in this file reads an environment variable, a feature, or a
//!     flag.

/// What the credential's grammar says it is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CredShape {
    ApiKey,
    Oauth,
    /// Matched no rule. Treated as a refusal by the caller.
    Unknown,
}

pub struct Rule {
    /// Stable identifier used by the canary corpus and by `with_rule_disabled`.
    pub name: &'static str,
    pub shape: CredShape,
    matches: fn(&[u8]) -> bool,
}

/// Ordered. OAuth rules come first because every Anthropic OAuth artifact shares the
/// `sk-ant-` stem with the API key, so a prefix rule for the key would swallow them.
pub const RULES: &[Rule] = &[
    Rule {
        name: "anthropic_oauth_access",
        shape: CredShape::Oauth,
        matches: |c| c.starts_with(b"sk-ant-oat"),
    },
    Rule {
        name: "anthropic_oauth_refresh",
        shape: CredShape::Oauth,
        matches: |c| c.starts_with(b"sk-ant-ort"),
    },
    Rule {
        name: "anthropic_oauth_session",
        shape: CredShape::Oauth,
        matches: |c| c.starts_with(b"sk-ant-sid"),
    },
    Rule {
        name: "jwt_bearer",
        shape: CredShape::Oauth,
        matches: is_jwt,
    },
    Rule {
        name: "anthropic_api_key",
        shape: CredShape::ApiKey,
        matches: |c| is_anthropic_api_key(c),
    },
    // No separate `sk-proj-` rule: `openai_api_key` below already matches it, to the same
    // `ApiKey` verdict. It was here, `canary_selftest_detects_planted_miss` proved disabling
    // it changed no classification, and a rule whose removal changes nothing is a rule that
    // ages into a false sense of coverage.
    Rule {
        name: "google_api_key",
        shape: CredShape::ApiKey,
        matches: |c| c.starts_with(b"AIza") && c.len() >= 35 && is_key_alphabet(&c[4..]),
    },
    Rule {
        name: "openai_api_key",
        shape: CredShape::ApiKey,
        matches: |c| {
            c.starts_with(b"sk-")
                && !c.starts_with(b"sk-ant-")
                && c.len() >= 40
                && is_key_alphabet(&c[3..])
        },
    },
];

/// `sk-ant-api<NN>-<body>` — the version digits are matched as digits, not as the literal
/// "03", so an `api04` key classifies correctly on the day it ships instead of falling to
/// `Unknown` and refusing every request.
fn is_anthropic_api_key(c: &[u8]) -> bool {
    let Some(rest) = c.strip_prefix(b"sk-ant-api") else {
        return false;
    };
    rest.len() > 3
        && rest[0].is_ascii_digit()
        && rest[1].is_ascii_digit()
        && rest[2] == b'-'
        && is_key_alphabet(&rest[3..])
}

/// Three base64url segments, header first. Covers every OAuth access token that is a JWT,
/// which is the shape a non-Anthropic subscription regime is most likely to arrive in.
fn is_jwt(c: &[u8]) -> bool {
    if !c.starts_with(b"eyJ") {
        return false;
    }
    let mut segs = c.split(|b| *b == b'.');
    let (Some(a), Some(b), Some(d), None) = (segs.next(), segs.next(), segs.next(), segs.next())
    else {
        return false;
    };
    !a.is_empty() && !b.is_empty() && !d.is_empty() && [a, b, d].iter().all(|s| is_key_alphabet(s))
}

fn is_key_alphabet(s: &[u8]) -> bool {
    !s.is_empty()
        && s.iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
}

pub struct Classifier {
    /// `None` in every build that is not a test binary. Present so 12 §3.3's
    /// `canary_selftest_detects_planted_miss` can prove the canary harness can fail.
    #[cfg(test)]
    disabled_rule: Option<&'static str>,
}

impl Default for Classifier {
    fn default() -> Self {
        Self::new()
    }
}

impl Classifier {
    pub const fn new() -> Self {
        Classifier {
            #[cfg(test)]
            disabled_rule: None,
        }
    }

    /// Test-only seam (12 §3.3). Not reachable from a release build: the field it sets does
    /// not exist there.
    #[cfg(test)]
    pub fn with_rule_disabled(name: &'static str) -> Self {
        assert!(RULES.iter().any(|r| r.name == name), "no such rule: {name}");
        Classifier {
            disabled_rule: Some(name),
        }
    }

    #[cfg(test)]
    fn is_live(&self, rule: &Rule) -> bool {
        self.disabled_rule != Some(rule.name)
    }

    #[cfg(not(test))]
    fn is_live(&self, _rule: &Rule) -> bool {
        true
    }

    /// `cred` is the raw credential bytes with any `Bearer ` scheme already stripped.
    pub fn classify(&self, cred: &[u8]) -> CredShape {
        for rule in RULES {
            if self.is_live(rule) && (rule.matches)(cred) {
                return rule.shape;
            }
        }
        CredShape::Unknown
    }
}

/// One corpus entry: a credential *shape* and what it must classify as. Never a live value —
/// 12 §3.3 records shapes (prefix, length, alphabet, structural markers) for exactly this
/// reason.
pub struct CanaryCase {
    pub label: &'static str,
    pub sample: &'static [u8],
    pub expect: CredShape,
}

/// The in-crate half of `conformance/canary/oauth/`. The recorded-shape corpus and the
/// weekly refresh lane live there; this table is what makes the PR-time lane meaningful on
/// a checkout that has not fetched fixtures, and it is what the meta-test plants a miss in.
/// Compile-time, not in the test: an empty corpus makes `canary_oauth_shape_classifier` pass
/// by iterating nothing, and this crate has to fail loudly rather than quietly for that.
const _: () = assert!(!CANARY_CORPUS.is_empty(), "empty canary corpus");

pub const CANARY_CORPUS: &[CanaryCase] = &[
    CanaryCase {
        label: "anthropic api key (api03)",
        sample: b"sk-ant-api03-AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz01",
        expect: CredShape::ApiKey,
    },
    CanaryCase {
        label: "anthropic api key (future api04)",
        sample: b"sk-ant-api04-AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz01",
        expect: CredShape::ApiKey,
    },
    CanaryCase {
        label: "anthropic oauth access token",
        sample: b"sk-ant-oat01-AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz01",
        expect: CredShape::Oauth,
    },
    CanaryCase {
        label: "anthropic oauth refresh token",
        sample: b"sk-ant-ort01-AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz01",
        expect: CredShape::Oauth,
    },
    CanaryCase {
        label: "anthropic session token",
        sample: b"sk-ant-sid01-AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz01",
        expect: CredShape::Oauth,
    },
    CanaryCase {
        label: "jwt access token",
        sample: b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        expect: CredShape::Oauth,
    },
    CanaryCase {
        label: "openai project key",
        sample: b"sk-proj-AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123",
        expect: CredShape::ApiKey,
    },
    CanaryCase {
        label: "openai classic key",
        sample: b"sk-AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz012345",
        expect: CredShape::ApiKey,
    },
    CanaryCase {
        label: "google api key",
        sample: b"AIzaSyAaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQ",
        expect: CredShape::ApiKey,
    },
    // Near-misses: one character moved toward the other grammar (12 §3.3 corpus (b)).
    CanaryCase {
        label: "near-miss: oauth prefix truncated to an unknown stem",
        sample: b"sk-ant-oa01-AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz",
        expect: CredShape::Unknown,
    },
    CanaryCase {
        label: "near-miss: api key with a non-digit version",
        sample: b"sk-ant-apiX3-AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz",
        expect: CredShape::Unknown,
    },
    CanaryCase {
        label: "near-miss: jwt with two segments",
        sample: b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0",
        expect: CredShape::Unknown,
    },
    CanaryCase { label: "empty", sample: b"", expect: CredShape::Unknown },
];

/// Run the corpus against a classifier. Returns the labels that classified wrong.
///
/// Separated from the `#[test]` so the meta-test can call it against a lobotomized
/// classifier and assert that it *reports* the miss — a canary that cannot fail is
/// decoration (12 §3.3).
pub fn run_canary(c: &Classifier) -> Vec<&'static str> {
    CANARY_CORPUS
        .iter()
        .filter(|case| c.classify(case.sample) != case.expect)
        .map(|case| case.label)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 12 §3.3 `canary_oauth_shape_classifier`, PR-time lane.
    #[test]
    fn canary_oauth_shape_classifier() {
        // Non-empty is asserted at compile time above, so this cannot pass by running nothing.
        let misses = run_canary(&Classifier::new());
        assert!(misses.is_empty(), "classifier misses: {misses:?}");
    }

    /// 12 §3.3 `canary_selftest_detects_planted_miss` — the meta-test. Disabling any single
    /// rule must make the harness report at least one miss; a rule whose removal changes
    /// nothing is a rule the corpus does not exercise.
    #[test]
    fn canary_selftest_detects_planted_miss() {
        for rule in RULES {
            let misses = run_canary(&Classifier::with_rule_disabled(rule.name));
            assert!(
                !misses.is_empty(),
                "disabling rule {} produced no miss — the corpus does not cover it",
                rule.name
            );
        }
    }

    #[test]
    fn unknown_is_the_default_not_apikey() {
        assert_eq!(Classifier::new().classify(b"hunter2"), CredShape::Unknown);
        assert_eq!(Classifier::new().classify(b"Bearer"), CredShape::Unknown);
    }

    #[test]
    fn rule_names_are_unique() {
        let mut names: Vec<_> = RULES.iter().map(|r| r.name).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(
            names.len(),
            before,
            "duplicate rule name makes with_rule_disabled ambiguous"
        );
    }
}
