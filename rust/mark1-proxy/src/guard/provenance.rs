//! The OAuth non-interception control — 04 §3.1 in full, 04 §9.6 as a machine.
//!
//! CON-001, FR-ENROLL-006, NFR-SECURITY-006.
//!
//! # Why nothing here can be switched off
//!
//! The refusal is structural, not asserted. Two mechanisms carry that:
//!
//! 1. **`ForwardTicket` has private fields and is minted in exactly one place** — the
//!    `Forward`/`NoopForward` arms of [`Guard::decide`]. `upstream::connect` takes one by
//!    reference. No other module in this crate can name, construct or forge one, because
//!    Rust will not let a struct literal with private fields be written outside the defining
//!    module. That is the *no code path forwards an unprovisioned credential* property
//!    (NFR-SECURITY-006) expressed in the type system rather than in a test.
//! 2. **There is no input that changes the answer.** This module reads no environment
//!    variable except the off-marker check that 04 §3.1 step 1 and edge invariant 2 mandate,
//!    no feature flag, no CLI argument and no bundle field other than the forward sampling
//!    rate — which cannot affect whether a request is forwarded, only whether the decision is
//!    recorded. `tools/ci/override_pattern_gate.sh` is the other side of that claim.
//!
//! # The off-marker arm, and where this departs from a literal reading of §9.6
//!
//! §9.6 draws `RECEIVED --> NOOP_FORWARD` straight off `RECEIVED`, ahead of `FP_CHECK`.
//! Taken literally that makes `MARK1_DISABLE=1` an environment variable under which the
//! binary forwards an unprovisioned credential — precisely what §3.1 step 4 and CON-001
//! forbid, and what edge invariant 5 already refuses to allow for the sibling legality
//! control ("the admit-to-upload axis is fail-closed with no off switch").
//!
//! Resolution, and it is a deliberate departure: **the off-check runs first and is recorded
//! first — invariant 2's ordering is preserved and asserted by `unit_guard_state_machine` —
//! but `NOOP_FORWARD` is only reachable for a request that already satisfied steps 2, 3 and
//! 5.** Off disables Mark 1's *involvement* (no tee, no header edits beyond transport, no
//! mutation); it does not disable a control whose failure mode is a legal event. Physically
//! this changes nothing about the documented scenario: §3.1 step 1 says the in-binary check
//! exists only for the race window after `mark1 off` reverted the base-URL fragment, and any
//! request still arriving in that window came from the provisioned fragment and therefore
//! carries a valid `M1-Cred-Ref`.

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use hmac::{Hmac, Mac};
use m1p_wire::pb;
use sha2::Sha256;
use subtle::ConstantTimeEq;

use super::shape::{Classifier, CredShape};
use crate::secret::Secret;

/// Injected by the provisioned agent config fragment (04 §3.1 step 2), stripped before
/// upstream (§3.2).
pub const CRED_REF_HEADER: &str = "m1-cred-ref";

/// D-AJ: the FORWARD arm's rate. Bundle-tunable **upward** only.
pub const DEFAULT_FORWARD_SAMPLE_RATE: f64 = 0.01;

/// D-AJ, binding: the REFUSED arm is never sampled. There is no setter for this and no
/// bundle field that reaches it — the refusal record IS the evidence for the legal claim,
/// and a sampled refusal demonstrates a policy rather than a practice.
pub const REFUSED_SAMPLE_RATE: f64 = 1.0;

/// 04 §3.1 step 6 / D-AI: emitted on the contamination kill path.
pub const REASON_OAUTH_MARKER: &str = "oauth_marker";
/// 04 §3.1 step 3: the only other member of the closed edge-emitted vocabulary.
pub const REASON_UNPROVISIONED: &str = "unprovisioned_cred";

/// Permission to open an upstream connection for one request.
///
/// Fields are private and the type has no public constructor, no `Default` and no
/// `Clone`-from-parts: it exists only as the return value of a successful [`Guard::decide`].
pub struct ForwardTicket {
    cred_ref: String,
    /// The enrollment fingerprint that matched. This is the `credential-identity` leg of the
    /// pool key (04 §3.4) — the pool is keyed by *which* credential without ever holding it.
    cred_identity: [u8; 32],
    /// False on the NOOP_FORWARD arm: forward as transport and observe nothing.
    observe: bool,
}

impl ForwardTicket {
    pub fn cred_ref(&self) -> &str {
        &self.cred_ref
    }

    pub fn cred_identity(&self) -> &[u8; 32] {
        &self.cred_identity
    }

    pub fn observe(&self) -> bool {
        self.observe
    }
}

/// Local diagnostic detail. Deliberately **not** on the wire: `GuardDecision.reason_code` is
/// a closed two-member vocabulary (07 §3), and widening it here to be more helpful would
/// widen a frozen contract to be more helpful.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Cause {
    /// No `M1-Cred-Ref` header (04 §3.1 step 2).
    MissingCredRef,
    /// `M1-Cred-Ref` present but not a value the registry knows.
    UnknownRef,
    /// No credential in `x-api-key` or `Authorization`, two that disagree, or one name
    /// carrying several values (D-BH — see `credential_bytes`).
    CredentialAmbiguous,
    /// HMAC fingerprint did not match enrollment (FR-ENROLL-006: a refusal, never a silent
    /// re-provision).
    FingerprintMismatch,
    /// Step 5 tripwire: an OAuth-shaped credential reached this listener at all. **P0, and
    /// deliberately not conditioned on matching enrollment** — see `decide`. Whether the
    /// provisioning path admitted it or the user's environment steered a subscription
    /// session into an API-key pointer, the observable fact is the same and it is CON-001's.
    OauthShaped,
    /// Step 5: matched no rule. Ambiguity refuses (§3.1 step 3).
    ShapeUnknown,
    /// 04 §3.5 row 1: registry unreadable or HMAC key missing. Fail-closed.
    GuardUnverifiable,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refusal {
    /// `M1E-8001`.
    Unprovisioned(Cause),
    /// `M1E-8002` — this session already tripped the contamination kill path (§3.1 step 6).
    Contaminated,
}

impl Refusal {
    pub fn code(&self) -> &'static str {
        match self {
            Refusal::Unprovisioned(_) => "M1E-8001",
            Refusal::Contaminated => "M1E-8002",
        }
    }

    pub fn reason_code(&self) -> &'static str {
        match self {
            Refusal::Unprovisioned(_) => REASON_UNPROVISIONED,
            Refusal::Contaminated => REASON_OAUTH_MARKER,
        }
    }
}

/// What the registry says about one `cred_ref` right now.
///
/// Three-valued on purpose. The durable kill set (`router::load_killed`) drops a record whose
/// ref is enrolled under a *different* fingerprint, and folding "no line for this ref" together
/// with "the registry could not be read at all" would make 04 §3.5 row 1 — the fail-closed
/// state — the one input that clears every kill on disk. An unreadable registry is the state in
/// which the proxy trusts itself least; it cannot also be the state in which it forgets that a
/// credential proved subscription-backed.
pub enum Enrollment {
    /// Registry readable and this ref is enrolled under this fingerprint.
    Enrolled([u8; 32]),
    /// Registry readable and has no line for this ref: provisioning moved on.
    Absent,
    /// 04 §3.5 row 1 — registry or key unreadable. Says nothing about any ref.
    Unverifiable,
}

/// 04 §9.6's terminal states.
pub enum Decision {
    /// `FORWARDING`.
    Forward(ForwardTicket),
    /// `NOOP_FORWARD` — off-marker present; transport only.
    NoopForward(ForwardTicket),
    /// `REFUSED` — 403.
    Refused(Refusal),
}

impl Decision {
    pub fn ticket(&self) -> Option<&ForwardTicket> {
        match self {
            Decision::Forward(t) | Decision::NoopForward(t) => Some(t),
            Decision::Refused(_) => None,
        }
    }
}

/// What `decide` produced: the decision, and the ledger record if this decision was sampled.
pub struct Outcome {
    pub decision: Decision,
    /// `None` only on a FORWARD arm that sampling declined. A REFUSED arm always carries
    /// one (D-AJ).
    pub record: Option<pb::GuardDecision>,
}

/// D-AJ made executable: the forward rate is clamped into `[DEFAULT, 1.0]` and the refusal
/// rate is a constant with no setter.
#[derive(Clone, Copy, Debug)]
pub struct Sampling {
    forward: f64,
}

impl Default for Sampling {
    fn default() -> Self {
        Sampling {
            forward: DEFAULT_FORWARD_SAMPLE_RATE,
        }
    }
}

impl Sampling {
    /// The bundle's `verify` section may raise the forward rate. A value below the default
    /// is clamped up, not honoured: D-AJ's "may raise / may not lower" is enforced here so
    /// that a decode-time bundle check and this are not two places to get it wrong.
    pub fn from_bundle(rate: f64) -> Self {
        if !rate.is_finite() {
            return Sampling::default();
        }
        Sampling {
            forward: rate.clamp(DEFAULT_FORWARD_SAMPLE_RATE, 1.0),
        }
    }

    pub fn forward_rate(&self) -> f64 {
        self.forward
    }
}

/// Cheap non-cryptographic sampler. Sampling decides only whether an *already-made* decision
/// is recorded, so it is not a security primitive; the refusal arm never consults it.
struct Sampler {
    state: AtomicU64,
}

impl Sampler {
    fn new() -> Self {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E37_79B9_7F4A_7C15);
        Sampler {
            state: AtomicU64::new(seed | 1),
        }
    }

    fn admits(&self, rate: f64) -> bool {
        if rate >= 1.0 {
            return true;
        }
        if rate <= 0.0 {
            return false;
        }
        let mut x = self.state.load(Ordering::Relaxed);
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state.store(x, Ordering::Relaxed);
        ((x >> 11) as f64) / ((1u64 << 53) as f64) < rate
    }
}

/// `ref-id → HMAC-SHA256 fingerprint`, recorded at provisioning (04 §3.1 step 3).
enum Verifier {
    Ready {
        key: Secret<Vec<u8>>,
        registry: HashMap<String, [u8; 32]>,
    },
    /// 04 §3.5 row 1: registry unreadable or HMAC key missing ⇒ fail-closed. The process
    /// still starts and still listens; every request is refused. WHY not refuse to start:
    /// a proxy that exits leaves the agent's provisioned base URL pointing at a closed port,
    /// which is a confusing outage; a proxy that refuses with `M1E-8001` is a legible one.
    Unverifiable,
}

pub struct Guard {
    verifier: Verifier,
    classifier: Classifier,
    sampling: Sampling,
    sampler: Sampler,
}

impl Guard {
    /// Load the device-local guard key and the provisioning registry from `base`
    /// (`~/.omium/mark1/guard/`). Any failure yields a guard that refuses everything.
    ///
    /// The paths are this crate's choice: 04 §3.1 step 3 specifies the registry's *content*
    /// (`ref-id → fingerprint`, recorded at provisioning) and its custody, but no document
    /// pins a filename. `guard.key` mirrors the `redact.key` convention `mark1-hookshim`
    /// already materializes under the same root.
    pub fn load(base: &Path, sampling: Sampling) -> Self {
        let verifier = match load_verifier(base) {
            Some(v) => v,
            None => {
                tracing::error!(
                    target: "mark1_proxy::guard",
                    dir = %base.display(),
                    "guard cannot verify (04 §3.5): refusing every request until the registry \
                     and key are readable"
                );
                Verifier::Unverifiable
            }
        };
        Guard {
            verifier,
            classifier: Classifier::new(),
            sampling,
            sampler: Sampler::new(),
        }
    }

    /// In-memory constructor for tests and for gateway-mode fleet policy, which delivers the
    /// registry over the wire rather than from disk.
    pub fn from_parts(
        key: Vec<u8>,
        registry: HashMap<String, [u8; 32]>,
        sampling: Sampling,
    ) -> Self {
        Guard {
            verifier: Verifier::Ready {
                key: Secret::new(key),
                registry,
            },
            classifier: Classifier::new(),
            sampling,
            sampler: Sampler::new(),
        }
    }

    pub fn unverifiable(sampling: Sampling) -> Self {
        Guard {
            verifier: Verifier::Unverifiable,
            classifier: Classifier::new(),
            sampling,
            sampler: Sampler::new(),
        }
    }

    pub fn sampling(&self) -> Sampling {
        self.sampling
    }

    /// The enrollment fingerprint of `cred` under the device-local guard key. Public so the
    /// provisioning-side tooling and the tests compute it exactly one way.
    pub fn fingerprint(&self, cred: &[u8]) -> Option<[u8; 32]> {
        let Verifier::Ready { key, .. } = &self.verifier else {
            return None;
        };
        fingerprint_under(key.expose_for_upstream(), cred)
    }

    /// What the registry currently enrolls for `cred_ref` (04 §3.1 step 3).
    ///
    /// Read-only and widens nothing: the fingerprint is already a public output of
    /// [`Guard::fingerprint`], i.e. a value any caller holding the credential can compute
    /// itself. Nothing here admits a request — `decide` is still the only route to a
    /// `ForwardTicket`.
    pub fn enrollment(&self, cred_ref: &str) -> Enrollment {
        let Verifier::Ready { registry, .. } = &self.verifier else {
            return Enrollment::Unverifiable;
        };
        match registry.get(cred_ref) {
            Some(fp) => Enrollment::Enrolled(*fp),
            None => Enrollment::Absent,
        }
    }

    /// 04 §3.1 steps 1-5, in order, before a single byte goes upstream.
    ///
    /// `off` is the caller's already-evaluated off-marker state (step 1 / invariant 2: read
    /// before any other guard state is touched, which is why it is a parameter rather than a
    /// call made partway down this function).
    pub fn decide(&self, headers: &http::HeaderMap, off: bool) -> Outcome {
        // Step 1 is the caller's `off`, threaded in above.

        // 04 §3.5 row 1. Checked before the header reads so an unverifiable guard cannot be
        // probed for which of its inputs is missing.
        let Verifier::Ready { key, registry } = &self.verifier else {
            return self.refuse(Cause::GuardUnverifiable, None);
        };

        // Step 2: M1-Cred-Ref presence.
        let Some(cred_ref) = headers.get(CRED_REF_HEADER).and_then(|v| v.to_str().ok()) else {
            return self.refuse(Cause::MissingCredRef, None);
        };
        let Some(enrolled) = registry.get(cred_ref) else {
            return self.refuse(Cause::UnknownRef, None);
        };

        let Some(cred) = credential_bytes(headers) else {
            return self.refuse(Cause::CredentialAmbiguous, None);
        };

        // The shape tripwire runs BEFORE the fingerprint compare, and the order is the
        // control, not a preference (D-CQ).
        //
        // Fingerprint-first answers "is this the credential we enrolled?" and returns
        // FingerprintMismatch the moment it is not — so the arrival of a SUBSCRIPTION
        // bearer at this listener, which is CON-001's event, exited one step early and was
        // reported as an ordinary wrong-key 403. The tripwire only ever saw credentials
        // that had already MATCHED enrollment, i.e. only the case where our own
        // provisioning was buggy. The case where the user's environment delivers an OAuth
        // session into a proxy pointer meant for their API key — the one that actually
        // happens, because the pointer is machine-wide and the regime sniff is per-shell —
        // was structurally outside the tripwire's reach.
        //
        // And fingerprint-first computes a keyed HMAC over the OAuth bearer to find that
        // out. Classify first: we take no function of a subscription credential, not even a
        // one-way one. Ambiguity refuses here too — an unclassifiable credential is not
        // something to hash and then think about.
        //
        // Strictly a narrowing: shape is now a precondition of reaching the compare, so
        // this can only add refusals, never admit anything the old order refused.
        match self.classifier.classify(cred) {
            CredShape::ApiKey => {}
            CredShape::Oauth => {
                tracing::error!(
                    target: "mark1_proxy::guard",
                    severity = "P0",
                    cred_ref,
                    "OAUTH-SHAPED CREDENTIAL AT THE PROXY — CON-001: subscription traffic \
                     reached this listener. Refused before any function was computed over \
                     it (04 §3.1 step 5)"
                );
                // No fingerprint: producing one would mean HMAC-ing the bearer we just
                // refused to touch.
                return self.refuse(Cause::OauthShaped, None);
            }
            CredShape::Unknown => return self.refuse(Cause::ShapeUnknown, None),
        }

        // Step 3: HMAC fingerprint match to enrollment, constant-time.
        let Some(actual) = fingerprint_under(key.expose_for_upstream(), cred) else {
            return self.refuse(Cause::GuardUnverifiable, None);
        };
        if !bool::from(actual.ct_eq(enrolled)) {
            return self.refuse(Cause::FingerprintMismatch, Some(actual));
        }

        // Step 4 is structural — see the module header. There is nothing to evaluate.

        let ticket = ForwardTicket {
            cred_ref: cred_ref.to_owned(),
            cred_identity: actual,
            observe: !off,
        };
        let record = self
            .sampler
            .admits(self.sampling.forward)
            .then(|| pb::GuardDecision {
                outcome: pb::GuardOutcome::Forwarded as i32,
                cred_fingerprint: actual.to_vec(),
                sample_rate: self.sampling.forward,
                reason_code: String::new(),
            });
        let decision = if off {
            Decision::NoopForward(ticket)
        } else {
            Decision::Forward(ticket)
        };
        Outcome { decision, record }
    }

    /// The REFUSED arm. Always records, always at `sample_rate = 1.0` (D-AJ). There is no
    /// parameter, field or branch by which this becomes conditional.
    fn refuse(&self, cause: Cause, fingerprint: Option<[u8; 32]>) -> Outcome {
        let refusal = Refusal::Unprovisioned(cause);
        tracing::warn!(target: "mark1_proxy::guard", code = refusal.code(), ?cause, "refused");
        Outcome {
            decision: Decision::Refused(refusal),
            record: Some(refused_record(refusal, fingerprint)),
        }
    }
}

/// Constructed here rather than at each call site so `sample_rate` has exactly one source.
pub fn refused_record(refusal: Refusal, fingerprint: Option<[u8; 32]>) -> pb::GuardDecision {
    pb::GuardDecision {
        outcome: pb::GuardOutcome::Refused as i32,
        cred_fingerprint: fingerprint.map(|f| f.to_vec()).unwrap_or_default(),
        sample_rate: REFUSED_SAMPLE_RATE,
        reason_code: refusal.reason_code().to_owned(),
    }
}

/// `None` is unreachable for `Hmac<Sha256>`, which accepts a key of any length — but it is
/// returned rather than substituted, because the alternative is fingerprinting under a key
/// the caller did not choose, and every such value would be a silent non-match that reads
/// like an attack.
fn fingerprint_under(key: &[u8], cred: &[u8]) -> Option<[u8; 32]> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).ok()?;
    mac.update(cred);
    Some(mac.finalize().into_bytes().into())
}

/// The credential as it sits in the client's headers. **Borrowed, never copied**: this
/// process does not own a customer credential in sidecar mode, so there is nothing for it to
/// log, cache, transform or leak. `Authorization` is read only if `x-api-key` is absent, and
/// two disagreeing credentials are an ambiguity, which refuses (04 §3.1 step 3).
///
/// A REPEATED credential header is the same ambiguity and refuses identically. `HeaderMap`
/// permits several values under one name and `HeaderMap::get` returns only the first, so
/// reading a single value cannot decide what the upstream will receive — `request::sanitize`
/// does not de-duplicate and hyper writes every value as its own header line. Without this
/// check a client sends `x-api-key: <enrolled key>` followed by
/// `x-api-key: sk-ant-oat01-<subscription token>`, the guard fingerprints and shape-classifies
/// value #1, mints a `ForwardTicket`, and the proxy carries the OAuth credential upstream
/// anyway. The structural claim would be defeated by a header the guard never looked at.
/// Refusing is right rather than merely safe: no legitimate client sends two, and picking one
/// would mean the value we verified is not the value we forward. See D-BH.
fn credential_bytes(headers: &http::HeaderMap) -> Option<&[u8]> {
    for name in [
        http::HeaderName::from_static("x-api-key"),
        http::header::AUTHORIZATION,
    ] {
        if headers.get_all(&name).iter().nth(1).is_some() {
            return None;
        }
    }
    let api_key = headers.get("x-api-key").map(|v| v.as_bytes());
    let bearer = headers
        .get(http::header::AUTHORIZATION)
        .map(|v| v.as_bytes())
        .map(|v| v.strip_prefix(b"Bearer ").unwrap_or(v));
    match (api_key, bearer) {
        (Some(a), Some(b)) if a != b => None,
        (Some(a), _) => Some(a).filter(|s| !s.is_empty()),
        (None, Some(b)) => Some(b).filter(|s| !s.is_empty()),
        (None, None) => None,
    }
}

/// 64 hex chars → the 32-byte fingerprint. Shared by the `registry` reader here and the
/// `guard-killed` reader in `router`, so the two files cannot drift into disagreeing about
/// what a fingerprint looks like — the kill set's re-arm rule compares one against the other
/// and a length or case difference would silently make every comparison a mismatch.
pub(crate) fn parse_fingerprint_hex(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// The inverse, for the `guard-killed` writer. Lowercase, matching what `mark1d` writes into
/// `registry` (`adapters/claudecode/baseurl.go`, `hex.EncodeToString`).
pub(crate) fn fingerprint_hex(fp: &[u8; 32]) -> String {
    use std::fmt::Write;
    fp.iter().fold(String::with_capacity(64), |mut s, b| {
        // `write!` to a String cannot fail; the result is discarded rather than unwrapped
        // because a panic on the P0 kill path would be worse than a short line.
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn load_verifier(base: &Path) -> Option<Verifier> {
    let key = std::fs::read(base.join("guard.key")).ok()?;
    if key.is_empty() {
        return None;
    }
    let raw = std::fs::read_to_string(base.join("registry")).ok()?;
    let mut registry = HashMap::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (r, fp) = line.split_once(' ')?;
        registry.insert(r.to_owned(), parse_fingerprint_hex(fp)?);
    }
    Some(Verifier::Ready {
        key: Secret::new(key),
        registry,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"device-local-guard-key";
    const API_KEY: &[u8] = b"sk-ant-api03-AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz01";
    const OAUTH: &[u8] = b"sk-ant-oat01-AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz01";
    const OAUTH_BEARER: &[u8] =
        b"Bearer sk-ant-oat01-AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz01";

    fn guard_with(cred: &[u8]) -> Guard {
        guard_with_sampling(cred, Sampling::default())
    }

    fn guard_with_sampling(cred: &[u8], sampling: Sampling) -> Guard {
        let mut registry = HashMap::new();
        registry.insert("ref-1".to_owned(), fingerprint_under(KEY, cred).unwrap());
        Guard::from_parts(KEY.to_vec(), registry, sampling)
    }

    fn headers(pairs: &[(&str, &[u8])]) -> http::HeaderMap {
        let mut h = http::HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                http::HeaderValue::from_bytes(v).unwrap(),
            );
        }
        h
    }

    fn provisioned() -> http::HeaderMap {
        headers(&[(CRED_REF_HEADER, b"ref-1"), ("x-api-key", API_KEY)])
    }

    /// 12 §2.7 `unit_guard_state_machine`: every terminal state of 04 §9.6 is reachable, and
    /// no `FP_CHECK`-fail reaches `FORWARDING`.
    #[test]
    fn unit_guard_state_machine() {
        let g = guard_with(API_KEY);

        // RECEIVED -> FP_CHECK -> TRIPWIRE -> FORWARDING
        assert!(matches!(
            g.decide(&provisioned(), false).decision,
            Decision::Forward(_)
        ));

        // ... -> NOOP_FORWARD (off-marker present)
        let noop = g.decide(&provisioned(), true).decision;
        let Decision::NoopForward(t) = &noop else {
            panic!("expected NOOP_FORWARD")
        };
        assert!(!t.observe(), "NOOP_FORWARD must not observe");

        // RECEIVED -> REFUSED (no M1-Cred-Ref)
        assert_refused(
            &g,
            &headers(&[("x-api-key", API_KEY)]),
            Cause::MissingCredRef,
            false,
        );
        // FP_CHECK -> REFUSED (unknown ref)
        assert_refused(
            &g,
            &headers(&[(CRED_REF_HEADER, b"ref-nope"), ("x-api-key", API_KEY)]),
            Cause::UnknownRef,
            false,
        );
        // FP_CHECK -> REFUSED (HMAC mismatch) — and it stays refused with the off-marker set.
        let wrong = headers(&[
            (CRED_REF_HEADER, b"ref-1"),
            ("x-api-key", b"sk-ant-api03-other"),
        ]);
        assert_refused(&g, &wrong, Cause::FingerprintMismatch, false);
        assert_refused(&g, &wrong, Cause::FingerprintMismatch, true);
        // TRIPWIRE -> REFUSED (credential classifies OAuth despite matching enrollment)
        let g_oauth = guard_with(OAUTH);
        assert_refused(
            &g_oauth,
            &headers(&[(CRED_REF_HEADER, b"ref-1"), ("authorization", OAUTH_BEARER)]),
            Cause::OauthShaped,
            false,
        );
        // The case the OLD ordering could not see, and the one that actually happens: an
        // OAuth session arrives at a listener enrolled for this machine's API KEY. The
        // fingerprint cannot match, so a fingerprint-first guard exits at
        // FingerprintMismatch — CON-001's event reported as an ordinary wrong-key 403,
        // after HMAC-ing the subscription bearer to work that out. It must trip the
        // tripwire (D-CQ). Reordering the two checks back is what turns this red.
        assert_refused(
            &g,
            &headers(&[(CRED_REF_HEADER, b"ref-1"), ("authorization", OAUTH_BEARER)]),
            Cause::OauthShaped,
            false,
        );
    }

    fn assert_refused(g: &Guard, h: &http::HeaderMap, want: Cause, off: bool) {
        let out = g.decide(h, off);
        match out.decision {
            Decision::Refused(Refusal::Unprovisioned(got)) => assert_eq!(got, want),
            _ => panic!("expected REFUSED({want:?})"),
        }
        // D-AJ on every refusal, not just the convenient one.
        let rec = out.record.expect("refusals are never sampled away");
        assert_eq!(rec.sample_rate, 1.0);
        assert_eq!(rec.outcome, pb::GuardOutcome::Refused as i32);
        assert_eq!(rec.reason_code, REASON_UNPROVISIONED);
    }

    /// 04 §3.5 row 1.
    #[test]
    fn unverifiable_guard_refuses_everything() {
        let g = Guard::unverifiable(Sampling::default());
        assert_refused(&g, &provisioned(), Cause::GuardUnverifiable, false);
        assert_refused(&g, &provisioned(), Cause::GuardUnverifiable, true);
    }

    /// D-BH. `headers()` above builds with `insert`, which replaces — so no other test in
    /// this file can reach the repeated-header path at all, and the refusal it asserts was
    /// unexercised code until this test existed. `HeaderMap::get` returns the FIRST of
    /// several values under one name while hyper writes every one of them upstream, so a
    /// guard that reads one value cannot speak for what the upstream receives.
    #[test]
    fn d_bh_repeated_credential_header_refuses() {
        let g = guard_with(API_KEY);
        let api = http::HeaderName::from_static("x-api-key");

        // The attack: value #1 is the enrolled key, so without this check the guard
        // fingerprints and shape-classifies #1, mints a ticket, and forwards the OAuth
        // token it never looked at.
        let mut smuggled = provisioned();
        smuggled.append(&api, http::HeaderValue::from_bytes(OAUTH).unwrap());
        assert_refused(&g, &smuggled, Cause::CredentialAmbiguous, false);

        // Repeating the SAME value refuses too: the check is on arity, not on disagreement.
        // "They matched" is a property of the two we compared, not of the N sent.
        let mut twice = provisioned();
        twice.append(&api, http::HeaderValue::from_bytes(API_KEY).unwrap());
        assert_refused(&g, &twice, Cause::CredentialAmbiguous, false);

        // The `Authorization` arm is its own reachable path — it is read only when
        // `x-api-key` is absent, so a check on the first name alone would leave it open.
        let mut auth = headers(&[(CRED_REF_HEADER, b"ref-1")]);
        for _ in 0..2 {
            auth.append(
                http::header::AUTHORIZATION,
                http::HeaderValue::from_bytes(OAUTH_BEARER).unwrap(),
            );
        }
        assert_refused(&g, &auth, Cause::CredentialAmbiguous, false);
    }

    /// D-AJ: the bundle may raise the forward rate and may not lower it, and no input path
    /// reaches the refusal rate at all.
    #[test]
    fn d_aj_sample_rates() {
        assert_eq!(
            Sampling::from_bundle(0.0).forward_rate(),
            DEFAULT_FORWARD_SAMPLE_RATE
        );
        assert_eq!(
            Sampling::from_bundle(-5.0).forward_rate(),
            DEFAULT_FORWARD_SAMPLE_RATE
        );
        assert_eq!(
            Sampling::from_bundle(f64::NAN).forward_rate(),
            DEFAULT_FORWARD_SAMPLE_RATE
        );
        assert_eq!(Sampling::from_bundle(0.5).forward_rate(), 0.5);
        assert_eq!(Sampling::from_bundle(9.0).forward_rate(), 1.0);
        assert_eq!(REFUSED_SAMPLE_RATE, 1.0);

        // Every refusal record, at every bundle setting, is 1.0.
        for rate in [0.0, 0.01, 0.5, 1.0] {
            let g = Guard::from_parts(KEY.to_vec(), HashMap::new(), Sampling::from_bundle(rate));
            let out = g.decide(&provisioned(), false);
            assert_eq!(out.record.map(|r| r.sample_rate), Some(1.0));
        }
    }

    #[test]
    fn forward_arm_is_sampled_at_the_configured_rate() {
        let g = guard_with(API_KEY);
        let sampled = (0..20_000)
            .filter(|_| g.decide(&provisioned(), false).record.is_some())
            .count();
        // 1% of 20k = 200; a wide band, because the point is "sampled, not always and not
        // never", not the quality of an xorshift.
        assert!(
            (50..600).contains(&sampled),
            "sampled {sampled}/20000 at rate 0.01"
        );
    }

    #[test]
    fn disagreeing_credentials_are_an_ambiguity_not_a_preference() {
        let g = guard_with(API_KEY);
        let mut h = provisioned();
        h.insert(
            "authorization",
            http::HeaderValue::from_static("Bearer sk-ant-api03-different"),
        );
        assert_refused(&g, &h, Cause::CredentialAmbiguous, false);
    }

    #[test]
    fn registry_round_trips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("guard.key"), KEY).unwrap();
        let fp = fingerprint_under(KEY, API_KEY).unwrap();
        let hex: String = fp.iter().map(|b| format!("{b:02x}")).collect();
        std::fs::write(
            dir.path().join("registry"),
            format!("# provisioned\nref-1 {hex}\n"),
        )
        .unwrap();
        let g = Guard::load(dir.path(), Sampling::default());
        assert!(matches!(
            g.decide(&provisioned(), false).decision,
            Decision::Forward(_)
        ));
        assert_eq!(g.fingerprint(API_KEY), Some(fp));
    }

    #[test]
    fn a_truncated_registry_line_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("guard.key"), KEY).unwrap();
        std::fs::write(dir.path().join("registry"), "ref-1 deadbeef\n").unwrap();
        let g = Guard::load(dir.path(), Sampling::default());
        assert_refused(&g, &provisioned(), Cause::GuardUnverifiable, false);
    }

    /// 12 §9 row 1 `neg_no_classifier_override_in_binary` — CON-001's "no override path may
    /// exist" checked against the compiled decision function rather than against the text
    /// that produced it.
    ///
    /// What it proves: no construction path, no parameter and no environment input turns an
    /// OAuth-shaped credential into a forward. Every way this binary can build a `Guard`
    /// (`load`, `from_parts`, `unverifiable`), crossed with every `Sampling` it accepts and
    /// both values of `off`, refuses — and refuses before taking any function of the
    /// credential (D-CQ: the emitted record carries no fingerprint of a subscription token).
    ///
    /// `off` is the arm that earns the sweep. `mark1 off` / `MARK1_DISABLE=1` is the nearest
    /// thing this system has to an operator switch, and `router.rs`'s claim that it narrows
    /// what the proxy does rather than widening what it will carry was a comment until here.
    /// A `Sampling` of 0.0 is the other: sampling suppresses *records*, and a guard that let
    /// it suppress the decision would drop the refusal on the floor at the exact rate an
    /// operator chose.
    ///
    /// What it does NOT prove: that the artifact a customer runs was built from this source.
    /// That is a property of the build, not of a test running inside it.
    /// `tools/ci/override_pattern_gate.sh` (13 §7.5) is the other half of the two-sided
    /// claim — the gate refuses the source patterns that would build a different binary,
    /// this test proves the binary that exists refuses.
    ///
    /// Environment is enumerable and enumerated: the crate reads exactly `HOME` /
    /// `USERPROFILE` (`lib.rs:170` — where to look for state), `XDG_RUNTIME_DIR`
    /// (`fabric.rs:210` — which socket to dial) and `MARK1_DISABLE` (`lib.rs:181`). The
    /// first three select paths and cannot name a credential; the last reaches a decision
    /// only as the `off` argument, which is swept below. There is no fourth.
    #[test]
    fn neg_no_classifier_override_in_binary() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("guard.key"), KEY).unwrap();
        let hex: String = fingerprint_under(KEY, API_KEY)
            .unwrap()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        std::fs::write(dir.path().join("registry"), format!("ref-1 {hex}\n")).unwrap();

        // Every `Sampling` reachable: the default, both clamp extremes, and the two inputs
        // `from_bundle` special-cases. A bundle cannot ask for 0.0 (D-AJ clamps up), so it
        // is constructed here to prove the clamp is not what is holding the property.
        let samplings = [
            Sampling::default(),
            Sampling::from_bundle(0.0),
            Sampling::from_bundle(1.0),
            Sampling::from_bundle(-1.0),
            Sampling::from_bundle(f64::NAN),
            Sampling { forward: 0.0 },
        ];

        // Both header names the guard will read a credential from. `x-api-key` holding an
        // OAuth token is the contamination this crate exists to stop; `authorization` is the
        // shape the vendor's own subscription client sends.
        let presentations = [
            (
                "oauth in x-api-key",
                headers(&[(CRED_REF_HEADER, b"ref-1"), ("x-api-key", OAUTH)]),
            ),
            (
                "oauth in authorization",
                headers(&[(CRED_REF_HEADER, b"ref-1"), ("authorization", OAUTH_BEARER)]),
            ),
        ];

        let mut checked = 0;
        for sampling in samplings {
            // `guard_with(OAUTH)` is the adversarial enrollment: a registry that vouches for
            // the OAuth token itself, so the fingerprint check PASSES and only the shape
            // tripwire stands between it and the upstream.
            let paths: [(&str, Guard, Cause); 4] = [
                (
                    "from_parts, the oauth token itself enrolled",
                    guard_with_sampling(OAUTH, sampling),
                    Cause::OauthShaped,
                ),
                (
                    "from_parts, api key enrolled",
                    guard_with_sampling(API_KEY, sampling),
                    Cause::OauthShaped,
                ),
                (
                    "load from disk",
                    Guard::load(dir.path(), sampling),
                    Cause::OauthShaped,
                ),
                (
                    "unverifiable",
                    Guard::unverifiable(sampling),
                    Cause::GuardUnverifiable,
                ),
            ];
            for (how, g, want) in paths {
                for off in [false, true] {
                    for (shape, h) in &presentations {
                        let case = format!("{how} / off={off} / {shape} / {sampling:?}");
                        let out = g.decide(h, off);
                        let Decision::Refused(Refusal::Unprovisioned(cause)) = out.decision else {
                            panic!("{case}: an OAuth-shaped credential was not refused");
                        };
                        assert_eq!(cause, want, "{case}");
                        // D-AJ: a refusal is never sampled away, at any rate including 0.0.
                        let rec = out.record.unwrap_or_else(|| panic!("{case}: no record"));
                        assert_eq!(rec.sample_rate, REFUSED_SAMPLE_RATE, "{case}");
                        // D-CQ: shape precedes fingerprinting, so nothing derived from a
                        // subscription credential leaves this process — not even a hash.
                        assert!(rec.cred_fingerprint.is_empty(), "{case}: fingerprinted");
                        checked += 1;
                    }
                }
            }
        }
        // The sweep is the assertion; a refactor that silently drops an arm from any of the
        // four loops would otherwise leave this test passing on less than it claims.
        assert_eq!(checked, 6 * 4 * 2 * 2, "the override sweep lost coverage");
    }
}
