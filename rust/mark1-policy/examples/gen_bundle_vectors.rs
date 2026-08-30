//! Deterministic generator for `conformance/vectors/bundle/` — see that
//! directory's README.md. House rule (12 §3.4, .gitleaks.toml): the vectors
//! are generated ONCE by the Rust reference implementation; the committed
//! files are the frozen contract, and if regeneration ever changes a byte
//! that is a finding against THIS file, never a license to re-freeze.
//!
//! Run: `cargo run -p mark1-policy --example gen_bundle_vectors`
//!
//! Every emitted vector is driven through `verify_and_decode` before being
//! written: an accept vector that rejects, or a negative rejecting with the
//! wrong code/kind, aborts generation — the generator cannot freeze a vector
//! the reference implementation disagrees with.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, bail, ensure, Context, Result};
use ciborium::value::Value;
use mark1_policy::{
    body_sha256, encode_canonical, section_signing_input, verify_and_decode, Bundle, Section,
    SectionKeys, SigInput, TlogHead, GENESIS_PREV_HASH, MAX_BUNDLE_LEN,
};
use mark1_receipt::{hex, Ed25519Signer, Signer};
use serde_json::json;
use sha2::{Digest, Sha256};

/// TEST-ONLY published seeds (receipt-family style: fixed repeated bytes,
/// spelled out in README.md) — one per section class, ASCII '1'..'6' in
/// `Section::ALL` order.
const SEED_BYTES: [u8; 6] = [b'1', b'2', b'3', b'4', b'5', b'6'];

const TENANT_ID: [u8; 16] = [
    0x01, 0x92, 0xaa, 0x7e, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];
/// 2026-08-29T00:00:00Z, fixed so the vectors are byte-stable.
const ISSUED_AT: u64 = 1_787_961_600;

// ── Value construction shorthand ────────────────────────────────────────

fn t(s: &str) -> Value {
    Value::Text(s.into())
}
fn u(n: u64) -> Value {
    Value::Integer(n.into())
}
fn f(x: f64) -> Value {
    Value::Float(x)
}
fn b(bytes: &[u8]) -> Value {
    Value::Bytes(bytes.to_vec())
}
fn m(pairs: &[(&str, Value)]) -> Value {
    Value::Map(pairs.iter().map(|(k, v)| (t(k), v.clone())).collect())
}
fn a(items: &[Value]) -> Value {
    Value::Array(items.to_vec())
}
fn p4(v: [f64; 4]) -> Value {
    a(&[f(v[0]), f(v[1]), f(v[2]), f(v[3])])
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn canon(v: &Value) -> Result<Vec<u8>> {
    encode_canonical(v).map_err(|e| anyhow!("canonical encode: {e}"))
}

// ── section content ─────────────────────────────────────────────────────

/// Signal-dominant 4x3 confusion builder (D-R shape; the literature default
/// for a bootstrapping verifier model): each TRUE verdict row puts `diag` on
/// its expected SIGNAL — satisfied→accept, violated→reject, refused/error→
/// abstain (a verifier that cannot run mostly stays silent) — remainder
/// spread evenly, so every row is a proper distribution by construction.
fn verifier(id: &str, diag: f64) -> Value {
    let off = (1.0 - diag) / 2.0;
    let row = |signal: usize| {
        let mut r = [off; 3];
        r[signal] = diag;
        a(&[f(r[0]), f(r[1]), f(r[2])])
    };
    m(&[
        ("verifier_id", t(id)),
        ("confusion", a(&[row(0), row(1), row(2), row(2)])),
    ])
}

/// The six sections that turn fusion on (D-P: bundle zero ships
/// literature-default matrices). `rich` also populates the optional fields
/// (thresholds already ride both; exploration + quarantine are rich-only).
fn sections_full(rich: bool) -> Value {
    let verify = m(&[
        (
            "anchors",
            a(&[
                m(&[
                    ("catalog_id", t("cargo-check")),
                    ("enabled", Value::Bool(true)),
                    ("debounce_ms", u(750)),
                ]),
                m(&[
                    ("catalog_id", t("pytest")),
                    ("enabled", Value::Bool(true)),
                    ("thresholds", m(&[("fail_ratio", f(0.0))])),
                ]),
            ]),
        ),
        (
            "verifiers",
            a(&[
                verifier("anchor.syntactic", 0.9),
                verifier("anchor.test_suite", 0.92),
                verifier("llm.judge", 0.75),
            ]),
        ),
        ("priors", p4([0.55, 0.25, 0.1, 0.1])),
        // 07 NORMATIVE: the syntactic and test anchors form ONE group — a
        // linter and a test suite failing on the same diff is one
        // observation about the diff, not two.
        (
            "correlation_groups",
            a(&[m(&[
                ("group_id", t("syntactic_and_tests")),
                (
                    "members",
                    a(&[t("anchor.syntactic"), t("anchor.test_suite")]),
                ),
            ])]),
        ),
        (
            "quarantine",
            if rich { a(&[t("llm.judge")]) } else { a(&[]) },
        ),
    ]);

    let mut route_pairs = vec![
        (
            "cpvs",
            a(&[m(&[
                ("task_class", t("code_edit")),
                ("model_id", t("claude-sonnet-4-5")),
                ("p_pass", f(0.62)),
                ("tokens_est", u(2400)),
            ])]),
        ),
        (
            "ladders",
            a(&[m(&[
                ("ladder_id", t("default")),
                (
                    "rungs",
                    a(&[
                        m(&[
                            ("model_id", t("claude-haiku-4-5")),
                            ("keep_prefix", Value::Bool(true)),
                        ]),
                        m(&[
                            ("model_id", t("claude-sonnet-4-5")),
                            ("keep_prefix", Value::Bool(true)),
                        ]),
                    ]),
                ),
            ])]),
        ),
        (
            "knee",
            m(&[
                ("cost_basis", t("usd")),
                (
                    "rows",
                    a(&[
                        m(&[("n", u(1)), ("c_n", f(0.02))]),
                        m(&[("n", u(2)), ("c_n", f(0.05))]),
                        m(&[("n", u(3)), ("c_n", f(0.12))]),
                    ]),
                ),
                ("v_default", f(0.35)),
            ]),
        ),
    ];
    if rich {
        route_pairs.push(("exploration", m(&[("epsilon", f(0.05))])));
    }
    let route = m(&route_pairs);

    let memory = m(&[
        (
            "injection_rules",
            a(&[
                m(&[("facet", t("conventions")), ("max_items", u(8))]),
                m(&[("facet", t("decisions"))]),
            ]),
        ),
        ("budgets", m(&[("pack_tokens_max", u(1200))])),
    ]);
    let cortex = m(&[
        ("map_budget_tokens", m(&[("min", u(400)), ("max", u(2000))])),
        (
            "channels",
            a(&[t("session_start"), t("prompt_submit"), t("before_model")]),
        ),
    ]);
    let gates = m(&[
        ("stop_gate_enabled", Value::Bool(true)),
        ("max_consecutive_blocks", u(3)),
        ("hourly_block_ceiling", u(20)),
    ]);
    let agent_maps = m(&[(
        "agents",
        a(&[m(&[
            ("agent_id", t("claudecode")),
            ("agent_version", t("2.1.0")),
            (
                "hook_fields",
                m(&[
                    ("usage.input_tokens", t("/message/usage/input_tokens")),
                    ("usage.output_tokens", t("/message/usage/output_tokens")),
                ]),
            ),
            (
                "tailer_rules",
                m(&[
                    ("dedupe.message_id", t("/message/id")),
                    ("dedupe.request_id", t("/requestId")),
                ]),
            ),
        ])]),
    )]);

    m(&[
        ("verify", verify),
        ("route", route),
        ("memory", memory),
        ("cortex", cortex),
        ("gates", gates),
        ("agent_maps", agent_maps),
    ])
}

/// The smallest sections the CDDL admits: every `*` collection empty, every
/// `+` collection at one element, no optionals.
fn sections_minimal() -> Value {
    m(&[
        (
            "verify",
            m(&[
                ("anchors", a(&[])),
                ("verifiers", a(&[])),
                ("priors", p4([0.55, 0.25, 0.1, 0.1])),
                ("correlation_groups", a(&[])),
                ("quarantine", a(&[])),
            ]),
        ),
        (
            "route",
            m(&[
                ("cpvs", a(&[])),
                ("ladders", a(&[])),
                (
                    "knee",
                    m(&[
                        ("cost_basis", t("quota")),
                        ("rows", a(&[m(&[("n", u(1)), ("c_n", f(0.5))])])),
                        ("v_default", f(1.0)),
                    ]),
                ),
            ]),
        ),
        (
            "memory",
            m(&[
                ("injection_rules", a(&[])),
                ("budgets", m(&[("pack_tokens_max", u(0))])),
            ]),
        ),
        (
            "cortex",
            m(&[
                ("map_budget_tokens", m(&[("min", u(500)), ("max", u(500))])),
                ("channels", a(&[])),
            ]),
        ),
        (
            "gates",
            m(&[
                ("stop_gate_enabled", Value::Bool(false)),
                ("max_consecutive_blocks", u(0)),
                ("hourly_block_ceiling", u(0)),
            ]),
        ),
        ("agent_maps", m(&[("agents", a(&[]))])),
    ])
}

// ── assembly + signing ──────────────────────────────────────────────────

fn section_of<'v>(sections: &'v Value, name: &str) -> Result<&'v Value> {
    let Value::Map(entries) = sections else {
        bail!("sections is not a map")
    };
    entries
        .iter()
        .find_map(|(k, v)| matches!(k, Value::Text(s) if s == name).then_some(v))
        .with_context(|| format!("section {name} missing"))
}

/// Replaces the map entry `key` in `v` (must exist) — the negative vectors
/// are honest mutations of a good bundle, not parallel constructions.
fn map_set(v: &mut Value, key: &str, new_val: Value) -> Result<()> {
    let Value::Map(entries) = v else {
        bail!("expected map")
    };
    let slot = entries
        .iter_mut()
        .find_map(|(k, val)| matches!(k, Value::Text(s) if s == key).then_some(val))
        .with_context(|| format!("key {key} missing"))?;
    *slot = new_val;
    Ok(())
}

/// Adds a NEW entry (must not exist) — the stray-key negative's constructor.
fn map_add(v: &mut Value, key: &str, new_val: Value) -> Result<()> {
    let Value::Map(entries) = v else {
        bail!("expected map")
    };
    ensure!(
        !entries
            .iter()
            .any(|(k, _)| matches!(k, Value::Text(s) if s == key)),
        "key {key} already present"
    );
    entries.push((t(key), new_val));
    Ok(())
}

/// The expired verify-class key's window end: long before ISSUED_AT, so any
/// bundle issued "now" is outside it (the pre-D-Q probe backdated issued_at
/// to sneak inside such a window; outside_validity pins the window check).
const EXPIRED_NOT_AFTER: &str = "2020-01-01T00:00:00Z";
const EXPIRED_SEED: u8 = b'7';

struct Signers {
    sections: [Ed25519Signer; 6],
    /// Published in the verify ring but rotated out (not_after 2020).
    expired: Ed25519Signer,
}

impl Signers {
    fn new() -> Self {
        Self {
            sections: std::array::from_fn(|i| Ed25519Signer::from_seed([SEED_BYTES[i]; 32])),
            expired: Ed25519Signer::from_seed([EXPIRED_SEED; 32]),
        }
    }

    fn for_section(&self, s: Section) -> &Ed25519Signer {
        &self.sections[Section::ALL.iter().position(|x| *x == s).unwrap_or(0)]
    }

    fn key_set(&self) -> SectionKeys {
        let mut keys = SectionKeys::new();
        for s in Section::ALL {
            keys.insert_public(s, self.for_section(s).public_key());
        }
        let mut entry = mark1_receipt::KeyEntry::new(
            self.expired.public_key(),
            mark1_receipt::KeyRole::ServerChain,
        );
        entry.not_after = Some(EXPIRED_NOT_AFTER.into());
        keys.insert(Section::Verify, entry);
        keys
    }
}

/// The envelope fields D-Q signs (everything but `inclusion`); one struct so
/// a vector cannot sign one envelope and carry another by accident.
struct Env<'a> {
    channel: &'a str,
    seq: u64,
    prev_hash: [u8; 32],
    max_age: u64,
}

fn sign_one(signer: &Ed25519Signer, section: Section, sec: &Value, env: &Env) -> Result<Value> {
    let bytes = canon(sec)?;
    let msg = section_signing_input(&SigInput {
        section,
        section_bytes: &bytes,
        tenant_id: &TENANT_ID,
        channel: env.channel,
        seq: env.seq,
        issued_at_epoch_s: ISSUED_AT,
        max_age_s: env.max_age,
        prev_hash: &env.prev_hash,
    })
    .map_err(|e| anyhow!("signing input: {e}"))?;
    Ok(m(&[
        ("key_id", t(&signer.key_id())),
        ("sig", b(&signer.sign(&msg))),
    ]))
}

fn signatures(signers: &Signers, sections: &Value, env: &Env) -> Result<Value> {
    let mut pairs = Vec::new();
    for s in Section::ALL {
        pairs.push((
            s.name(),
            sign_one(
                signers.for_section(s),
                s,
                section_of(sections, s.name())?,
                env,
            )?,
        ));
    }
    Ok(m(&pairs))
}

fn bundle_value(
    seq: u64,
    channel: &str,
    prev_hash: [u8; 32],
    max_age: u64,
    sections: Value,
    sigs: Value,
    inclusion: Value,
) -> Value {
    m(&[
        ("schema", t("policy_bundle.v1")),
        ("tenant_id", b(&TENANT_ID)),
        ("channel", t(channel)),
        ("seq", u(seq)),
        ("issued_at", Value::Tag(1, Box::new(u(ISSUED_AT)))),
        ("max_age", u(max_age)),
        ("prev_hash", b(&prev_hash)),
        ("sections", sections),
        ("signatures", sigs),
        ("inclusion", inclusion),
    ])
}

/// Single-leaf tlog: the proof for the only bundle ever logged, plus the
/// pinned head a well-behaved caller holds (D-S: the head is the evidence;
/// the in-map root alone is self-consistency).
fn single_leaf_proof(body: [u8; 32]) -> (Value, TlogHead) {
    let root = sha256(&[&[0x00], &body]);
    let proof = m(&[
        ("leaf_index", u(0)),
        ("tree_size", u(1)),
        ("path", a(&[])),
        ("root", b(&root)),
    ]);
    (proof, TlogHead { tree_size: 1, root })
}

/// 3-leaf tlog with this bundle at index 2 — exercises a non-trivial audit
/// path (one interior sibling) in every implementation.
fn three_leaf_proof(body: [u8; 32]) -> (Value, TlogHead) {
    let lh0 = sha256(&[&[0x00], &[0xAA; 32]]);
    let lh1 = sha256(&[&[0x00], &[0xBB; 32]]);
    let lh2 = sha256(&[&[0x00], &body]);
    let n01 = sha256(&[&[0x01], &lh0, &lh1]);
    let root = sha256(&[&[0x01], &n01, &lh2]);
    let proof = m(&[
        ("leaf_index", u(2)),
        ("tree_size", u(3)),
        ("path", a(&[b(&n01)])),
        ("root", b(&root)),
    ]);
    (proof, TlogHead { tree_size: 3, root })
}

/// The canonical-form defect classes the decoder must reject (RFC 8949
/// §4.2.1's clauses, one vector each): a tolerant CBOR reader decodes every
/// one of these to bundle_zero's exact semantics, so ONLY a canonical-form
/// check can object — which is precisely what the vectors exist to force on
/// the Go twin.
#[derive(Clone, Copy, PartialEq)]
enum Defect {
    /// Top-level map keys in reverse sorted order (canonical pair bytes).
    UnsortedTop,
    /// First map re-emitted with an indefinite-length head.
    IndefMap,
    /// First text string re-emitted as an indefinite-length text (one chunk).
    IndefText,
    /// First integer < 24 widened to the two-byte 0x18 head.
    NonMinimalInt,
    /// First shorter-encodable float widened to the 9-byte f64 form.
    WidenFloat,
    /// First NESTED map with ≥ 2 entries emitted in reverse key order.
    UnsortedNested,
    /// First nested map's first pair emitted twice (a duplicate key).
    DupKey,
}

/// Re-encodes `v` with exactly ONE defect injected at the first eligible
/// site; everything else stays canonical so the vector isolates its defect.
fn encode_with_defect(v: &Value, defect: Defect) -> Result<Vec<u8>> {
    fn head(major: u8, n: u64, out: &mut Vec<u8>) -> Result<()> {
        // The generator's shapes are small; growing past 0xff is a bug here.
        match n {
            0..=23 => out.push((major << 5) | n as u8),
            24..=0xff => out.extend_from_slice(&[(major << 5) | 24, n as u8]),
            _ => bail!("defect encoder: head arg {n} too large"),
        }
        Ok(())
    }
    fn walk(
        v: &Value,
        out: &mut Vec<u8>,
        armed: &mut bool,
        defect: Defect,
        depth: usize,
    ) -> Result<()> {
        match v {
            Value::Map(entries) => {
                let mut pairs: Vec<(Vec<u8>, &Value, &Value)> = Vec::with_capacity(entries.len());
                for (k, val) in entries {
                    pairs.push((canon(k)?, k, val));
                }
                pairs.sort_by(|a, b| a.0.cmp(&b.0));
                let nested = depth >= 1;
                if *armed && defect == Defect::IndefMap {
                    *armed = false;
                    out.push(0xbf); // indefinite-length map head
                    for (_, k, val) in &pairs {
                        walk(k, out, armed, defect, depth + 1)?;
                        walk(val, out, armed, defect, depth + 1)?;
                    }
                    out.push(0xff);
                    return Ok(());
                }
                let unsorted_site = match defect {
                    Defect::UnsortedTop => depth == 0,
                    Defect::UnsortedNested => nested && pairs.len() >= 2,
                    _ => false,
                };
                if *armed && unsorted_site {
                    *armed = false;
                    pairs.reverse();
                } else if *armed && defect == Defect::DupKey && nested && !pairs.is_empty() {
                    *armed = false;
                    head(5, pairs.len() as u64 + 1, out)?;
                    out.extend_from_slice(&pairs[0].0);
                    out.extend_from_slice(&canon(pairs[0].2)?);
                    for (kb, _, val) in &pairs {
                        out.extend_from_slice(kb);
                        out.extend_from_slice(&canon(val)?);
                    }
                    return Ok(());
                }
                head(5, pairs.len() as u64, out)?;
                for (_, k, val) in &pairs {
                    walk(k, out, armed, defect, depth + 1)?;
                    walk(val, out, armed, defect, depth + 1)?;
                }
                Ok(())
            }
            Value::Array(items) => {
                head(4, items.len() as u64, out)?;
                for item in items {
                    walk(item, out, armed, defect, depth + 1)?;
                }
                Ok(())
            }
            Value::Tag(tag, inner) => {
                head(6, *tag, out)?;
                walk(inner, out, armed, defect, depth + 1)
            }
            Value::Text(_) if *armed && defect == Defect::IndefText => {
                *armed = false;
                out.push(0x7f); // indefinite-length text: one canonical chunk
                out.extend_from_slice(&canon(v)?);
                out.push(0xff);
                Ok(())
            }
            Value::Integer(i)
                if *armed
                    && defect == Defect::NonMinimalInt
                    && (0..24).contains(&i128::from(*i)) =>
            {
                *armed = false;
                out.extend_from_slice(&[0x18, i128::from(*i) as u8]); // 0..23 needs no arg byte
                Ok(())
            }
            Value::Float(f) if *armed && defect == Defect::WidenFloat && canon(v)?.len() < 9 => {
                *armed = false;
                out.push(0xfb); // full f64 width where a shorter form is exact
                out.extend_from_slice(&f.to_be_bytes());
                Ok(())
            }
            other => {
                out.extend_from_slice(&canon(other)?);
                Ok(())
            }
        }
    }
    let mut out = Vec::new();
    let mut armed = true;
    walk(v, &mut out, &mut armed, defect, 0)?;
    ensure!(!armed, "defect found no eligible site in this value");
    Ok(out)
}

// ── vector records ──────────────────────────────────────────────────────

struct Vector {
    name: &'static str,
    raw: Vec<u8>,
    last_applied_seq: Option<u64>,
    /// The pinned log head the driving caller holds (D-S). None both for the
    /// seq-0 vectors (pre-log, head irrelevant) and for the vector that
    /// PROVES a missing head refuses at seq > 0.
    tlog_head: Option<TlogHead>,
    /// None = accept; Some((code, kind)) = the NAMED reject.
    expect: Option<(&'static str, &'static str)>,
}

fn summary_of(bundle: &Bundle) -> serde_json::Value {
    json!({
        "seq": bundle.seq,
        "channel": bundle.channel,
        "issued_at_epoch_s": bundle.issued_at_epoch_s,
        "max_age_s": bundle.max_age.as_secs(),
        "anchors": bundle.verify.anchors.len(),
        "verifiers": bundle.verify.verifiers.len(),
        "quarantined": bundle.verify.quarantined.iter().filter(|q| **q).count(),
        "correlation_groups": bundle.verify.correlation_groups.len(),
        "knee_rows": bundle.route.knee.rows.len(),
        "exploration_epsilon": bundle.route.exploration_epsilon,
        "stop_gate_enabled": bundle.gates.stop_gate_enabled,
        "max_consecutive_blocks": bundle.gates.max_consecutive_blocks,
        "agents": bundle.agent_maps.agents.len(),
    })
}

fn build_vectors(signers: &Signers) -> Result<Vec<Vector>> {
    let mut out = Vec::new();

    // bundle_zero — D-P's Phase 2 fixture: seq 0, channel "local", genesis
    // prev_hash, inclusion null (the structural waiver), fusion ON.
    let env_local0 = Env {
        channel: "local",
        seq: 0,
        prev_hash: GENESIS_PREV_HASH,
        // A year: the local bundle must not fail-static to built-ins mid-phase.
        max_age: 31_536_000,
    };
    let bz_sections = sections_full(false);
    let bz_sigs = signatures(signers, &bz_sections, &env_local0)?;
    let bundle_zero = bundle_value(
        env_local0.seq,
        env_local0.channel,
        env_local0.prev_hash,
        env_local0.max_age,
        bz_sections.clone(),
        bz_sigs.clone(),
        Value::Null,
    );
    out.push(Vector {
        name: "bundle_zero",
        raw: canon(&bundle_zero)?,
        last_applied_seq: None,
        tlog_head: None,
        expect: None,
    });

    // full — six sections with every optional populated, seq 1 on "stable",
    // single-leaf tlog proof, genesis prev_hash (m1_009: seq 1 chains from
    // the 32-zero head default).
    let env_stable1 = Env {
        channel: "stable",
        seq: 1,
        prev_hash: GENESIS_PREV_HASH,
        max_age: 86_400,
    };
    let full_sections = sections_full(true);
    let full_sigs = signatures(signers, &full_sections, &env_stable1)?;
    let full_no_proof = bundle_value(
        env_stable1.seq,
        env_stable1.channel,
        env_stable1.prev_hash,
        env_stable1.max_age,
        full_sections.clone(),
        full_sigs.clone(),
        Value::Null,
    );
    let full_body = body_sha256(&canon(&full_no_proof)?).map_err(|e| anyhow!("{e}"))?;
    let (full_proof, full_head) = single_leaf_proof(full_body);
    let mut full = full_no_proof.clone();
    map_set(&mut full, "inclusion", full_proof)?;
    let full_raw = canon(&full)?;
    out.push(Vector {
        name: "full",
        raw: full_raw.clone(),
        last_applied_seq: Some(0),
        tlog_head: Some(full_head),
        expect: None,
    });

    // minimal — smallest admissible sections, seq 2, prev_hash chained to
    // full's body hash, 3-leaf tlog proof.
    let env_stable2 = Env {
        channel: "stable",
        seq: 2,
        prev_hash: full_body,
        max_age: 3_600,
    };
    let min_sections = sections_minimal();
    let min_sigs = signatures(signers, &min_sections, &env_stable2)?;
    let min_no_proof = bundle_value(
        env_stable2.seq,
        env_stable2.channel,
        env_stable2.prev_hash,
        env_stable2.max_age,
        min_sections.clone(),
        min_sigs,
        Value::Null,
    );
    let min_body = body_sha256(&canon(&min_no_proof)?).map_err(|e| anyhow!("{e}"))?;
    let (min_proof, min_head) = three_leaf_proof(min_body);
    let mut minimal = min_no_proof;
    map_set(&mut minimal, "inclusion", min_proof)?;
    out.push(Vector {
        name: "minimal",
        raw: canon(&minimal)?,
        last_applied_seq: Some(1),
        tlog_head: Some(min_head),
        expect: None,
    });

    // bad_section_sig — bundle zero with the gates signature corrupted (last
    // sig byte flipped); everything else intact.
    let mut bad_sig = bundle_zero.clone();
    let mut sigs = bz_sigs.clone();
    let gates_sig = {
        let gate_entry = section_of(&sigs, "gates")?.clone();
        let Value::Map(pairs) = &gate_entry else {
            bail!("sig entry not a map")
        };
        let raw_sig = pairs
            .iter()
            .find_map(|(k, v)| matches!(k, Value::Text(s) if s == "sig").then_some(v))
            .context("sig field")?;
        let Value::Bytes(bytes) = raw_sig else {
            bail!("sig not bytes")
        };
        let mut corrupted = bytes.clone();
        corrupted[63] ^= 0x01;
        m(&[
            ("key_id", t(&signers.for_section(Section::Gates).key_id())),
            ("sig", b(&corrupted)),
        ])
    };
    map_set(&mut sigs, "gates", gates_sig)?;
    map_set(&mut bad_sig, "signatures", sigs)?;
    out.push(Vector {
        name: "bad_section_sig",
        raw: canon(&bad_sig)?,
        last_applied_seq: None,
        tlog_head: None,
        expect: Some(("M1E-3001", "bad_signature")),
    });

    // wrong_key_role — the verify section signed by the GATES key: a valid
    // signature by a published key, but published for another section class.
    // 05 §4.5's whole point: it must die as unknown_key, not verify.
    let mut wrong_role = bundle_zero.clone();
    let mut wr_sigs = bz_sigs.clone();
    map_set(
        &mut wr_sigs,
        "verify",
        sign_one(
            signers.for_section(Section::Gates),
            Section::Verify,
            section_of(&bz_sections, "verify")?,
            &env_local0,
        )?,
    )?;
    map_set(&mut wrong_role, "signatures", wr_sigs)?;
    out.push(Vector {
        name: "wrong_key_role",
        raw: canon(&wrong_role)?,
        last_applied_seq: None,
        tlog_head: None,
        expect: Some(("M1E-3001", "unknown_key")),
    });

    // non_canonical* — bundle zero's exact content under each canonical-form
    // defect class the decoder handles: same semantics through any tolerant
    // reader, different bytes, must reject. One vector per class so a twin
    // that misses ONE clause of RFC 8949 §4.2.1 fails ONE named vector.
    for (name, defect) in [
        ("non_canonical", Defect::UnsortedTop),
        ("non_canonical_indef_map", Defect::IndefMap),
        ("non_canonical_indef_text", Defect::IndefText),
        ("non_canonical_nonminimal_int", Defect::NonMinimalInt),
        ("non_canonical_widened_float", Defect::WidenFloat),
        ("non_canonical_unsorted_nested", Defect::UnsortedNested),
        ("non_canonical_dup_key", Defect::DupKey),
    ] {
        out.push(Vector {
            name,
            raw: encode_with_defect(&bundle_zero, defect)?,
            last_applied_seq: None,
            tlog_head: None,
            expect: Some(("M1E-3001", "non_canonical")),
        });
    }

    // seq_replay — the (valid) full bundle offered when seq 1 was already
    // applied: the anti-rollback `>` with no exception path.
    out.push(Vector {
        name: "seq_replay",
        raw: full_raw.clone(),
        last_applied_seq: Some(1),
        tlog_head: Some(full_head),
        expect: Some(("M1E-3002", "seq_replay")),
    });

    // tampered_prev_hash — a seq-0 bundle VALIDLY SIGNED over a nonzero
    // prev_hash (post-D-Q the envelope is signed, so a post-signing mutation
    // would die as bad_signature instead): the compiler-bug shape only the
    // genesis chain rule can catch — proving that rule exists.
    let env_bad_genesis = Env {
        prev_hash: [0x11; 32],
        ..env_local0
    };
    let tampered = bundle_value(
        env_bad_genesis.seq,
        env_bad_genesis.channel,
        env_bad_genesis.prev_hash,
        env_bad_genesis.max_age,
        bz_sections.clone(),
        signatures(signers, &bz_sections, &env_bad_genesis)?,
        Value::Null,
    );
    out.push(Vector {
        name: "tampered_prev_hash",
        raw: canon(&tampered)?,
        last_applied_seq: None,
        tlog_head: None,
        expect: Some(("M1E-3001", "prev_hash_mismatch")),
    });

    // backdated_issued_at — the D-Q probe: the adversarial review backdated
    // the (then-unsigned) issued_at to 2017 and revived a section key whose
    // not_after was 2020, with no re-signing. issued_at is now under every
    // section signature, so the same mutation is a bad_signature.
    let mut backdated = full.clone();
    map_set(
        &mut backdated,
        "issued_at",
        Value::Tag(1, Box::new(u(1_483_228_800))), // 2017-01-01T00:00:00Z
    )?;
    out.push(Vector {
        name: "backdated_issued_at",
        raw: canon(&backdated)?,
        last_applied_seq: Some(0),
        tlog_head: Some(full_head),
        expect: Some(("M1E-3001", "bad_signature")),
    });

    // inclusion_missing — seq 1 with a null proof (and the head PRESENT, so
    // this vector isolates the missing proof): the seq-0 waiver must not
    // stretch one sequence number past zero.
    out.push(Vector {
        name: "inclusion_missing",
        raw: canon(&full_no_proof)?,
        last_applied_seq: Some(0),
        tlog_head: Some(full_head),
        expect: Some(("M1E-3003", "inclusion_invalid")),
    });

    // tlog_head_missing — the valid seq-1 bundle offered to a caller holding
    // NO pinned head: D-S makes that a refusal (keep last-known-good), never
    // a fall-back to the bundle's own root.
    out.push(Vector {
        name: "tlog_head_missing",
        raw: full_raw.clone(),
        last_applied_seq: Some(0),
        tlog_head: None,
        expect: Some(("M1E-3003", "inclusion_invalid")),
    });

    // forged_inclusion_root — the D-S kill shot: the untampered, validly
    // signed seq-1 body carrying a SELF-CONSISTENT proof (the audit walk
    // reproduces its own root) whose root is not the pinned head's. The
    // pre-D-S decoder accepted this, which made M1E-3003 decorative at
    // seq > 0: a proof verified against a root the bundle itself supplied.
    let mut forged_root = full_no_proof.clone();
    map_set(&mut forged_root, "inclusion", three_leaf_proof(full_body).0)?;
    out.push(Vector {
        name: "forged_inclusion_root",
        raw: canon(&forged_root)?,
        last_applied_seq: Some(0),
        tlog_head: Some(full_head),
        expect: Some(("M1E-3003", "inclusion_invalid")),
    });

    // tampered_body_self_proof — the review probe verbatim: max_age stretched
    // to u64::MAX, prev_hash rewritten, a fresh single-leaf proof recomputed
    // over the tampered body and its root written into `inclusion`. Pre-D-Q/
    // D-S this was ACCEPTED with no signing key involved. It now dies at the
    // SIGNATURE step (D-Q signs max_age and prev_hash); had it somehow
    // survived, the self-made root would still fail the pinned-head
    // comparison (proven by forged_inclusion_root above).
    let mut tampered_body = full_no_proof.clone();
    map_set(&mut tampered_body, "max_age", u(u64::MAX))?;
    map_set(&mut tampered_body, "prev_hash", b(&[0x42; 32]))?;
    let tampered_digest = body_sha256(&canon(&tampered_body)?).map_err(|e| anyhow!("{e}"))?;
    map_set(
        &mut tampered_body,
        "inclusion",
        single_leaf_proof(tampered_digest).0,
    )?;
    out.push(Vector {
        name: "tampered_body_self_proof",
        raw: canon(&tampered_body)?,
        last_applied_seq: Some(0),
        tlog_head: Some(full_head),
        expect: Some(("M1E-3001", "bad_signature")),
    });

    // command_string — a properly SIGNED bundle whose verify section smuggles
    // a shell command as a catalog_id. Signatures pass; the structural
    // grammar (07 rule 1) must reject the whole bundle as M1E-3005.
    let mut cs_sections = sections_full(false);
    {
        let verify = {
            let mut v = section_of(&cs_sections, "verify")?.clone();
            map_set(
                &mut v,
                "anchors",
                a(&[m(&[
                    ("catalog_id", t("rm -rf /tmp")),
                    ("enabled", Value::Bool(true)),
                ])]),
            )?;
            v
        };
        map_set(&mut cs_sections, "verify", verify)?;
    }
    let cs_sigs = signatures(signers, &cs_sections, &env_local0)?;
    let command_string = bundle_value(
        env_local0.seq,
        env_local0.channel,
        env_local0.prev_hash,
        env_local0.max_age,
        cs_sections,
        cs_sigs,
        Value::Null,
    );
    out.push(Vector {
        name: "command_string",
        raw: canon(&command_string)?,
        last_applied_seq: None,
        tlog_head: None,
        expect: Some(("M1E-3005", "command_string")),
    });

    // schema_stray_key — a properly SIGNED bundle whose memory section
    // carries the exact shape a future `wasm_module` smuggle would take.
    // Signatures pass (they cover whatever bytes the section holds); 07 rule
    // 3's strict-map decode is the layer that must kill it — as `schema`
    // (M1E-3001), NOT command_string: an unknown key is a structural defect,
    // not a string-production violation (05 §4.3 pages a human on M1E-3005).
    let mut stray_sections = sections_full(false);
    {
        let mut memory = section_of(&stray_sections, "memory")?.clone();
        map_add(&mut memory, "wasm_module", Value::Bool(true))?;
        map_set(&mut stray_sections, "memory", memory)?;
    }
    let stray_sigs = signatures(signers, &stray_sections, &env_local0)?;
    let stray = bundle_value(
        env_local0.seq,
        env_local0.channel,
        env_local0.prev_hash,
        env_local0.max_age,
        stray_sections,
        stray_sigs,
        Value::Null,
    );
    out.push(Vector {
        name: "schema_stray_key",
        raw: canon(&stray)?,
        last_applied_seq: None,
        tlog_head: None,
        expect: Some(("M1E-3001", "schema")),
    });

    // outside_validity — the verify section signed by a PUBLISHED verify-ring
    // key whose not_after (2020) precedes issued_at (2026): a rotated-out key
    // must die on its window, not verify. (Backdating issued_at to re-enter
    // the window is the D-Q vector above.)
    let mut expired = bundle_zero.clone();
    let mut ex_sigs = bz_sigs.clone();
    map_set(
        &mut ex_sigs,
        "verify",
        sign_one(
            &signers.expired,
            Section::Verify,
            section_of(&bz_sections, "verify")?,
            &env_local0,
        )?,
    )?;
    map_set(&mut expired, "signatures", ex_sigs)?;
    out.push(Vector {
        name: "outside_validity",
        raw: canon(&expired)?,
        last_applied_seq: None,
        tlog_head: None,
        expect: Some(("M1E-3001", "outside_validity")),
    });

    // too_large — one canonical bstr of MAX_BUNDLE_LEN zero bytes (total =
    // bound + 5 head bytes): the length gate fires BEFORE any parse, so the
    // content past the head is deliberately inert. Zeros keep the frozen
    // 4 MiB file compressible to nothing in git.
    out.push(Vector {
        name: "too_large",
        raw: canon(&b(&vec![0u8; MAX_BUNDLE_LEN]))?,
        last_applied_seq: None,
        tlog_head: None,
        expect: Some(("M1E-3001", "too_large")),
    });

    Ok(out)
}

fn main() -> Result<()> {
    let signers = Signers::new();
    let keys = signers.key_set();
    let vectors = build_vectors(&signers)?;

    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/vectors/bundle");
    fs::create_dir_all(&dir)?;

    let mut manifest_vectors = Vec::new();
    for v in &vectors {
        let file = format!("{}.cbor", v.name);
        let outcome = verify_and_decode(&v.raw, &keys, v.last_applied_seq, v.tlog_head.as_ref());
        let mut entry = json!({
            "name": v.name,
            "file": file,
            "last_applied_seq": v.last_applied_seq,
            "tlog_head": v.tlog_head.map(|h| json!({
                "tree_size": h.tree_size,
                "root_hex": hex::encode(&h.root),
            })),
            "file_sha256_hex": hex::encode(&sha256(&[&v.raw])),
        });
        match (&v.expect, outcome) {
            (None, Ok(bundle)) => {
                entry["expect"] = json!("accept");
                entry["body_sha256_hex"] = json!(hex::encode(&bundle.body_sha256));
                entry["summary"] = summary_of(&bundle);
            }
            (Some((code, kind)), Err(reject)) => {
                ensure!(
                    reject.code() == *code && reject.kind() == *kind,
                    "{}: expected {code}/{kind}, got {}/{} ({reject})",
                    v.name,
                    reject.code(),
                    reject.kind()
                );
                entry["expect"] = json!("reject");
                entry["code"] = json!(code);
                entry["kind"] = json!(kind);
            }
            (None, Err(reject)) => bail!("{}: accept vector rejected: {reject}", v.name),
            (Some(_), Ok(_)) => bail!("{}: negative vector accepted", v.name),
        }
        fs::write(dir.join(&file), &v.raw)?;
        manifest_vectors.push(entry);
    }

    let mut key_json = BTreeMap::new();
    for (i, s) in Section::ALL.iter().enumerate() {
        let signer = signers.for_section(*s);
        key_json.insert(
            s.name(),
            json!({
                "seed_hex": hex::encode(&[SEED_BYTES[i]; 32]),
                "public_hex": hex::encode(&signer.public_key()),
                "key_id": signer.key_id(),
            }),
        );
    }

    let manifest = json!({
        "_readme": "Frozen bundle-family conformance contract. README.md is normative; this file is the referee; generated once by gen_bundle_vectors.rs (Rust reference implementation).",
        "schema": "policy_bundle.v1",
        "tenant_id_hex": hex::encode(&TENANT_ID),
        "issued_at_epoch_s": ISSUED_AT,
        "genesis_prev_hash_hex": hex::encode(&GENESIS_PREV_HASH),
        // A verify-class key every driver must publish WITH its window: the
        // outside_validity vector is signed by it.
        "expired_key": {
            "section": "verify",
            "seed_hex": hex::encode(&[EXPIRED_SEED; 32]),
            "public_hex": hex::encode(&signers.expired.public_key()),
            "key_id": signers.expired.key_id(),
            "not_after": EXPIRED_NOT_AFTER,
        },
        "signing_input": "D-Q: \"mark1-bundle-v1\\0\" || canonical_cbor({schema, section_name, tenant_id: bstr16, channel, seq, issued_at: tag1(uint), max_age, prev_hash: bstr32, section: bstr(canonical section bytes)}) — covers the whole envelope except `inclusion`",
        "tlog": "RFC 6962 shape, SHA-256: leaf entry = body_sha256 (bundle map minus `inclusion`, canonical bytes); leaf_hash = sha256(0x00 || entry); node = sha256(0x01 || left || right); waived structurally at seq == 0 (D-P). D-S: at seq > 0 the driver MUST hold the per-vector `tlog_head` (null = no head pinned, an M1E-3003 refusal) and the proof root must equal the head's",
        "keys": key_json,
        "vectors": manifest_vectors,
    });
    fs::write(dir.join("manifest.json"), format!("{:#}\n", manifest))?;
    eprintln!(
        "gen_bundle_vectors: wrote {} vectors + manifest.json to {}",
        vectors.len(),
        dir.display()
    );
    Ok(())
}
