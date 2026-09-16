//! The stop-gate (04 §5 step 5; 08 §5.1's `Stop` row) — the one hook path
//! where the shim's answer changes what the agent does.
//!
//! Order, normative: the off-check runs FIRST, in `main::off()`, before stdin
//! and therefore before any socket exists (invariant 2, 04 §6 step 1); this
//! module is only ever reached with capture on. Then the vendor hard cap
//! `stop_hook_active` (08 §5.1) — a block issued inside a block-induced
//! continuation is how a session wedges. Then the fabric round-trip.
//!
//! Every failure is ALLOW: timeout, unreachable daemon, refused handshake, a
//! malformed reply. Gating is fail-open for availability (08 §5 rule 5,
//! M1E-5001) — Mark 1's absence must never block a developer — and each
//! fail-open answer is counted, because an uncounted fail-open is
//! indistinguishable from a product that silently does nothing.
//!
//! The remaining local hard caps of 08 §5.1 (≤3 consecutive blocks per task,
//! the hourly ceiling) are NOT here: 04 §2.3 puts them in the daemon's gate
//! handler, which owns the per-task streak state a per-exec process cannot.

use std::io::Write;
use std::path::Path;
use std::time::Duration;

use m1p_wire::pb;

use crate::maps::{EventRule, GateRule};

/// 08 §4.4: the shim, not the daemon, owns the agent-facing deadline — the
/// agent hook's own budget minus 10 ms. Never 0: D-Y(c) makes `deadline_ms`
/// 0 mean "unspecified", so the shim must always state a real number.
const SHIM_MARGIN_MS: u32 = 10;

/// Run the gate and answer the agent on stdout. Returns nothing: exit 0 with
/// no output IS the allow answer (08 §5.1 `Stop` row — "exit 0 with no
/// decision"), byte-identical to Mark 1 being absent.
pub fn run(
    home: Option<&Path>,
    rule: &EventRule,
    gate: &GateRule,
    payload: &serde_json::Value,
    event_frame: Vec<u8>,
    session_id: &[u8],
) {
    let Some(kind) = kind(gate) else {
        // A gate kind this binary does not implement is not a guess to make
        // (08 §5 rule 2): fall back to the observer path, which is allow.
        observe(home, event_frame, session_id);
        return;
    };
    if stop_hook_active(rule, payload) {
        observe(home, event_frame, session_id);
        return;
    }

    // Never 0 (D-Y(c)); saturating so a bundle that ships a budget under the
    // margin degrades to "1 ms, answer now" rather than to "unspecified".
    let deadline_ms = gate.budget_ms.saturating_sub(SHIM_MARGIN_MS).max(1);
    let query = pb::GateQuery {
        // The shim has no task_id: 04 §9.2 mints it in the daemon and R-4
        // keeps it off the client wire (emit.rs leaves Event.task_id empty),
        // and no document states how a per-exec hook process learns it. It is
        // sent empty rather than fabricated — see the report accompanying
        // this change.
        task_id: Vec::new(),
        gate: kind as i32,
        deadline_ms,
    };
    let budget = Duration::from_millis(u64::from(deadline_ms));

    let waited = std::time::Instant::now();
    match crate::fabric::gate_query(&event_frame, query, session_id, budget) {
        Ok(v) if v.decision == pb::GateDecision::Block as i32 => block(&v),
        Ok(v) if !v.system_message.is_empty() => knee(&v),
        // ALLOW, and anything else the daemon can say: allow.
        Ok(_) => {}
        Err(_) => {
            let elapsed = waited.elapsed(); // before the spill: redaction + sealing is real work, not the deadline
            crate::spill::append(home, event_frame);
            crate::spill::count_gate_timeout(home);
            crate::spill::record_timing(home, "hookshim.gate_elapsed_ms", elapsed);
        }
    }
}

/// The gate declined before any socket IO: the event is still an observer
/// event and takes the ordinary fire-and-forget path. The full abandon budget
/// applies — a gate hook's own budget is seconds, so 45 ms from here is the
/// same promise 04 §5 step 4 makes.
fn observe(home: Option<&Path>, event_frame: Vec<u8>, session_id: &[u8]) {
    crate::observe(
        home,
        event_frame,
        session_id,
        Duration::from_millis(crate::FABRIC_ABANDON_MS),
    );
}

fn kind(gate: &GateRule) -> Option<pb::GateKind> {
    match gate.kind.as_str() {
        "stop" => Some(pb::GateKind::Stop),
        "tool" => Some(pb::GateKind::Tool),
        _ => None,
    }
}

/// 08 §5.1: `stop_hook_active` is a hard cap checked BEFORE the gate. The
/// vendor sets it when this Stop is itself the continuation of a previous
/// block; blocking again from inside one is an unbounded loop with the agent
/// on the other end.
fn stop_hook_active(rule: &EventRule, payload: &serde_json::Value) -> bool {
    rule.fields
        .get("stop_hook_active")
        .and_then(|vendor| payload.get(vendor))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

/// 08 §5.1's block row, transcribed: `{"decision":"block","reason":"<verdict
/// + failure evidence as continuation reason>"}` on stdout, exit 0. Never
/// `continue:false`, never exit 2 (its blocking semantics duplicate
/// `decision`, and 08 §5.1 fixes exit 0 + JSON as the only mode).
fn block(v: &pb::GateVerdict) {
    let mut reason = v.reason.clone();
    if !v.evidence_ref.is_empty() {
        reason.push_str(" [evidence: ");
        reason.push_str(&v.evidence_ref);
        reason.push(']');
    }
    answer(serde_json::json!({
        "decision": "block",
        "reason": reason,
    }));
}

/// 08 §5.1's at-the-knee sub-row: no `decision` (Claude stops), `systemMessage` for the human, never the model.
fn knee(v: &pb::GateVerdict) {
    answer(serde_json::json!({ "systemMessage": v.system_message }));
}

/// The gate path's one stdout sink; a partial write is unparseable JSON, which Claude Code discards — the allow answer.
fn answer(json: serde_json::Value) {
    let Ok(bytes) = serde_json::to_vec(&json) else {
        return;
    };
    let _ = std::io::stdout().write_all(&bytes);
}
