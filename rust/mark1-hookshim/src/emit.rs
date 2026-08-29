//! `m1p.v1.Event` construction (04 §5): the shim stamps `event_id` (UUIDv7)
//! and `occurred_at`; it does NOT stamp `seq` or `session_epoch` — per-session
//! causal order is assigned by mark1d at admission (04 §0.4 R-4: a shim-local
//! counter cannot be session-monotonic across the shim's many short-lived
//! processes).

use m1p_wire::pb;

use crate::maps::{EventRule, FieldMap};

/// Map one hook payload to its Event, or None when the contract says emit
/// nothing: unmapped hook name, unmapped kind, or an unparseable session id
/// (adapters never guess a field — 08 §5 rule 2).
pub fn build(map: &FieldMap, payload: &serde_json::Value) -> Option<pb::Event> {
    let hook = payload.get(&map.event_field)?.as_str()?;
    let rule = map.events.get(hook)?;
    let body = body_for(map, rule, payload)?;
    let session_id = payload
        .get(&map.session_id_field)?
        .as_str()
        .and_then(|s| uuid::Uuid::parse_str(s).ok())?;
    Some(pb::Event {
        event_id: uuid::Uuid::now_v7().as_bytes().to_vec(),
        session_id: session_id.as_bytes().to_vec(),
        occurred_at: Some(now()),
        body: Some(body),
        // seq / session_epoch / task_id / server band: all zero-valued on the
        // client wire by contract (R-4; 07 §2 server-stamped band).
        ..Default::default()
    })
}

fn body_for(
    map: &FieldMap,
    rule: &EventRule,
    payload: &serde_json::Value,
) -> Option<pb::event::Body> {
    // The kind vocabulary is the binary's semantic surface (04 §5: the shim
    // binary changes only when semantics change); everything vendor-specific
    // came from the map.
    let field = |logical: &str| -> String {
        rule.fields
            .get(logical)
            .and_then(|vendor| payload.get(vendor))
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_owned()
    };
    let duration = || -> u64 {
        rule.fields
            .get("duration_ms")
            .and_then(|vendor| payload.get(vendor))
            .and_then(|v| v.as_u64())
            .unwrap_or_default()
    };
    let tool = |status: pb::ToolStatus, duration_ms: u64| {
        pb::event::Body::ToolUse(pb::ToolUse {
            tool_name: field("tool_name"),
            tool_use_id: field("tool_use_id"),
            duration_ms,
            status: status as i32,
        })
    };
    let turn = |initiator: pb::Initiator| {
        pb::event::Body::Turn(pb::Turn {
            // The shim is stateless per exec; turn indexing is daemon-side
            // session state, so 0 = "unnumbered" on the client wire.
            turn_index: 0,
            initiator: initiator as i32,
        })
    };
    match rule.kind.as_str() {
        "session_start" => Some(pb::event::Body::SessionStart(pb::SessionStart {
            agent: map.agent.clone(),
            agent_version: map.agent_version.clone(),
            // workspace_id is HMAC_tenant(root) — tenant-key custody is
            // mark1d.identity (04 §2.9), so the daemon stamps it at
            // admission; the shim sends it empty rather than unkeyed.
            workspace_id: Vec::new(),
            capture_paths: vec![pb::CapturePath::Hooks as i32],
        })),
        "session_end" => Some(pb::event::Body::SessionEnd(pb::SessionEnd {
            // Every hook-observed end is a clean agent exit; crash/idle ends
            // are tailer inferences (07 §3), never hook events.
            reason: pb::EndReason::Exit as i32,
            duration_ms: 0,
            drained: false,
        })),
        "turn_human" => Some(turn(pb::Initiator::Human)),
        "turn_agent" => Some(turn(pb::Initiator::Agent)),
        "tool_open" => Some(tool(pb::ToolStatus::Unspecified, 0)),
        "tool_close_ok" => Some(tool(pb::ToolStatus::Ok, duration())),
        "tool_close_error" => Some(tool(pb::ToolStatus::Error, duration())),
        // "none" and anything unknown: mapped-to-nothing is a first-class
        // rule state (PreCompact has no committed m1p.v1 body to ride).
        _ => None,
    }
}

fn now() -> m1p_wire::google::protobuf::Timestamp {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => m1p_wire::google::protobuf::Timestamp {
            seconds: d.as_secs() as i64,
            nanos: d.subsec_nanos() as i32,
        },
        // A pre-epoch clock is display-grade nonsense either way (07 §2:
        // occurred_at is never ordering); zero is the honest sentinel.
        Err(_) => m1p_wire::google::protobuf::Timestamp {
            seconds: 0,
            nanos: 0,
        },
    }
}
