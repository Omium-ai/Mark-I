//! ADR-0018: the MCP surface as an external writer. Three `mark1.*` tools let
//! an MCP client that runs its own agent loop reach `mark1d` the way a socket
//! host does (ADR-0012/0013), with cortexd as the transport: the client's
//! manifest and events go over the fabric as component `ext:mcp/<client>`,
//! and the daemon's recommendations and proposals for that session come back
//! from the files the daemon leaves for file-tail hosts (08 §4.7, §3.7).
//!
//! Transport only. Nothing here reads the index, spends a budget or emits a
//! `CortexInjection`; the daemon admits, mints, binds and judges exactly as it
//! does for any `ext:` writer, and a refusal from it is reported, never
//! retried or papered over.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use m1p_wire::pb;
use serde_json::{json, Map, Value};

use crate::fabric::{ext_exchange, ext_hello, PushError};
use crate::session::Shared;

/// Every tool of this surface starts with this; `handle` routes on it so the
/// index-state gates of the other tools never apply here.
pub const PREFIX: &str = "mark1.";

/// 08 §10 fabric codes as the refusal envelope reports them.
const CODE_HANDSHAKE_REFUSED: &str = "M1E-4003";
const CODE_MANIFEST_REFUSED: &str = "M1E-4007";
const CODE_UNREACHABLE: &str = "M1E-4008";

/// One MCP client's bound external-writer session, kept for the life of the
/// cortexd process: the daemon minted the id at the first Hello, and every
/// later Hello for the client presents the same id, manifest and correlation
/// id so the daemon binds the same session (08 §4.3 step 2a).
#[derive(Debug, Clone)]
pub struct ExtSession {
    pub session: [u8; 16],
    pub manifest: Option<pb::HostManifest>,
    pub host_correlation_id: String,
}

pub type ExtSessions = HashMap<String, ExtSession>;

/// The three tools' MCP schemas (08 §6.7–6.9).
pub fn tool_list() -> Vec<Value> {
    let client = json!({ "type": "string", "pattern": "^[A-Za-z0-9._-]{1,64}$",
        "description": "Your host's name; the fabric component becomes ext:mcp/<client>. One session per client per cortexd process." });
    vec![
        json!({
            "name": "mark1.send_manifest",
            "description": "Declare your host profile to mark1d (ADR-0013) and open the external-writer session the other mark1.* tools use. Returns the daemon-minted session_id. The manifest is validated by the daemon (M1E-4007 on refusal).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "client": client,
                    "host_manifest": {
                        "type": "object",
                        "properties": {
                            "host_id": { "type": "string" },
                            "host_version": { "type": "string" },
                            "owns_execution": { "type": "boolean" },
                            "owns_config_surface": { "type": "boolean" },
                            "owns_memory": { "type": "boolean" },
                            "arrest_mode": { "type": "string", "enum": ["act", "recommend"] },
                            "supplies_identity": { "type": "boolean" },
                            "schema_version": { "type": "string", "enum": ["m1p.v1"] }
                        },
                        "required": ["host_id", "host_version", "arrest_mode", "schema_version"],
                        "additionalProperties": false
                    },
                    "host_correlation_id": { "type": "string", "maxLength": 256,
                        "description": "Optional: your own run/session id; mark1d keeps it on the session and in receipts, never as a Mark 1 session id." }
                },
                "required": ["client", "host_manifest"], "additionalProperties": false
            }
        }),
        json!({
            "name": "mark1.emit_event",
            "description": "Forward one m1p.v1 Event (protojson object: optional task_id and occurred_at, exactly one of task_open, task_close, turn, usage, artifact_outcome) to mark1d as your host's external-writer session. event_id, seq and session_id are the daemon's to stamp.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "client": client,
                    "event": { "type": "object", "description": "One m1p.v1.Event in protojson (08 §4.6.2's line format)." }
                },
                "required": ["client", "event"], "additionalProperties": false
            }
        }),
        json!({
            "name": "mark1.get_recommendations",
            "description": "What mark1d recommended (ADR-0015, arrest_mode recommend) and proposed (ADR-0016, owns_memory) for your session so far: the protojson Events from <state>/run/recommendations and <state>/run/proposals.",
            "inputSchema": {
                "type": "object",
                "properties": { "client": client },
                "required": ["client"], "additionalProperties": false
            }
        }),
    ]
}

/// Dispatch for `mark1.*`; `Err` is an invalid-params JSON-RPC error, a
/// refusal is a success result with `refused: true` (08 §6).
pub async fn call(shared: &Arc<Shared>, name: &str, args: &Value) -> Result<Value, String> {
    let client = client_of(args)?;
    match name {
        "mark1.send_manifest" => send_manifest(shared, &client, args).await,
        "mark1.emit_event" => emit_event(shared, &client, args).await,
        "mark1.get_recommendations" => Ok(get_recommendations(shared, &client)),
        other => Err(format!("unknown tool: {other}")),
    }
}

fn client_of(args: &Value) -> Result<String, String> {
    let c = args
        .get("client")
        .and_then(Value::as_str)
        .ok_or_else(|| "client is required".to_string())?;
    let ok = !c.is_empty()
        && c.len() <= 64
        && c.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-');
    if !ok {
        return Err("client must match ^[A-Za-z0-9._-]{1,64}$".to_string());
    }
    Ok(c.to_string())
}

pub fn component(client: &str) -> String {
    format!("ext:mcp/{client}")
}

fn refusal(code: &str, reason: String) -> Value {
    json!({ "refused": true, "reason_code": code, "reason": reason })
}

fn refused(e: PushError, manifest_sent: bool) -> Value {
    match e {
        PushError::HandshakeRefused if manifest_sent => refusal(
            CODE_MANIFEST_REFUSED,
            "mark1d closed the handshake: the manifest or the protocol version was refused (M1E-4007 / M1E-4003; the daemon log names which)".into(),
        ),
        PushError::HandshakeRefused => refusal(
            CODE_HANDSHAKE_REFUSED,
            "mark1d closed the handshake (M1E-4003; the daemon log names why)".into(),
        ),
        PushError::Unavailable(e) => refusal(CODE_UNREACHABLE, format!("mark1d is not reachable: {e}")),
    }
}

fn sessions(shared: &Shared) -> std::sync::MutexGuard<'_, ExtSessions> {
    shared
        .ext_sessions
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

async fn send_manifest(shared: &Arc<Shared>, client: &str, args: &Value) -> Result<Value, String> {
    let manifest = manifest_from_json(
        args.get("host_manifest")
            .ok_or_else(|| "host_manifest is required".to_string())?,
    )?;
    let corr = args
        .get("host_correlation_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if corr.len() > 256 {
        return Err("host_correlation_id is at most 256 bytes".to_string());
    }
    let hello = ext_hello(&component(client), None, Some(manifest.clone()), &corr);
    match ext_exchange(hello, &[]).await {
        Ok(sid) => {
            sessions(shared).insert(
                client.to_string(),
                ExtSession {
                    session: sid,
                    manifest: Some(manifest),
                    host_correlation_id: corr,
                },
            );
            Ok(json!({ "refused": false, "session_id": hex(&sid), "component": component(client) }))
        }
        Err(e) => Ok(refused(e, true)),
    }
}

async fn emit_event(shared: &Arc<Shared>, client: &str, args: &Value) -> Result<Value, String> {
    let mut event = event_from_json(
        args.get("event")
            .ok_or_else(|| "event is required".to_string())?,
    )?;
    let existing = sessions(shared).get(client).cloned();
    let ext = match existing {
        Some(s) => s,
        None => {
            // No manifest declared: the daemon mints a Default-profile session
            // for the component, as it does for any ext: Hello without one.
            let hello = ext_hello(&component(client), None, None, "");
            match ext_exchange(hello, &[]).await {
                Ok(sid) => {
                    let s = ExtSession {
                        session: sid,
                        manifest: None,
                        host_correlation_id: String::new(),
                    };
                    sessions(shared).insert(client.to_string(), s.clone());
                    s
                }
                Err(e) => return Ok(refused(e, false)),
            }
        }
    };
    event.session_id = ext.session.to_vec();
    let mut frame = Vec::new();
    m1p_wire::encode_frame(&event, &mut frame).map_err(|e| format!("event does not frame: {e}"))?;
    let hello = ext_hello(
        &component(client),
        Some(ext.session),
        ext.manifest.clone(),
        &ext.host_correlation_id,
    );
    match ext_exchange(hello, &[frame]).await {
        Ok(_) => Ok(json!({ "refused": false, "session_id": hex(&ext.session), "delivered": 1 })),
        Err(e) => Ok(refused(e, ext.manifest.is_some())),
    }
}

fn get_recommendations(shared: &Arc<Shared>, client: &str) -> Value {
    let Some(dir) = state_dir() else {
        return refusal(
            CODE_UNREACHABLE,
            "mark1d state directory unknown: set MARK1_STATE_DIR or HOME".into(),
        );
    };
    get_recommendations_in(&dir, shared, client)
}

fn get_recommendations_in(dir: &std::path::Path, shared: &Arc<Shared>, client: &str) -> Value {
    let Some(ext) = sessions(shared).get(client).cloned() else {
        return refusal(
            CODE_HANDSHAKE_REFUSED,
            "no session for this client yet: call mark1.send_manifest (or mark1.emit_event) first"
                .into(),
        );
    };
    let sid = hex(&ext.session);
    let (recommendations, unparsed_r) = read_lines(
        &dir.join("run")
            .join("recommendations")
            .join(format!("{sid}.jsonl")),
    );
    let (proposals, unparsed_p) = read_lines(
        &dir.join("run")
            .join("proposals")
            .join(format!("{sid}.jsonl")),
    );
    json!({
        "refused": false,
        "session_id": sid,
        "recommendations": recommendations,
        "proposals": proposals,
        "unparsed_lines": unparsed_r + unparsed_p,
    })
}

/// `<state>` as the daemon lays it out: `MARK1_STATE_DIR`, else `$HOME/.omium/mark1`
/// (the socket's own directory, fabric::endpoints), else `%USERPROFILE%` likewise.
pub fn state_dir() -> Option<PathBuf> {
    if let Some(d) = std::env::var_os("MARK1_STATE_DIR") {
        return Some(PathBuf::from(d));
    }
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(|h| PathBuf::from(h).join(".omium").join("mark1"))
}

/// Every parseable JSON line of a daemon-written file; an absent file is an
/// empty list, a malformed line is counted and skipped, never a failure.
pub fn read_lines(path: &std::path::Path) -> (Vec<Value>, u64) {
    let Ok(text) = std::fs::read_to_string(path) else {
        return (Vec::new(), 0);
    };
    let mut out = Vec::new();
    let mut bad = 0;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(line) {
            Ok(v) => out.push(v),
            Err(_) => bad += 1,
        }
    }
    (out, bad)
}

// ---------------------------------------------------------------------------
// protojson → m1p.v1 (the external-writer vocabulary only)
// ---------------------------------------------------------------------------

/// A `HostManifest` from the tool's object: field names as the proto spells
/// them (snake_case) or protojson's lowerCamelCase; `arrest_mode` as `act` /
/// `recommend`, the enum's full name, or its number. Validation is the
/// daemon's (M1E-4007); here only the shape is checked.
pub fn manifest_from_json(v: &Value) -> Result<pb::HostManifest, String> {
    let o = v
        .as_object()
        .ok_or_else(|| "host_manifest must be an object".to_string())?;
    let arrest_mode = match field(o, "arrest_mode") {
        None => pb::ArrestMode::Unspecified as i32,
        Some(Value::Number(n)) => {
            n.as_i64()
                .ok_or_else(|| "arrest_mode: bad number".to_string())? as i32
        }
        Some(Value::String(s)) => match s.to_ascii_lowercase().as_str() {
            "act" | "arrest_mode_act" => pb::ArrestMode::Act as i32,
            "recommend" | "arrest_mode_recommend" => pb::ArrestMode::Recommend as i32,
            "unspecified" | "arrest_mode_unspecified" => pb::ArrestMode::Unspecified as i32,
            other => return Err(format!("arrest_mode: {other:?} is not act or recommend")),
        },
        Some(_) => return Err("arrest_mode must be a string or a number".to_string()),
    };
    Ok(pb::HostManifest {
        host_id: string(o, "host_id")?,
        host_version: string(o, "host_version")?,
        owns_execution: boolean(o, "owns_execution")?,
        owns_config_surface: boolean(o, "owns_config_surface")?,
        owns_memory: boolean(o, "owns_memory")?,
        arrest_mode,
        supplies_identity: boolean(o, "supplies_identity")?,
        schema_version: string(o, "schema_version")?,
    })
}

/// One `Event` from a protojson object: `task_id` (base64 or hex) and
/// `occurred_at` (RFC 3339; now when absent) from the envelope, and exactly
/// one of the five external-writer bodies. `event_id`, `seq` and
/// `session_id` are ignored: the daemon stamps them (ADR-0012).
pub fn event_from_json(v: &Value) -> Result<pb::Event, String> {
    let o = v
        .as_object()
        .ok_or_else(|| "event must be an object".to_string())?;
    let mut bodies: Vec<pb::event::Body> = Vec::new();
    if let Some(b) = field(o, "task_open") {
        let b = obj(b, "task_open")?;
        bodies.push(pb::event::Body::TaskOpen(pb::TaskOpen {
            task_seg_version: string(b, "task_seg_version")?,
            parent_task_id: bytes(b, "parent_task_id")?,
            prompt_digest: bytes(b, "prompt_digest")?,
            file_set_digest: bytes(b, "file_set_digest")?,
            task_class: string(b, "task_class")?,
        }));
    }
    if let Some(b) = field(o, "task_close") {
        let b = obj(b, "task_close")?;
        bodies.push(pb::event::Body::TaskClose(pb::TaskClose {
            resolution: enum_value(b, "resolution", |n| {
                pb::Resolution::from_str_name(n).map(|e| e as i32)
            })?,
            final_verdict_id: bytes(b, "final_verdict_id")?,
            turn_count: u32_of(b, "turn_count")?,
        }));
    }
    if let Some(b) = field(o, "turn") {
        let b = obj(b, "turn")?;
        bodies.push(pb::event::Body::Turn(pb::Turn {
            turn_index: u32_of(b, "turn_index")?,
            initiator: enum_value(b, "initiator", |n| {
                pb::Initiator::from_str_name(n).map(|e| e as i32)
            })?,
        }));
    }
    if let Some(b) = field(o, "usage") {
        let b = obj(b, "usage")?;
        bodies.push(pb::event::Body::Usage(pb::Usage {
            idem_key: bytes(b, "idem_key")?,
            message_id: string(b, "message_id")?,
            request_id: string(b, "request_id")?,
            model: string(b, "model")?,
            input_tokens: u64_of(b, "input_tokens")?,
            output_tokens: u64_of(b, "output_tokens")?,
            cache_creation_input_tokens: u64_of(b, "cache_creation_input_tokens")?,
            cache_read_input_tokens: u64_of(b, "cache_read_input_tokens")?,
            service_tier: string(b, "service_tier")?,
            source: enum_value(b, "source", |n| {
                pb::UsageSource::from_str_name(n).map(|e| e as i32)
            })?,
        }));
    }
    if let Some(b) = field(o, "artifact_outcome") {
        let b = obj(b, "artifact_outcome")?;
        bodies.push(pb::event::Body::ArtifactOutcome(pb::ArtifactOutcome {
            artifact_id: bytes(b, "artifact_id")?,
            task_verdict: enum_value(b, "task_verdict", |n| {
                pb::Verdict::from_str_name(n).map(|e| e as i32)
            })?,
            artifact_followed: boolean(b, "artifact_followed")?,
        }));
    }
    if bodies.len() != 1 {
        return Err(format!(
            "event needs exactly one of task_open, task_close, turn, usage, artifact_outcome; found {}",
            bodies.len()
        ));
    }
    let occurred_at = match field(o, "occurred_at") {
        None => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            (now.as_secs() as i64, now.subsec_nanos() as i32)
        }
        Some(Value::String(s)) => {
            parse_rfc3339(s).ok_or_else(|| format!("occurred_at: {s:?} is not RFC 3339"))?
        }
        Some(_) => return Err("occurred_at must be an RFC 3339 string".to_string()),
    };
    Ok(pb::Event {
        event_id: Vec::new(),
        seq: 0,
        session_id: Vec::new(),
        task_id: bytes(o, "task_id")?,
        occurred_at: Some(m1p_wire::google::protobuf::Timestamp {
            seconds: occurred_at.0,
            nanos: occurred_at.1,
        }),
        session_epoch: 0,
        tenant_id: Vec::new(),
        device_id: Vec::new(),
        received_at: None,
        clock_skew_ms: 0,
        body: bodies.pop(),
    })
}

fn camel(snake: &str) -> String {
    let mut out = String::with_capacity(snake.len());
    let mut up = false;
    for c in snake.chars() {
        if c == '_' {
            up = true;
        } else if up {
            out.extend(c.to_uppercase());
            up = false;
        } else {
            out.push(c);
        }
    }
    out
}

/// A field by its proto name or protojson's lowerCamelCase spelling.
fn field<'a>(o: &'a Map<String, Value>, snake: &str) -> Option<&'a Value> {
    o.get(snake).or_else(|| o.get(&camel(snake)))
}

fn obj<'a>(v: &'a Value, name: &str) -> Result<&'a Map<String, Value>, String> {
    v.as_object()
        .ok_or_else(|| format!("{name} must be an object"))
}

fn string(o: &Map<String, Value>, k: &str) -> Result<String, String> {
    match field(o, k) {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(s)) => Ok(s.clone()),
        Some(_) => Err(format!("{k} must be a string")),
    }
}

fn boolean(o: &Map<String, Value>, k: &str) -> Result<bool, String> {
    match field(o, k) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(format!("{k} must be a boolean")),
    }
}

fn u64_of(o: &Map<String, Value>, k: &str) -> Result<u64, String> {
    match field(o, k) {
        None | Some(Value::Null) => Ok(0),
        Some(Value::Number(n)) => n
            .as_u64()
            .ok_or_else(|| format!("{k} must be a non-negative integer")),
        Some(Value::String(s)) => s
            .parse::<u64>()
            .map_err(|_| format!("{k} must be a non-negative integer")),
        Some(_) => Err(format!("{k} must be an integer")),
    }
}

fn u32_of(o: &Map<String, Value>, k: &str) -> Result<u32, String> {
    u32::try_from(u64_of(o, k)?).map_err(|_| format!("{k} does not fit uint32"))
}

fn enum_value(
    o: &Map<String, Value>,
    k: &str,
    by_name: impl Fn(&str) -> Option<i32>,
) -> Result<i32, String> {
    match field(o, k) {
        None | Some(Value::Null) => Ok(0),
        Some(Value::Number(n)) => n
            .as_i64()
            .and_then(|i| i32::try_from(i).ok())
            .ok_or_else(|| format!("{k}: bad enum number")),
        Some(Value::String(s)) => {
            by_name(s).ok_or_else(|| format!("{k}: {s:?} is not a known enum name"))
        }
        Some(_) => Err(format!("{k} must be an enum name or number")),
    }
}

/// protojson bytes are base64 (standard or URL alphabet, padding optional).
/// Hex is accepted too, since the daemon's own files print ids that way: a
/// 32- or 64-character all-hex string is an id or a hash (16 / 32 bytes) and
/// reads as hex first — base64 of 16 bytes is 22 or 24 characters, never 32;
/// anything else tries base64, then hex.
fn bytes(o: &Map<String, Value>, k: &str) -> Result<Vec<u8>, String> {
    match field(o, k) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::String(s)) if s.is_empty() => Ok(Vec::new()),
        Some(Value::String(s)) => {
            let hexy = (s.len() == 32 || s.len() == 64) && s.bytes().all(|b| b.is_ascii_hexdigit());
            let decoded = if hexy {
                decode_hex(s)
            } else {
                decode_base64(s).or_else(|| decode_hex(s))
            };
            decoded.ok_or_else(|| format!("{k} must be base64 (protojson) or hex"))
        }
        Some(_) => Err(format!("{k} must be a string")),
    }
}

pub fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

pub fn decode_base64(s: &str) -> Option<Vec<u8>> {
    let s = s.trim_end_matches('=');
    if s.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    // Leftover bits must be zero padding of a whole byte boundary.
    if bits >= 6 || (acc & ((1 << bits) - 1)) != 0 {
        return None;
    }
    Some(out)
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// RFC 3339 (`YYYY-MM-DDTHH:MM:SS[.frac](Z|±HH:MM)`) → (unix seconds, nanos).
pub fn parse_rfc3339(s: &str) -> Option<(i64, i32)> {
    let b = s.as_bytes();
    if b.len() < 20 {
        return None;
    }
    let num = |from: usize, to: usize| -> Option<i64> { s.get(from..to)?.parse::<i64>().ok() };
    let (y, mo, d) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    if b[4] != b'-'
        || b[7] != b'-'
        || (b[10] != b'T' && b[10] != b't' && b[10] != b' ')
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let (h, mi, sec) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    let mut i = 19;
    let mut nanos: i64 = 0;
    if i < b.len() && b[i] == b'.' {
        i += 1;
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        let frac = s.get(start..i)?;
        if frac.is_empty() {
            return None;
        }
        let mut f = frac.to_string();
        f.truncate(9);
        while f.len() < 9 {
            f.push('0');
        }
        nanos = f.parse().ok()?;
    }
    let offset: i64 = match b.get(i) {
        Some(b'Z') | Some(b'z') if i + 1 == b.len() => 0,
        Some(sign @ (b'+' | b'-')) if i + 6 == b.len() && b[i + 3] == b':' => {
            let oh = num(i + 1, i + 3)?;
            let om = num(i + 4, i + 6)?;
            let o = oh * 3600 + om * 60;
            if *sign == b'+' {
                o
            } else {
                -o
            }
        }
        _ => return None,
    };
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    // days from civil (Howard Hinnant), proleptic Gregorian
    let y2 = if mo <= 2 { y - 1 } else { y };
    let era = if y2 >= 0 { y2 } else { y2 - 399 } / 400;
    let yoe = y2 - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    let secs = days * 86400 + h * 3600 + mi * 60 + sec - offset;
    Some((secs, nanos as i32))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_and_hex_bytes() {
        assert_eq!(decode_base64("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(decode_base64("aGVsbG8").unwrap(), b"hello");
        assert_eq!(decode_base64("_-8").unwrap(), vec![0xff, 0xef]);
        assert!(decode_base64("a").is_none());
        assert_eq!(decode_hex("00ff").unwrap(), vec![0, 255]);
        assert!(decode_hex("0f0").is_none());
    }

    #[test]
    fn rfc3339_to_unix() {
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some((0, 0)));
        let (s, n) = parse_rfc3339("2026-10-03T12:34:56.789Z").unwrap();
        assert_eq!(n, 789_000_000);
        // 2026-10-03T12:34:56Z: days since epoch 20729 → 1790987696
        assert_eq!(s, 20729 * 86400 + 12 * 3600 + 34 * 60 + 56);
        let (s2, _) = parse_rfc3339("2026-10-03T14:34:56+02:00").unwrap();
        assert_eq!(s2, s);
        assert!(parse_rfc3339("2026-10-03 12:34").is_none());
        assert!(parse_rfc3339("2026-13-03T12:34:56Z").is_none());
    }

    #[test]
    fn manifest_accepts_proto_and_camel_spellings() {
        let m = manifest_from_json(&json!({
            "hostId": "cem888", "host_version": "2.0.1", "ownsExecution": true, "owns_memory": true,
            "arrest_mode": "recommend", "supplies_identity": true, "schema_version": "m1p.v1"
        }))
        .unwrap();
        assert_eq!(m.host_id, "cem888");
        assert!(m.owns_execution && m.owns_memory && m.supplies_identity && !m.owns_config_surface);
        assert_eq!(m.arrest_mode, pb::ArrestMode::Recommend as i32);
        assert_eq!(
            manifest_from_json(&json!({"arrest_mode": "ARREST_MODE_ACT"}))
                .unwrap()
                .arrest_mode,
            1
        );
        assert_eq!(
            manifest_from_json(&json!({"arrest_mode": 2}))
                .unwrap()
                .arrest_mode,
            2
        );
        assert!(manifest_from_json(&json!({"arrest_mode": "maybe"})).is_err());
        assert!(manifest_from_json(&json!("x")).is_err());
    }

    #[test]
    fn events_from_protojson_for_every_writer_body() {
        let task = "AQEBAQEBAQEBAQEBAQEBAQ=="; // 16 × 0x01
        let usage = event_from_json(&json!({
            "taskId": task, "occurredAt": "2026-10-03T00:00:01Z",
            "usage": { "idemKey": "AAEC", "model": "claude", "inputTokens": "12", "outputTokens": 3, "source": "USAGE_SOURCE_TRANSCRIPT" }
        }))
        .unwrap();
        assert_eq!(usage.task_id, vec![1u8; 16]);
        assert_eq!(usage.occurred_at.as_ref().unwrap().seconds, 1790985601);
        match usage.body.unwrap() {
            pb::event::Body::Usage(u) => {
                assert_eq!(u.idem_key, vec![0, 1, 2]);
                assert_eq!((u.input_tokens, u.output_tokens), (12, 3));
                assert_eq!(u.source, pb::UsageSource::Transcript as i32);
            }
            other => panic!("{other:?}"),
        }
        let close = event_from_json(&json!({ "task_id": "02020202020202020202020202020202",
            "task_close": { "resolution": "RESOLUTION_VERDICT", "turn_count": 4 } }))
        .unwrap();
        assert_eq!(close.task_id, vec![2u8; 16]);
        assert!(
            matches!(close.body, Some(pb::event::Body::TaskClose(ref c)) if c.resolution == pb::Resolution::Verdict as i32 && c.turn_count == 4)
        );
        let turn = event_from_json(&json!({ "turn": { "turnIndex": 7, "initiator": 2 } })).unwrap();
        assert!(
            matches!(turn.body, Some(pb::event::Body::Turn(ref t)) if t.turn_index == 7 && t.initiator == 2)
        );
        assert!(
            turn.occurred_at.is_some() && turn.event_id.is_empty() && turn.session_id.is_empty()
        );
        let open = event_from_json(
            &json!({ "task_open": { "task_seg_version": "task_seg.v1", "task_class": "fix" } }),
        )
        .unwrap();
        assert!(
            matches!(open.body, Some(pb::event::Body::TaskOpen(ref o)) if o.task_seg_version == "task_seg.v1" && o.task_class == "fix")
        );
        let art = event_from_json(&json!({ "artifactOutcome": { "artifactId": "AQ==", "taskVerdict": "VERDICT_SATISFIED", "artifactFollowed": true } })).unwrap();
        assert!(
            matches!(art.body, Some(pb::event::Body::ArtifactOutcome(ref a)) if a.artifact_id == vec![1] && a.task_verdict == 1 && a.artifact_followed)
        );
        // A frame encodes: what emit_event sends is a FabricFrame Event arm.
        let mut frame = Vec::new();
        m1p_wire::encode_frame(&art, &mut frame).unwrap();
        assert_eq!(&frame[..4], b"M1PL");
    }

    #[test]
    fn events_need_exactly_one_body() {
        assert!(event_from_json(&json!({ "task_id": "AQ==" })).is_err());
        assert!(event_from_json(&json!({ "turn": {}, "usage": {} })).is_err());
        assert!(event_from_json(&json!({ "turn": { "turn_index": "x" } })).is_err());
        assert!(event_from_json(&json!({ "turn": {}, "occurred_at": "yesterday" })).is_err());
        assert!(event_from_json(&json!([])).is_err());
    }

    #[test]
    fn client_names_are_bounded() {
        assert_eq!(client_of(&json!({ "client": "cem888" })).unwrap(), "cem888");
        assert_eq!(component("cem888"), "ext:mcp/cem888");
        assert!(client_of(&json!({ "client": "" })).is_err());
        assert!(client_of(&json!({ "client": "a b" })).is_err());
        assert!(client_of(&json!({ "client": "x".repeat(65) })).is_err());
        assert!(client_of(&json!({})).is_err());
    }

    #[test]
    fn tool_list_names_the_three_tools() {
        let tools = tool_list();
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(
            names,
            [
                "mark1.send_manifest",
                "mark1.emit_event",
                "mark1.get_recommendations"
            ]
        );
        for t in tool_list() {
            assert!(t["inputSchema"]["required"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r == "client"));
        }
    }

    /// The tool reads the client's own session files and refuses, with the
    /// handshake code, a client that has no session yet.
    #[tokio::test]
    async fn get_recommendations_reads_the_sessions_files() {
        let dir = std::env::temp_dir().join(format!("mark1-mcp-state-{}", uuid::Uuid::now_v7()));
        let sid = [0x5a_u8; 16];
        let runs = dir.join("run");
        std::fs::create_dir_all(runs.join("recommendations")).unwrap();
        std::fs::create_dir_all(runs.join("proposals")).unwrap();
        let rec = runs
            .join("recommendations")
            .join(format!("{}.jsonl", hex(&sid)));
        let prop = runs.join("proposals").join(format!("{}.jsonl", hex(&sid)));
        std::fs::write(
            &rec,
            concat!(
                "{",
                r#""arrestRecommendation":{"kind":"stop_gate_block"}"#,
                "}",
                "
"
            ),
        )
        .unwrap();
        std::fs::write(
            &prop,
            concat!(
                "{",
                r#""memoryProposal":{"evidence":"pack"}"#,
                "}",
                "
",
                "broken",
                "
"
            ),
        )
        .unwrap();
        let shared = Arc::new(Shared::new(dir.clone(), dir.clone(), 2000));
        let none = call(
            &shared,
            "mark1.get_recommendations",
            &json!({ "client": "cem888" }),
        )
        .await
        .unwrap();
        assert_eq!(none["refused"], true);
        assert_eq!(none["reason_code"], CODE_HANDSHAKE_REFUSED);
        sessions(&shared).insert(
            "cem888".into(),
            ExtSession {
                session: sid,
                manifest: None,
                host_correlation_id: String::new(),
            },
        );
        let out = get_recommendations_in(&dir, &shared, "cem888");
        assert_eq!(out["refused"], false);
        assert_eq!(out["session_id"], hex(&sid));
        assert_eq!(
            out["recommendations"][0]["arrestRecommendation"]["kind"],
            "stop_gate_block"
        );
        assert_eq!(out["proposals"][0]["memoryProposal"]["evidence"], "pack");
        assert_eq!(out["unparsed_lines"], 1);
        assert!(call(&shared, "mark1.nope", &json!({ "client": "x" }))
            .await
            .is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn daemon_files_are_read_line_by_line() {
        let dir = std::env::temp_dir().join(format!("mark1-mcp-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("x.jsonl");
        std::fs::write(&p, "{\"arrestRecommendation\":{\"kind\":\"knee_arrest\"}}\nnot json\n\n{\"memoryProposal\":{}}\n").unwrap();
        let (lines, bad) = read_lines(&p);
        assert_eq!(lines.len(), 2);
        assert_eq!(bad, 1);
        assert_eq!(lines[0]["arrestRecommendation"]["kind"], "knee_arrest");
        assert_eq!(read_lines(&dir.join("absent.jsonl")), (Vec::new(), 0));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
