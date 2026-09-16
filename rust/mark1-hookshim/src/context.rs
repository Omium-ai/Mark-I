//! D-AE context pull over FabricFrame arms 8/9, hand-encoded (the committed gen has no ContextQuery yet); byte twin: go/mark1d/internal/fabric/context.go.

use std::io::Write;
use std::path::Path;
use std::time::Duration;

use crate::maps::EventRule;

const ARM_QUERY: u64 = 8;
const ARM_REPLY: u64 = 9;
/// m1p.v1.InjectionChannel values (intelligence.proto).
const CHANNEL_HOOK_CONTEXT: u64 = 2;
const CHANNEL_REACTIVE_PITFALL: u64 = 4;
const CHANNEL_CORRECTION: u64 = 5;
/// Round-trip budgets: a pack is a daemon cache read (the gate's sizing); a pitfall may reach the server fuzz tier.
const PACK_BUDGET_MS: u32 = 250;
const PITFALL_BUDGET_MS: u32 = 1_500;
const SHIM_MARGIN_MS: u32 = 10;
/// Only the first lines key the signature (retrieve.py); the rest never leaves the box.
const ERROR_MAX_BYTES: usize = 1024;
/// 08 §5.1 D-AF: the vendor discards longer strings, so a longer reply is a daemon bug, not a truncation to hide.
const VENDOR_CAP_CHARS: usize = 10_000;

pub struct ContextQuery {
    pub channel: u64,
    pub tool_name: String,
    pub error: String,
    pub deadline_ms: u32,
    pub is_interrupt: bool,
}

/// The query a hook warrants, by binary-fixed kind: `turn_human` opens the task (pack), `tool_close_ok` pulls the next-turn correction (08 §5.1 PostToolUse row), `tool_close_error` is the pitfall row.
pub fn plan(rule: &EventRule, payload: &serde_json::Value) -> Option<ContextQuery> {
    let field = |logical: &str| -> String {
        rule.fields
            .get(logical)
            .and_then(|vendor| payload.get(vendor))
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_owned()
    };
    match rule.kind.as_str() {
        "turn_human" | "tool_close_ok" => Some(ContextQuery {
            channel: if rule.kind == "turn_human" {
                CHANNEL_HOOK_CONTEXT
            } else {
                CHANNEL_CORRECTION
            },
            tool_name: String::new(),
            error: String::new(),
            deadline_ms: PACK_BUDGET_MS.saturating_sub(SHIM_MARGIN_MS).max(1),
            is_interrupt: false,
        }),
        "tool_close_error" => {
            let mut error = field("error");
            if error.len() > ERROR_MAX_BYTES {
                let mut cut = ERROR_MAX_BYTES;
                while !error.is_char_boundary(cut) {
                    cut -= 1;
                }
                error.truncate(cut);
            }
            Some(ContextQuery {
                channel: CHANNEL_REACTIVE_PITFALL,
                tool_name: field("tool_name"),
                error,
                deadline_ms: PITFALL_BUDGET_MS.saturating_sub(SHIM_MARGIN_MS).max(1),
                is_interrupt: rule
                    .fields
                    .get("is_interrupt")
                    .and_then(|vendor| payload.get(vendor))
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false),
            })
        }
        _ => None,
    }
}

fn varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn field_varint(out: &mut Vec<u8>, num: u64, v: u64) {
    if v != 0 {
        varint(out, num << 3);
        varint(out, v);
    }
}

fn field_bytes(out: &mut Vec<u8>, num: u64, b: &[u8]) {
    if !b.is_empty() {
        varint(out, (num << 3) | 2);
        varint(out, b.len() as u64);
        out.extend_from_slice(b);
    }
}

/// One FabricFrame payload: arm 8 wrapping the query, proto3 presence (zero-valued fields absent).
pub fn encode_query(q: &ContextQuery) -> Vec<u8> {
    let mut inner = Vec::new();
    field_varint(&mut inner, 1, q.channel);
    field_bytes(&mut inner, 2, q.tool_name.as_bytes());
    field_bytes(&mut inner, 3, q.error.as_bytes());
    field_varint(&mut inner, 4, u64::from(q.deadline_ms));
    field_varint(&mut inner, 5, u64::from(q.is_interrupt));
    let mut out = Vec::with_capacity(inner.len() + 4);
    varint(&mut out, (ARM_QUERY << 3) | 2);
    varint(&mut out, inner.len() as u64);
    out.extend_from_slice(&inner);
    out
}

fn read_varint(b: &[u8], at: &mut usize) -> Option<u64> {
    let mut v = 0u64;
    for shift in (0..64).step_by(7) {
        let byte = *b.get(*at)?;
        *at += 1;
        v |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(v);
        }
    }
    None
}

/// The one length-delimited field `num` of a message, skipping everything else.
fn find_bytes(b: &[u8], num: u64) -> Option<Option<&[u8]>> {
    let mut at = 0usize;
    let mut found = None;
    while at < b.len() {
        let tag = read_varint(b, &mut at)?;
        let (field, wire) = (tag >> 3, tag & 7);
        match wire {
            0 => {
                read_varint(b, &mut at)?;
            }
            1 => at = at.checked_add(8)?,
            5 => at = at.checked_add(4)?,
            2 => {
                let len = usize::try_from(read_varint(b, &mut at)?).ok()?;
                let end = at.checked_add(len)?;
                let v = b.get(at..end)?;
                if field == num {
                    found = Some(v);
                }
                at = end;
            }
            _ => return None,
        }
        if field == num && wire != 2 {
            return None;
        }
    }
    if at != b.len() {
        return None;
    }
    Some(found)
}

/// Arm 9's `additional_context`: None for an absent arm or a malformed frame, Some("") for an empty reply.
pub fn decode_reply(payload: &[u8]) -> Option<String> {
    let reply = find_bytes(payload, ARM_REPLY)??;
    match find_bytes(reply, 1)? {
        Some(text) => String::from_utf8(text.to_vec()).ok(),
        None => Some(String::new()),
    }
}

/// 08 §5.1's `hookSpecificOutput.additionalContext` under the vendor's event name; nothing for an empty reply.
pub fn render(hook_event_name: &str, text: &str) -> Option<Vec<u8>> {
    if text.is_empty() || text.chars().count() > VENDOR_CAP_CHARS {
        return None;
    }
    serde_json::to_vec(&serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": hook_event_name,
            "additionalContext": text,
        }
    }))
    .ok()
}

/// The gate's shape (gate.rs): one connection, Err ⇒ the event spills and the miss is counted.
pub fn run(
    home: Option<&Path>,
    q: &ContextQuery,
    event_frame: Vec<u8>,
    session_id: &[u8],
    hook_event_name: &str,
) {
    let budget = Duration::from_millis(u64::from(q.deadline_ms));
    match crate::fabric::context_query(&event_frame, &encode_query(q), session_id, budget) {
        Ok(reply) => {
            if let Some(json) = decode_reply(&reply).and_then(|t| render(hook_event_name, &t)) {
                let _ = std::io::stdout().write_all(&json);
            }
        }
        Err(_) => {
            crate::spill::append(home, event_frame);
            crate::spill::count_context_timeout(home);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // Shared verbatim with go/mark1d/internal/fabric/context_test.go.
    const QUERY_HEX: &str = "421f08041204426173681a124578697420636f646520310a4641494c207820d20b";
    const QUERY_FLAG_HEX: &str = "4207080220f0012801";
    const REPLY_HEX: &str = "4a1e0a1c5b6d61726b31206d656d6f72795d2072656d6564793a207265747279";
    const REPLY_EMPTY_HEX: &str = "4a00";
    const REPLY_TEXT: &str = "[mark1 memory] remedy: retry";
    const CORRECTION_QUERY_HEX: &str = "4205080520f001";
    const CORRECTION_REPLY_HEX: &str = "4a670a655b6d61726b3120636f7272656374696f6e5d206120736c6f772076657269666965722066696e697368656420616674657220746865206c61737420766572646963743a2076696f6c6174656420776173207265766973656420746f20736174697366696564";
    const CORRECTION_TEXT: &str = "[mark1 correction] a slow verifier finished after the last verdict: violated was revised to satisfied";

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn rule(kind: &str, fields: &[(&str, &str)]) -> EventRule {
        EventRule {
            kind: kind.to_owned(),
            gate: None,
            fields: fields
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect::<HashMap<_, _>>(),
        }
    }

    #[test]
    fn query_bytes_agree_with_mark1d() {
        let q = ContextQuery {
            channel: CHANNEL_REACTIVE_PITFALL,
            tool_name: "Bash".into(),
            error: "Exit code 1\nFAIL x".into(),
            deadline_ms: 1490,
            is_interrupt: false,
        };
        assert_eq!(hex(&encode_query(&q)), QUERY_HEX);
        let flag = ContextQuery {
            channel: CHANNEL_HOOK_CONTEXT,
            tool_name: String::new(),
            error: String::new(),
            deadline_ms: 240,
            is_interrupt: true,
        };
        assert_eq!(hex(&encode_query(&flag)), QUERY_FLAG_HEX);
        let correction = ContextQuery {
            channel: CHANNEL_CORRECTION,
            tool_name: String::new(),
            error: String::new(),
            deadline_ms: 240,
            is_interrupt: false,
        };
        assert_eq!(hex(&encode_query(&correction)), CORRECTION_QUERY_HEX);
    }

    #[test]
    fn reply_bytes_agree_with_mark1d() {
        assert_eq!(decode_reply(&unhex(REPLY_HEX)).as_deref(), Some(REPLY_TEXT));
        assert_eq!(decode_reply(&unhex(REPLY_EMPTY_HEX)).as_deref(), Some(""));
        assert_eq!(
            decode_reply(&unhex(CORRECTION_REPLY_HEX)).as_deref(),
            Some(CORRECTION_TEXT)
        );
        // A foreign arm (GateVerdict), a truncated frame, a bad wire type: none is a reply.
        assert_eq!(decode_reply(&unhex("2a00")), None);
        assert_eq!(decode_reply(&unhex("4a1e0a1c5b6d")), None);
        assert_eq!(decode_reply(&unhex("4a020801")), None);
        assert_eq!(decode_reply(&[]), None);
        // A later field beside the text is skipped, not refused.
        assert_eq!(
            decode_reply(&unhex("4a080a01781001180512")).as_deref(),
            None
        );
        assert_eq!(decode_reply(&unhex("4a060a0178100118")).as_deref(), None);
        assert_eq!(decode_reply(&unhex("4a050a01781001")).as_deref(), Some("x"));
    }

    #[test]
    fn plan_keys_on_the_binary_fixed_kind() {
        let payload = serde_json::json!({
            "tool_name": "Bash", "error": "Exit code 1\nboom", "is_interrupt": true
        });
        let pitfall = rule(
            "tool_close_error",
            &[
                ("tool_name", "tool_name"),
                ("error", "error"),
                ("is_interrupt", "is_interrupt"),
            ],
        );
        let q = plan(&pitfall, &payload).unwrap();
        assert_eq!(q.channel, CHANNEL_REACTIVE_PITFALL);
        assert_eq!(
            (q.tool_name.as_str(), q.error.as_str()),
            ("Bash", "Exit code 1\nboom")
        );
        assert!(q.is_interrupt);
        assert_eq!(q.deadline_ms, PITFALL_BUDGET_MS - SHIM_MARGIN_MS);

        let unmapped = plan(&rule("tool_close_error", &[]), &payload).unwrap();
        assert!(unmapped.error.is_empty() && !unmapped.is_interrupt);

        let pack = plan(&rule("turn_human", &[]), &payload).unwrap();
        assert_eq!(pack.channel, CHANNEL_HOOK_CONTEXT);
        assert_eq!(pack.deadline_ms, PACK_BUDGET_MS - SHIM_MARGIN_MS);
        // PostToolUse pulls the correction on the pack's budget: a daemon queue read, nothing of the payload.
        let correction = plan(
            &rule("tool_close_ok", &[("tool_name", "tool_name")]),
            &payload,
        )
        .unwrap();
        assert_eq!(correction.channel, CHANNEL_CORRECTION);
        assert_eq!(correction.deadline_ms, PACK_BUDGET_MS - SHIM_MARGIN_MS);
        assert!(correction.tool_name.is_empty() && correction.error.is_empty());
        assert_eq!(hex(&encode_query(&correction)), CORRECTION_QUERY_HEX);
        for observer in ["session_start", "tool_open", "turn_agent", "none"] {
            assert!(plan(&rule(observer, &[]), &payload).is_none(), "{observer}");
        }

        let long = serde_json::json!({ "error": "é".repeat(ERROR_MAX_BYTES) });
        let q = plan(&rule("tool_close_error", &[("error", "error")]), &long).unwrap();
        assert!(q.error.len() <= ERROR_MAX_BYTES && q.error.chars().all(|c| c == 'é'));
    }

    #[test]
    fn render_is_the_vendor_shape_or_nothing() {
        let out = render("PostToolUseFailure", REPLY_TEXT).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"hookSpecificOutput": {
                "hookEventName": "PostToolUseFailure", "additionalContext": REPLY_TEXT}})
        );
        assert!(render("UserPromptSubmit", "").is_none());
        assert!(render("UserPromptSubmit", &"x".repeat(VENDOR_CAP_CHARS)).is_some());
        assert!(render("UserPromptSubmit", &"x".repeat(VENDOR_CAP_CHARS + 1)).is_none());
    }

    #[cfg(unix)]
    mod fake_fabric {
        use super::*;
        use m1p_wire::pb;
        use std::io::{Read, Write};
        use std::os::unix::net::UnixListener;
        use std::sync::mpsc;
        use std::time::Instant;

        const SESSION: [u8; 16] = [7u8; 16];

        enum Mode {
            Reply,
            EmptyReply,
            Mute,
        }

        fn frame(payload: &[u8]) -> Vec<u8> {
            let mut out = Vec::new();
            out.extend_from_slice(&m1p_wire::framing::MAGIC);
            out.push(m1p_wire::framing::VERSION);
            out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            out.extend_from_slice(payload);
            out
        }

        /// A daemon speaking the real dialect plus arm 8: the raw query bytes go back to the test, the pinned reply goes out.
        fn daemon(dir: &std::path::Path, mode: Mode) -> mpsc::Receiver<Vec<u8>> {
            let sock = dir.join("omium-mark1");
            std::fs::create_dir_all(&sock).unwrap();
            let listener = UnixListener::bind(sock.join("m1p.sock")).unwrap();
            let (tx, rx) = mpsc::channel();
            std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut dec = m1p_wire::FrameDecoder::new();
                let mut buf = [0u8; 4096];
                let mut seen = 0;
                loop {
                    let n = match stream.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    dec.push(&buf[..n]);
                    while let m1p_wire::Outcome::Accept { payload, .. } = dec.next_frame() {
                        seen += 1;
                        match seen {
                            1 => {
                                let f = m1p_wire::decode_payload(&payload).unwrap();
                                let Some(pb::fabric_frame::Kind::Hello(h)) = f.kind else {
                                    panic!("first frame must be Hello");
                                };
                                assert_eq!(h.session_id, SESSION);
                                let mut out = Vec::new();
                                m1p_wire::encode_control(
                                    &pb::FabricFrame {
                                        kind: Some(pb::fabric_frame::Kind::HelloAck(
                                            pb::HelloAck {
                                                accepted: true,
                                                max_frame: m1p_wire::M1PL_MAX_FRAME,
                                                want_ver: 0,
                                            },
                                        )),
                                    },
                                    &mut out,
                                )
                                .unwrap();
                                stream.write_all(&out).unwrap();
                            }
                            2 => {
                                let f = m1p_wire::decode_payload(&payload).unwrap();
                                assert!(matches!(f.kind, Some(pb::fabric_frame::Kind::Event(_))));
                            }
                            _ => {
                                tx.send(payload).unwrap();
                                match mode {
                                    Mode::Reply => {
                                        stream.write_all(&frame(&unhex(REPLY_HEX))).unwrap()
                                    }
                                    Mode::EmptyReply => {
                                        stream.write_all(&frame(&unhex(REPLY_EMPTY_HEX))).unwrap()
                                    }
                                    Mode::Mute => std::thread::sleep(Duration::from_secs(5)),
                                }
                                return;
                            }
                        }
                    }
                }
            });
            rx
        }

        fn event_frame() -> Vec<u8> {
            let mut out = Vec::new();
            m1p_wire::encode_frame(
                &pb::Event {
                    session_id: SESSION.to_vec(),
                    body: Some(pb::event::Body::Turn(pb::Turn::default())),
                    ..Default::default()
                },
                &mut out,
            )
            .unwrap();
            out
        }

        fn with_daemon(mode: Mode) -> (tempfile::TempDir, mpsc::Receiver<Vec<u8>>) {
            let dir = tempfile::tempdir().unwrap();
            std::env::set_var("XDG_RUNTIME_DIR", dir.path());
            let rx = daemon(dir.path(), mode);
            (dir, rx)
        }

        #[test]
        fn round_trip_against_a_fake_fabric() {
            let (_dir, rx) = with_daemon(Mode::Reply);
            let q = ContextQuery {
                channel: CHANNEL_REACTIVE_PITFALL,
                tool_name: "Bash".into(),
                error: "Exit code 1\nFAIL x".into(),
                deadline_ms: 1490,
                is_interrupt: false,
            };
            let reply = crate::fabric::context_query(
                &event_frame(),
                &encode_query(&q),
                &SESSION,
                Duration::from_millis(1490),
            )
            .unwrap();
            assert_eq!(
                hex(&rx.recv_timeout(Duration::from_secs(2)).unwrap()),
                QUERY_HEX
            );
            assert_eq!(decode_reply(&reply).as_deref(), Some(REPLY_TEXT));

            let (_dir, _rx) = with_daemon(Mode::EmptyReply);
            let reply = crate::fabric::context_query(
                &event_frame(),
                &encode_query(&q),
                &SESSION,
                Duration::from_millis(1490),
            )
            .unwrap();
            assert_eq!(decode_reply(&reply).as_deref(), Some(""));
            assert!(render("PostToolUseFailure", "").is_none());

            let (_dir, _rx) = with_daemon(Mode::Mute);
            let q = ContextQuery {
                channel: CHANNEL_HOOK_CONTEXT,
                tool_name: String::new(),
                error: String::new(),
                deadline_ms: 240,
                is_interrupt: false,
            };
            let started = Instant::now();
            let res = crate::fabric::context_query(
                &event_frame(),
                &encode_query(&q),
                &SESSION,
                Duration::from_millis(240),
            );
            assert!(res.is_err());
            assert!(
                started.elapsed() < Duration::from_millis(1_000),
                "{:?}",
                started.elapsed()
            );
        }
    }
}
