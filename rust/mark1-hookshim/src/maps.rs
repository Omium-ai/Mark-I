//! Per-agent field maps AS DATA (04 §5, 08 §5 rule 1): the vendor-name →
//! `m1p.v1` mapping ships in bundle data so a vendor field rename is an
//! `agent_maps` push reaching the fleet in minutes, not a shim release. The
//! binary fixes only the *kinds* (which body a hook becomes); every vendor
//! string is table data.

use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;

/// The shipped defaults, one per pinned fixture corpus (08 §5 rule 3: the
/// fixture produces the field map; nothing is authored from memory) —
/// `conformance/hooks/claudecode@2.1.251`, `conformance/hooks/codex@0.154.0`,
/// `conformance/hooks/gemini@0.59.0`, `conformance/hooks/opencode@1.18.31`,
/// `conformance/hooks/copilot@1.0.85` and `conformance/hooks/cursor@2026.09.10-fd3934a`.
const BUILTIN_CLAUDECODE: &str = include_str!("../maps/claudecode.json");
const BUILTIN_CODEX: &str = include_str!("../maps/codex.json");
const BUILTIN_GEMINI: &str = include_str!("../maps/gemini.json");
const BUILTIN_OPENCODE: &str = include_str!("../maps/opencode.json");
const BUILTIN_COPILOT: &str = include_str!("../maps/copilot.json");
const BUILTIN_CURSOR: &str = include_str!("../maps/cursor.json");

/// Which agent exec'd us: argv[1] (cursor's fragment writes `<shim> cursor`,
/// the one spelling every OS shell accepts), else `MARK1_AGENT` (codex's
/// fragment, gemini's and copilot's hook entries, opencode's plugin), else
/// claudecode, whose fragment predates both. The payloads are otherwise
/// indistinguishable — all carry `hook_event_name` and `session_id` — so
/// nothing here sniffs shape, which is also why Cursor running a claudecode
/// entry (it loads ~/.claude/settings.json too) maps to nothing: its `stop`
/// is not claudecode's `Stop`. An unknown name selects no builtin: emit
/// nothing, never guess (08 §5 rule 2).
fn agent() -> String {
    agent_from(std::env::args().nth(1), std::env::var("MARK1_AGENT").ok())
}

fn agent_from(arg: Option<String>, env: Option<String>) -> String {
    arg.filter(|a| !a.is_empty())
        .or(env)
        .unwrap_or_else(|| "claudecode".to_owned())
}

fn builtin(agent: &str) -> Option<&'static str> {
    match agent {
        "claudecode" => Some(BUILTIN_CLAUDECODE),
        "codex" => Some(BUILTIN_CODEX),
        "gemini" => Some(BUILTIN_GEMINI),
        "opencode" => Some(BUILTIN_OPENCODE),
        "copilot" => Some(BUILTIN_COPILOT),
        "cursor" => Some(BUILTIN_CURSOR),
        _ => None,
    }
}

#[derive(Deserialize)]
pub struct FieldMap {
    pub agent: String,
    pub agent_version: String,
    /// Vendor field naming the hook event (`hook_event_name` on claudecode).
    pub event_field: String,
    /// Vendor field(s) carrying the session id, tried in order; a string or a list in the map.
    #[serde(deserialize_with = "one_or_many")]
    pub session_id_field: Vec<String>,
    pub events: HashMap<String, EventRule>,
}

fn one_or_many<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }
    Ok(match OneOrMany::deserialize(d)? {
        OneOrMany::One(s) => vec![s],
        OneOrMany::Many(v) => v,
    })
}

#[derive(Deserialize)]
pub struct EventRule {
    /// Binary-fixed semantic: which `m1p.v1` body this hook becomes — see
    /// `emit::build`. Unknown kinds map to nothing (never guess, 08 §5).
    pub kind: String,
    /// Present ⇒ this hook is a gate (04 §5 step 5); absent ⇒ pure observer.
    /// WHICH hooks gate is bundle data for the same reason the field names
    /// are: 08 §5.1 makes `Stop` the stop-gate and `SubagentStop`
    /// observer-only, and that is a vendor fact, not a shim semantic.
    #[serde(default)]
    pub gate: Option<GateRule>,
    /// logical name (binary-fixed) → vendor JSON field (bundle data).
    pub fields: HashMap<String, String>,
}

#[derive(Deserialize)]
pub struct GateRule {
    /// `m1p.v1.GateKind`, named in data: "stop" | "tool".
    pub kind: String,
    /// The shim's own wall budget for the whole gate round trip, in ms. 08
    /// §4.4 bounds it from ABOVE by the fragment's hook timeout minus 10 ms
    /// (`timeout: 30` for Stop, 08 §5.1) — an upper bound, not the value. The
    /// value is what the round trip actually costs: 04 §2.3 makes the daemon's
    /// side a ≤5 ms cache read, so 250 ms is the whole exchange getting what
    /// 08 §4.4 already grants ONE event write, and 50x the documented read.
    ///
    /// Sized this way because the fragment's number is a kill deadline, not a
    /// budget: at 30 s a daemon that accepts the connection and never answers
    /// cost 31.4 s per turn end against 217 ms for a daemon that was not
    /// running at all — a half-dead Mark 1 145x worse than an absent one, on
    /// the hook that fires every turn. The shim subtracts 08 §4.4's 10 ms
    /// margin to get the agent-facing deadline it states on the wire.
    pub budget_ms: u32,
}

impl FieldMap {
    /// The rule this payload's hook maps to, or None when the hook is
    /// unmapped (04 §5 step 2: emit nothing speculative).
    pub fn rule(&self, payload: &serde_json::Value) -> Option<&EventRule> {
        self.events.get(payload.get(&self.event_field)?.as_str()?)
    }
}

/// The daemon-materialized cache wins over the builtin so a bundle push
/// updates behavior with no binary change (FR-AGENT-001); any read or parse
/// failure falls back to the shipped map rather than guessing.
pub fn load(home: Option<&Path>) -> FieldMap {
    let agent = agent();
    if let Some(h) = home {
        // 04 §5: ~/.omium/mark1/maps/<agent>.bin, pre-compiled by mark1d.
        // ponytail: "pre-compiled" is JSON bytes in v1 — parse cost on a
        // ~1 KiB map is microseconds; a binary format buys nothing until a
        // map is large enough to measure.
        let cached = h.join(".omium/mark1/maps").join(format!("{agent}.bin"));
        if let Ok(bytes) = std::fs::read(cached) {
            if let Ok(map) = serde_json::from_slice::<FieldMap>(&bytes) {
                return map;
            }
        }
    }
    // The builtin is compiled from a committed fixture-derived file; if it
    // ever failed to parse the binary itself is broken, and emitting nothing
    // (empty map) is the only honest fallback — never a panic (04 §5).
    builtin(&agent)
        .and_then(|b| serde_json::from_str(b).ok())
        .unwrap_or(FieldMap {
            agent,
            agent_version: String::new(),
            event_field: String::new(),
            session_id_field: Vec::new(),
            events: HashMap::new(),
        })
}

/// `conf_hooks_codex_0.154.0_replay`, hook half: every committed codex
/// fixture body through the builtin codex map, asserting the body kind.
#[cfg(test)]
mod codex_map {
    use super::*;
    use m1p_wire::pb::event::Body;

    fn fixture(name: &str) -> serde_json::Value {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../conformance/hooks/codex/v0.154.0/hooks")
            .join(format!("{name}.json"));
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    #[test]
    fn builtin_codex_map_parses_and_covers_every_fixture() {
        let map: FieldMap = serde_json::from_str(BUILTIN_CODEX).unwrap();
        assert_eq!(map.agent, "codex");
        assert_eq!(map.agent_version, "0.154.0");
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../conformance/hooks/codex/v0.154.0/hooks");
        let mut on_disk: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| {
                e.unwrap()
                    .file_name()
                    .to_string_lossy()
                    .trim_end_matches(".json")
                    .to_owned()
            })
            .collect();
        on_disk.sort();
        let mut mapped: Vec<String> = map.events.keys().cloned().collect();
        mapped.sort();
        assert_eq!(
            mapped, on_disk,
            "map events must equal the pinned fixture bodies"
        );
        for (event, rule) in &map.events {
            let payload = fixture(event);
            assert!(map.rule(&payload).is_some(), "{event}: unmapped");
            for vendor in rule.fields.values() {
                assert!(
                    payload.get(vendor).is_some(),
                    "{event}: field {vendor} absent from the vendor schema body"
                );
            }
        }
    }

    #[test]
    fn codex_fixture_replay() {
        let map: FieldMap = serde_json::from_str(BUILTIN_CODEX).unwrap();
        let expect = |name: &str, f: &dyn Fn(&Body) -> bool| {
            let ev = crate::emit::build(&map, &fixture(name))
                .unwrap_or_else(|| panic!("{name}: no event"));
            assert!(f(ev.body.as_ref().unwrap()), "{name}: wrong body");
            assert_eq!(
                ev.session_id,
                uuid::Uuid::parse_str("019965a0-0000-7000-8000-00000000aa01")
                    .unwrap()
                    .as_bytes()
            );
        };
        expect(
            "SessionStart",
            &|b| matches!(b, Body::SessionStart(s) if s.agent == "codex" && s.agent_version == "0.154.0"),
        );
        expect("SessionEnd", &|b| matches!(b, Body::SessionEnd(_)));
        expect(
            "UserPromptSubmit",
            &|b| matches!(b, Body::Turn(t) if t.initiator == m1p_wire::pb::Initiator::Human as i32),
        );
        expect(
            "PreToolUse",
            &|b| matches!(b, Body::ToolUse(t) if t.tool_name == "shell" && t.tool_use_id == "call_SynthFixtureTTTTTTTT" && t.status == m1p_wire::pb::ToolStatus::Unspecified as i32),
        );
        expect(
            "PostToolUse",
            &|b| matches!(b, Body::ToolUse(t) if t.tool_name == "shell" && t.status == m1p_wire::pb::ToolStatus::Ok as i32),
        );
        expect(
            "Stop",
            &|b| matches!(b, Body::Turn(t) if t.initiator == m1p_wire::pb::Initiator::Agent as i32),
        );
        expect("SubagentStop", &|b| matches!(b, Body::Turn(_)));
        let stop = map.rule(&fixture("Stop")).unwrap();
        assert_eq!(
            stop.gate.as_ref().map(|g| (g.kind.as_str(), g.budget_ms)),
            Some(("stop", 250))
        );
        for none in ["SubagentStart", "PreCompact", "PostCompact", "Interrupt"] {
            assert!(map.rule(&fixture(none)).is_some_and(|r| r.gate.is_none()));
            assert!(
                crate::emit::build(&map, &fixture(none)).is_none(),
                "{none}: mapped-to-nothing must emit nothing"
            );
        }
    }

    #[test]
    fn agent_comes_from_argv_then_env_then_claudecode() {
        assert_eq!(
            agent_from(Some("cursor".into()), Some("codex".into())),
            "cursor"
        );
        assert_eq!(
            agent_from(Some(String::new()), Some("codex".into())),
            "codex"
        );
        assert_eq!(agent_from(None, Some("codex".into())), "codex");
        assert_eq!(agent_from(None, None), "claudecode");
    }

    #[test]
    fn unknown_agent_selects_no_builtin() {
        assert!(builtin("crush").is_none());
        assert!(builtin("").is_none());
        for agent in [
            "claudecode",
            "codex",
            "gemini",
            "opencode",
            "copilot",
            "cursor",
        ] {
            assert!(builtin(agent).is_some(), "{agent}");
        }
    }
}

/// One fixture-corpus check shared by the gemini and opencode maps: the map's
/// events equal the committed hook bodies and every mapped vendor field is on
/// the body it names.
#[cfg(test)]
fn assert_map_covers_corpus(map: &FieldMap, fixtures: &str) {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(fixtures);
    let mut on_disk: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| {
            e.unwrap()
                .file_name()
                .to_string_lossy()
                .trim_end_matches(".json")
                .to_owned()
        })
        .collect();
    on_disk.sort();
    let mut mapped: Vec<String> = map.events.keys().cloned().collect();
    mapped.sort();
    assert_eq!(
        mapped, on_disk,
        "map events must equal the pinned fixture bodies"
    );
    for (event, rule) in &map.events {
        let payload: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join(format!("{event}.json"))).unwrap())
                .unwrap();
        assert!(map.rule(&payload).is_some(), "{event}: unmapped");
        for vendor in rule.fields.values() {
            assert!(
                payload.get(vendor).is_some(),
                "{event}: field {vendor} absent from the vendor body"
            );
        }
    }
}

/// `conf_hooks_gemini_0.59.0_replay`, hook half.
#[cfg(test)]
mod gemini_map {
    use super::*;
    use m1p_wire::pb::event::Body;

    const FIXTURES: &str = "../../conformance/hooks/gemini/v0.59.0/hooks";

    fn fixture(name: &str) -> serde_json::Value {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join(FIXTURES)
            .join(format!("{name}.json"));
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    #[test]
    fn builtin_gemini_map_parses_and_covers_every_fixture() {
        let map: FieldMap = serde_json::from_str(BUILTIN_GEMINI).unwrap();
        assert_eq!(map.agent, "gemini");
        assert_eq!(map.agent_version, "0.59.0");
        assert_map_covers_corpus(&map, FIXTURES);
    }

    #[test]
    fn gemini_fixture_replay() {
        let map: FieldMap = serde_json::from_str(BUILTIN_GEMINI).unwrap();
        let session = uuid::Uuid::parse_str("6f1e2d3c-0000-4000-8000-00000000aa01").unwrap();
        let expect = |name: &str, f: &dyn Fn(&Body) -> bool| {
            let ev = crate::emit::build(&map, &fixture(name))
                .unwrap_or_else(|| panic!("{name}: no event"));
            assert!(f(ev.body.as_ref().unwrap()), "{name}: wrong body");
            assert_eq!(ev.session_id, session.as_bytes());
        };
        expect(
            "SessionStart",
            &|b| matches!(b, Body::SessionStart(s) if s.agent == "gemini" && s.agent_version == "0.59.0"),
        );
        expect("SessionEnd", &|b| matches!(b, Body::SessionEnd(_)));
        expect(
            "BeforeAgent",
            &|b| matches!(b, Body::Turn(t) if t.initiator == m1p_wire::pb::Initiator::Human as i32),
        );
        // No tool-call id exists on this surface (BeforeToolInput): tool_use_id is empty, not guessed.
        expect(
            "BeforeTool",
            &|b| matches!(b, Body::ToolUse(t) if t.tool_name == "run_shell_command" && t.tool_use_id.is_empty() && t.status == m1p_wire::pb::ToolStatus::Unspecified as i32),
        );
        expect(
            "AfterTool",
            &|b| matches!(b, Body::ToolUse(t) if t.tool_name == "run_shell_command" && t.status == m1p_wire::pb::ToolStatus::Ok as i32),
        );
        expect(
            "AfterAgent",
            &|b| matches!(b, Body::Turn(t) if t.initiator == m1p_wire::pb::Initiator::Agent as i32),
        );
        let stop = map.rule(&fixture("AfterAgent")).unwrap();
        assert_eq!(
            stop.gate.as_ref().map(|g| (g.kind.as_str(), g.budget_ms)),
            Some(("stop", 250))
        );
        assert_eq!(
            stop.fields.get("stop_hook_active").map(String::as_str),
            Some("stop_hook_active")
        );
        assert!(map
            .rule(&fixture("PreCompress"))
            .is_some_and(|r| r.gate.is_none()));
        assert!(
            crate::emit::build(&map, &fixture("PreCompress")).is_none(),
            "PreCompress: mapped-to-nothing must emit nothing"
        );
    }
}

/// `conf_hooks_opencode_1.18.31_replay`, hook half: the bodies mark1.js
/// composes, through the builtin opencode map.
#[cfg(test)]
mod opencode_map {
    use super::*;
    use m1p_wire::pb::event::Body;

    const FIXTURES: &str = "../../conformance/hooks/opencode/v1.18.31/hooks";

    fn fixture(name: &str) -> serde_json::Value {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join(FIXTURES)
            .join(format!("{name}.json"));
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    #[test]
    fn builtin_opencode_map_parses_and_covers_every_fixture() {
        let map: FieldMap = serde_json::from_str(BUILTIN_OPENCODE).unwrap();
        assert_eq!(map.agent, "opencode");
        assert_eq!(map.agent_version, "1.18.31");
        assert_map_covers_corpus(&map, FIXTURES);
    }

    #[test]
    fn opencode_fixture_replay() {
        let map: FieldMap = serde_json::from_str(BUILTIN_OPENCODE).unwrap();
        // UUIDv5(NameSpaceURL, "opencode:ses_0199a1b2c3d4SynthFixtuAA01") — the
        // plugin's recipe; opencode.SessionUUID and selfcheck.py derive the same value.
        let session = uuid::Uuid::parse_str("27777fa2-d57a-5838-b8bd-bf4c0f358055").unwrap();
        let expect = |name: &str, f: &dyn Fn(&Body) -> bool| {
            let ev = crate::emit::build(&map, &fixture(name))
                .unwrap_or_else(|| panic!("{name}: no event"));
            assert!(f(ev.body.as_ref().unwrap()), "{name}: wrong body");
            assert_eq!(
                ev.session_id,
                session.as_bytes(),
                "{name}: session_id is not the derived UUIDv5"
            );
        };
        expect(
            "session.created",
            &|b| matches!(b, Body::SessionStart(s) if s.agent == "opencode" && s.agent_version == "1.18.31"),
        );
        expect(
            "chat.message",
            &|b| matches!(b, Body::Turn(t) if t.initiator == m1p_wire::pb::Initiator::Human as i32),
        );
        expect(
            "tool.execute.before",
            &|b| matches!(b, Body::ToolUse(t) if t.tool_name == "bash" && t.tool_use_id == "call_SynthFixtureTTTTTTTT" && t.status == m1p_wire::pb::ToolStatus::Unspecified as i32),
        );
        expect(
            "tool.execute.after",
            &|b| matches!(b, Body::ToolUse(t) if t.tool_name == "bash" && t.tool_use_id == "call_SynthFixtureTTTTTTTT" && t.status == m1p_wire::pb::ToolStatus::Ok as i32),
        );
        expect(
            "session.idle",
            &|b| matches!(b, Body::Turn(t) if t.initiator == m1p_wire::pb::Initiator::Agent as i32),
        );
        for rule in map.events.values() {
            assert!(
                rule.gate.is_none(),
                "opencode has no gate hook on this surface"
            );
        }
    }
}

/// `conf_hooks_copilot_1.0.85_replay`, hook half: the PascalCase bodies the
/// CLI recorded, through the builtin copilot map.
#[cfg(test)]
mod copilot_map {
    use super::*;
    use m1p_wire::pb::event::Body;

    const FIXTURES: &str = "../../conformance/hooks/copilot/v1.0.85/hooks";

    fn fixture(name: &str) -> serde_json::Value {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join(FIXTURES)
            .join(format!("{name}.json"));
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    #[test]
    fn builtin_copilot_map_parses_and_covers_every_fixture() {
        let map: FieldMap = serde_json::from_str(BUILTIN_COPILOT).unwrap();
        assert_eq!(map.agent, "copilot");
        assert_eq!(map.agent_version, "1.0.85");
        assert_map_covers_corpus(&map, FIXTURES);
    }

    #[test]
    fn copilot_fixture_replay() {
        let map: FieldMap = serde_json::from_str(BUILTIN_COPILOT).unwrap();
        // Every body is from recording aa01 except PostToolUseFailure, which only the
        // failing-view recording aa02 produced (README).
        let expect = |name: &str, f: &dyn Fn(&Body) -> bool| {
            let ev = crate::emit::build(&map, &fixture(name))
                .unwrap_or_else(|| panic!("{name}: no event"));
            assert!(f(ev.body.as_ref().unwrap()), "{name}: wrong body");
            let recording = if name == "PostToolUseFailure" {
                "aa02"
            } else {
                "aa01"
            };
            let session =
                uuid::Uuid::parse_str(&format!("c0910000-0000-4000-8000-00000000{recording}"))
                    .unwrap();
            assert_eq!(ev.session_id, session.as_bytes(), "{name}");
        };
        expect(
            "SessionStart",
            &|b| matches!(b, Body::SessionStart(s) if s.agent == "copilot" && s.agent_version == "1.0.85"),
        );
        expect("SessionEnd", &|b| matches!(b, Body::SessionEnd(_)));
        expect(
            "UserPromptSubmit",
            &|b| matches!(b, Body::Turn(t) if t.initiator == m1p_wire::pb::Initiator::Human as i32),
        );
        // The PascalCase body names the tool by its Claude name and carries no call id (README).
        expect(
            "PreToolUse",
            &|b| matches!(b, Body::ToolUse(t) if t.tool_name == "Bash" && t.tool_use_id.is_empty() && t.status == m1p_wire::pb::ToolStatus::Unspecified as i32),
        );
        expect(
            "PostToolUse",
            &|b| matches!(b, Body::ToolUse(t) if t.tool_name == "Bash" && t.status == m1p_wire::pb::ToolStatus::Ok as i32),
        );
        expect(
            "PostToolUseFailure",
            &|b| matches!(b, Body::ToolUse(t) if t.tool_name == "Read" && t.status == m1p_wire::pb::ToolStatus::Error as i32),
        );
        expect(
            "Stop",
            &|b| matches!(b, Body::Turn(t) if t.initiator == m1p_wire::pb::Initiator::Agent as i32),
        );
        let stop = map.rule(&fixture("Stop")).unwrap();
        assert_eq!(
            stop.gate.as_ref().map(|g| (g.kind.as_str(), g.budget_ms)),
            Some(("stop", 250))
        );
        assert_eq!(
            stop.fields.get("stop_hook_active").map(String::as_str),
            Some("stop_hook_active")
        );
        let pitfall = crate::context::plan(
            map.rule(&fixture("PostToolUseFailure")).unwrap(),
            &fixture("PostToolUseFailure"),
        )
        .unwrap();
        assert_eq!(pitfall.tool_name, "Read");
        assert_eq!(pitfall.error, "Path does not exist");
        for (name, rule) in &map.events {
            assert!(
                name == "Stop" || rule.gate.is_none(),
                "{name}: only Stop gates on this surface"
            );
        }
    }
}

/// `conf_hooks_cursor_2026.09.10_replay`, hook half: the bodies composed from
/// the CLI's payload builders, through the builtin cursor map.
#[cfg(test)]
mod cursor_map {
    use super::*;
    use m1p_wire::pb::event::Body;

    const FIXTURES: &str = "../../conformance/hooks/cursor/v2026.09.10-fd3934a/hooks";

    fn fixture(name: &str) -> serde_json::Value {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join(FIXTURES)
            .join(format!("{name}.json"));
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    #[test]
    fn builtin_cursor_map_parses_and_covers_every_fixture() {
        let map: FieldMap = serde_json::from_str(BUILTIN_CURSOR).unwrap();
        assert_eq!(map.agent, "cursor");
        assert_eq!(map.agent_version, "2026.09.10-fd3934a");
        assert_eq!(map.session_id_field, ["session_id", "conversation_id"]);
        assert_map_covers_corpus(&map, FIXTURES);
    }

    /// The IDE's non-session hooks carry `conversation_id` and no `session_id`
    /// (docs: `session_id` is listed on sessionStart/sessionEnd only).
    #[test]
    fn cursor_session_id_falls_back_to_conversation_id() {
        let map: FieldMap = serde_json::from_str(BUILTIN_CURSOR).unwrap();
        let mut body = fixture("preToolUse");
        body.as_object_mut().unwrap().remove("session_id");
        let ev = crate::emit::build(&map, &body).expect("conversation_id alone must still emit");
        assert_eq!(
            ev.session_id,
            uuid::Uuid::parse_str("cc0e0000-0000-4000-8000-00000000aa01")
                .unwrap()
                .as_bytes()
        );
        body.as_object_mut().unwrap().remove("conversation_id");
        assert!(
            crate::emit::build(&map, &body).is_none(),
            "neither id: emit nothing"
        );
    }

    #[test]
    fn cursor_fixture_replay() {
        let map: FieldMap = serde_json::from_str(BUILTIN_CURSOR).unwrap();
        // session_id is the conversation id (runner: session_id ?? conversation_id).
        let session = uuid::Uuid::parse_str("cc0e0000-0000-4000-8000-00000000aa01").unwrap();
        let expect = |name: &str, f: &dyn Fn(&Body) -> bool| {
            let ev = crate::emit::build(&map, &fixture(name))
                .unwrap_or_else(|| panic!("{name}: no event"));
            assert!(f(ev.body.as_ref().unwrap()), "{name}: wrong body");
            assert_eq!(ev.session_id, session.as_bytes());
        };
        expect(
            "sessionStart",
            &|b| matches!(b, Body::SessionStart(s) if s.agent == "cursor" && s.agent_version == "2026.09.10-fd3934a"),
        );
        expect("sessionEnd", &|b| matches!(b, Body::SessionEnd(_)));
        expect(
            "beforeSubmitPrompt",
            &|b| matches!(b, Body::Turn(t) if t.initiator == m1p_wire::pb::Initiator::Human as i32),
        );
        expect(
            "preToolUse",
            &|b| matches!(b, Body::ToolUse(t) if t.tool_name == "Shell" && t.tool_use_id == "call_SynthFixtureTTTTTTTT" && t.status == m1p_wire::pb::ToolStatus::Unspecified as i32),
        );
        // `duration`, not `duration_ms`, on the tool steps (cli-hook-dispatch.js).
        expect(
            "postToolUse",
            &|b| matches!(b, Body::ToolUse(t) if t.tool_name == "Shell" && t.duration_ms == 42 && t.status == m1p_wire::pb::ToolStatus::Ok as i32),
        );
        expect(
            "postToolUseFailure",
            &|b| matches!(b, Body::ToolUse(t) if t.tool_name == "Read" && t.tool_use_id == "call_SynthFixtureTTTTTTT2" && t.duration_ms == 7 && t.status == m1p_wire::pb::ToolStatus::Error as i32),
        );
        expect(
            "stop",
            &|b| matches!(b, Body::Turn(t) if t.initiator == m1p_wire::pb::Initiator::Agent as i32),
        );
        expect("subagentStop", &|b| matches!(b, Body::Turn(_)));
        let stop = map.rule(&fixture("stop")).unwrap();
        assert_eq!(
            stop.gate.as_ref().map(|g| (g.kind.as_str(), g.budget_ms)),
            Some(("stop", 250))
        );
        // No stop_hook_active on this surface: the vendor's loop_limit is the cap, and the
        // shim must not read a field the payload never carries.
        assert!(!stop.fields.contains_key("stop_hook_active"));
        assert!(map
            .rule(&fixture("subagentStop"))
            .is_some_and(|r| r.gate.is_none()));
        let pitfall = crate::context::plan(
            map.rule(&fixture("postToolUseFailure")).unwrap(),
            &fixture("postToolUseFailure"),
        )
        .unwrap();
        assert_eq!(pitfall.error, "Path does not exist");
        assert!(!pitfall.is_interrupt);
    }
}
