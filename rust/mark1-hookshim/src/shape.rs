//! Hook-shape spill (D-EE for the hook path): per agent and mapped event,
//! `~/.omium/mark1/shape/<agent>/<event>.json` = the payload's top-level
//! key → JSON type (no values, so nothing to redact) plus `missing`, the
//! map's vendor names this payload lacks. mark1d's compat probe reads it, so a
//! vendor rename surfaces as `incompatible` naming the key instead of as
//! silence. Rewritten only when the shape changes; every failure is a no-op.

use std::path::Path;

use crate::maps::FieldMap;

/// Vendor event names are file names here; the map bounds the set, this bounds the bytes.
const MAX_EVENT_NAME: usize = 64;

pub fn record(home: Option<&Path>, map: &FieldMap, payload: &serde_json::Value) {
    let (Some(home), Some(obj)) = (home, payload.as_object()) else {
        return;
    };
    let Some(event) = obj.get(&map.event_field).and_then(|v| v.as_str()) else {
        return;
    };
    let Some(rule) = map.events.get(event) else {
        return;
    };
    if event.is_empty() || event.len() > MAX_EVENT_NAME || event.contains(['/', '\\']) {
        return;
    }
    let keys: serde_json::Map<String, serde_json::Value> = obj
        .iter()
        .map(|(k, v)| (k.clone(), kind(v).into()))
        .collect();
    let mut missing: Vec<&str> = rule
        .fields
        .values()
        .filter(|f| !obj.contains_key(*f))
        .map(String::as_str)
        .collect();
    if !map.session_id_field.iter().any(|f| obj.contains_key(f)) {
        missing.extend(map.session_id_field.first().map(String::as_str));
    }
    missing.sort_unstable();
    missing.dedup();
    let Ok(bytes) = serde_json::to_vec(&serde_json::json!({ "keys": keys, "missing": missing }))
    else {
        return;
    };
    let dir = home.join(".omium/mark1/shape").join(&map.agent);
    let path = dir.join(format!("{event}.json"));
    if std::fs::read(&path).is_ok_and(|old| old == bytes) {
        return;
    }
    if crate::spill::create_private_dir(&dir).is_err() {
        return;
    }
    let _ = write_private(&path, &bytes);
}

fn kind(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?
        .write_all(bytes)
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map() -> FieldMap {
        serde_json::from_str(include_str!("../maps/cursor.json")).unwrap()
    }

    #[test]
    fn shape_names_types_and_the_maps_missing_vendor_fields() {
        let home = tempfile::tempdir().unwrap();
        let mut body: serde_json::Value =
            serde_json::from_slice(
                &std::fs::read(std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
                    "../../conformance/hooks/cursor/v2026.09.10-fd3934a/hooks/preToolUse.json",
                ))
                .unwrap(),
            )
            .unwrap();
        record(Some(home.path()), &map(), &body);
        let path = home
            .path()
            .join(".omium/mark1/shape/cursor/preToolUse.json");
        let shape: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(shape["keys"]["tool_name"], "string");
        assert_eq!(shape["keys"]["tool_input"], "object");
        assert_eq!(shape["keys"]["user_email"], "null");
        assert_eq!(shape["missing"], serde_json::json!([]));
        assert!(!std::fs::read_to_string(&path).unwrap().contains("Shell"));

        let obj = body.as_object_mut().unwrap();
        obj.remove("tool_use_id");
        obj.remove("session_id");
        obj.remove("conversation_id");
        record(Some(home.path()), &map(), &body);
        let shape: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            shape["missing"],
            serde_json::json!(["session_id", "tool_use_id"])
        );
    }

    #[test]
    fn unmapped_or_unsafe_events_write_nothing() {
        let home = tempfile::tempdir().unwrap();
        for name in ["notAHook", "../escape", "a/b"] {
            record(
                Some(home.path()),
                &map(),
                &serde_json::json!({ "hook_event_name": name, "session_id": "x" }),
            );
        }
        assert!(!home.path().join(".omium/mark1/shape").exists());
    }
}
