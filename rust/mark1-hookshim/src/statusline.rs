//! `mark1-hookshim statusline`: Claude Code pipes its status-line JSON here (https://code.claude.com/docs/en/statusline); the rate-limit slice is filed under `~/.omium/mark1/claude/` and stdin is replayed to the command the user had before Mark 1 took the slot. No token, no network, no prompt text.

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use serde_json::Value;

use crate::spill::{create_private_dir, open_private_append};

/// Newest lines kept in `ratelimits.jsonl`; over it the file is rewritten atomically.
const MAX_LINES: usize = 2000;

/// The stdin fields filed per record; everything else (cwd, transcript_path, cost) is dropped.
const KEEP: [&str; 4] = ["rate_limits", "model", "context_window", "prompt_cache"];

pub fn run(home: Option<&Path>, record: bool) {
    let mut raw = Vec::new();
    if std::io::stdin()
        .take(crate::MAX_STDIN)
        .read_to_end(&mut raw)
        .is_err()
    {
        raw.clear();
    }
    let Some(dir) = home.map(|h| h.join(".omium/mark1/claude")) else {
        return;
    };
    if record {
        append(&dir, &raw);
    }
    chain(&dir, &raw);
}

fn append(dir: &Path, raw: &[u8]) {
    let Ok(payload) = serde_json::from_slice::<Value>(raw) else {
        return;
    };
    let mut rec = serde_json::Map::new();
    rec.insert("received_at".into(), unix_secs().into());
    for k in KEEP {
        rec.insert(k.into(), payload.get(k).cloned().unwrap_or(Value::Null));
    }
    let Ok(mut line) = serde_json::to_vec(&rec) else {
        return;
    };
    line.push(b'\n');
    if create_private_dir(dir).is_err() {
        return;
    }
    let path = dir.join("ratelimits.jsonl");
    let Ok(mut file) = open_private_append(&path) else {
        return;
    };
    if file.write_all(&line).is_err() {
        return;
    }
    drop(file);
    trim(&path);
}

/// ponytail: read, truncate, rewrite in place (no rename: CON-008 cannot follow a rename); a line appended by a concurrent session between the two is lost, and the next message refiles it.
fn trim(path: &Path) {
    let Ok(data) = std::fs::read(path) else {
        return;
    };
    let extra = data
        .iter()
        .filter(|&&b| b == b'\n')
        .count()
        .saturating_sub(MAX_LINES);
    if extra == 0 {
        return;
    }
    let mut seen = 0;
    let Some(cut) = data.iter().position(|&b| {
        if b == b'\n' {
            seen += 1;
        }
        seen == extra
    }) else {
        return;
    };
    let Ok(mut file) = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
    else {
        return;
    };
    let _ = file.write_all(&data[cut + 1..]);
}

/// Replays stdin to the user's previous status-line command, recorded by the adapter at provision (StatusLinePrevPath); nothing recorded ⇒ Mark 1's own one-liner, so the footer never goes blank.
fn chain(dir: &Path, raw: &[u8]) {
    let prev = std::fs::read(dir.join("statusline.prev.json")).ok();
    let cmd = prev
        .as_deref()
        .and_then(|b| serde_json::from_slice::<Value>(b).ok())
        .and_then(|v| v.get("command")?.as_str().map(str::to_owned));
    let Some(cmd) = cmd else {
        let _ = std::io::stdout().write_all(own_line(raw).as_bytes());
        return;
    };
    let Ok(mut child) = shell(&cmd).stdin(Stdio::piped()).spawn() else {
        return;
    };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(raw);
    }
    let _ = child.wait();
}

#[cfg(unix)]
fn shell(cmd: &str) -> Command {
    let mut c = Command::new("/bin/sh");
    c.arg("-c").arg(cmd);
    c
}

/// ponytail: Claude Code uses Git Bash here and PowerShell only when it is absent; the PowerShell fallback is not built.
#[cfg(not(unix))]
fn shell(cmd: &str) -> Command {
    let mut c = Command::new("bash");
    c.arg("-c").arg(cmd);
    c
}

/// "Mark 1 · claude-opus-5 · 5h 34% · 7d 12%": the model and the two windows Claude Code reports, nothing else.
fn own_line(raw: &[u8]) -> String {
    let v: Value = serde_json::from_slice(raw).unwrap_or(Value::Null);
    let mut parts = vec!["Mark 1".to_owned()];
    if let Some(m) = v
        .pointer("/model/display_name")
        .or_else(|| v.pointer("/model/id"))
        .and_then(Value::as_str)
    {
        parts.push(m.to_owned());
    }
    for (key, label) in [("five_hour", "5h"), ("seven_day", "7d")] {
        if let Some(p) = v
            .pointer(&format!("/rate_limits/{key}/used_percentage"))
            .and_then(Value::as_f64)
        {
            parts.push(format!("{label} {}%", p.round() as i64));
        }
    }
    parts.join(" · ")
}

fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}
