#!/usr/bin/env python3
"""Audit that the frozen copilot fixtures and expectations.json agree — see README.md.

Not the reader under test (that is `mark1d.tailers` driven by the copilot
adapter's events.jsonl Format; the CI gate is `conf_hooks_copilot_1.0.85_replay`).
This re-derives the expected DIAGNOSTIC events per stream from the vendor's own
`schema/session-events.subset.schema.json` (session.start opens, session.shutdown
closes, nothing else is read), proves the corpus carries NO per-request usage line
(assistant.usage is `ephemeral: true` in the vendor schema and absent on disk),
checks every recorded hook body against the docs' PascalCase field set, and
enforces the sanitization rule: fixture payloads carry zero recording-machine identity.
"""

import datetime
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).parent

FORBIDDEN = [b"anurag", b"omium", b"Omium", b"OMIUM", b"scratchpad", b"claude-1000"]

REGISTERED = {
    "SessionStart",
    "UserPromptSubmit",
    "PreToolUse",
    "PostToolUse",
    "PostToolUseFailure",
    "Stop",
    "SessionEnd",
}

BASE = {"hook_event_name", "session_id", "timestamp", "cwd"}
# Per-event extra fields from docs.github.com hooks-reference (PascalCase / VS Code compatible input).
EXTRA = {
    "SessionStart": {"source", "initial_prompt"},
    "UserPromptSubmit": {"prompt"},
    "PreToolUse": {"tool_name", "tool_input"},
    "PostToolUse": {"tool_name", "tool_input", "tool_result"},
    "PostToolUseFailure": {"tool_name", "tool_input", "error"},
    "Stop": {"transcript_path", "stop_reason", "stop_hook_active"},
    "SessionEnd": {"reason"},
}
ENUMS = {
    ("SessionStart", "source"): {"startup", "resume", "new"},
    ("SessionEnd", "reason"): {"complete", "error", "abort", "timeout", "user_exit"},
    ("Stop", "stop_reason"): {"end_turn"},
}
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def parse_ts(ts: str) -> int:
    return int(datetime.datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp() * 1000)


def stream_diagnostics(path: Path):
    """Reference reading: the first session.start opens, the session.shutdown closes."""
    start = end = None
    usage_lines = 0
    for raw in path.read_text().splitlines():
        line = json.loads(raw)
        if line["type"] == "assistant.usage":
            usage_lines += 1
        if line["type"] == "session.start" and start is None:
            start = line
        if line["type"] == "session.shutdown":
            end = line
    assert start is not None, f"{path}: no session.start"
    assert end is not None, f"{path}: no session.shutdown"
    events = [
        {
            "body": "session_start",
            "agent": "copilot",
            "agent_version": start["data"]["copilotVersion"],
            "capture_path": "CAPTURE_PATH_TRANSCRIPT",
        }
    ]
    reason = (
        "END_REASON_EXIT"
        if end["data"]["shutdownType"] == "routine"
        else "END_REASON_CRASH_DETECTED"
    )
    events.append(
        {
            "body": "session_end",
            "reason": reason,
            "duration_ms": parse_ts(end["timestamp"]) - end["data"]["sessionStartTime"],
            "drained": False,
        }
    )
    return (
        start["data"]["sessionId"],
        start["data"]["context"]["cwd"],
        events,
        usage_lines,
        end["data"]["modelMetrics"],
    )


def main() -> int:
    failures = []
    exp = json.loads((ROOT / "transcripts" / "expectations.json").read_text())
    schema = json.loads((ROOT / "schema" / "session-events.subset.schema.json").read_text())[
        "definitions"
    ]

    # The vendor schema says per-request usage is never persisted; the corpus must agree.
    eph = schema["AssistantUsageEvent"]["properties"]["ephemeral"]
    if eph.get("const") is not True:
        failures.append(
            "vendor schema no longer marks assistant.usage ephemeral: re-spike the Usage class"
        )
    if "modelMetrics" not in schema["ShutdownData"]["required"]:
        failures.append("vendor schema no longer requires modelMetrics on session.shutdown")

    for p in ROOT.rglob("*"):
        if p.is_file() and p.name not in {"README.md", "selfcheck.py"}:
            b = p.read_bytes()
            for word in FORBIDDEN:
                if word in b:
                    failures.append(f"{p.relative_to(ROOT)}: carries {word!r}")

    on_disk = {p.stem for p in (ROOT / "hooks").glob("*.json")}
    if on_disk != REGISTERED or set(exp["hooks"]["registered"]) != REGISTERED:
        failures.append(f"hook bodies {sorted(on_disk)} != registered {sorted(REGISTERED)}")
    for name in on_disk:
        body = json.loads((ROOT / "hooks" / f"{name}.json").read_text())
        if body.get("hook_event_name") != name:
            failures.append(f"hooks/{name}.json: hook_event_name {body.get('hook_event_name')!r}")
        if not UUID.match(body.get("session_id", "")):
            failures.append(f"hooks/{name}.json: session_id is not a UUID (the shim requires one)")
        want = BASE | EXTRA[name]
        if set(body) != want:
            failures.append(f"hooks/{name}.json: fields {sorted(body)} != {sorted(want)}")
        for (ev, field), allowed in ENUMS.items():
            if ev == name and body.get(field) not in allowed:
                failures.append(
                    f"hooks/{name}.json: {field}={body.get(field)!r} not in {sorted(allowed)}"
                )
        for k, v in body.items():
            if isinstance(v, (int, float)) and not isinstance(v, bool) and k != "timestamp":
                failures.append(
                    f"hooks/{name}.json: numeric field {k}: no hook body carries token usage (08 section 5 rule 4)"
                )

    root = exp["workspace_root"]
    seen = set()
    for st in exp["streams"]:
        sid, cwd, events, usage_lines, rollup = stream_diagnostics(ROOT / st["file"])
        seen.add(st["file"])
        if cwd != root or st["cwd"] != cwd or st["session_id"] != sid:
            failures.append(f"{st['file']}: cwd/session mismatch ({cwd}, {sid})")
        if events != st["diagnostic_events"]:
            failures.append(
                f"{st['file']}: diagnostic events\n  derived  {events}\n  expected {st['diagnostic_events']}"
            )
        if usage_lines:
            failures.append(
                f"{st['file']}: {usage_lines} assistant.usage lines persisted — the DIAGNOSTIC-only reading is wrong"
            )
        if sorted(rollup) != st["never_usage_from_rollup"]["models"]:
            failures.append(f"{st['file']}: rollup models {sorted(rollup)}")
        if Path(st["file"]).parent.name != sid:
            failures.append(f"{st['file']}: directory is not the session id")
    for st in exp["out_of_workspace_streams"]:
        sid, cwd, _, _, _ = stream_diagnostics(ROOT / st["file"])
        seen.add(st["file"])
        if cwd == root or st["never_emit_session_id"] != sid:
            failures.append(f"{st['file']}: foreign stream is not foreign ({cwd})")
    on_disk_streams = {
        str(p.relative_to(ROOT))
        for p in (ROOT / "transcripts" / "session-state").rglob("events.jsonl")
    }
    if on_disk_streams != seen:
        failures.append(f"streams on disk {sorted(on_disk_streams)} != expectations {sorted(seen)}")
    if exp["usage_events_expected"] != 0 or exp["usage_class"] != "DIAGNOSTIC":
        failures.append("expectations claim a Usage class this surface cannot carry")

    for f in failures:
        print("FAIL:", f)
    print("ok" if not failures else f"{len(failures)} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
