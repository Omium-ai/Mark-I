#!/usr/bin/env python3
"""Audit that the frozen cursor fixtures and expectations.json agree — see README.md.

Not the adapter under test (the CI gate is `conf_hooks_cursor_2026.09.10_replay`: the shim
map over these bodies plus the fragment tests). This checks every hook body against the
VENDOR's own field lists — the agent.v1 proto messages the CLI dispatch switch renders
(`schema/hooks_pb.fields.json`, `schema/cli-hook-dispatch.js`) plus the base fields the
runner adds (`schema/cli-hook-runner.js`), or the docs reference for the two IDE-only
events — checks every event name against the vendor's vocabulary in
`schema/hooks-module.js`, proves the stop-output translation the gate relies on is in that
module, and enforces the sanitization rule: zero recording-machine identity.
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).parent

FORBIDDEN = [b"anurag", b"omium", b"Omium", b"OMIUM", b"scratchpad", b"claude-1000"]

# Fields the runner (executeHookForStep) adds to every non-workspaceOpen payload.
RUNNER_BASE = {
    "session_id",
    "hook_event_name",
    "cursor_version",
    "workspace_roots",
    "user_email",
    "transcript_path",
}
# The dispatch switch's leading object: conversation_id, generation_id, model, then U4(e).
DISPATCH_BASE = {"conversation_id", "generation_id", "model"}
U4_OPTIONAL = {"model_id", "model_params"}
# Fields the dispatch switch renders per step, from cli-hook-dispatch.js (duration, not
# duration_ms, on the tool steps; token fields omitted when the runtime leaves them unset).
DISPATCHED = {
    "beforeSubmitPrompt": {"prompt", "attachments", "composer_mode"},
    "preToolUse": {"tool_name", "tool_input", "tool_use_id", "cwd"},
    "postToolUse": {"tool_name", "tool_input", "tool_output", "duration", "tool_use_id", "cwd"},
    "postToolUseFailure": {
        "tool_name",
        "tool_input",
        "error_message",
        "failure_type",
        "duration",
        "tool_use_id",
        "is_interrupt",
    },
    "stop": {"status", "loop_count"},
    "subagentStop": {
        "subagent_id",
        "subagent_type",
        "status",
        "duration_ms",
        "summary",
        "parent_conversation_id",
        "message_count",
        "tool_call_count",
        "modified_files",
        "git_branch",
        "loop_count",
        "task",
        "description",
    },
}
STOP_TOKEN_FIELDS = {"input_tokens", "output_tokens", "cache_read_tokens", "cache_write_tokens"}
# IDE-only events: fields per the docs reference (no CLI builder exists at this pin).
IDE_ONLY = {
    "sessionStart": {"is_background_agent", "composer_mode"},
    "sessionEnd": {"reason", "duration_ms", "is_background_agent", "final_status"},
}
ENUMS = {
    ("stop", "status"): {"completed", "aborted", "error"},
    ("postToolUseFailure", "failure_type"): {"error", "timeout", "permission_denied"},
    ("sessionEnd", "reason"): {"completed", "aborted", "error", "window_close", "user_close"},
    ("sessionStart", "composer_mode"): {"agent", "ask", "edit"},
}
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def vendor_events(module: str) -> set:
    m = re.search(r"const r = \{(.*?)\},\n\s+s = \{", module, re.S)
    return set(re.findall(r'(\w+): "\w+"', m.group(1))) if m else set()


def main() -> int:
    failures = []
    exp = json.loads((ROOT / "expectations.json").read_text())
    module = (ROOT / "schema" / "hooks-module.js").read_text()
    dispatch = (ROOT / "schema" / "cli-hook-dispatch.js").read_text()
    pb = json.loads((ROOT / "schema" / "hooks_pb.fields.json").read_text())["messages"]

    for p in ROOT.rglob("*"):
        if p.is_file() and p.name not in {"README.md", "selfcheck.py"}:
            b = p.read_bytes()
            for word in FORBIDDEN:
                if word in b:
                    failures.append(f"{p.relative_to(ROOT)}: carries {word!r}")

    events = vendor_events(module)
    if len(events) < 20 or "stop" not in events:
        failures.append(f"could not read the vendor event vocabulary ({len(events)} names)")
    if "followup_message: r.reason.trim()" not in module:
        failures.append("hooks-module.js lost the decision:block -> followup_message translation")
    if "Stop: r.stop" not in module or "PreToolUse: r.preToolUse" not in module:
        failures.append("hooks-module.js lost the Claude-name translation table")
    cli_dispatched = set(re.findall(r'case "(\w+)": \{', dispatch))
    if cli_dispatched != set(exp["hooks"]["cli_dispatched_at_pin"]):
        failures.append(f"dispatch switch cases {sorted(cli_dispatched)} != expectations")
    for ev in exp["hooks"]["ide_only_at_pin"]:
        if ev in cli_dispatched:
            failures.append(f"{ev} is marked IDE-only but the CLI dispatches it")

    registered = set(exp["hooks"]["registered"])
    on_disk = {p.stem for p in (ROOT / "hooks").glob("*.json")}
    if on_disk != registered:
        failures.append(f"hook bodies {sorted(on_disk)} != registered {sorted(registered)}")
    for name in on_disk:
        body = json.loads((ROOT / "hooks" / f"{name}.json").read_text())
        if name not in events:
            failures.append(f"hooks/{name}.json: not a vendor event name")
        if body.get("hook_event_name") != name:
            failures.append(f"hooks/{name}.json: hook_event_name {body.get('hook_event_name')!r}")
        for f in ("session_id", "conversation_id", "generation_id"):
            if not UUID.match(str(body.get(f, ""))):
                failures.append(f"hooks/{name}.json: {f} is not a UUID (the shim requires one)")
        if body.get("session_id") != body.get("conversation_id"):
            failures.append(
                f"hooks/{name}.json: session_id != conversation_id (runner k = session_id ?? conversation_id)"
            )
        present = set(body)
        if name in DISPATCHED:
            want = RUNNER_BASE | DISPATCH_BASE | DISPATCHED[name]
            extra = present - want - U4_OPTIONAL
            missing = want - present
            if name == "stop":
                extra -= STOP_TOKEN_FIELDS
            if extra or missing:
                failures.append(
                    f"hooks/{name}.json: extra {sorted(extra)} missing {sorted(missing)}"
                )
            query = pb.get(name[0].upper() + name[1:] + "RequestQuery", [])
            rendered = DISPATCHED[name] | DISPATCH_BASE | U4_OPTIONAL
            for f in rendered - {"duration"}:
                if f not in query:
                    failures.append(
                        f"hooks/{name}.json: {f} is not a proto field the runtime sends"
                    )
        elif name in IDE_ONLY:
            want = RUNNER_BASE | DISPATCH_BASE | IDE_ONLY[name]
            extra = present - want - U4_OPTIONAL
            missing = want - present
            if extra or missing:
                failures.append(
                    f"hooks/{name}.json: extra {sorted(extra)} missing {sorted(missing)}"
                )
        for (ev, field), allowed in ENUMS.items():
            if ev == name and body.get(field) not in allowed:
                failures.append(
                    f"hooks/{name}.json: {field}={body.get(field)!r} not in {sorted(allowed)}"
                )
        if name == "stop" and STOP_TOKEN_FIELDS & present:
            failures.append(
                "hooks/stop.json: token fields are unconfirmed live and must stay absent"
            )
    if exp["usage_events_expected"] != 0 or exp["usage_class"] != "none":
        failures.append("expectations claim a Usage class this surface cannot carry")
    if (ROOT / "transcripts").exists():
        failures.append("a transcripts tree exists but no durable local usage surface is GO")

    for f in failures:
        print("FAIL:", f)
    print("ok" if not failures else f"{len(failures)} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
