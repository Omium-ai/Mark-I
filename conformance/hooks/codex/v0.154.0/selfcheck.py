#!/usr/bin/env python3
"""Audit that the frozen codex fixtures and expectations.json agree — see README.md.

Not the tailer under test (that is `mark1d.tailers` driven by the codex
adapter's Format; the CI gate is `conf_hooks_codex_0.154.0_replay`). This
re-derives the expected Usage events from the rollout dedupe rule (one per
(thread_id, turn_id, response_id) token_usage_record line, last wins; token_count
snapshots never count) so a mis-frozen fixture is caught here, validates every
hook body against the VENDOR's own generated JSON schema for that event, and
enforces the sanitization rule: fixture payloads carry zero real workspace
content.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parent

FORBIDDEN = [b"anurag", b"omium", b"Omium", b"OMIUM"]

REGISTERED = {
    "SessionStart", "SessionEnd", "UserPromptSubmit", "PreToolUse", "PostToolUse",
    "PreCompact", "PostCompact", "SubagentStart", "SubagentStop", "Stop", "Interrupt",
}

SCHEMA_FILE = {
    "SessionStart": "session-start", "SessionEnd": "session-end",
    "UserPromptSubmit": "user-prompt-submit", "PreToolUse": "pre-tool-use",
    "PostToolUse": "post-tool-use", "PreCompact": "pre-compact",
    "PostCompact": "post-compact", "SubagentStart": "subagent-start",
    "SubagentStop": "subagent-stop", "Stop": "stop", "Interrupt": "interrupt",
}


def validate(body, schema, path=""):
    """The draft-07 subset codex-rs/hooks/src/schema.rs emits: object props,
    required, additionalProperties:false, type, enum, const, NullableString."""
    errs = []
    if schema is True:
        return errs  # `tool_input`/`tool_response` are `true` (any JSON) in the vendor schema
    if "$ref" in schema:
        if schema["$ref"] == "#/definitions/NullableString":
            if not (body is None or isinstance(body, str)):
                errs.append(f"{path}: not a nullable string")
            return errs
        errs.append(f"{path}: unknown $ref {schema['$ref']}")
        return errs
    if "const" in schema and body != schema["const"]:
        errs.append(f"{path}: {body!r} != const {schema['const']!r}")
    if "enum" in schema and body not in schema["enum"]:
        errs.append(f"{path}: {body!r} not in enum {schema['enum']}")
    t = schema.get("type")
    if t is not None:
        types = t if isinstance(t, list) else [t]
        ok = any({
            "object": isinstance(body, dict), "string": isinstance(body, str),
            "boolean": isinstance(body, bool), "null": body is None,
            "array": isinstance(body, list),
        }.get(x, True) for x in types)
        if not ok:
            errs.append(f"{path}: type {type(body).__name__} not in {types}")
    if isinstance(body, dict) and "properties" in schema:
        props = schema["properties"]
        for k in schema.get("required", []):
            if k not in body:
                errs.append(f"{path}: required field {k} missing")
        if schema.get("additionalProperties") is False:
            for k in body:
                if k not in props:
                    errs.append(f"{path}: field {k} not in the vendor schema")
        for k, v in body.items():
            if k in props:
                errs.extend(validate(v, props[k], f"{path}.{k}"))
    return errs


def rollout_usage(path: Path):
    """Reference dedupe: one Usage per (thread_id, turn_id, response_id) from
    top-level token_usage_record lines, last wins, first-seen order; model is
    the last preceding turn_context's model. Nothing else on the stream counts."""
    pending, order, model = {}, [], ""
    for raw in path.read_text().splitlines():
        line = json.loads(raw)
        p = line.get("payload") or {}
        if line.get("type") == "turn_context":
            model = p.get("model", "")
            continue
        if line.get("type") != "token_usage_record":
            continue
        key = (p["thread_id"], p["turn_id"], p["response_id"])
        if key not in pending:
            order.append(key)
        pending[key] = (line, model)
    out = []
    for key in order:
        line, m = pending[key]
        p, u = line["payload"], line["payload"]["usage"]
        out.append({
            "idem_key_inputs": {"session_id": p["thread_id"], "message_id": p["turn_id"],
                                "request_id": p["response_id"]},
            "usage": {"input_tokens": u["input_tokens"], "output_tokens": u["output_tokens"],
                      "cache_creation_input_tokens": u["cache_write_input_tokens"],
                      "cache_read_input_tokens": u["cached_input_tokens"]},
            "model": m, "occurred_at": line["timestamp"], "root_session_id": p["session_id"],
        })
    return out


def exec_usage(path: Path, thread_id):
    turn, out = 0, []
    for raw in path.read_text().splitlines():
        ev = json.loads(raw)
        if ev["type"] == "thread.started":
            thread_id = ev["thread_id"]
        elif ev["type"] == "turn.started":
            turn += 1
        elif ev["type"] == "turn.completed":
            u = ev["usage"]
            out.append({
                "idem_key_inputs": {"session_id": thread_id, "message_id": f"turn:{turn}",
                                    "request_id": f"exec:{thread_id}"},
                "usage": {"input_tokens": u["input_tokens"], "output_tokens": u["output_tokens"],
                          "cache_creation_input_tokens": u["cache_write_input_tokens"],
                          "cache_read_input_tokens": u["cached_input_tokens"]},
            })
    return out


def main() -> int:
    fails = []
    exp = json.loads((ROOT / "transcripts" / "expectations.json").read_text())

    for stream in exp["streams"]:
        got = rollout_usage(ROOT / stream["file"])
        if got != stream["usage_events"]:
            fails.append(f"{stream['file']}: derived events != expectations\n"
                         f"  derived:  {json.dumps(got)}\n"
                         f"  expected: {json.dumps(stream['usage_events'])}")
        if not got:
            fails.append(f"{stream['file']}: no usage lines — replaying it asserts nothing")

    root = exp["workspace_root"]
    for foreign in exp["out_of_workspace_streams"]:
        path = ROOT / foreign["file"]
        if not path.exists():
            fails.append(f"{foreign['file']}: out-of-workspace fixture missing")
            continue
        head = json.loads(path.read_text().splitlines()[0])
        cwd = head.get("payload", {}).get("cwd")
        if head.get("type") != "session_meta" or not cwd:
            fails.append(f"{foreign['file']}: line 1 is not a session_meta with a cwd — unattributable")
        elif cwd == root or cwd.startswith(root + "/"):
            fails.append(f"{foreign['file']}: cwd {cwd} is inside workspace_root — not foreign")
        if not rollout_usage(path):
            fails.append(f"{foreign['file']}: no usage lines — a gate-less tailer would emit nothing anyway")
        ids = {e["idem_key_inputs"]["request_id"] for e in rollout_usage(path)}
        if foreign["never_emit_response_id"] not in ids:
            fails.append(f"{foreign['file']}: never_emit_response_id is not in the stream — the trap is toothless")

    # openai/codex#14489: keep the re-emit corpus honest.
    rr = exp["rate_limit_reemit_case"]
    lines = [json.loads(raw) for raw in (ROOT / rr["file"]).read_text().splitlines()]
    records = [l for l in lines if l["type"] == "token_usage_record"
               and l["payload"]["response_id"] == rr["response_id"]]
    last = records[-1]["payload"]["usage"] if records else None
    snaps = [l for l in lines if l["type"] == "event_msg" and l["payload"].get("type") == "token_count"
             and (l["payload"].get("info") or {}).get("last_token_usage") == last]
    if len(records) != rr["token_usage_record_lines"]:
        fails.append(f"reemit case: {len(records)} token_usage_record lines, expected {rr['token_usage_record_lines']}")
    if len(snaps) != rr["token_count_lines_carrying_it_as_last_usage"]:
        fails.append(f"reemit case: {len(snaps)} token_count snapshots carry the same last usage, expected {rr['token_count_lines_carrying_it_as_last_usage']}")
    if len(snaps) < 2:
        fails.append("reemit case: fewer than 2 snapshots — this corpus no longer exhibits #14489")
    nested = sum(1 for l in lines if l["type"] == "compacted"
                 and (l["payload"].get("latest_token_usage_record") or {}).get("response_id"))
    if nested == 0:
        fails.append("no compacted line nests a token usage record — the nested-copy trap is gone")

    ex = exp["exec_stream"]
    got = exec_usage(ROOT / ex["file"], ex["thread_id"])
    if got != ex["usage_events"]:
        fails.append(f"{ex['file']}: derived events != expectations\n  derived: {json.dumps(got)}")

    for p in sorted(list((ROOT / "hooks").glob("*.json")) + list((ROOT / "transcripts").rglob("*.json*"))
                    + list((ROOT / "exec").glob("*.jsonl"))):
        data = p.read_bytes()
        for needle in FORBIDDEN:
            if needle in data:
                fails.append(f"{p.relative_to(ROOT)}: forbidden identity {needle!r} in fixture")

    on_disk = {p.stem for p in (ROOT / "hooks").glob("*.json")}
    for missing in sorted(REGISTERED - on_disk):
        fails.append(f"hooks/{missing}.json: registered, missing on disk")
    for extra in sorted(on_disk - REGISTERED):
        fails.append(f"hooks/{extra}.json: not a registered event")
    for name in sorted(on_disk & REGISTERED):
        body = json.loads((ROOT / "hooks" / f"{name}.json").read_text())
        schema = json.loads((ROOT / "schema" / f"{SCHEMA_FILE[name]}.command.input.schema.json").read_text())
        for e in validate(body, schema, f"hooks/{name}.json"):
            fails.append(e)
        if body.get("hook_event_name") != name:
            fails.append(f"hooks/{name}.json: hook_event_name != filename")
        if "usage" in json.dumps(body):
            fails.append(f"hooks/{name}.json: token usage in a hook payload contradicts 08 §5 rule 4")

    if fails:
        print("SELFCHECK FAILED")
        for f in fails:
            print(" -", f)
        return 1
    print("selfcheck ok: fixtures, vendor schemas, expectations and sanitization rule agree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
