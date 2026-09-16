#!/usr/bin/env python3
"""Audit that the frozen gemini fixtures and expectations.json agree — see README.md.

Not the tailer under test (that is `mark1d.tailers` driven by the gemini
adapter's Format; the CI gate is `conf_hooks_gemini_0.59.0_replay`). This
re-derives the expected Usage events from the chat-recording dedupe rule (one
per (message id, session) `gemini` line carrying `tokens`, last wins; lines
without tokens never count), checks every hook body's fields and enum values
against the VENDOR's own `schema/hooks-types.ts`, checks every stream's
projectHash against its slug's .project_root, and enforces the sanitization
rule: fixture payloads carry zero real workspace content.
"""
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).parent

FORBIDDEN = [b"anurag", b"omium", b"Omium", b"OMIUM"]

REGISTERED = {"SessionStart", "SessionEnd", "BeforeAgent", "AfterAgent", "BeforeTool", "AfterTool", "PreCompress"}

BASE = {"session_id", "transcript_path", "cwd", "hook_event_name", "timestamp"}
# Per-event fields and the TS enum each string field must come from (hooks-types.ts).
EXTRA = {
    "SessionStart": ({"source"}, {"source": "SessionStartSource"}),
    "SessionEnd": ({"reason"}, {"reason": "SessionEndReason"}),
    "BeforeAgent": ({"prompt"}, {}),
    "AfterAgent": ({"prompt", "prompt_response", "stop_hook_active"}, {}),
    "BeforeTool": ({"tool_name", "tool_input"}, {}),
    "AfterTool": ({"tool_name", "tool_input", "tool_response"}, {}),
    "PreCompress": ({"trigger"}, {"trigger": "PreCompressTrigger"}),
}


def ts_interface_fields(src: str, name: str) -> set:
    m = re.search(r"export interface " + name + r"\b[^{]*\{(.*?)\n\}", src, re.S)
    if not m:
        return set()
    return set(re.findall(r"^\s+(\w+)\??:", m.group(1), re.M))


def ts_enum_values(src: str, name: str) -> set:
    m = re.search(r"export enum " + name + r"\s*\{(.*?)\}", src, re.S)
    return set(re.findall(r"=\s*'([^']+)'", m.group(1))) if m else set()


def chat_usage(path: Path):
    """Reference dedupe: one Usage per (id) `gemini` line with tokens, last
    wins, first-seen order; request_id is chat:<this stream's sessionId>."""
    session, pending, order = "", {}, []
    for raw in path.read_text().splitlines():
        line = json.loads(raw)
        if "id" not in line:
            session = line.get("sessionId", session)
            continue
        if line.get("type") != "gemini" or not line.get("tokens"):
            continue
        if line["id"] not in pending:
            order.append(line["id"])
        pending[line["id"]] = line
    out = []
    for mid in order:
        l = pending[mid]
        t = l["tokens"]
        out.append({
            "message_id": mid, "request_id": "chat:" + session,
            "usage": {"input_tokens": t["input"], "output_tokens": t["output"] + t.get("thoughts", 0),
                      "cache_creation_input_tokens": 0, "cache_read_input_tokens": t["cached"]},
            "model": l["model"], "occurred_at": l["timestamp"],
        })
    return out


def head(path: Path):
    return json.loads(path.read_text().splitlines()[0])


def main() -> int:
    fails = []
    exp = json.loads((ROOT / "transcripts" / "expectations.json").read_text())
    tmp = ROOT / "transcripts" / "tmp"
    markers = {d.name: (d / ".project_root").read_text().strip() for d in tmp.iterdir() if (d / ".project_root").exists()}
    if not markers:
        fails.append("no .project_root markers under transcripts/tmp")

    def marker_of(rel: str) -> str:
        return markers.get(rel.split("/")[2], "")

    for stream in exp["streams"]:
        path = ROOT / stream["file"]
        got = chat_usage(path)
        want = [dict(e, **{"message_id": e["idem_key_inputs"]["message_id"], "request_id": e["idem_key_inputs"]["request_id"]}) for e in stream["usage_events"]]
        for w in want:
            w.pop("idem_key_inputs")
        if got != want:
            fails.append(f"{stream['file']}: derived events != expectations\n  derived:  {json.dumps(got)}\n  expected: {json.dumps(want)}")
        if not got:
            fails.append(f"{stream['file']}: no usage lines — replaying it asserts nothing")
        h = head(path)
        if h.get("projectHash") != hashlib.sha256(marker_of(stream["file"]).encode()).hexdigest():
            fails.append(f"{stream['file']}: metadata projectHash != sha256(.project_root) of its slug")
        if marker_of(stream["file"]) != exp["workspace_root"]:
            fails.append(f"{stream['file']}: slug marker is not workspace_root")
        if stream["role"] == "subagent":
            parent = stream["file"].split("/")[-2]
            if h.get("kind") != "subagent" or parent != stream["usage_events"][0]["idem_key_inputs"]["session_id"]:
                fails.append(f"{stream['file']}: subagent stream must sit under chats/<parent sessionId>/ and carry kind=subagent")
        for e in stream["usage_events"]:
            if e["idem_key_inputs"]["session_id"] != (h["sessionId"] if stream["role"] == "parent" else stream["file"].split("/")[-2]):
                fails.append(f"{stream['file']}: idem session_id must be the parent stream's sessionId")

    root = exp["workspace_root"]
    for foreign in exp["out_of_workspace_streams"]:
        path = ROOT / foreign["file"]
        if not path.exists():
            fails.append(f"{foreign['file']}: out-of-workspace fixture missing")
            continue
        m = marker_of(foreign["file"])
        if m == root or m.startswith(root + "/"):
            fails.append(f"{foreign['file']}: slug marker {m} is inside workspace_root — not foreign")
        ids = {e["message_id"] for e in chat_usage(path)}
        if foreign["never_emit_message_id"] not in ids:
            fails.append(f"{foreign['file']}: never_emit_message_id is not on the stream — the trap is toothless")
    for stray in exp["unattributable_streams"]:
        path = ROOT / stray["file"]
        if not path.exists():
            fails.append(f"{stray['file']}: unattributable fixture missing")
            continue
        if marker_of(stray["file"]) != root:
            fails.append(f"{stray['file']}: must sit under the enabled slug to trap the hash check")
        if head(path).get("projectHash") == hashlib.sha256(root.encode()).hexdigest():
            fails.append(f"{stray['file']}: projectHash matches the enabled root — not a mis-hashed stream")
        if stray["never_emit_message_id"] not in {e["message_id"] for e in chat_usage(path)}:
            fails.append(f"{stray['file']}: never_emit_message_id is not on the stream — the trap is toothless")

    types = (ROOT / "schema" / "hooks-types.ts").read_text()
    if not ts_interface_fields(types, "HookInput") >= BASE:
        fails.append("schema/hooks-types.ts: HookInput no longer carries the base fields this corpus assumes")
    on_disk = {p.stem for p in (ROOT / "hooks").glob("*.json")}
    for missing in sorted(REGISTERED - on_disk):
        fails.append(f"hooks/{missing}.json: registered, missing on disk")
    for extra in sorted(on_disk - REGISTERED):
        fails.append(f"hooks/{extra}.json: not a registered event")
    for name in sorted(on_disk & REGISTERED):
        body = json.loads((ROOT / "hooks" / f"{name}.json").read_text())
        fields, enums = EXTRA[name]
        vendor = ts_interface_fields(types, name + "Input") | BASE
        for k in body:
            if k not in vendor:
                fails.append(f"hooks/{name}.json: field {k} is not on {name}Input in the vendor types")
        for k in BASE | fields:
            if k not in body:
                fails.append(f"hooks/{name}.json: required field {k} missing")
        for k, enum in enums.items():
            if body.get(k) not in ts_enum_values(types, enum):
                fails.append(f"hooks/{name}.json: {k}={body.get(k)!r} not in enum {enum}")
        if body.get("hook_event_name") != name:
            fails.append(f"hooks/{name}.json: hook_event_name != filename")
        if "usage" in json.dumps(body) or "tokens" in json.dumps(body):
            fails.append(f"hooks/{name}.json: token usage in a hook payload contradicts 08 §5 rule 4")

    for p in sorted(list((ROOT / "hooks").glob("*.json")) + list((ROOT / "transcripts").rglob("*.json*"))):
        data = p.read_bytes()
        for needle in FORBIDDEN:
            if needle in data:
                fails.append(f"{p.relative_to(ROOT)}: forbidden identity {needle!r} in fixture")

    if fails:
        print("SELFCHECK FAILED")
        for f in fails:
            print(" -", f)
        return 1
    print("selfcheck ok: fixtures, vendor types, expectations and sanitization rule agree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
