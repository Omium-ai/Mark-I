#!/usr/bin/env python3
"""Audit that the frozen transcript fixtures and expectations.json agree — see README.md.

Not the tailer under test (that is `mark1d.tailers`, 04 §2.1; the CI gate is
`conf_hooks_claudecode_2.1.273_replay`, 12 §3.2). This re-derives the expected
Usage events from 08 §5.1's dedupe and sidechain rules so a mis-frozen fixture
is caught here, before it teaches the real tailer a wrong answer. Also enforces
the sanitization rule: fixture payloads carry zero real workspace content.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parent

# 08 §5.1 sanitization tripwire: identities from the recording machine that must
# never appear in a fixture payload. Checked over raw bytes, not parsed fields,
# so a leak in an unmapped field still fails.
FORBIDDEN = [b"anurag", b"omium", b"Omium", b"OMIUM"]


def emitted_usage(path: Path, role: str):
    """Reference dedupe per 08 §5.1: one Usage per (message.id, requestId),
    last-write-wins; sidechain lines in the PARENT stream are dropped; a
    subagent stream is the origin of its own (sidechain-flagged) lines and
    emits them. Emission order = first-seen key order (EOF stands in for the
    Stop-hook/quiesce flush of 04 §2.1)."""
    pending = {}
    order = []
    for raw in path.read_text().splitlines():
        line = json.loads(raw)
        msg = line.get("message") or {}
        # The tailer reads only lines whose message carries usage (08 §5.1).
        if line.get("type") != "assistant" or "usage" not in msg:
            continue
        if role == "parent" and line.get("isSidechain"):
            continue
        key = (msg["id"], line["requestId"])
        if key not in pending:
            order.append(key)
        pending[key] = line  # last line per key wins
    events = []
    for key in order:
        line = pending[key]
        u = line["message"]["usage"]
        events.append({
            "idem_key_inputs": {
                # 04 §2.1: subagent streams are tailed under the PARENT session_id,
                # which is the `sessionId` field (matches the hook payload's
                # session_id and the transcript filename), not `session_id`.
                "session_id": line["sessionId"],
                "message_id": line["message"]["id"],
                "request_id": line["requestId"],
            },
            "usage": {k: u[k] for k in (
                "input_tokens", "output_tokens",
                "cache_creation_input_tokens", "cache_read_input_tokens",
                "service_tier")},
            "model": line["message"]["model"],
        })
    return events


def main() -> int:
    fails = []
    exp = json.loads((ROOT / "transcripts" / "expectations.json").read_text())

    for stream in exp["streams"]:
        path = ROOT / stream["file"]
        got = emitted_usage(path, stream["role"])
        want = stream["usage_events"]
        if got != want:
            fails.append(f"{stream['file']}: derived events != expectations\n"
                         f"  derived:  {json.dumps(got)}\n"
                         f"  expected: {json.dumps(want)}")
        emitted_keys = {(e["idem_key_inputs"]["message_id"],
                         e["idem_key_inputs"]["request_id"]) for e in got}
        for banned in stream["never_emit"]:
            if (banned["message_id"], banned["request_id"]) in emitted_keys:
                fails.append(f"{stream['file']}: never_emit key leaked: {banned}")

    # Containment fixtures (04 §0.3 invariant 3): every out-of-workspace
    # stream must be a REAL trap — it lives in the enabled root's own munged
    # dir (the '/'→'-' collision), its every cwd resolves outside
    # workspace_root, and it carries usage a gate-less tailer WOULD emit.
    # A toothless fixture here would let the workspace gate rot invisibly.
    root = exp["workspace_root"]
    def munge(p):
        return p.replace("/", "-")
    for foreign in exp.get("out_of_workspace_streams", []):
        path = ROOT / foreign["file"]
        if not path.exists():
            fails.append(f"{foreign['file']}: out-of-workspace fixture missing")
            continue
        if path.parent.name != munge(root):
            fails.append(f"{foreign['file']}: not in the enabled root's munged dir — no collision, no trap")
        cwds = {json.loads(raw).get("cwd") for raw in path.read_text().splitlines()} - {None}
        if not cwds:
            fails.append(f"{foreign['file']}: no cwd on any line — unattributable, proves nothing")
        for c in sorted(cwds):
            if c == root or c.startswith(root + "/"):
                fails.append(f"{foreign['file']}: cwd {c} is inside workspace_root — not foreign")
            if munge(c) != munge(root):
                fails.append(f"{foreign['file']}: cwd {c} does not munge-collide with {root} — the trap is gone")
        if not emitted_usage(path, "parent"):
            fails.append(f"{foreign['file']}: no usage lines — a gate-less tailer would emit nothing anyway")

    # Keep the overcount corpus honest: if someone flattens the 4-line rewrite,
    # this directory stops being NFR-CORRECTNESS-001's evidence and must go red.
    oc = exp["overcount_case"]
    parent_path = ROOT / exp["streams"][0]["file"]
    per_line = [json.loads(raw)["message"]["usage"]["output_tokens"]
                for raw in parent_path.read_text().splitlines()
                if (l := json.loads(raw)).get("type") == "assistant"
                and l["message"]["id"] == oc["message_id"]
                and l["requestId"] == oc["request_id"]]
    if len(per_line) != oc["streamed_lines"]:
        fails.append(f"overcount case: {len(per_line)} lines, expected {oc['streamed_lines']}")
    if sum(per_line) != oc["naive_per_line_output_token_sum"]:
        fails.append(f"overcount case: naive sum {sum(per_line)} != {oc['naive_per_line_output_token_sum']}")
    if per_line and per_line[-1] != oc["correct_output_tokens"]:
        fails.append(f"overcount case: last line {per_line[-1]} != correct {oc['correct_output_tokens']}")
    if per_line and sum(per_line) < oc["min_overcount_ratio_asserted"] * per_line[-1]:
        fails.append("overcount case: naive/correct ratio fell below the asserted floor — "
                     "this corpus no longer exhibits the ~2.5x overcount")

    # Sanitization tripwire over every fixture payload byte.
    for p in sorted(list((ROOT / "hooks").glob("*.json"))
                    + list((ROOT / "transcripts").rglob("*.json*"))):
        data = p.read_bytes()
        for needle in FORBIDDEN:
            if needle in data:
                fails.append(f"{p.relative_to(ROOT)}: forbidden identity {needle!r} in fixture")

    # Every hook event 08 §5.1 registers must have exactly one fixture body.
    expected_hooks = {"SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse",
                      "PostToolUseFailure", "Stop", "SubagentStop", "PreCompact",
                      "SessionEnd"}
    on_disk = {p.stem for p in (ROOT / "hooks").glob("*.json")}
    for missing in sorted(expected_hooks - on_disk):
        fails.append(f"hooks/{missing}.json: registered in 08 §5.1, missing on disk")
    for extra in sorted(on_disk - expected_hooks):
        fails.append(f"hooks/{extra}.json: not a registered 08 §5.1 event")
    for name in sorted(on_disk & expected_hooks):
        body = json.loads((ROOT / "hooks" / f"{name}.json").read_text())
        for field in ("session_id", "transcript_path", "cwd", "hook_event_name"):
            if field not in body:
                fails.append(f"hooks/{name}.json: missing common field {field}")
        if body.get("hook_event_name") != name:
            fails.append(f"hooks/{name}.json: hook_event_name != filename")
        # 08 §5.1: no hook payload carries token usage on this surface.
        if "usage" in json.dumps(body):
            fails.append(f"hooks/{name}.json: token usage in a hook payload contradicts 08 §5.1")

    if fails:
        print("SELFCHECK FAILED")
        for f in fails:
            print(" -", f)
        return 1
    print("selfcheck ok: fixtures, expectations and sanitization rule agree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
