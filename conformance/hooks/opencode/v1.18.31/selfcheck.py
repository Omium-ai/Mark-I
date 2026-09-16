#!/usr/bin/env python3
"""Audit that the frozen opencode fixtures, the plugin and expectations.json agree — see README.md.

Not the tailer under test (that is `mark1d.tailers` driven by the opencode
adapter's Format; the CI gate is `conf_hooks_opencode_1.18.31_replay`). Three
checks: (1) the REAL plugin (go/mark1d/adapters/opencode/mark1.js) driven by
harness.mjs over inputs/plugin-inputs.json composes exactly the hook bodies
under hooks/ and appends exactly the capture lines under transcripts/capture/
— the positive control runs the production mechanism; (2) the expected Usage
events re-derive from the capture lines by the step-finish rule (one per
(messageID, partID), last wins); (3) every vendor field name on a hook body
exists in the vendor's plugin types, and no fixture byte carries a real
identity.
"""
import json
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

ROOT = Path(__file__).parent
PLUGIN = ROOT / "../../../../go/mark1d/adapters/opencode/mark1.js"

FORBIDDEN = [b"anurag", b"omium", b"Omium", b"OMIUM"]
REGISTERED = {"session.created", "chat.message", "tool.execute.before", "tool.execute.after", "session.idle"}
OURS = {"hook_event_name", "session_id", "cwd"}


def session_uuid(sid: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "opencode:" + sid))


def capture_usage(path: Path):
    """Reference dedupe: one Usage per step-finish (messageID, partID), last
    wins, first-seen order; model from the message.updated of that message."""
    models, pending, order = {}, {}, []
    for raw in path.read_text().splitlines():
        line = json.loads(raw)
        p = line["properties"]
        if line["type"] == "message.updated" and p["info"].get("role") == "assistant":
            models[p["info"]["id"]] = p["info"]["providerID"] + "/" + p["info"]["modelID"]
            continue
        if line["type"] != "message.part.updated" or p["part"].get("type") != "step-finish":
            continue
        key = (p["part"]["messageID"], p["part"]["id"])
        if key not in pending:
            order.append(key)
        pending[key] = (p, models.get(key[0], ""))
    out = []
    for mid, pid in order:
        p, model = pending[(mid, pid)]
        t = p["part"]["tokens"]
        ms = p["time"]
        from datetime import datetime, timezone
        ts = datetime.fromtimestamp(ms / 1000, tz=timezone.utc).isoformat().replace("+00:00", "Z")
        out.append({
            "idem_key_inputs": {"session_id": session_uuid(p["sessionID"]), "message_id": mid, "request_id": pid},
            "usage": {"input_tokens": t["input"], "output_tokens": t["output"] + t["reasoning"],
                      "cache_creation_input_tokens": t["cache"]["write"], "cache_read_input_tokens": t["cache"]["read"]},
            "model": model, "occurred_at": ts,
        })
    return out


def norm_ts(s: str) -> str:
    from datetime import datetime
    return datetime.fromisoformat(s.replace("Z", "+00:00")).isoformat()


def run_plugin(fails):
    node = shutil.which("node")
    if not node:
        fails.append("node not on PATH — the plugin positive control cannot run")
        return
    with tempfile.TemporaryDirectory() as home:
        r = subprocess.run([node, str(ROOT / "harness.mjs"), str(ROOT / "inputs/plugin-inputs.json"), str(PLUGIN), home],
                           capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"})
        if r.returncode != 0:
            fails.append(f"harness failed: {r.stderr.strip()}")
            return
        got = {}
        for p in sorted(Path(home, "hooks").glob("*.json")):
            b = json.loads(p.read_text())
            got.setdefault((b["hook_event_name"], b["sessionID"]), b)
        exp = json.loads((ROOT / "transcripts/expectations.json").read_text())
        for name in sorted((ROOT / "hooks").glob("*.json")):
            body = json.loads(name.read_text())
            live = got.get((body["hook_event_name"], body["sessionID"]))
            if live != body:
                fails.append(f"hooks/{name.name}: the plugin composes {json.dumps(live)} but the fixture says {json.dumps(body)}")
        for f in exp["out_of_workspace_streams"]:
            sid = Path(f["file"]).stem
            if ("session.idle", sid) not in got:
                fails.append("the other-app instance's session.idle never reached the shim — instance isolation in the harness is broken")
        for fixture in sorted((ROOT / "transcripts/capture").glob("*.jsonl")):
            live = Path(home, ".omium/mark1/capture/opencode", fixture.name)
            if not live.exists() or live.read_bytes() != fixture.read_bytes():
                fails.append(f"{fixture.relative_to(ROOT)}: the plugin's capture output differs from the fixture bytes")
        extra = {p.name for p in Path(home, ".omium/mark1/capture/opencode").glob("*.jsonl")} - {p.name for p in (ROOT / "transcripts/capture").glob("*.jsonl")}
        if extra:
            fails.append(f"the plugin wrote capture files the corpus does not carry: {sorted(extra)}")


def main() -> int:
    fails = []
    exp = json.loads((ROOT / "transcripts/expectations.json").read_text())

    for stream in exp["streams"]:
        got = capture_usage(ROOT / stream["file"])
        want = [dict(e, occurred_at=norm_ts(e["occurred_at"])) for e in stream["usage_events"]]
        got = [dict(e, occurred_at=norm_ts(e["occurred_at"])) for e in got]
        if got != want:
            fails.append(f"{stream['file']}: derived events != expectations\n  derived:  {json.dumps(got)}\n  expected: {json.dumps(want)}")
        if not got:
            fails.append(f"{stream['file']}: no usage lines — replaying it asserts nothing")
        head = json.loads((ROOT / stream["file"]).read_text().splitlines()[0])
        if head["type"] != "message.updated" or head["properties"]["info"]["path"]["cwd"] != exp["workspace_root"]:
            fails.append(f"{stream['file']}: head line must be an assistant message.updated inside workspace_root")

    root = exp["workspace_root"]
    for foreign in exp["out_of_workspace_streams"]:
        path = ROOT / foreign["file"]
        if not path.exists():
            fails.append(f"{foreign['file']}: out-of-workspace fixture missing")
            continue
        cwd = json.loads(path.read_text().splitlines()[0])["properties"]["info"]["path"]["cwd"]
        if cwd == root or cwd.startswith(root + "/"):
            fails.append(f"{foreign['file']}: cwd {cwd} is inside workspace_root — not foreign")
        if foreign["never_emit_request_id"] not in {e["idem_key_inputs"]["request_id"] for e in capture_usage(path)}:
            fails.append(f"{foreign['file']}: never_emit_request_id is not on the stream — the trap is toothless")

    types = (ROOT / "schema/plugin-index.ts").read_text()
    hooks_block = types[types.index("export interface Hooks"):]
    on_disk = {p.stem for p in (ROOT / "hooks").glob("*.json")}
    if on_disk != REGISTERED or set(exp["hooks"]["registered"]) != REGISTERED:
        fails.append(f"hooks on disk {sorted(on_disk)} != registered {sorted(REGISTERED)}")
    for name in sorted(on_disk & REGISTERED):
        body = json.loads((ROOT / "hooks" / f"{name}.json").read_text())
        if body.get("hook_event_name") != name:
            fails.append(f"hooks/{name}.json: hook_event_name != filename")
        if body.get("session_id") != session_uuid(body.get("sessionID", "")):
            fails.append(f"hooks/{name}.json: session_id is not UUIDv5(NameSpaceURL, opencode:<sessionID>)")
        if body.get("cwd") != root:
            fails.append(f"hooks/{name}.json: cwd is not the plugin instance directory")
        vendor = hooks_block if name.startswith(("tool.", "chat.")) else types
        for k in set(body) - OURS:
            if not re.search(r"\b" + re.escape(k) + r"\b", vendor):
                fails.append(f"hooks/{name}.json: field {k} is not a vendor field name in schema/plugin-index.ts")
        if "tokens" in json.dumps(body) or "usage" in json.dumps(body):
            fails.append(f"hooks/{name}.json: token usage in a hook payload contradicts 08 §5 rule 4")
    if "args" in json.loads((ROOT / "hooks/tool.execute.after.json").read_text()):
        fails.append("hooks/tool.execute.after.json: tool args (content) must not travel to the shim")

    run_plugin(fails)

    for p in sorted(list((ROOT / "hooks").glob("*.json")) + list((ROOT / "transcripts").rglob("*.json*")) + list((ROOT / "inputs").glob("*.json"))):
        data = p.read_bytes()
        for needle in FORBIDDEN:
            if needle in data:
                fails.append(f"{p.relative_to(ROOT)}: forbidden identity {needle!r} in fixture")

    if fails:
        print("SELFCHECK FAILED")
        for f in fails:
            print(" -", f)
        return 1
    print("selfcheck ok: plugin output, fixtures, vendor types, expectations and sanitization rule agree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
