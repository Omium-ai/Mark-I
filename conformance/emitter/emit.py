#!/usr/bin/env python3
"""The reference external writer, Python copy (08 §4.6; docs/integrating-a-host.md).

Writes the SAME sample session as the Go emitter (emitter.go), byte for byte:
one protojson m1p.v1.Event per line, keys sorted, compact separators — which is
exactly what protojson produces once re-serialised with sorted keys. No
dependencies: a partner can run this with a bare interpreter.

    python emit.py <dir>     writes <dir>/sample.jsonl and <dir>/sample.manifest.json
    python emit.py           prints the JSONL to stdout

protojson's shapes, reproduced by hand here so the file stays dependency-free:
bytes are standard base64 with padding; uint64 fields are JSON strings;
uint32/bool/string are themselves; enums are their names; defaults are
omitted; timestamps are RFC 3339 UTC with a trailing Z.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

COMPONENT = "ext:omium/reference-emitter@0.1.0"
HOST_CORRELATION_ID = "sample-run-0001"
SCHEMA_VERSION = "m1p.v1"


def _event_id(i: int) -> str:
    raw = bytes([0x01, 0x99, 0x9F, 0xC4, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0, 0, 0, 0, 0, i])
    return base64.b64encode(raw).decode("ascii")


def session() -> list[dict]:
    """The sample session in 08 §4.6.3 order, one second apart from a fixed instant."""
    bodies = [
        {"sessionStart": {"agent": "acme-runner", "agentVersion": "1.2.3"}},
        {"taskOpen": {"taskSegVersion": "ext:acme/runner.v1", "taskClass": "*"}},
        {"turn": {"initiator": "INITIATOR_HUMAN"}},
        {"turn": {"turnIndex": 1, "initiator": "INITIATOR_AGENT"}},
        {"toolUse": {"toolName": "Bash", "toolUseId": "toolu_01", "durationMs": "42", "status": "TOOL_STATUS_OK"}},
        {"usage": {"messageId": "msg_01", "requestId": "req_01", "model": "claude-fable-5-1", "inputTokens": "120", "outputTokens": "30"}},
        {"artifactOutcome": {"artifactId": base64.b64encode(bytes([0xA7] * 16)).decode("ascii"), "taskVerdict": "VERDICT_SATISFIED", "artifactFollowed": True}},
        {"taskClose": {"resolution": "RESOLUTION_VERDICT", "turnCount": 2}},
        {"sessionEnd": {"reason": "END_REASON_EXIT", "durationMs": "8000", "drained": True}},
    ]
    out = []
    for i, body in enumerate(bodies):
        ev = {"eventId": _event_id(i), "occurredAt": f"2026-10-02T12:00:{i:02d}Z"}
        ev.update(body)
        out.append(ev)
    return out


def jsonl() -> bytes:
    return "".join(json.dumps(ev, sort_keys=True, separators=(",", ":")) + "\n" for ev in session()).encode("utf-8")


HOST_MANIFEST = {
    "hostId": "cem888",
    "hostVersion": "2.0.1",
    "ownsExecution": True,
    "ownsConfigSurface": True,
    "ownsMemory": True,
    "arrestMode": "ARREST_MODE_RECOMMEND",
    "suppliesIdentity": True,
    "schemaVersion": "m1p.v1",
}


def manifest(with_host_manifest: bool = False) -> bytes:
    """The sidecar; with_host_manifest adds the ADR-0013 block (the extmanifest family).

    The block is one m1p.v1.HostManifest in protojson, key order as the Go emitter
    renders it (field order of the message), so both copies stay byte-identical.
    """
    doc = {"component": COMPONENT, "host_correlation_id": HOST_CORRELATION_ID, "schema_version": SCHEMA_VERSION}
    if with_host_manifest:
        doc["host_manifest"] = HOST_MANIFEST
    return (json.dumps(doc, separators=(",", ":")) + "\n").encode("utf-8")


def main(argv: list[str]) -> int:
    with_manifest = "--manifest" in argv
    argv = [a for a in argv if a != "--manifest"]
    if len(argv) > 1:
        out = Path(argv[1])
        out.mkdir(parents=True, exist_ok=True)
        # Sidecar first (08 §4.6.2): the daemon binds the file from it before it reads a line.
        (out / "sample.manifest.json").write_bytes(manifest(with_manifest))
        (out / "sample.jsonl").write_bytes(jsonl())
        return 0
    sys.stdout.buffer.write(jsonl())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
