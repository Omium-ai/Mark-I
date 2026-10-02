"""The `ext` conformance family's Python lane (conformance/vectors/ext/README.md).

The Python reference emitter must reproduce the frozen sample session byte for
byte — the same claim the Go lane makes of the Go emitter — so the two copies a
partner may start from are one artifact. Lives in this suite because it is the
dependency-free Python package the cross-language gate already collects; the
emitter itself imports nothing outside the standard library.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
VECTORS = ROOT / "conformance" / "vectors" / "ext"
EMITTER = ROOT / "conformance" / "emitter" / "emit.py"


def _load_emitter():
    spec = importlib.util.spec_from_file_location("mark1_ext_emitter", EMITTER)
    assert spec is not None and spec.loader is not None, f"no emitter at {EMITTER}"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_conf_vectors_ext_emitter_matches_golden():
    emit = _load_emitter()
    assert emit.jsonl() == (VECTORS / "sample.jsonl").read_bytes(), "emit.py drifted from the frozen sample.jsonl"
    assert emit.manifest() == (VECTORS / "sample.manifest.json").read_bytes(), "emit.py drifted from the frozen sidecar"


def test_conf_vectors_ext_golden_is_well_formed():
    """Every line is one JSON object with one body arm and the envelope rules a host owns."""
    import json

    lines = (VECTORS / "sample.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 9
    envelope = {"eventId", "occurredAt"}
    last = ""
    for line in lines:
        ev = json.loads(line)
        body = set(ev) - envelope
        assert len(body) == 1, f"one body arm per line, got {sorted(body)}"
        assert "seq" not in ev and "sessionEpoch" not in ev and "sessionId" not in ev
        assert ev["occurredAt"] >= last, "occurred_at must be non-decreasing"
        last = ev["occurredAt"]
