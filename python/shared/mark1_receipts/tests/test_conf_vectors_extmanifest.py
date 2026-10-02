"""The `extmanifest` conformance family's Python lane (conformance/vectors/extmanifest/README.md).

`emit.py --manifest` must reproduce the frozen manifest-bearing sidecar and the
unchanged events byte for byte, so the Python copy a partner starts from declares
the same profile the Go emitter does.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
VECTORS = ROOT / "conformance" / "vectors" / "extmanifest"
EXT = ROOT / "conformance" / "vectors" / "ext"
EMITTER = ROOT / "conformance" / "emitter" / "emit.py"


def _load_emitter():
    spec = importlib.util.spec_from_file_location("mark1_ext_emitter_m", EMITTER)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_conf_vectors_extmanifest_emitter_matches_golden():
    emit = _load_emitter()
    assert emit.jsonl() == (VECTORS / "sample.jsonl").read_bytes()
    assert emit.manifest(True) == (VECTORS / "sample.manifest.json").read_bytes(), "emit.py --manifest drifted from the frozen sidecar"


def test_conf_vectors_extmanifest_events_equal_ext_and_block_is_the_cem888_profile():
    assert (VECTORS / "sample.jsonl").read_bytes() == (EXT / "sample.jsonl").read_bytes(), "declaring a profile must change no event"
    sidecar = json.loads((VECTORS / "sample.manifest.json").read_text(encoding="utf-8"))
    block = sidecar["host_manifest"]
    assert block == {
        "hostId": "cem888",
        "hostVersion": "2.0.1",
        "ownsExecution": True,
        "ownsConfigSurface": True,
        "ownsMemory": True,
        "arrestMode": "ARREST_MODE_RECOMMEND",
        "suppliesIdentity": True,
        "schemaVersion": "m1p.v1",
    }
    assert sidecar["component"].startswith("ext:")
