"""The cloud RM's vendored rm-input/v1 (app/rm/render.py) against the fixtures the Go edge also
reads, rendered by training_jobs/rm/prompt.py: train, edge and cloud pinned to one set."""

import hashlib
import json
from pathlib import Path

import pytest
from app.rm import render

ROOT = Path(__file__).resolve().parents[3]
TESTDATA = ROOT / "go/mark1d/internal/rm/testdata"
TRAINING = ROOT.parent / "omium-training-plane/training-jobs/src/training_jobs/rm/prompt.py"
BODY_SHA = "20934d1b98b889af46ab3e2a827982b83732dba1087576b648163975940e8158"


def _body(path: Path) -> bytes:
    return path.read_bytes().split(b"\n", 1)[1]


def test_vendored_renderer_is_the_training_source_verbatim():
    ours = _body(Path(render.__file__))
    assert hashlib.sha256(ours).hexdigest() == BODY_SHA
    if TRAINING.exists():
        assert ours == _body(TRAINING), "training_jobs/rm/prompt.py moved: re-vendor and re-pin"


def test_render_cases_match_the_training_renderer():
    cases = json.loads((TESTDATA / "parity.json").read_text())
    assert len(cases) >= 10
    for c in cases:
        r = render.render(c["task"], c["diff"], c["max_diff_chars"])
        assert (r.abstain or "", "" if r.abstain else r.text) == (c["abstain"], c["text"]), c[
            "name"
        ]


@pytest.mark.parametrize("slot", ["a", "b"])
def test_export_parity_vectors_render_identically(slot):
    doc = json.loads((TESTDATA / f"export-parity-{slot}.json").read_text())
    assert doc["template_version"] == render.TEMPLATE_VERSION
    for v in doc["vectors"]:
        r = render.render(v["task"], v["diff"])
        assert r.abstain is None and r.prefix == v["prefix"] and r.text == v["rendered"]
        assert hashlib.sha256(r.text.encode()).hexdigest() == v["text_sha256"]
