"""The Python half of the cross-language coverage-band lock.

ONE fixture, TWO asserters (the wave-5 lesson: stub-tested halves drift):
go/controld/internal/querychoke/testdata/tvo_band_golden.json is asserted here through
the REAL intel pipeline (coverage.py coverage_band → report.py assemble_report) and in
Go through querychoke's coverageBand/guaranteeRefusals (golden_band_test.go — the
arithmetic behind GET /api/v1/reports/tvo). Arithmetic normative in 07; refusal rule in
06 §8.5 (D23 floor on the shed-narrowed lower edge; unresolved usd basis). Refusal
strings are asserted byte-for-byte, in order — a reformat in either language goes red.

The `conf_vectors` name is load-bearing: tools/ci/conformance_crosslang.sh collects
Python with `pytest -k conf_vectors`, so this lock rides the same gate as the wire
vectors.
"""

import json
import math
from pathlib import Path

import pytest
from app.tvo.coverage import COVERAGE_FLOOR, coverage_band
from app.tvo.engine import TvoInputs, TvoResult
from app.tvo.report import ModelPrice, assemble_report
from app.tvo.waste import WasteTriple

_FIXTURE = (
    Path(__file__).resolve().parents[3]
    / "go/controld/internal/querychoke/testdata/tvo_band_golden.json"
)

_fixture = json.loads(_FIXTURE.read_text())


def test_conf_vectors_fixture_floor_is_d23():
    assert _fixture["floor"] == COVERAGE_FLOOR, "fixture floor drifted from D23 (06 §8.5)"
    assert _fixture["cases"], "zero golden cases — an empty lock locks nothing"


@pytest.mark.parametrize("case", _fixture["cases"], ids=lambda c: c["name"])
def test_conf_vectors_tvo_band_golden(case: dict):
    band = coverage_band(
        observed_ms=case["observed_ms"],
        bypass_ms=case["bypass_ms"],
        disabled_ms=case["disabled_ms"],
        dropped_billing=case["dropped_billing"],
        events_billing_ingested=case["events_billing_ingested"],
    )
    assert math.isclose(band.coverage, case["expect"]["coverage"], abs_tol=1e-12)
    assert math.isclose(band.coverage_lower, case["expect"]["coverage_lower"], abs_tol=1e-12)

    # A certified result with clean inputs: the fixture isolates the band + basis
    # refusals, the two conditions the Go surface evaluates too (its extra
    # zero-verified and missing-day refusals are handler-level, tested in Go).
    certified = int(case.get("certified", case["verified"]))
    result = TvoResult(
        tvo=1.0,
        break_even_v=0.0,
        inputs=TvoInputs(c=1.0, v=0.0, p=1.0, alpha=1.0, beta=0.0, d=0.0),
        attempts=int(case["verified"]),
        certified_attempts=certified,
        cert_status="certified" if certified > 0 else "bootstrapping",
    )
    price = ModelPrice("model_prices.golden", 0.0, 0.0, 0.0, 0.0) if case["price_pinned"] else None
    report = assemble_report(
        result,
        WasteTriple(0, 0, 0),
        band,
        cost_basis=case["cost_basis"],
        task_seg_version="task_seg.v1",
        price=price,
    )
    assert report.guarantee_grade is case["expect"]["guarantee_grade"]
    # Byte-for-byte AND in order: the "; "-joined wire field must match Go's.
    assert list(report.refusals) == case["expect"]["refusals"]
