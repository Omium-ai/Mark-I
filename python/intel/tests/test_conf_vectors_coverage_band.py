"""The Python half of the coverage-family cross-language lock (NFR-OPERABILITY-001).

conformance/vectors/coverage/manifest.json carries WIRE shapes — the `Batch.dropped[]`
rows of 07's `Dropped` message and the ClickHouse rollup columns the band reads — and
freezes the arithmetic from that batch to the band. The fold from rows to
`dropped_billing` runs in production as SQL (the `dropped_by_tenant_day` template /
`mv_tvo_session`: `dropped_durability_class = 'billing_grade'`, any reason), so it is
restated here in three lines and asserted against the manifest's frozen intermediate;
the band itself is the PRODUCTION function, app/tvo/coverage.py coverage_band — the
same pattern test_conf_vectors_tvo_band_golden uses. README.md there is normative.

The `conf_vectors` name is load-bearing: tools/ci/conformance_crosslang.sh collects
Python with `pytest -k conf_vectors`, so this lock rides the cross-language gate.
"""

import json
import math
from pathlib import Path

import pytest
from app.tvo.coverage import coverage_band
from m1p.v1 import DropReason, DurabilityClass

_BILLING_GRADE = "DURABILITY_CLASS_BILLING_GRADE"
_MANIFEST = Path(__file__).resolve().parents[3] / "conformance/vectors/coverage/manifest.json"
_manifest = json.loads(_MANIFEST.read_text())


def _dropped_billing(rows: list[dict]) -> int:
    """The template predicate, restated: sum the LOST quantity where the loss's
    durability class is billing_grade — reason is not part of the predicate."""
    return sum(r["quantity"] for r in rows if r["durability_class"] == _BILLING_GRADE)


def test_conf_vectors_coverage_manifest_is_populated():
    assert _manifest["cases"], "zero coverage vectors — an empty lock locks nothing"


@pytest.mark.parametrize("case", _manifest["cases"], ids=lambda c: c["name"])
def test_conf_vectors_coverage_band(case: dict):
    # Wire-shape guard: every row names a value the m1p.v1 enums actually carry.
    for row in case["dropped"]:
        DropReason[row["reason"].removeprefix("DROP_REASON_")]
        DurabilityClass[row["durability_class"].removeprefix("DURABILITY_CLASS_")]
        assert row["quantity"] >= 0

    dropped_billing = _dropped_billing(case["dropped"])
    assert dropped_billing == case["expect"]["dropped_billing"]

    band = coverage_band(
        observed_ms=case["rollup"]["observed_ms"],
        bypass_ms=case["rollup"]["bypass_ms"],
        disabled_ms=case["rollup"]["disabled_ms"],
        dropped_billing=dropped_billing,
        events_billing_ingested=case["rollup"]["events_billing_ingested"],
    )
    tol = _manifest["tolerance"]
    assert math.isclose(band.coverage, case["expect"]["coverage"], abs_tol=tol)
    assert math.isclose(band.coverage_lower, case["expect"]["coverage_lower"], abs_tol=tol)
