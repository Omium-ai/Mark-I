"""Coverage band arithmetic (07 §MVs formula) and the M1E-5004 refusal (06 §8.5 D23,
08 §9 error table: refusal-by-design — the report renders, the guarantee is refused)."""

import pytest
from app.tvo.coverage import (
    COVERAGE_FLOOR,
    CoverageBand,
    CoverageFloorRefusal,
    coverage_band,
    require_guarantee_grade,
)


def test_band_arithmetic():
    band = coverage_band(
        observed_ms=94_000,
        bypass_ms=4_000,
        disabled_ms=2_000,
        dropped_billing=0,
        events_billing_ingested=1_000,
    )
    assert band.coverage == pytest.approx(0.94)
    assert band.coverage_lower == pytest.approx(0.94)  # no shed ⇒ no narrowing


def test_shed_narrows_only_the_lower_edge():
    band = coverage_band(
        observed_ms=98_000,
        bypass_ms=1_000,
        disabled_ms=1_000,
        dropped_billing=50,
        events_billing_ingested=950,
    )
    assert band.coverage == pytest.approx(0.98)
    assert band.coverage_lower == pytest.approx(0.98 * (1 - 50 / 1000))
    assert band.coverage_lower < band.coverage


def test_zero_surface_time_is_zero_coverage_never_assumed():
    band = coverage_band(0, 0, 0, 0, 0)
    assert band == CoverageBand(coverage_lower=0.0, coverage=0.0)


def test_negative_inputs_refused():
    with pytest.raises(ValueError):
        coverage_band(-1, 0, 0, 0, 0)


def test_floor_refusal_is_m1e_5004():
    band = CoverageBand(coverage_lower=0.90, coverage=0.94)
    with pytest.raises(CoverageFloorRefusal) as excinfo:
        require_guarantee_grade(band)
    assert excinfo.value.code == "M1E-5004"
    # The exact wire refusal string from 08 §3.3 must lead the message.
    assert str(excinfo.value).startswith("M1E-5004 coverage below floor")


def test_floor_passes_at_and_above_d23():
    require_guarantee_grade(CoverageBand(COVERAGE_FLOOR, 0.99))  # boundary: >= floor passes
    require_guarantee_grade(CoverageBand(0.97, 0.99))


def test_refusal_applies_to_lower_edge_not_headline():
    # Headline coverage above the floor is NOT enough: shed narrowing is what the
    # guarantee is priced on (06 §8.2 — every number carries the band's lower edge).
    band = CoverageBand(coverage_lower=0.93, coverage=0.97)
    with pytest.raises(CoverageFloorRefusal):
        require_guarantee_grade(band)
