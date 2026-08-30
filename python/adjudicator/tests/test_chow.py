"""The Chow band arithmetic (06 §3.1 step 4, Paper II Thm 5.1)."""

import pytest
from app.adjudicate.chow import Costs, chow_verdict


def test_default_band_is_the_d4_band():
    # D4: A=1, R=3, D=9 ⇒ (A/R, 1−A/D) = (0.333…, 0.888…) — 06 §3.1's printed band.
    lo, hi = Costs().band
    assert lo == pytest.approx(1 / 3)
    assert hi == pytest.approx(8 / 9)


def test_boundaries_are_the_pseudocodes_inclusivity():
    costs = Costs()
    lo, hi = costs.band
    assert chow_verdict(hi, costs) == "satisfied"  # η ≥ 1 − A/D
    assert chow_verdict(lo, costs) == "violated"  # η ≤ A/R
    assert chow_verdict(lo + 1e-9, costs) == "refused"  # open interval
    assert chow_verdict(hi - 1e-9, costs) == "refused"
    assert chow_verdict(0.999, costs) == "satisfied"
    assert chow_verdict(0.001, costs) == "violated"


def test_chow_condition_refuses_an_empty_band():
    # A ≥ DR/(D+R) folds the rule back to binary — Thm 5.1 says that is strictly
    # dominated, so pricing it is refused, never silently accepted.
    with pytest.raises(ValueError, match="empties the Chow band"):
        Costs(a=3.0, r=3.0, d=9.0)  # DR/(D+R) = 2.25 < 3


def test_degenerate_but_nonzero_regions_are_refused():
    """The emptiness check alone holds only at the exact zero-width point. A band of
    width 4.4e-8 is a "never refuse" rule and A→0 an "always refuse" rule — both fold
    the three-verdict rule into a dominated one and must be refused, not accepted."""
    with pytest.raises(ValueError, match="degenerate Chow pricing"):
        Costs(a=2.2499999, r=3.0, d=9.0)  # band width ≈ 4.4e-8
    with pytest.raises(ValueError, match="degenerate Chow pricing"):
        Costs(a=1e-12, r=3.0, d=9.0)  # violated/satisfied regions ≈ 0


def test_nonpositive_costs_refused():
    with pytest.raises(ValueError, match="strictly positive"):
        Costs(a=0.0, r=3.0, d=9.0)


def test_paper2_token_costs_produce_the_papers_band():
    lo, hi = Costs(a=20_000, r=45_000, d=150_000).band
    assert round(lo, 3) == 0.444
    assert round(hi, 3) == 0.867
