"""The Chow band arithmetic (06 §3.1 step 4, Paper II Thm 5.1)."""

from fractions import Fraction

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
    assert chow_verdict(hi, 1.0, costs) == "satisfied"  # η ≥ 1 − A/D
    assert chow_verdict(lo, 1.0, costs) == "violated"  # η ≤ A/R
    assert chow_verdict(lo + 1e-9, 1.0, costs) == "refused"  # open interval
    assert chow_verdict(hi - 1e-9, 1.0, costs) == "refused"
    assert chow_verdict(0.999, 1.0, costs) == "satisfied"
    assert chow_verdict(0.001, 1.0, costs) == "violated"


def test_boundaries_are_scale_invariant_and_never_divide():
    """D-AK: the rule is `u_S·R ≤ A·total`, so the same η decided by a bundle whose
    masses were rescaled by a power of two (the fusion loop's underflow guard) must
    land on the same verdict — and the exact boundary must survive the scaling."""
    costs = Costs()
    for k in (-600, -1, 0, 1, 600):
        scale = 2.0**k
        assert chow_verdict(1.0 * scale, 3.0 * scale, costs) == "violated"  # η = A/R
        assert chow_verdict(8.0 * scale, 9.0 * scale, costs) == "satisfied"  # η = 1−A/D
        assert chow_verdict(1.0 * scale, 2.0 * scale, costs) == "refused"


def test_division_would_flip_this_verdict_and_cross_multiplication_does_not():
    """D-AK: the withdrawn form computed `u_s / total >= 1 − A/D`, which rounds twice —
    once in the quotient, once in the derived band constant — and the two errors can add
    up to a whole verdict. Here `u_s·9` and `8·total` are both exactly representable, so
    the cross-multiplied comparison IS the exact rational answer: η is strictly below
    8/9 and the honest verdict is `refused`. The quotient rounds up to exactly the band
    constant and reads `satisfied`, shipping a green verdict on evidence that does not
    reach the threshold."""
    u_s, total = 0.8788095083430196, 0.9886606968858972
    assert Fraction(u_s) * 9 < 8 * Fraction(total)  # exact truth: below the threshold
    assert u_s / total >= 1 - 1 / 9  # the divided form's answer: satisfied
    assert chow_verdict(u_s, total, Costs()) == "refused"


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
