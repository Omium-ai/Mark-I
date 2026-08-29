"""Closed-form unit tests (06 §8.1): domain refusals and the theorem-named edge cases —
p→0 (Thm 4.1 needs p·α > 0; Thm 4.2's proof divides by p and p·α too), α→β (Thm 4.2:
an undiscriminating verifier never pays), and the knee's preconditions (Thm 5.1,
verbatim strict: ρ ∈ (0,1), γ ∈ (0,1))."""

import pytest
from app.tvo.closed_forms import repair_knee, tvo, verifier_break_even


def test_tvo_no_verifier_baseline_form():
    # (v, α, β) = (0, 1, 1) collapses Thm 4.1 to (c + (1-p)·D) / p — Thm 4.2's baseline.
    c, p, d = 30_000, 0.4, 150_000
    assert tvo(c, 0, p, 1.0, 1.0, d) == pytest.approx((c + (1 - p) * d) / p)


def test_tvo_diverges_as_p_approaches_zero():
    previous = 0.0
    for p in (0.1, 0.01, 0.001, 1e-9):
        current = tvo(30_000, 0, p, 1.0, 0.0, 150_000)
        assert current > previous
        previous = current
    # p = 0 exactly violates the finiteness condition p·α > 0: refuse, never inf/NaN.
    with pytest.raises(ValueError):
        tvo(30_000, 0, 0.0, 1.0, 0.0, 150_000)


def test_tvo_alpha_zero_refused():
    with pytest.raises(ValueError):
        tvo(30_000, 0, 0.4, 0.0, 0.0, 150_000)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"c": -1.0},
        {"v": -1.0},
        {"d": -1.0},
        {"p": 1.5},
        {"alpha": 1.5},
        {"beta": -0.1},
        {"beta": 1.1},
    ],
)
def test_tvo_domain_refusals(kwargs):
    args = {"c": 30_000.0, "v": 0.0, "p": 0.4, "alpha": 1.0, "beta": 0.0, "d": 150_000.0}
    args.update(kwargs)
    with pytest.raises(ValueError):
        tvo(**args)


def test_break_even_alpha_equals_beta_never_pays():
    # α = β ⇒ J = 0 ⇒ v* = −c·(1−α) ≤ 0: worse than nothing even free of charge (Paper I).
    for ab in (0.2, 0.5, 0.9):
        assert verifier_break_even(30_000, 0.4, ab, ab, 150_000) == pytest.approx(
            -30_000 * (1 - ab)
        )
    # And exactly zero at the accept-everything corner α = β = 1.
    assert verifier_break_even(30_000, 0.4, 1.0, 1.0, 150_000) == 0.0


def test_break_even_p_domain():
    # p=1 is inside the domain and leaves only the false-rejection tax.
    assert verifier_break_even(30_000, 1.0, 0.85, 0.20, 150_000) == pytest.approx(-4_500.0)
    # p=0 and α=0 are outside Thm 4.2's derivation domain (its proof divides the
    # verified TVO by p·α and the baseline by p): refuse, never extrapolate.
    with pytest.raises(ValueError, match="p="):
        verifier_break_even(30_000, 0.0, 0.85, 0.20, 150_000)
    with pytest.raises(ValueError, match="alpha="):
        verifier_break_even(30_000, 0.4, 0.0, 0.0, 150_000)


def test_repair_knee_grid_spot_checks():
    # Interior cells of Paper I Table 2 (away from the ρ=γ boundary).
    assert repair_knee(0.2, 0.5) == 3
    assert repair_knee(0.2, 0.8) == 8
    assert repair_knee(0.4, 0.7) == 3
    assert repair_knee(0.4, 0.8) == 5


@pytest.mark.parametrize(
    "rho,gamma",
    [(1.5, 0.5), (1.0, 0.5), (0.0, 0.5), (0.3, 1.0), (0.3, 0.0), (0.3, 1.2)],
)
def test_repair_knee_precondition_refusals(rho, gamma):
    # Thm 5.1 assumes ρ < 1 STRICTLY ("repair rounds are cheaper than fresh
    # attempts") — ρ = 1.0 is a refusal, not a knee of 1.
    with pytest.raises(ValueError):
        repair_knee(rho, gamma)
