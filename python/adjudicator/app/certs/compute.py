"""Noise-certificate computation (06 §5.2, Paper II Thm 6.1): ρ₊/ρ₋ Wilson estimates on
the binary satisfied-vs-violated projection, the Natarajan margin 1 − (ρ₊+ρ₋), and its
95% LCB — NATARAJAN_OK ⇔ LCB₉₅(1 − (ρ₊+ρ₋)) > 0, the theorem's actual condition
(m1_021's noise_certificates.natarajan_lcb column note).

Never a fabricated rate: with zero gold rows on either side of the projection the rates
are None and the certificate stays below `certified` — the DB's certified_is_earned
CHECK enforces the same fact at write time; this module refuses one layer earlier."""

import math
from dataclasses import dataclass

from app.gold.score import GoldScore

_Z95 = 1.959963984540054  # two-sided 95%


def wilson_interval(k: int, n: int, z: float = _Z95) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion — 06 §5.2 names Wilson
    explicitly (a normal interval at ρ near 0 would collapse to a lying [0, 0])."""
    if n <= 0:
        raise ValueError("Wilson interval over zero trials is not a measurement")
    if not 0 <= k <= n:
        raise ValueError(f"k={k} outside [0, n={n}]")
    p = k / n
    denom = 1.0 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = (z / denom) * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (max(0.0, center - half), min(1.0, center + half))


@dataclass(frozen=True)
class CertComputation:
    """Everything a noise_certificates row stores about the measurement (06 §5.2)."""

    rho_plus: float | None  # P(verdict=violated | gold=satisfied), covered rows
    rho_minus: float | None  # P(verdict=satisfied | gold=violated), covered rows
    rho_plus_ci: tuple[float, float] | None
    rho_minus_ci: tuple[float, float] | None
    natarajan_margin: float | None  # 1 − (ρ₊ + ρ₋), point
    natarajan_lcb: float | None  # LCB₉₅ of the margin
    natarajan_ok: bool | None  # None ⇒ not yet measurable — NEVER defaulted to a bool
    abstention_mass: float | None  # verdict-refused/-error share of scoreable gold
    gold_n: int  # scoring-window size backing the measurement


def compute_certificate(score: GoldScore) -> CertComputation:
    """GoldScore counts → the certificate quantities. Paper II Thm 6.1's ρ are defined
    on COVERED instances (η thresholded "on covered instances"), so refused/error
    VERDICTS leave the ρ denominators and are reported as abstention mass, exactly as
    refused/error GOLD rows are held out upstream (06 §5.2)."""
    if score.n_plus == 0 or score.n_minus == 0:
        # One side of the projection has no covered gold: ρ on that side would be a
        # fabricated rate. Report what is measurable (nothing), keep status honest.
        return CertComputation(
            rho_plus=None,
            rho_minus=None,
            rho_plus_ci=None,
            rho_minus_ci=None,
            natarajan_margin=None,
            natarajan_lcb=None,
            natarajan_ok=None,
            abstention_mass=score.abstention_mass,
            gold_n=score.gold_n,
        )

    rho_plus = score.k_plus / score.n_plus
    rho_minus = score.k_minus / score.n_minus
    ci_plus = wilson_interval(score.k_plus, score.n_plus)
    ci_minus = wilson_interval(score.k_minus, score.n_minus)
    margin = 1.0 - (rho_plus + rho_minus)
    # Conservative LCB of the margin: each ρ at its own Wilson upper bound (a union
    # bound — DESIGN; the certificate CIs inherit the estimator's O(√(log/N)) rate
    # rather than inventing their own, 06 §4.1).
    lcb = 1.0 - (ci_plus[1] + ci_minus[1])
    return CertComputation(
        rho_plus=rho_plus,
        rho_minus=rho_minus,
        rho_plus_ci=ci_plus,
        rho_minus_ci=ci_minus,
        natarajan_margin=margin,
        natarajan_lcb=lcb,
        natarajan_ok=lcb > 0.0,  # NATARAJAN_OK, provably at 95% (06 §5.2)
        abstention_mass=score.abstention_mass,
        gold_n=score.gold_n,
    )
