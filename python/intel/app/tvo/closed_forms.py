"""Paper I closed forms (06 §8.1). The FORMS are PROVED and frozen — changing one is an ADR;
the *inputs* are measured ledger quantities (06 §0 traceability table). Domain checks raise
rather than extrapolate: a formula evaluated outside its theorem's preconditions is fiction."""

import math


def _check_unit(name: str, x: float, *, lo_open: bool = False, hi: float = 1.0) -> None:
    lo_ok = x > 0.0 if lo_open else x >= 0.0
    if not (lo_ok and x <= hi):
        lo = "(0" if lo_open else "[0"
        raise ValueError(f"{name}={x!r} outside {lo}, {hi}]")


def _check_nonneg(name: str, x: float) -> None:
    if x < 0.0:
        raise ValueError(f"{name}={x!r} must be >= 0")


def tvo(c: float, v: float, p: float, alpha: float, beta: float, d: float) -> float:
    """Paper I Thm 4.1: TVO = (c + v + (1-p)·β·D) / (p·α). Tokens per verified outcome.

    Finiteness requires p·α > 0 (the theorem's own condition), so p and α must be
    strictly positive here; p→0 or α→0 is a session that never verifiably completes.
    """
    _check_nonneg("c", c)
    _check_nonneg("v", v)
    _check_nonneg("D", d)
    _check_unit("p", p, lo_open=True)
    _check_unit("alpha", alpha, lo_open=True)
    _check_unit("beta", beta)
    return (c + v + (1.0 - p) * beta * d) / (p * alpha)


def verifier_break_even(c: float, p: float, alpha: float, beta: float, d: float) -> float:
    """Paper I Thm 4.2: v* = (1-p)·D·(α-β) − c·(1-α). Max verifier spend that still pays.

    v* ≤ 0 means the verifier cannot pay for itself at any price, even free — the
    α=β (random/accept-all) case the paper calls out is exactly −c·(1-α) ≤ 0.

    Domain: the theorem's proof compares (c+v+(1-p)βD)/(pα) against the baseline
    (c+(1-p)D)/p (paper1-tvo.tex, Thm 4.2 proof), so it divides by both p and p·α —
    p=0 or α=0 is outside the derivation domain and the formula's value there is
    fiction, not a limit. Refuse, per this module's header rule.
    """
    _check_nonneg("c", c)
    _check_nonneg("D", d)
    _check_unit("p", p, lo_open=True)
    _check_unit("alpha", alpha, lo_open=True)
    _check_unit("beta", beta)
    return (1.0 - p) * d * (alpha - beta) - c * (1.0 - alpha)


def repair_knee(rho: float, gamma: float) -> int:
    """Paper I Thm 5.1: k* = 1 + ⌊ln ρ / ln γ⌋. Compute-optimal repair rounds before resampling.

    Preconditions from the theorem, verbatim: "Assume ρ<1 (repair rounds are cheaper
    than fresh attempts) and geometric decay γ ∈ (0,1)" (paper1-tvo.tex Thm 5.1).
    Both bounds are STRICT — ρ = 1 (repair as dear as resample) and a non-decaying γ
    are outside the interchange argument's domain; raise, never fabricate a horizon.
    """
    if not 0.0 < rho < 1.0:
        raise ValueError(
            f"rho={rho!r} outside (0, 1) — Thm 5.1 assumes repair rounds are strictly "
            "cheaper than fresh attempts (rho < 1)"
        )
    if not 0.0 < gamma < 1.0:
        raise ValueError(f"gamma={gamma!r} outside (0, 1) — Thm 5.1 assumes geometric decay")
    return 1 + math.floor(math.log(rho) / math.log(gamma))
