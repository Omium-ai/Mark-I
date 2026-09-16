"""Candidate vs incumbent route policy (06 §11.3 promotion floor, §11.4 ε = 0 refusal)."""

from collections.abc import Sequence
from dataclasses import dataclass
from functools import partial
from typing import Literal

import numpy as np

from app.ope.estimators import (
    Z95,
    Diagnostics,
    Estimate,
    Policy,
    RewardModel,
    diagnostics,
    dr_terms,
    mean_estimate,
    snips,
)
from app.ope.inputs import LoggedRow

ESS_MIN = 200.0  # D35
ESS_FRAC_MIN = 0.05  # D36

Decision = Literal[
    "promote",
    "not_better",
    "insufficient_evidence",
    "diagnostic_failure",
    "non_regression_on_overlap",
]


@dataclass(frozen=True)
class Scorecard:
    dr: Estimate
    snips: Estimate
    dm_extrapolated: float
    diagnostics: Diagnostics


@dataclass(frozen=True)
class Verdict:
    decision: Decision
    claim: str
    candidate: Scorecard
    incumbent: Scorecard
    diff: Estimate


def score(
    rows: Sequence[LoggedRow], policy: Policy, qhat: RewardModel
) -> tuple[Scorecard, np.ndarray]:
    psi, ext = dr_terms(rows, policy, qhat)
    return Scorecard(
        mean_estimate(psi), snips(rows, policy), float(ext.mean()), diagnostics(rows, policy)
    ), psi


def compare(
    rows: Sequence[LoggedRow], candidate: Policy, incumbent: Policy, lam: float = 1.0
) -> Verdict:
    """Promote iff ESS ≥ 200, ESS/n ≥ 0.05, DR_LCB95(cand) > DR_point(inc), SNIPS agrees with DR,
    and the log carries real exploration (some p_i < 1); `diff` is the paired DR CI, reported."""
    if not rows:
        empty = Estimate(float("nan"), float("inf"))
        diag = Diagnostics(0, 0.0, 0.0, 0.0, 0.0, 0.0)
        card = Scorecard(empty, empty, 0.0, diag)
        return Verdict("insufficient_evidence", "no admitted rows", card, card, empty)
    qhat = RewardModel(rows, lam)
    cand, psi_c = score(rows, candidate, qhat)
    inc, psi_i = score(rows, incumbent, qhat)
    diff = mean_estimate(psi_c - psi_i)
    d = cand.diagnostics
    verdict = partial(Verdict, candidate=cand, incumbent=inc, diff=diff)
    if d.ess < ESS_MIN or d.ess / d.n < ESS_FRAC_MIN:
        return verdict("insufficient_evidence", f"ESS = {d.ess:.1f} of n = {d.n}")
    if abs(cand.dr.point - cand.snips.point) > Z95 * np.hypot(cand.dr.se, cand.snips.se):
        return verdict("diagnostic_failure", "DR and SNIPS disagree beyond the joint CI")
    versus = f"DR_LCB {cand.dr.lcb:.4f} vs incumbent {inc.dr.point:.4f}"
    if all(r.propensity == 1.0 for r in rows):
        claim = f"non-regression on overlap, ESS = {d.ess:.0f}"
        return verdict("non_regression_on_overlap" if diff.ucb >= 0 else "not_better", claim)
    if cand.dr.lcb > inc.dr.point:
        return verdict("promote", versus)
    return verdict("not_better", versus)
