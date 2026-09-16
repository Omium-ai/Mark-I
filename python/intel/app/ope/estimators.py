"""SNIPS and doubly-robust estimators over LoggedRows (06 §11.1) with the §11.3 diagnostics.
Formulas are the section's, verbatim; q̂ is a ridge on one-hot context/action/cell features."""

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

import numpy as np

from app.ope.inputs import LoggedRow

Policy = Mapping[str, Mapping[str, float]]  # context -> action -> π(a|x); absent = 0

Z95 = 1.959964
W_MAX = 100.0  # D37: importance weights clipped here, clipped mass reported


@dataclass(frozen=True)
class Estimate:
    point: float
    se: float

    @property
    def lcb(self) -> float:
        return self.point - Z95 * self.se

    @property
    def ucb(self) -> float:
        return self.point + Z95 * self.se


@dataclass(frozen=True)
class Diagnostics:
    n: int
    ess: float
    max_w: float
    w_p99: float
    overlap: float
    clipped_mass: float


def prob(policy: Policy, context: str, action: str) -> float:
    return float(policy.get(context, {}).get(action, 0.0))


def weights(rows: Sequence[LoggedRow], policy: Policy) -> tuple[np.ndarray, float]:
    """w_i = π(a_i|x_i)/p_i clipped at W_MAX; second value is the clipped mass fraction."""
    raw = np.array([prob(policy, r.context, r.action) / r.propensity for r in rows])
    w = np.minimum(raw, W_MAX)
    total = raw.sum()
    return w, float((raw - w).sum() / total) if total > 0 else 0.0


def diagnostics(rows: Sequence[LoggedRow], policy: Policy) -> Diagnostics:
    w, clipped = weights(rows, policy)
    sq = float((w**2).sum())
    return Diagnostics(
        n=len(rows),
        ess=float(w.sum() ** 2 / sq) if sq > 0 else 0.0,
        max_w=float(w.max()) if len(w) else 0.0,
        w_p99=float(np.percentile(w, 99)) if len(w) else 0.0,
        overlap=float((w > 0).mean()) if len(w) else 0.0,
        clipped_mass=clipped,
    )


def snips(rows: Sequence[LoggedRow], policy: Policy) -> Estimate:
    """SNIPS(π) = Σ w_i·r_i / Σ w_i; se by the delta method on the ratio."""
    w, _ = weights(rows, policy)
    r = np.array([x.reward for x in rows])
    total = w.sum()
    if total <= 0:
        return Estimate(math.nan, math.inf)
    v = float((w * r).sum() / total)
    return Estimate(v, float(math.sqrt(((w * (r - v)) ** 2).sum()) / total))


class RewardModel:
    """q̂(x,a): ridge over [1, one-hot(x), one-hot(a), one-hot(x×a)]; unseen keys contribute 0."""

    def __init__(self, rows: Sequence[LoggedRow], lam: float = 1.0) -> None:
        self._cols: dict[object, int] = {"": 0}
        for r in rows:
            for key in (("x", r.context), ("a", r.action), ("xa", r.context, r.action)):
                self._cols.setdefault(key, len(self._cols))
        phi = np.stack([self._features(r.context, r.action) for r in rows])
        y = np.array([r.reward for r in rows])
        d = phi.shape[1]
        self._beta = np.linalg.solve(phi.T @ phi + lam * np.eye(d), phi.T @ y)
        self.support: dict[str, set[str]] = {}
        for r in rows:
            self.support.setdefault(r.context, set()).add(r.action)

    def _features(self, context: str, action: str) -> np.ndarray:
        f = np.zeros(len(self._cols))
        for key in ("", ("x", context), ("a", action), ("xa", context, action)):
            if key in self._cols:
                f[self._cols[key]] = 1.0
        return f

    def predict(self, context: str, action: str) -> float:
        return float(self._features(context, action) @ self._beta)


def dr_terms(
    rows: Sequence[LoggedRow], policy: Policy, qhat: RewardModel
) -> tuple[np.ndarray, np.ndarray]:
    """Per-row ψ_i = q̂(x_i,π) + w_i·(r_i − q̂(x_i,a_i)) on supported actions; second array is
    the DM mass on actions never logged in x_i (06 §11.4 DM_extrapolated, reported, never used)."""
    w, _ = weights(rows, policy)
    psi = np.zeros(len(rows))
    ext = np.zeros(len(rows))
    for i, r in enumerate(rows):
        for a, p in policy.get(r.context, {}).items():
            if a in qhat.support.get(r.context, ()):
                psi[i] += p * qhat.predict(r.context, a)
            else:
                ext[i] += p * qhat.predict(r.context, a)
        psi[i] += w[i] * (r.reward - qhat.predict(r.context, r.action))
    return psi, ext


def mean_estimate(terms: np.ndarray) -> Estimate:
    n = len(terms)
    if n == 0:
        return Estimate(math.nan, math.inf)
    se = float(terms.std(ddof=1) / math.sqrt(n)) if n > 1 else math.inf
    return Estimate(float(terms.mean()), se)


def doubly_robust(
    rows: Sequence[LoggedRow], policy: Policy, qhat: RewardModel
) -> tuple[Estimate, float]:
    """DR(π) = (1/n) Σ ψ_i; returns (estimate, DM_extrapolated)."""
    psi, ext = dr_terms(rows, policy, qhat)
    return mean_estimate(psi), float(ext.mean()) if len(ext) else 0.0
