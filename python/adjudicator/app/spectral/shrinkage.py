"""Hierarchical shrinkage of per-tenant estimates toward the global pass (06 §4.2) and the
D7 deviation alarm that routes a tenant to manual review (FR-VERIFY-019)."""

import numpy as np

TAU = 200.0  # D6: the global prior is worth 200 tasks
DEVIATION_TV = 0.25  # D7: any row of the UNSHRUNK tenant estimate this far (TV) from global


def shrink(tenant: np.ndarray, n: np.ndarray | float, global_: np.ndarray, tau: float = TAU):
    """Ĉ = (n·Ĉ_t + τ·C_global) / (n + τ); n is per leading index (verifier) or a scalar (prior)."""
    w = np.asarray(n, dtype=float)
    w = w.reshape(w.shape + (1,) * (tenant.ndim - w.ndim))
    return (w * tenant + tau * global_) / (w + tau)


def deviation_alarm(tenant: np.ndarray, global_: np.ndarray, tv: float = DEVIATION_TV) -> bool:
    """True when any row (last axis) is more than `tv` total variation away: review, not publish."""
    return bool((0.5 * np.abs(tenant - global_).sum(-1) > tv).any())
