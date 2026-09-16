"""Spectral reduction (06 §4.1 step 3): whiten M2, robust tensor power iteration on
M3(W,W,W) (Anandkumar et al. 2014 Alg. 1), un-whiten to group laws and the prior."""

import numpy as np

from app.spectral.moments import pair, symmetric_moments

_FLOOR = 1e-9


def whiten(m2: np.ndarray, k: int) -> tuple[np.ndarray, np.ndarray, float]:
    """(W, B, κ): Wᵀ M2 W = I_k on the top-k eigenspace, B = (Wᵀ)⁺, κ = λ₁/λ_k."""
    lam, u = np.linalg.eigh(m2)
    lam, u = lam[::-1][:k], u[:, ::-1][:, :k]
    if lam[-1] <= 0:
        return u, u, np.inf
    return u / np.sqrt(lam), u * np.sqrt(lam), float(lam[0] / lam[-1])


def power_iteration(
    t: np.ndarray, rng: np.random.Generator, restarts: int = 10, iters: int = 50
) -> tuple[np.ndarray, np.ndarray]:
    """k robust eigenpairs (λ_y, v_y) of a symmetric k×k×k tensor, by deflation."""
    k = t.shape[0]
    lams, vecs = [], []
    for _ in range(k):
        lam, th = 0.0, np.zeros(k)
        for _ in range(restarts):
            cand = rng.standard_normal(k)
            for _ in range(iters):
                cand = np.einsum("ijl,j,l->i", t, cand, cand)
                cand /= np.linalg.norm(cand) + _FLOOR
            val = float(np.einsum("ijl,i,j,l", t, cand, cand, cand))
            if abs(val) > abs(lam):
                lam, th = val, cand
        if lam < 0:
            lam, th = -lam, -th
        lams.append(lam)
        vecs.append(th)
        t = t - lam * np.einsum("i,j,l->ijl", th, th, th)
    return np.array(lams), np.array(vecs).T


def _law(m: np.ndarray) -> np.ndarray:
    """Clip to the simplex column-wise; a spectral point is an initialiser, not a count."""
    m = np.clip(m, _FLOOR, None)
    return m / m.sum(0, keepdims=True)


def spectral_init(
    g: np.ndarray, k: int, rng: np.random.Generator
) -> tuple[np.ndarray, np.ndarray, float]:
    """(N, 3 groups, 3 symbols) → (laws (3, 3, k), prior (k,), κ); labels up to permutation."""
    a, b, c = g[:, 0], g[:, 1], g[:, 2]
    m2, m3 = symmetric_moments(a, b, c, k)
    w, unwhiten, cond = whiten(m2, k)
    if not np.isfinite(cond):
        return np.full((3, 3, k), 1 / 3), np.full(k, 1 / k), cond
    lams, vecs = power_iteration(np.einsum("ijl,ia,jb,lc->abc", m3, w, w, w), rng)
    mu_c = _law(unwhiten @ (vecs * lams))
    pi = 1 / np.clip(lams, _FLOOR, None) ** 2
    pi = pi / pi.sum()
    mu_a = _law(np.linalg.lstsq(mu_c * pi, pair(c, a), rcond=None)[0].T)
    mu_b = _law(np.linalg.lstsq(mu_c * pi, pair(c, b), rcond=None)[0].T)
    return np.stack([mu_a, mu_b, mu_c]), pi, cond
