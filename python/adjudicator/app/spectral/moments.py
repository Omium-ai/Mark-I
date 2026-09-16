"""Vote encoding and cross-group agreement moments (06 §4.1 steps 1–2; Paper II App. A,
P_jl = M_j diag(π) M_lᵀ; symmetrisation per Zhang–Chen–Zhou–Jordan 2014 Alg. 1)."""

from collections.abc import Sequence
from itertools import permutations

import numpy as np

ACCEPT, REJECT, ABSTAIN = 0, 1, 2  # vote codes; -1 = the verifier did not run


def onehot(votes: np.ndarray) -> np.ndarray:
    """(N, V) int codes → (N, V, 3) floats; a missing vote (-1) is an all-zero row."""
    return (np.asarray(votes)[..., None] == np.arange(3)).astype(float)


def group_observations(oh: np.ndarray, groups: Sequence[str]) -> tuple[list[str], np.ndarray]:
    """One symbol per group per task: majority of non-abstaining members, ties → reject,
    no non-abstaining member → abstain. Returns (sorted group names, (N, G, 3) one-hots)."""
    names = sorted(set(groups))
    member = np.array([[g == n for n in names] for g in groups], dtype=float)
    counts = np.einsum("nvs,vg->ngs", oh, member)
    acc, rej = counts[..., ACCEPT], counts[..., REJECT]
    obs = np.full(acc.shape, ABSTAIN)
    obs[acc > rej] = ACCEPT
    obs[(rej >= acc) & (rej > 0)] = REJECT
    return names, np.eye(3)[obs]


def pair(x: np.ndarray, y: np.ndarray) -> np.ndarray:
    """Empirical cross-moment E[e_x ⊗ e_y] over tasks, (3, 3)."""
    return x.T @ y / len(x)


def sigma_k(m: np.ndarray, k: int) -> float:
    """k-th singular value: the smallest one the k-class model needs to be non-zero."""
    return float(np.linalg.svd(m, compute_uv=False)[k - 1])


def pinv_k(m: np.ndarray, k: int) -> np.ndarray:
    """Rank-k truncated pseudo-inverse; the full pinv would invert sampling noise in σ_{k+1}."""
    u, s, vt = np.linalg.svd(m)
    return (vt[:k].T / s[:k]) @ u[:, :k].T


def symmetric_moments(a: np.ndarray, b: np.ndarray, c: np.ndarray, k: int):
    """Re-express groups a, b in c's basis so M2 = M_c diag(π) M_cᵀ and M3 = Σ_y π_y M_c[:,y]^⊗3."""
    n = len(a)
    za = pair(c, b) @ pinv_k(pair(a, b), k)
    zb = pair(c, a) @ pinv_k(pair(b, a), k)
    a2, b2 = a @ za.T, b @ zb.T
    m2 = a2.T @ b2 / n
    m3 = np.einsum("ni,nj,nl->ijl", a2, b2, c) / n
    m3 = sum(m3.transpose(p) for p in permutations(range(3))) / 6
    return (m2 + m2.T) / 2, m3
