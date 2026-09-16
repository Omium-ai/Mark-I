"""The identifiability gate (06 §4.3, G1–G6): spectral output is USED only when every
precondition of Paper II Thm 4.1–4.3 is checked, never assumed. Diagnostics persist either way."""

from dataclasses import dataclass
from itertools import combinations, permutations

import numpy as np

from app.spectral.moments import ABSTAIN, pair, sigma_k
from app.spectral.tensor import spectral_init

COVERAGE_MIN = 0.60  # D8  G1: non-abstaining on ≥ 60% of tasks, ≥ 3 such groups
SIGMA_MIN = 0.05  # D9  G2: σ_k of every pairwise cross-moment in the triple
MIN_TASKS = 2000  # D10 G3 (per-tenant with shrinkage: 500)
ANCHOR_SEPARATION = 10.0  # D11 G4: anchor reject-rate ratio between the two orientations
BOOTSTRAP_DIST = 0.15  # D12 G5: max permutation-aligned entry drift over B resamples
BOOTSTRAP_B = 50
CONDITION_MAX = 1e3  # D13 G6: κ of M2 on its top-k eigenspace


@dataclass(frozen=True)
class Diagnostics:
    """All six §4.3 diagnostics plus which gates failed; stored on the certificate row."""

    n_tasks: int
    coverage: dict[str, float]
    triple: tuple[str, ...]
    sigma_min: float
    condition: float
    bootstrap_dist: float
    anchor_separation: float
    failed: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return not self.failed


def _aligned_dist(ref: np.ndarray, est: np.ndarray, k: int) -> float:
    """Entry-wise distance after the best column permutation (labels identified only up to it)."""
    return min(float(np.abs(est[..., list(p)] - ref).max()) for p in permutations(range(k)))


def diagnose(
    g: np.ndarray, names: list[str], k: int, min_n: int, rng: np.random.Generator
) -> tuple[Diagnostics, tuple[int, ...], np.ndarray | None, np.ndarray | None]:
    """G1–G3, G5, G6 on (N, G, 3) group one-hots → (diag with G4 pending, triple, laws, prior)."""
    n = len(g)
    coverage = {nm: float(1 - g[:, i, ABSTAIN].mean()) for i, nm in enumerate(names)}
    covered = [i for i, nm in enumerate(names) if coverage[nm] >= COVERAGE_MIN]
    failed = ["G1"] if len(covered) < 3 else []
    if n < min_n:
        failed.append("G3")
    if "G1" in failed:
        diag = Diagnostics(n, coverage, (), np.nan, np.nan, np.nan, np.nan, tuple(failed))
        return diag, (), None, None

    def weakest_pair(tri: tuple[int, ...]) -> float:
        return min(sigma_k(pair(g[:, i], g[:, j]), k) for i, j in combinations(tri, 2))

    triple = max(combinations(covered, 3), key=weakest_pair)
    sig = weakest_pair(triple)
    if sig < SIGMA_MIN:
        failed.append("G2")
    g3 = g[:, list(triple)]
    laws, prior, cond = spectral_init(g3, k, rng)
    if not cond <= CONDITION_MAX:
        failed.append("G6")
    dist = 0.0
    for _ in range(BOOTSTRAP_B):
        boot, _, c = spectral_init(g3[rng.integers(0, n, n)], k, rng)
        dist = max(dist, _aligned_dist(laws, boot, k) if np.isfinite(c) else np.inf)
    if not dist <= BOOTSTRAP_DIST:
        failed.append("G5")
    diag = Diagnostics(
        n, coverage, tuple(names[i] for i in triple), sig, cond, dist, np.nan, tuple(failed)
    )
    return diag, triple, laws, prior
