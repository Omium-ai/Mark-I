"""SPECTRAL_DS (06 §4.1; Paper II Alg. 1 lines 1–3): spectral init → EM refinement → per-verifier
recovery → anchor orientation (Thm 4.2), gated by §4.3. Latent classes are Paper II's binary
Y ∈ {satisfied, violated}; refused/error rows are not identifiable from a 3-symbol alphabet."""

from collections.abc import Sequence
from dataclasses import dataclass, replace

import numpy as np

from app.spectral.identifiability import ANCHOR_SEPARATION, MIN_TASKS, Diagnostics, diagnose
from app.spectral.moments import REJECT, group_observations, onehot

PSEUDO = 0.5  # Jeffreys pseudo-count on the M-step: EM is a MAP, no law ever hits an exact 0


@dataclass(frozen=True)
class Estimate:
    """Per-verifier laws (V, k, 3) rows [satisfied, violated] × [accept, reject, abstain] and prior
    (k,) — both None unless the gate passed; n_votes (V,) are the §4.2 shrinkage weights."""

    confusion: np.ndarray | None
    prior: np.ndarray | None
    posterior: np.ndarray | None
    n_votes: np.ndarray
    diagnostics: Diagnostics


def posteriors(g: np.ndarray, laws: np.ndarray, prior: np.ndarray) -> np.ndarray:
    """E-step: q[n, y] ∝ π_y Π_g M_g[X_gn | y] — one factor PER GROUP (clique collapse)."""
    ll = np.log(prior) + np.einsum("ngs,gsy->ny", g, np.log(laws))
    q = np.exp(ll - ll.max(1, keepdims=True))
    return q / q.sum(1, keepdims=True)


def laws_from(oh: np.ndarray, q: np.ndarray, pseudo: float = PSEUDO) -> np.ndarray:
    """M-step: posterior-weighted symbol frequencies, (X, 3, k)."""
    num = np.einsum("nxs,ny->xsy", oh, q) + pseudo
    return num / num.sum(1, keepdims=True)


def member_laws(oh, g, laws, prior, q, member_of: np.ndarray) -> np.ndarray:
    """Step 5, Paper II App. 'Extra cliques': a lone member IS its clique's law; a member of a
    multi-verifier clique solves E[e_v g] = M_v E[1_Y g], g = the leave-its-clique-out posterior."""
    conf = np.empty((oh.shape[1], 3, len(prior)))
    for j in range(g.shape[1]):
        members = np.flatnonzero(member_of == j)
        if len(members) == 1:
            conf[members[0]] = laws[j]
            continue
        keep = [i for i in range(g.shape[1]) if i != j]
        loo = posteriors(g[:, keep], laws[keep], prior)
        a = np.einsum("nvs,ny->vsy", oh[:, members], loo) / len(oh)
        m = np.clip(a @ np.linalg.pinv(q.T @ loo / len(oh)), 1e-9, None)
        conf[members] = m / m.sum(1, keepdims=True)
    return conf


def em(g: np.ndarray, laws: np.ndarray, prior: np.ndarray, iters: int, tol: float):
    """EM from the spectral point (Zhang et al. 2014: one round keeps the rate; more only climb)."""
    for _ in range(iters):
        q = posteriors(g, laws, prior)
        new = laws_from(g, q)
        done = np.abs(new - laws).max() < tol
        laws, prior = new, q.mean(0)
        if done:
            break
    return laws, prior


def orient(conf: np.ndarray, anchors: np.ndarray, n_votes: np.ndarray) -> tuple[list[int], float]:
    """Thm 4.2: satisfied is the class the pooled anchors almost never reject → (perm, ratio)."""
    w = n_votes * anchors
    if w.sum() == 0:
        return list(range(conf.shape[2])), 0.0
    r = w @ conf[:, REJECT, :] / w.sum()
    s = int(np.argmin(r))
    rest = [y for y in range(len(r)) if y != s]
    return [s, *rest], float(r[rest].min() / max(r[s], 1e-12))


def estimate(
    votes: np.ndarray,
    groups: Sequence[str],
    anchors: Sequence[bool],
    *,
    k: int = 2,
    min_n: int = MIN_TASKS,
    em_iters: int = 100,
    tol: float = 1e-6,
    seed: int = 0,
) -> Estimate:
    """votes (N, V) codes 0/1/2 (-1 missing), groups per verifier, anchor mask → Estimate."""
    rng = np.random.default_rng(seed)
    oh = onehot(votes)
    n_votes = oh.sum((0, 2))
    names, g = group_observations(oh, groups)
    diag, triple, laws3, prior = diagnose(g, names, k, min_n, rng)
    if laws3 is None or not np.isfinite(diag.condition):
        return Estimate(None, None, None, n_votes, replace(diag, failed=(*diag.failed, "G4")))
    q = posteriors(g[:, list(triple)], laws3, prior)
    laws, prior = em(g, laws_from(g, q), q.mean(0), em_iters, tol)
    q = posteriors(g, laws, prior)
    member_of = np.array([names.index(x) for x in groups])
    conf = member_laws(oh, g, laws, prior, q, member_of)
    perm, sep = orient(conf, np.asarray(anchors, dtype=float), n_votes)
    failed = diag.failed + (("G4",) if sep < ANCHOR_SEPARATION else ())
    diag = replace(diag, anchor_separation=sep, failed=failed)
    if failed:
        return Estimate(None, None, None, n_votes, diag)
    return Estimate(conf[:, :, perm].transpose(0, 2, 1), prior[perm], q[:, perm], n_votes, diag)
