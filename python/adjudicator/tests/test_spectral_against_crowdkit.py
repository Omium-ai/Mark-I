"""06 §4.5: crowd-kit's DawidSkene is the TEST ORACLE for our spectral D-S — the one file
allowed to import it (ruff.toml). Same synthetic votes, both estimators, tolerance asserted."""

import numpy as np
import pandas as pd
import pytest
from app.spectral.estimate import estimate
from crowdkit.aggregation import DawidSkene

# Five independent verifiers (each its own clique), binary votes so crowd-kit's label
# alphabet {accept, reject} coincides with the latent {satisfied, violated}; e is the anchor.
PLANTED = np.array(
    [
        [[0.90, 0.10, 0.0], [0.15, 0.85, 0.0]],
        [[0.80, 0.20, 0.0], [0.30, 0.70, 0.0]],
        [[0.85, 0.15, 0.0], [0.20, 0.80, 0.0]],
        [[0.75, 0.25, 0.0], [0.25, 0.75, 0.0]],
        [[0.97, 0.03, 0.0], [0.55, 0.45, 0.0]],
    ]
)
PRIOR = np.array([0.6, 0.4])
GROUPS = list("abcde")
ANCHORS = [False, False, False, False, True]
N = 6000


def _crowdkit(votes: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """(errors (V, 2, 2) rows [S, V] × [accept, reject], prior [S, V], probas (N, 2))."""
    label = np.where(votes == 0, "accept", "reject")
    rows = [(t, f"w{w}", label[t, w]) for t in range(len(votes)) for w in range(votes.shape[1])]
    ds = DawidSkene(n_iter=200, tol=1e-8).fit(
        pd.DataFrame(rows, columns=["task", "worker", "label"])
    )
    sym = ["accept", "reject"]
    errors = np.array(
        [
            [[ds.errors_.loc[(f"w{w}", s), t] for s in sym] for t in sym]
            for w in range(votes.shape[1])
        ]
    )
    prior = ds.priors_[sym].to_numpy()
    probas = ds.probas_.sort_index()[sym].to_numpy()
    return errors, prior, probas


@pytest.fixture
def votes(simulate) -> np.ndarray:
    return simulate(np.random.default_rng(7), PRIOR, PLANTED, N)[0]


def test_spectral_ds_recovers_planted_matrices(votes):
    est = estimate(votes, GROUPS, ANCHORS)
    assert est.diagnostics.passed, est.diagnostics
    assert np.abs(est.confusion - PLANTED).max() < 0.05
    assert np.abs(est.prior - PRIOR).max() < 0.02


def test_spectral_matches_crowdkit_dawid_skene(votes):
    est = estimate(votes, GROUPS, ANCHORS)
    errors, prior, probas = _crowdkit(votes)
    assert np.abs(est.confusion[:, :, :2] - errors).max() < 0.02
    assert np.abs(est.prior - prior).max() < 0.02
    assert np.abs(est.posterior - probas).mean() < 0.01
    assert (est.posterior.argmax(1) == probas.argmax(1)).mean() > 0.99


def test_paper2_example_spectral_init_beats_majority_vote_init(simulate):
    # 06 §4.5 reason (1) measured: on Paper II's own three weak cliques, EM from majority
    # vote lands on a worse local optimum; the spectral point lands on the truth.
    planted = np.array(
        [
            [[0.85, 0.15, 0.0], [0.20, 0.80, 0.0]],
            [[0.75, 0.25, 0.0], [0.25, 0.75, 0.0]],
            [[1.00, 0.00, 0.0], [0.60, 0.40, 0.0]],
        ]
    )
    v, _ = simulate(np.random.default_rng(1), [0.4, 0.6], planted, 20000)
    est = estimate(v, ["rubric", "rrm", "anchor"], [False, False, True])
    errors, prior, _ = _crowdkit(v)
    assert np.abs(est.confusion - planted).max() < 0.03
    assert np.abs(errors - planted[:, :, :2]).max() > 0.08
    assert abs(prior[0] - 0.4) > 0.08 > abs(est.prior[0] - 0.4)
