"""Spectral D-S (06 §4): Paper II §9 reproduced from UNLABELED votes, the §4.3 gate refusing
degenerate designs, §4.2 shrinkage, and the certificate ladder reaching CERTIFIED past the gate."""

import json
from pathlib import Path

import numpy as np
import pytest
from app.adjudicate.likelihoods import CALIBRATED_CONFUSION
from app.certs.state_machine import BOOTSTRAPPING, CERTIFIED, CertEvidence, next_status
from app.spectral.estimate import Estimate, estimate
from app.spectral.moments import ABSTAIN, ACCEPT, REJECT, group_observations, onehot
from app.spectral.shrinkage import deviation_alarm, shrink
from app.spectral.tensor import spectral_init

FIXTURE = json.loads(
    (Path(__file__).parent / "fixtures" / "paper2_worked_example.json").read_text()
)
NAMES = ("rubric", "rrm", "anchor")
PAPER2 = np.array(
    [
        [
            [a := FIXTURE["verifiers"][n]["accept_given_s"], 1 - a, 0.0],
            [b := FIXTURE["verifiers"][n]["accept_given_v"], 1 - b, 0.0],
        ]
        for n in NAMES
    ]
)
PI = FIXTURE["prior_satisfied"]
ANCHORS = [n == "anchor" for n in NAMES]


def _paper2(simulate, n: int = 50000, seed: int = 1) -> Estimate:
    votes, _ = simulate(np.random.default_rng(seed), [PI, 1 - PI], PAPER2, n)
    return estimate(votes, NAMES, ANCHORS)


def _eta(est: Estimate, pattern: tuple[int, ...]) -> float:
    """Paper II eq. (posterior) from the RECOVERED parameters."""
    odds = est.prior[1] / est.prior[0]
    for v, s in enumerate(pattern):
        odds *= est.confusion[v, 1, s] / est.confusion[v, 0, s]
    return 1 / (1 + odds)


def _verdict(eta: float) -> str:
    lo, hi = FIXTURE["band"]
    return "satisfied" if eta >= hi else "violated" if eta <= lo else "refused"


def test_paper2_worked_example_reproduced(simulate):
    est = _paper2(simulate)
    assert est.diagnostics.passed, est.diagnostics
    assert np.abs(est.confusion - PAPER2).max() < 0.02
    assert abs(est.prior[0] - PI) < 0.02
    # tab:surface from UNLABELED votes: every row's verdict, η within the finite-sample rate.
    code = {"accept": 0, "reject": 1}
    for row in FIXTURE["surface"]:
        got = _eta(est, tuple(code[p] for p in row["pattern"]))
        assert _verdict(got) == row["verdict"], (row, got)
        assert abs(got - row["eta"]) < 0.05 if row["eta"] > 0 else got < 0.1, (row, got)
    assert est.confusion[2, 0, 1] < 0.01  # the anchor's r ≈ 0 is RECOVERED, not assumed


def test_spectral_point_alone_is_consistent(simulate):
    # Thm 4.3 is about the spectral estimator BEFORE EM: the init must already be near truth.
    votes, _ = simulate(np.random.default_rng(1), [PI, 1 - PI], PAPER2, 50000)
    names, g = group_observations(onehot(votes), NAMES)
    laws, prior, cond = spectral_init(g, 2, np.random.default_rng(0))
    truth = PAPER2[[NAMES.index(n) for n in names]].transpose(0, 2, 1)
    if abs(prior[0] - PI) > abs(prior[1] - PI):  # labels are only identified up to swap
        laws, prior = laws[..., ::-1], prior[::-1]
    assert np.abs(laws - truth).max() < 0.05
    assert abs(prior[0] - PI) < 0.05
    assert cond < 100


def test_clique_collapse_rule():
    # 06 §4.1 step 1: majority of non-abstaining members, tie → reject, silence → abstain.
    oh = onehot(np.array([[0, 1], [0, 2], [2, 2], [-1, 1], [1, 0], [0, -1]]))
    names, g = group_observations(oh, ["g", "g"])
    assert names == ["g"]
    assert g[:, 0].argmax(1).tolist() == [REJECT, ACCEPT, ABSTAIN, REJECT, REJECT, ACCEPT]


def test_recovers_members_of_multi_verifier_cliques_with_abstention(simulate):
    # The bundle's literature rows (S, V only) as planted truth: two-member syntactic and
    # judge cliques, an abstaining judge, a lone RM — per-member laws come out of step 5.
    kinds = ["lint", "compile", "judge", "judge", "rm"]
    planted = np.array([CALIBRATED_CONFUSION[k][:2] for k in kinds])
    planted[3] = [[0.70, 0.10, 0.20], [0.15, 0.65, 0.20]]
    groups = ["syntactic", "syntactic", "judges", "judges", "rms"]
    votes, _ = simulate(np.random.default_rng(5), [0.55, 0.45], planted, 20000)
    est = estimate(votes, groups, [k == "compile" for k in kinds])
    assert est.diagnostics.passed, est.diagnostics
    assert est.diagnostics.triple == ("judges", "rms", "syntactic")
    assert np.abs(est.confusion - planted).max() < 0.03
    assert abs(est.prior[0] - 0.55) < 0.02


def _degenerate(simulate, case: str):
    rng = np.random.default_rng(3)
    if case == "G1":  # two cliques: Thm 4.1 needs three
        v, _ = simulate(rng, [PI, 1 - PI], PAPER2[:2], 5000)
        return estimate(v, NAMES[:2], ANCHORS[:2])
    if case == "G2":  # collinear: a third clique whose two class rows coincide (Kruskal rank 1)
        flat = np.array([[[0.5, 0.5, 0.0], [0.5, 0.5, 0.0]]])
        v, _ = simulate(rng, [PI, 1 - PI], np.concatenate([PAPER2[:2], flat]), 5000)
        return estimate(v, NAMES, ANCHORS)
    if case == "G3":  # too few tasks for the O(√(log/N)) rate to mean anything
        v, _ = simulate(rng, [PI, 1 - PI], PAPER2, 400)
        return estimate(v, NAMES, ANCHORS)
    v, _ = simulate(rng, [PI, 1 - PI], PAPER2, 5000)  # G4: no anchor ⇒ label swap unresolvable
    return estimate(v, NAMES, [False, False, False])


@pytest.mark.parametrize("gate", ["G1", "G2", "G3", "G4"])
def test_identifiability_gate_degrades_honestly(simulate, gate):
    est = _degenerate(simulate, gate)
    assert gate in est.diagnostics.failed, est.diagnostics
    assert not est.diagnostics.passed
    assert est.confusion is None and est.prior is None  # spectral path provably not taken


def test_shrinkage_weights_by_volume():
    tenant = np.array([[[0.60, 0.30, 0.10], [0.50, 0.40, 0.10]]])
    global_ = np.array([[[0.90, 0.05, 0.05], [0.20, 0.75, 0.05]]])
    gap = np.abs(tenant - global_).max()
    assert np.abs(shrink(tenant, [5], global_) - global_).max() < 0.03 * gap
    assert np.abs(shrink(tenant, [5000], global_) - tenant).max() < 0.04 * gap
    assert np.allclose(shrink(tenant, [5], global_).sum(-1), 1.0)
    prior = shrink(np.array([0.2, 0.8]), 5, np.array([0.6, 0.4]))
    assert abs(prior[0] - 0.6) < 0.02


def test_prior_deviation_routes_to_review():
    global_ = np.array([[[0.90, 0.05, 0.05], [0.20, 0.75, 0.05]]])
    assert not deviation_alarm(global_ + 0.0, global_)
    assert deviation_alarm(np.array([[[0.60, 0.30, 0.10], [0.20, 0.75, 0.05]]]), global_)
    assert deviation_alarm(np.array([0.2, 0.8]), np.array([0.6, 0.4]))


def test_cert_state_machine_transitions(simulate):
    def evidence(est: Estimate) -> CertEvidence:
        return CertEvidence(
            gold_n=250,
            fresh_frac=0.9,
            estimator_ran=True,
            identifiability_passed=est.diagnostics.passed,
            natarajan_ok=True,
        )

    assert next_status(BOOTSTRAPPING, evidence(_paper2(simulate, n=5000))) == CERTIFIED
    assert next_status(BOOTSTRAPPING, evidence(_degenerate(simulate, "G1"))) == BOOTSTRAPPING
    assert next_status(CERTIFIED, evidence(_degenerate(simulate, "G4"))) == BOOTSTRAPPING


def test_g5_g6_thresholds_bind_exactly(simulate, monkeypatch):
    import app.spectral.identifiability as ident

    votes, _ = simulate(np.random.default_rng(3), [PI, 1 - PI], PAPER2, 5000)
    d = estimate(votes, NAMES, ANCHORS).diagnostics
    assert (
        d.passed
        and 0 < d.bootstrap_dist < ident.BOOTSTRAP_DIST
        and d.condition < ident.CONDITION_MAX
    )
    monkeypatch.setattr(ident, "BOOTSTRAP_DIST", d.bootstrap_dist - 1e-9)
    assert "G5" in estimate(votes, NAMES, ANCHORS).diagnostics.failed
    monkeypatch.setattr(ident, "BOOTSTRAP_DIST", ident.BOOTSTRAP_DIST + 1)
    monkeypatch.setattr(ident, "CONDITION_MAX", d.condition - 1e-9)
    assert "G6" in estimate(votes, NAMES, ANCHORS).diagnostics.failed
