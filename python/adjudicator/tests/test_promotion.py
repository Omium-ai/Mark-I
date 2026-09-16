"""06 §12.4 promotion math and the shadow split: the Youden influence samples, the
empirical-Bernstein twin of intel's admit.py, decide's three arms, and the proof through
adjudicate() that a shadow member's votes never enter fusion."""

import math
import random
from uuid import uuid4

import pytest
from app.adjudicate.algorithm import adjudicate
from app.adjudicate.likelihoods import Bundle, VerifierParams
from app.registry.handlers import NormalizedVote
from app.registry.integrity import IntegrityFlags
from app.registry.promotion import (
    DELTA,
    SHADOW_MIN,
    ShadowPair,
    decide,
    lcb_ucb,
    split_shadow,
    youden,
    youden_samples,
)


def pairs(n: int, tpr: float, fpr: float, seed: int = 1, cert: str = "c") -> list[ShadowPair]:
    rng = random.Random(seed)
    out = []
    for i in range(n):
        verdict = "violated" if i % 2 else "satisfied"
        p = tpr if verdict == "violated" else fpr
        out.append(ShadowPair("reject" if rng.random() < p else "accept", verdict, cert))
    return out


def test_youden_samples_mean_is_tpr_minus_fpr():
    ps = pairs(1000, 0.8, 0.1)
    u, phi = youden_samples(ps)
    rej_v = sum(1 for p in ps if p.verdict == "violated" and p.vote == "reject")
    rej_s = sum(1 for p in ps if p.verdict == "satisfied" and p.vote == "reject")
    assert math.isclose(sum(u) / len(u), rej_v / 500 - rej_s / 500)
    assert phi == 2.0 and all(abs(x) <= phi for x in u)


def test_youden_samples_hold_out_refused_and_error_and_need_both_classes():
    ps = pairs(10, 1.0, 0.0) + [
        ShadowPair("reject", "refused", "c"),
        ShadowPair("reject", "error", "c"),
    ]
    u, _ = youden_samples(ps)
    assert len(u) == 10
    assert youden_samples([ShadowPair("reject", "violated", "c")] * 5) == ([], 0.0)


def test_lcb_formula_pinned_to_admit_py():
    samples = [1.0, -1.0, 0.5, 0.25, 0.0, 0.75, -0.5, 0.5]
    n, phi = len(samples), 1.0
    ln = math.log(2 / DELTA)
    mean = sum(samples) / n
    var = sum((x - mean) ** 2 for x in samples) / (n - 1)
    slack = math.sqrt(2 * var * ln / n) + 7 * phi * ln / (3 * (n - 1))
    lcb, ucb = lcb_ucb(samples, phi)
    assert math.isclose(lcb, mean - slack) and math.isclose(ucb, mean + slack)


def test_decide_arms():
    assert decide(pairs(SHADOW_MIN - 1, 0.9, 0.0), 0.0).verdict == "insufficient_evidence"
    good = decide(pairs(600, 0.8, 0.1), 0.0)
    assert good.verdict == "promote" and 0 < good.lcb < youden(
        ((0, 0.1, 0), (0, 0.8, 0), (0, 0, 0), (0, 0, 0))
    )
    assert decide(pairs(600, 0.8, 0.1), 0.6).verdict == "insufficient_evidence"
    assert decide(pairs(600, 0.3, 0.3), 0.5).verdict == "regress"


def test_youden_of_abstain_always_is_zero():
    assert youden(((0.0, 0.0, 1.0),) * 4) == 0.0


def _vote(vid: str, kind: str, vote: str) -> NormalizedVote:
    return NormalizedVote(vid, kind, uuid4(), uuid4(), vote, b"", IntegrityFlags(), "T0")  # type: ignore[arg-type]


RUFF = VerifierParams("ruff@1", "lint", ((0.8, 0.1, 0.1),) * 4, "syntactic", "prior")
JUDGE = VerifierParams(
    "judge:a@1",
    "judge",
    ((0.85, 0.1, 0.05), (0.2, 0.75, 0.05), (0.3, 0.3, 0.4), (0.3, 0.3, 0.4)),
    "judges",
    "prior",
)
CANDIDATE = VerifierParams(
    "rm:cand@1",
    "rm",
    ((0.99, 0.01, 0.0), (0.01, 0.99, 0.0), (0.5, 0.5, 0.0), (0.5, 0.5, 0.0)),
    "rms",
    "prior",
)


@pytest.mark.parametrize("calibrated_defaults", [False, True])
def test_shadow_votes_never_enter_fusion(calibrated_defaults: bool):
    """Positive control: listed in the bundle, the candidate's reject flips the fusion.
    Split off as shadow, the fusion is bit-identical to a world where it never voted."""
    bundle = Bundle(
        verifiers={p.verifier_id: p for p in (RUFF, JUDGE, CANDIDATE)},
        calibrated_defaults=calibrated_defaults,
    )
    honest = [_vote("ruff@1", "lint", "accept"), _vote("judge:a@1", "judge", "accept")]
    votes = [*honest, _vote("rm:cand@1", "rm", "reject")]
    baseline = adjudicate(honest, bundle)
    counted = adjudicate(votes, bundle)
    assert counted.posterior != baseline.posterior and counted.verdict != baseline.verdict

    fused, shadow = split_shadow(votes, {"rm:cand@1"})
    assert [v.verifier_id for v in shadow] == ["rm:cand@1"]
    got = adjudicate(fused, bundle)
    assert (got.posterior, got.verdict, got.vote_count) == (
        baseline.posterior,
        baseline.verdict,
        baseline.vote_count,
    )
