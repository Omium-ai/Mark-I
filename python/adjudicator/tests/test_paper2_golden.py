"""The Phase 2 verification gate (execution-plan-v2 §Verification): "adjudicator unit
tests against synthetic verifier outputs reproducing Paper II's posterior/verdict
table". Every row of the paper's §9 decision surface (tab:surface) — including the
η = 0.612 → refused band row and the counterfactual anchor-reject veto rows — must fall
out of adjudicate() exactly, plus the event-E row via the error path (Thm 5.2)."""

import json
import math
from pathlib import Path
from uuid import uuid4

import pytest
from app.adjudicate.algorithm import adjudicate
from app.adjudicate.chow import Costs
from app.adjudicate.likelihoods import Bundle, VerifierParams
from app.registry.handlers import NormalizedVote
from app.registry.integrity import IntegrityFlags

FIXTURE = json.loads(
    (Path(__file__).parent / "fixtures" / "paper2_worked_example.json").read_text()
)

PI = FIXTURE["prior_satisfied"]
# The paper's example is the binary S-vs-V projection; the four-class machinery
# reproduces it exactly under zero refused/error priors (log-space handles the exact
# -inf; no epsilon may soften it — Paper II §9: anchor rejection forces odds 0).
PRIORS = (PI, 1.0 - PI, 0.0, 0.0)
COSTS = Costs(
    a=FIXTURE["costs_tokens"]["A"],
    r=FIXTURE["costs_tokens"]["R"],
    d=FIXTURE["costs_tokens"]["D"],
)
_UNIFORM = (1 / 3, 1 / 3, 1 / 3)  # R/E rows: never consulted under zero prior


def _params(name: str) -> VerifierParams:
    spec = FIXTURE["verifiers"][name]
    a_s, a_v = spec["accept_given_s"], spec["accept_given_v"]
    return VerifierParams(
        verifier_id=name,
        kind="paper2",
        confusion=(
            (a_s, 1.0 - a_s, 0.0),  # satisfied: [accept, reject, abstain]
            (a_v, 1.0 - a_v, 0.0),  # violated  (anchor: reject|S = 0 EXACTLY — r=0)
            _UNIFORM,
            _UNIFORM,
        ),
        group=name,  # three independent cliques (Paper II §9)
        provenance="prior",
    )


BUNDLE = Bundle(priors=PRIORS, verifiers={n: _params(n) for n in ("rubric", "rrm", "anchor")})


def _vote(verifier: str, vote: str, **integrity) -> NormalizedVote:
    return NormalizedVote(
        verifier_id=verifier,
        kind="paper2",
        task_id=uuid4(),
        attempt_id=uuid4(),
        vote=vote,
        evidence_digest=b"",
        integrity=IntegrityFlags(**integrity),
        tier="T0",
    )


def _run(pattern):
    votes = [_vote(n, v) for n, v in zip(("rubric", "rrm", "anchor"), pattern, strict=True)]
    return adjudicate(votes, BUNDLE, COSTS)


@pytest.mark.parametrize("row", FIXTURE["surface"], ids=lambda r: "-".join(r["pattern"]))
def test_decision_surface_row(row):
    event = _run(row["pattern"])
    eta = event.posterior[0]
    assert event.verdict == row["verdict"]
    # Table prints η to 3 decimals — reproduce it at print precision, exactly.
    assert round(eta, 3) == row["eta"]
    # The likelihood-ratio column: posterior odds ÷ prior odds.
    if eta < 1.0:
        lr = (eta / (1.0 - eta)) / (PI / (1.0 - PI))
        assert round(lr, 3) == pytest.approx(row["likelihood_ratio"], abs=5e-3)
    # Zero refused/error prior ⇒ zero refused/error posterior mass, exactly.
    assert event.posterior[2] == 0.0
    assert event.posterior[3] == 0.0


def test_the_band_row_is_refused_through_the_anchor_accept_path():
    """06 §3.2(b): Paper II's own §9 worked example lands at η = 0.612 → refused
    THROUGH the anchor-accept path — the conformance fixture's named row."""
    event = _run(["accept", "reject", "accept"])
    assert event.verdict == "refused"
    assert round(event.posterior[0], 3) == 0.612
    lo, hi = COSTS.band
    assert round(lo, 3) == FIXTURE["band"][0]
    assert round(hi, 3) == FIXTURE["band"][1]
    assert lo < event.posterior[0] < hi  # squarely inside the abstention band


def test_anchor_reject_vetoes_regardless_of_other_verifiers():
    """The counterfactual anchor-reject rows: a perfect-precision (r = 0) anchor
    rejection collapses the satisfied mass to EXACTLY zero — the clamp is the
    likelihood, no special-case branch (06 §3.1 step 1 / Paper II Thm 4.2)."""
    for others in (("accept", "accept"), ("accept", "reject"), ("reject", "accept")):
        event = _run([others[0], others[1], "reject"])
        assert event.verdict == "violated"
        assert event.posterior[0] == 0.0


def test_unanimous_acceptance_posterior_odds():
    """Paper §9: unanimous acceptance yields posterior odds 14.2 (η = 0.934)."""
    event = _run(["accept", "accept", "accept"])
    eta = event.posterior[0]
    assert round(eta / (1.0 - eta), 1) == FIXTURE["unanimous_posterior_odds"]


def test_banded_pattern_mass_is_the_papers_coverage_arithmetic():
    """cor:coverage made explicit in §9: the lone banded pattern (acc rej acc) has
    population mass 0.139 — 86.1% coverage. Pure fixture arithmetic, kept here so a
    likelihood-row typo in the fixture cannot silently pass the surface tests."""
    v = FIXTURE["verifiers"]
    mass = PI * (v["rubric"]["accept_given_s"] * (1 - v["rrm"]["accept_given_s"]) * 1.0) + (
        1 - PI
    ) * (v["rubric"]["accept_given_v"] * (1 - v["rrm"]["accept_given_v"]) * 0.60)
    assert round(mass, 3) == FIXTURE["banded_pattern_mass"]


def test_event_e_is_error_never_violated():
    """The surface's last row: any pattern on event E → error (Thm 5.2 — the system
    cannot manufacture a customer-facing failure out of its own outage)."""
    votes = [
        _vote("rubric", "abstain", infra_failed=True),
        _vote("rrm", "abstain", infra_failed=True),
        _vote("anchor", "abstain", infra_failed=True),
    ]
    event = adjudicate(votes, BUNDLE, COSTS)
    assert event.verdict == "error"
    assert event.reason == "insufficient_evidence"
    assert event.posterior == (0.0, 0.0, 0.0, 1.0)


def test_infra_dominant_pattern_is_error_even_with_a_live_vote():
    """Majority-infra window: the posterior is computed but the verdict is `error`
    (06 §3.1 step 3's infra_dominant arm), never a confident claim about the code."""
    votes = [
        _vote("rubric", "abstain", infra_failed=True),
        _vote("rrm", "abstain", infra_failed=True),
        _vote("anchor", "accept"),
    ]
    event = adjudicate(votes, BUNDLE, COSTS)
    assert event.verdict == "error"
    assert math.isclose(sum(event.posterior), 1.0)
