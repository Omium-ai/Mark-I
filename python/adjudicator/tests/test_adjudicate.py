"""ADJUDICATE's own worked example (06 §3.2 — the four-class Rust task) plus every
branch of the pseudocode: tamper partition, insufficient evidence, clique collapse,
abstention symmetry, the calibrated-default fallback, and the zero-mass refusal."""

import math
from uuid import uuid4

import pytest
from app.adjudicate.algorithm import VerdictEvent, adjudicate
from app.adjudicate.chow import Costs
from app.adjudicate.likelihoods import (
    Bundle,
    VerifierParams,
    calibrated_params,
)
from app.registry.handlers import NormalizedVote
from app.registry.integrity import IntegrityFlags

# 06 §3.2's bundle: priors and the three verifiers' likelihood columns, verbatim where
# the doc prints them (cargo accept row 0.98/0.60/0.50/0.50, judge reject row
# 0.15/0.70/0.40/0.40, ruff's symmetric 0.70 abstention); rows the doc leaves open
# (cargo's reject|R, reject|E) are fixed at 0.02 — the values under which the doc's
# stated counterfactual "violated at ≥ 0.95" holds.
PRIORS = (0.55, 0.30, 0.10, 0.05)
CARGO = VerifierParams(
    "cargo-check-warm",
    "compile",
    confusion=(
        (0.98, 0.02, 0.00),  # satisfied — reject|S = ε_anchor (D2)
        (0.60, 0.40, 0.00),  # violated
        (0.50, 0.02, 0.48),  # refused
        (0.50, 0.02, 0.48),  # error
    ),
    group="syntactic",
    provenance="prior",
)
RUFF = VerifierParams(
    "ruff",
    "lint",
    confusion=(
        (0.20, 0.10, 0.70),
        (0.20, 0.10, 0.70),
        (0.20, 0.10, 0.70),
        (0.20, 0.10, 0.70),
    ),
    group="syntactic",
    provenance="prior",
)
JUDGE = VerifierParams(
    "judge:grounded-rubric",
    "judge",
    confusion=(
        (0.80, 0.15, 0.05),
        (0.25, 0.70, 0.05),
        (0.20, 0.40, 0.40),
        (0.20, 0.40, 0.40),
    ),
    group="judges",
    provenance="prior",
)
BUNDLE = Bundle(
    priors=PRIORS,
    verifiers={p.verifier_id: p for p in (CARGO, RUFF, JUDGE)},
)


def vote(params: VerifierParams, v: str, **integrity) -> NormalizedVote:
    return NormalizedVote(
        verifier_id=params.verifier_id,
        kind=params.kind,
        task_id=uuid4(),
        attempt_id=uuid4(),
        vote=v,
        evidence_digest=b"",
        integrity=IntegrityFlags(**integrity),
        tier="T0",
    )


def test_06_worked_example_lands_in_the_band_by_0008():
    """06 §3.2: posterior [0.3414, 0.5320, 0.0844, 0.0422], η = 0.3414 inside
    (0.333, 0.889) ⇒ refused — by 0.008. The exact match also proves the clique
    collapse: ruff shares cargo's group and the doc's arithmetic omits it."""
    event = adjudicate(
        [vote(CARGO, "accept"), vote(RUFF, "abstain"), vote(JUDGE, "reject")],
        BUNDLE,
    )
    assert event.verdict == "refused"
    assert [round(p, 4) for p in event.posterior] == [0.3414, 0.5320, 0.0844, 0.0422]
    # All-prior bundle, nothing stamped: the honest stage is `uncertified`, never
    # CERTIFIED (06 §5 — the status governs the claims permitted about the math).
    assert event.stage == "uncertified"
    assert event.vote_count == 3


def test_06_counterfactual_anchor_reject_collapses_satisfied_mass():
    """06 §3.2(a): had the compile anchor rejected, u(S) collapses ~50-fold
    (0.98 → 0.02) and the verdict is violated regardless of what the judge said —
    at ≥ 0.95 on the example's own judge-reject row."""
    rejected = adjudicate(
        [vote(CARGO, "reject"), vote(RUFF, "abstain"), vote(JUDGE, "reject")],
        BUNDLE,
    )
    assert rejected.verdict == "violated"
    assert rejected.posterior[1] >= 0.95
    # "regardless of what the judge said": even a judge ACCEPT cannot rescue it.
    overruled = adjudicate(
        [vote(CARGO, "reject"), vote(RUFF, "abstain"), vote(JUDGE, "accept")],
        BUNDLE,
    )
    assert overruled.verdict == "violated"


def test_symmetric_abstention_changes_nothing():
    """Honest silence: ruff abstaining (symmetric likelihood) leaves the posterior
    exactly where cargo+judge alone put it."""
    with_ruff = adjudicate(
        [vote(CARGO, "accept"), vote(RUFF, "abstain"), vote(JUDGE, "reject")], BUNDLE
    )
    without = adjudicate([vote(CARGO, "accept"), vote(JUDGE, "reject")], BUNDLE)
    assert with_ruff.posterior == pytest.approx(without.posterior)


def test_group_collapse_one_term_per_clique():
    """A linter and a compiler agreeing on the same diff is ONE observation: adding a
    same-group accepter must not double-count toward satisfied."""
    lint_accepts = VerifierParams(
        "eslint",
        "lint",
        confusion=RUFF.confusion,
        group="syntactic",
        provenance="prior",
    )
    solo = adjudicate([vote(CARGO, "accept"), vote(JUDGE, "reject")], BUNDLE)
    doubled_bundle = Bundle(
        priors=PRIORS,
        verifiers={**BUNDLE.verifiers, "eslint": lint_accepts},
    )
    doubled = adjudicate(
        [vote(CARGO, "accept"), vote(lint_accepts, "accept"), vote(JUDGE, "reject")],
        doubled_bundle,
    )
    # cargo's accept LR (0.98/0.60) dominates eslint's (0.20/0.20): the group's one
    # term is cargo's either way, so the posterior is unchanged.
    assert doubled.posterior == pytest.approx(solo.posterior)


def test_group_collapse_reject_wins_and_is_the_sharpest_rejecter():
    """Within a clique, disagreement collapses to the reject — and to the SHARPEST
    rejecter (min P(reject|S)), preserving the anchor clamp unsmoothed (§4.5)."""
    disagreeing = adjudicate([vote(CARGO, "reject"), vote(RUFF, "accept")], BUNDLE)
    cargo_alone = adjudicate([vote(CARGO, "reject")], BUNDLE)
    # The group's one term is cargo's reject — ruff's accept contributes nothing.
    assert disagreeing.posterior == pytest.approx(cargo_alone.posterior)


def test_tampered_votes_never_enter_the_likelihood():
    clean = adjudicate([vote(JUDGE, "reject")], BUNDLE)
    with_tamper = adjudicate([vote(CARGO, "accept", tamper=True), vote(JUDGE, "reject")], BUNDLE)
    assert with_tamper.posterior == pytest.approx(clean.posterior)
    assert with_tamper.vote_count == 1  # the tampered vote is quarantined, not counted


def test_all_tampered_is_error_insufficient_evidence():
    event = adjudicate([vote(CARGO, "accept", tamper=True)], BUNDLE)
    assert event.verdict == "error"
    assert event.reason == "insufficient_evidence"
    assert event.posterior == (0.0, 0.0, 0.0, 1.0)


def test_all_abstain_is_refused_insufficient_evidence():
    event = adjudicate([vote(RUFF, "abstain"), vote(JUDGE, "abstain")], BUNDLE)
    assert event.verdict == "refused"
    assert event.reason == "insufficient_evidence"
    assert event.posterior == (0.0, 0.0, 1.0, 0.0)


def test_no_votes_at_all_is_refused():
    event = adjudicate([], BUNDLE)
    assert event.verdict == "refused"
    assert event.reason == "insufficient_evidence"


def test_calibrated_default_fallback_provenance_is_prior():
    """Phase 2 posture (mirror of intel engine.py): a verifier with no bundle row gets
    the literature-CALIBRATED default for its kind, provenance honestly 'prior'."""
    p = calibrated_params("mypy@1", "typecheck")
    assert p.provenance == "prior"
    assert p.group == "syntactic"
    # And it fuses: an empty bundle still adjudicates on kind defaults.
    empty = Bundle(priors=PRIORS)
    unlisted = VerifierParams("mypy@1", "typecheck", p.confusion, "syntactic", "prior")
    event = adjudicate([vote(unlisted, "accept")], empty)
    assert isinstance(event, VerdictEvent)
    assert math.isclose(sum(event.posterior), 1.0)


def test_stage_is_earned_not_stamped():
    """A verdict fused from literature defaults must never say CERTIFIED (06 §5: the
    same silent-default-under-a-certified-banner defect class this repo was already
    burned by). CERTIFIED requires measured rows AND a stamped certificate; below
    that, the honest §5.3 vocabulary — and provenance rides on the event, weakest
    row wins."""
    votes = [vote(CARGO, "accept"), vote(JUDGE, "reject")]

    # All-prior rows, no cert stamped: the floor.
    event = adjudicate(votes, BUNDLE)
    assert event.stage == "uncertified"
    assert event.provenance == "prior"

    # All-prior rows, cert stamped: honestly "we are measuring", still not CERTIFIED.
    event = adjudicate(votes, BUNDLE, noise_cert_id="c-1")
    assert event.stage == "bootstrapping"
    assert event.provenance == "prior"

    # Measured rows + stamped cert: CERTIFIED is earned.
    measured = Bundle(
        priors=PRIORS,
        verifiers={
            p.verifier_id: VerifierParams(p.verifier_id, p.kind, p.confusion, p.group, "spectral")
            for p in (CARGO, RUFF, JUDGE)
        },
    )
    event = adjudicate(votes, measured, noise_cert_id="c-1")
    assert event.stage == "CERTIFIED"
    assert event.provenance == "spectral"

    # One prior row anywhere poisons the claim: weakest provenance wins.
    mixed = Bundle(
        priors=PRIORS,
        verifiers={**measured.verifiers, JUDGE.verifier_id: JUDGE},
    )
    event = adjudicate(votes, mixed, noise_cert_id="c-1")
    assert event.stage == "bootstrapping"
    assert event.provenance == "prior"

    # Step-0 degenerate verdicts fused nothing: never a calibrated claim.
    event = adjudicate([vote(RUFF, "abstain")], measured, noise_cert_id="c-1")
    assert event.reason == "insufficient_evidence"
    assert event.stage == "bootstrapping"


def test_calibrated_default_refuses_unknown_kind():
    with pytest.raises(KeyError):
        calibrated_params("mystery@1", "vibes")


def test_zero_posterior_mass_raises_instead_of_inventing_a_verdict():
    degenerate = Bundle(
        priors=(1.0, 0.0, 0.0, 0.0),
        verifiers={
            "veto": VerifierParams(
                "veto",
                "compile",
                confusion=(
                    (0.98, 0.00, 0.02),  # reject|S = 0, and every other prior is 0
                    (0.60, 0.40, 0.00),
                    (0.50, 0.05, 0.45),
                    (0.50, 0.05, 0.45),
                ),
                group="syntactic",
                provenance="prior",
            )
        },
    )
    veto = degenerate.verifiers["veto"]
    with pytest.raises(ValueError, match="zero posterior mass"):
        adjudicate([vote(veto, "reject")], degenerate)


def test_costs_are_bundle_overridable():
    """D4 is a default, not a law: a tenant pricing A high enough narrows the band and
    flips the 06 §3.2 example from refused to violated (η=0.3414 ≤ A/R = 0.35)."""
    event = adjudicate(
        [vote(CARGO, "accept"), vote(JUDGE, "reject")],
        BUNDLE,
        costs=Costs(a=3.5, r=10.0, d=90.0),
    )
    assert event.verdict == "violated"
