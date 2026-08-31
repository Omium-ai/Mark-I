"""ADJUDICATE's own worked example (06 §3.2 — the four-class Rust task) plus every
branch of the pseudocode: tamper partition, insufficient evidence, clique collapse,
abstention symmetry, the calibrated-default fallback, and the zero-mass refusal."""

import ast
import inspect
import math
from uuid import uuid4

import pytest
from app.adjudicate import algorithm, chow
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
    # And it fuses: a bundle that OPTED IN adjudicates on kind defaults.
    empty = Bundle(priors=PRIORS, calibrated_defaults=True)
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


def test_accept_tie_breaks_to_the_smallest_verifier_id():
    """D-W: every collapse branch resolves ties to the LEXICALLY SMALLEST id. The
    accept branch used max(), which breaks toward the LARGEST — so one (bundle,
    votes) produced two different wire posteriors depending on which side ran it."""
    rows = {
        # Equal accept LR (0.80/0.40 = 2); only the refused/error rows differ, so
        # which member the clique collapses to is observable in the posterior.
        "aaa": ((0.80, 0.10, 0.10), (0.40, 0.50, 0.10), (0.20, 0.40, 0.40), (0.20, 0.40, 0.40)),
        "zzz": ((0.80, 0.10, 0.10), (0.40, 0.50, 0.10), (0.60, 0.20, 0.20), (0.60, 0.20, 0.20)),
    }
    tied = Bundle(
        priors=PRIORS,
        verifiers={
            vid: VerifierParams(vid, "lint", conf, "syntactic", "prior")
            for vid, conf in rows.items()
        },
    )
    event = adjudicate(
        [vote(tied.verifiers["zzz"], "accept"), vote(tied.verifiers["aaa"], "accept")],
        tied,
    )
    # aaa's row: u = [0.55·0.80, 0.30·0.40, 0.10·0.20, 0.05·0.20] / 0.59.
    assert event.posterior == pytest.approx(
        (0.44 / 0.59, 0.12 / 0.59, 0.02 / 0.59, 0.01 / 0.59), abs=1e-12
    )


def test_unlisted_verifier_gets_no_row_when_a_bundle_is_present():
    """D-X: a bundle is the SOLE source of fusion parameters. A verifier it does not
    list contributes no likelihood — a per-kind default here would silently disagree
    with the edge twin, which has no such table — and is counted, never dropped."""
    stranger = VerifierParams("mypy@1", "typecheck", RUFF.confusion, "syntactic", "prior")
    base = adjudicate([vote(CARGO, "accept"), vote(JUDGE, "reject")], BUNDLE)
    with_stranger = adjudicate(
        [vote(CARGO, "accept"), vote(JUDGE, "reject"), vote(stranger, "reject")], BUNDLE
    )
    assert with_stranger.posterior == base.posterior
    assert with_stranger.unknown_voters == 1
    assert with_stranger.vote_count == 3  # counted as a vote, just not as evidence
    assert BUNDLE.params_for("mypy@1", "typecheck") is None


def test_unlisted_verifier_supplies_no_coverage_and_cannot_unlock_a_block():
    """D-AB: membership gates COVERAGE, not only likelihood. The only listed verifier
    abstains, so D1 is unmet and the honest answer is `refused`. Counting the unlisted
    vote as evidence made the same inputs fuse to a BLOCK whose posterior is priors ×
    the abstainer's column alone — the stranger provably contributed zero likelihood
    and still flipped the gate. A quarantined verifier is the same path: 07's
    quarantine list is applied by dropping the row, so it too is `params_for` → None."""
    stranger = VerifierParams("mystery", "judge", JUDGE.confusion, "judges", "prior")
    alone = adjudicate([vote(CARGO, "abstain")], BUNDLE)
    with_stranger = adjudicate([vote(CARGO, "abstain"), vote(stranger, "reject")], BUNDLE)
    assert alone.verdict == "refused"
    assert with_stranger.verdict == "refused"
    assert with_stranger.reason == "insufficient_evidence"
    assert with_stranger.unknown_voters == 1
    assert with_stranger.vote_count == 2


def test_no_transcendental_is_evaluated_on_the_verdict_path(monkeypatch):
    """D-AK, the root cause and its removal. IEEE-754 mandates correctly-rounded
    `+ - * /` and `sqrt`; it mandates NOTHING for exp/log. One `math.log` here is the
    entire reason Go's pure-Go math and CPython's platform libm could land a fusion one
    ulp apart — and one ulp on the Chow threshold is the edge blocking a developer the
    cloud refuses to block. Quantising the result never fixed that (the rounded value
    is still derived from the transcendental); deleting the call does."""

    def banned(*_a, **_k):
        raise AssertionError("exp/log on the verdict path — determinism is not mandated")

    monkeypatch.setattr(math, "log", banned)
    monkeypatch.setattr(math, "exp", banned)
    event = adjudicate([vote(CARGO, "accept"), vote(JUDGE, "reject")], BUNDLE)
    assert event.verdict == "refused"


def _reductions(mod) -> set[tuple[str, str]]:
    """(enclosing top-level statement, callee) for every library reduction in `mod`."""
    banned = {"sum", "fsum", "nansum", "prod", "cumsum", "reduce", "accumulate"}
    out = set()
    for top in ast.parse(inspect.getsource(mod)).body:
        for node in ast.walk(top):
            if isinstance(node, ast.Call):
                name = ast.unparse(node.func).rpartition(".")[2]
                if name in banned:
                    out.add((getattr(top, "name", "<module>"), name))
    return out


def test_no_library_reduction_is_used_on_the_verdict_path():
    """D-AO(a), the enforcement — a ban stated only in prose is the thing this pass
    exists to stop. IEEE-754 pins BINARY `+`; it says nothing about an n-ary reduction,
    and a standard library may compensate: CPython's `sum()` over floats became Neumaier
    summation in a POINT RELEASE, so it disagrees with Go's sequential fold by an ulp,
    and an ulp in `total` is the verdict on a Chow boundary. The only permitted reduction
    in the module is the INT count in _infra_dominant, where compensation is a no-op."""
    assert _reductions(algorithm) == {("_infra_dominant", "sum")}
    assert _reductions(chow) == set()


@pytest.mark.parametrize("bad", [math.inf, -math.inf, math.nan])
def test_a_non_finite_prior_refuses_instead_of_silently_answering_refused(bad):
    """S3-2: the guard was `total == 0.0`, which lets Inf and NaN through. NaN makes
    every `>=`/`<=` in the Chow band False, so the band's own default — REFUSED — became
    the answer to a broken bundle, on a NaN posterior that then reached the wire. Go
    guards `!(total > 0) || IsInf`; this is the same branch."""
    bundle = Bundle(priors=(bad, 0.30, 0.10, 0.05), verifiers={CARGO.verifier_id: CARGO})
    with pytest.raises(ValueError, match="zero posterior mass"):
        adjudicate([vote(CARGO, "accept")], bundle)


def test_chow_boundary_eta_exactly_a_over_r_lands_on_the_rules_answer():
    """This construction's EXACT posterior[satisfied] is 1/3 = A/R, so the rule
    (η ≤ A/R ⇒ violated) says violated. It is one of the 27 constructions the review
    swept: under D-AC's quantisation 8 of them flipped verdict BETWEEN the two
    languages, in both directions. Cross-multiplied against the unnormalised mass
    (u_S·R ≤ A·total) there is no division and no transcendental left to straddle."""
    edge = VerifierParams(
        "boundary",
        "judge",
        confusion=(
            (0.04, 0.48, 0.48),
            (0.05, 0.47, 0.48),
            (0.06, 0.47, 0.47),
            (0.06, 0.47, 0.47),
        ),
        group="judges",
        provenance="prior",
    )
    bundle = Bundle(priors=(0.4, 0.4, 0.1, 0.1), verifiers={edge.verifier_id: edge})
    event = adjudicate([vote(edge, "accept")], bundle)
    assert event.verdict == "violated"
    # The wire posterior is the fusion's own quotient — there is no second, rounded
    # "comparison" copy of it any more (D-AK clause 4).
    assert event.posterior[0] == 0.4 * 0.04 / (0.4 * 0.04 + 0.4 * 0.05 + 0.1 * 0.06 * 2)


def test_four_cliques_of_1e300_likelihoods_still_fuse():
    """Direct multiplication underflows where log-space did not, so the fusion loop
    rescales by an exact POWER OF TWO (mantissa untouched, cancels in normalisation).
    Without it these four cliques multiply straight through the smallest subnormal and
    an ordinary fusion reads as `zero posterior mass — inconsistent bundle`."""
    tiny = 1e-300
    verifiers = {
        f"x{i}": VerifierParams(
            f"x{i}",
            "lint",
            tuple((tiny * (i + t + 1), 0.5, 0.5) for t in range(4)),
            f"x{i}",  # its own clique
            "prior",
        )
        for i in range(4)
    }
    bundle = Bundle(priors=PRIORS, verifiers=verifiers)
    event = adjudicate([vote(p, "accept") for p in verifiers.values()], bundle)
    assert math.isclose(sum(event.posterior), 1.0)
    assert all(p > 0.0 for p in event.posterior)


def test_calibrated_fallback_is_certification_path_only_and_taints_the_stage():
    """The fallback survives only where a caller EXPLICITLY claims the certification /
    gold-set path. D-T: anything that consumed a fallback row is at best BOOTSTRAPPING
    — its provenance is 'prior' by construction, and CERTIFIED demands measured rows."""
    no_bundle = Bundle(priors=PRIORS, calibrated_defaults=True)
    mypy = VerifierParams("mypy@1", "typecheck", RUFF.confusion, "syntactic", "prior")
    assert no_bundle.params_for("mypy@1", "typecheck") is not None
    event = adjudicate([vote(mypy, "accept")], no_bundle, noise_cert_id="c-1")
    assert event.unknown_voters == 0
    assert event.provenance == "prior"
    assert event.stage == "bootstrapping"  # never CERTIFIED


def test_an_empty_bundle_grants_a_stranger_nothing():
    """A bundle carrying ZERO verifiers is not a licence: inferring the certification
    path from `not self.verifiers` gave a total stranger full likelihood AND coverage
    (measured: verdict=violated, unknown_voters=0), off the unauthenticated
    /v1/adjudicate/preview whenever `verifiers` is omitted. The edge's equivalent state
    contributes nothing, so the inference was a Python-only divergence from D-AB."""
    empty = Bundle(priors=PRIORS)
    stranger = VerifierParams("mystery@1", "judge", JUDGE.confusion, "judges", "prior")
    assert empty.params_for("mystery@1", "judge") is None
    event = adjudicate([vote(stranger, "reject")], empty)
    assert event.verdict == "refused"  # not `violated` — no coverage was supplied
    assert event.reason == "insufficient_evidence"
    assert event.unknown_voters == 1  # dropped, never lost


def test_group_iteration_is_sorted_not_insertion_ordered():
    """04 §2.3, binding on both sides: groups are summed in SORTED id order. Float
    log-sums are not associative, so insertion order made the posterior a function
    of the order votes happened to arrive — and 06 §3's conformance is bit-exact,
    not approximate. These four rows differ in the last bits when reordered."""
    accepts = [
        (0.34, 0.19, 0.64, 0.12),
        (0.53, 0.38, 0.10, 0.51),
        (0.08, 0.44, 0.11, 0.13),
        (0.43, 0.79, 0.16, 0.25),
    ]
    verifiers = {}
    for i, col in enumerate(accepts):
        vid = f"g{i}"
        verifiers[vid] = VerifierParams(
            vid,
            "lint",
            tuple((a, round((1 - a) * 0.4, 4), round((1 - a) * 0.6, 4)) for a in col),
            vid,  # its own clique
            "prior",
        )
    bundle = Bundle(priors=PRIORS, verifiers=verifiers)
    ordered = [vote(verifiers[f"g{i}"], "accept") for i in range(4)]
    permuted = [ordered[i] for i in (3, 1, 2, 0)]
    assert adjudicate(permuted, bundle).posterior == adjudicate(ordered, bundle).posterior


def test_empty_group_is_its_own_clique_not_a_shared_bucket():
    """An empty group id means "independent" (the edge's BundleMatrices says so).
    Bucketing every ungrouped verifier under "" would collapse two independent
    observations into one and drop half the evidence."""
    a = VerifierParams("solo-a", "lint", JUDGE.confusion, "", "prior")
    b = VerifierParams("solo-b", "lint", JUDGE.confusion, "", "prior")
    bundle = Bundle(priors=PRIORS, verifiers={p.verifier_id: p for p in (a, b)})
    one = adjudicate([vote(a, "reject")], bundle)
    two = adjudicate([vote(a, "reject"), vote(b, "reject")], bundle)
    assert two.posterior != one.posterior
