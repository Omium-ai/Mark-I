"""T2 reward-model members (06 §2 KIND_RM, 16 §L6): an RmScore folds through its calibration
(the code table or the catalog row's sealed artifact) into a wire verdict, never a fabricated
one, and a shadow RM vote carries zero fusion weight (FR-LEARN-004, 10 R-4)."""

import math
from uuid import uuid4

import pytest
from app.adjudicate.algorithm import adjudicate
from app.adjudicate.likelihoods import CALIBRATED_CONFUSION, Bundle, VerifierParams
from app.registry.catalog import entry_from_row
from app.registry.handlers import KIND_RM, NormalizedVote, normalize_votes
from app.registry.integrity import IntegrityFlags
from app.registry.promotion import ShadowPair, decide, split_shadow
from app.rm.scorer import (
    CALIBRATION,
    CALIBRATION_VERSION,
    calibration_for,
    fold,
    rm_refused_total,
    shadow_fuse,
    to_raw_vote,
)
from m1p.v1 import RmScore

KEY = "sk-rm-7c1f-SECRET-do-not-log"
RM_ID = "rm:test-rm@1"  # never a seeded key: catalog rows are immutable
IDS = (uuid4(), uuid4(), uuid4())
SEALED = {
    "kind": "rm",
    "group": "rm-a",
    "artifact": {
        "calibration": {
            "version": "rm-a-cal@1",
            "scale": 1.0,
            "shift": 0.0,
            "reject_below": 0.3,
            "accept_above": 0.7,
        }
    },
}


def test_calibration_starts_at_the_bundle_prior():
    cal = CALIBRATION[CALIBRATION_VERSION]
    assert cal.confusion == CALIBRATED_CONFUSION["rm"]
    assert all(abs(sum(row) - 1.0) < 1e-9 for row in cal.confusion)
    assert 0.0 < cal.reject_below < 0.5 < cal.accept_above < 1.0


@pytest.mark.parametrize(
    ("logit", "verdict"),
    [
        (-3.0, "violated"),
        (-0.9, "violated"),
        (0.0, "refused"),
        (0.8, "refused"),
        (2.0, "satisfied"),
    ],
)
def test_sealed_artifact_calibration_is_platt_over_the_raw_logit(logit, verdict):
    """The wire carries σ(raw logit); the sealed calibration recovers the logit and maps
    σ(scale·s + shift) through its own band; a version the artifact does not name never folds."""
    assert fold(1.0 / (1.0 + math.exp(-logit)), "rm-a-cal@1", SEALED) == verdict
    assert fold(-2.0, "rm-a-cal@1", SEALED) is None  # a raw logit on the wire is out of contract
    assert calibration_for("rm-a-cal@1", {}) is None
    assert fold(0.9, CALIBRATION_VERSION, SEALED) is None
    for bad in (math.nan, math.inf, None, True, "0.9"):
        assert fold(bad, "rm-a-cal@1", SEALED) is None
    assert fold(1.4, CALIBRATION_VERSION) is None  # rm-cal@1 scores are probabilities


@pytest.mark.parametrize(
    ("score", "verdict"),
    [
        (0.0, "violated"),
        (0.39, "violated"),
        (0.40, "refused"),
        (0.5, "refused"),
        (0.60, "refused"),
        (0.61, "satisfied"),
        (1.0, "satisfied"),
    ],
)
def test_to_raw_vote_folds_through_the_calibration(score, verdict):
    raw = to_raw_vote(RmScore(RM_ID, score, CALIBRATION_VERSION), IDS[1], IDS[2], b"\x22" * 32)
    assert (raw.verifier_id, raw.kind, raw.verdict) == (RM_ID, KIND_RM, verdict)


def test_to_raw_vote_refuses_unknown_calibration_and_out_of_range_ledger_rows():
    before = dict(rm_refused_total)
    assert to_raw_vote(RmScore(RM_ID, 0.9, "rm-cal@0"), IDS[1], IDS[2], b"") is None
    assert to_raw_vote(RmScore(RM_ID, 1.5, CALIBRATION_VERSION), IDS[1], IDS[2], b"") is None
    assert (
        rm_refused_total["refused_rm_unknown_calibration"]
        == before.get("refused_rm_unknown_calibration", 0) + 1
    )
    assert (
        rm_refused_total["refused_rm_malformed_score"]
        == before.get("refused_rm_malformed_score", 0) + 1
    )


@pytest.mark.parametrize(
    "definition",
    [
        SEALED,
        {**SEALED, "artifact": {"status": "pending", "calibration": None}},
        {**SEALED, "artifact": None},
    ],
)
def test_a_sealed_model_folds_only_through_its_own_calibration(definition):
    """A device naming rm-cal@1 (or any version but the artifact's) for a model that carries an
    artifact block is refused and counted, never folded through the code table's wider band."""
    before = rm_refused_total["refused_rm_calibration_not_sealed"]
    for version in (CALIBRATION_VERSION, "rm-a-cal@2", ""):
        assert calibration_for(version, definition) is None
        rm = RmScore(RM_ID, 0.65, version)
        assert to_raw_vote(rm, IDS[1], IDS[2], b"", definition) is None
    assert rm_refused_total["refused_rm_calibration_not_sealed"] == before + 3
    assert calibration_for(CALIBRATION_VERSION, {"kind": "rm"}) == CALIBRATION[CALIBRATION_VERSION]


async def test_rm_vote_normalizes_through_the_registry_handler_as_t2():
    row = {
        "id": uuid4(),
        "verifier_key": "rm:test-rm",
        "version": 1,
        "kind": "reward_model",
        "definition": SEALED,
        "effective_execution_hash": None,
        "retired_at": None,
    }
    entry = entry_from_row(row)
    assert entry.kind == KIND_RM and entry.definition == SEALED
    raw = to_raw_vote(RmScore(RM_ID, 0.8808, "rm-a-cal@1"), IDS[1], IDS[2], b"\x22" * 32, SEALED)
    votes, refusals = await normalize_votes([raw], {RM_ID: entry})
    assert refusals == []
    (v,) = votes
    assert (v.verifier_id, v.kind, v.vote, v.tier) == (RM_ID, KIND_RM, "accept", "T2")
    assert not v.integrity.tamper and not v.integrity.infra_failed


def _vote(vid: str, kind: str, vote: str, tier: str = "T0") -> NormalizedVote:
    return NormalizedVote(vid, kind, IDS[1], IDS[2], vote, b"", IntegrityFlags(), tier)  # type: ignore[arg-type]


RUFF = VerifierParams("ruff@1", "lint", CALIBRATED_CONFUSION["lint"], "syntactic", "prior")
JUDGE = VerifierParams("judge:a@1", "judge", CALIBRATED_CONFUSION["judge"], "judges", "prior")
SHARP = VerifierParams(
    RM_ID,
    "rm",
    ((0.99, 0.01, 0.0), (0.01, 0.99, 0.0), (0.5, 0.5, 0.0), (0.5, 0.5, 0.0)),
    "rms",
    "prior",
)


@pytest.mark.parametrize("listed", [False, True])
def test_shadow_rm_vote_changes_nothing_in_adjudicate(listed: bool):
    """R-4 / 06 §12.4 row 2: even a bundle that LISTS the RM with a sharp row (positive
    control: counted, its reject flips the verdict) fuses bit-identically without it."""
    bundle = Bundle(
        verifiers={p.verifier_id: p for p in (RUFF, JUDGE, *([SHARP] if listed else []))}
    )
    honest = [_vote("ruff@1", "lint", "accept"), _vote("judge:a@1", "judge", "accept")]
    rm = _vote(RM_ID, "rm", "reject", "T2")
    baseline = adjudicate(honest, bundle, noise_cert_id="cert-1")
    counted = adjudicate([*honest, rm], bundle, noise_cert_id="cert-1")
    if listed:
        assert counted.verdict != baseline.verdict and counted.posterior != baseline.posterior
    else:
        assert counted.unknown_voters == baseline.unknown_voters + 1

    event, pair = shadow_fuse(honest, rm, bundle, noise_cert_id="cert-1")
    assert event == baseline
    assert pair == ShadowPair("reject", baseline.verdict, "cert-1")


def test_shadow_pairs_feed_promotion_decide_without_touching_fusion():
    bundle = Bundle(verifiers={p.verifier_id: p for p in (RUFF, JUDGE)})
    pairs = []
    for i in range(600):
        honest_vote = "reject" if i % 2 else "accept"
        honest = [_vote("ruff@1", "lint", honest_vote), _vote("judge:a@1", "judge", honest_vote)]
        event, pair = shadow_fuse(
            honest, _vote(RM_ID, "rm", honest_vote, "T2"), bundle, noise_cert_id="c"
        )
        assert event.vote_count == 2 and event.unknown_voters == 0
        pairs.append(pair)
    assert {p.verdict for p in pairs} == {"satisfied", "violated"}
    assert decide(pairs, bar=0.0).verdict == "promote"
    fused, shadow = split_shadow([_vote(RM_ID, "rm", "accept", "T2")], {RM_ID})
    assert fused == [] and len(shadow) == 1
