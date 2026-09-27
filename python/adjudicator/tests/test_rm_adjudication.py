"""16 §L6 adjudicator integration, end to end through the estimator: RmScore folds into the vote
matrix, groups come from the catalog (an E0 judge is syntactic), G4 orients on compile/test alone,
a derived view passes the gate yet biases the prior and only the Thm 6.1 structural check against
gold sees it, shadow members enter estimation but never fusion, and promotion pairs come from the
gold set and the certified ledger."""

import base64
import json
from uuid import UUID, uuid4

import numpy as np
import pytest
from app.adjudicate.algorithm import adjudicate
from app.adjudicate.chow import Costs
from app.adjudicate.likelihoods import CALIBRATED_CONFUSION, Bundle
from app.certs.compute import structural_violation
from app.gold.score import score_agreement
from app.jobs import nightly
from app.jobs.readjudicate import bundle_for, registry_by_wire_id, votes_by_task
from app.registry.catalog import entry_from_row
from app.registry.promotion import GOLD, CanaryWatch, ShadowPair, in_canary, split_shadow
from app.spectral.estimate import estimate, predicted_noise
from tests.test_jobs import RM_XH, VOTE_ROW
from tests.test_rm import SEALED

WIRE = {0: "satisfied", 1: "violated", 2: "refused"}
SCORE = {0: 0.9, 1: 0.1, 2: 0.5}
PI = 0.6
N = 4000


SEALED_BY_KIND = {"anchor": b"\x01" * 32, "reward_model": RM_XH}


def entry(key: str, db_kind: str, definition: dict):
    return entry_from_row(
        {
            "id": uuid4(),
            "verifier_key": key,
            "version": 1,
            "kind": db_kind,
            "definition": definition,
            "effective_execution_hash": SEALED_BY_KIND.get(db_kind),
            "retired_at": None,
        }
    )


REGISTRY = registry_by_wire_id(
    [
        entry("cargo-check@cat-1", "anchor", {"kind": "compile"}),
        entry("ruff@cat-1", "anchor", {"kind": "lint"}),
        entry("judge:grounded-rubric", "judge", {"kind": "judge", "evidence_tier": "E0"}),
        entry("judge:diff-rubric", "judge", {"kind": "judge", "group": "judge"}),
        entry("rm:mark1-rm-a", "reward_model", {"kind": "rm", "group": "rm-a"}),
        entry("rm:sealed", "reward_model", SEALED),
    ]
)
COMPILE, LINT, E0_JUDGE, DIFF_JUDGE, RM = (
    "cargo-check@cat-1",
    "ruff@cat-1",
    "judge:grounded-rubric@1",
    "judge:diff-rubric@1",
    "rm:mark1-rm-a@1",
)
FAMILY = {COMPILE: "AnchorVote", LINT: "AnchorVote", E0_JUDGE: "JudgeVote", DIFF_JUDGE: "JudgeVote"}


def world(seed: int = 1):
    """Paper II's laws, with the E0 judge a function of the anchors' votes and never of Y."""
    rng = np.random.default_rng(seed)
    y = (rng.random(N) < PI).astype(int)

    def draw(p_s, p_v):
        p = np.where(y[:, None] == 1, p_s, p_v)
        return np.minimum((rng.random(N)[:, None] > p.cumsum(1)).sum(1), 2)

    compile_ = draw((0.93, 0.02, 0.05), (0.55, 0.40, 0.05))
    lint = draw((0.80, 0.10, 0.10), (0.55, 0.35, 0.10))
    bad = (compile_ == 1) | (lint == 1)
    derived = np.where(bad[:, None], (0.05, 0.90, 0.05), (0.85, 0.10, 0.05))
    e0_judge = np.minimum((rng.random(N)[:, None] > derived.cumsum(1)).sum(1), 2)
    return {
        "y": y,
        COMPILE: compile_,
        LINT: lint,
        E0_JUDGE: e0_judge,
        DIFF_JUDGE: draw((0.85, 0.10, 0.05), (0.20, 0.75, 0.05)),
        RM: draw((0.75, 0.20, 0.05), (0.25, 0.70, 0.05)),
    }


def rows_for(w: dict, verifiers, *, tier: str = "") -> list[dict]:
    out = []
    for n in range(N):
        task = str(UUID(int=n + 1))
        for seq, vid in enumerate(verifiers):
            code = int(w[vid][n])
            family = FAMILY.get(vid, "RmScore")
            judge = family == "JudgeVote"
            out.append(
                {
                    **VOTE_ROW,
                    "task_id": task,
                    "vote_id": str(uuid4()),
                    "seq": seq + 1,
                    "family": family,
                    "verifier_id": vid,
                    "is_anchor": int(family == "AnchorVote"),
                    "vote": "" if family == "RmScore" else WIRE[code],
                    "score": SCORE[code] if family == "RmScore" else 0,
                    "calibration_version": "rm-cal@1" if family == "RmScore" else "",
                    "tier_used": tier if judge else "",
                    "vote_trigger": "JUDGE_TRIGGER_ALWAYS" if judge else "",
                }
            )
    return out


def gold_score(est, y, rng, n: int = 400):
    """What the gold set measures: the Chow-thresholded label against the truth."""
    lo, hi = Costs().band
    eta = est.posterior[:, 0]
    verdict = np.where(eta >= hi, "satisfied", np.where(eta <= lo, "violated", "refused"))
    idx = rng.choice(len(y), n, replace=False)
    return score_agreement([("satisfied" if y[i] else "violated", str(verdict[i])) for i in idx])


def test_rmscore_folds_in_vote_matrix():
    task = str(uuid4())
    base = {**VOTE_ROW, "task_id": task, "family": "RmScore", "is_anchor": 0, "vote": ""}
    rows = [
        {**base, "verifier_id": RM, "score": 0.93, "calibration_version": "rm-cal@1"},
        {
            **base,
            "verifier_id": "rm:sealed@1",
            "score": 0.1192,
            "calibration_version": "rm-a-cal@1",
        },  # σ(−2)
        {**base, "verifier_id": "rm:unknown-cal@1", "score": 0.9, "calibration_version": "x@9"},
        {
            **base,
            "verifier_id": "rm:nan@1",
            "score": float("nan"),
            "calibration_version": "rm-cal@1",
        },
    ]
    votes, groups, anchors, verifiers = nightly.vote_matrix(rows, REGISTRY)
    got = dict(zip(verifiers, votes[0].tolist(), strict=True))
    assert got == {RM: 0, "rm:sealed@1": 1, "rm:unknown-cal@1": -1, "rm:nan@1": -1}
    assert dict(zip(verifiers, groups, strict=True))[RM] == "rm-a"
    fused = {v.verifier_id: v.vote for v in votes_by_task(rows, REGISTRY)[UUID(task)]}
    assert fused == {RM: "accept", "rm:sealed@1": "reject"}


def test_e0_judge_counts_in_syntactic_group():
    task = str(uuid4())
    judge = {**VOTE_ROW, "task_id": task, "family": "JudgeVote", "is_anchor": 0, "vote": "violated"}
    rows = [
        {**judge, "verifier_id": E0_JUDGE, "tier_used": "EVIDENCE_TIER_E0"},
        {**judge, "verifier_id": DIFF_JUDGE, "tier_used": "EVIDENCE_TIER_E1"},
        {**judge, "verifier_id": "judge:unlisted@3", "tier_used": ""},
    ]
    _, groups, _, verifiers = nightly.vote_matrix(rows, REGISTRY)
    assert dict(zip(verifiers, groups, strict=True)) == {
        E0_JUDGE: "syntactic",
        DIFF_JUDGE: "judge",
        "judge:unlisted@3": "syntactic",
    }
    # The group follows the evidence it read: one E0 vote makes even a declared judge syntactic.
    e0_diff = [*rows, {**judge, "verifier_id": DIFF_JUDGE, "tier_used": "EVIDENCE_TIER_E0"}]
    _, groups, _, verifiers = nightly.vote_matrix(e0_diff, REGISTRY)
    assert dict(zip(verifiers, groups, strict=True))[DIFF_JUDGE] == "syntactic"
    # An ambiguity-triggered vote feeds fusion only.
    ambiguous = {**rows[1], "vote_trigger": "JUDGE_TRIGGER_AMBIGUOUS"}
    assert nightly.vote_matrix([ambiguous], REGISTRY)[3] == []
    assert [v.verifier_id for v in votes_by_task([ambiguous], REGISTRY)[UUID(task)]] == [DIFF_JUDGE]


def test_derived_view_passes_gate_but_biases():
    """The research sim: anchors + an E0 judge (a function of the anchor votes) + an independent
    RM pass every identifiability gate when the judge is grouped by family, and certify a prior
    of ~0.68 against a true 0.60. Grouped as what it is (syntactic), G1 refuses."""
    w = world()
    old = estimate(
        np.stack([w[COMPILE], w[LINT], w[E0_JUDGE], w[RM]], 1),
        ["syntactic", "syntactic", "judges", "rms"],
        [True, False, False, False],
    )
    assert old.diagnostics.passed
    assert old.prior[0] - PI > 0.05, old.prior
    est, run = nightly.run_spectral(rows_for(w, (COMPILE, LINT, E0_JUDGE, RM)), REGISTRY)
    assert not run["passed"] and "G1" in run["diagnostics"]["failed"]
    assert run["diagnostics"]["groups"][E0_JUDGE] == "syntactic"
    control = estimate(
        np.stack([w[COMPILE], w[LINT], w[DIFF_JUDGE], w[RM]], 1),
        ["syntactic", "syntactic", "judge", "rm-a"],
        [True, False, False, False],
    )
    assert control.diagnostics.passed and abs(control.prior[0] - PI) < 0.03


def test_selfcert_vs_gold_flags_structure():
    w, rng = world(), np.random.default_rng(7)
    derived = estimate(
        np.stack([w[COMPILE], w[LINT], w[E0_JUDGE], w[RM]], 1),
        ["syntactic", "syntactic", "judges", "rms"],
        [True, False, False, False],
    )
    assert derived.diagnostics.passed
    assert structural_violation(
        predicted_noise(derived.posterior), gold_score(derived, w["y"], rng)
    )
    control = estimate(
        np.stack([w[COMPILE], w[LINT], w[DIFF_JUDGE], w[RM]], 1),
        ["syntactic", "syntactic", "judge", "rm-a"],
        [True, False, False, False],
    )
    score = gold_score(control, w["y"], rng)
    assert not structural_violation(predicted_noise(control.posterior), score)
    assert not structural_violation(None, score)
    assert not structural_violation(predicted_noise(control.posterior), score_agreement([]))


def test_g4_sound_rejectors_only():
    """Pooling lint with compile halves the orientation margin (lint rejects correct code) and
    G4 refuses a design that is identifiable; the catalog kinds keep lint out of the mask."""
    w = world()
    pooled = estimate(
        np.stack([w[COMPILE], w[LINT], w[DIFF_JUDGE], w[RM]], 1),
        ["syntactic", "syntactic", "judge", "rm-a"],
        [True, True, False, False],
    )
    assert "G4" in pooled.diagnostics.failed
    rows = rows_for(w, (COMPILE, LINT, DIFF_JUDGE, RM), tier="EVIDENCE_TIER_E1")
    _, _, anchors, verifiers = nightly.vote_matrix(rows, REGISTRY)
    assert dict(zip(verifiers, anchors, strict=True)) == {
        COMPILE: True,
        LINT: False,
        DIFF_JUDGE: False,
        RM: False,
    }
    est, run = nightly.run_spectral(rows, REGISTRY)
    assert run["passed"], run["diagnostics"]["failed"]
    assert run["diagnostics"]["anchor_separation"] >= 10 and abs(run["prior"][0] - PI) < 0.03


def test_shadow_in_estimation_not_fusion():
    """Amends 06 §4.4: a shadow member's votes are columns of the estimator (so the third clique
    can be measured before it serves) and never inputs to adjudicate; a canary member fuses on
    its hashed slice only."""
    w = world()
    rows = rows_for(w, (COMPILE, LINT, DIFF_JUDGE, RM), tier="EVIDENCE_TIER_E1")
    _, _, _, verifiers = nightly.vote_matrix(rows, REGISTRY)
    assert RM in verifiers
    _, run = nightly.run_spectral(rows, REGISTRY)
    assert run["passed"] and RM in run["confusion"]
    tasks = votes_by_task(rows, REGISTRY)
    bundle = Bundle(calibrated_defaults=True)
    canary = sum(in_canary(t) for t in tasks)
    assert 0.07 * len(tasks) < canary < 0.13 * len(tasks)
    for task, votes in list(tasks.items())[:200]:
        fused, shadow = split_shadow(votes, {RM})
        assert [v.verifier_id for v in shadow] == [RM]
        honest = [v for v in votes if v.verifier_id != RM]
        assert adjudicate(fused, bundle) == adjudicate(honest, bundle)
        fused, shadow = split_shadow(votes, {RM}, {RM})
        assert (RM in {v.verifier_id for v in fused}) is in_canary(task)


def test_pairs_from_gold_and_certified_ledger():
    """A head's vote pairs with the task's gold label where one exists, else (non-serving heads
    only) with the certified ledger verdict under its cert; a canary head gets its slice watch."""
    cert = str(uuid4())
    outside = (t for t in (uuid4() for _ in range(1000)) if not in_canary(t))
    t_gold, t_ledger, t_prov = next(outside), next(outside), next(outside)
    canary_task = next(t for t in (uuid4() for _ in range(1000)) if in_canary(t))

    def rm(task, score, verdict="", cert_id="00000000-0000-0000-0000-000000000000"):
        return {
            **VOTE_ROW,
            "task_id": str(task),
            "family": "RmScore",
            "verifier_id": RM,
            "is_anchor": 0,
            "vote": "",
            "score": score,
            "calibration_version": "rm-cal@1",
            "task_verdict": verdict,
            "task_noise_cert_id": cert_id,
        }

    rows = [
        rm(t_gold, 0.1, "satisfied", cert),
        rm(t_ledger, 0.9, "satisfied", cert),
        rm(t_prov, 0.1),
        rm(canary_task, 0.1, "violated", cert),
        {
            **rm(canary_task, 0, "violated", cert),
            "family": "AnchorVote",
            "verifier_id": COMPILE,
            "vote": "satisfied",
        },
    ]
    gold = {t_gold: "violated", canary_task: "violated"}
    heads = [
        {"id": uuid4(), "state": "shadow", "vid": RM, "bar": 0.0},
        {"id": uuid4(), "state": "canary", "vid": RM, "bar": 0.0},
        {"id": uuid4(), "state": "shadow", "vid": "rm:silent@1", "bar": 0.0},
    ]
    got = nightly.measurements(rows, REGISTRY, heads, gold, {RM}, Bundle(calibrated_defaults=True))
    shadow, serving = got[heads[0]["id"]], got[heads[1]["id"]]
    assert heads[2]["id"] not in got
    assert sorted(shadow.pairs, key=lambda p: p.verdict) == sorted(
        [
            ShadowPair("reject", "violated", GOLD),
            ShadowPair("accept", "satisfied", cert),
            ShadowPair("reject", "violated", GOLD),
        ],
        key=lambda p: p.verdict,
    )
    assert shadow.votes == 4 and shadow.canary is None
    assert sorted(p.cert_id for p in serving.pairs) == [GOLD, GOLD]
    bundle = Bundle(calibrated_defaults=True)
    votes = votes_by_task(rows, REGISTRY)[canary_task]
    with_ = adjudicate(votes, bundle).verdict
    without = adjudicate([v for v in votes if v.verifier_id != RM], bundle).verdict
    assert serving.canary == CanaryWatch(
        1, int(with_ != without), (int(with_ == "violated"), 1), (int(without == "violated"), 1)
    )


@pytest.mark.parametrize(
    ("watch", "healthy"),
    [
        (CanaryWatch(100, 5, (40, 50), (38, 50)), True),
        (CanaryWatch(100, 11, (40, 50), (38, 50)), False),
        (CanaryWatch(100, 5, (37, 50), (38, 50)), False),
        (CanaryWatch(100, 0, (0, 0), (0, 0)), True),
    ],
)
def test_canary_watch_bounds_flips_and_gold_agreement(watch, healthy):
    assert watch.healthy() is healthy


def test_spectral_run_persists_selfcert_as_valid_json():
    w = world()
    _, run = nightly.run_spectral(rows_for(w, (COMPILE, LINT, DIFF_JUDGE, RM)), REGISTRY)
    selfcert = json.loads(json.dumps(run["diagnostics"]["selfcert"], allow_nan=False))
    assert 0 <= selfcert["rho_plus"] < 0.2 and 0 <= selfcert["rho_minus"] < 0.2


CLOUD = "judge:grounded-rubric@2"
CLOUD_E0 = f"{CLOUD}/E0"
CLOUD_REGISTRY = {
    **REGISTRY,
    CLOUD: entry(
        "judge:grounded-rubric",
        "judge",
        {
            "kind": "judge",
            "group": "judge",
            "evidence_tier": "E1",
            "e0_fallback": {"group": "syntactic", "evidence_tier": "E0"},
        },
    ),
}


def cloud_row(task: int, tier: str, vote: str = "satisfied") -> dict:
    return {
        **VOTE_ROW,
        "family": "JudgeVote",
        "is_anchor": 0,
        "vote": vote,
        "task_id": str(UUID(int=task)),
        "verifier_id": CLOUD,
        "tier_used": f"EVIDENCE_TIER_{tier}",
    }


def lint_row(task: int, vote: str) -> dict:
    return {**VOTE_ROW, "task_id": str(UUID(int=task)), "verifier_id": LINT, "vote": vote}


def test_cloud_judge_e1_votes_are_judge_and_its_e0_fallback_is_its_own_syntactic_column():
    """m1_100's @2: diff-reading E1 votes are the independent `judge` view; the E0 fallback (anchor
    facts) is a separate column in `syntactic`, so one fallback never demotes the E1 view."""
    rows = [cloud_row(1, "E1"), cloud_row(2, "E0")]
    votes, groups, _, verifiers = nightly.vote_matrix(rows, CLOUD_REGISTRY)
    assert dict(zip(verifiers, groups, strict=True)) == {CLOUD: "judge", CLOUD_E0: "syntactic"}
    assert votes.tolist() == [[0, -1], [-1, 0]]
    fused = {v.task_id.int: v for vs in votes_by_task(rows, CLOUD_REGISTRY).values() for v in vs}
    # The judge_batch idempotence check still sees the one wire id; fusion sees the tier's column.
    assert {v.verifier_id for v in fused.values()} == {CLOUD}
    assert (fused[1].law_id, fused[1].group) == (CLOUD, "judge")
    assert (fused[2].law_id, fused[2].group) == (CLOUD_E0, "syntactic")


E1_LAW = [[0.90, 0.05, 0.05], [0.10, 0.85, 0.05]]
E0_LAW = [[0.60, 0.30, 0.10], [0.40, 0.50, 0.10]]
OTHER_LAW = [[0.50, 0.45, 0.05], [0.45, 0.50, 0.05]]
LINT_LAW = [[0.95, 0.02, 0.03], [0.50, 0.45, 0.05]]


def fuse(rows: list[dict], laws: dict, task: int):
    tasks = votes_by_task(rows, CLOUD_REGISTRY)
    bundle = bundle_for(
        (v for vs in tasks.values() for v in vs), {"passed": True, "confusion": laws}
    )
    return adjudicate(tasks[UUID(int=task)], bundle), bundle


def test_e0_and_e1_votes_of_the_cloud_judge_fuse_on_their_own_tiers_laws():
    """16 §L7: the same judge vote on the same task fuses on the E1 law when it read hunks and on
    the `/E0` law when it read anchor rows; neither tier's posterior moves with the other's law."""
    laws = {CLOUD: E1_LAW, CLOUD_E0: E0_LAW}
    same_task = fuse([cloud_row(1, "E1", "violated")], laws, 1)[0]
    assert same_task.posterior != fuse([cloud_row(1, "E0", "violated")], laws, 1)[0].posterior
    window = [cloud_row(1, "E1", "violated"), cloud_row(2, "E0", "violated")]
    (e1, bundle), (e0, _) = fuse(window, laws, 1), fuse(window, laws, 2)
    moved_e1, moved_e0 = {**laws, CLOUD: OTHER_LAW}, {**laws, CLOUD_E0: OTHER_LAW}
    assert fuse(window, moved_e0, 1)[0].posterior == e1.posterior
    assert fuse(window, moved_e1, 1)[0].posterior != e1.posterior
    assert fuse(window, moved_e1, 2)[0].posterior == e0.posterior
    assert fuse(window, moved_e0, 2)[0].posterior != e0.posterior
    assert bundle.verifiers[CLOUD].confusion[:2] == tuple(map(tuple, E1_LAW))
    assert bundle.verifiers[CLOUD_E0].confusion[:2] == tuple(map(tuple, E0_LAW))
    assert e1.provenance == e0.provenance == "spectral"


def test_a_tier_with_no_estimated_law_fuses_on_the_diff_rubrics_prior_never_the_other_tiers():
    rows = [
        cloud_row(1, "E1"),
        cloud_row(2, "E0"),
        {**cloud_row(3, "E1"), "verifier_id": DIFF_JUDGE},
    ]
    tasks = votes_by_task(rows, CLOUD_REGISTRY)
    votes = [v for vs in tasks.values() for v in vs]
    prior = (CALIBRATED_CONFUSION["judge"], "prior")
    only_e1 = bundle_for(votes, {"passed": True, "confusion": {CLOUD: E1_LAW}}).verifiers
    only_e0 = bundle_for(votes, {"passed": True, "confusion": {CLOUD_E0: E0_LAW}}).verifiers
    for p in (only_e1[CLOUD_E0], only_e1[DIFF_JUDGE], only_e0[CLOUD]):
        assert (p.confusion, p.provenance) == prior
    assert adjudicate(tasks[UUID(int=2)], Bundle(verifiers=only_e1)).provenance == "prior"


def test_each_tier_fuses_in_its_own_correlation_group():
    """An E0-fallback vote is one clique with the anchors it read (its reject collapses into the
    sharper lint reject); an E1 vote is the independent `judge` view and multiplies in."""
    laws = {CLOUD: E1_LAW, CLOUD_E0: E0_LAW, LINT: LINT_LAW}
    window = [
        lint_row(1, "violated"),
        cloud_row(1, "E1", "violated"),
        lint_row(2, "violated"),
        cloud_row(2, "E0", "violated"),
    ]
    tasks = votes_by_task(window, CLOUD_REGISTRY)
    bundle = bundle_for(
        (v for vs in tasks.values() for v in vs), {"passed": True, "confusion": laws}
    )
    assert {k: p.group for k, p in bundle.verifiers.items()} == {
        LINT: "syntactic",
        CLOUD: "judge",
        CLOUD_E0: "syntactic",
    }
    lint_alone = adjudicate([v for v in tasks[UUID(int=2)] if v.verifier_id == LINT], bundle)
    assert adjudicate(tasks[UUID(int=2)], bundle).posterior == lint_alone.posterior
    assert adjudicate(tasks[UUID(int=1)], bundle).posterior != lint_alone.posterior


def test_device_rmscore_votes_only_under_its_sealed_execution():
    from app.jobs.votes import vote_of
    from app.rm.scorer import rm_refused_total

    sealed = registry_by_wire_id([entry("rm:mark1-rm-a", "reward_model", {"kind": "rm"})])
    unsealed = registry_by_wire_id(
        [
            entry_from_row(
                {
                    "id": uuid4(),
                    "verifier_key": "rm:mark1-rm-a",
                    "version": 1,
                    "kind": "reward_model",
                    "definition": {"kind": "rm"},
                    "effective_execution_hash": None,
                    "retired_at": None,
                }
            )
        ]
    )
    base = {
        **VOTE_ROW,
        "family": "RmScore",
        "verifier_id": RM,
        "vote": "",
        "score": 0.9,
        "calibration_version": "rm-cal@1",
        "locus": "JUDGE_LOCUS_CLIENT_SIDE",
    }
    before = rm_refused_total.copy()
    assert vote_of(base, sealed) == "satisfied"
    other = base64.b64encode(b"\x09" * 32).decode()
    for row, reg in (
        ({**base, "execution_hash": other}, sealed),
        ({**base, "execution_hash": ""}, sealed),
        ({**base, "execution_hash": "not base64!"}, sealed),
        ({**base, "locus": ""}, unsealed),
    ):
        assert vote_of(row, reg) == "", row
    assert rm_refused_total["refused_rm_execution_hash"] - before["refused_rm_execution_hash"] == 3
    assert rm_refused_total["refused_rm_unsealed"] - before["refused_rm_unsealed"] == 1
    before = rm_refused_total.copy()
    cloud = {**base, "locus": "JUDGE_LOCUS_CLOUD"}
    assert vote_of(cloud, sealed) == "satisfied"  # the cloud serves the same sealed execution
    assert vote_of({**cloud, "execution_hash": ""}, sealed) == ""
    assert vote_of(cloud, unsealed) == ""
    assert rm_refused_total["refused_rm_execution_hash"] - before["refused_rm_execution_hash"] == 1
    assert rm_refused_total["refused_rm_unsealed"] - before["refused_rm_unsealed"] == 1
