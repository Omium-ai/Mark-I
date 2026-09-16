"""OPE (06 §11): estimators recover a known ground truth within CI, the C9 fidelity gate drops
and counts what it must, the ledger invariant's twin refuses bad propensities, and the promotion
floor fails closed (12 §: test_ope_estimators_synthetic_ground_truth, neg_ope_fidelity_filter,
test_ope_ess_floor_blocks_promotion)."""

import json
from datetime import date
from pathlib import Path

import numpy as np
import pytest
from app.ope import compare as cmp
from app.ope import estimators as est
from app.ope import inputs
from app.ope.inputs import DecisionRow, LoggedRow, assemble
from app.tvo.reader import QuerychokeReader
from choke_mock import MockChoke

CHOKE_FIXTURE_ROWS = json.loads(
    (
        Path(__file__).resolve().parents[3]
        / "go/controld/internal/querychoke/testdata/intel_template_rows.json"
    ).read_text()
)
CTX = {"ctx0": 0.5, "ctx1": 0.3, "ctx2": 0.2}
ACTS = ["small", "mid", "large"]
MU = {  # true P(satisfied | x, a)
    "ctx0": {"small": 0.30, "mid": 0.55, "large": 0.70},
    "ctx1": {"small": 0.60, "mid": 0.50, "large": 0.65},
    "ctx2": {"small": 0.20, "mid": 0.40, "large": 0.80},
}
LOGGING = {x: {"small": 0.70, "mid": 0.15, "large": 0.15} for x in CTX}  # ε-greedy on "small"
CANDIDATE = {x: {max(MU[x], key=MU[x].get): 1.0} for x in CTX}  # deterministic best action
# Re-routes ctx0 and ctx2 in opposite directions so its true value equals the logging policy's.
EQUAL_VALUE = {
    **LOGGING,
    "ctx0": {"small": 0.67, "mid": 0.15, "large": 0.18},
    "ctx2": {"small": 0.85, "mid": 0.0, "large": 0.15},
}


def true_value(policy: est.Policy) -> float:
    return sum(px * sum(pa * MU[x][a] for a, pa in policy[x].items()) for x, px in CTX.items())


def simulate(rng: np.random.Generator, n: int, logging: est.Policy = LOGGING) -> list[LoggedRow]:
    xs = rng.choice(list(CTX), size=n, p=list(CTX.values()))
    rows = []
    for x in xs:
        acts, probs = zip(*logging[x].items(), strict=True)
        a = acts[rng.choice(len(acts), p=probs)]
        rows.append(LoggedRow(x, a, float(rng.random() < MU[x][a]), logging[x][a]))
    return rows


def test_ope_estimators_synthetic_ground_truth():
    rng = np.random.default_rng(7)
    v = true_value(CANDIDATE)
    rows = simulate(rng, 4000)
    s = est.snips(rows, CANDIDATE)
    d, ext = est.doubly_robust(rows, CANDIDATE, est.RewardModel(rows))
    assert s.lcb <= v <= s.ucb
    assert d.lcb <= v <= d.ucb
    assert ext == 0.0  # full-support log: nothing extrapolated
    hits = [0, 0]
    for _ in range(100):
        rows = simulate(rng, 1000)
        s = est.snips(rows, CANDIDATE)
        d, _ = est.doubly_robust(rows, CANDIDATE, est.RewardModel(rows))
        hits[0] += s.lcb <= v <= s.ucb
        hits[1] += d.lcb <= v <= d.ucb
    assert min(hits) >= 90


def _decision(fidelity: str, **kw) -> DecisionRow:
    base = dict(
        decision_id="d",
        context="claudecode|small,mid,large",
        action="mid",
        propensity=0.5,
        fidelity=fidelity,
        served_model="mid",
        verdict="satisfied",
        verdict_stage="certified",
        label_confidence=0.9,
    )
    return DecisionRow(**{**base, **kw})


def test_advisory_rows_dropped_and_counted():
    out = assemble([_decision("wire_enforced"), _decision("advisory"), _decision("advisory")])
    assert len(out.rows) == 1 and out.rows[0].reward == 0.9
    assert out.dropped == {"advisory": 2}


def test_config_steered_admitted_only_with_served_model_confirmation():
    out = assemble(
        [
            _decision("config_steered", served_model="mid"),
            _decision("config_steered", served_model="large"),
            _decision("config_steered", served_model=None),
        ]
    )
    assert len(out.rows) == 1
    assert out.dropped == {"config_steered_unconfirmed": 2}


def test_uncertified_and_unresolved_rewards_excluded_not_zero_filled():
    out = assemble(
        [
            _decision("wire_enforced", verdict_stage="provisional"),
            _decision("wire_enforced", verdict="refused"),
            _decision("wire_enforced", verdict="violated"),
        ]
    )
    assert [r.reward for r in out.rows] == [0.0]
    assert out.dropped == {"uncertified": 1, "unresolved": 1}


@pytest.mark.parametrize("p", [0.0, 1.0001, -0.2, float("nan")])
def test_propensity_outside_unit_interval_refused(p):
    with pytest.raises(ValueError, match="ledger invariant"):
        assemble([_decision("wire_enforced", propensity=p)])


def test_unknown_fidelity_refused():
    with pytest.raises(ValueError, match="ledger invariant"):
        assemble([_decision("")])


def test_promotion_refused_when_ci_straddles_zero():
    assert true_value(EQUAL_VALUE) == pytest.approx(true_value(LOGGING))
    rows = simulate(np.random.default_rng(10), 3000)
    v = cmp.compare(rows, EQUAL_VALUE, LOGGING)
    assert v.candidate.dr.point > v.incumbent.dr.point  # a point rule would promote this draw
    assert v.decision == "not_better"
    assert v.diff.lcb <= 0 <= v.diff.ucb
    assert v.candidate.diagnostics.ess >= cmp.ESS_MIN  # refused on the CI, not the floor


def test_promotes_when_candidate_clearly_better():
    rows = simulate(np.random.default_rng(11), 4000)
    v = cmp.compare(rows, CANDIDATE, LOGGING)
    assert v.decision == "promote"
    assert v.candidate.dr.lcb > v.incumbent.dr.point and v.diff.lcb > 0  # paired CI agrees
    assert v.candidate.diagnostics.ess >= cmp.ESS_MIN


def test_ope_ess_floor_blocks_promotion():
    rows = simulate(np.random.default_rng(5), 300)  # deterministic candidate ⇒ ESS well under 200
    v = cmp.compare(rows, CANDIDATE, LOGGING)
    assert v.decision == "insufficient_evidence"
    assert v.candidate.diagnostics.ess < cmp.ESS_MIN
    assert cmp.compare([], CANDIDATE, LOGGING).decision == "insufficient_evidence"


def test_epsilon_zero_never_promotes():
    logging = {x: {"small": 1.0} for x in CTX}
    rows = simulate(np.random.default_rng(9), 2000, logging)
    v = cmp.compare(rows, logging, logging)
    assert v.decision == "non_regression_on_overlap"
    assert v.claim == "non-regression on overlap, ESS = 2000"


def test_weights_clipped_at_w_max_with_mass_reported():
    rows = [LoggedRow("x", "a", 1.0, 0.001), LoggedRow("x", "a", 0.0, 1.0)]
    w, clipped = est.weights(rows, {"x": {"a": 1.0}})
    assert w.tolist() == [est.W_MAX, 1.0]
    assert clipped == pytest.approx(900 / 1001)


async def test_fetch_speaks_choke_wire_and_gates():
    """Two-way lock with controld: the rows are the choke's own fixture (templates_test.go asserts
    the template's aliases equal these keys), fed through fetch() exactly as served."""
    choke = MockChoke()
    choke.templates[inputs.TEMPLATE] = CHOKE_FIXTURE_ROWS[inputs.TEMPLATE]
    reader = QuerychokeReader(choke.client(), "http://choke")
    out = await inputs.fetch(reader, date(2026, 8, 1), date(2026, 8, 31), bearer="op-token")
    assert out.rows == (
        LoggedRow("claudecode|small,mid", "mid", 0.9, 0.8),
    )  # config_steered, served
    assert out.dropped == {
        "uncertified": 1
    }  # wire_enforced but no certified verdict, never zero-filled
    template, params, auth = choke.requests[0]
    assert (template, params, auth) == (
        inputs.TEMPLATE,
        {"from": "2026-08-01", "to": "2026-08-31"},
        "Bearer op-token",
    )


async def test_score_job_assembles_closed_window_and_returns_no_receipt(monkeypatch):
    from types import SimpleNamespace

    from app.ope.jobs import score

    monkeypatch.setenv("INTEL_QUERYCHOKE_TOKEN", "svc-token")
    choke = MockChoke()
    choke.templates[inputs.TEMPLATE] = []
    ctx = SimpleNamespace(
        settings=SimpleNamespace(querychoke_base_url="http://choke", http_timeout_s=1.0),
        tenant_id="tenant-a",
        day=date(2026, 9, 15),
    )
    assert await score(ctx, http=choke.client()) is None
    assert choke.requests[0] == (
        inputs.TEMPLATE,
        {"from": "2026-09-15", "to": "2026-09-15"},
        "Bearer svc-token",
    )
    monkeypatch.delenv("INTEL_QUERYCHOKE_TOKEN")
    with pytest.raises(ValueError, match="INTEL_QUERYCHOKE_TOKEN"):
        await score(ctx, http=choke.client())
