"""06 §10.3 knee tables under both cost bases (FR-VERIFY-009). Golden rows are hand-derived
in comments from the closed forms (06 §8.4, Wilson) — never from calling knee.py."""

import pytest
from app.policy_compiler.knee import (
    AttemptCost,
    KneeInputs,
    KneeRow,
    implied_knee,
    knee_table,
    wilson_lcb,
)
from app.tvo.report import ModelPrice

# Pinned price row: $3/M in, $15/M out, $3.75/M cache-create, $0.30/M cache-read.
PRICE = ModelPrice("prices-2026-09", 3e-6, 15e-6, 3.75e-6, 0.3e-6)


def _a(task, n, verdict, stage="certified", **tok):
    return AttemptCost(task_id=task, attempt_n=n, fused_verdict=verdict, verdict_stage=stage, **tok)


# Certified attempts, by n. Two provisional rows are in the window and must not enter any fit.
ATTEMPTS = (
    # n=1 — outcomes S,V,S ⇒ k=2, t=3
    _a("a", 1, "satisfied", input_tokens=1000, output_tokens=500, verifier_spend_usd=0.00135),
    _a("b", 1, "violated", input_tokens=3000, output_tokens=1000, cache_read_tokens=500),
    _a("c", 1, "satisfied", input_tokens=1000, output_tokens=500),
    _a("d", 1, "violated", stage="provisional", input_tokens=9000, output_tokens=9000),
    # n=2 — outcomes V,S ⇒ k=1, t=2
    _a("a", 2, "violated", input_tokens=1000, output_tokens=500),
    _a("b", 2, "satisfied", stage="revised", input_tokens=2000, output_tokens=500),
    # n=3 — one certified `refused`: costed, but no S/V outcome ⇒ p_lcb ABSENT
    _a("a", 3, "refused", input_tokens=2000, output_tokens=1000),
    # n=4 — provisional only ⇒ no row at all
    _a("b", 4, "satisfied", stage="provisional", input_tokens=100, output_tokens=100),
)


def _inputs(**over):
    kw = dict(
        task_class="fn",
        attempts=ATTEMPTS,
        v_task=25.0,
        price=PRICE,
        window_limit_tokens=50_000,
        shadow_price_usd=200.0,
    )
    kw.update(over)
    return KneeInputs(**kw)


# Wilson 95% LCB, z = 1.959963984540054, z² = 3.841458820694124:
#   lcb = [ (p̂ + z²/2t) − z·sqrt(p̂(1−p̂)/t + z²/4t²) ] / (1 + z²/t)
# n=1: p̂=2/3, t=3: denom = 1 + 1.280486 = 2.280486;
#      center = (0.666667 + 0.640243)/2.280486 = 0.573083;
#      half = 1.959964·sqrt(0.074074 + 0.106707)/2.280486 = 1.959964·0.425184/2.280486 = 0.365423
#      ⇒ 0.573083 − 0.365423 = 0.207660  (0.20765960080204765)
# n=2: p̂=1/2, t=2: denom = 1 + 1.920729 = 2.920729;
#      center = (0.5 + 0.960365)/2.920729 = 0.500000;
#      half = 1.959964·sqrt(0.125 + 0.240091)/2.920729 = 1.959964·0.604228/2.920729 = 0.405469
#      ⇒ 0.5 − 0.405469 = 0.094531  (0.09453120573423074)
P_LCB_1 = 0.20765960080204765
P_LCB_2 = 0.09453120573423074


def test_knee_table_usd_and_quota_golden():
    # usd (06 §8.4): in·3e-6 + out·15e-6 + cr·0.3e-6 + v, mean over certified rows at n.
    #   n=1: a = 0.003 + 0.0075 + 0.00135 = 0.01185; b = 0.009 + 0.015 + 0.00015 = 0.02415;
    #        c = 0.0105  ⇒ (0.01185 + 0.02415 + 0.0105)/3 = 0.0465/3 = 0.0155
    #   n=2: a = 0.0105; b = 0.006 + 0.0075 = 0.0135  ⇒ 0.024/2 = 0.012
    #   n=3: 0.006 + 0.015 = 0.021
    usd = knee_table(_inputs(), "usd")
    assert usd.cost_basis == "usd"
    assert usd.v_default == 25.0
    assert usd.price_table_version == "prices-2026-09" and usd.shadow_price_usd is None
    assert usd.certified_attempts == 6
    assert [r.n for r in usd.rows] == [1, 2, 3]
    assert [r.c_n for r in usd.rows] == pytest.approx([0.0155, 0.012, 0.021])
    assert [r.p_lcb for r in usd.rows][:2] == pytest.approx([P_LCB_1, P_LCB_2])
    assert usd.rows[2].p_lcb is None

    # quota (06 §8.4): (tokens_consumed / W) × S with W = 50 000, S = 200.
    #   n=1: tokens 1500, 4500 (3000+1000+500), 1500 ⇒ mean 2500 ⇒ 2500/50000·200 = 10.0
    #   n=2: tokens 1500, 2500 ⇒ mean 2000 ⇒ 8.0
    #   n=3: tokens 3000 ⇒ 12.0
    quota = knee_table(_inputs(), "quota")
    assert quota.cost_basis == "quota"
    assert quota.shadow_price_usd == 200.0 and quota.price_table_version is None
    assert [r.c_n for r in quota.rows] == pytest.approx([10.0, 8.0, 12.0])
    # p̂_LCB is basis-free: same certified outcomes, same rows.
    assert [r.p_lcb for r in quota.rows] == [r.p_lcb for r in usd.rows]

    # Wire shape = 07 knee-table verbatim; absent p_lcb is absent, not null (D-Z).
    assert usd.wire() == {
        "cost_basis": "usd",
        "rows": [
            {"n": 1, "c_n": pytest.approx(0.0155), "p_lcb": pytest.approx(P_LCB_1)},
            {"n": 2, "c_n": pytest.approx(0.012), "p_lcb": pytest.approx(P_LCB_2)},
            {"n": 3, "c_n": pytest.approx(0.021)},
        ],
        "v_default": 25.0,
    }

    # Cross-check (06 §8.1/§10.3): γ̂ from p̂ = [2/3, 1/2] ⇒ exp(ln 0.5 − ln 2/3) = 0.75.
    #   quota: ρ̂ = c(1)/(p₁·V) = 10/(2/3·25) = 0.6 ⇒ k* = 1 + ⌊ln 0.6/ln 0.75⌋ = 1 + ⌊1.776⌋ = 2;
    #          governor: 0.20766·25 = 5.19 ≤ 10 ⇒ implied knee 1; |1 − 2| ≤ 1 ⇒ publishable.
    #   usd:   ρ̂ = 0.0155/(2/3·25) = 0.00093 ⇒ k* = 1 + ⌊6.980/0.2877⌋ = 1 + 24 = 25;
    #          5.19 > 0.0155, 2.36 > 0.012, n=3 not evaluable ⇒ no stop in table; 25 > 3 ⇒ ok.
    assert (quota.implied_knee, quota.closed_form_knee, quota.publishable) == (1, 2, True)
    assert (usd.implied_knee, usd.closed_form_knee, usd.publishable) == (None, 25, True)


def test_quota_and_usd_knees_differ_for_the_same_task():
    # Anti-vacuity: the quota table is not the usd table with a relabelled basis — c(n)
    # differs on every row, and so does what the governor would do with it.
    usd, quota = knee_table(_inputs(), "usd"), knee_table(_inputs(), "quota")
    assert all(u.c_n != q.c_n for u, q in zip(usd.rows, quota.rows, strict=True))
    assert usd.implied_knee != quota.implied_knee
    # The quota knee moves with window exhaustion (06 §10.3): halve the window, c(n) doubles.
    tight = knee_table(_inputs(window_limit_tokens=25_000), "quota")
    assert [r.c_n for r in tight.rows] == pytest.approx([20.0, 16.0, 24.0])


def test_no_certified_rows_keeps_previous_table_with_note():
    prev = knee_table(_inputs(), "usd")
    only_provisional = tuple(a for a in ATTEMPTS if a.verdict_stage == "provisional")
    kept = knee_table(_inputs(attempts=only_provisional), "usd", previous=prev)
    assert kept.wire() == prev.wire()
    assert "previous knee table kept" in kept.note
    # No previous table either: nothing publishable (07 requires ≥ 1 row) — and no invented rows.
    bare = knee_table(_inputs(attempts=only_provisional), "usd")
    assert bare.rows == () and not bare.publishable


def test_absent_p_lcb_never_stops_zero_always_does():
    # Twin of mark1d TestKneeAbsentPLCBNeverStops: zero certified outcomes at n ⇒ p_lcb absent
    # ⇒ not evaluable, even with c_n large enough that any p̂ would stop; 0.0 is measured hopeless.
    assert implied_knee([KneeRow(n=1, c_n=1e9)], 25.0) is None
    assert implied_knee([KneeRow(n=1, c_n=1e9, p_lcb=0.0)], 25.0) == 1
    with pytest.raises(ValueError):
        wilson_lcb(0, 0)
    # k=0 successes has a real (zero) lower bound — distinct from "no trials".
    assert wilson_lcb(0, 5) == 0.0


def test_basis_prerequisites_and_d34_cap():
    with pytest.raises(ValueError, match="model_prices"):
        knee_table(_inputs(price=None), "usd")
    with pytest.raises(ValueError, match="window_limit_tokens"):
        knee_table(_inputs(window_limit_tokens=None), "quota")
    with pytest.raises(ValueError, match="cost_basis"):
        knee_table(_inputs(), "tokens")  # type: ignore[arg-type]
    deep = ATTEMPTS + (_a("z", 9, "satisfied", input_tokens=1, output_tokens=1),)
    assert [r.n for r in knee_table(_inputs(attempts=deep), "usd").rows] == [1, 2, 3]
