"""Certificate computation (06 §5.2) and the status ladder (06 §5.3)."""

import pytest
from app.certs.compute import compute_certificate, wilson_interval
from app.certs.state_machine import (
    BOOTSTRAPPING,
    CERTIFIED,
    UNCERTIFIED,
    CertEvidence,
    may_gate_learning,
    next_status,
)
from app.gold.score import GoldScore, score_agreement

# ---------------------------------------------------------------------------
# Wilson + ρ computation
# ---------------------------------------------------------------------------


def test_wilson_contains_the_point_and_shrinks_with_n():
    lo1, hi1 = wilson_interval(5, 10)
    lo2, hi2 = wilson_interval(50, 100)
    assert lo1 < 0.5 < hi1
    assert lo2 < 0.5 < hi2
    assert (hi2 - lo2) < (hi1 - lo1)


def test_wilson_zero_count_upper_bound_is_honest():
    # k=0 must NOT yield [0, 0] — that is the lie Wilson exists to prevent.
    lo, hi = wilson_interval(0, 200)
    assert lo == 0.0
    assert 0.0 < hi < 0.03


def test_wilson_refuses_zero_trials():
    with pytest.raises(ValueError):
        wilson_interval(0, 0)


def _score(k_plus=3, n_plus=150, k_minus=2, n_minus=120, abstained=10, held_out=5):
    return GoldScore(
        n_plus=n_plus,
        k_plus=k_plus,
        n_minus=n_minus,
        k_minus=k_minus,
        abstained=abstained,
        held_out=held_out,
        gold_n=n_plus + n_minus + abstained + held_out,
    )


def test_certificate_computation_healthy_window():
    c = compute_certificate(_score())
    assert c.rho_plus == pytest.approx(3 / 150)
    assert c.rho_minus == pytest.approx(2 / 120)
    assert c.natarajan_margin == pytest.approx(1 - (3 / 150 + 2 / 120))
    assert c.natarajan_lcb is not None and 0 < c.natarajan_lcb < c.natarajan_margin
    assert c.natarajan_ok is True
    assert c.abstention_mass == pytest.approx(10 / 280)


def test_certificate_never_fabricates_a_rate():
    # No covered gold on the violated side: ρ₋ is unmeasurable, so EVERYTHING derived
    # from it is None — never a defaulted 0.0 wearing a measurement's column.
    c = compute_certificate(_score(n_minus=0, k_minus=0))
    assert c.rho_plus is None
    assert c.rho_minus is None
    assert c.natarajan_lcb is None
    assert c.natarajan_ok is None


def test_natarajan_fails_on_noisy_window():
    # ρ₊ + ρ₋ near 1: the LCB cannot clear 0 — the certificate must say so.
    c = compute_certificate(_score(k_plus=75, n_plus=150, k_minus=60, n_minus=120))
    assert c.natarajan_ok is False


def test_score_agreement_projection_rules():
    pairs = [
        ("satisfied", "satisfied"),  # n₊
        ("satisfied", "violated"),  # n₊, k₊
        ("satisfied", "refused"),  # abstained — covered-instances rule (Thm 6.1)
        ("violated", "satisfied"),  # n₋, k₋
        ("violated", "violated"),  # n₋
        ("violated", "error"),  # abstained
        ("refused", "satisfied"),  # held out — gold refused/error never enters ρ
        ("error", "violated"),  # held out
    ]
    s = score_agreement(pairs)
    assert (s.n_plus, s.k_plus) == (2, 1)
    assert (s.n_minus, s.k_minus) == (2, 1)
    assert s.abstained == 2
    assert s.held_out == 2
    assert s.gold_n == 8
    assert s.abstention_mass == pytest.approx(2 / 6)


# ---------------------------------------------------------------------------
# The §5.3 status ladder
# ---------------------------------------------------------------------------


def ev(**kw) -> CertEvidence:
    defaults = dict(
        gold_n=0,
        fresh_frac=0.0,
        estimator_ran=True,
        identifiability_passed=False,
        natarajan_ok=None,
    )
    defaults.update(kw)
    return CertEvidence(**defaults)


ALL_GREEN = ev(gold_n=250, fresh_frac=0.9, identifiability_passed=True, natarajan_ok=True)


def test_uncertified_needs_50_labels_and_a_running_estimator():
    assert next_status(UNCERTIFIED, ev(gold_n=49)) == UNCERTIFIED
    assert next_status(UNCERTIFIED, ev(gold_n=50)) == BOOTSTRAPPING
    assert next_status(UNCERTIFIED, ev(gold_n=500, estimator_ran=False)) == UNCERTIFIED


def test_no_path_skips_bootstrapping_upward():
    # Even a perfect window: uncertified → bootstrapping, NEVER straight to certified.
    assert next_status(UNCERTIFIED, ALL_GREEN) == BOOTSTRAPPING


def test_bootstrapping_to_certified_needs_every_gate():
    assert next_status(BOOTSTRAPPING, ALL_GREEN) == CERTIFIED
    # D15 size gate
    assert (
        next_status(
            BOOTSTRAPPING,
            ev(gold_n=199, fresh_frac=0.9, identifiability_passed=True, natarajan_ok=True),
        )
        == BOOTSTRAPPING
    )
    # D16 freshness gate
    assert (
        next_status(
            BOOTSTRAPPING,
            ev(gold_n=250, fresh_frac=0.4, identifiability_passed=True, natarajan_ok=True),
        )
        == BOOTSTRAPPING
    )
    # §4.3 identifiability gate — the Phase 2 permanent state (spectral is Phase 4)
    assert (
        next_status(BOOTSTRAPPING, ev(gold_n=250, fresh_frac=0.9, natarajan_ok=True))
        == BOOTSTRAPPING
    )
    # NATARAJAN_OK unmeasured is not a pass
    assert (
        next_status(BOOTSTRAPPING, ev(gold_n=250, fresh_frac=0.9, identifiability_passed=True))
        == BOOTSTRAPPING
    )


def test_certified_demotes_one_step_on_quality_lapse():
    stale = ev(gold_n=250, fresh_frac=0.4, identifiability_passed=True, natarajan_ok=True)
    shrunk = ev(gold_n=150, fresh_frac=0.9, identifiability_passed=True, natarajan_ok=True)
    gate_fail = ev(gold_n=250, fresh_frac=0.9, identifiability_passed=False, natarajan_ok=True)
    assert next_status(CERTIFIED, stale) == BOOTSTRAPPING
    assert next_status(CERTIFIED, shrunk) == BOOTSTRAPPING
    assert next_status(CERTIFIED, gate_fail) == BOOTSTRAPPING
    assert next_status(CERTIFIED, ALL_GREEN) == CERTIFIED


def test_validity_problems_demote_to_the_floor_from_any_state():
    for current in (CERTIFIED, BOOTSTRAPPING):
        assert next_status(current, ev(gold_n=250, natarajan_ok=False)) == UNCERTIFIED
        assert (
            next_status(current, ev(gold_n=250, natarajan_ok=True, drift_alarm=True)) == UNCERTIFIED
        )
        assert (
            next_status(current, ev(gold_n=250, natarajan_ok=True, tamper_event=True))
            == UNCERTIFIED
        )


def test_unmeasured_natarajan_is_not_a_violation():
    # None means "not yet measurable", not "failed": bootstrapping holds.
    assert next_status(BOOTSTRAPPING, ev(gold_n=100, natarajan_ok=None)) == BOOTSTRAPPING


def test_unknown_status_refused():
    with pytest.raises(ValueError):
        next_status("gold-plated", ALL_GREEN)


def test_only_certified_gates_learning():
    # The §5.4 settled rule: uncertified/bootstrapping verdicts gate NOTHING on the
    # learning side — not memory extraction, not corpus admission.
    assert may_gate_learning(CERTIFIED) is True
    assert may_gate_learning(BOOTSTRAPPING) is False
    assert may_gate_learning(UNCERTIFIED) is False
