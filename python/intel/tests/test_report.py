"""Report assembly (06 §8.2/§8.4/§8.5, wire shape 08 §3.3): the guarantee/indicative flip,
every refusal reason stated on the report, cost-basis arithmetic under both bases, and a
full body snapshot so the assembled shape cannot drift silently."""

import dataclasses

import pytest
from app.tvo.coverage import CoverageBand
from app.tvo.engine import AttemptRow, NoiseCertificate, tvo_from_ledger
from app.tvo.report import (
    DEFAULT_SHADOW_PRICE_USD,
    ModelPrice,
    TvoReport,
    assemble_report,
    quota_cost,
    usd_cost,
)
from app.tvo.waste import WasteTriple

ATTEMPTS = [
    AttemptRow("t1", 1, 30_000, 25_000, "violated", "certified"),
    AttemptRow("t1", 2, 12_000, 25_000, "satisfied", "certified"),
]
CERTIFIED = NoiseCertificate("certified", rho_plus=0.15, rho_minus=0.20)
WASTE = WasteTriple(37_000, 26_000, 6_000)
GOOD_BAND = CoverageBand(coverage_lower=0.96, coverage=0.98)
LOW_BAND = CoverageBand(coverage_lower=0.90, coverage=0.94)
PRICE = ModelPrice("prices-v3", 3e-6, 15e-6, 3.75e-6, 0.3e-6)


def _result(cert=CERTIFIED):
    return tvo_from_ledger(ATTEMPTS, cert, d=150_000)


def test_guarantee_grade_when_all_gates_green():
    report = assemble_report(
        _result(), WASTE, GOOD_BAND, cost_basis="usd", task_seg_version="task_seg.v1", price=PRICE
    )
    assert report.guarantee_grade is True
    assert report.grade == "guarantee-grade"
    assert report.refusals == ()
    assert report.input_provenance["alpha"] == "measured"


def test_coverage_floor_flips_to_indicative_with_m1e_5004():
    report = assemble_report(
        _result(), WASTE, LOW_BAND, cost_basis="usd", task_seg_version="task_seg.v1", price=PRICE
    )
    assert report.guarantee_grade is False
    assert report.grade == "indicative"
    # 08 §3.3: the refusal IS the message, verbatim code included.
    assert any(r.startswith("M1E-5004 coverage below floor") for r in report.refusals)
    # The number still renders — refused outright, not withheld (08 §3.3).
    assert report.tvo > 0
    assert "refusal" in report.to_body()


def test_uncertified_cert_flips_to_indicative_with_status_string():
    report = assemble_report(
        _result(NoiseCertificate("bootstrapping")),
        WASTE,
        GOOD_BAND,
        cost_basis="usd",
        task_seg_version="task_seg.v1",
        price=PRICE,
    )
    assert report.guarantee_grade is False
    assert any("bootstrapping" in r for r in report.refusals)  # §5.4: status appears verbatim
    assert report.input_provenance["alpha"] == "calibrated"  # and the inputs say so too


def test_quota_basis_needs_confirmed_shadow_price():
    unconfirmed = assemble_report(
        _result(), WASTE, GOOD_BAND, cost_basis="quota", task_seg_version="task_seg.v1"
    )
    assert unconfirmed.guarantee_grade is False
    assert any("shadow price" in r for r in unconfirmed.refusals)
    assert unconfirmed.shadow_price_usd == DEFAULT_SHADOW_PRICE_USD  # D22 placeholder, stamped

    confirmed = assemble_report(
        _result(),
        WASTE,
        GOOD_BAND,
        cost_basis="quota",
        task_seg_version="task_seg.v1",
        shadow_price_usd=350.0,
        shadow_price_confirmed=True,
    )
    assert confirmed.guarantee_grade is True
    assert confirmed.shadow_price_usd == 350.0


def test_task_seg_boundary_crossing_refused_without_both_series():
    kwargs = dict(
        cost_basis="usd",
        task_seg_version="task_seg.v1",
        price=PRICE,
        task_seg_versions_in_window=["task_seg.v1", "task_seg.v2"],
    )
    crossed = assemble_report(_result(), WASTE, GOOD_BAND, **kwargs)
    assert crossed.guarantee_grade is False
    both = assemble_report(_result(), WASTE, GOOD_BAND, both_series_shown=True, **kwargs)
    assert both.guarantee_grade is True


def test_cost_basis_never_mixed():
    with pytest.raises(ValueError):
        assemble_report(
            _result(), WASTE, GOOD_BAND, cost_basis="usd+quota", task_seg_version="task_seg.v1"
        )


def test_usd_basis_needs_pinned_price_table():
    # Symmetric with the quota rule (06 §8.4): a usd report without a pinned
    # model_prices row cannot state which prices it used — indicative, stated.
    unpinned = assemble_report(
        _result(), WASTE, GOOD_BAND, cost_basis="usd", task_seg_version="task_seg.v1"
    )
    assert unpinned.guarantee_grade is False
    assert any("model_prices" in r for r in unpinned.refusals)
    assert unpinned.price_table_version is None


def test_cross_basis_fields_never_stamped():
    # A price row alongside a quota report is ignored, never stamped (06 §8.4);
    # the quota fields never land on a usd report either.
    quota = assemble_report(
        _result(),
        WASTE,
        GOOD_BAND,
        cost_basis="quota",
        task_seg_version="task_seg.v1",
        price=PRICE,
        shadow_price_usd=350.0,
        shadow_price_confirmed=True,
    )
    assert quota.price_table_version is None
    usd = assemble_report(
        _result(), WASTE, GOOD_BAND, cost_basis="usd", task_seg_version="task_seg.v1", price=PRICE
    )
    assert usd.shadow_price_usd is None


def test_cross_basis_field_is_a_constructor_error():
    base = assemble_report(
        _result(), WASTE, GOOD_BAND, cost_basis="usd", task_seg_version="task_seg.v1", price=PRICE
    )
    with pytest.raises(ValueError, match="shadow_price_usd"):
        dataclasses.replace(base, shadow_price_usd=200.0)
    with pytest.raises(ValueError, match="price_table_version"):
        dataclasses.replace(base, cost_basis="quota", shadow_price_usd=None)


def test_usd_cost_arithmetic():
    # 06 §8.4: Σ(token class × pinned price) + verifier spend.
    cost = usd_cost(1_000_000, 100_000, 50_000, 400_000, PRICE, verifier_spend_usd=0.293)
    assert cost == pytest.approx(3.0 + 1.5 + 0.1875 + 0.12 + 0.293)


def test_quota_cost_arithmetic_and_refusals():
    # (tokens / window_limit) × S: half a window at the D22 default prices $100.
    assert quota_cost(500_000, 1_000_000) == pytest.approx(100.0)
    assert quota_cost(500_000, 1_000_000, shadow_price_usd=300.0) == pytest.approx(150.0)
    with pytest.raises(ValueError):
        quota_cost(500_000, 0)  # unfitted window limit is unmeasurable, not free
    with pytest.raises(ValueError):
        quota_cost(500_000, 1_000_000, shadow_price_usd=-1.0)


def test_report_has_no_bandless_constructor():
    # 06 §8.2: the report dataclass has no band-less constructor, deliberately.
    fields = {f.name for f in dataclasses.fields(TvoReport)}
    assert "coverage_band" in fields and "cost_basis" in fields
    with pytest.raises(TypeError):
        TvoReport(  # type: ignore[call-arg]
            tvo=1.0,
            break_even_v=0.0,
            waste=WASTE,
            coverage_floor=0.95,
            cost_basis="usd",
            task_seg_version="task_seg.v1",
            cert_status="certified",
            grade="indicative",
            guarantee_grade=False,
        )


def test_body_snapshot():
    report = assemble_report(
        _result(), WASTE, GOOD_BAND, cost_basis="usd", task_seg_version="task_seg.v1", price=PRICE
    )
    body = report.to_body()
    assert body == {
        "tvo": pytest.approx(143_529.4117647059),
        "coverage_band": {
            "observed_fraction": 0.98,
            "coverage_lower": 0.96,
            "floor": 0.95,
        },
        "cost_basis": "usd",
        "task_seg_version": "task_seg.v1",
        "waste": {
            "retry_loop_tokens": 37_000,
            "re_exploration_tokens": 26_000,
            "over_model_tokens": 6_000,
        },
        "guarantee_grade": True,
        "grade": "guarantee-grade",
        "cert_status": "certified",
        "input_provenance": {
            "c": "measured",
            "v": "measured",
            "p": "measured",
            "alpha": "measured",
            "beta": "measured",
            "D": "configured",
        },
    }
