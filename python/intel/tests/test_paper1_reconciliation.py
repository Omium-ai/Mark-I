"""06 §8.6 — the Phase 1 gate's 'TVO output matches hand-computed values', executable.

Golden test against Paper I (mark1-research/paper1-tvo.tex, §9 'Numerical Illustrations',
Table 1 / tab:regimes: population p=0.4, c=30k, D=150k) and both published repair knees
(§5, Theorem 5.1's zero-parameter validation: function-level k*=2 at ρ=0.3, γ=0.5;
repository-scale k*=6 at ρ=0.3, γ=0.8). The fixture carries the papers' printed numbers —
including the corrections-log AUROC-0.537 row (TVO 360.0k / +20%, v* = −7.2k) — so this
test also detects silent drift between the papers and the code."""

import json
from pathlib import Path

import pytest
from app.tvo.closed_forms import repair_knee, tvo, verifier_break_even

FIXTURE = json.loads(
    (Path(__file__).parent / "fixtures" / "paper1_worked_example.json").read_text()
)


def _round_to_paper_precision(tokens: float) -> float:
    # Table 1 prints TVO to 0.1k tokens (e.g. 257.1k = 257100): nearest 100 tokens.
    return round(tokens / 100.0) * 100.0


@pytest.mark.parametrize("regime", FIXTURE["regimes"], ids=lambda r: r["name"])
def test_table1_tvo_rows(regime):
    pop = FIXTURE["population"]
    computed = tvo(pop["c"], regime["v"], pop["p"], regime["alpha"], regime["beta"], pop["D"])
    assert _round_to_paper_precision(computed) == regime["tvo_tokens"]


@pytest.mark.parametrize(
    "regime",
    [r for r in FIXTURE["regimes"] if "v_star_tokens" in r],
    ids=lambda r: r["name"],
)
def test_table1_break_even_rows(regime):
    pop = FIXTURE["population"]
    computed = verifier_break_even(pop["c"], pop["p"], regime["alpha"], regime["beta"], pop["D"])
    assert computed == pytest.approx(regime["v_star_tokens"], abs=1e-6)


@pytest.mark.parametrize(
    "regime",
    [r for r in FIXTURE["regimes"] if "vs_baseline_pct" in r],
    ids=lambda r: r["name"],
)
def test_table1_vs_baseline_column(regime):
    pop = FIXTURE["population"]
    baseline = tvo(pop["c"], 0, pop["p"], 1.0, 1.0, pop["D"])
    computed = tvo(pop["c"], regime["v"], pop["p"], regime["alpha"], regime["beta"], pop["D"])
    assert round((computed / baseline - 1.0) * 100.0) == regime["vs_baseline_pct"]


@pytest.mark.parametrize("knee", FIXTURE["repair_knees"], ids=lambda k: k["scale"])
def test_published_repair_knees(knee):
    assert repair_knee(knee["rho"], knee["gamma"]) == knee["k_star"]
