"""Waste taxonomy arithmetic (06 §8.3; channel definitions normative in 07 §MVs) on a
synthetic session shaped after Paper I §9.1's worked accounting example (tab:worked):
exploration, attempt 1 rejected, one repair round, verified completion. The taxonomy's
channels are deliberately NOT the paper's Shapley channels — Shapley is gated on
ADR-0003 (06 §0) — so only the ledger-witnessed arithmetic is asserted here."""

import pytest
from app.tvo.engine import AttemptRow
from app.tvo.waste import (
    RungSignal,
    ToolUseRow,
    WasteTriple,
    over_model_tokens,
    reexploration_tokens,
    retry_loop_tokens,
    waste_taxonomy,
)

# Paper I tab:worked, as ledger rows: attempt 1 (30k gen + 25k verify) → violated;
# repair round (12k gen + 25k verify) → satisfied, certified.
ATTEMPTS = [
    AttemptRow("task-1", 1, 30_000, 25_000, "violated", "certified"),
    AttemptRow("task-1", 2, 12_000, 25_000, "satisfied", "certified"),
]

# 26k of the 41k exploration (all on attempt 1) re-derives facts the Cortex map had
# already served (digests d1, d2); the remaining 15k reads fresh targets.
TOOL_USES = [
    ToolUseRow("sess-1", "task-1", 1, "read", 20_000, "d1"),
    ToolUseRow("sess-1", "task-1", 1, "grep", 6_000, "d2"),
    ToolUseRow("sess-1", "task-1", 1, "read", 15_000, "d3"),
    # not a read-class category — never waste
    ToolUseRow("sess-1", "task-1", 1, "edit", 9_000, "d1"),
]
SERVED = {"sess-1": frozenset({"d1", "d2"})}


def test_retry_loop_charges_the_loop_not_the_work():
    # Attempt 2 follows a violated verdict: all 37k of its metered tokens are loop waste.
    # Attempt 1 is never waste by definition.
    assert retry_loop_tokens(ATTEMPTS) == 12_000 + 25_000


def test_retry_loop_not_charged_after_non_violated_verdicts():
    rows = [
        AttemptRow("t", 1, 10_000, 1_000, "refused", "certified"),
        AttemptRow("t", 2, 5_000, 1_000, "satisfied", "certified"),
    ]
    assert retry_loop_tokens(rows) == 0


def test_retry_loop_attempt_gap_witnesses_nothing():
    rows = [
        AttemptRow("t", 1, 10_000, 1_000, "violated", "certified"),
        AttemptRow("t", 3, 5_000, 1_000, "satisfied", "certified"),  # attempt 2 missing
    ]
    assert retry_loop_tokens(rows) == 0


def test_reexploration_joins_digest_to_digest():
    # 20k + 6k hit the served set; the fresh 15k read and the 9k edit do not.
    assert reexploration_tokens(TOOL_USES, SERVED) == 26_000


def test_reexploration_unclaimable_without_cortex_injection():
    # No CortexInjection for the session ⇒ no counterfactual model, zero claimed (07).
    assert reexploration_tokens(TOOL_USES, {}) == 0


VERDICTS = {"task-1": ("satisfied", "certified")}


def test_over_model_delta_vs_cheapest_passing_rung():
    signals = [
        RungSignal("task-1", rung_rank=2, output_tokens=9_000, passed=True, used=True),
        RungSignal("task-1", rung_rank=0, output_tokens=3_000, passed=True, used=False),
        # A cheaper rung that FAILED is not an alternative — must not shrink the delta.
        RungSignal("task-1", rung_rank=1, output_tokens=1_000, passed=False, used=False),
    ]
    assert over_model_tokens(signals, VERDICTS) == 6_000


def test_over_model_zero_when_no_cheaper_rung_exercised():
    signals = [RungSignal("task-1", rung_rank=2, output_tokens=9_000, passed=True, used=True)]
    assert over_model_tokens(signals, VERDICTS) == 0


def test_over_model_only_for_certified_satisfied_tasks():
    signals = [
        RungSignal("task-1", 2, 9_000, True, True),
        RungSignal("task-1", 0, 3_000, True, False),
    ]
    assert over_model_tokens(signals, {"task-1": ("satisfied", "provisional")}) == 0
    assert over_model_tokens(signals, {"task-1": ("violated", "certified")}) == 0
    assert over_model_tokens(signals, {}) == 0


def test_taxonomy_assembles_the_triple():
    signals = [
        RungSignal("task-1", 2, 9_000, True, True),
        RungSignal("task-1", 0, 3_000, True, False),
    ]
    triple = waste_taxonomy(ATTEMPTS, TOOL_USES, SERVED, signals, VERDICTS)
    assert triple == WasteTriple(
        retry_loop_tokens=37_000,
        reexploration_tokens=26_000,
        over_model_tokens=6_000,
    )
    # The 06 §8.3 audit identity: channels + unattributed remainder == window total.
    total = sum(a.gen_tokens + a.verifier_tokens for a in ATTEMPTS)
    channels = triple.retry_loop_tokens + triple.reexploration_tokens + triple.over_model_tokens
    assert 0 <= channels <= total  # remainder = total - channels, non-negative


def test_taxonomy_precedence_loop_outranks_reexploration():
    # A served-set re-read INSIDE the loop attempt is already charged to the loop
    # (precedence 1 > 2): the same tokens must not appear in both channels.
    uses = [
        ToolUseRow("sess-1", "task-1", 1, "read", 20_000, "d1"),
        ToolUseRow("sess-1", "task-1", 2, "grep", 6_000, "d2"),  # on the loop attempt
    ]
    triple = waste_taxonomy(ATTEMPTS, uses, SERVED, [], VERDICTS)
    assert triple.retry_loop_tokens == 37_000
    assert triple.reexploration_tokens == 20_000  # the loop-attempt 6k is NOT re-charged
    # The standalone 07 §MVs arithmetic (no precedence) still counts both — the
    # partition is waste_taxonomy's property, the primitives stay normative.
    assert reexploration_tokens(uses, SERVED) == 26_000


def test_taxonomy_precedence_over_model_capped_at_unattributed():
    # over_model (precedence 3) may only claim tokens precedence 1–2 left on its task:
    # task total 92k − 37k loop − 26k re-exploration = 29k remaining; a 40k rung delta
    # is capped there rather than double-charging loop/re-read tokens.
    signals = [
        RungSignal("task-1", 2, 45_000, True, True),
        RungSignal("task-1", 0, 5_000, True, False),
    ]
    triple = waste_taxonomy(ATTEMPTS, TOOL_USES, SERVED, signals, VERDICTS)
    assert triple.over_model_tokens == 29_000
    total = sum(a.gen_tokens + a.verifier_tokens for a in ATTEMPTS)
    assert (
        triple.retry_loop_tokens + triple.reexploration_tokens + triple.over_model_tokens == total
    )


def test_taxonomy_refuses_rows_outside_the_window():
    # A tool use (or rung signal) on a task with no attempt rows has no total to
    # partition against — the window is incoherent, refuse (06 §8.3 audit identity).
    stray = [ToolUseRow("sess-1", "task-9", 1, "read", 1_000, "d1")]
    with pytest.raises(ValueError, match="task-9"):
        waste_taxonomy(ATTEMPTS, stray, SERVED, [], VERDICTS)
    signals = [  # a CLAIMING signal pair on a task with no attempt rows
        RungSignal("task-9", 1, 5_000, True, True),
        RungSignal("task-9", 0, 1_000, True, False),
    ]
    verdicts = {**VERDICTS, "task-9": ("satisfied", "certified")}
    with pytest.raises(ValueError, match="task-9"):
        waste_taxonomy(ATTEMPTS, [], SERVED, signals, verdicts)


def test_taxonomy_refuses_a_broken_partition():
    # Tool tokens exceeding their attempts' metered total cannot partition — the
    # identity check must refuse rather than report negative unattributed tokens.
    uses = [ToolUseRow("sess-1", "task-1", 1, "read", 999_000, "d1")]
    with pytest.raises(ValueError, match="partition"):
        waste_taxonomy(ATTEMPTS, uses, SERVED, [], VERDICTS)
