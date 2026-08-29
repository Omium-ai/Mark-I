"""The deterministic waste taxonomy (06 §8.3; per-channel arithmetic normative in 07 §MVs).
Deliberately counterfactual-free: each channel counts only tokens with a ledger-WITNESSED
alternative — no model of what a cheaper rung or a warmer cache *would* have done.
`waste_taxonomy` additionally makes the channels PARTITION the window's metered tokens
under a stated precedence (retry_loop > reexploration > over_model) so 06 §8.3's
'auditable by arithmetic' holds literally: channels + unattributed remainder == total.
Shapley attribution is deliberately absent: ADR-0003 (the game definition) is unsigned
(06 §0), and when it lands it is presentation over these columns, never a replacement."""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from app.tvo.engine import AttemptRow, group_by_task

# Tool categories whose re-reads the Cortex served-set can witness (07: read/grep/list/glob).
_REEXPLORATION_CATEGORIES = frozenset({"read", "grep", "list", "glob"})

_CERTIFIED_STAGES = frozenset({"certified", "revised"})


@dataclass(frozen=True)
class ToolUseRow:
    """One ToolUse ledger event, digest already per-tenant HMAC-salted (07: the join is
    digest-to-digest — this module never sees a path or an excerpt). (task_id, attempt_n)
    is the attempt span the event fell in (07 §MVs: attempt boundaries come from
    VerdictEvent rows) — the linkage the channel-precedence partition joins on."""

    session_id: str
    task_id: str
    attempt_n: int
    category: str
    tokens: int
    target_digest: str


@dataclass(frozen=True)
class RungSignal:
    """A (task, ladder rung) observation: output tokens plus whether an actual passing
    anchor-verified signal exists at this rung (shadow run or mid-task downgrade, 07)."""

    task_id: str
    rung_rank: int  # ladder position by cost, 0 = cheapest
    output_tokens: int
    passed: bool
    used: bool  # the rung the session actually ran


@dataclass(frozen=True)
class WasteTriple:
    retry_loop_tokens: int
    reexploration_tokens: int
    over_model_tokens: int


def _loop_attempt_keys(attempts: Iterable[AttemptRow]) -> set[tuple[str, int]]:
    """The one definition of 'loop attempt' (07 §MVs): attempt n (n ≥ 2) whose attempt
    n−1 carried a 'violated' fused verdict. A gap in numbering witnesses nothing."""
    keys: set[tuple[str, int]] = set()
    for task_id, rows in group_by_task(attempts).items():
        by_n = {a.attempt_n: a for a in rows}
        for a in rows:
            if a.attempt_n < 2:
                continue
            prev = by_n.get(a.attempt_n - 1)
            if prev is not None and prev.fused_verdict == "violated":
                keys.add((task_id, a.attempt_n))
    return keys


def retry_loop_tokens(attempts: Iterable[AttemptRow]) -> int:
    """07: per task, tokens of attempt n (n ≥ 2) where attempt n−1's fused verdict was
    'violated'. First attempts are never waste — the taxonomy charges the loop, not the
    work. A gap in attempt numbering witnesses nothing and charges nothing."""
    rows = list(attempts)
    loop = _loop_attempt_keys(rows)
    # All metered tokens of the loop attempt (R1 totality): the retry's verification
    # spend is as much a cost of the loop as its generation.
    return sum(a.gen_tokens + a.verifier_tokens for a in rows if (a.task_id, a.attempt_n) in loop)


def reexploration_tokens(
    tool_uses: Iterable[ToolUseRow],
    served_digests: Mapping[str, frozenset[str]],
) -> int:
    """07: read/grep/list/glob tokens whose target digest is in the session's
    CortexInjection served-set. Claimable ONLY where an injection exists — a session
    absent from `served_digests` had no served set and contributes zero, by rule."""
    total = 0
    for row in tool_uses:
        if row.category not in _REEXPLORATION_CATEGORIES:
            continue
        served = served_digests.get(row.session_id)
        if served and row.target_digest in served:
            total += row.tokens
    return total


def _over_model_by_task(
    signals: Iterable[RungSignal],
    task_verdicts: Mapping[str, tuple[str, str]],
) -> dict[str, int]:
    by_task: dict[str, list[RungSignal]] = {}
    for s in signals:
        by_task.setdefault(s.task_id, []).append(s)

    claims: dict[str, int] = {}
    for task_id, sigs in by_task.items():
        verdict, stage = task_verdicts.get(task_id, ("", ""))
        if verdict != "satisfied" or stage not in _CERTIFIED_STAGES:
            continue
        used = next((s for s in sigs if s.used), None)
        if used is None:
            continue
        cheaper_passing = [s for s in sigs if s.passed and s.rung_rank < used.rung_rank]
        if not cheaper_passing:
            continue
        cheapest = min(cheaper_passing, key=lambda s: s.rung_rank)
        # ponytail: floored at 0 — a cheaper rung that emitted MORE output is not
        # negative waste, it is zero waste; the 07 formula presumes the normal ordering.
        claims[task_id] = max(0, used.output_tokens - cheapest.output_tokens)
    return claims


def over_model_tokens(
    signals: Iterable[RungSignal],
    task_verdicts: Mapping[str, tuple[str, str]],  # task_id -> (fused_verdict, verdict_stage)
) -> int:
    """07: for certified-satisfied tasks only, output_tokens(r_used) − output_tokens
    (r_cheapest_passing), where the cheapest passing rung must have an ACTUAL passing
    signal on this same task. Zero when no cheaper rung was exercised — the taxonomy
    refuses to guess what a cheaper model would have done."""
    return sum(_over_model_by_task(signals, task_verdicts).values())


def waste_taxonomy(
    attempts: Iterable[AttemptRow],
    tool_uses: Iterable[ToolUseRow],
    served_digests: Mapping[str, frozenset[str]],
    rung_signals: Iterable[RungSignal],
    task_verdicts: Mapping[str, tuple[str, str]],
) -> WasteTriple:
    """The three channels assembled so they PARTITION the window's metered tokens —
    06 §8.3's taxonomy is 'auditable by arithmetic', which a token charged to two
    channels breaks. Precedence order, coarsest witness first (06 §8.3):

      1. retry_loop      — whole loop attempts (the loop outranks anything inside it);
      2. reexploration   — served-set re-reads on NON-loop attempts only (a re-read
                           inside a loop attempt is already charged to the loop);
      3. over_model      — the rung delta, capped at the task's still-unattributed
                           tokens (output tokens live inside attempt totals).

    Invariant, asserted: retry + reexploration + over_model + unattributed == total
    metered tokens of the window, with unattributed ≥ 0. Inputs must be one coherent
    ledger window — a tool use or rung signal on a task with no attempt rows has no
    total to partition against and is refused."""
    rows = list(attempts)
    task_total: dict[str, int] = {}
    for a in rows:
        task_total[a.task_id] = task_total.get(a.task_id, 0) + a.gen_tokens + a.verifier_tokens

    loop = _loop_attempt_keys(rows)
    retry_by_task: dict[str, int] = {}
    for a in rows:
        if (a.task_id, a.attempt_n) in loop:
            retry_by_task[a.task_id] = (
                retry_by_task.get(a.task_id, 0) + a.gen_tokens + a.verifier_tokens
            )

    # Precedence 2: only tool uses OUTSIDE loop attempts may claim re-exploration.
    non_loop_uses = []
    reexp_by_task: dict[str, int] = {}
    for u in tool_uses:
        if u.task_id not in task_total:
            raise ValueError(f"tool use on task {u.task_id!r} with no attempt rows in the window")
        if (u.task_id, u.attempt_n) in loop:
            continue
        non_loop_uses.append(u)
    for u in non_loop_uses:
        served = served_digests.get(u.session_id)
        if u.category in _REEXPLORATION_CATEGORIES and served and u.target_digest in served:
            reexp_by_task[u.task_id] = reexp_by_task.get(u.task_id, 0) + u.tokens
    reexp = reexploration_tokens(non_loop_uses, served_digests)

    # Precedence 3: over_model claims only what precedence 1–2 left on its task.
    over = 0
    for task_id, claim in _over_model_by_task(rung_signals, task_verdicts).items():
        if task_id not in task_total:
            raise ValueError(f"rung signal on task {task_id!r} with no attempt rows in the window")
        remaining = (
            task_total[task_id] - retry_by_task.get(task_id, 0) - reexp_by_task.get(task_id, 0)
        )
        over += min(claim, max(0, remaining))

    retry = sum(retry_by_task.values())
    total = sum(task_total.values())
    unattributed = total - retry - reexp - over
    if unattributed < 0 or retry + reexp + over + unattributed != total:
        # The audit identity failing means the ledger inputs are incoherent (e.g. tool
        # tokens exceeding their attempts' metered tokens) — refuse, never report it.
        raise ValueError(
            f"waste channels do not partition the window: retry={retry} reexploration={reexp} "
            f"over_model={over} vs total={total} (06 §8.3 audit identity)"
        )
    return WasteTriple(
        retry_loop_tokens=retry,
        reexploration_tokens=reexp,
        over_model_tokens=over,
    )
