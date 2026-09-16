"""Model ladders (06 §10.2): the prefix principle with its honest correlation correction.

Per task_class the incumbent is the strongest measured rung (highest p̂_LCB, cheaper on ties)
with TVO = c/p̂. A cheaper candidate m is PREPENDED iff its corrected index beats the incumbent
ladder's TVO:

    index(m | L) = c_m / (1 − (1 − p_m)·κ)     <  TVO(L),     κ = p_h / P(h passes | m failed)

where h is the ladder's first rung. κ = 1 is the independent (uncorrected) case, index = c_m/p_m.
P(h | ¬m) is MEASURED as the Wilson LCB over tasks where a certified `violated` on m was followed
by a certified outcome on h when there are ≥ MIN_CELL such pairs; otherwise it is the Fréchet
lower bound max(0, (p_h − p_m)/(1 − p_m)) — the most pessimistic conditional consistent with the
marginals. Assuming independence is exactly how the principle over-prepends (06 §10.2), so the
no-evidence default assumes the opposite. Candidates are tried costliest-first so each prepend
lands at the front; TVO([m, L]) = c_m + (1 − p_m)·κ·TVO(L) carries forward.

keep_prefix on rung i says its context rides into rung i+1 on escalation (mark1d verdict.Ladder):
set iff the rung's certified attempts read prompt cache (cache_read_share > 0) — the only ledger
evidence that a preserved prefix is cache-priced; the last rung has nothing to escalate to.
"""

from collections import defaultdict
from collections.abc import Iterable

from pydantic import BaseModel, ConfigDict

from app.policy_compiler.cpvs import MIN_CELL, CertifiedAttempt, CPVSCell, certified
from app.policy_compiler.knee import wilson_lcb

_OUTCOMES = frozenset({"satisfied", "violated"})


class Rung(BaseModel):
    model_config = ConfigDict(frozen=True)

    model_id: str
    keep_prefix: bool


class Ladder(BaseModel):
    model_config = ConfigDict(frozen=True)

    ladder_id: str  # the task_class
    rungs: tuple[Rung, ...]  # cheapest → strongest
    tvo: float  # the ladder's corrected cost per verified success; never on the wire

    def wire(self) -> dict:
        return {"ladder_id": self.ladder_id, "rungs": [r.model_dump() for r in self.rungs]}


def _pairs(attempts: list[CertifiedAttempt]) -> dict[tuple[str, str, str], tuple[int, int]]:
    """(task_class, m, h) → (h satisfied, h outcomes) over attempts on h that followed a
    certified violated attempt on m within the same task."""
    by_task: dict[str, list[CertifiedAttempt]] = defaultdict(list)
    for a in attempts:
        if a.fused_verdict in _OUTCOMES:
            by_task[a.task_id].append(a)
    counts: dict[tuple[str, str, str], list[int]] = defaultdict(lambda: [0, 0])
    for rows in by_task.values():
        rows.sort(key=lambda a: a.attempt_n)
        failed: set[str] = set()
        for a in rows:
            for m in failed:
                if m != a.model_id:
                    c = counts[a.task_class, m, a.model_id]
                    c[0] += a.fused_verdict == "satisfied"
                    c[1] += 1
            if a.fused_verdict == "violated":
                failed.add(a.model_id)
    return {k: (v[0], v[1]) for k, v in counts.items()}


def conditional_pass(m: CPVSCell, h: CPVSCell, pairs: dict) -> float:
    k, t = pairs.get((m.task_class, m.model_id, h.model_id), (0, 0))
    if t >= MIN_CELL:
        return wilson_lcb(k, t)
    if m.p_lcb >= 1.0:
        return 0.0
    return max(0.0, (h.p_lcb - m.p_lcb) / (1.0 - m.p_lcb))


def build_ladders(cells: Iterable[CPVSCell], attempts: Iterable[CertifiedAttempt]) -> list[Ladder]:
    pairs = _pairs(certified(attempts))
    by_class: dict[str, list[CPVSCell]] = defaultdict(list)
    for c in cells:
        if c.p_lcb > 0:
            by_class[c.task_class].append(c)
    out: list[Ladder] = []
    for task_class, cands in sorted(by_class.items()):
        base = max(cands, key=lambda c: (c.p_lcb, -c.cost))
        ladder, tvo = [base], base.cpvs
        for m in sorted((c for c in cands if c.cost < base.cost), key=lambda c: -c.cost):
            p_cond = conditional_pass(m, ladder[0], pairs)
            if p_cond <= 0:
                continue
            kappa = ladder[0].p_lcb / p_cond
            denom = 1.0 - (1.0 - m.p_lcb) * kappa
            if denom <= 0 or m.cost / denom >= tvo:
                continue
            tvo = m.cost + (1.0 - m.p_lcb) * kappa * tvo
            ladder.insert(0, m)
        rungs = tuple(
            Rung(model_id=c.model_id, keep_prefix=i + 1 < len(ladder) and c.cache_read_share > 0)
            for i, c in enumerate(ladder)
        )
        out.append(Ladder(ladder_id=task_class, rungs=rungs, tvo=tvo))
    return out
