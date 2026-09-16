"""CPVS scoring (06 §10.1): cost-per-verified-success per (task_class, model).

    CPVS(task_class, m) = E[cost per attempt under basis] / p̂_LCB(task_class, m)

The denominator is the 95% Wilson LCB of the certified pass rate, never the point estimate
(three lucky passes must not top the table); the numerator is the tenant's cost basis (06
§8.4, the same `coster` the knee uses). D33: a cell needs MIN_CELL certified outcomes, below
that it inherits the model's pooled estimate and is marked `inherited`; a model whose pool is
also below the floor is unmeasured and emits no row. Certified rows only (06 §5.4).
"""

from collections import defaultdict
from collections.abc import Callable, Iterable
from statistics import fmean

from pydantic import BaseModel, ConfigDict, Field

from app.policy_compiler.knee import AttemptCost, Basis, coster, wilson_lcb
from app.tvo.engine import _CERTIFIED_STAGES
from app.tvo.report import DEFAULT_SHADOW_PRICE_USD, ModelPrice

MIN_CELL = 30  # D33
_OUTCOMES = frozenset({"satisfied", "violated"})


class CertifiedAttempt(AttemptCost):
    """One ledger attempt at the compiler's grain: knee.py's cost columns plus the two keys
    CPVS scores on. `cost_basis` is the row's C1.9 cohort stamp (07 m1p_events)."""

    task_class: str
    model_id: str
    cost_basis: Basis


class Regime(BaseModel):
    """What the ledger rows do not carry: the channel's basis and its pricing inputs (06 §8.4)
    plus V(task)'s fallback (06 §8.1). One basis per channel, never mixed (CON-014)."""

    model_config = ConfigDict(frozen=True)

    cost_basis: Basis
    v_default: float = Field(gt=0.0)
    price: ModelPrice | None = None
    window_limit_tokens: int | None = None
    shadow_price_usd: float = DEFAULT_SHADOW_PRICE_USD

    def coster(self) -> Callable[[AttemptCost], float]:
        return coster(
            self.cost_basis,
            price=self.price,
            window_limit_tokens=self.window_limit_tokens,
            shadow_price_usd=self.shadow_price_usd,
        )


class CPVSCell(BaseModel):
    model_config = ConfigDict(frozen=True)

    task_class: str
    model_id: str
    p_lcb: float
    cost: float  # E[cost per attempt] under the regime's basis
    tokens_est: int
    outcomes: int  # certified satisfied+violated behind p_lcb (the D33 count)
    cache_read_share: float  # of tokens_consumed; ladders.py's keep_prefix evidence
    inherited: bool = False

    @property
    def cpvs(self) -> float:
        return self.cost / self.p_lcb if self.p_lcb > 0 else float("inf")

    def wire(self) -> dict:
        """07 `cpvs-row`, field names verbatim; p_pass carries the LCB (06 §10.1)."""
        return {
            "task_class": self.task_class,
            "model_id": self.model_id,
            "p_pass": self.p_lcb,
            "tokens_est": self.tokens_est,
        }


def certified(attempts: Iterable[CertifiedAttempt]) -> list[CertifiedAttempt]:
    return [a for a in attempts if a.verdict_stage in _CERTIFIED_STAGES]


def _estimate(task_class: str, model_id: str, rows: list[CertifiedAttempt], cost) -> CPVSCell:
    scored = [a for a in rows if a.fused_verdict in _OUTCOMES]
    k = sum(1 for a in scored if a.fused_verdict == "satisfied")
    consumed = sum(a.tokens_consumed for a in rows)
    return CPVSCell(
        task_class=task_class,
        model_id=model_id,
        p_lcb=wilson_lcb(k, len(scored)),
        cost=fmean(cost(a) for a in rows),
        tokens_est=round(consumed / len(rows)),
        outcomes=len(scored),
        cache_read_share=sum(a.cache_read_tokens for a in rows) / consumed if consumed else 0.0,
    )


def cpvs_table(attempts: Iterable[CertifiedAttempt], regime: Regime) -> list[CPVSCell]:
    """One cell per observed (task_class, model) with a measured or inherited estimate,
    sorted for a deterministic wire order."""
    cost = regime.coster()
    by_cell: dict[tuple[str, str], list[CertifiedAttempt]] = defaultdict(list)
    by_model: dict[str, list[CertifiedAttempt]] = defaultdict(list)
    for a in certified(attempts):
        by_cell[a.task_class, a.model_id].append(a)
        by_model[a.model_id].append(a)
    pooled = {
        m: _estimate("*", m, rows, cost)
        for m, rows in by_model.items()
        if sum(1 for a in rows if a.fused_verdict in _OUTCOMES) >= MIN_CELL
    }
    out: list[CPVSCell] = []
    for (task_class, model_id), rows in sorted(by_cell.items()):
        if sum(1 for a in rows if a.fused_verdict in _OUTCOMES) >= MIN_CELL:
            out.append(_estimate(task_class, model_id, rows, cost))
        elif model_id in pooled:
            cell = pooled[model_id]
            out.append(cell.model_copy(update={"task_class": task_class, "inherited": True}))
    return out
