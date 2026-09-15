"""Knee tables under both cost bases (06 §10.3) — the producer of 07's `route.knee` section.

Per (tenant, task_class): rows `(n, c_n, ?p_lcb)` for n = 1..8 (D34), fitted on certified
attempts only (06 §5.4 consumer row). The edge's governor (`mark1d` `kneeFor`, 04 §2.3) stops
when `p̂_LCB(n)·V(task) ≤ c(n)`; this module supplies both sides of that inequality and
never issues the verdict itself.

Two bases (06 §8.4), same attempts, genuinely different c(n):
  usd   = Σ tokens × pinned price + verifier spend v     (`report.usd_cost`)
  quota = (tokens_consumed / window_limit_tokens) × S    (`report.quota_cost`)

p̂_LCB(n) is the 95% Wilson lower bound of P(satisfied | attempt n) over certified
satisfied/violated outcomes (refused/error leave the denominator, as in `engine.measured_inputs`).
06 §10.3 does not name the estimator; §10.1 names Wilson 95% for the same p̂_LCB quantity and
`cache.go`'s KneeState documents "95% Wilson LCB", so Wilson it is, at the adjudicator's z.
Zero outcomes at n ⇒ `p_lcb` ABSENT (D-Z) ⇒ the edge never stops on that row.

Paper I Thm 5.1's k*(ρ̂, γ̂) is a CROSS-CHECK, not the governor (06 §8.1): the table's implied
knee must land within ±1 of it, or the table is not publishable.
"""

import math
from collections import defaultdict
from collections.abc import Callable
from statistics import fmean
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.tvo.closed_forms import repair_knee
from app.tvo.engine import _CERTIFIED_STAGES, fit_gamma, knee_consistent, rho_hat
from app.tvo.report import (
    COST_BASIS_QUOTA,
    COST_BASIS_USD,
    DEFAULT_SHADOW_PRICE_USD,
    ModelPrice,
    quota_cost,
    usd_cost,
)

MAX_N = 8  # D34: rows n = 1..8
_Z95 = 1.959963984540054  # two-sided 95% — same constant as adjudicator/app/certs/compute.py

Basis = Literal["usd", "quota"]


def wilson_lcb(k: int, n: int, z: float = _Z95) -> float:
    """Wilson score lower bound for k successes in n trials (06 §10.1's "95% LCB (Wilson)").
    n = 0 is not a measurement — callers leave `p_lcb` absent instead (D-Z)."""
    if n <= 0:
        raise ValueError("Wilson LCB over zero trials is not a measurement")
    if not 0 <= k <= n:
        raise ValueError(f"k={k} outside [0, n={n}]")
    p, z2 = k / n, z * z
    denom = 1.0 + z2 / n
    center = (p + z2 / (2 * n)) / denom
    half = (z / denom) * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n))
    return max(0.0, center - half)


class AttemptCost(BaseModel):
    """One attempt of one task at the ledger's usage grain (07 m1p_events usage columns):
    the four token classes `usd_cost` prices, plus the measured verifier spend v."""

    model_config = ConfigDict(frozen=True)

    task_id: str
    attempt_n: int = Field(ge=1)
    fused_verdict: Literal["satisfied", "violated", "refused", "error"]
    verdict_stage: Literal["provisional", "certified", "revised"]
    input_tokens: int = Field(0, ge=0)
    output_tokens: int = Field(0, ge=0)
    cache_creation_tokens: int = Field(0, ge=0)
    cache_read_tokens: int = Field(0, ge=0)
    verifier_spend_usd: float = Field(0.0, ge=0.0)  # usd basis only (06 §8.4 "plus v")

    @property
    def tokens_consumed(self) -> int:
        # Quota numerator: everything the attempt drew from the rate-limit window. Judge
        # tokens are metered as ordinary usage (06 §6.4), so they are already in here.
        return (
            self.input_tokens
            + self.output_tokens
            + self.cache_creation_tokens
            + self.cache_read_tokens
        )


class KneeInputs(BaseModel):
    model_config = ConfigDict(frozen=True)

    task_class: str
    attempts: tuple[AttemptCost, ...]
    v_task: float = Field(gt=0.0)  # V(task): task-class estimate, else bundle v_default (06 §8.1)
    price: ModelPrice | None = None  # usd: the pinned model_prices row (06 §8.4)
    window_limit_tokens: int | None = None  # quota: fitted from rate-limit events (06 §8.4)
    shadow_price_usd: float = DEFAULT_SHADOW_PRICE_USD  # D22
    max_n: int = Field(MAX_N, ge=1)


class KneeRow(BaseModel):
    """07 knee-table row, field names verbatim: `n`, `c_n`, optional `p_lcb`."""

    model_config = ConfigDict(frozen=True)

    n: int
    c_n: float
    p_lcb: float | None = None


class KneeTable(BaseModel):
    model_config = ConfigDict(frozen=True)

    # ── the 07 wire fields ──
    cost_basis: Basis
    rows: tuple[KneeRow, ...]
    v_default: float
    # ── publication metadata, never on the wire ──
    task_class: str
    certified_attempts: int
    price_table_version: str | None = None  # stamped under usd
    shadow_price_usd: float | None = None  # stamped under quota
    implied_knee: int | None = None  # first n the table stops at; None = never within the table
    closed_form_knee: int | None = None  # k*(ρ̂, γ̂); None = fit refused
    publishable: bool
    note: str

    def wire(self) -> dict:
        """Exactly 07's `knee-table` map. An absent `p_lcb` is ABSENT, never null — the
        CDDL says `? p_lcb: float` and both decoders reject a null there."""
        return {
            "cost_basis": self.cost_basis,
            "rows": [r.model_dump(exclude_none=True) for r in self.rows],
            "v_default": self.v_default,
        }


def implied_knee(rows: tuple[KneeRow, ...] | list[KneeRow], v_task: float) -> int | None:
    """The governor over the table, the Python twin of `kneeFor` (cache.go): first n with
    `p_lcb·V ≤ c_n`. A row without `p_lcb` is not evaluable and never stops (D-Z)."""
    return next((r.n for r in rows if r.p_lcb is not None and r.p_lcb * v_task <= r.c_n), None)


def _coster(inputs: KneeInputs, basis: Basis) -> Callable[[AttemptCost], float]:
    if basis == COST_BASIS_USD:
        price = inputs.price
        if price is None:
            raise ValueError("usd basis needs a pinned model_prices row (06 §8.4)")
        return lambda a: usd_cost(
            a.input_tokens,
            a.output_tokens,
            a.cache_creation_tokens,
            a.cache_read_tokens,
            price,
            a.verifier_spend_usd,
        )
    if basis == COST_BASIS_QUOTA:
        window = inputs.window_limit_tokens
        if window is None:
            raise ValueError("quota basis needs a fitted window_limit_tokens (06 §8.4)")
        return lambda a: quota_cost(a.tokens_consumed, window, inputs.shadow_price_usd)
    raise ValueError(f"cost_basis={basis!r} not in ('usd', 'quota') — never mixed")


def knee_table(inputs: KneeInputs, basis: Basis, previous: KneeTable | None = None) -> KneeTable:
    """06 §10.3. Fits proceed on certified rows only; with none, the previous table is returned
    with its wire fields unchanged and a note saying so (06 §5.4). With no previous table
    either, the result has no rows and is not publishable (07 requires ≥ 1 row)."""
    cost = _coster(inputs, basis)
    certified = [
        a
        for a in inputs.attempts
        if a.verdict_stage in _CERTIFIED_STAGES and a.attempt_n <= inputs.max_n
    ]
    stamp = {
        "price_table_version": inputs.price.price_table_version
        if basis == COST_BASIS_USD and inputs.price
        else None,
        "shadow_price_usd": inputs.shadow_price_usd if basis == COST_BASIS_QUOTA else None,
    }
    if not certified:
        note = f"no certified attempts for {inputs.task_class!r}: previous knee table kept (§5.4)"
        if previous is not None:
            return previous.model_copy(update={"note": note})
        return KneeTable(
            cost_basis=basis,
            rows=(),
            v_default=inputs.v_task,
            task_class=inputs.task_class,
            certified_attempts=0,
            publishable=False,
            note=note + "; no previous table — knee section not publishable",
            **stamp,
        )

    by_n: dict[int, list[AttemptCost]] = defaultdict(list)
    for a in certified:
        by_n[a.attempt_n].append(a)
    rows: list[KneeRow] = []
    rates = [0.0] * max(by_n)  # index n−1; 0.0 = no outcome at n, which fit_gamma skips
    for n in sorted(by_n):
        k = sum(1 for a in by_n[n] if a.fused_verdict == "satisfied")
        t = k + sum(1 for a in by_n[n] if a.fused_verdict == "violated")
        if t:
            rates[n - 1] = k / t
        rows.append(
            KneeRow(n=n, c_n=fmean(cost(a) for a in by_n[n]), p_lcb=wilson_lcb(k, t) if t else None)
        )

    implied = implied_knee(rows, inputs.v_task)
    try:
        gamma = fit_gamma(rates)
        c1 = next((r.c_n for r in rows if r.n == 1), 0.0)
        rho = rho_hat(c1, rates[0], inputs.v_task)
        k_star: int | None = repair_knee(rho, gamma)
    except ValueError as exc:
        # Not a violated gate — an unverifiable one; publish, and say so.
        k_star, ok = None, True
        note = f"closed-form cross-check not performed: {exc}"
    else:
        # No stop within the table means the (clamped) edge never stops; that agrees with
        # the closed form only when k* also lies past the last row.
        ok = k_star > rows[-1].n if implied is None else knee_consistent(implied, rho, gamma)
        note = f"implied knee {implied} vs k*={k_star}: " + ("within ±1" if ok else "VIOLATED")
    return KneeTable(
        cost_basis=basis,
        rows=tuple(rows),
        v_default=inputs.v_task,
        task_class=inputs.task_class,
        certified_attempts=len(certified),
        implied_knee=implied,
        closed_form_knee=k_star,
        publishable=ok,
        note=note,
        **stamp,
    )
