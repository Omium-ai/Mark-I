"""Report assembly (06 §8.2, §8.4, §8.5; wire shape 08 §3.3). Every number leaves with its
coverage band and its cost basis stamped; guarantee-grade is something a report *earns* —
any open refusal reason downgrades it to `indicative`, never to silence."""

from collections.abc import Sequence
from dataclasses import dataclass, field

from app.tvo.coverage import (
    COVERAGE_FLOOR,
    CoverageBand,
    CoverageFloorRefusal,
    require_guarantee_grade,
)
from app.tvo.engine import TvoResult
from app.tvo.waste import WasteTriple

# The two bases (06 §8.4, C1.9): a report is computed under exactly one, never mixed.
COST_BASIS_USD = "usd"
COST_BASIS_QUOTA = "quota"
_BASES = frozenset({COST_BASIS_USD, COST_BASIS_QUOTA})

# D22 (06 §8.4): the wall-clock shadow price default — EXPLICITLY a placeholder the tenant
# must confirm before guarantee-grade issuance; an unconfirmed S is a refusal reason.
DEFAULT_SHADOW_PRICE_USD = 200.0

GRADE_GUARANTEE = "guarantee-grade"
GRADE_INDICATIVE = "indicative"


@dataclass(frozen=True)
class ModelPrice:
    """One pinned row of the versioned model_prices table (06 §8.4) — a report records
    which price-table version it used, so a re-issue under new prices is a new claim."""

    price_table_version: str
    price_in: float
    price_out: float
    price_cache_creation: float
    price_cache_read: float


def usd_cost(
    input_tokens: int,
    output_tokens: int,
    cache_creation_tokens: int,
    cache_read_tokens: int,
    price: ModelPrice,
    verifier_spend_usd: float = 0.0,
) -> float:
    """06 §8.4 usd basis: token classes priced at the pinned row, PLUS verifier spend v —
    a verifier that is not in the bill is a verifier whose break-even nobody can audit."""
    return (
        input_tokens * price.price_in
        + output_tokens * price.price_out
        + cache_creation_tokens * price.price_cache_creation
        + cache_read_tokens * price.price_cache_read
        + verifier_spend_usd
    )


def quota_cost(
    tokens_consumed: int,
    window_limit_tokens: int,
    shadow_price_usd: float = DEFAULT_SHADOW_PRICE_USD,
) -> float:
    """06 §8.4 quota basis: (tokens / window_limit) × S. window_limit is fitted from
    transcript-observed rate-limit events — the only honest source — so a zero/absent
    limit is unmeasurable, not free: refuse rather than divide by fiction."""
    if window_limit_tokens <= 0:
        raise ValueError("window_limit_tokens must be > 0 — unfitted window limit, not free tokens")
    if shadow_price_usd < 0:
        raise ValueError("shadow price S must be >= 0")
    return (tokens_consumed / window_limit_tokens) * shadow_price_usd


@dataclass(frozen=True)
class TvoReport:
    """The assembled artifact. There is deliberately no band-less or basis-less constructor
    (06 §8.2): a TVO without (coverage_lower, coverage) and a stamped basis is not an
    output type in this module."""

    tvo: float
    break_even_v: float
    waste: WasteTriple
    coverage_band: CoverageBand
    coverage_floor: float
    cost_basis: str
    task_seg_version: str
    cert_status: str
    grade: str
    guarantee_grade: bool
    refusals: tuple[str, ...] = ()
    input_provenance: dict[str, str] = field(default_factory=dict)
    price_table_version: str | None = None  # pinned when basis is usd
    shadow_price_usd: float | None = None  # stamped when basis is quota

    def __post_init__(self) -> None:
        # 06 §8.4 (C1.9): a report is computed under exactly ONE basis, never mixed —
        # so a field belonging to the OTHER basis is a constructor error, not a stray
        # to ignore: a quota report carrying a price-table pin (or a usd report
        # carrying a shadow price) would claim provenance its arithmetic never used.
        if self.cost_basis == COST_BASIS_USD and self.shadow_price_usd is not None:
            raise ValueError("usd-basis report must not carry shadow_price_usd (06 §8.4)")
        if self.cost_basis == COST_BASIS_QUOTA and self.price_table_version is not None:
            raise ValueError("quota-basis report must not carry price_table_version (06 §8.4)")

    def to_body(self) -> dict:
        """The 08 §3.3 response body shape (also what lands in tvo_reports.body)."""
        body: dict = {
            "tvo": self.tvo,
            "coverage_band": {
                "observed_fraction": self.coverage_band.coverage,
                "coverage_lower": self.coverage_band.coverage_lower,
                "floor": self.coverage_floor,
            },
            "cost_basis": self.cost_basis,
            "task_seg_version": self.task_seg_version,
            "waste": {
                "retry_loop_tokens": self.waste.retry_loop_tokens,
                "re_exploration_tokens": self.waste.reexploration_tokens,
                "over_model_tokens": self.waste.over_model_tokens,
            },
            "guarantee_grade": self.guarantee_grade,
            "grade": self.grade,
            "cert_status": self.cert_status,
            "input_provenance": self.input_provenance,
        }
        if self.refusals:
            # 08 §3.3: the number still renders, the guarantee is refused — refused
            # outright, not footnoted.
            body["refusal"] = "; ".join(self.refusals)
        return body


def assemble_report(
    result: TvoResult,
    waste: WasteTriple,
    band: CoverageBand,
    *,
    cost_basis: str,
    task_seg_version: str,
    coverage_floor: float = COVERAGE_FLOOR,
    price: ModelPrice | None = None,
    shadow_price_usd: float | None = None,
    shadow_price_confirmed: bool = False,
    task_seg_versions_in_window: Sequence[str] | None = None,
    both_series_shown: bool = False,
) -> TvoReport:
    """06 §8.5's refusal rule, in full. Guarantee-grade iff ALL of: coverage_lower ≥ floor
    (D23, else M1E-5004), certificate `certified` (§5.4 consumer row), resolved cost
    basis (quota needs a tenant-confirmed S; usd needs a pinned model_prices row, 06 §8.4),
    and no task_seg_version boundary crossing the window without both series shown.
    Each refusal is stated on the report."""
    if cost_basis not in _BASES:
        raise ValueError(f"cost_basis={cost_basis!r} not in {sorted(_BASES)} — never mixed")

    refusals: list[str] = []

    try:
        require_guarantee_grade(band, coverage_floor)
    except CoverageFloorRefusal as exc:
        refusals.append(str(exc))

    if result.cert_status != "certified":
        # §5.4: the status string itself appears on the report — `indicative`, never
        # a guarantee built on uncertified labels.
        refusals.append(f"noise certificate is '{result.cert_status}', not 'certified'")

    # Basis resolution is SYMMETRIC (06 §8.4): quota needs a tenant-confirmed S (D22),
    # and usd needs a pinned model_prices row — §8.4's "a report pins the price-table
    # version it used" is unsatisfiable with no row, so issuing guarantee-grade without
    # one would claim a provenance the report cannot state. Missing ⇒ indicative.
    if cost_basis == COST_BASIS_QUOTA and not shadow_price_confirmed:
        refusals.append("cost basis unresolved: shadow price S unconfirmed by tenant (D22)")
    if cost_basis == COST_BASIS_USD and price is None:
        refusals.append("cost basis unresolved: no pinned model_prices row for usd (06 §8.4)")

    versions = list(task_seg_versions_in_window or [task_seg_version])
    if len(set(versions)) > 1 and not both_series_shown:
        refusals.append("task_seg_version boundary crosses the window without both series shown")

    guarantee = not refusals
    return TvoReport(
        tvo=result.tvo,
        break_even_v=result.break_even_v,
        waste=waste,
        coverage_band=band,
        coverage_floor=coverage_floor,
        cost_basis=cost_basis,
        task_seg_version=task_seg_version,
        cert_status=result.cert_status,
        grade=GRADE_GUARANTEE if guarantee else GRADE_INDICATIVE,
        guarantee_grade=guarantee,
        refusals=tuple(refusals),
        input_provenance=dict(result.inputs.provenance),
        # Basis-owned fields only (06 §8.4, enforced by __post_init__): a price row
        # handed alongside a quota report is never stamped, and vice versa.
        price_table_version=(
            price.price_table_version if cost_basis == COST_BASIS_USD and price else None
        ),
        shadow_price_usd=(
            (shadow_price_usd if shadow_price_usd is not None else DEFAULT_SHADOW_PRICE_USD)
            if cost_basis == COST_BASIS_QUOTA
            else None
        ),
    )
