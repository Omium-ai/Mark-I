"""Coverage band + the guarantee floor (06 §8.2, §8.5; formula normative in 07 §MVs).
A TVO without its band is not an output type in this module — reports carry
(coverage_lower, coverage) on every number, and issuance below the floor is a refusal."""

from dataclasses import dataclass

# D23 (06 §8.5): the coverage floor for guarantee-grade issuance, applied to the band's
# LOWER edge — the shed-narrowed number, because a report never claims precision the
# capture layer didn't earn. A default (Dn), so a config change, never a code change.
COVERAGE_FLOOR = 0.95

# The wire refusal string, verbatim from 08 §3.3 — the refusal IS the message.
REFUSAL_COVERAGE_FLOOR = "M1E-5004 coverage below floor"


@dataclass(frozen=True)
class CoverageBand:
    coverage_lower: float
    coverage: float


class CoverageFloorRefusal(Exception):
    """M1E-5004 (08 §9 error table): guarantee-grade report below coverage floor.
    Refusal-by-design — the report still exists, labeled `indicative`; only the
    *guarantee* is refused (200 body / CLI exit 4)."""

    code = "M1E-5004"

    def __init__(self, band: CoverageBand, floor: float) -> None:
        self.band = band
        self.floor = floor
        super().__init__(
            f"{REFUSAL_COVERAGE_FLOOR}: coverage_lower={band.coverage_lower:.4f} < {floor}"
        )


def coverage_band(
    observed_ms: int,
    bypass_ms: int,
    disabled_ms: int,
    dropped_billing: int,
    events_billing_ingested: int,
) -> CoverageBand:
    """07 (normative): coverage = observed / (observed + bypass + disabled), lower edge
    narrowed by shed accounting: coverage × (1 − dropped / (dropped + ingested)).
    Zero surface time is zero coverage — there is deliberately no 'assumed covered'."""
    for name, x in (
        ("observed_ms", observed_ms),
        ("bypass_ms", bypass_ms),
        ("disabled_ms", disabled_ms),
        ("dropped_billing", dropped_billing),
        ("events_billing_ingested", events_billing_ingested),
    ):
        if x < 0:
            raise ValueError(f"{name}={x!r} must be >= 0")

    total_ms = observed_ms + bypass_ms + disabled_ms
    coverage = observed_ms / total_ms if total_ms else 0.0

    drop_denominator = dropped_billing + events_billing_ingested
    shed = dropped_billing / drop_denominator if drop_denominator else 0.0
    return CoverageBand(coverage_lower=coverage * (1.0 - shed), coverage=coverage)


def require_guarantee_grade(band: CoverageBand, floor: float = COVERAGE_FLOOR) -> None:
    """The refusal rule (06 §8.5, normative): coverage_lower < floor ⇒ M1E-5004 raised.
    Callers assembling reports catch this and downgrade to `indicative` — they never
    swallow it into a silently-issued guarantee."""
    if band.coverage_lower < floor:
        raise CoverageFloorRefusal(band, floor)
