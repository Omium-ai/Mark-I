"""The Chow abstention band (06 §3.1 step 4; Paper II Thm 5.1).

The band is `η ∈ (A/R, 1 − A/D)`: abstention strictly dominates every binary folding
whenever posterior mass lands inside it, regardless of the exact cost values. The
boundary inclusivity is the pseudocode's, verbatim: `η ≥ 1 − A/D ⇒ satisfied`,
`η ≤ A/R ⇒ violated`, open interval ⇒ refused."""

from dataclasses import dataclass

# D4 (DESIGN, bundle-overridable per tenant, 06 §3.1): A=1 (a refusal costs one human
# look), R=3 (a false rejection wastes a retry loop), D=9 (a false acceptance ships a
# bad outcome) — "shipping a wrong outcome is 3× worse than blocking a right one, which
# is 3× worse than asking a human". Band: (0.333…, 0.888…).
DEFAULT_COSTS = (1.0, 3.0, 9.0)  # (A, R, D)

# A decision region narrower than η's own resolution is decorative: η is fused from
# confusion rows specified at two-decimal granularity (the literature defaults;
# EPSILON_ANCHOR = 0.02), and even a D15-sized gold window (n = 200) yields Wilson CIs
# on ρ no tighter than ~0.02 — no distinction in η finer than 0.01 is ever a measured
# fact. So each of the three regions (violated ≤ A/R, the band, satisfied ≥ 1 − A/D)
# must be at least 0.01 wide: thinner, and it can only be hit by float luck, silently
# folding the three-verdict rule into the binary rule Thm 5.1 proves dominated —
# 4.4e-8-wide "never refuse" bands and A→0 "always refuse" bands alike.
MIN_REGION_WIDTH = 0.01


@dataclass(frozen=True)
class Costs:
    """Abstain / false-reject / false-accept costs — Paper II §5's (A, R, D)."""

    a: float = DEFAULT_COSTS[0]
    r: float = DEFAULT_COSTS[1]
    d: float = DEFAULT_COSTS[2]

    def __post_init__(self) -> None:
        # Chow's condition (Thm 5.1): the band is nonempty iff A < DR/(D+R). Costs
        # that empty the band would silently fold the three-verdict rule back into
        # the binary rule the theorem proves strictly dominated — refuse them here
        # rather than let a bundle misprice its way out of abstention.
        if not (self.a > 0 and self.r > 0 and self.d > 0):
            raise ValueError("Chow costs must be strictly positive")
        if self.a >= (self.d * self.r) / (self.d + self.r):
            raise ValueError(
                f"A={self.a} empties the Chow band (needs A < DR/(D+R) = "
                f"{(self.d * self.r) / (self.d + self.r):.4f}, Paper II Thm 5.1)"
            )
        lo, hi = self.band
        if min(lo, hi - lo, 1.0 - hi) < MIN_REGION_WIDTH:
            raise ValueError(
                f"degenerate Chow pricing: region widths (violated={lo:.3g}, "
                f"band={hi - lo:.3g}, satisfied={1.0 - hi:.3g}) — each must be "
                f"≥ {MIN_REGION_WIDTH} to be a real decision region (see MIN_REGION_WIDTH)"
            )

    @property
    def band(self) -> tuple[float, float]:
        """(reject threshold A/R, accept threshold 1 − A/D)."""
        return (self.a / self.r, 1.0 - self.a / self.d)


def chow_verdict(eta: float, costs: Costs) -> str:
    """06 §3.1 step 4, exactly: η is posterior[satisfied]."""
    lo, hi = costs.band
    if eta >= hi:
        return "satisfied"
    if eta <= lo:
        return "violated"
    return "refused"  # η ∈ (A/R, 1 − A/D) — the Chow band
