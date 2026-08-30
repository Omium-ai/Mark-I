"""Gold-set freshness and rotation arithmetic (06 §5.1). WHY these windows exist:
verifier error laws drift with toolchain versions; a certificate tethered to last
quarter's ruff is a fictional certificate with a real signature."""

from dataclasses import dataclass
from datetime import datetime, timedelta

# D16: the freshness window — ≥ 50% of gold labels within the last 30 days (the ≥50%
# gate itself lives in certs/state_machine.py as FRESH_FRAC_GATE).
FRESH_WINDOW_DAYS = 30
# D17: a gold label older than 90 days leaves the scoring window entirely.
MAX_AGE_DAYS = 90


@dataclass(frozen=True)
class GoldLabel:
    task_digest: bytes
    true_label: str
    labeled_at: datetime


def scoring_window(members: list[GoldLabel], now: datetime) -> list[GoldLabel]:
    """The D17 filter: what a certificate is allowed to be measured on."""
    cutoff = now - timedelta(days=MAX_AGE_DAYS)
    return [m for m in members if m.labeled_at > cutoff]


def fresh_fraction(members: list[GoldLabel], now: datetime) -> float:
    """The D16 numerator: fraction of the scoring window labeled within 30 days.
    An empty window is 0.0 fresh — it cannot satisfy any freshness gate."""
    window = scoring_window(members, now)
    if not window:
        return 0.0
    cutoff = now - timedelta(days=FRESH_WINDOW_DAYS)
    return sum(1 for m in window if m.labeled_at > cutoff) / len(window)


def rotate_oldest_out(members: list[GoldLabel], max_size: int) -> list[GoldLabel]:
    """Oldest-out as new labels land, PRESERVING the stratification quotas (06 §5.1):
    capacity is allocated across true-label classes proportionally to their current
    mix (largest-remainder), then the newest labels win within each class — so
    rotation can never quietly drain one verdict class out of the set."""
    if max_size <= 0:
        raise ValueError("max_size must be positive")
    if len(members) <= max_size:
        return list(members)

    by_class: dict[str, list[GoldLabel]] = {}
    for m in members:
        by_class.setdefault(m.true_label, []).append(m)

    total = len(members)
    quotas = {c: (len(rows) * max_size) // total for c, rows in by_class.items()}
    remainders = sorted(
        by_class,
        key=lambda c: ((len(by_class[c]) * max_size) % total, c),
        reverse=True,
    )
    short = max_size - sum(quotas.values())
    for c in remainders[:short]:
        quotas[c] += 1

    kept: list[GoldLabel] = []
    for c, rows in by_class.items():
        rows.sort(key=lambda m: m.labeled_at, reverse=True)
        kept.extend(rows[: quotas[c]])
    kept.sort(key=lambda m: m.labeled_at, reverse=True)
    return kept
