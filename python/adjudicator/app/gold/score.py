"""Gold-set agreement scoring (06 §1.2 `gold_score` job's arithmetic): certified
verdicts joined to gold labels → the counts certs/compute.py turns into ρ₊/ρ₋.

Projection rules (06 §5.2): refused/error GOLD rows are held out of ρ entirely;
refused/error VERDICTS on scoreable gold leave the ρ denominators too (Paper II
Thm 6.1 defines ρ on covered instances) and are reported as abstention mass."""

from dataclasses import dataclass

_BINARY = frozenset({"satisfied", "violated"})


@dataclass(frozen=True)
class GoldScore:
    n_plus: int  # gold=satisfied, verdict covered (∈ {satisfied, violated})
    k_plus: int  # gold=satisfied, verdict=violated  → ρ₊ numerator
    n_minus: int  # gold=violated, verdict covered
    k_minus: int  # gold=violated, verdict=satisfied → ρ₋ numerator
    abstained: int  # scoreable gold whose verdict was refused/error
    held_out: int  # gold rows labeled refused/error — never in the projection
    gold_n: int  # total gold rows in the scoring window

    @property
    def abstention_mass(self) -> float | None:
        scoreable = self.n_plus + self.n_minus + self.abstained
        return self.abstained / scoreable if scoreable else None


def score_agreement(pairs: list[tuple[str, str]]) -> GoldScore:
    """pairs: (gold true_label, certified verdict) — both in the four-verdict
    vocabulary (m1_020's `verdict` enum)."""
    n_plus = k_plus = n_minus = k_minus = abstained = held_out = 0
    for gold, verdict in pairs:
        if gold not in _BINARY:
            held_out += 1
            continue
        if verdict not in _BINARY:
            abstained += 1
            continue
        if gold == "satisfied":
            n_plus += 1
            k_plus += verdict == "violated"
        else:
            n_minus += 1
            k_minus += verdict == "satisfied"
    return GoldScore(
        n_plus=n_plus,
        k_plus=k_plus,
        n_minus=n_minus,
        k_minus=k_minus,
        abstained=abstained,
        held_out=held_out,
        gold_n=len(pairs),
    )
