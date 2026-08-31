#!/usr/bin/env python3
"""Generator for the fusion conformance family (house rule: vectors are generated
ONCE, by a reference that is neither of the implementations under test).

There is no Rust twin of ADJUDICATE, so the reference here is arithmetic rather than
a third codebase: every expected posterior is derived in EXACT RATIONAL arithmetic
(fractions.Fraction over the parsed float64 inputs — no logs, no exp, no floating
addition), then rounded once to float64 at the end. Under D-AK both implementations
compute the same quantity by direct multiplication and exact power-of-two rescaling,
so they agree with each other bit for bit and sit a few ulps from this value;
README.md fixes the tolerance.

Run: python3 conformance/vectors/fusion/gen_fusion_vectors.py
Regeneration must be byte-stable. If it is not, that is a finding against this
generator, never a licence to re-freeze the family.
"""

import hashlib
import json
from fractions import Fraction
from pathlib import Path

HERE = Path(__file__).resolve().parent

_S, _V, _R, _E = 0, 1, 2, 3
COL = {"satisfied": 0, "violated": 1, "refused": 2, "error": None}  # None ⇒ infra
CLASSES = ("satisfied", "violated", "refused", "error")
# D-AG. anchor_reject_clamp had to INVENT the reject columns 06 §3.2 declines to print,
# and nothing on disk distinguished those invented numbers from the columns the doc does
# print — so a figure laundered from an agent's guess read exactly like a verified one.
# Every vector now declares which of its consumed inputs are printed and which are ours.
# The declaration lives in the manifest, never in the vector payload, so freezing it moved
# no vector's bytes; `bit_identical_to` is the precedent.
PROVENANCE_CLASSES = ("doc-derived", "mixed", "fixture-local")
# D4 (06 §3.1): A = 1, R = 3, D = 9. The edge hardcodes these, so the family cannot
# carry per-vector costs — a vector that needed other costs would be undrivable there.
COST_A, COST_R, COST_D = Fraction(1), Fraction(3), Fraction(9)
THETA_ERROR = Fraction(1, 2)  # D3
INFRA_DOMINANT_FRAC = Fraction(1, 2)


def row(a: float, r: float, b: float) -> list[float]:
    return [a, r, b]


def conf(s: list[float], v: list[float], r: list[float], e: list[float]) -> list[list[float]]:
    return [s, v, r, e]


def verifier(
    kind: str, group: str, confusion: list[list[float]], quarantined: bool = False
) -> dict:
    spec = {"kind": kind, "group": group, "confusion": confusion}
    # 07's `quarantine` list. The key is emitted only when set, so freezing it changes
    # no existing vector's bytes; a driver must drop the row exactly as it drops an
    # unlisted one (frombundle.go), which is what makes D-AB testable here.
    if quarantined:
        spec["quarantined"] = True
    return spec


def votes(*items: tuple) -> list[dict]:
    out = []
    for it in items:
        vid, verdict = it[0], it[1]
        out.append({"verifier_id": vid, "verdict": verdict, "tamper": bool(it[2:] and it[2])})
    return out


PRIORS = [0.55, 0.30, 0.10, 0.05]

# 06 §3.2's three verifiers, verbatim where the doc prints a column: cargo's accept
# column 0.98/0.60/0.50/0.50, the judge's reject column 0.15/0.70/0.40/0.40, ruff's
# symmetric 0.70 abstention. Columns the doc never prints are filled to make every
# row a proper distribution — they cannot affect this example's arithmetic.
CARGO = verifier(
    "compile",
    "syntactic",
    conf(row(0.98, 0.02, 0.00), row(0.60, 0.40, 0.00), row(0.50, 0.02, 0.48), row(0.50, 0.02, 0.48)),
)
RUFF = verifier(
    "lint",
    "syntactic",
    conf(row(0.20, 0.10, 0.70), row(0.20, 0.10, 0.70), row(0.20, 0.10, 0.70), row(0.20, 0.10, 0.70)),
)
JUDGE = verifier(
    "judge",
    "judges",
    conf(row(0.80, 0.15, 0.05), row(0.25, 0.70, 0.05), row(0.20, 0.40, 0.40), row(0.20, 0.40, 0.40)),
)

# The D-V probe's bundle: an anchor that reports and a slow judge that does not (yet).
# Its abstain column is deliberately asymmetric (0.05/0.05/0.60/0.60) so synthesising
# it for a member that never voted is measurable — and it measured VIOLATED.
PROBE_ANCHOR = verifier(
    "compile",
    "syntactic",
    conf(row(0.90, 0.02, 0.08), row(0.55, 0.40, 0.05), row(0.46, 0.04, 0.50), row(0.46, 0.04, 0.50)),
)
PROBE_JUDGE = verifier(
    "judge",
    "judges",
    conf(row(0.85, 0.10, 0.05), row(0.25, 0.70, 0.05), row(0.20, 0.20, 0.60), row(0.20, 0.20, 0.60)),
)

# Equal accept likelihood ratios (0.80/0.40 = 2), differing refused/error rows: which
# member the clique collapses to is visible in the posterior.
TIE_LOW = verifier(
    "lint",
    "syntactic",
    conf(row(0.80, 0.10, 0.10), row(0.40, 0.50, 0.10), row(0.20, 0.40, 0.40), row(0.20, 0.40, 0.40)),
)
TIE_HIGH = verifier(
    "lint",
    "syntactic",
    conf(row(0.80, 0.10, 0.10), row(0.40, 0.50, 0.10), row(0.60, 0.20, 0.20), row(0.60, 0.20, 0.20)),
)
# Equal P(reject | satisfied) = 0.10, differing elsewhere.
RTIE_LOW = verifier(
    "lint",
    "syntactic",
    conf(row(0.80, 0.10, 0.10), row(0.30, 0.60, 0.10), row(0.20, 0.40, 0.40), row(0.20, 0.40, 0.40)),
)
RTIE_HIGH = verifier(
    "lint",
    "syntactic",
    conf(row(0.80, 0.10, 0.10), row(0.30, 0.60, 0.10), row(0.40, 0.10, 0.50), row(0.40, 0.10, 0.50)),
)
# Identical accept/reject columns, differing ABSTAIN columns: only the all-abstain
# branch's tie-break can be read off the result.
ATIE_LOW = verifier(
    "judge",
    "judges",
    conf(row(0.50, 0.30, 0.20), row(0.30, 0.50, 0.20), row(0.30, 0.30, 0.40), row(0.30, 0.30, 0.40)),
)
ATIE_HIGH = verifier(
    "judge",
    "judges",
    conf(row(0.50, 0.30, 0.20), row(0.30, 0.50, 0.20), row(0.10, 0.20, 0.70), row(0.10, 0.20, 0.70)),
)
# 07's quarantine list, expressed in the vector schema: listed, distrusted, dropped.
DISTRUSTED_JUDGE = verifier(
    "judge",
    "judges",
    conf(row(0.85, 0.10, 0.05), row(0.25, 0.70, 0.05), row(0.20, 0.20, 0.60), row(0.20, 0.20, 0.60)),
    quarantined=True,
)
# Priors (0.4, 0.4, 0.1, 0.1) times this accept column give posterior[satisfied]
# EXACTLY 1/3 = A/R in rational arithmetic — the lower Chow boundary, reachable.
BOUNDARY = verifier(
    "judge",
    "judges",
    conf(row(0.04, 0.48, 0.48), row(0.05, 0.47, 0.48), row(0.06, 0.47, 0.47), row(0.06, 0.47, 0.47)),
)
# Uninformative on every class (the accept column is flat), so it multiplies the whole
# mass vector by one constant and moves eta not at all — while forcing a SECOND clique
# through the fusion loop, and with it the power-of-two rescale (D-AK step 2).
FLAT = verifier(
    "rm", "rms", conf(*[row(0.50, 0.25, 0.25)] * 4)
)
# Priors (0.5, 0.25, 0.125, 0.125) times this accept column give posterior[satisfied]
# EXACTLY 8/9 = 1 - A/D: the UPPER Chow boundary, which no vector reached. Every factor
# here is a power of two times the same float, so the float fusion is exact and lands
# on the rational referee's answer rather than near it.
BOUNDARY_HIGH = verifier(
    "judge",
    "judges",
    conf(row(0.40, 0.30, 0.30), row(0.05, 0.45, 0.50), row(0.05, 0.45, 0.50), row(0.05, 0.45, 0.50)),
)

# ---------------------------------------------------------------------------
# The two constructions D-AC's withdrawn 1e-12 quantisation straddled. Each has an
# EXACT eta of the form (n + 1/2)/1e12 adjacent to a Chow threshold, so
# `floor(eta*1e12 + 0.5)` sits precisely on its own tipping point: the frozen value
# rounds one way and the value ONE ULP BELOW it rounds the other, across the threshold,
# flipping the verdict. That is the defect the whole family failed to see — 8 of 27
# such constructions flipped between Go and CPython while all 21 vectors stayed green,
# because every one of them sat comfortably off the grid.
#
# The mantissas (2**-41 / 2**-42 scalings of integers below 2**53) are chosen so every
# product in the fusion is exact; nothing here depends on a lucky rounding.
# ---------------------------------------------------------------------------
GRID_PRIORS = [0.25, 0.5, 0.125, 0.125]
# eta = 666666666667/2e12 = 0.3333333333335 exactly; eta*1e12 = 333333333333.5.
_HALF_LO_S, _HALF_LO_V = 1333333333334 * 2.0**-41, 1333333333333 * 2.0**-41
GRID_HALF_ABOVE_LO = verifier(
    "judge",
    "judges",
    conf(
        row(_HALF_LO_S, 0.0, 1.0 - _HALF_LO_S),
        row(_HALF_LO_V, 0.0, 1.0 - _HALF_LO_V),
        row(0.0, 0.5, 0.5),
        row(0.0, 0.5, 0.5),
    ),
)
# eta = 1777777777777/2e12 = 0.8888888888885 exactly; eta*1e12 = 888888888888.5.
_HALF_HI_S, _HALF_HI_V = 1777777777777 * 2.0**-41, 222222222223 * 2.0**-42
GRID_HALF_BELOW_HI = verifier(
    "judge",
    "judges",
    conf(
        row(_HALF_HI_S, 0.0, 1.0 - _HALF_HI_S),
        row(_HALF_HI_V, 0.0, 1.0 - _HALF_HI_V),
        row(0.0, 0.5, 0.5),
        row(0.0, 0.5, 0.5),
    ),
)
SOLO_ANCHOR = verifier(
    "compile",
    "syntactic",
    conf(row(0.90, 0.05, 0.05), row(0.40, 0.55, 0.05), row(0.30, 0.20, 0.50), row(0.30, 0.20, 0.50)),
)

# Four independent cliques whose per-class accept columns make the product
# order-sensitive: multiplied in a different order, the posterior moves in its last bits.
ORDER_COLS = [
    (0.34, 0.19, 0.64, 0.12),
    (0.53, 0.38, 0.10, 0.51),
    (0.08, 0.44, 0.11, 0.13),
    (0.43, 0.79, 0.16, 0.25),
]
ORDER_VERIFIERS = {
    f"g{i}": verifier(
        "lint",
        f"g{i}",
        conf(*[row(a, round((1 - a) * 0.4, 4), round((1 - a) * 0.6, 4)) for a in col]),
    )
    for i, col in enumerate(ORDER_COLS)
}

TINY = 1e-300
EXTREME = {
    f"x{i}": verifier(
        "lint",
        f"x{i}",
        conf(
            row(TINY * (i + 1), 0.5, 0.5),
            row(TINY * (i + 2), 0.5, 0.5),
            row(TINY * (i + 3), 0.5, 0.5),
            row(TINY * (i + 4), 0.5, 0.5),
        ),
    )
    for i in range(4)
}

VECTORS: list[dict] = [
    {
        "name": "worked_example_06_32",
        "provenance": ("doc-derived", "pi, cargo's accept column, ruff's abstain column and the judge's reject column are each printed in 06 3.2's table; this vector consumes no other column."),
        "doc": "06 §3.2 verbatim: compile accepts, ruff abstains (same clique, collapsed away), judge rejects ⇒ refused inside the Chow band by 0.008.",
        "priors": PRIORS,
        "verifiers": {"cargo-check-warm": CARGO, "ruff": RUFF, "judge:grounded-rubric": JUDGE},
        "votes": votes(
            ("cargo-check-warm", "satisfied"),
            ("ruff", "refused"),
            ("judge:grounded-rubric", "violated"),
        ),
    },
    {
        "name": "anchor_reject_clamp",
        "provenance": ("mixed", "pi and the judge's reject column are printed. The cargo REJECT column this vector's verdict turns on is NOT: only reject|S = 0.02 appears, in 3.2 counterfactual (a)'s prose. reject|V/R/E are fixture-local, and D-AG withdrew the doc's point figure for precisely that reason."),
        "doc": "06 §3.2 counterfactual (a): the anchor's ε_anchor reject column collapses the satisfied mass through the ordinary product — no special-case branch.",
        "priors": PRIORS,
        "verifiers": {"cargo-check-warm": CARGO, "ruff": RUFF, "judge:grounded-rubric": JUDGE},
        "votes": votes(
            ("cargo-check-warm", "violated"),
            ("ruff", "refused"),
            ("judge:grounded-rubric", "violated"),
        ),
    },
    {
        "name": "absent_member",
        "provenance": ("fixture-local", "PROBE_ANCHOR/PROBE_JUDGE are constructed here, with a deliberately asymmetric abstain column so synthesising it for a silent member is measurable. No documentary basis."),
        "doc": "D-V: the anchor accepts, the slow judge has not reported. Absence consumes NOTHING. Synthesising its abstain column drove η to 0.3327 ≤ A/R and blocked a developer on evidence nobody gathered.",
        "priors": PRIORS,
        "verifiers": {"anchor": PROBE_ANCHOR, "slow-judge": PROBE_JUDGE},
        "votes": votes(("anchor", "satisfied")),
    },
    {
        "name": "absent_member_explicit_abstain",
        "provenance": ("fixture-local", "Same constructed PROBE_* bundle as absent_member; it is the pair that carries the meaning."),
        "doc": "The other half of D-V: the same member VOTING abstain consumes the abstain column. Its posterior must differ from absent_member's — abstain is information, absence is not.",
        "priors": PRIORS,
        "verifiers": {"anchor": PROBE_ANCHOR, "slow-judge": PROBE_JUDGE},
        "votes": votes(("anchor", "satisfied"), ("slow-judge", "refused")),
    },
    {
        "name": "tampered_vote_excluded",
        "provenance": ("fixture-local", "Same constructed PROBE_* bundle; the tamper flag is a fixture input, not a doc figure."),
        "doc": "Thm 5.2 + D-V: a tampered vote never enters the likelihood and is NOT replaced by an abstain — the posterior equals the untampered member's alone.",
        "priors": PRIORS,
        "verifiers": {"anchor": PROBE_ANCHOR, "slow-judge": PROBE_JUDGE},
        "votes": votes(("anchor", "satisfied"), ("slow-judge", "violated", True)),
    },
    {
        "name": "unknown_voter",
        "provenance": ("doc-derived", "pi, cargo's accept column and the judge's reject column are printed; both strangers are unlisted, so no unprinted column is consumed."),
        "doc": "D-X: a voter the bundle does not list contributes no likelihood — no per-kind default — and is COUNTED (unknown_voters = 1), never silently dropped. The unlisted INFRA vote is not counted there: unknown_voters counts votes that would otherwise have carried a likelihood, and an infra failure never does.",
        "priors": PRIORS,
        "verifiers": {"cargo-check-warm": CARGO, "judge:grounded-rubric": JUDGE},
        "votes": votes(
            ("cargo-check-warm", "satisfied"),
            ("judge:grounded-rubric", "violated"),
            ("mystery-linter", "violated"),
            ("mystery-sandbox", "error"),
        ),
    },
    {
        "name": "unlisted_voter_no_coverage",
        "provenance": ("fixture-local", "Constructed PROBE_ANCHOR; the stranger is unlisted and contributes nothing."),
        "doc": "D-AB: the only LISTED verifier abstains, so D1 is unmet and the honest answer is the degenerate refused. The unlisted stranger's reject contributes no likelihood term at all — counted as coverage it flipped this same input to a BLOCK whose posterior was priors x the abstainer's column, unchanged. Membership gates coverage, not only likelihood.",
        "priors": PRIORS,
        "verifiers": {"anchor": PROBE_ANCHOR},
        "votes": votes(("anchor", "refused"), ("mystery-judge", "violated")),
    },
    {
        "name": "quarantined_voter_no_coverage",
        "provenance": ("fixture-local", "Constructed PROBE_ANCHOR plus a judge invented to exercise 07's quarantine list."),
        "doc": "D-AB, the other half: a verifier the bundle LISTS and quarantines (07) is dropped exactly as an unlisted one is, so an explicitly distrusted verifier cannot unlock a block either. Same shape as unlisted_voter_no_coverage, and it must land on the same answer.",
        "priors": PRIORS,
        "verifiers": {"anchor": PROBE_ANCHOR, "distrusted-judge": DISTRUSTED_JUDGE},
        "votes": votes(("anchor", "refused"), ("distrusted-judge", "violated")),
    },
    {
        "name": "chow_boundary_eta_exactly_a_over_r",
        "provenance": ("fixture-local", "Priors and confusion row solved backwards so eta lands EXACTLY on A/R. The doc prints no such construction; the boundary is the algebra's, not the document's."),
        "doc": "D-AK: posterior[satisfied] is EXACTLY A/R = 1/3, so the rule (eta <= A/R => violated) says violated. Through logsumexp a leg landed within one ulp of 1/3 and which side it landed on was its libm's business, not the rule's - that is how Go and CPython were measured flipping each other's verdict. With the transcendentals gone the fusion is exact IEEE-754 arithmetic and the Chow branch is cross-multiplied (u_S*R <= A*total), so both legs decide this by the rule.",
        "priors": [0.4, 0.4, 0.1, 0.1],
        "verifiers": {"boundary": BOUNDARY},
        "votes": votes(("boundary", "satisfied")),
    },
    {
        "name": "chow_boundary_a_over_r_two_cliques",
        "provenance": ("fixture-local", "Same solved-backwards boundary, plus a flat uninformative clique invented to force the power-of-two rescale to run mid-fusion."),
        "doc": "The same exact eta = A/R = 1/3, reached through TWO cliques instead of one: the second is uninformative (a flat accept column), so it scales the whole mass vector by one constant and moves eta not at all, while forcing the fusion loop's power-of-two rescale to run between the boundary verifier and the answer. A rescale that touched a mantissa bit, or a group order that was not sorted, moves this off the boundary and flips the verdict.",
        "priors": [0.4, 0.4, 0.1, 0.1],
        "verifiers": {"boundary": BOUNDARY, "flat": FLAT},
        "votes": votes(("boundary", "satisfied"), ("flat", "satisfied")),
    },
    {
        "name": "chow_boundary_eta_exactly_one_minus_a_over_d",
        "provenance": ("fixture-local", "Solved backwards so eta lands EXACTLY on 1 - A/D. Fixture-local by construction."),
        "doc": "The OTHER Chow boundary, which no vector reached: posterior[satisfied] is EXACTLY 1 - A/D = 8/9, so the rule (eta >= 1 - A/D => satisfied) says satisfied. Cross-multiplied this is u_S*D >= (D-A)*total, which is also why the comparison must not be written against the float `1 - A/D`: A/D = 1/9 is not representable, so that subtraction put a second rounding on the threshold itself.",
        "priors": [0.5, 0.25, 0.125, 0.125],
        "verifiers": {"boundary-high": BOUNDARY_HIGH},
        "votes": votes(("boundary-high", "satisfied")),
    },
    {
        "name": "chow_grid_half_point_above_a_over_r",
        "provenance": ("fixture-local", "Solved so eta*1e12 is exactly ...333.5 -- a half-point of D-AC's withdrawn quantiser. Nothing in any doc names this grid."),
        "doc": "A construction D-AC's withdrawn quantisation straddled: exact eta = 0.3333333333335, so eta*1e12 is exactly 333333333333.5. floor(eta*1e12 + 0.5) is therefore 333333333334 => 0.333333333334 > A/R => refused, while the value ONE ULP BELOW rounds to 333333333333 => 0.333333333333 <= A/R => violated. One ulp of libm disagreement, one flipped verdict, and the frozen family could not see it because all 21 vectors sat off the grid. The rule's own answer is refused (eta > A/R), and with no transcendental left both legs compute the same eta.",
        "priors": GRID_PRIORS,
        "verifiers": {"grid": GRID_HALF_ABOVE_LO},
        "votes": votes(("grid", "satisfied")),
    },
    {
        "name": "chow_grid_half_point_below_one_minus_a_over_d",
        "provenance": ("fixture-local", "The same solved half-point at the upper threshold."),
        "doc": "The same straddle at the upper threshold: exact eta = 0.8888888888885, eta*1e12 exactly 888888888888.5. Quantised it becomes 0.888888888889 >= 1 - A/D => satisfied; one ulp lower it becomes 0.888888888888 => refused. The rule's own answer is refused (eta < 8/9) - so D-AC's rounding did not merely relocate the straddle set, on this construction it shipped the WRONG side of the band under both legs when they happened to agree.",
        "priors": GRID_PRIORS,
        "verifiers": {"grid": GRID_HALF_BELOW_HI},
        "votes": votes(("grid", "satisfied")),
    },
    {
        "name": "accept_tie_smallest_id",
        "provenance": ("fixture-local", "Two rows built with equal accept likelihood ratios and differing elsewhere, so D-W's tie-break is visible in the posterior."),
        "doc": "D-W, accept branch: two accepters in one clique with equal accept LR. Ties resolve to the LEXICALLY SMALLEST id (aaa), where max() would pick zzz.",
        "priors": PRIORS,
        "verifiers": {"aaa": TIE_LOW, "zzz": TIE_HIGH},
        "votes": votes(("zzz", "satisfied"), ("aaa", "satisfied")),
    },
    {
        "name": "reject_tie_smallest_id",
        "provenance": ("fixture-local", "Rows built with equal P(reject|satisfied) for the reject branch of D-W."),
        "doc": "D-W, reject branch: equal P(reject|satisfied) ⇒ smallest id.",
        "priors": PRIORS,
        "verifiers": {"aaa": RTIE_LOW, "zzz": RTIE_HIGH},
        "votes": votes(("zzz", "violated"), ("aaa", "violated")),
    },
    {
        "name": "all_abstain_tie_smallest_id",
        "provenance": ("fixture-local", "Rows built with equal abstain columns, plus a solo anchor invented to supply the D1 coverage."),
        "doc": "D-W, all-abstain branch: a clique where every member abstained collapses to the smallest id; a second clique supplies the D1 coverage.",
        "priors": PRIORS,
        "verifiers": {"aaa": ATIE_LOW, "zzz": ATIE_HIGH, "anchor": SOLO_ANCHOR},
        "votes": votes(("zzz", "refused"), ("aaa", "refused"), ("anchor", "satisfied")),
    },
    {
        "name": "group_even_split",
        "provenance": ("mixed", "pi is printed, but this vector consumes cargo's REJECT column and ruff's ACCEPT column, and 06 3.2 prints neither -- it prints cargo's accept column and ruff's abstain column."),
        "doc": "One accept and one reject inside one clique: any reject wins the collapse (the anchor's perfect-precision clamp is never averaged with a soft member).",
        "priors": PRIORS,
        "verifiers": {"cargo-check-warm": CARGO, "ruff": RUFF},
        "votes": votes(("cargo-check-warm", "violated"), ("ruff", "satisfied")),
    },
    {
        "name": "zero_likelihood_veto",
        "provenance": ("fixture-local", "Inline verifier carrying an exact 0.00 entry; the veto is the fixture's point."),
        "doc": "An exact 0.0 is a legal veto, never softened to an epsilon: the class it zeroes gets exactly 0 posterior mass and the others renormalize.",
        "priors": PRIORS,
        "verifiers": {
            "veto": verifier(
                "compile",
                "syntactic",
                conf(
                    row(0.98, 0.00, 0.02),
                    row(0.60, 0.40, 0.00),
                    row(0.50, 0.05, 0.45),
                    row(0.50, 0.05, 0.45),
                ),
            )
        },
        "votes": votes(("veto", "violated")),
    },
    {
        "name": "negative_likelihood",
        "provenance": ("fixture-local", "Inline verifier carrying a deliberately malformed -0.5 entry."),
        "doc": "A malformed row (-0.5) contributes ZERO MASS, never a NaN: anything not strictly positive zeroes its class outright. NaN posteriors sail through every downstream comparison and reach the wire.",
        "priors": PRIORS,
        "verifiers": {
            "broken": verifier(
                "judge",
                "judges",
                conf(
                    row(0.80, 0.15, 0.05),
                    row(0.25, 0.70, 0.05),
                    row(0.20, -0.50, 0.40),
                    row(0.20, 0.40, 0.40),
                ),
            )
        },
        "votes": votes(("broken", "violated")),
    },
    {
        "name": "extreme_log_scores",
        "provenance": ("fixture-local", "Four cliques with 1e-300 rows, constructed to drive the mass through the smallest subnormal."),
        "doc": "Four cliques with 1e-300 likelihoods. Direct multiplication drives the mass straight through the smallest subnormal to zero, which is what log-space was actually protecting: the fusion loop buys it back by rescaling the mass vector by an exact POWER OF TWO, which shifts the exponent, touches no mantissa bit and cancels in the normalisation. The posterior must still be a distribution - unrescaled this vector reads as a broken bundle.",
        "priors": PRIORS,
        "verifiers": EXTREME,
        "votes": votes(*[(f"x{i}", "satisfied") for i in range(4)]),
    },
    {
        "name": "multi_group_sorted",
        "provenance": ("fixture-local", "Four invented order-sensitive cliques."),
        "doc": "Four independent cliques whose product is order-sensitive; votes arrive in sorted id order.",
        "priors": PRIORS,
        "verifiers": ORDER_VERIFIERS,
        "votes": votes(*[(f"g{i}", "satisfied") for i in range(4)]),
    },
    {
        "name": "group_order_permuted",
        "provenance": ("fixture-local", "The same four invented cliques, vote order shuffled."),
        "doc": "The SAME cliques, votes shuffled. Groups are multiplied in sorted group-id order, so the result must be BIT-IDENTICAL to multi_group_sorted — map/insertion order made it differ in the last bits, which flips a verdict sitting on a Chow threshold.",
        "priors": PRIORS,
        "verifiers": ORDER_VERIFIERS,
        "votes": votes(*[(f"g{i}", "satisfied") for i in (3, 1, 2, 0)]),
        "bit_identical_to": "multi_group_sorted",
    },
    {
        "name": "insufficient_evidence_all_abstain",
        "provenance": ("mixed", "pi and ruff's abstain column are printed; the judge's ABSTAIN column consumed here is not -- 06 3.2 prints only the judge's reject column."),
        "doc": "D1 step 0: no non-abstaining verifier ⇒ degenerate refused, and nothing was fused.",
        "priors": PRIORS,
        "verifiers": {"ruff": RUFF, "judge:grounded-rubric": JUDGE},
        "votes": votes(("ruff", "refused"), ("judge:grounded-rubric", "refused")),
    },
    {
        "name": "infra_dominant_error",
        "provenance": ("doc-derived", "pi and cargo's accept column are printed; the two infra votes consume no confusion column at all (COL['error'] is None), so no unprinted figure enters."),
        "doc": "Step 3: more than half the surviving votes are infra failures ⇒ error, whatever the posterior says. An outage is never a coverage claim.",
        "priors": PRIORS,
        "verifiers": {"cargo-check-warm": CARGO, "ruff": RUFF, "judge:grounded-rubric": JUDGE},
        "votes": votes(
            ("cargo-check-warm", "satisfied"),
            ("ruff", "error"),
            ("judge:grounded-rubric", "error"),
        ),
    },
    {
        "name": "zero_mass_inconsistent_bundle",
        "provenance": ("fixture-local", "Degenerate priors [1,0,0,0] and an inline vetoing verifier -- a broken bundle built on purpose."),
        "doc": "Every class assigned probability 0 by the votes: a broken bundle, not a verdict. Both implementations must REFUSE (see README — the cloud raises, the edge has no way to and answers latent error).",
        "priors": [1.0, 0.0, 0.0, 0.0],
        "verifiers": {
            "veto": verifier(
                "compile",
                "syntactic",
                conf(
                    row(0.98, 0.00, 0.02),
                    row(0.60, 0.40, 0.00),
                    row(0.50, 0.05, 0.45),
                    row(0.50, 0.05, 0.45),
                ),
            )
        },
        "votes": votes(("veto", "violated")),
    },
]


def _collapse(members: list[tuple[str, dict, int]]) -> tuple[str, dict, int]:
    """One observation per clique (06 §3.1 step 2). D-W: every branch ties to the
    lexically smallest verifier id."""
    rejects = [m for m in members if m[2] == 1]
    if rejects:
        return min(rejects, key=lambda m: (Fraction(m[1]["confusion"][_S][1]), m[0]))
    accepts = [m for m in members if m[2] == 0]
    if accepts:

        def key(m):
            a_s, a_v = Fraction(m[1]["confusion"][_S][0]), Fraction(m[1]["confusion"][_V][0])
            # Infinite LR (P(accept|violated) = 0) sorts ahead of every finite one.
            return ((0, Fraction(0)) if a_v <= 0 else (1, -a_s / a_v), m[0])

        return min(accepts, key=key)
    return min(members, key=lambda m: m[0])


# D-AQ (lead, binding): a case this generator places within a few ulps of a Chow
# threshold is marked `boundary`, and its VERDICT is then not the oracle's to assert.
# This referee rounds ONCE, at the end, in exact rationals; a float64 leg rounds per
# multiply, so at a construction built to sit ON the threshold no float64 evaluation can
# be expected to reach the exact rational answer — `chow_boundary_eta_exactly_one_minus_
# a_over_d` has both legs agreeing on `refused` where the rational answer is `satisfied`.
# Agreement is the property under test, and reporting that as a failure gives one number
# for two different defects. Boundary vectors are asserted cross-leg instead
# (tools/ci/conformance_crosslang.sh); interior vectors keep both assertions.
#
# 4 ulps of the larger side, which is not a knife edge: over the 25 frozen vectors the
# margins are either EXACTLY 0 (the three on-threshold constructions) or ≥ 1970 ulps.
BOUNDARY_ULPS = 4
_ULP = Fraction(2) ** -52


def _on_boundary(lhs: Fraction, rhs: Fraction) -> bool:
    scale = max(abs(lhs), abs(rhs))
    return scale > 0 and abs(lhs - rhs) <= BOUNDARY_ULPS * _ULP * scale


def derive(vec: dict) -> dict:
    """Exact-rational ADJUDICATE. Returns the manifest expectation block."""
    kept = [v for v in vec["votes"] if not v["tamper"]]
    tampered = len(kept) != len(vec["votes"])
    groups: dict[str, list[tuple[str, dict, int]]] = {}
    infra = coverage = unknown = 0
    for v in kept:
        col = COL[v["verdict"]]
        if col is None:
            infra += 1
            continue
        params = vec["verifiers"].get(v["verifier_id"])
        # D-AB: membership gates COVERAGE, not only likelihood — the filter runs BEFORE
        # the D1 count, or a stranger who supplies no likelihood term still unlocks a
        # block. Quarantined is the same path as unlisted, by construction.
        if params is None or params.get("quarantined"):
            unknown += 1
            continue
        if col != 2:
            coverage += 1
        groups.setdefault(params["group"] or f"\x00solo:{v['verifier_id']}", []).append(
            (v["verifier_id"], params, col)
        )

    if coverage < 1:
        verdict = "error" if (tampered or infra) else "refused"
        post = [Fraction(0)] * 4
        post[CLASSES.index(verdict)] = Fraction(1)
        return {
            "expect": "degenerate",
            "verdict": verdict,
            "posterior": [float(p) for p in post],
            "vote_count": len(kept),
            "unknown_voters": unknown,
        }

    u = [Fraction(p) for p in vec["priors"]]
    for gid in sorted(groups):
        _vid, params, col = _collapse(groups[gid])
        for t in range(4):
            x = Fraction(params["confusion"][t][col])
            u[t] = u[t] * x if x > 0 else Fraction(0)  # not-positive ⇒ -inf ⇒ zero mass
    total = sum(u)
    if total == 0:
        return {"expect": "zero_mass", "vote_count": len(kept), "unknown_voters": unknown}
    post = [x / total for x in u]

    # D-AQ: how close this construction sits to either Chow threshold, in exact
    # rationals, BEFORE the branch that uses them.
    boundary = _on_boundary(u[_S] * COST_D, (COST_D - COST_A) * total) or _on_boundary(
        u[_S] * COST_R, COST_A * total
    )
    if post[_E] > THETA_ERROR or (kept and Fraction(infra, len(kept)) > INFRA_DOMINANT_FRAC):
        verdict = "error"
        boundary = False  # step 3 short-circuits the band; the thresholds never ran
    else:
        # D-AK: the Chow rule cross-multiplied, exactly as both implementations run it
        # (u_S·D ≥ (D−A)·total / u_S·R ≤ A·total). D-AC's 1e-12 quantisation is gone:
        # it was the ONE float in this derivation, and rounding a value derived from a
        # transcendental only relocates the set of constructions the two languages
        # straddle. The transcendentals themselves are what left; nothing here rounds.
        if u[_S] * COST_D >= (COST_D - COST_A) * total:
            verdict = "satisfied"
        elif u[_S] * COST_R <= COST_A * total:
            verdict = "violated"
        else:
            verdict = "refused"
    out = {
        "expect": "fuse",
        "verdict": verdict,
        "posterior": [float(p) for p in post],
        "vote_count": len(kept),
        "unknown_voters": unknown,
    }
    if boundary:
        out["boundary"] = True  # emitted only when set: absent ⇒ interior, no drift
    return out


def main() -> None:
    entries = []
    for vec in VECTORS:
        payload = {k: v for k, v in vec.items() if k not in ("bit_identical_to", "provenance")}
        path = HERE / f"{vec['name']}.json"
        raw = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
        path.write_bytes(raw)
        cls, note = vec["provenance"]  # KeyError ⇒ a vector was added without declaring (D-AG)
        if cls not in PROVENANCE_CLASSES:
            raise SystemExit(f"{vec['name']}: provenance class {cls!r} is not one of {PROVENANCE_CLASSES}")
        entry = {
            "name": vec["name"],
            "file": path.name,
            "file_sha256_hex": hashlib.sha256(raw).hexdigest(),
            "provenance": {"class": cls, "note": note},
            **derive(vec),
        }
        if "bit_identical_to" in vec:
            entry["bit_identical_to"] = vec["bit_identical_to"]
        entries.append(entry)

    manifest = {
        "_readme": "Frozen fusion-family conformance contract. README.md is normative; this file is the referee; generated by gen_fusion_vectors.py, whose expectations are EXACT RATIONAL derivations, not a recording of either implementation. Each vector carries a `provenance` declaration (D-AG): `doc-derived` = every consumed input is printed in a frozen doc, `mixed` = some consumed column is not, `fixture-local` = constructed here for an algebraic property. A family that ratifies the first guess is worth no more than one that ratifies the first implementation.",
        "classes": list(CLASSES),
        "costs": {"A": 1.0, "R": 3.0, "D": 9.0},
        "tolerance": 1e-12,
        "vectors": entries,
    }
    (HERE / "manifest.json").write_bytes(
        (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    )
    print(f"wrote {len(entries)} fusion vectors + manifest.json")


if __name__ == "__main__":
    main()
