#!/usr/bin/env python3
"""Deterministic generator for the coverage-band conformance vectors — see README.md.

Run:  python3 gen_vectors.py          (stdlib only)
It rewrites manifest.json in place. Committed so the vectors are re-derivable,
but the MANIFEST is the frozen contract — if regeneration ever changes a byte,
that is a finding against this script, not a license to update the manifest.

Expectations are derived in exact rational arithmetic (fractions.Fraction) and
rounded to float64 exactly once, so neither implementation under test is the
referee for the other (the fusion family's rule). The two steps, restated from
the normative sources (07 "Coverage"; the `dropped_by_tenant_day` template body
in go/controld/internal/querychoke/templates.go; migrations/m1_ch_002_rollups.sql):

  dropped_billing = Σ quantity over Batch.dropped rows whose durability_class is
                    DURABILITY_CLASS_BILLING_GRADE — any reason; DIAGNOSTIC and
                    UNSPECIFIED rows contribute nothing
  coverage        = observed_ms / (observed_ms + bypass_ms + disabled_ms)     (0 on 0/0)
  coverage_lower  = coverage × (1 − dropped_billing / (dropped_billing
                                                       + events_billing_ingested))  (shed 0 on 0/0)
"""

from __future__ import annotations

import json
from fractions import Fraction

BILLING = "DURABILITY_CLASS_BILLING_GRADE"
DIAGNOSTIC = "DURABILITY_CLASS_DIAGNOSTIC"
UNSPECIFIED = "DURABILITY_CLASS_UNSPECIFIED"

FULL_DAY_MS = 24 * 60 * 60 * 1000  # a whole UTC day observed, nothing bypassed or disabled


def dropped(reason: str, cls: str, quantity: int) -> dict:
    return {"reason": f"DROP_REASON_{reason}", "durability_class": cls, "quantity": quantity}


def rollup(
    observed_ms: int, bypass_ms: int, disabled_ms: int, events_billing_ingested: int
) -> dict:
    return {
        "observed_ms": observed_ms,
        "bypass_ms": bypass_ms,
        "disabled_ms": disabled_ms,
        "events_billing_ingested": events_billing_ingested,
    }


def fold(rows: list[dict]) -> int:
    return sum(r["quantity"] for r in rows if r["durability_class"] == BILLING)


def band(dropped_billing: int, r: dict) -> tuple[Fraction, Fraction]:
    total = r["observed_ms"] + r["bypass_ms"] + r["disabled_ms"]
    coverage = Fraction(r["observed_ms"], total) if total else Fraction(0)
    denom = dropped_billing + r["events_billing_ingested"]
    shed = Fraction(dropped_billing, denom) if denom else Fraction(0)
    return coverage, coverage * (1 - shed)


CASES = [
    {
        "name": "zero_loss_point_band",
        "_why": "No Dropped rows at all: the shed term is 0/(0+ingested) = 0 and the band collapses to the point (test_band_arithmetic's numbers).",
        "dropped": [],
        "rollup": rollup(94_000, 4_000, 2_000, 1_000),
    },
    {
        "name": "diagnostic_shed_does_not_narrow",
        "_why": "A DIAGNOSTIC spool shed (NFR-OPERABILITY-001's row) folds to dropped_billing = 0: the predicate is durability_class = billing_grade, so the band is still the point. Same surface and ingested count as the next case — only the class differs.",
        "dropped": [dropped("SPOOL_SHED", DIAGNOSTIC, 50)],
        "rollup": rollup(98_000, 1_000, 1_000, 950),
    },
    {
        "name": "billing_grade_loss_narrows_only_the_lower_edge",
        "_why": "The same 50 as a BILLING_GRADE CRC loss: coverage is unchanged (the upper edge never moves on a drop), the lower edge is coverage × (1 − 50/1000) (test_shed_narrows_only_the_lower_edge's numbers).",
        "dropped": [dropped("CRC_LOSS", BILLING, 50)],
        "rollup": rollup(98_000, 1_000, 1_000, 950),
    },
    {
        "name": "mixed_rows_fold_by_class_not_reason",
        "_why": "Five rows, three classes, five reasons: billing_grade quantities SUM across reasons (1 + 2), diagnostic rows and the UNSPECIFIED zero value contribute nothing. Shed = 3/(3+9).",
        "dropped": [
            dropped("SPOOL_SHED", DIAGNOSTIC, 54),
            dropped("CRC_LOSS", BILLING, 1),
            dropped("LOCAL_QUARANTINE", DIAGNOSTIC, 1),
            dropped("UNSPECIFIED", UNSPECIFIED, 7),
            dropped("QUARANTINED", BILLING, 2),
        ],
        "rollup": rollup(FULL_DAY_MS, 0, 0, 9),
    },
    {
        "name": "spool_shed_reaches_the_wire",
        "_why": "The exact row go/mark1d/cmd/wiring_test.go TestSpoolShedReachesTheWire puts on the wire — 32 HUMAN prompts under a 1 KiB cap shed 27 TaskOpen + 27 Turn records (README derives it) — and the day's rollup as that daemon's day would read: no CoverageTransition, no billing-grade event landed. Surface stipulated as a full observed day so the arithmetic is visible; ingested is 0 so the shed denominator is 0/0.",
        "dropped": [dropped("SPOOL_SHED", DIAGNOSTIC, 54)],
        "rollup": rollup(FULL_DAY_MS, 0, 0, 0),
    },
]


def main() -> None:
    cases = []
    for c in CASES:
        db = fold(c["dropped"])
        coverage, lower = band(db, c["rollup"])
        cases.append(
            {
                **c,
                "expect": {
                    "dropped_billing": db,
                    "coverage": float(coverage),
                    "coverage_lower": float(lower),
                    "exact": {"coverage": str(coverage), "coverage_lower": str(lower)},
                },
            }
        )
    manifest = {
        "_readme": "Frozen coverage-family conformance contract. README.md is normative; this file is the referee.",
        "arithmetic": {
            "dropped_billing": "sum(quantity) over `dropped` rows whose durability_class is DURABILITY_CLASS_BILLING_GRADE, any reason (dropped_by_tenant_day / mv_tvo_session predicate: dropped_durability_class = 'billing_grade')",
            "coverage": "observed_ms / (observed_ms + bypass_ms + disabled_ms); 0 when the denominator is 0",
            "coverage_lower": "coverage * (1 - dropped_billing / (dropped_billing + events_billing_ingested)); the shed term is 0 when its denominator is 0",
        },
        "tolerance": 1e-12,
        "cases": cases,
    }
    with open("manifest.json", "w") as f:
        json.dump(manifest, f, indent=1, sort_keys=False)
        f.write("\n")
    print(f"manifest.json written: {len(cases)} cases")


if __name__ == "__main__":
    main()
