"""Bundle-supplied likelihood parameters for ADJUDICATE (06 §3.1 inputs), plus the
Phase 2 answer to "where do confusion matrices come from before spectral D-S exists":
literature-CALIBRATED per-kind defaults with provenance stamped 'prior' — the same
posture as intel's engine.py CALIBRATED_ALPHA/BETA (values are the trilogy's cited
operating points, never our claim; replaced row-by-row when Phase 4's estimator writes
`spectral`/`shrunk-global` rows).

Confusion matrix shape (06 §3.1): per verifier, 4×3 — rows are the latent classes
[satisfied, violated, refused, error] (frozen order, proto VerdictEvent.posterior),
columns are the vote outcomes [accept, reject, abstain]."""

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Literal

CLASSES = ("satisfied", "violated", "refused", "error")
VOTES = ("accept", "reject", "abstain")
_VOTE_IX = {v: i for i, v in enumerate(VOTES)}

Vote = Literal["accept", "reject", "abstain"]
# 4 rows (true class, [S,V,R,E] order) × 3 cols (accept, reject, abstain).
Confusion = tuple[tuple[float, float, float], ...]

# D2 (06 §3.1 step 1): an anchor's P(reject | satisfied) ≈ ε_anchor. The asymmetry is
# the identifying fact — anchor confusion rows are never smoothed toward symmetry.
EPSILON_ANCHOR = 0.02

# ---------------------------------------------------------------------------
# Literature-CALIBRATED default confusion rows, per handler kind (Paper II §9's
# published operating points where they exist; DESIGN fills marked inline).
# Rows are proper distributions over (accept, reject, abstain) per latent class.
# ---------------------------------------------------------------------------
_ANCHOR_DEFAULT: Confusion = (
    # Compile/test anchors: perfect-precision rejection — reject|S = ε_anchor (D2);
    # Paper II §9's anchor clique rejects 40% of false candidates (reject|V = 0.40).
    (0.93, EPSILON_ANCHOR, 0.05),  # satisfied
    (0.55, 0.40, 0.05),  # violated
    (0.30, 0.10, 0.60),  # refused   (DESIGN: mostly can't run → abstain)
    (0.25, 0.15, 0.60),  # error     (DESIGN: infra failure → abstain-heavy)
)
_SYNTACTIC_DEFAULT: Confusion = (
    # Lint/typecheck: deterministic but NOT perfect-precision (style false positives);
    # DESIGN values — no literature point exists for this class, so rows are honestly
    # wide and provenance says 'prior'.
    (0.80, 0.10, 0.10),  # satisfied
    (0.55, 0.35, 0.10),  # violated
    (0.30, 0.20, 0.50),  # refused
    (0.25, 0.25, 0.50),  # error
)
_JUDGE_DEFAULT: Confusion = (
    # Grounded-rubric judge, Paper II §9: (a, b) = (0.85, 0.20).
    (0.85, 0.10, 0.05),  # satisfied
    (0.20, 0.75, 0.05),  # violated
    (0.30, 0.30, 0.40),  # refused
    (0.30, 0.30, 0.40),  # error
)
_RM_DEFAULT: Confusion = (
    # Reasoning reward model, Paper II §9: (a, b) = (0.75, 0.25).
    (0.75, 0.20, 0.05),  # satisfied
    (0.25, 0.70, 0.05),  # violated
    (0.30, 0.30, 0.40),  # refused
    (0.30, 0.30, 0.40),  # error
)
_CONSISTENCY_DEFAULT: Confusion = (
    # Escalation-scoped, low power by construction (C1.16) — honestly wide rows.
    (0.60, 0.25, 0.15),  # satisfied
    (0.40, 0.45, 0.15),  # violated
    (0.30, 0.30, 0.40),  # refused
    (0.30, 0.30, 0.40),  # error
)

# Handler kind (06 §2.1's KIND_*) → calibrated default. m1_020's coarse DB kind
# 'anchor' covers lint/typecheck/compile/test; the handler kinds are the estimation
# grain here because their error laws differ (a compile reject is perfect-precision,
# a lint reject is not).
CALIBRATED_CONFUSION: MappingProxyType[str, Confusion] = MappingProxyType(
    {
        "lint": _SYNTACTIC_DEFAULT,
        "typecheck": _SYNTACTIC_DEFAULT,
        "compile": _ANCHOR_DEFAULT,
        "test": _ANCHOR_DEFAULT,
        "judge": _JUDGE_DEFAULT,
        "rm": _RM_DEFAULT,
        "consistency": _CONSISTENCY_DEFAULT,
    }
)

# 06 §3.1 (bundle priors are a required input; this is the fallback when a tenant has
# no compiled bundle yet). Values from the 06 §3.2 worked example's bundle — DESIGN.
DEFAULT_PRIORS = (0.55, 0.30, 0.10, 0.05)

# Correlation groups (06 §4.1); fallback def.group. Tests/judges/RMs own clique (16 §Indep).
KIND_TO_GROUP: MappingProxyType[str, str] = MappingProxyType(
    {
        "lint": "syntactic",
        "typecheck": "syntactic",
        "compile": "syntactic",
        "test": "tests",
        "judge": "judges",
        "rm": "rms",
        "consistency": "consistency",
    }
)


@dataclass(frozen=True)
class VerifierParams:
    """One verifier's row set in the bundle's `verify` section, provenance stamped
    (06 §1.3 vocabulary: spectral | shrunk-global | prior)."""

    verifier_id: str
    kind: str
    confusion: Confusion
    group: str
    provenance: Literal["spectral", "shrunk-global", "prior"]


@dataclass(frozen=True)
class Bundle:
    """ADJUDICATE's bundle input (06 §3.1): priors π[4], per-verifier confusion,
    correlation groups, Chow costs. Costs live in chow.Costs at the call site."""

    priors: tuple[float, float, float, float] = DEFAULT_PRIORS
    verifiers: dict[str, VerifierParams] = field(default_factory=dict)
    # OPT-IN, and only where someone decided it: the certification / gold-set path has
    # no bundle to contradict, so it may fall back to the literature-CALIBRATED rows.
    # It was inferred from `not self.verifiers` instead, which made a bundle carrying
    # ZERO verifiers grant full likelihood AND coverage to a total stranger — an
    # unlisted verifier producing a BLOCK-grade `violated` and not even counted in
    # unknown_voters, reachable through the unauthenticated /v1/adjudicate/preview
    # whenever `verifiers` is omitted. The edge's equivalent state contributes
    # nothing, so the inference was also a Python-only divergence from D-AB.
    calibrated_defaults: bool = False

    def params_for(self, verifier_id: str, kind: str) -> VerifierParams | None:
        """The verifier's row, or None when this bundle cannot honestly supply one.

        DECISION D-X (lead, binding). A BUNDLE IS THE SOLE SOURCE OF FUSION
        PARAMETERS. A verifier this bundle does not list gets no likelihood at all
        (None) — the caller counts it and moves on, exactly as the edge twin does; a
        per-kind default here would silently disagree with a mark1d that has no such
        table, on the same (bundle, votes).

        `calibrated_defaults=True` is the one exemption, and it is a caller's explicit
        claim to be on the certification path. Its provenance is 'prior', so _stamp
        caps any fusion that consumed one at BOOTSTRAPPING (D-T), never CERTIFIED.
        """
        got = self.verifiers.get(verifier_id)
        if got is not None:
            return got
        return calibrated_params(verifier_id, kind) if self.calibrated_defaults else None

    @classmethod
    def from_verify(
        cls,
        priors: tuple[float, float, float, float],
        verify: dict[str, dict],
    ) -> "Bundle":
        """Build a bundle from a policy bundle's raw `verify` section (07).

        The QUARANTINE DROP lives here, in the production path, not in whatever
        happens to be reading a fixture: a quarantined verifier's row is DROPPED
        rather than zeroed, so its votes reach fusion indistinguishable from any other
        unlisted voter's — no likelihood, no coverage (D-AB), counted by D-X's
        unknown_voters. Mirrors frombundle.go, which is where the edge does it."""
        return cls(
            priors=priors,
            verifiers={
                vid: VerifierParams(
                    verifier_id=vid,
                    kind=spec["kind"],
                    confusion=tuple(tuple(row) for row in spec["confusion"]),
                    group=spec["group"],
                    provenance=spec.get("provenance", "prior"),
                )
                for vid, spec in verify.items()
                if not spec.get("quarantined")
            },
        )


def calibrated_params(verifier_id: str, kind: str) -> VerifierParams:
    if kind not in CALIBRATED_CONFUSION:
        # An unknown kind must have been refused at normalization (06 §2.2); reaching
        # here means a caller bypassed handlers.py — refuse loudly, never fabricate
        # a likelihood row for a kind we cannot interpret.
        raise KeyError(f"no calibrated confusion for unhandled kind {kind!r}")
    return VerifierParams(
        verifier_id=verifier_id,
        kind=kind,
        confusion=CALIBRATED_CONFUSION[kind],
        group=KIND_TO_GROUP[kind],
        provenance="prior",
    )


def likelihood(params: VerifierParams, vote: Vote, class_ix: int) -> float:
    """P(vote | latent class) from the verifier's confusion row."""
    return params.confusion[class_ix][_VOTE_IX[vote]]
