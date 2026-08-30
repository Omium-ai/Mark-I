"""The certificate status ladder (06 §5.3): uncertified → bootstrapping → certified.

Two structural properties, both tested:
- There is NO path that skips `bootstrapping` on the way up — even a window with every
  gate green goes uncertified → bootstrapping first.
- The two downward paths are asymmetric: quality-of-evidence problems (size dip,
  freshness lapse, identifiability gate) demote ONE step; validity problems (Natarajan
  violated, drift alarm, tamper event) demote to the FLOOR from any state. The status
  is a claim about what may be asserted, so it degrades faster than it upgrades.

Phase 2 honesty: `identifiability_passed` is False until the Phase 4 spectral
estimator exists, so `certified` is structurally unreachable — the ladder still
encodes it because the ladder IS the contract, not the current capability."""

from dataclasses import dataclass

UNCERTIFIED = "uncertified"
BOOTSTRAPPING = "bootstrapping"
CERTIFIED = "certified"
_STATUSES = frozenset({UNCERTIFIED, BOOTSTRAPPING, CERTIFIED})

# §5.3 diagram: "gold set forming (≥ 50 labels)" — unnumbered in 06's Dn list.
GOLD_BOOTSTRAP_MIN = 50
# D15: size gate — a certificate may reach `certified` only on ≥ 200 gold labels.
GOLD_SIZE_GATE = 200
# D16: ≥ 50% of gold labels within the last 30 days (the window arithmetic lives in
# gold/rotate.py; this is the fraction gate).
FRESH_FRAC_GATE = 0.5


@dataclass(frozen=True)
class CertEvidence:
    """The nightly recompute's inputs to one transition decision."""

    gold_n: int  # labels in the D17-filtered scoring window
    fresh_frac: float  # fraction within the D16 30-day window
    estimator_ran: bool  # "estimator running (any mode)" — weighted-majority counts
    identifiability_passed: bool  # §4.3 gate (Phase 4); False until spectral exists
    natarajan_ok: bool | None  # None ⇒ not yet measurable (compute.py, never defaulted)
    drift_alarm: bool = False  # label-free CUSUM (Paper II)
    tamper_event: bool = False


def _upgrade_gates_green(ev: CertEvidence) -> bool:
    return (
        ev.gold_n >= GOLD_SIZE_GATE
        and ev.fresh_frac >= FRESH_FRAC_GATE
        and ev.identifiability_passed
        and ev.natarajan_ok is True
    )


def next_status(current: str, ev: CertEvidence) -> str:
    """One transition of the §5.3 state machine."""
    if current not in _STATUSES:
        raise ValueError(f"unknown certificate status {current!r}")

    # Validity problems demote to the floor from ANY state (§5.3 prose): a measured
    # Natarajan violation, drift, or tamper is not a quality-of-evidence issue —
    # natarajan_ok is None ("not yet measurable") is NOT a violation.
    if ev.natarajan_ok is False or ev.drift_alarm or ev.tamper_event:
        return UNCERTIFIED

    if current == UNCERTIFIED:
        # No skip: even all-green evidence lands in bootstrapping first.
        if ev.gold_n >= GOLD_BOOTSTRAP_MIN and ev.estimator_ran:
            return BOOTSTRAPPING
        return UNCERTIFIED

    if current == BOOTSTRAPPING:
        return CERTIFIED if _upgrade_gates_green(ev) else BOOTSTRAPPING

    # current == CERTIFIED: quality-of-evidence lapse demotes one step.
    return CERTIFIED if _upgrade_gates_green(ev) else BOOTSTRAPPING


def may_gate_learning(status: str) -> bool:
    """The §5.4 settled rule, one spelling for every caller in THIS service: only a
    `certified` status lets a verdict gate memory extraction, corpus admission, or any
    other learning consumer. `bootstrapping`/`uncertified` verdicts still gate the
    SESSION (provisional loop value) — they gate no learning fuel. The cross-service
    enforcement twin is m1_021's mark1_assert_certified()."""
    return status == CERTIFIED
