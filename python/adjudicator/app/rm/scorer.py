"""T2 reward-model members (06 §2 KIND_RM, 16 §L6): an RmScore's raw scalar folds through its
calibration into a wire verdict. A trained RM's calibration rides its catalog row's sealed
artifact (definition.artifact.calibration, m1_094, written at publish) and folds through that
calibration ONLY: a score naming any other version is refused and counted, so the device that
scored it cannot pick its own band. rm-cal@1 is the pre-training table for a model whose row
carries no artifact block (the tests and the legacy probability scores)."""

import logging
import math
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from m1p.v1 import RmScore

from app.adjudicate.algorithm import VerdictEvent, adjudicate
from app.adjudicate.chow import Costs
from app.adjudicate.likelihoods import CALIBRATED_CONFUSION, Bundle, Confusion
from app.registry.handlers import KIND_RM, NormalizedVote, RawVoteEvent
from app.registry.promotion import ShadowPair, split_shadow

log = logging.getLogger("adjudicator.rm")

CALIBRATION_VERSION = "rm-cal@1"

rm_refused_total: Counter[str] = Counter()


@dataclass(frozen=True)
class Calibration:
    reject_below: float
    accept_above: float
    confusion: Confusion = CALIBRATED_CONFUSION["rm"]
    scale: float | None = (
        None  # Platt g(s) = σ(scale·s + shift) on s = logit(score); None ⇒ the score is already p
    )
    shift: float = 0.0

    def p(self, score: float) -> float | None:
        # the wire carries σ(raw logit) ∈ [0,1] (16 L6); Platt runs on the recovered logit
        if not 0.0 <= score <= 1.0:
            return None
        if self.scale is None:
            return score
        q = min(max(score, 1e-12), 1.0 - 1e-12)
        z = self.scale * math.log(q / (1.0 - q)) + self.shift
        return 1.0 / (1.0 + math.exp(-z)) if z > -700 else 0.0


# ponytail: one D18-wide abstain band at the bundle prior; isotonic bins after D38's 500 pairs
CALIBRATION: dict[str, Calibration] = {
    CALIBRATION_VERSION: Calibration(0.40, 0.60),
}


def calibration_for(
    version: str, definition: Mapping[str, Any] | None = None
) -> Calibration | None:
    """A model with an artifact block: its sealed calibration when the score names exactly that
    version, else None. A model without one: the code table."""
    definition = definition or {}
    if "artifact" not in definition:
        return CALIBRATION.get(version)
    cal = (definition.get("artifact") or {}).get("calibration") or {}
    if version and cal.get("version") == version:
        return Calibration(
            float(cal["reject_below"]),
            float(cal["accept_above"]),
            scale=None if cal.get("scale") is None else float(cal["scale"]),
            shift=float(cal.get("shift", 0.0)),
        )
    return None


def calibration_refusal(version: str, definition: Mapping[str, Any] | None = None) -> str | None:
    """Why an RmScore under `version` cannot fold, or None when it can."""
    if calibration_for(version, definition) is not None:
        return None
    if "artifact" in (definition or {}):
        return f"refused_rm_calibration_not_sealed:{version}"
    return f"refused_rm_unknown_calibration:{version}"


def fold(score: Any, version: str, definition: Mapping[str, Any] | None = None) -> str | None:
    """Raw score → wire verdict (in-band is an honest `refused`), or None: nothing to count."""
    cal = calibration_for(version, definition)
    if cal is None or isinstance(score, bool) or not isinstance(score, int | float):
        return None
    if not math.isfinite(score):
        return None
    p = cal.p(float(score))
    if p is None:
        return None
    if p < cal.reject_below:
        return "violated"
    if p > cal.accept_above:
        return "satisfied"
    return "refused"


def _refuse(rm_id: str, reason: str) -> None:
    rm_refused_total[reason.split(":", 1)[0]] += 1
    log.info("%s refused %s", rm_id, reason)
    return None


def to_raw_vote(
    rm: RmScore,
    task_id: UUID,
    attempt_id: UUID,
    evidence_digest: bytes,
    definition: Mapping[str, Any] | None = None,
) -> RawVoteEvent | None:
    """Ledger RmScore → wire verdict for _normalize_rm (06 §2.5)."""
    if reason := calibration_refusal(rm.calibration_version, definition):
        return _refuse(rm.model_id, reason)
    verdict = fold(rm.score, rm.calibration_version, definition)
    if verdict is None:
        return _refuse(rm.model_id, "refused_rm_malformed_score")
    return RawVoteEvent(
        verifier_id=rm.model_id,
        kind=KIND_RM,
        task_id=task_id,
        attempt_id=attempt_id,
        verdict=verdict,
        evidence_digest=evidence_digest,
    )


def shadow_fuse(
    votes: list[NormalizedVote],
    rm_vote: NormalizedVote,
    bundle: Bundle,
    costs: Costs | None = None,
    noise_cert_id: str = "",
    escalation: bool = False,
) -> tuple[VerdictEvent, ShadowPair]:
    """06 §12.4 row 2: fuse WITHOUT the shadow member, pair its vote against the fused verdict."""
    fused, (shadow,) = split_shadow([*votes, rm_vote], {rm_vote.verifier_id})
    event = adjudicate(fused, bundle, costs, noise_cert_id, escalation)
    return event, ShadowPair(shadow.vote, event.verdict, event.noise_cert_id)
