"""Judge registry + the client-side-default runner (06 §6, contract C4).

This module orchestrates WHICH judge runs on WHICH evidence tier; in the default path
it executes nothing. `ClientSideJudge.run` emits a `JudgeRequest` the edge (mark1d)
consumes: evidence is assembled locally, the model is called through the CUSTOMER'S
OWN key, and only the resulting `JudgeVote` (proto/m1p/v1/verify.proto) comes back.

Registry discipline is probes.py's, imported whole (06 §2.2): the spec dict and the
registered set are the same fact stated twice, asserted at import; a judge_id outside
the set is REFUSED with a typed error, never faked into a vote."""

from collections import Counter
from dataclasses import dataclass
from typing import Literal, Protocol
from uuid import UUID

from m1p.v1 import JudgeLocus, JudgeVote

from app.adjudicate.likelihoods import CALIBRATED_CONFUSION, Confusion

Tier = Literal["E0", "E1", "E2"]
TIERS: tuple[Tier, ...] = ("E0", "E1", "E2")
# E2 (full diff) exists only inside the customer boundary (06 §6.2 table).
E2_PROFILES = frozenset({"vpc", "selfhost"})


class JudgeRefused(Exception):
    """A statement about Mark 1's own verifier plane, never about the customer's code
    (06 §2.2). `reason` is the machine-readable form; tests match on it."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


judges_refused_total: Counter[str] = Counter()


def refuse(reason: str, detail: str = "") -> JudgeRefused:
    judges_refused_total[reason.split(":", 1)[0]] += 1
    return JudgeRefused(reason, detail)


@dataclass(frozen=True)
class JudgeSpec:
    """One registry entry, keyed `judge:<name>@<version>` (06 §6.3: any change to rubric
    text, tier requirement or model rung is a NEW version with no inherited confusion)."""

    judge_id: str
    rubric: str  # the static, cacheable prefix — DATA, distributes like a field map
    evidence_tier: Tier
    model: str
    subprocessor: str  # vendor the cloud path would disclose (06 §6.5 precondition 2)
    region: str  # vendor-side inference geo the cloud path pins (precondition 3)
    token_budget: int
    confusion: Confusion  # 06 §2.3: a fresh version starts from the shrunk prior


_GROUNDED_RUBRIC = (
    "You are a grounded code-change judge. Judge ONLY from the typed evidence supplied: "
    "anchor outputs, diagnostic codes, diff structure and the task's acceptance criteria. "
    "Do not speculate beyond it. Reply with exactly one word from: "
    "satisfied|violated|refused|error. Use `refused` when the evidence is insufficient "
    "to judge honestly, `error` only when the evidence itself is malformed."
)

JUDGE_SPECS: dict[str, JudgeSpec] = {
    "judge:grounded-rubric@1": JudgeSpec(
        judge_id="judge:grounded-rubric@1",
        rubric=_GROUNDED_RUBRIC,
        evidence_tier="E0",
        # cheapest rung that accepts inference_geo; 06 §6.5's Haiku rung cannot pin a region
        model="claude-sonnet-5",
        subprocessor="anthropic",
        region="us",
        token_budget=2048,
        confusion=CALIBRATED_CONFUSION["judge"],
    ),
}
_REGISTERED_JUDGES = frozenset({"judge:grounded-rubric@1"})

# The registry and the registered set are the same fact stated twice (probes.py rule).
assert set(JUDGE_SPECS) == _REGISTERED_JUDGES
assert all(s.judge_id == k and s.evidence_tier in TIERS for k, s in JUDGE_SPECS.items())


def spec_for(judge_id: str, profile: str) -> JudgeSpec:
    """Registry lookup + the evidence-tier gate both loci share (FR-VERIFY-016)."""
    spec = JUDGE_SPECS.get(judge_id)
    if spec is None:
        raise refuse(f"refused_unregistered_judge:{judge_id}", "no JUDGE_SPECS entry")
    if spec.evidence_tier == "E2" and profile not in E2_PROFILES:
        raise refuse("refused_tier_e2_outside_vpc_selfhost", f"profile={profile!r}")
    return spec


@dataclass(frozen=True)
class JudgeRequest:
    """What crosses to the edge on the client-side path (06 §6.2 step 2). Rubric text
    rides as prompt DATA; no command, no evidence, no key ever crosses. Go side owed:
    mark1d consumes this and emits the JudgeVote."""

    judge_id: str
    task_id: UUID
    attempt_id: UUID
    rubric: str
    evidence_tier: Tier
    model: str
    token_budget: int
    locus: JudgeLocus = JudgeLocus.CLIENT_SIDE


class JudgeRunner(Protocol):
    locus: JudgeLocus

    async def run(
        self, tenant_id: UUID, judge_id: str, task_id: UUID, attempt_id: UUID
    ) -> JudgeRequest | JudgeVote: ...


class ClientSideJudge:
    """The default. Emits the request; the adjudicator only ever sees the vote come back
    through the ledger. Zero network here by construction — there is no client."""

    locus = JudgeLocus.CLIENT_SIDE

    def __init__(self, profile: str = "saas") -> None:
        self._profile = profile

    async def run(
        self, tenant_id: UUID, judge_id: str, task_id: UUID, attempt_id: UUID
    ) -> JudgeRequest:
        spec = spec_for(judge_id, self._profile)
        return JudgeRequest(
            judge_id=spec.judge_id,
            task_id=task_id,
            attempt_id=attempt_id,
            rubric=spec.rubric,
            evidence_tier=spec.evidence_tier,
            model=spec.model,
            token_budget=spec.token_budget,
        )
