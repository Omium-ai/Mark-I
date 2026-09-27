"""Judge registry + the client-side-default runner (06 §6, contract C4).

This module orchestrates WHICH judge runs on WHICH evidence tier; in the default path
it executes nothing. `ClientSideJudge.run` posts a `JudgeRequest` (proto/m1p/v1/verify.proto)
to controld's internal fan-out route; it rides the tenant's policy SSE stream as
`event: judge_request`, the owning edge (mark1d internal/judge) assembles evidence locally,
calls the model through the CUSTOMER'S OWN key, and only the `JudgeVote` comes back.

Registry discipline is probes.py's, imported whole (06 §2.2): the spec dict and the
registered set are the same fact stated twice, asserted at import; a judge_id outside
the set is REFUSED with a typed error, never faked into a vote."""

from collections import Counter
from dataclasses import dataclass, replace
from typing import Literal, Protocol
from uuid import UUID, uuid5

import betterproto
import httpx
from m1p.v1 import EvidenceTier, JudgeLocus, JudgeRequest, JudgeVote

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
    locus: Literal["edge", "cloud"]  # edge = the customer's own key; cloud = Omium's router
    rubric: str  # the static, cacheable prefix — DATA, distributes like a field map
    evidence_tier: Tier
    model: str
    subprocessor: str  # vendor the consent row must name (06 §6.5 precondition 2)
    region: str  # vendor-side processing region the consent row must name (precondition 3)
    token_budget: int
    confusion: Confusion  # 06 §2.3: a fresh version starts from the shrunk prior
    e0_rubric: str | None = None  # an E1 judge's rubric for a task with no E1 evidence; votes E0


_GROUNDED_RUBRIC = (
    "You are a grounded code-change judge. Judge ONLY from the typed evidence supplied: "
    "anchor outputs, diagnostic codes, diff structure and the task's acceptance criteria. "
    "Do not speculate beyond it. Reply with exactly one word from: "
    "satisfied|violated|refused|error. Use `refused` when the evidence is insufficient "
    "to judge honestly, `error` only when the evidence itself is malformed."
)

# 16 §L7: reads only the task and the change, never anchor output, so it is a view of its own
_DIFF_RUBRIC = (
    "You are a code-change judge. You see the task the change was made for, when it was shared, "
    "and the change itself as secret-scrubbed diff hunks. Judge ONLY whether the change does "
    "what the task asks, from the text supplied; do not speculate beyond it. Reply with exactly "
    "one word from: satisfied|violated|refused|error. Use `refused` when the hunks are "
    "insufficient to judge honestly, `error` only when the input itself is malformed."
)

JUDGE_SPECS: dict[str, JudgeSpec] = {
    "judge:grounded-rubric@1": JudgeSpec(
        judge_id="judge:grounded-rubric@1",
        locus="edge",
        rubric=_GROUNDED_RUBRIC,
        evidence_tier="E0",
        model="claude-sonnet-5",
        subprocessor="anthropic",
        region="us",
        token_budget=2048,
        confusion=CALIBRATED_CONFUSION["judge"],
    ),
    # 16 §L1: the cloud judge is GLM on Nebius Token Factory through the platform llm-router
    "judge:grounded-rubric@2": JudgeSpec(
        judge_id="judge:grounded-rubric@2",
        locus="cloud",
        rubric=_DIFF_RUBRIC,
        evidence_tier="E1",
        model="zai-org/GLM-5.2",
        subprocessor="nebius",
        region="global",
        token_budget=2048,
        confusion=CALIBRATED_CONFUSION["judge"],
        e0_rubric=_GROUNDED_RUBRIC,
    ),
}
_REGISTERED_JUDGES = frozenset({"judge:grounded-rubric@1", "judge:grounded-rubric@2"})

# The registry and the registered set are the same fact stated twice (probes.py rule).
assert set(JUDGE_SPECS) == _REGISTERED_JUDGES
assert all(s.judge_id == k and s.evidence_tier in TIERS for k, s in JUDGE_SPECS.items())


def at_tier(spec: JudgeSpec, tier: str) -> JudgeSpec:
    """The spec as it judged at `tier`: an E1 judge falling back to E0 votes E0 on its E0 rubric."""
    if tier == spec.evidence_tier or spec.e0_rubric is None or tier != "E0":
        return spec
    return replace(spec, evidence_tier="E0", rubric=spec.e0_rubric, e0_rubric=None)


def spec_for(judge_id: str, profile: str) -> JudgeSpec:
    """Registry lookup + the evidence-tier gate both loci share (FR-VERIFY-016)."""
    spec = JUDGE_SPECS.get(judge_id)
    if spec is None:
        raise refuse(f"refused_unregistered_judge:{judge_id}", "no JUDGE_SPECS entry")
    if spec.evidence_tier == "E2" and profile not in E2_PROFILES:
        raise refuse("refused_tier_e2_outside_vpc_selfhost", f"profile={profile!r}")
    return spec


JUDGE_REQUESTS_PATH = "/internal/v1/judge-requests"
WIRE_TIER = {"E0": EvidenceTier.E0, "E1": EvidenceTier.E1, "E2": EvidenceTier.E2}


class JudgeRunner(Protocol):
    locus: JudgeLocus

    async def run(
        self, tenant_id: UUID, judge_id: str, task_id: UUID, attempt_id: UUID, session_id: UUID
    ) -> JudgeRequest | JudgeVote: ...


def request_id_for(judge_id: str, task_id: UUID, attempt_id: UUID) -> str:
    """Deterministic per (task, judge, attempt): the edge keeps one vote per request_id, so a
    repost after a missed delivery is safe and a re-run cannot mint a second vote."""
    return str(uuid5(task_id, f"{judge_id}/{attempt_id}"))


def protojson(req: JudgeRequest) -> dict[str, object]:
    d = req.to_dict(casing=betterproto.Casing.CAMEL)
    # betterproto strips the enum prefix ("E0"); protojson wants the full name or the integer.
    d["tier"], d["locus"] = req.tier.value, req.locus.value
    return d


class ClientSideJudge:
    """The default. Posts the request to controld's fan-out route and returns it; the
    adjudicator only ever sees the vote come back through the ledger. No model client
    exists here by construction, so no evidence and no key can leave through it."""

    locus = JudgeLocus.CLIENT_SIDE

    def __init__(
        self, http: httpx.AsyncClient, base_url: str, service_token: str, profile: str = "saas"
    ) -> None:
        self._http, self._base_url, self._token, self._profile = (
            http,
            base_url,
            service_token,
            profile,
        )

    async def run(
        self, tenant_id: UUID, judge_id: str, task_id: UUID, attempt_id: UUID, session_id: UUID
    ) -> JudgeRequest:
        spec = spec_for(judge_id, self._profile)
        if spec.locus != "edge":
            raise refuse("refused_cloud_judge_at_edge", spec.judge_id)
        if not self._base_url or not self._token:
            raise refuse("refused_no_controld", "controld base URL or service token unset")
        req = JudgeRequest(
            request_id=request_id_for(spec.judge_id, task_id, attempt_id),
            judge_id=spec.judge_id,
            task_id=task_id.bytes,
            session_id=session_id.bytes,
            rubric=spec.rubric,
            tier=WIRE_TIER[spec.evidence_tier],
            model=spec.model,
            token_budget=spec.token_budget,
            locus=JudgeLocus.CLIENT_SIDE,
        )
        resp = await self._http.post(
            f"{self._base_url.rstrip('/')}{JUDGE_REQUESTS_PATH}",
            json={"tenant_id": str(tenant_id), "request": protojson(req)},
            headers={"Authorization": f"Bearer {self._token}"},
        )
        if resp.status_code // 100 != 2:
            raise refuse(f"refused_dispatch_failed:{resp.status_code}", resp.text[:200])
        return req
