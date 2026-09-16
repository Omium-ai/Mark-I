"""The cloud-judge path (06 §6.5) — the ONLY place this service calls a model vendor.

Four hard preconditions, machine-checked at admission, none waivable in code:
(1) a live tenant consent row (m1_065), (2) that row names this judge's subprocessor,
(3) that row names the region the call is pinned to, (4) evidence tier <= the consented
tier, and E2 never — refused before consent is even read. Every failure is a typed
`JudgeRefused`; no vote is ever synthesized around a refusal."""

import hashlib
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from uuid import UUID

import asyncpg
from anthropic import AsyncAnthropic
from m1p.v1 import EvidenceTier, JudgeLocus, JudgeVote, Verdict

from app.db import set_local_tenant
from app.judges.specs import TIERS, JudgeSpec, refuse, spec_for


@dataclass(frozen=True)
class Consent:
    """One live m1_cloud_judge_consents row."""

    subprocessor: str
    region: str
    max_tier: str


ConsentReader = Callable[[UUID, str], Awaitable[Consent | None]]
EvidenceReader = Callable[[UUID, UUID, str], Awaitable[str]]


def pg_consent_reader(pool: asyncpg.Pool) -> ConsentReader:
    async def read(tenant_id: UUID, judge_id: str) -> Consent | None:
        async with pool.acquire() as conn, conn.transaction():
            await set_local_tenant(conn, str(tenant_id))
            row = await conn.fetchrow(
                """
                SELECT subprocessor, region, max_tier FROM m1_cloud_judge_consents
                WHERE tenant_id = $1 AND judge_id = $2 AND revoked_at IS NULL
                """,
                tenant_id,
                judge_id,
            )
        return Consent(**dict(row)) if row else None

    return read


def admit(spec: JudgeSpec, consent: Consent | None) -> None:
    """06 §6.5 preconditions (1)-(4). Order matters: E2 is refused structurally, before
    any consent could be read to (mis)permit it."""
    if spec.evidence_tier == "E2":
        raise refuse("refused_tier_e2_never_cloud", "E2 stays inside the customer boundary")
    if consent is None:
        raise refuse("refused_no_cloud_consent", spec.judge_id)
    if consent.subprocessor != spec.subprocessor:
        raise refuse(
            f"refused_subprocessor_not_listed:{spec.subprocessor}",
            f"consent names {consent.subprocessor!r}",
        )
    if consent.region != spec.region:
        raise refuse(f"refused_region_mismatch:{spec.region}", f"consent pins {consent.region!r}")
    if TIERS.index(spec.evidence_tier) > TIERS.index(consent.max_tier):
        raise refuse(
            f"refused_tier_above_consent:{spec.evidence_tier}", f"consented {consent.max_tier}"
        )


_TIER = {"E0": EvidenceTier.E0, "E1": EvidenceTier.E1, "E2": EvidenceTier.E2}


def parse_verdict(stop_reason: str | None, text: str) -> Verdict:
    """Model output → wire verdict. A model refusal IS the judge refusing; anything the
    vocabulary cannot name is the run failing (Paper II's event E), never a guess."""
    if stop_reason == "refusal":
        return Verdict.REFUSED
    word = text.strip().strip("`.").lower()
    try:
        v = Verdict[word.upper()]
    except KeyError:
        return Verdict.ERROR
    return Verdict.ERROR if v == Verdict.UNSPECIFIED else v


class CloudJudge:
    """Runs here, under consent. `consent_for` reads m1_065; `evidence_for` assembles
    the tier-bounded evidence text (E0 typed record / E1 sanitized hunks) — injected
    because the ledger read lives behind controld's query choke, not in this service."""

    locus = JudgeLocus.CLOUD

    def __init__(
        self,
        client: AsyncAnthropic,
        consent_for: ConsentReader,
        evidence_for: EvidenceReader,
        profile: str = "saas",
    ) -> None:
        self._client = client
        self._consent_for = consent_for
        self._evidence_for = evidence_for
        self._profile = profile

    async def run(
        self, tenant_id: UUID, judge_id: str, task_id: UUID, attempt_id: UUID, session_id: UUID
    ) -> JudgeVote:
        spec = spec_for(judge_id, self._profile)
        admit(spec, await self._consent_for(tenant_id, judge_id))
        evidence = await self._evidence_for(task_id, attempt_id, spec.evidence_tier)
        # ponytail: one Messages call per task; Batch API + cascade (06 §6.5) once volume pays
        msg = await self._client.messages.create(
            model=spec.model,
            max_tokens=spec.token_budget,
            system=[{"type": "text", "text": spec.rubric, "cache_control": {"type": "ephemeral"}}],
            messages=[{"role": "user", "content": evidence}],
            inference_geo=spec.region,
        )
        served = msg.usage.inference_geo
        if served is not None and served != spec.region:
            raise refuse(f"refused_region_mismatch:{spec.region}", f"served from {served!r}")
        text = "".join(b.text for b in msg.content if b.type == "text")
        return JudgeVote(
            judge_id=spec.judge_id,
            vote=parse_verdict(msg.stop_reason, text),
            tier_used=_TIER[spec.evidence_tier],
            # ponytail: sha256 not HMAC_tenant; no Python resolver for m1_001's hmac salt exists yet
            rubric_hash=hashlib.sha256(spec.rubric.encode()).digest(),
            locus=JudgeLocus.CLOUD,
        )
