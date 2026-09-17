"""The cloud-judge path (06 §6.5) — the ONLY place this service calls a model vendor.

Four hard preconditions, machine-checked at admission, none waivable in code:
(1) a live tenant consent row (m1_065), (2) that row names this judge's subprocessor,
(3) that row names the region the call is pinned to, (4) evidence tier <= the consented
tier, and E2 never — refused before consent is even read. Every failure is a typed
`JudgeRefused`; no vote is ever synthesized around a refusal."""

import asyncio
import hashlib
import logging
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Any, Protocol
from uuid import UUID

import asyncpg
from anthropic import AsyncAnthropic
from anthropic.types import Message
from anthropic.types.message_create_params import MessageCreateParamsNonStreaming
from anthropic.types.messages.batch_create_params import Request
from m1p.v1 import EvidenceTier, JudgeLocus, JudgeVote, Verdict

from app.db import set_local_tenant
from app.judges.specs import TIERS, JudgeSpec, refuse, spec_for

log = logging.getLogger("adjudicator.cloud_path")


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
        # ponytail: one Messages call per task; the nightly Batch API path is jobs/judge_batch.py
        msg = await self._client.messages.create(**message_params(spec, evidence))
        return vote_from(spec, msg)


def message_params(spec: JudgeSpec, evidence: str) -> MessageCreateParamsNonStreaming:
    """The one call shape both cloud loci make: rubric as the cached static prefix (06 §6.3),
    the evidence as the user turn, the region pinned (§6.5 precondition 3)."""
    return MessageCreateParamsNonStreaming(
        model=spec.model,
        max_tokens=spec.token_budget,
        system=[{"type": "text", "text": spec.rubric, "cache_control": {"type": "ephemeral"}}],
        messages=[{"role": "user", "content": evidence}],
        inference_geo=spec.region,
    )


def vote_from(spec: JudgeSpec, msg: Message) -> JudgeVote:
    """A served region other than the pinned one is a refusal, never a vote."""
    served = msg.usage.inference_geo
    if served is not None and served != spec.region:
        raise refuse(f"refused_region_mismatch:{spec.region}", f"served from {served!r}")
    text = "".join(b.text for b in msg.content if b.type == "text")
    return judge_vote(spec, parse_verdict(msg.stop_reason, text))


def judge_vote(spec: JudgeSpec, vote: Verdict) -> JudgeVote:
    return JudgeVote(
        judge_id=spec.judge_id,
        vote=vote,
        tier_used=_TIER[spec.evidence_tier],
        # ponytail: sha256 not HMAC_tenant; no Python resolver for m1_001's hmac salt exists yet
        rubric_hash=hashlib.sha256(spec.rubric.encode()).digest(),
        locus=JudgeLocus.CLOUD,
    )


class BatchRunner(Protocol):
    async def run(self, requests: Sequence[Request]) -> tuple[str, dict[str, Message]]: ...


class AnthropicBatchRunner:
    """intel memory/extract.py's Batch API runner, keeping the whole Message: the job books
    usage (06 §6.4) and reads stop_reason (a refusal IS the judge refusing)."""

    def __init__(self, client: AsyncAnthropic, *, poll_s: float = 60.0) -> None:
        self._client = client
        self._poll_s = poll_s

    async def run(self, requests: Sequence[Request]) -> tuple[str, dict[str, Message]]:
        batch = await self._client.messages.batches.create(requests=list(requests))
        while batch.processing_status != "ended":
            await asyncio.sleep(self._poll_s)
            batch = await self._client.messages.batches.retrieve(batch.id)
        out: dict[str, Message] = {}
        async for r in await self._client.messages.batches.results(batch.id):
            if r.result.type == "succeeded":
                out[r.custom_id] = r.result.message
            else:
                log.warning("batch %s: %s %s", batch.id, r.custom_id, r.result.type)
        return batch.id, out


def batch_request(spec: JudgeSpec, request_id: str, evidence: str) -> Request:
    return Request(custom_id=request_id, params=message_params(spec, evidence))


def usage_of(msg: Message) -> dict[str, Any]:
    """The four counters 06 §6.4 books as verifier spend v (cache_read is §6.3's SLO)."""
    u = msg.usage
    return {
        "input_tokens": u.input_tokens,
        "output_tokens": u.output_tokens,
        "cache_creation_input_tokens": u.cache_creation_input_tokens or 0,
        "cache_read_input_tokens": u.cache_read_input_tokens or 0,
    }
