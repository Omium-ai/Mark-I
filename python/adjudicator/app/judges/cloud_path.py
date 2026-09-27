"""The cloud-judge path (06 §6.5): admission for every consent-gated cloud member, and the
router reply → vote step for the cloud judge (16 §L1, app/llm.py makes the call).

Four hard preconditions, machine-checked at admission, none waivable in code:
(1) a live tenant consent row (m1_065), (2) that row names this judge's subprocessor,
(3) that row names the vendor's processing region, (4) evidence tier <= the consented
tier, and E2 never — refused before consent is even read. Every failure is a typed
`JudgeRefused`; no vote is ever synthesized around a refusal. On top of the tenant row, each
task's own device decides whether its evidence may go (m1_082 cloud_judge, e1): `device_tiers`
and `task_tiers` below."""

import hashlib
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any
from uuid import UUID

import asyncpg
from m1p.v1 import EvidenceTier, JudgeLocus, JudgeTrigger, JudgeVote, Verdict

from app.db import set_local_tenant
from app.judges.specs import TIERS, JudgeSpec, refuse
from app.llm import Completion


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


NIL_DEVICE = UUID(int=0)
# controld ingest.ServiceDevice, the stamp on every service batch; test_judges pins it to Go.
SERVICE_DEVICE = UUID("db04ac08-e817-5f51-a555-2aa350c56d33")


async def device_tiers(conn: asyncpg.Connection, tenant_id: str) -> dict[UUID, str]:
    """The highest tier each device lets the cloud judge read, from its LATEST m1_082 row
    (append-only, ordered by row_seq): cloud_judge admits E0 anchor facts, e1 on top admits E1
    hunks. A device whose latest row turns cloud_judge off, or that recorded no row, is absent."""
    async with conn.transaction():
        await set_local_tenant(conn, tenant_id)
        rows = await conn.fetch(
            "SELECT DISTINCT ON (device_id) device_id, e1, cloud_judge FROM m1_device_consents "
            "WHERE tenant_id = $1 ORDER BY device_id, row_seq DESC",
            UUID(tenant_id),
        )
    return {UUID(str(r["device_id"])): "E1" if r["e1"] else "E0" for r in rows if r["cloud_judge"]}


def task_tiers(
    task_rows: Mapping[UUID, Iterable[Mapping[str, Any]]], devices: Mapping[UUID, str]
) -> dict[UUID, str]:
    """task → the highest tier EVERY device that recorded it admits. Service-authored rows
    (nil or ServiceDevice) speak for no device. A task with no device on its rows, or one
    device with no admitting consent, is absent: nothing of it leaves."""
    out = {}
    for task, rows in task_rows.items():
        ids = {UUID(str(r["device_id"])) for r in rows if r.get("device_id")} - {
            NIL_DEVICE,
            SERVICE_DEVICE,
        }
        tiers = {devices.get(d) for d in ids}
        if ids and None not in tiers:
            out[task] = "E1" if tiers == {"E1"} else "E0"
    return out


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
    if stop_reason in ("refusal", "content_filter"):
        return Verdict.REFUSED
    word = text.strip().strip("`.").lower()
    try:
        v = Verdict[word.upper()]
    except KeyError:
        return Verdict.ERROR
    return Verdict.ERROR if v == Verdict.UNSPECIFIED else v


def vote_from(spec: JudgeSpec, reply: Completion) -> JudgeVote:
    """The router already refused a reply served by any model but the pinned one."""
    text = reply.text.rsplit("</think>", 1)[-1]  # a reasoning model's trace is not its answer
    return judge_vote(spec, parse_verdict(reply.finish_reason, text))


def judge_vote(spec: JudgeSpec, vote: Verdict) -> JudgeVote:
    return JudgeVote(
        judge_id=spec.judge_id,
        vote=vote,
        tier_used=_TIER[spec.evidence_tier],
        # ponytail: sha256 not HMAC_tenant; no Python resolver for m1_001's hmac salt exists yet
        rubric_hash=hashlib.sha256(spec.rubric.encode()).digest(),
        locus=JudgeLocus.CLOUD,
        trigger=JudgeTrigger.ALWAYS,  # judge_batch runs the cloud judge on every task it can
    )
