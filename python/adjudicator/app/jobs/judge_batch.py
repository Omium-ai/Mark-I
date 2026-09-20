"""judge_batch (06 §1.2, §6): the nightly judge dispatch. Per tenant, a task in the trailing
window that is ambiguous under D18 (§6.2 step 1) and carries no vote from a registered E0/E1
judge gets one. The default locus is the edge (C4): one JudgeRequest per task rides controld's
fan-out route and the customer's own key votes. Under a live m1_065 consent row that admits the
judge (§6.5 preconditions 1-4) the cloud path runs instead: one Anthropic Batch per (tenant,
judge), region-pinned, the votes re-entering the ledger through the service ingest route
(app/ledger.py) with the token counts booked on judge_dispatches (adj_003, §6.4). Idempotent
per task: a vote in the ledger makes the task a non-candidate; a spent cloud row is re-posted,
never re-called (§7.3.5)."""

import contextlib
import json
import logging
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

import asyncpg
import httpx
from anthropic import AsyncAnthropic
from m1p.v1 import Event, JudgeVote, Verdict

from app import ledger
from app.adjudicate.algorithm import adjudicate
from app.adjudicate.chow import Costs
from app.adjudicate.likelihoods import Bundle
from app.certs.state_machine import CERTIFIED
from app.certs.store import current_cert
from app.choke import run_template
from app.db import set_local_tenant
from app.jobs.nightly import SPECTRAL_WINDOW_DAYS, VOTES_TEMPLATE, _spectral_run
from app.jobs.readjudicate import (
    NO_ATTEMPT,
    bundle_for,
    is_candidate,
    registry_by_wire_id,
    sessions_by_task,
    votes_by_task,
)
from app.judges.cloud_path import (
    AnthropicBatchRunner,
    BatchRunner,
    EvidenceReader,
    admit,
    batch_request,
    judge_vote,
    pg_consent_reader,
    usage_of,
    vote_from,
)
from app.judges.specs import JUDGE_SPECS, ClientSideJudge, JudgeRefused, JudgeSpec, request_id_for
from app.registry.catalog import list_verifiers
from app.registry.handlers import NormalizedVote
from app.registry.promotion import shadow_ids, split_shadow

log = logging.getLogger("adjudicator.judge_batch")

USAGE_COLUMNS = (
    "input_tokens",
    "output_tokens",
    "cache_creation_input_tokens",
    "cache_read_input_tokens",
)

judge_batch_skipped_total: Counter[str] = Counter()


@dataclass(frozen=True)
class Dispatch:
    task_id: UUID
    judge_id: str
    request_id: UUID
    locus: str
    window_start: datetime
    vote: JudgeVote | None = None
    model: str | None = None
    batch_id: str | None = None
    usage: Mapping[str, int] = field(default_factory=dict)
    spent: bool = False


def lacks_vote_from(votes: Iterable[NormalizedVote], judge_id: str) -> bool:
    return all(v.verifier_id != judge_id for v in votes)


def select(
    tasks: Mapping[UUID, list[NormalizedVote]],
    shadow: set[str],
    bundle: Bundle,
    costs: Costs,
    cert_id: str,
    judge_id: str,
) -> list[UUID]:
    """06 §6.2 step 1 for one judge: ambiguous under D18 and not yet voted on by it."""
    out = []
    for task_id, votes in tasks.items():
        if not lacks_vote_from(votes, judge_id):
            continue
        fused, _ = split_shadow(votes, shadow)
        if is_candidate(adjudicate(fused, bundle, costs, cert_id).posterior[0], costs):
            out.append(task_id)
    return out


def e0_evidence(rows: Iterable[Mapping[str, Any]]) -> str:
    """06 §6.2's E0 row: typed anchor facts only — id, vote, integrity. No paths, no text."""
    # ponytail: the vote grain; EvidenceRecord fields need a choke template serving the payload
    return json.dumps(
        [
            {"anchor": str(r["verifier_id"]), "vote": str(r["vote"]), "tamper": bool(r["tamper"])}
            for r in rows
            if r["family"] == "AnchorVote"
        ],
        sort_keys=True,
    )


async def spent_rows(conn: asyncpg.Connection, tenant_id: str) -> dict[tuple[UUID, str], dict]:
    async with conn.transaction():
        await set_local_tenant(conn, tenant_id)
        rows = await conn.fetch(
            "SELECT task_id, judge_id, request_id, window_start, vote::text AS vote, model, "
            "batch_id, input_tokens, output_tokens, cache_creation_input_tokens, "
            "cache_read_input_tokens FROM judge_dispatches "
            "WHERE tenant_id = $1 AND vote IS NOT NULL",
            UUID(tenant_id),
        )
    return {(UUID(str(r["task_id"])), str(r["judge_id"])): dict(r) for r in rows}


async def client_side(
    judge: ClientSideJudge,
    tenant: UUID,
    spec: JudgeSpec,
    candidates: Iterable[UUID],
    sessions: Mapping[UUID, UUID],
    window_start: datetime,
) -> list[Dispatch]:
    """The C4 default. A refused POST propagates: controld being down fails the run, it does
    not silently skip a night. The request_id is the edge's dedupe key, so the nightly
    repost of a task still lacking its vote is the recovery the SSE hub has no replay for."""
    out = []
    for task_id in candidates:
        session = sessions.get(task_id)
        if session is None:
            judge_batch_skipped_total["no_session_id"] += 1
            continue
        req = await judge.run(tenant, spec.judge_id, task_id, NO_ATTEMPT, session)
        out.append(
            Dispatch(task_id, spec.judge_id, UUID(req.request_id), "client_side", window_start)
        )
    return out


def _from_row(spec: JudgeSpec, row: Mapping[str, Any]) -> Dispatch:
    return Dispatch(
        UUID(str(row["task_id"])),
        spec.judge_id,
        UUID(str(row["request_id"])),
        "cloud",
        row["window_start"],
        vote=judge_vote(spec, Verdict[str(row["vote"]).upper()]),
        model=row["model"],
        batch_id=row["batch_id"],
        usage={c: int(row[c]) for c in USAGE_COLUMNS},
        spent=True,
    )


async def cloud(
    batch: BatchRunner,
    spec: JudgeSpec,
    candidates: Iterable[UUID],
    sessions: Mapping[UUID, UUID],
    task_rows: Mapping[UUID, list[Mapping[str, Any]]],
    evidence_for: EvidenceReader | None,
    spent: Mapping[tuple[UUID, str], dict],
    window_start: datetime,
) -> list[Dispatch]:
    """06 §6.5 under an admitted consent: one Batch for every candidate not already spent;
    a missing, errored or off-region result is a counted skip the next night retries."""
    out, pending = [], []
    for task_id in candidates:
        if task_id not in sessions:
            judge_batch_skipped_total["no_session_id"] += 1
            continue
        row = spent.get((task_id, spec.judge_id))
        if row is not None:
            out.append(_from_row(spec, row))
            continue
        if spec.evidence_tier == "E0":
            evidence = e0_evidence(task_rows.get(task_id, ()))
        elif evidence_for is None:
            judge_batch_skipped_total["cloud_no_evidence_reader"] += 1
            continue
        else:
            evidence = await evidence_for(task_id, NO_ATTEMPT, spec.evidence_tier)
        request_id = request_id_for(spec.judge_id, task_id, NO_ATTEMPT)
        pending.append((task_id, request_id, batch_request(spec, request_id, evidence)))
    if not pending:
        return out
    # ponytail: one batch awaited inline; split into submit/collect halves keyed by batch_id
    # if a batch ever outlives the runner's 2 h lease.
    batch_id, messages = await batch.run([r for _, _, r in pending])
    for task_id, request_id, _ in pending:
        msg = messages.get(request_id)
        if msg is None:
            judge_batch_skipped_total["cloud_result_missing"] += 1
            continue
        try:
            vote = vote_from(spec, msg)
        except JudgeRefused as exc:
            judge_batch_skipped_total[exc.reason.split(":", 1)[0]] += 1
            continue
        out.append(
            Dispatch(
                task_id,
                spec.judge_id,
                UUID(request_id),
                "cloud",
                window_start,
                vote=vote,
                model=spec.model,
                batch_id=batch_id,
                usage=usage_of(msg),
            )
        )
    return out


async def _upsert(conn: asyncpg.Connection, tenant_id: str, dispatches: Iterable[Dispatch]) -> None:
    async with conn.transaction():
        await set_local_tenant(conn, tenant_id)
        for d in dispatches:
            await conn.execute(
                "INSERT INTO judge_dispatches (tenant_id, task_id, judge_id, request_id, "
                "window_start, locus, vote, model, batch_id, input_tokens, output_tokens, "
                "cache_creation_input_tokens, cache_read_input_tokens) "
                "VALUES ($1, $2, $3, $4, $5, $6, $7::verdict, $8, $9, $10, $11, $12, $13) "
                "ON CONFLICT (tenant_id, task_id, judge_id) DO UPDATE SET "
                "request_id = EXCLUDED.request_id, window_start = EXCLUDED.window_start, "
                "locus = EXCLUDED.locus, vote = EXCLUDED.vote, model = EXCLUDED.model, "
                "batch_id = EXCLUDED.batch_id, input_tokens = EXCLUDED.input_tokens, "
                "output_tokens = EXCLUDED.output_tokens, "
                "cache_creation_input_tokens = EXCLUDED.cache_creation_input_tokens, "
                "cache_read_input_tokens = EXCLUDED.cache_read_input_tokens, "
                "dispatched_at = now()",
                UUID(tenant_id),
                d.task_id,
                d.judge_id,
                d.request_id,
                d.window_start,
                d.locus,
                d.vote.vote.name.lower() if d.vote else None,
                d.model,
                d.batch_id,
                *(d.usage.get(c) for c in USAGE_COLUMNS),
            )


def wire(
    tenant: UUID, sessions: Mapping[UUID, UUID], dispatches: Iterable[Dispatch]
) -> list[Event]:
    return [
        ledger.judge_vote_wire(
            d.vote,
            tenant_id=tenant,
            task_id=d.task_id,
            session_id=sessions[d.task_id],
            window_start=d.window_start,
        )
        for d in dispatches
        if d.vote is not None
    ]


async def run(
    ctx: Any,
    *,
    http: httpx.AsyncClient | None = None,
    evidence_for: EvidenceReader | None = None,
    batch: BatchRunner | None = None,
) -> None:
    """Scheduler target `app.jobs.judge_batch:run`. `evidence_for` is the E1 reader seam (no
    choke template serves sanitized hunks to this job yet; E0 renders from the window's own
    anchor votes); `batch` defaults to the Anthropic Batch API under ANTHROPIC_API_KEY, built
    only once a consented cloud dispatch is actually due."""
    settings = ctx.settings
    if not settings.querychoke_base_url:
        raise RuntimeError("ADJ_QUERYCHOKE_BASE_URL is unset: judge_batch has no ledger path")
    window = {
        "from": (ctx.day - timedelta(days=SPECTRAL_WINDOW_DAYS - 1)).isoformat(),
        "to": ctx.day.isoformat(),
    }
    tenant = UUID(ctx.tenant_id)
    bearer = settings.querychoke_token.get_secret_value()
    own = (
        contextlib.nullcontext(http) if http else httpx.AsyncClient(timeout=settings.http_timeout_s)
    )
    async with own as client:
        rows = await run_template(
            client,
            settings.querychoke_base_url,
            VOTES_TEMPLATE,
            window,
            bearer=bearer,
            tenant_id=ctx.tenant_id,
        )
        registry = registry_by_wire_id(await list_verifiers(ctx.pool))
        cert = await current_cert(ctx.pool, ctx.tenant_id)
        cert_id = str(cert.id) if cert.status == CERTIFIED else ""
        async with ctx.pool.acquire() as conn:
            shadow = await shadow_ids(conn, ctx.tenant_id)
            spent = await spent_rows(conn, ctx.tenant_id)
            async with conn.transaction():
                await set_local_tenant(conn, ctx.tenant_id)
                spectral = await _spectral_run(conn, ctx.tenant_id, ctx.window_start)
            tasks = votes_by_task(rows, registry)
            sessions = sessions_by_task(rows)
            task_rows: dict[UUID, list[Mapping[str, Any]]] = {}
            for r in rows:
                task_rows.setdefault(UUID(str(r["task_id"])), []).append(r)
            bundle = bundle_for((v for vs in tasks.values() for v in vs), spectral)
            costs = Costs()
            consent_for = pg_consent_reader(ctx.pool)
            edge = ClientSideJudge(client, settings.querychoke_base_url, bearer)
            dispatches: list[Dispatch] = []
            for spec in JUDGE_SPECS.values():
                if spec.evidence_tier == "E2":
                    continue  # 06 §6.5: no E2 branch, at either locus
                candidates = select(tasks, shadow, bundle, costs, cert_id, spec.judge_id)
                consent = await consent_for(tenant, spec.judge_id)
                admitted = False
                if consent is not None:
                    try:
                        admit(spec, consent)
                        admitted = True
                    except JudgeRefused as exc:
                        judge_batch_skipped_total[f"cloud_{exc.reason.split(':', 1)[0]}"] += 1
                        log.warning(
                            "judge_batch %s %s: %s; client-side", ctx.tenant_id, spec.judge_id, exc
                        )
                if admitted:
                    if batch is None:
                        batch = AnthropicBatchRunner(AsyncAnthropic())
                    dispatches += await cloud(
                        batch,
                        spec,
                        candidates,
                        sessions,
                        task_rows,
                        evidence_for,
                        spent,
                        ctx.window_start,
                    )
                else:
                    dispatches += await client_side(
                        edge, tenant, spec, candidates, sessions, ctx.window_start
                    )
            # Row before POST: a retry re-posts the spent vote under the same event_id.
            await _upsert(conn, ctx.tenant_id, (d for d in dispatches if not d.spent))
            events = wire(tenant, sessions, dispatches)
            if events:
                await ledger.post_verdicts(
                    client, settings.querychoke_base_url, bearer, tenant, events
                )
    usage = Counter[str]()
    for d in dispatches:
        if not d.spent:
            usage.update(d.usage)
    log.info(
        "judge_batch %s %s: %d tasks, %d client-side, %d cloud (%d spent), %d posted, "
        "tokens=%s skips=%s",
        ctx.tenant_id,
        ctx.day,
        len(tasks),
        sum(d.locus == "client_side" for d in dispatches),
        sum(d.locus == "cloud" for d in dispatches),
        sum(d.spent for d in dispatches),
        len(events),
        dict(usage),
        dict(judge_batch_skipped_total),
    )
    return None
