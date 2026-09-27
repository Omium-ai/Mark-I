"""judge_batch (06 §1.2, §6; 16 §L1): the nightly judge dispatch. Per tenant, a task in the
trailing window that carries no vote from a registered E0/E1 judge gets one. An edge judge (C4)
takes the tasks ambiguous under D18 (§6.2 step 1), one JudgeRequest each over controld's fan-out
route, and the customer's own key votes. A cloud judge runs on every task (trigger ALWAYS, 16
§Independence) only under a live m1_065 consent row that admits it (§6.5 preconditions 1-4),
and only on a task whose device's latest m1_082 row keeps cloud_judge on (E1 hunks also need
e1 on; a task no device consent covers never leaves): one router call per task (app/llm.py,
pinned model, capped per tenant-day), the votes re-entering the ledger through the service
ingest route (app/ledger.py) with the token counts booked on judge_dispatches (adj_003,
§6.4). Idempotent per task: a vote in the ledger makes the task a non-candidate; a spent
cloud row is re-posted, never re-called (§7.3.5)."""

import asyncio
import contextlib
import json
import logging
from collections import Counter
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from functools import partial
from typing import Any
from uuid import UUID

import asyncpg
import httpx
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
    EvidenceReader,
    admit,
    device_tiers,
    judge_vote,
    pg_consent_reader,
    task_tiers,
    vote_from,
)
from app.judges.evidence import PerTask, e1_reader
from app.judges.specs import (
    JUDGE_SPECS,
    ClientSideJudge,
    JudgeRefused,
    JudgeSpec,
    at_tier,
    request_id_for,
)
from app.llm import Completion, RouterClient, RouterRefused, reserve_today
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
    tier: str | None = None  # the evidence tier the cloud vote was cast on


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
    """06 §6.2 step 1: fused 'refused' (a clean task's clique caps near 0.71, never 0.89's
    satisfied) or within is_candidate's D18 margin, not yet voted on by this judge."""
    out = []
    for task_id, votes in tasks.items():
        if not lacks_vote_from(votes, judge_id):
            continue
        fused, _ = split_shadow(votes, shadow)
        event = adjudicate(fused, bundle, costs, cert_id)
        if event.verdict == "refused" or is_candidate(event.posterior[0], costs):
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
            "cache_read_input_tokens, evidence_tier FROM judge_dispatches "
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
    """The C4 default. A controld 5xx on one task is retried once then a counted skip; every
    task failing (controld down) fails the run, it does not silently skip a night. The
    request_id is the edge's dedupe key, so the nightly repost of a task still lacking its
    vote is the recovery the SSE hub has no replay for."""
    out, guard = [], PerTask(judge_batch_skipped_total, "controld_unavailable")
    for task_id in candidates:
        session = sessions.get(task_id)
        if session is None:
            judge_batch_skipped_total["no_session_id"] += 1
            continue
        req, ok = await guard(
            partial(judge.run, tenant, spec.judge_id, task_id, NO_ATTEMPT, session)
        )
        if ok:
            out.append(
                Dispatch(task_id, spec.judge_id, UUID(req.request_id), "client_side", window_start)
            )
    guard.check()
    return out


def _from_row(spec: JudgeSpec, row: Mapping[str, Any]) -> Dispatch:
    tier = row.get("evidence_tier") or spec.evidence_tier
    return Dispatch(
        UUID(str(row["task_id"])),
        spec.judge_id,
        UUID(str(row["request_id"])),
        "cloud",
        row["window_start"],
        vote=judge_vote(at_tier(spec, tier), Verdict[str(row["vote"]).upper()]),
        model=row["model"],
        batch_id=row["batch_id"],
        usage={c: int(row[c]) for c in USAGE_COLUMNS},
        spent=True,
        tier=tier,
    )


async def evidence_of(
    spec: JudgeSpec,
    task_id: UUID,
    task_rows: Mapping[UUID, list[Mapping[str, Any]]],
    evidence_for: EvidenceReader | None,
) -> tuple[JudgeSpec, str] | None:
    """The spec as it judges this task and what it reads: E1 hunks when receipted ones exist,
    else the E0 anchor facts on the E0 rubric (tier_used=E0), else nothing to judge."""
    if spec.evidence_tier == "E1" and evidence_for is not None:
        try:
            return spec, await evidence_for(task_id, NO_ATTEMPT, "E1")
        except JudgeRefused as exc:
            judge_batch_skipped_total[f"e1_{exc.reason.split(':', 1)[0]}"] += 1
    e0 = at_tier(spec, "E0")
    if e0.evidence_tier != "E0":
        judge_batch_skipped_total["cloud_no_evidence_reader"] += 1
        return None
    facts = e0_evidence(task_rows.get(task_id, ()))
    if facts == "[]":
        judge_batch_skipped_total["cloud_no_evidence"] += 1  # no anchor ran: nothing to read
        return None
    return e0, facts


def usage_of(reply: Completion) -> dict[str, int]:
    """The four counters 06 §6.4 books as verifier spend v; the router has no cache-write count."""
    return {
        "input_tokens": reply.input_tokens,
        "output_tokens": reply.output_tokens,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": reply.cached_tokens,
    }


async def cloud(
    router: RouterClient,
    spec: JudgeSpec,
    candidates: Iterable[UUID],
    sessions: Mapping[UUID, UUID],
    task_rows: Mapping[UUID, list[Mapping[str, Any]]],
    evidence_for: EvidenceReader | None,
    spent: Mapping[tuple[UUID, str], dict],
    window_start: datetime,
    cap: int,
    reserve: Callable[[int], Awaitable[int]],
    tiers: Mapping[UUID, str],
) -> list[Dispatch]:
    """06 §6.5 under an admitted consent: one router call per candidate not already spent and
    admitted by its devices' consent (`tiers`, task_tiers: E0 facts only, or E1 hunks too), at
    most `cap` per run and what `reserve` grants of the tenant's UTC-day ledger (m1_101); a
    refused, blocked or off-model reply is a counted skip the next night retries."""
    out, pending, guard = [], [], PerTask(judge_batch_skipped_total, "cloud_controld_unavailable")
    for task_id in candidates:
        if task_id not in sessions:
            judge_batch_skipped_total["no_session_id"] += 1
            continue
        row = spent.get((task_id, spec.judge_id))
        if row is not None:
            out.append(_from_row(spec, row))
            continue
        tier = tiers.get(task_id)
        if tier is None:
            judge_batch_skipped_total["cloud_device_not_consented"] += 1
            continue
        if len(pending) == cap:
            judge_batch_skipped_total["cloud_run_cap"] += 1
            continue
        judged, _ = await guard(
            partial(evidence_of, spec, task_id, task_rows, evidence_for if tier == "E1" else None)
        )
        if judged is not None:
            pending.append((task_id, request_id_for(spec.judge_id, task_id, NO_ATTEMPT), *judged))
    guard.check()
    granted = await reserve(len(pending))
    judge_batch_skipped_total["cloud_daily_cap"] += len(pending) - granted
    pending = pending[:granted]
    replies = await asyncio.gather(
        *(router.complete(s.model, s.rubric, e, s.token_budget) for _, _, s, e in pending),
        return_exceptions=True,
    )
    for (task_id, request_id, task_spec, _), reply in zip(pending, replies, strict=True):
        if isinstance(reply, RouterRefused):
            judge_batch_skipped_total[reply.reason.split(":", 1)[0]] += 1
            continue
        if isinstance(reply, BaseException):
            raise reply
        out.append(
            Dispatch(
                task_id,
                spec.judge_id,
                UUID(request_id),
                "cloud",
                window_start,
                vote=vote_from(task_spec, reply),
                model=reply.model,
                usage=usage_of(reply),
                tier=task_spec.evidence_tier,
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
                "cache_creation_input_tokens, cache_read_input_tokens, evidence_tier) "
                "VALUES ($1, $2, $3, $4, $5, $6, $7::verdict, $8, $9, $10, $11, $12, $13, $14) "
                "ON CONFLICT (tenant_id, task_id, judge_id) DO UPDATE SET "
                "request_id = EXCLUDED.request_id, window_start = EXCLUDED.window_start, "
                "locus = EXCLUDED.locus, vote = EXCLUDED.vote, model = EXCLUDED.model, "
                "batch_id = EXCLUDED.batch_id, input_tokens = EXCLUDED.input_tokens, "
                "output_tokens = EXCLUDED.output_tokens, "
                "cache_creation_input_tokens = EXCLUDED.cache_creation_input_tokens, "
                "cache_read_input_tokens = EXCLUDED.cache_read_input_tokens, "
                "evidence_tier = EXCLUDED.evidence_tier, dispatched_at = now()",
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
                d.tier,
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
) -> None:
    """Scheduler target `app.jobs.judge_batch:run`. `evidence_for` is the E1 reader seam,
    controld's attach store under ADJ_EVIDENCE_TOKEN by default (app/judges/evidence.py; unset,
    no E1 read at all): a task with no served E1 part falls back to E0 anchor facts and votes
    tier_used=E0. The cloud judge calls
    LLM_ROUTER_URL; unset, a consented tenant's night is a counted skip."""
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
        e1_token = settings.evidence_token.get_secret_value()
        if evidence_for is None and e1_token:
            evidence_for = e1_reader(client, settings.querychoke_base_url, e1_token, tenant)
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
            tiers = task_tiers(task_rows, await device_tiers(conn, ctx.tenant_id))
            edge = ClientSideJudge(client, settings.querychoke_base_url, bearer)
            router = (
                RouterClient(client, settings.llm_router_url) if settings.llm_router_url else None
            )
            dispatches: list[Dispatch] = []
            for spec in JUDGE_SPECS.values():
                if spec.evidence_tier == "E2":
                    continue  # 06 §6.5: no E2 branch, at either locus
                if spec.locus == "edge":
                    candidates = select(tasks, shadow, bundle, costs, cert_id, spec.judge_id)
                    dispatches += await client_side(
                        edge, tenant, spec, candidates, sessions, ctx.window_start
                    )
                    continue
                # 16 §Independence: the cloud judge runs on every task it can, never on ambiguity
                candidates = [t for t, vs in tasks.items() if lacks_vote_from(vs, spec.judge_id)]
                consent = await consent_for(tenant, spec.judge_id)
                if consent is None:
                    continue  # no consent: the cloud judge does not run for this tenant
                if consent.max_tier == "E0":
                    spec = at_tier(spec, "E0")  # an E0 consent admits the E0 fallback, never E1
                try:
                    admit(spec, consent)
                except JudgeRefused as exc:
                    judge_batch_skipped_total[f"cloud_{exc.reason.split(':', 1)[0]}"] += 1
                    log.warning("judge_batch %s %s: %s", ctx.tenant_id, spec.judge_id, exc)
                    continue
                if router is None:
                    judge_batch_skipped_total["cloud_no_router"] += 1
                    log.warning(
                        "judge_batch %s %s: LLM_ROUTER_URL unset", ctx.tenant_id, spec.judge_id
                    )
                    continue
                dispatches += await cloud(
                    router,
                    spec,
                    candidates,
                    sessions,
                    task_rows,
                    evidence_for,
                    spent,
                    ctx.window_start,
                    settings.judge_max_tasks_per_run,
                    partial(
                        reserve_today,
                        conn,
                        ctx.tenant_id,
                        spec.judge_id,
                        cap=settings.judge_max_tasks_per_day,
                    ),
                    tiers,
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
