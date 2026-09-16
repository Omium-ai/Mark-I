"""readjudicate (06 §1.2): the nightly escalation caller. Per tenant, the trailing window's
ledger votes are fused once at the provisional stage; tasks inside the D18 margin of a Chow
band edge (06 §6.2 step 1) are escalated: the T2 reward model votes in shadow (06 §12.4 row
2), the repo's declared test anchor re-runs as a T3 certified run under the t3:e2b@1 consent,
and adjudicate(..., escalation=True) fuses everything (FR-VERIFY-017). The adjudicated
VerdictEvents re-enter the ledger through controld's service ingest route (app/ledger.py)
before the rows land in escalations (adj_002); promotion.step reads the shadow pairs back out."""

import contextlib
import json
import logging
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import timedelta
from decimal import Decimal
from typing import Any
from uuid import UUID

import asyncpg
import httpx
from pydantic import ValidationError

from app import ledger
from app.adjudicate.algorithm import VerdictEvent, adjudicate
from app.adjudicate.chow import Costs
from app.adjudicate.likelihoods import CALIBRATED_CONFUSION, KIND_TO_GROUP, Bundle, VerifierParams
from app.certified.e2b import E2BClient, E2BSettings
from app.certified.runner import (
    TEST_ANCHORS,
    ArchiveReader,
    CertifiedRunner,
    pg_run_recorder,
    pg_t3_consent_reader,
)
from app.certs.state_machine import CERTIFIED
from app.certs.store import current_cert
from app.choke import run_template
from app.db import set_local_tenant
from app.jobs.nightly import SPECTRAL_WINDOW_DAYS, VOTES_TEMPLATE, _spectral_run
from app.judges.cloud_path import EvidenceReader, pg_consent_reader
from app.judges.specs import JudgeRefused
from app.registry.catalog import RegistryEntry, entry_from_row, list_verifiers
from app.registry.handlers import _KIND_TIER, KIND_CONSISTENCY, NormalizedVote, normalize_votes
from app.registry.integrity import IntegrityFlags
from app.registry.promotion import Measurement, ShadowPair, shadow_ids, split_shadow, youden
from app.rm.scorer import RewardScorer, RmSettings, shadow_fuse, to_raw_vote

log = logging.getLogger("adjudicator.readjudicate")

MARGIN = 0.10  # D18 (06 §6.2 step 1): escalate iff fused |eta - band edges| < margin
NO_ATTEMPT = UUID(int=0)  # 07 §2: Event carries task_id only; the ledger has no attempt id
_FAMILY_KIND = {"JudgeVote": "judge", "RmScore": "rm", "ConsistencyVote": "consistency"}
_WIRE = {"satisfied": "accept", "violated": "reject", "refused": "abstain", "error": "abstain"}
_UNWIRE = {"accept": "satisfied", "reject": "violated"}

readjudicate_skipped_total: Counter[str] = Counter()


@dataclass(frozen=True)
class Escalation:
    task_id: UUID
    eta: float
    provisional: str
    event: VerdictEvent
    consistency_fused: int
    agreement_rate: float | None
    certified_run_id: UUID | None
    t3_skipped: str | None
    rm_verifier_id: str | None
    rm_vote: str | None
    rm_skipped: str | None


def is_candidate(eta: float, costs: Costs, margin: float = MARGIN) -> bool:
    lo, hi = costs.band
    return min(abs(eta - lo), abs(eta - hi)) < margin


def _kind(row: dict[str, Any], registry: dict[str, RegistryEntry]) -> str | None:
    entry = registry.get(str(row["verifier_id"]))
    if entry is not None:
        return entry.kind
    if row["family"] == "AnchorVote":
        # ponytail: unlisted anchor = the wide lint row, never the clamp; kind lives in m1_verifiers
        return "test" if row["verifier_id"] in TEST_ANCHORS else "lint"
    return _FAMILY_KIND.get(str(row["family"]))


def votes_by_task(
    rows: list[dict[str, Any]], registry: dict[str, RegistryEntry]
) -> dict[UUID, list[NormalizedVote]]:
    """`adjudication_votes` rows (task, epoch, seq order) → the latest vote per (task, verifier);
    '' (RmScore: no calibration_version on the wire) and unresolvable kinds are counted, never
    voted."""
    latest: dict[tuple[UUID, str], NormalizedVote] = {}
    for r in rows:
        vote, kind = _WIRE.get(str(r["vote"])), _kind(r, registry)
        if vote is None or kind is None:
            readjudicate_skipped_total[f"vote_unusable:{r['family']}"] += 1
            continue
        task = UUID(str(r["task_id"]))
        latest[task, str(r["verifier_id"])] = NormalizedVote(
            verifier_id=str(r["verifier_id"]),
            kind=kind,
            task_id=task,
            attempt_id=NO_ATTEMPT,
            vote=vote,  # type: ignore[arg-type]
            evidence_digest=b"",
            integrity=IntegrityFlags(tamper=bool(r["tamper"]), infra_failed=r["vote"] == "error"),
            tier=_KIND_TIER[kind],
        )
    out: dict[UUID, list[NormalizedVote]] = {}
    for (task, _vid), v in latest.items():
        out.setdefault(task, []).append(v)
    return out


def sessions_by_task(rows: list[dict[str, Any]]) -> dict[UUID, UUID]:
    """The session each task's votes rode on — the ledger identity a re-entered verdict must
    carry (gold_vs_verdict joins on it). Absent until adjudication_votes serves session_id."""
    out: dict[UUID, UUID] = {}
    for r in rows:
        if r.get("session_id"):
            out[UUID(str(r["task_id"]))] = UUID(str(r["session_id"]))
    return out


def bundle_for(votes: Iterable[NormalizedVote], spectral: dict[str, Any] | None) -> Bundle:
    """The window's spectral laws (06 §4, [satisfied, violated] rows) over the calibrated
    defaults; the estimator is binary-latent, so refused/error rows stay at the prior."""
    laws = spectral["confusion"] if spectral and spectral["passed"] else {}
    verifiers = {}
    for v in votes:
        law = laws.get(v.verifier_id)
        if law is None or v.verifier_id in verifiers:
            continue
        default = CALIBRATED_CONFUSION[v.kind]
        verifiers[v.verifier_id] = VerifierParams(
            v.verifier_id,
            v.kind,
            (tuple(law[0]), tuple(law[1]), default[2], default[3]),
            KIND_TO_GROUP[v.kind],
            "spectral",
        )
    return Bundle(verifiers=verifiers, calibrated_defaults=True)


def registry_by_wire_id(entries: Iterable[RegistryEntry]) -> dict[str, RegistryEntry]:
    """shadow_ids' `key@version` keying, plus the key itself when it already IS a wire id
    (`ruff@cat-1`, `t3:pytest@cat-1`) — no catalog publisher has pinned anchor keys yet."""
    out: dict[str, RegistryEntry] = {}
    for e in entries:
        out[f"{e.verifier_key}@{e.version}"] = e
        if "@" in e.verifier_key:
            out.setdefault(e.verifier_key, e)
    return out


def _edge_verdict(v: NormalizedVote) -> str:
    return _UNWIRE.get(v.vote) or ("error" if v.integrity.infra_failed else "refused")


def _scorer(
    http: httpx.AsyncClient, pool: asyncpg.Pool, evidence_for: EvidenceReader | None
) -> RewardScorer | None:
    if evidence_for is None:
        return None
    try:
        settings = RmSettings()
    except ValidationError:
        return None
    return RewardScorer(settings, http, pg_consent_reader(pool), evidence_for)


def _runner(
    http: httpx.AsyncClient,
    pool: asyncpg.Pool,
    archive_for: ArchiveReader | None,
    registry: dict[str, RegistryEntry],
) -> CertifiedRunner | None:
    if archive_for is None:
        return None
    try:
        settings = E2BSettings()
    except ValidationError:
        return None
    return CertifiedRunner(
        E2BClient(http, settings),
        pg_t3_consent_reader(pool),
        archive_for,
        pg_run_recorder(pool),
        registry,
        settings.template,
        settings.region,
    )


async def escalate(
    tenant_id: UUID,
    task_id: UUID,
    fused: list[NormalizedVote],
    provisional: VerdictEvent,
    bundle: Bundle,
    costs: Costs,
    cert_id: str,
    scorer: RewardScorer | None,
    runner: CertifiedRunner | None,
    registry: dict[str, RegistryEntry],
) -> Escalation:
    """One escalation: T3 under consent, the RM in shadow, then the escalation-stage fusion.
    Every failure is a counted reason on the row; nothing is ever imputed."""
    t3_votes: list[NormalizedVote] = []
    run, t3_skipped = None, None
    anchor = min(
        (v for v in fused if v.verifier_id in TEST_ANCHORS),
        key=lambda v: v.verifier_id,
        default=None,
    )
    if anchor is None:
        t3_skipped = "t3_no_test_anchor"
    elif runner is None:
        t3_skipped = "t3_no_archive_reader"
    else:
        try:
            run = await runner.run(
                tenant_id,
                task_id,
                NO_ATTEMPT,
                anchor.verifier_id,
                "E1",
                _edge_verdict(anchor),
                provisional.verdict,
            )
        except JudgeRefused as exc:
            t3_skipped = f"t3_refused:{exc.reason}"
        else:
            t3_votes = run.votes
            for r in run.refusals:
                readjudicate_skipped_total[f"t3_vote_{r.reason}"] += 1

    rm_vote, rm_skipped = None, "rm_no_scorer"
    if scorer is not None:
        score = await scorer.score(tenant_id, task_id, NO_ATTEMPT)
        raw = to_raw_vote(score, task_id, NO_ATTEMPT, b"") if score else None
        if raw is None:
            rm_skipped = "rm_refused"
        else:
            rm_votes, refusals = await normalize_votes([raw], registry)
            rm_vote = rm_votes[0] if rm_votes else None
            rm_skipped = None if rm_votes else f"rm_{refusals[0].reason}"
    if rm_skipped:
        readjudicate_skipped_total[rm_skipped] += 1
    if t3_skipped:
        readjudicate_skipped_total[":".join(t3_skipped.split(":")[:2])] += 1

    votes = [*fused, *t3_votes]
    if rm_vote is None:
        event = adjudicate(votes, bundle, costs, cert_id, escalation=True)
    else:
        event, _pair = shadow_fuse(votes, rm_vote, bundle, costs, cert_id, escalation=True)
    consistency = sum(1 for v in votes if v.kind == KIND_CONSISTENCY)
    return Escalation(
        task_id=task_id,
        eta=provisional.posterior[0],
        provisional=provisional.verdict,
        event=event,
        consistency_fused=consistency - event.consistency_excluded,
        agreement_rate=run.consistency.agreement_rate if run else None,
        certified_run_id=run.run_id if run else None,
        t3_skipped=t3_skipped,
        rm_verifier_id=rm_vote.verifier_id if rm_vote else None,
        rm_vote=rm_vote.vote if rm_vote else None,
        rm_skipped=rm_skipped,
    )


async def _upsert(
    conn: asyncpg.Connection, tenant_id: str, window_start: Any, e: Escalation
) -> None:
    async with conn.transaction():
        await set_local_tenant(conn, tenant_id)
        await conn.execute(
            "INSERT INTO escalations (tenant_id, task_id, window_start, eta, provisional, verdict, "
            "stage, posterior, provenance, noise_cert_id, vote_count, consistency_fused, "
            "consistency_excluded, agreement_rate, certified_run_id, t3_skipped, rm_verifier_id, "
            "rm_vote, rm_skipped) "
            "VALUES ($1, $2, $3, $4, $5::verdict, $6::verdict, $7, $8, $9, $10, $11, $12, $13, "
            "$14, $15, $16, $17, $18, $19) "
            "ON CONFLICT (tenant_id, task_id) DO UPDATE SET window_start = EXCLUDED.window_start, "
            "eta = EXCLUDED.eta, provisional = EXCLUDED.provisional, verdict = EXCLUDED.verdict, "
            "stage = EXCLUDED.stage, posterior = EXCLUDED.posterior, "
            "provenance = EXCLUDED.provenance, noise_cert_id = EXCLUDED.noise_cert_id, "
            "vote_count = EXCLUDED.vote_count, consistency_fused = EXCLUDED.consistency_fused, "
            "consistency_excluded = EXCLUDED.consistency_excluded, "
            "agreement_rate = EXCLUDED.agreement_rate, "
            "certified_run_id = EXCLUDED.certified_run_id, t3_skipped = EXCLUDED.t3_skipped, "
            "rm_verifier_id = EXCLUDED.rm_verifier_id, rm_vote = EXCLUDED.rm_vote, "
            "rm_skipped = EXCLUDED.rm_skipped, created_at = now()",
            UUID(tenant_id),
            e.task_id,
            window_start,
            Decimal(f"{e.eta:.6f}"),
            e.provisional,
            e.event.verdict,
            e.event.stage,
            list(e.event.posterior),
            e.event.provenance,
            UUID(e.event.noise_cert_id) if e.event.noise_cert_id else None,
            e.event.vote_count,
            e.consistency_fused,
            e.event.consistency_excluded,
            None if e.agreement_rate is None else Decimal(f"{e.agreement_rate:.6f}"),
            e.certified_run_id,
            e.t3_skipped,
            e.rm_verifier_id,
            e.rm_vote,
            e.rm_skipped,
        )


async def run(
    ctx: Any,
    *,
    http: httpx.AsyncClient | None = None,
    evidence_for: EvidenceReader | None = None,
    archive_for: ArchiveReader | None = None,
) -> None:
    """Scheduler target `app.jobs.readjudicate:run`. `evidence_for` (RM evidence) and
    `archive_for` (the E1 worktree tar) are reader seams: no choke template serves either
    today, so without them the RM and T3 legs are counted skips, never imputed votes."""
    settings = ctx.settings
    if not settings.querychoke_base_url:
        raise RuntimeError("ADJ_QUERYCHOKE_BASE_URL is unset: readjudicate has no ledger read path")
    window = {
        "from": (ctx.day - timedelta(days=SPECTRAL_WINDOW_DAYS - 1)).isoformat(),
        "to": ctx.day.isoformat(),
    }
    tenant = UUID(ctx.tenant_id)
    own = (
        contextlib.nullcontext(http) if http else httpx.AsyncClient(timeout=settings.http_timeout_s)
    )
    async with own as client:
        rows = await run_template(
            client,
            settings.querychoke_base_url,
            VOTES_TEMPLATE,
            window,
            bearer=settings.querychoke_token.get_secret_value(),
        )
        registry = registry_by_wire_id(await list_verifiers(ctx.pool))
        cert = await current_cert(ctx.pool, ctx.tenant_id)
        cert_id = str(cert.id) if cert.status == CERTIFIED else ""
        async with ctx.pool.acquire() as conn:
            shadow = await shadow_ids(conn, ctx.tenant_id)
            async with conn.transaction():
                await set_local_tenant(conn, ctx.tenant_id)
                spectral = await _spectral_run(conn, ctx.tenant_id, ctx.window_start)
                done = {
                    r["task_id"]
                    for r in await conn.fetch(
                        "SELECT task_id FROM escalations WHERE tenant_id = $1 "
                        "AND certified_run_id IS NOT NULL",
                        tenant,
                    )
                }
            tasks = votes_by_task(rows, registry)
            sessions = sessions_by_task(rows)
            bundle = bundle_for((v for vs in tasks.values() for v in vs), spectral)
            costs = Costs()
            scorer = _scorer(client, ctx.pool, evidence_for)
            runner = _runner(client, ctx.pool, archive_for, registry)
            escalations: list[Escalation] = []
            for task_id, votes in tasks.items():
                fused, _ = split_shadow(votes, shadow)
                provisional = adjudicate(fused, bundle, costs, cert_id)
                if task_id in done or not is_candidate(provisional.posterior[0], costs):
                    continue
                escalations.append(
                    await escalate(
                        tenant,
                        task_id,
                        fused,
                        provisional,
                        bundle,
                        costs,
                        cert_id,
                        scorer,
                        runner,
                        registry,
                    )
                )
            # The ledger write comes first: a failed POST fails the run before any row marks
            # the task done, so the retry re-derives the same event_ids and re-POSTs them.
            wire = [
                ledger.verdict_wire(
                    e.event,
                    provisional=e.provisional,
                    tenant_id=tenant,
                    task_id=e.task_id,
                    session_id=sessions[e.task_id],
                    window_start=ctx.window_start,
                    bundle_seq=int(ctx.window_start.timestamp()) if spectral else 0,
                )
                for e in escalations
                if e.task_id in sessions
            ]
            readjudicate_skipped_total["ingest_no_session_id"] += len(escalations) - len(wire)
            if wire:
                await ledger.post_verdicts(
                    client,
                    settings.querychoke_base_url,
                    settings.querychoke_token.get_secret_value(),
                    tenant,
                    wire,
                )
            for e in escalations:
                await _upsert(conn, ctx.tenant_id, ctx.window_start, e)
    log.info(
        "readjudicate %s %s: %d tasks, %d escalated, %d re-entered, skips=%s",
        ctx.tenant_id,
        ctx.day,
        len(tasks),
        len(escalations),
        len(wire),
        dict(readjudicate_skipped_total),
    )
    return None


async def measured_pairs(conn: asyncpg.Connection, tenant_id: str) -> dict[UUID, Measurement]:
    """escalations rows → 06 §12.4 row-2 pairs per promotion head; the bar is the incumbent's
    prior Youden, or 0 (abstain-always, m1_069) when the head augments the ensemble."""
    async with conn.transaction():
        await set_local_tenant(conn, tenant_id)
        heads = await conn.fetch(
            "SELECT p.id, v.verifier_key || '@' || v.version AS vid, i.id AS inc_id, "
            "i.verifier_key AS inc_key, i.version AS inc_version, i.kind AS inc_kind, "
            "i.definition::text AS inc_definition, i.effective_execution_hash AS inc_hash, "
            "i.retired_at AS inc_retired "
            "FROM m1_verifier_promotions p JOIN m1_verifiers v ON v.id = p.verifier_id "
            "LEFT JOIN m1_verifiers i ON i.id = p.incumbent_verifier_id WHERE p.tenant_id = $1",
            UUID(tenant_id),
        )
        rows = await conn.fetch(
            "SELECT rm_verifier_id, rm_vote, verdict::text AS verdict, noise_cert_id "
            "FROM escalations WHERE tenant_id = $1 AND rm_vote IS NOT NULL",
            UUID(tenant_id),
        )
    pairs: dict[str, list[ShadowPair]] = {}
    for r in rows:
        pairs.setdefault(r["rm_verifier_id"], []).append(
            ShadowPair(r["rm_vote"], r["verdict"], str(r["noise_cert_id"] or ""))
        )
    out: dict[UUID, Measurement] = {}
    for h in heads:
        if h["vid"] not in pairs:
            continue
        bar = 0.0
        if h["inc_id"] is not None:
            inc = entry_from_row(
                {
                    "id": h["inc_id"],
                    "verifier_key": h["inc_key"],
                    "version": h["inc_version"],
                    "kind": h["inc_kind"],
                    "definition": json.loads(h["inc_definition"]),
                    "effective_execution_hash": h["inc_hash"],
                    "retired_at": h["inc_retired"],
                }
            )
            bar = youden(CALIBRATED_CONFUSION[inc.kind])  # type: ignore[index]
        out[h["id"]] = Measurement(pairs[h["vid"]], bar)
    return out
