"""The nightly callables: freeze a formed gold set, run SPECTRAL_DS over the ledger's votes, then
recompute every verifier's cert off both."""

import contextlib
import hashlib
import hmac
import json
import logging
import math
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from functools import partial
from typing import Any
from uuid import UUID

import asyncpg
import httpx
import numpy as np
from mark1_receipts import append_server_record

from app.certs.compute import compute_certificate
from app.certs.state_machine import CERTIFIED, GOLD_BOOTSTRAP_MIN, CertEvidence, next_status
from app.certs.store import current_cert, insert_cert
from app.choke import run_template
from app.db import set_local_tenant
from app.gold.rotate import MAX_AGE_DAYS, GoldLabel, fresh_fraction, scoring_window
from app.gold.score import score_agreement
from app.registry.catalog import list_verifiers
from app.spectral.estimate import Estimate, estimate
from app.spectral.moments import ABSTAIN, ACCEPT, REJECT

log = logging.getLogger("adjudicator.jobs")

# querychoke templates.go; rows locked to its testdata/intel_template_rows.json.
VOTES_TEMPLATE = "adjudication_votes"
GOLD_TEMPLATE = "gold_vs_verdict"
# ponytail: trailing window = the D16 30-day freshness horizon; a per-tenant knob later.
SPECTRAL_WINDOW_DAYS = 30
# 06 §4.1 step 1: correlation groups are known by construction from the vote family.
_GROUP = {
    "AnchorVote": "syntactic",
    "JudgeVote": "judges",
    "RmScore": "rms",
    "ConsistencyVote": "consistency",
}
# handlers.py _WIRE_VOTE as codes; anything else ('' on RmScore: no calibration yet) = did not vote.
_CODE = {"satisfied": ACCEPT, "violated": REJECT, "refused": ABSTAIN, "error": ABSTAIN}


async def _latest_set(
    conn: asyncpg.Connection, tenant_id: str, frozen: bool
) -> asyncpg.Record | None:
    return await conn.fetchrow(
        "SELECT id, agent, frozen_at FROM gold_sets WHERE tenant_id = $1 "
        "AND (frozen_at IS NOT NULL) = $2 ORDER BY created_at DESC LIMIT 1",
        UUID(tenant_id),
        frozen,
    )


async def _members(conn: asyncpg.Connection, gold_set_id: UUID) -> list[GoldLabel]:
    rows = await conn.fetch(
        "SELECT task_digest, true_label, labeled_at FROM gold_set_members WHERE gold_set_id = $1",
        gold_set_id,
    )
    return [GoldLabel(r["task_digest"], r["true_label"], r["labeled_at"]) for r in rows]


async def gold_refresh(ctx: Any) -> None:
    """Snapshot each formed open set (§5.3 ≥ 50 labels in the D17 window) into a NEW frozen
    set. certs_recompute cites only the latest frozen set, so the snapshot is what a
    certificate measures against, while the open set keeps accumulating toward the D15 200
    gate; freezing the open set in place capped every set at the night it crossed 50 and the
    gate was unreachable. A night with nothing new mints nothing."""
    now = datetime.now(UTC)
    cutoff = now - timedelta(days=MAX_AGE_DAYS)
    async with ctx.pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, ctx.tenant_id)
        open_sets = await conn.fetch(
            "SELECT id, agent FROM gold_sets WHERE tenant_id = $1 AND frozen_at IS NULL "
            "ORDER BY created_at",
            UUID(ctx.tenant_id),
        )
        for open_set in open_sets:
            window = scoring_window(await _members(conn, open_set["id"]), now)
            if len(window) < GOLD_BOOTSTRAP_MIN:
                log.info(
                    "gold.refresh %s: %s open set has %d labels, nothing to freeze",
                    ctx.tenant_id,
                    open_set["agent"],
                    len(window),
                )
                continue
            frozen = await conn.fetchrow(
                "SELECT id FROM gold_sets WHERE tenant_id = $1 AND agent = $2 "
                "AND frozen_at IS NOT NULL ORDER BY frozen_at DESC LIMIT 1",
                UUID(ctx.tenant_id),
                open_set["agent"],
            )
            if frozen and set(await _members(conn, frozen["id"])) == set(window):
                log.info(
                    "gold.refresh %s: %s unchanged since the last snapshot",
                    ctx.tenant_id,
                    open_set["agent"],
                )
                continue
            new_id = await conn.fetchval(
                "INSERT INTO gold_sets (tenant_id, agent, frozen_at) VALUES ($1, $2, now()) "
                "RETURNING id",
                UUID(ctx.tenant_id),
                open_set["agent"],
            )
            await conn.execute(
                "INSERT INTO gold_set_members "
                "(gold_set_id, tenant_id, task_digest, true_label, label_source, labeled_at) "
                "SELECT $1, tenant_id, task_digest, true_label, label_source, labeled_at "
                "FROM gold_set_members WHERE gold_set_id = $2 AND labeled_at > $3",
                new_id,
                open_set["id"],
                cutoff,
            )
            log.info(
                "gold.refresh %s: froze snapshot %s of %s with %d labels",
                ctx.tenant_id,
                new_id,
                open_set["agent"],
                len(window),
            )
    return None


async def _ledger_pairs(
    ctx: Any, members: list[GoldLabel], *, http: httpx.AsyncClient | None = None
) -> list[tuple[str, str]]:
    """(gold true_label, stage-final fused verdict) per gold task the ledger holds. The choke
    hands back the ledger side only; the join key is m1_021's task_digest = HMAC-SHA256(tenant
    root, session_id ‖ task_id) (intel corpus/export.py task_digest, the one definition), the
    root HKDF-SHA256(pepper, info=mark1-tenant-root-v1:<tenant>) as controld enroll.TenantRoot.
    No pepper ⇒ [] = unmeasured, which no status transition can read as agreement."""
    pepper = getattr(ctx.settings, "tenant_hmac_pepper", None)
    if not members or not pepper:
        if members:
            log.warning("certs.recompute %s: no tenant_hmac_pepper, unmeasured", ctx.tenant_id)
        return []
    prk = hmac.new(b"\x00" * 32, bytes.fromhex(pepper), hashlib.sha256).digest()
    info = f"mark1-tenant-root-v1:{UUID(ctx.tenant_id)}".encode()
    root = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
    settings = ctx.settings
    # ponytail: tasks complete before they are labeled; 2×D17 covers a label at the window edge.
    window = {
        "from": (ctx.day - timedelta(days=2 * MAX_AGE_DAYS)).isoformat(),
        "to": ctx.day.isoformat(),
    }
    own = (
        contextlib.nullcontext(http) if http else httpx.AsyncClient(timeout=settings.http_timeout_s)
    )
    async with own as client:
        rows = await run_template(
            client,
            settings.querychoke_base_url,
            GOLD_TEMPLATE,
            window,
            bearer=settings.querychoke_token.get_secret_value(),
        )
    verdict = {
        hmac.new(
            root, UUID(str(r["session_id"])).bytes + UUID(str(r["task_id"])).bytes, hashlib.sha256
        ).digest(): str(r["fused_verdict"])
        for r in rows
        if r["verdict_stage"] in ("certified", "revised")
    }
    return [(m.true_label, verdict[m.task_digest]) for m in members if m.task_digest in verdict]


def vote_matrix(rows: list[dict[str, Any]]) -> tuple[np.ndarray, list[str], list[bool], list[str]]:
    """`adjudication_votes` rows → (votes (N, V) codes with -1 missing, groups, anchors, verifiers).
    Tampered anchor votes are quarantined from estimation (06 §2.4)."""
    rows = [r for r in rows if not r["tamper"]]
    verifiers = sorted({str(r["verifier_id"]) for r in rows})
    tasks = sorted({str(r["task_id"]) for r in rows})
    ti = {t: i for i, t in enumerate(tasks)}
    vi = {v: i for i, v in enumerate(verifiers)}
    votes = np.full((len(tasks), len(verifiers)), -1)
    family: dict[str, str] = {}
    anchor: dict[str, bool] = {}
    for r in rows:
        v = str(r["verifier_id"])
        votes[ti[str(r["task_id"])], vi[v]] = _CODE.get(r["vote"], -1)
        family[v] = str(r["family"])
        anchor[v] = bool(r["is_anchor"])
    groups = [_GROUP.get(family[v], family[v]) for v in verifiers]
    return votes, groups, [anchor[v] for v in verifiers], verifiers


def run_spectral(rows: list[dict[str, Any]]) -> tuple[Estimate | None, dict[str, Any]]:
    """The pure half of spectral.estimate: (Estimate, or None when no vote reached us; the row
    to persist)."""
    votes, groups, anchors, verifiers = vote_matrix(rows)
    if not verifiers:
        return None, {
            "n_tasks": 0,
            "passed": False,
            "diagnostics": {"n_tasks": 0, "failed": ["G1", "G3"]},
            "confusion": {},
            "prior": None,
        }
    est = estimate(votes, groups, anchors)
    diag = est.diagnostics
    passed = diag.passed
    return est, {
        "n_tasks": diag.n_tasks,
        "passed": passed,
        "diagnostics": _jsonable(asdict(diag)),
        "confusion": {v: est.confusion[i].tolist() for i, v in enumerate(verifiers)}
        if passed
        else {},
        "prior": est.prior.tolist() if passed else None,
    }


def _jsonable(v: Any) -> Any:
    if isinstance(v, dict):
        return {k: _jsonable(x) for k, x in v.items()}
    if isinstance(v, list | tuple):
        return [_jsonable(x) for x in v]
    if isinstance(v, float | np.floating):
        return float(v) if math.isfinite(v) else None
    return v


async def spectral_estimate(ctx: Any, *, http: httpx.AsyncClient | None = None) -> None:
    """Scheduler target `app.jobs.nightly:spectral_estimate` (06 §1.2): the trailing window's
    votes through the choke, SPECTRAL_DS behind the §4.3 gate, one spectral_runs row either way."""
    settings = ctx.settings
    if not settings.querychoke_base_url:
        raise RuntimeError(
            "ADJ_QUERYCHOKE_BASE_URL is unset: spectral.estimate has no ledger read path"
        )
    window = {
        "from": (ctx.day - timedelta(days=SPECTRAL_WINDOW_DAYS - 1)).isoformat(),
        "to": ctx.day.isoformat(),
    }
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
    est, run = run_spectral(rows)
    async with ctx.pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, ctx.tenant_id)
        await conn.execute(
            "INSERT INTO spectral_runs (tenant_id, window_start, window_days, n_tasks, passed, "
            "diagnostics, confusion, prior) "
            "VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8::jsonb) "
            "ON CONFLICT (tenant_id, window_start) DO UPDATE SET "
            "window_days = EXCLUDED.window_days, n_tasks = EXCLUDED.n_tasks, "
            "passed = EXCLUDED.passed, diagnostics = EXCLUDED.diagnostics, "
            "confusion = EXCLUDED.confusion, prior = EXCLUDED.prior, created_at = now()",
            UUID(ctx.tenant_id),
            ctx.window_start,
            SPECTRAL_WINDOW_DAYS,
            run["n_tasks"],
            run["passed"],
            json.dumps(run["diagnostics"]),
            json.dumps(run["confusion"]),
            json.dumps(run["prior"]),
        )
    log.info(
        "spectral.estimate %s %s: n_tasks=%d passed=%s failed=%s",
        ctx.tenant_id,
        ctx.day,
        run["n_tasks"],
        run["passed"],
        est.diagnostics.failed if est else ("G1", "G3"),
    )
    return None


async def _spectral_run(
    conn: asyncpg.Connection, tenant_id: str, window_start: datetime
) -> dict[str, Any] | None:
    row = await conn.fetchrow(
        "SELECT passed, diagnostics, confusion FROM spectral_runs "
        "WHERE tenant_id = $1 AND window_start = $2",
        UUID(tenant_id),
        window_start,
    )
    if row is None:
        return None
    return {
        "passed": row["passed"],
        "diagnostics": json.loads(row["diagnostics"]),
        "confusion": json.loads(row["confusion"]),
    }


async def certs_recompute(ctx: Any, *, http: httpx.AsyncClient | None = None) -> None:
    """One §5.3 transition per live verifier off the latest frozen set and this window's
    spectral run; a row when it changes, receipted through controld before it commits."""
    now = datetime.now(UTC)
    async with ctx.pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, ctx.tenant_id)
        frozen = await _latest_set(conn, ctx.tenant_id, frozen=True)
        members = await _members(conn, frozen["id"]) if frozen else []
        run = await _spectral_run(conn, ctx.tenant_id, ctx.window_start)
    window = scoring_window(members, now)
    comp = compute_certificate(score_agreement(await _ledger_pairs(ctx, window)))
    evidence = CertEvidence(
        gold_n=len(window),
        fresh_frac=fresh_fraction(members, now),
        estimator_ran=run is not None,
        identifiability_passed=bool(run and run["passed"]),
        natarajan_ok=comp.natarajan_ok,
    )
    current = (await current_cert(ctx.pool, ctx.tenant_id)).status
    status = next_status(current, evidence)
    if status == current != CERTIFIED and comp.rho_plus is None:
        log.info("certs.recompute %s: still %s, nothing measured", ctx.tenant_id, current)
        return None
    settings = ctx.settings
    own = (
        contextlib.nullcontext(http) if http else httpx.AsyncClient(timeout=settings.http_timeout_s)
    )
    async with own as client:
        append = partial(
            append_server_record,
            client,
            settings.querychoke_base_url,
            settings.querychoke_token.get_secret_value(),
        )
        for v in await list_verifiers(ctx.pool):
            cert_id = await insert_cert(
                ctx.pool,
                ctx.tenant_id,
                v.id,
                status,
                comp,
                frozen["id"] if frozen else None,
                identifiable=evidence.identifiability_passed,
                diagnostics={
                    **run["diagnostics"],
                    "confusion": run["confusion"].get(v.verifier_key),
                }
                if run
                else None,
                append=append,
            )
            log.info(
                "certs.recompute %s: %s -> %s cert=%s",
                ctx.tenant_id,
                v.verifier_key,
                status,
                cert_id,
            )
    return None


async def promotion_step(ctx: Any, *, http: httpx.AsyncClient | None = None) -> str | None:
    """06 §12.4 gates for every shadow/serving learned member over readjudicate's shadow
    pairs, each edge receipted through controld; the last receipt id, if any."""
    from app.jobs.readjudicate import measured_pairs
    from app.registry.promotion import run_promotion

    settings = ctx.settings
    own = (
        contextlib.nullcontext(http) if http else httpx.AsyncClient(timeout=settings.http_timeout_s)
    )
    async with own as client, ctx.pool.acquire() as conn:
        append = partial(
            append_server_record,
            client,
            settings.querychoke_base_url,
            settings.querychoke_token.get_secret_value(),
        )
        measured = await measured_pairs(conn, ctx.tenant_id)
        report = await run_promotion(conn, append, tenant_id=ctx.tenant_id, measured=measured)
    return str(report.receipt_ids[-1]) if report.receipt_ids else None
