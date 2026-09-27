"""The nightly callables: freeze a formed gold set, run SPECTRAL_DS over the ledger's votes, then
recompute every verifier's cert off both."""

import contextlib
import hashlib
import hmac
import json
import logging
import math
from collections.abc import Mapping
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from functools import partial
from typing import Any
from uuid import UUID

import asyncpg
import httpx
import numpy as np
from mark1_receipts import append_server_record

from app.certs.compute import compute_certificate, structural_violation
from app.certs.state_machine import CERTIFIED, GOLD_BOOTSTRAP_MIN, CertEvidence, next_status
from app.certs.store import current_cert, insert_cert
from app.choke import run_template
from app.db import set_local_tenant
from app.gold.rotate import MAX_AGE_DAYS, GoldLabel, fresh_fraction, scoring_window
from app.gold.score import score_agreement
from app.jobs.votes import column_of, estimable, groups_of, kind_of, vote_of
from app.registry.catalog import SOUND_REJECTORS, RegistryEntry, list_verifiers
from app.spectral.estimate import Estimate, estimate, predicted_noise
from app.spectral.moments import ABSTAIN, ACCEPT, REJECT

log = logging.getLogger("adjudicator.jobs")

# querychoke templates.go; rows locked to its testdata/intel_template_rows.json.
VOTES_TEMPLATE = "adjudication_votes"
GOLD_TEMPLATE = "gold_vs_verdict"
# ponytail: trailing window = the D16 30-day freshness horizon; a per-tenant knob later.
SPECTRAL_WINDOW_DAYS = 30
# handlers.py _WIRE_VOTE as codes; anything else ('' = an RmScore nothing folds) = did not vote.
_CODE = {"satisfied": ACCEPT, "violated": REJECT, "refused": ABSTAIN, "error": ABSTAIN}


async def _latest_set(
    conn: asyncpg.Connection, tenant_id: str, frozen: bool
) -> asyncpg.Record | None:
    return await conn.fetchrow(
        "SELECT id, agent, frozen_at FROM gold_sets WHERE tenant_id = $1 "
        "AND (frozen_at IS NOT NULL) = $2 ORDER BY row_seq DESC LIMIT 1",
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
            "ORDER BY row_seq",
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
                "AND frozen_at IS NOT NULL ORDER BY row_seq DESC LIMIT 1",
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


def tenant_root(ctx: Any) -> bytes | None:
    """HKDF-SHA256(pepper, info=mark1-tenant-root-v1:<tenant>) as controld enroll.TenantRoot."""
    pepper = getattr(ctx.settings, "tenant_hmac_pepper", None)
    if not pepper:
        return None
    prk = hmac.new(b"\x00" * 32, bytes.fromhex(pepper), hashlib.sha256).digest()
    info = f"mark1-tenant-root-v1:{UUID(ctx.tenant_id)}".encode()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


def task_digest(root: bytes, session_id: Any, task_id: Any) -> bytes:
    """m1_021's task_digest = HMAC-SHA256(tenant root, session_id ‖ task_id)."""
    return hmac.new(
        root, UUID(str(session_id)).bytes + UUID(str(task_id)).bytes, hashlib.sha256
    ).digest()


async def _ledger_pairs(
    ctx: Any, members: list[GoldLabel], *, http: httpx.AsyncClient | None = None
) -> list[tuple[str, str]]:
    """(gold true_label, stage-final fused verdict) per gold task the ledger holds. The choke
    hands back the ledger side only; the join key is m1_021's task_digest = HMAC-SHA256(tenant
    root, session_id ‖ task_id) (intel corpus/export.py task_digest, the one definition), the
    root HKDF-SHA256(pepper, info=mark1-tenant-root-v1:<tenant>) as controld enroll.TenantRoot.
    No pepper ⇒ [] = unmeasured, which no status transition can read as agreement."""
    root = tenant_root(ctx)
    if not members or root is None:
        if members:
            log.warning("certs.recompute %s: no tenant_hmac_pepper, unmeasured", ctx.tenant_id)
        return []
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
            tenant_id=ctx.tenant_id,
        )
    verdict = {
        task_digest(root, r["session_id"], r["task_id"]): str(r["fused_verdict"])
        for r in rows
        if r["verdict_stage"] in ("certified", "revised")
    }
    return [(m.true_label, verdict[m.task_digest]) for m in members if m.task_digest in verdict]


def vote_matrix(
    rows: list[dict[str, Any]], registry: Mapping[str, RegistryEntry] | None = None
) -> tuple[np.ndarray, list[str], list[bool], list[str]]:
    """`adjudication_votes` rows → (votes (N, V) codes with -1 missing, groups, sound-rejector
    mask, verifiers). Tampered anchor votes are quarantined from estimation (06 §2.4), and so
    are ambiguity-triggered judge votes (they feed fusion only); an RmScore folds through its
    calibration; groups come from the catalog row (16 §Independence rules), an E1 judge's
    E0-fallback votes are their own column, and G4 orients on compile/test alone. Every member
    votes here, shadow included."""
    registry = registry or {}
    rows = [
        r for r in rows if not r["tamper"] and estimable(r) and kind_of(r, registry) is not None
    ]
    verifiers = sorted({column_of(r, registry) for r in rows})
    tasks = sorted({str(r["task_id"]) for r in rows})
    ti = {t: i for i, t in enumerate(tasks)}
    vi = {v: i for i, v in enumerate(verifiers)}
    votes = np.full((len(tasks), len(verifiers)), -1)
    kind: dict[str, str | None] = {}
    for r in rows:
        v = column_of(r, registry)
        votes[ti[str(r["task_id"])], vi[v]] = _CODE.get(vote_of(r, registry), -1)
        kind[v] = kind_of(r, registry)
    group = groups_of(rows, registry)
    return (
        votes,
        [group[v] for v in verifiers],
        [kind[v] in SOUND_REJECTORS for v in verifiers],
        verifiers,
    )


def run_spectral(
    rows: list[dict[str, Any]], registry: Mapping[str, RegistryEntry] | None = None
) -> tuple[Estimate | None, dict[str, Any]]:
    """The pure half of spectral.estimate: (Estimate, or None when no vote reached us; the row
    to persist). A passed run carries Thm 6.1's predicted noise of its own labels ("selfcert")
    for certs.recompute's structural check against gold."""
    votes, groups, anchors, verifiers = vote_matrix(rows, registry)
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
    diagnostics = _jsonable(asdict(diag))
    diagnostics["groups"] = dict(zip(verifiers, groups, strict=True))
    if passed:
        diagnostics["selfcert"] = _jsonable(predicted_noise(est.posterior))
    return est, {
        "n_tasks": diag.n_tasks,
        "passed": passed,
        "diagnostics": diagnostics,
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
            tenant_id=ctx.tenant_id,
        )
    from app.jobs.readjudicate import registry_by_wire_id

    est, run = run_spectral(rows, registry_by_wire_id(await list_verifiers(ctx.pool)))
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
    score = score_agreement(await _ledger_pairs(ctx, window))
    comp = compute_certificate(score)
    structural = structural_violation(run["diagnostics"].get("selfcert") if run else None, score)
    if structural:
        log.warning("certs.recompute %s: predicted noise outside gold CI", ctx.tenant_id)
    evidence = CertEvidence(
        gold_n=len(window),
        fresh_frac=fresh_fraction(members, now),
        estimator_ran=run is not None,
        identifiability_passed=bool(run and run["passed"]) and not structural,
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
                    "structural_violation": structural,
                    "confusion": run["confusion"].get(f"{v.verifier_key}@{v.version}")
                    or run["confusion"].get(v.verifier_key),
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


async def _gold_labels(conn: asyncpg.Connection, tenant_id: str) -> dict[bytes, str]:
    """task_digest → the latest human or T3 label (never batch-readjudication: that one is the
    ensemble grading itself)."""
    async with conn.transaction():
        await set_local_tenant(conn, tenant_id)
        rows = await conn.fetch(
            "SELECT DISTINCT ON (task_digest) task_digest, true_label::text AS true_label "
            "FROM gold_set_members WHERE tenant_id = $1 AND label_source IN ('t3', 'human') "
            "ORDER BY task_digest, row_seq DESC",
            UUID(tenant_id),
        )
    return {bytes(r["task_digest"]): r["true_label"] for r in rows}


async def _heads(conn: asyncpg.Connection, tenant_id: str) -> list[dict[str, Any]]:
    """Every live head: its wire id, state, and the bar — the incumbent's prior Youden, or 0
    (abstain-always, m1_069) when it augments the ensemble."""
    from app.adjudicate.likelihoods import CALIBRATED_CONFUSION
    from app.registry.promotion import youden

    async with conn.transaction():
        await set_local_tenant(conn, tenant_id)
        rows = await conn.fetch(
            "SELECT p.id, p.state::text AS state, v.verifier_key || '@' || v.version AS vid, "
            "i.definition::text AS inc_definition, i.kind AS inc_kind "
            "FROM m1_verifier_promotions p JOIN m1_verifiers v ON v.id = p.verifier_id "
            "LEFT JOIN m1_verifiers i ON i.id = p.incumbent_verifier_id "
            "WHERE p.tenant_id = $1 AND p.state <> 'retired'",
            UUID(tenant_id),
        )
    out = []
    for h in rows:
        bar = 0.0
        if h["inc_kind"] is not None:
            definition = json.loads(h["inc_definition"] or "{}")
            kind = definition.get("kind") or {"judge": "judge", "reward_model": "rm"}.get(
                h["inc_kind"], "consistency"
            )
            bar = youden(CALIBRATED_CONFUSION[kind])
        out.append({"id": h["id"], "state": h["state"], "vid": h["vid"], "bar": bar})
    return out


def measurements(
    rows: list[dict[str, Any]],
    registry: Mapping[str, RegistryEntry],
    heads: list[dict[str, Any]],
    gold: Mapping[UUID, str],
    shadow: set[str],
    bundle: Any,
) -> dict[UUID, Any]:
    """16 §L6 promotion pairs: a head's vote against the gold label where the task has one,
    else (non-serving heads only — a serving member helped make the verdict) against the task's
    certified ledger verdict under its noise cert. Never escalations. A canary head also gets
    the watch over its hashed slice."""
    from app.adjudicate.algorithm import adjudicate
    from app.jobs.readjudicate import votes_by_task
    from app.registry.promotion import (
        GOLD,
        SERVING,
        CanaryWatch,
        Measurement,
        ShadowPair,
        in_canary,
    )

    tasks = votes_by_task(rows, registry)
    ledger: dict[UUID, tuple[str, str]] = {}
    for r in rows:
        if r.get("task_verdict") in ("satisfied", "violated", "refused", "error"):
            ledger[UUID(str(r["task_id"]))] = (r["task_verdict"], str(r["task_noise_cert_id"]))
    out: dict[UUID, Any] = {}
    for h in heads:
        member = {t: v for t, vs in tasks.items() for v in vs if v.verifier_id == h["vid"]}
        if not member:
            continue
        pairs = []
        for task, v in member.items():
            if task in gold:
                pairs.append(ShadowPair(v.vote, gold[task], GOLD))
            elif h["state"] not in SERVING and task in ledger:
                pairs.append(ShadowPair(v.vote, *ledger[task]))
        watch = None
        if h["state"] == "canary":
            n = flips = 0
            gw, go = [0, 0], [0, 0]
            for task, vote in member.items():
                if not in_canary(task):
                    continue
                base = [v for v in tasks[task] if v.verifier_id not in shadow]
                with_, without = adjudicate([*base, vote], bundle), adjudicate(base, bundle)
                n += 1
                flips += with_.verdict != without.verdict
                if gold.get(task) in ("satisfied", "violated"):
                    gw[0] += with_.verdict == gold[task]
                    go[0] += without.verdict == gold[task]
                    gw[1] += 1
                    go[1] += 1
            watch = CanaryWatch(n, flips, (gw[0], gw[1]), (go[0], go[1]))
        out[h["id"]] = Measurement(pairs, h["bar"], votes=len(member), canary=watch)
    return out


async def promotion_step(ctx: Any, *, http: httpx.AsyncClient | None = None) -> str | None:
    """06 §12.4 for every head, each edge receipted through controld; the register caller runs
    first so a newly seeded learned member is born in probation the same night."""
    from app.jobs.readjudicate import bundle_for, registry_by_wire_id, votes_by_task
    from app.registry.promotion import register_catalog, run_promotion, shadow_ids

    settings = ctx.settings
    window = {
        "from": (ctx.day - timedelta(days=SPECTRAL_WINDOW_DAYS - 1)).isoformat(),
        "to": ctx.day.isoformat(),
    }
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
        entries = await list_verifiers(ctx.pool)
        await register_catalog(conn, tenant_id=ctx.tenant_id, entries=entries)
        rows = await run_template(
            client,
            settings.querychoke_base_url,
            VOTES_TEMPLATE,
            window,
            bearer=settings.querychoke_token.get_secret_value(),
            tenant_id=ctx.tenant_id,
        )
        registry = registry_by_wire_id(entries)
        root = tenant_root(ctx)
        labels = await _gold_labels(conn, ctx.tenant_id) if root else {}
        gold = (
            {
                UUID(str(r["task_id"])): labels[d]
                for r in rows
                if r.get("session_id")
                and (d := task_digest(root, r["session_id"], r["task_id"])) in labels
            }
            if root
            else {}
        )
        async with conn.transaction():
            await set_local_tenant(conn, ctx.tenant_id)
            spectral = await _spectral_run(conn, ctx.tenant_id, ctx.window_start)
        tasks = votes_by_task(rows, registry)
        bundle = bundle_for((v for vs in tasks.values() for v in vs), spectral)
        measured = measurements(
            rows,
            registry,
            await _heads(conn, ctx.tenant_id),
            gold,
            await shadow_ids(conn, ctx.tenant_id),
            bundle,
        )
        report = await run_promotion(conn, append, tenant_id=ctx.tenant_id, measured=measured)
    return str(report.receipt_ids[-1]) if report.receipt_ids else None
