"""Nightly `policy_compiler.compile` (06 §7.2, runs_after memory.admit): certified rows through
the choke → cpvs/ladders/knee → one `bundle_drafts` row; controld publishes (publish.py)."""

import contextlib
import json
import logging
import os
from datetime import date, timedelta
from typing import Any

import asyncpg
import httpx

from app.db import set_local_tenant
from app.policy_compiler.compile import (
    NothingToCompile,
    SpectralRun,
    VerifyInputs,
    compile_sections,
)
from app.policy_compiler.cpvs import CertifiedAttempt, Regime, certified
from app.policy_compiler.publish import KneeGateViolation, previous_sections, write_draft
from app.regime import load_regime
from app.tvo.reader import QuerychokeReader

# controld's closed registry serves it with the ledger's own task_class and cost_basis per attempt.
ATTEMPTS_TEMPLATE = "policy_compiler_attempts"
CHANNEL = "canary"  # 05 §4.3 step 1: a publication targets the canary channel first
# ponytail: trailing window so D33's 30-outcome cells can fill; per-tenant when volumes differ.
LOOKBACK_DAYS = 30

log = logging.getLogger("intel.policy_compiler.jobs")


async def read_attempts(
    reader: QuerychokeReader, day: date, *, bearer: str
) -> tuple[CertifiedAttempt, ...]:
    """[day − 29, day] at attempt grain; the template's column names are CertifiedAttempt's."""
    result = await reader.run_template(
        ATTEMPTS_TEMPLATE,
        {
            "from": (day - timedelta(days=LOOKBACK_DAYS - 1)).isoformat(),
            "to": (day + timedelta(days=1)).isoformat(),
        },
        bearer=bearer,
    )
    return tuple(CertifiedAttempt.model_validate(dict(r)) for r in result.rows)


def _as_dict(value: Any) -> Any:
    return json.loads(value) if isinstance(value, str) else value


async def _verify_inputs(conn: asyncpg.Connection, tenant_id: str) -> VerifyInputs:
    """The newest spectral_runs row (identifiable or not) and the `stable` channel's published
    head, both under the caller's tenant GUC — compile_sections' verify basis (06 §4)."""
    row = await conn.fetchrow(
        "SELECT window_start, passed, confusion, prior FROM spectral_runs "
        "WHERE tenant_id = $1 ORDER BY window_start DESC LIMIT 1",
        tenant_id,
    )
    run = None
    if row is not None:
        confusion = _as_dict(row["confusion"])
        prior = _as_dict(row["prior"])
        run = SpectralRun(
            window_start=row["window_start"],
            passed=row["passed"],
            confusion={k: (tuple(rows[0]), tuple(rows[1])) for k, rows in confusion.items()},
            prior=tuple(prior) if prior is not None else None,
        )
    stable = await previous_sections(conn, tenant_id, "stable")
    stable_seq = None
    if stable is not None:
        stable_seq = await conn.fetchval(
            "SELECT head_seq FROM bundle_channel_heads WHERE tenant_id = $1 AND channel = 'stable'",
            tenant_id,
        )
    return VerifyInputs(
        spectral_run=run,
        stable_verify_cbor=stable["verify"] if stable is not None else None,
        stable_seq=stable_seq,
    )


async def compile(  # noqa: A001 — the scheduler contract names the entry `compile`
    ctx: Any, *, http: httpx.AsyncClient | None = None, regime: Regime | None = None
) -> str | None:
    """Scheduler target `app.policy_compiler.jobs:compile`. Returns None: the publication
    receipt is controld's, emitted inside Module.Publish when the draft is taken up."""
    bearer = os.environ.get("INTEL_QUERYCHOKE_TOKEN", "")
    if not bearer:
        raise RuntimeError("INTEL_QUERYCHOKE_TOKEN is required (intel's service credential)")
    own = (
        contextlib.nullcontext(http)
        if http
        else httpx.AsyncClient(timeout=ctx.settings.http_timeout_s)
    )
    async with own as client:
        attempts = await read_attempts(
            QuerychokeReader(client, ctx.settings.querychoke_base_url, tenant_id=ctx.tenant_id),
            ctx.day,
            bearer=bearer,
        )
    bases = {a.cost_basis for a in certified(attempts)}
    if not bases:
        log.info("policy_compiler.compile %s %s: no certified rows", ctx.tenant_id, ctx.day)
        return None
    if len(bases) > 1:
        raise RuntimeError(
            f"policy_compiler.compile: window carries both cost bases {sorted(bases)}; never mixed "
            "(CON-014) — two regimes need two channels"
        )
    basis = bases.pop()
    async with ctx.pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, ctx.tenant_id)
        regime = regime or await load_regime(conn, ctx.tenant_id)
        if regime.cost_basis != basis:
            raise RuntimeError(f"regime basis {regime.cost_basis!r} != ledger basis {basis!r}")
        previous = await previous_sections(conn, ctx.tenant_id, CHANNEL)
        verify_inputs = await _verify_inputs(conn, ctx.tenant_id)
        try:
            compiled = compile_sections(attempts, regime, previous, verify_inputs)
        except NothingToCompile:
            return None
        if regime.price is not None:
            # ponytail: digest rides in knee_note; a bundle_drafts column once controld reads it
            note = f"{compiled.note}; priced by {regime.price.price_table_version}"
            compiled = compiled.model_copy(update={"note": note})
        inserted = await write_draft(conn, ctx.tenant_id, CHANNEL, ctx.window_start, compiled)
    log.info(
        "policy_compiler.compile %s %s: draft %s %s gate=%s: %s",
        ctx.tenant_id,
        ctx.day,
        compiled.draft_hash.hex()[:16],
        "written" if inserted else "already present",
        compiled.knee_gate_ok,
        compiled.note,
    )
    if not compiled.knee_gate_ok:
        raise KneeGateViolation(compiled.note)
    return None
