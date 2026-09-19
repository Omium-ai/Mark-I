"""The nightly `corpus.export` entry (06 §7.2: no runs_after — independent of the compiler)."""

import asyncio
import contextlib
import logging
import os
from datetime import datetime
from typing import Any

import httpx
from mark1_receipts import append_server_record

from app.corpus.export import (
    RECEIPT_TYPE,
    build,
    load_gate,
    tenant_root,
    training_consented,
    write,
)
from app.db import set_local_tenant
from app.tvo.reader import QuerychokeReader

# Not yet in controld's closed registry: the choke answers M1E-2008 and the job parks (fail-closed).
CANDIDATES_TEMPLATE = "corpus_candidates"

log = logging.getLogger("intel.corpus.jobs")


def _candidate(row: dict[str, Any]) -> dict[str, Any]:
    """JSON wire → export() input: RFC 3339 → datetime, hex digest → bytes."""
    return {
        **row,
        "occurred_at": datetime.fromisoformat(row["occurred_at"]),
        "prompt_digest": bytes.fromhex(row["prompt_digest"]),
    }


async def export(ctx: Any, *, http: httpx.AsyncClient | None = None) -> str | None:
    """Scheduler target `app.corpus.jobs:export`: the tenant's training consent (m1_082) first --
    nothing is read, written or receipted without it -- then objects → controld's corpus_export
    receipt (the one chain writer, m1_002 §5) → manifest.json + receipt.json. A refusal or crash
    before the receipt leaves an unreferenced export_id with no manifest (06 §13: never served);
    the receipt is never ahead of the bytes it attests."""
    root = getattr(ctx.settings, "corpus_root_uri", None)
    pepper = getattr(ctx.settings, "tenant_hmac_pepper", None)
    if not (root and pepper):
        raise RuntimeError(
            "INTEL_CORPUS_ROOT_URI and INTEL_TENANT_HMAC_PEPPER are required: corpus.export "
            "has nowhere to write or no root to mint task_digest under"
        )
    bearer = os.environ.get("INTEL_QUERYCHOKE_TOKEN", "")
    if not bearer:
        raise RuntimeError("INTEL_QUERYCHOKE_TOKEN is required (intel's service credential)")
    async with ctx.pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, ctx.tenant_id)
        if not await training_consented(conn, ctx.tenant_id):
            log.info("corpus.export %s %s: skipped, no training consent", ctx.tenant_id, ctx.day)
            return None
        admitted, certs = await load_gate(conn, ctx.tenant_id)
    own = (
        contextlib.nullcontext(http)
        if http
        else httpx.AsyncClient(timeout=ctx.settings.http_timeout_s)
    )
    base_url = ctx.settings.querychoke_base_url
    async with own as client:
        result = await QuerychokeReader(client, base_url, tenant_id=ctx.tenant_id).run_template(
            CANDIDATES_TEMPLATE,
            {"from": ctx.day.isoformat(), "to": ctx.day.isoformat()},
            bearer=bearer,
        )
        built = await asyncio.to_thread(
            build,
            root,
            ctx.tenant_id,
            [_candidate(r) for r in result.rows],
            admitted,
            certs,
            hmac_root=tenant_root(bytes.fromhex(pepper), ctx.tenant_id),
        )
        await asyncio.to_thread(write, root, built.objects)
        ref = await append_server_record(
            client,
            base_url,
            bearer,
            tenant_id=ctx.tenant_id,
            record_type=RECEIPT_TYPE,
            subject_id=built.export_id,
            idempotency_key=f"corpus.export:{built.export_id}",
            payload=built.receipt_fields,
        )
        await asyncio.to_thread(
            write, root, [built.manifest, (built.receipt_key, ref.payload.encode())]
        )
    log.info("corpus.export %s %s: %s", ctx.tenant_id, ctx.day, built.receipt_fields)
    return str(ref.receipt_id)
