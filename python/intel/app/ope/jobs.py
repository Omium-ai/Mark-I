"""Nightly `ope.score` entry (06 §7.2): assemble the closed window's OPE inputs through the choke.
No candidate source exists until policy_compiler.compile publishes one, so nothing is scored or
receipted yet — the C9 accounting is logged and None is returned."""

import logging
import os
from typing import Any

import httpx

from app.ope.inputs import fetch
from app.tvo.reader import QuerychokeReader

log = logging.getLogger("intel.ope.jobs")


async def score(ctx: Any, http: httpx.AsyncClient | None = None) -> str | None:
    bearer = os.environ.get("INTEL_QUERYCHOKE_TOKEN", "")
    if not bearer:
        raise ValueError("INTEL_QUERYCHOKE_TOKEN is required (intel's service credential)")
    settings = ctx.settings
    async with http or httpx.AsyncClient(timeout=settings.http_timeout_s) as client:
        reader = QuerychokeReader(client, settings.querychoke_base_url)
        out = await fetch(reader, ctx.day, ctx.day, bearer=bearer)
    log.info(
        "ope.score %s %s: admitted=%d dropped=%s",
        ctx.tenant_id,
        ctx.day,
        len(out.rows),
        out.dropped,
    )
    return None
