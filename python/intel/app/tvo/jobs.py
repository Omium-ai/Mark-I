"""The hourly `tvo.rollup_verify` entry (06 §7.2): drives rollup.run_rollup for the previous
UTC day once its D20 grace window has closed."""

import contextlib
import os
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from app.tvo.reader import QuerychokeReader
from app.tvo.rollup import run_rollup, window_close


async def rollup_verify(
    ctx: Any,
    *,
    http: httpx.AsyncClient | None = None,
    now: datetime | None = None,
    allow_unsigned_write: bool = False,
) -> str | None:
    """Scheduler target `app.tvo.jobs:rollup_verify`. An hourly tick's OWN day never
    closes (window_close(ctx.day) is always >24h out), so this rolls up the PREVIOUS UTC
    day -- the one an hourly tick can actually observe crossing its D20 grace lag; a tick
    inside that lag is a clean no-op, not a failure. `allow_unsigned_write` mirrors
    run_rollup's own flag verbatim (ADR-0010 unsigned, test/dev-lane only) -- the
    scheduler calls this with `ctx` alone, so production always takes the safe False
    default; only a test opts in explicitly, same as rollup.py's own suite does.
    Returns the last write's job_key (RollupOutcome carries no other receipt-shaped id),
    or None when there is nothing to write yet."""
    now = now or datetime.now(UTC)
    day = (now - timedelta(days=1)).date()
    if now < window_close(day):
        return None
    bearer = os.environ.get("INTEL_QUERYCHOKE_TOKEN", "")
    if not bearer:
        raise RuntimeError("INTEL_QUERYCHOKE_TOKEN is required (intel's service credential)")
    own = (
        contextlib.nullcontext(http)
        if http
        else httpx.AsyncClient(timeout=ctx.settings.http_timeout_s)
    )
    async with own as client:
        outcomes = await run_rollup(
            QuerychokeReader(client, ctx.settings.querychoke_base_url),
            tenant_id=ctx.tenant_id,
            day=day,
            bearer=bearer,
            now=now,
            allow_unsigned_write=allow_unsigned_write,
        )
    return outcomes[-1].job_key if outcomes else None
