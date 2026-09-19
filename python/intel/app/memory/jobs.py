"""The nightly memory entry: memory.extract before memory.admit, runs_after-ordered (06 §7.2)."""

import argparse
import asyncio
import logging
import os
from collections.abc import Callable, Coroutine
from datetime import UTC, date, datetime
from functools import partial
from typing import Any

import asyncpg
import httpx
from anthropic import AsyncAnthropic
from mark1_receipts import append_server_record

from app.memory.admit import ReceiptAppend, run_admit
from app.memory.extract import AnthropicBatchRunner, BatchRunner, run_extract
from app.memory.retrieve import embed_missing
from app.tvo.reader import QuerychokeReader
from app.tvo.rollup import window_close

JOBS: tuple[tuple[str, str | None], ...] = (
    ("memory.extract", None),
    ("memory.admit", "memory.extract"),
)

log = logging.getLogger("intel.memory.jobs")


def ordered(jobs: tuple[tuple[str, str | None], ...] = JOBS) -> tuple[str, ...]:
    """Declared order must already satisfy runs_after; a spec that does not is a boot refusal."""
    order: list[str] = []
    for name, after in jobs:
        if after is not None and after not in order:
            raise ValueError(f"{name} runs_after {after}, which is not scheduled before it")
        order.append(name)
    return tuple(order)


def bearer_from_env() -> str:
    token = os.environ.get("INTEL_QUERYCHOKE_TOKEN", "")
    if not token:
        raise RuntimeError("INTEL_QUERYCHOKE_TOKEN is required (intel's service credential)")
    return token


def receipt_append(http: httpx.AsyncClient, base_url: str, bearer: str) -> ReceiptAppend:
    """controld's internal append route rides the querychoke base URL (one binary, 05 §0.1) under
    the same service credential the rollup write presents (ADR-0010 §2.2)."""
    return partial(append_server_record, http, base_url, bearer)


async def extract(ctx: Any) -> str | None:
    """Scheduler entry (registry `memory.extract`): ctx carries pool, settings, tenant_id, day."""
    timeout = ctx.settings.http_timeout_s
    async with (
        ctx.pool.acquire() as conn,
        httpx.AsyncClient(timeout=timeout) as http,
        AsyncAnthropic() as anthropic,
    ):
        await run_extract(
            QuerychokeReader(http, ctx.settings.querychoke_base_url, tenant_id=ctx.tenant_id),
            conn,
            AnthropicBatchRunner(anthropic),
            tenant_id=ctx.tenant_id,
            day=ctx.day,
            bearer=bearer_from_env(),
        )
    return None


async def admit(ctx: Any) -> str | None:
    """Scheduler entry (registry `memory.admit`): returns the last admission receipt id, if any."""
    bearer, base_url = bearer_from_env(), ctx.settings.querychoke_base_url
    async with (
        ctx.pool.acquire() as conn,
        httpx.AsyncClient(timeout=ctx.settings.http_timeout_s) as http,
    ):
        report = await run_admit(
            QuerychokeReader(http, base_url, tenant_id=ctx.tenant_id),
            conn,
            receipt_append(http, base_url, bearer),
            tenant_id=ctx.tenant_id,
            day=ctx.day,
            bearer=bearer,
        )
        await embed_missing(conn, ctx.tenant_id)
    return str(report.receipt_ids[-1]) if report.receipt_ids else None


async def run_nightly(
    reader: QuerychokeReader,
    conn: asyncpg.Connection,
    batch: BatchRunner,
    append: ReceiptAppend,
    *,
    tenant_id: str,
    day: date,
    bearer: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    close = window_close(day)
    if (now or datetime.now(UTC)) < close:
        raise ValueError(f"window for {day} closes at {close.isoformat()} — not yet closed")
    runners: dict[str, Callable[[], Coroutine[Any, Any, Any]]] = {
        "memory.extract": lambda: run_extract(
            reader, conn, batch, tenant_id=tenant_id, day=day, bearer=bearer
        ),
        "memory.admit": lambda: run_admit(
            reader, conn, append, tenant_id=tenant_id, day=day, bearer=bearer
        ),
    }
    results: dict[str, Any] = {}
    for name in ordered():
        results[name] = await runners[name]()
        log.info("%s %s %s: %s", name, tenant_id, day, results[name])
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="memory.extract + memory.admit for one tenant-day")
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--day", required=True, type=date.fromisoformat)
    parser.add_argument("--base-url", required=True, help="querychoke base URL")
    args = parser.parse_args(argv)
    dsn = os.environ.get("INTEL_PG_DSN", "")
    if not dsn:
        parser.error("INTEL_PG_DSN is required")
    bearer = bearer_from_env()

    async def _run() -> dict[str, Any]:
        conn = await asyncpg.connect(dsn)
        try:
            async with httpx.AsyncClient(timeout=30.0) as http, AsyncAnthropic() as anthropic:
                return await run_nightly(
                    QuerychokeReader(http, args.base_url, tenant_id=args.tenant_id),
                    conn,
                    AnthropicBatchRunner(anthropic),
                    receipt_append(http, args.base_url, bearer),
                    tenant_id=args.tenant_id,
                    day=args.day,
                    bearer=bearer,
                )
        finally:
            await conn.close()

    for name, report in asyncio.run(_run()).items():
        log.info("done: %s %s", name, report)
    return 0


if __name__ == "__main__":
    from app.logging import configure_logging

    configure_logging()
    raise SystemExit(main())
