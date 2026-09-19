"""The runner (06 §7.3): one `job_runs` row per (job, tenant, window); retry = attempts+1."""

import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Any

import asyncpg

from app.db import set_local_tenant
from app.jobs.registry import Job, order

log = logging.getLogger("jobs.runner")

MAX_ATTEMPTS = 5  # D21: after this a window is `parked` and needs an operator
# ponytail: fixed lease over a crashed `running` row; 2× measured p99 (D19) once one exists.
LEASE = timedelta(hours=2)
_TERMINAL_BAD = ("failed", "parked", "skipped_prereq_failed")


@dataclass(frozen=True)
class JobContext:
    pool: asyncpg.Pool
    settings: Any
    tenant_id: str
    window_start: datetime

    @property
    def day(self) -> date:
        return self.window_start.date()


def window_for(cadence: str, now: datetime, day: date | None = None) -> datetime:
    """Closed window: yesterday (or --day) for nightly, the previous full hour for hourly."""
    if cadence == "hourly":
        return now.astimezone(UTC).replace(minute=0, second=0, microsecond=0) - timedelta(hours=1)
    return datetime.combine(
        day or (now.astimezone(UTC) - timedelta(days=1)).date(), datetime.min.time(), UTC
    )


async def run_one(
    pool: asyncpg.Pool,
    settings: Any,
    job: Job,
    fn: Any,
    *,
    tenant_id: str,
    window_start: datetime,
) -> str:
    """The ledger outcome, or `already_done` / `already_running` when there is nothing to do."""
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant_id)
        row = await conn.fetchrow(
            "SELECT outcome, attempts, started_at FROM job_runs "
            "WHERE job = $1 AND tenant_id = $2 AND window_start = $3 FOR UPDATE",
            job.name,
            tenant_id,
            window_start,
        )
        if row is not None:
            await conn.execute(
                "UPDATE job_runs SET requested = requested + 1 "
                "WHERE job = $1 AND tenant_id = $2 AND window_start = $3",
                job.name,
                tenant_id,
                window_start,
            )
            if row["outcome"] == "succeeded":
                return "already_done"
            if row["outcome"] == "parked":
                log.error(
                    "%s %s %s: parked after %d attempts",
                    job.name,
                    tenant_id,
                    window_start,
                    row["attempts"],
                )
                return "parked"
            if row["outcome"] == "running" and row["started_at"] > datetime.now(UTC) - LEASE:
                return "already_running"
        failed_prereq = await conn.fetchrow(
            "SELECT p.job, coalesce(r.outcome, 'absent') AS outcome "
            "FROM unnest($3::text[]) AS p(job) LEFT JOIN job_runs r "
            "ON r.job = p.job AND r.tenant_id = $1 AND r.window_start = $2 "
            "WHERE r.outcome IS DISTINCT FROM 'succeeded' ORDER BY p.job LIMIT 1",
            tenant_id,
            window_start,
            list(job.runs_after),
        )
        if failed_prereq is not None:
            reason = f"prerequisite {failed_prereq['job']} is {failed_prereq['outcome']}"
            await conn.execute(
                "INSERT INTO job_runs (job, tenant_id, window_start, outcome, error, finished_at) "
                "VALUES ($1, $2, $3, 'skipped_prereq_failed', $4, now()) "
                "ON CONFLICT (job, tenant_id, window_start) DO UPDATE "
                "SET outcome = EXCLUDED.outcome, error = EXCLUDED.error, finished_at = now()",
                job.name,
                tenant_id,
                window_start,
                reason,
            )
            log.warning("%s %s %s: skipped, %s", job.name, tenant_id, window_start, reason)
            return "skipped_prereq_failed"
        await conn.execute(
            "INSERT INTO job_runs (job, tenant_id, window_start, outcome, attempts) "
            "VALUES ($1, $2, $3, 'running', 1) "
            "ON CONFLICT (job, tenant_id, window_start) DO UPDATE "
            "SET outcome = 'running', attempts = job_runs.attempts + 1, "
            "    started_at = now(), finished_at = NULL, error = NULL",
            job.name,
            tenant_id,
            window_start,
        )

    ctx = JobContext(pool=pool, settings=settings, tenant_id=tenant_id, window_start=window_start)
    try:
        receipt_id = await fn(ctx)
    except Exception as exc:
        log.exception("%s %s %s: failed", job.name, tenant_id, window_start)
        async with pool.acquire() as conn, conn.transaction():
            await set_local_tenant(conn, tenant_id)
            outcome = await conn.fetchval(
                "UPDATE job_runs SET error = $5, finished_at = now(), "
                "outcome = CASE WHEN attempts >= $4 THEN 'parked' ELSE 'failed' END "
                "WHERE job = $1 AND tenant_id = $2 AND window_start = $3 RETURNING outcome",
                job.name,
                tenant_id,
                window_start,
                MAX_ATTEMPTS,
                repr(exc)[:2000],
            )
        return outcome
    # job_runs.receipt_id is a uuid (m1_067); a job whose receipt is a job_key (tvo.rollup_verify:
    # "tvo.rollup_tenant_day:<day>:<day>:<hash>", already the ledger's dedup token) records NULL
    # rather than crashing the run and leaving the row 'running' for the 2 h lease (prod 09-19).
    stored = _as_uuid(receipt_id)
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant_id)
        await conn.execute(
            "UPDATE job_runs SET outcome = 'succeeded', receipt_id = $4, finished_at = now() "
            "WHERE job = $1 AND tenant_id = $2 AND window_start = $3",
            job.name,
            tenant_id,
            window_start,
            stored,
        )
    log.info("%s %s %s: succeeded receipt=%s", job.name, tenant_id, window_start, receipt_id)
    return "succeeded"


def _as_uuid(ref: str | None) -> uuid.UUID | None:
    if ref is None:
        return None
    try:
        return uuid.UUID(str(ref))
    except ValueError:
        return None


async def run_many(
    pool: asyncpg.Pool,
    settings: Any,
    jobs: list[Job],
    targets: dict[str, Any],
    *,
    tenant_id: str,
    now: datetime,
    day: date | None = None,
) -> dict[str, str]:
    """Dependency-ordered run for one tenant; each job gates on its prerequisites' rows."""
    results: dict[str, str] = {}
    for job in order(jobs):
        results[job.name] = await run_one(
            pool,
            settings,
            job,
            targets[job.name],
            tenant_id=tenant_id,
            window_start=window_for(job.cadence, now, day),
        )
    return results
