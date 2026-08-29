"""asyncpg pool factory with tenant GUC discipline (06 §1.1): RLS does the isolating,
we set the GUC."""

import asyncpg

from app.config import Settings


async def _tenant_guc_reset(conn: asyncpg.Connection) -> None:
    # Runs on every Pool.acquire(): a pooled connection must never leak the previous
    # job's tenant GUC into the next job's RLS context (the estate's two-arg
    # current_setting('app.tenant_id', true) policies read exactly this).
    await conn.execute("RESET app.tenant_id")


async def create_pool(settings: Settings) -> asyncpg.Pool:
    return await asyncpg.create_pool(
        dsn=settings.pg_dsn_app,
        min_size=settings.pg_pool_min,
        max_size=settings.pg_pool_max,
        setup=_tenant_guc_reset,
    )


async def set_local_tenant(conn: asyncpg.Connection, tenant_id: str) -> None:
    # SET LOCAL (is_local=true): the GUC dies with the surrounding transaction, so a
    # job-context write can never bleed tenant identity past its own commit (06 §1.1).
    await conn.execute("SELECT set_config('app.tenant_id', $1, true)", tenant_id)
