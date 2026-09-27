"""Store-backed tests run the code under test as the service's production role."""

import os

import asyncpg
import pytest
from app.db import _tenant_guc_reset

SERVICE_ROLE = "adjudicator_app"


async def service_pool(**kw):
    """The pool code under test runs on: the service's production role, SET from the migrator
    (which holds every role, 06 §1.1's split), with the service's own per-acquire GUC reset. A
    missing grant or an RLS-dependent read fails here, not in prod."""
    dsn = os.environ.get("M1_MIGRATE_PG_DSN", "")
    if not dsn:
        if os.environ.get("M1_REQUIRE_STORES", "0") == "1":
            pytest.fail("M1_MIGRATE_PG_DSN unset: the service role is SET from it", pytrace=False)
        pytest.skip("M1_MIGRATE_PG_DSN not set: no service role to run as")

    async def setup(conn):
        await conn.execute(f"SET ROLE {SERVICE_ROLE}")
        await _tenant_guc_reset(conn)

    return await asyncpg.create_pool(dsn=dsn, setup=setup, **kw)
