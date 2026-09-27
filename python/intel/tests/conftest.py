"""Pin this service's root at sys.path[0]: `app` must resolve to python/intel/app even when
a sibling service (python/adjudicator has the same top-level `app` layout, 06 §1.1) is
installed in the shared workspace venv — suites are invoked per-service from repo root."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import os  # noqa: E402

import asyncpg  # noqa: E402
import pytest  # noqa: E402


@pytest.fixture
async def admin():
    """Fixture setup only: seeding rows other services own, as the suite role (M1_TEST_PG_DSN)."""
    dsn = os.environ.get("M1_TEST_PG_DSN", "")
    if not dsn:
        if os.environ.get("M1_REQUIRE_STORES", "0") == "1":
            pytest.fail("M1_TEST_PG_DSN unset under M1_REQUIRE_STORES=1", pytrace=False)
        pytest.skip("M1_TEST_PG_DSN not set (estate skipif idiom)")
    p = await asyncpg.create_pool(dsn=dsn, min_size=1, max_size=3)
    try:
        yield p
    finally:
        await p.close()


@pytest.fixture
async def admin_conn(admin):
    async with admin.acquire() as c:
        yield c
