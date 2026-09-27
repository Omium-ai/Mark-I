"""Pin this service's root at sys.path[0]: `app` must resolve to python/adjudicator/app
even when a sibling service (python/intel has the same top-level `app` layout, 06 §1.1)
is installed in the shared workspace venv — suites are invoked per-service from repo
root (justfile `test`)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import os  # noqa: E402

import asyncpg  # noqa: E402
import numpy as np  # noqa: E402
import pytest  # noqa: E402


@pytest.fixture
def simulate():
    """Votes from planted laws: (prior (k,), confusion (V, k, 3), n) → ((n, V) codes, y)."""

    def _simulate(rng: np.random.Generator, prior, confusion, n: int):
        prior, confusion = np.asarray(prior, float), np.asarray(confusion, float)
        y = rng.choice(len(prior), size=n, p=prior)
        cdf = confusion.cumsum(-1)[:, y].transpose(1, 0, 2)
        u = rng.random((n, confusion.shape[0], 1))
        return np.minimum((u > cdf).sum(-1), 2), y

    return _simulate


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
