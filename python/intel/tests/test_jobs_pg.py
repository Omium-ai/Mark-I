"""Real-Postgres runner semantics over `job_runs` (m1_067): prerequisite skip, idempotent
re-run, retry-to-parked, and the RLS negative. Same DSN gating as adjudicator's test_pg_stores."""

import os
import random
from datetime import UTC, datetime
from uuid import UUID, uuid4

import asyncpg
import pytest
from app.db import _tenant_guc_reset, set_local_tenant
from app.jobs.registry import Job
from app.jobs.runner import MAX_ATTEMPTS, run_many, run_one

DSN = os.environ.get("M1_TEST_PG_DSN", "")
REQUIRE_STORES = os.environ.get("M1_REQUIRE_STORES", "0") == "1"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not DSN and not REQUIRE_STORES,
        reason="M1_TEST_PG_DSN not set (estate skipif idiom; M1_REQUIRE_STORES=0)",
    ),
]

NOW = datetime(2026, 9, 16, 3, 0, tzinfo=UTC)
WINDOW = datetime(2026, 9, 15, tzinfo=UTC)


@pytest.fixture
async def pool():
    if not DSN:
        pytest.fail("M1_TEST_PG_DSN unset under M1_REQUIRE_STORES=1", pytrace=False)
    try:
        p = await asyncpg.create_pool(dsn=DSN, min_size=1, max_size=3, setup=_tenant_guc_reset)
    except Exception as exc:
        if REQUIRE_STORES:
            pytest.fail(f"{DSN!r} unreachable under M1_REQUIRE_STORES=1: {exc!r}", pytrace=False)
        pytest.skip(f"Postgres unreachable: {exc!r}")
    try:
        yield p
    finally:
        await p.close()


async def _mk_tenant(pool: asyncpg.Pool) -> str:
    tag = f"jobstest-{random.randbytes(4).hex()}"
    tenant = uuid4()
    async with pool.acquire() as conn, conn.transaction():
        org = await conn.fetchval(
            "INSERT INTO m1_organizations (name, primary_domain) VALUES ($1, $2) RETURNING id",
            tag,
            f"{tag}.example",
        )
        await set_local_tenant(conn, str(tenant))
        await conn.execute(
            "INSERT INTO m1_tenants (id, org_id, name) VALUES ($1, $2, $3)", tenant, org, tag
        )
    return str(tenant)


async def _row(pool: asyncpg.Pool, tenant: str, job: str) -> asyncpg.Record | None:
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        return await conn.fetchrow(
            "SELECT * FROM job_runs WHERE job = $1 AND tenant_id = $2 AND window_start = $3",
            job,
            UUID(tenant),
            WINDOW,
        )


def _cascade(calls: list[str], failing: set[str] = frozenset()):
    def target(name: str):
        async def fn(ctx) -> str | None:
            calls.append(name)
            if name in failing:
                raise RuntimeError(f"{name} blew up")
            return str(uuid4()) if name == "memory.admit" else None

        return fn

    jobs = [
        Job("corpus.export", "x:y", "nightly"),
        Job("policy_compiler.compile", "x:y", "nightly", ("memory.admit",)),
        Job("memory.admit", "x:y", "nightly", ("memory.extract",)),
        Job("memory.extract", "x:y", "nightly"),
    ]
    return jobs, {j.name: target(j.name) for j in jobs}


async def test_prerequisite_failure_skips_the_chain_but_not_independents(pool):
    tenant = await _mk_tenant(pool)
    calls: list[str] = []
    jobs, targets = _cascade(calls, failing={"memory.extract"})
    results = await run_many(pool, None, jobs, targets, tenant_id=tenant, now=NOW)
    assert results == {
        "memory.extract": "failed",
        "memory.admit": "skipped_prereq_failed",
        "policy_compiler.compile": "skipped_prereq_failed",
        "corpus.export": "succeeded",
    }
    assert sorted(calls) == ["corpus.export", "memory.extract"]
    admit = await _row(pool, tenant, "memory.admit")
    assert admit["outcome"] == "skipped_prereq_failed"
    assert admit["attempts"] == 0
    assert admit["error"] == "prerequisite memory.extract is failed"
    assert (await _row(pool, tenant, "memory.extract"))["error"].startswith("RuntimeError")


async def test_absent_prerequisite_row_skips_the_dependent(pool):
    tenant = await _mk_tenant(pool)
    calls: list[str] = []
    jobs, targets = _cascade(calls)
    admit = next(j for j in jobs if j.name == "memory.admit")
    out = await run_one(
        pool, None, admit, targets["memory.admit"], tenant_id=tenant, window_start=WINDOW
    )
    assert out == "skipped_prereq_failed" and calls == []
    assert (await _row(pool, tenant, "memory.admit"))[
        "error"
    ] == "prerequisite memory.extract is absent"


async def test_ordering_and_idempotent_rerun(pool):
    tenant = await _mk_tenant(pool)
    calls: list[str] = []
    jobs, targets = _cascade(calls)
    first = await run_many(pool, None, jobs, targets, tenant_id=tenant, now=NOW)
    assert set(first.values()) == {"succeeded"}
    assert calls.index("memory.extract") < calls.index("memory.admit")
    assert calls.index("memory.admit") < calls.index("policy_compiler.compile")
    admit = await _row(pool, tenant, "memory.admit")
    assert admit["receipt_id"] is not None

    second = await run_many(pool, None, jobs, targets, tenant_id=tenant, now=NOW)
    assert set(second.values()) == {"already_done"}
    assert len(calls) == 4, "a re-run of a succeeded window must not invoke the callable"
    admit = await _row(pool, tenant, "memory.admit")
    assert (admit["outcome"], admit["attempts"], admit["requested"]) == ("succeeded", 1, 2)


async def test_retry_is_the_same_row_and_parks_at_max_attempts(pool):
    tenant = await _mk_tenant(pool)
    job = Job("flaky", "x:y", "nightly")
    remaining = {"fails": 1}

    async def flaky(ctx) -> None:
        if remaining["fails"]:
            remaining["fails"] -= 1
            raise RuntimeError("transient")

    assert await run_one(pool, None, job, flaky, tenant_id=tenant, window_start=WINDOW) == "failed"
    assert (
        await run_one(pool, None, job, flaky, tenant_id=tenant, window_start=WINDOW) == "succeeded"
    )
    row = await _row(pool, tenant, "flaky")
    assert (row["attempts"], row["requested"], row["error"]) == (2, 2, None)

    async def dead(ctx) -> None:
        raise RuntimeError("permanent")

    doomed = Job("doomed", "x:y", "nightly")
    outcomes = [
        await run_one(pool, None, doomed, dead, tenant_id=tenant, window_start=WINDOW)
        for _ in range(MAX_ATTEMPTS + 1)
    ]
    assert outcomes == ["failed"] * (MAX_ATTEMPTS - 1) + ["parked", "parked"]
    row = await _row(pool, tenant, "doomed")
    assert (row["attempts"], row["requested"]) == (MAX_ATTEMPTS, MAX_ATTEMPTS + 1)


async def test_rls_isolation_on_job_runs(pool):
    async with pool.acquire() as conn:
        bypass = await conn.fetchval(
            "SELECT rolbypassrls OR rolsuper FROM pg_roles WHERE rolname = current_user"
        )
    if bypass:
        pytest.fail("test role bypasses RLS — isolation not observable from here", pytrace=False)
    tenant_a, tenant_b = await _mk_tenant(pool), await _mk_tenant(pool)
    job = Job("solo", "x:y", "nightly")

    async def ok(ctx) -> None:
        return None

    await run_one(pool, None, job, ok, tenant_id=tenant_a, window_start=WINDOW)
    async with pool.acquire() as conn:
        assert await conn.fetchval("SELECT count(*) FROM job_runs") == 0, "GUC unset ⇒ nothing"
        async with conn.transaction():
            await set_local_tenant(conn, tenant_b)
            assert await conn.fetch("SELECT job FROM job_runs WHERE job = 'solo'") == []
            with pytest.raises(asyncpg.InsufficientPrivilegeError):
                await conn.execute(
                    "INSERT INTO job_runs (job, tenant_id, window_start, outcome, finished_at) "
                    "VALUES ('solo', $1, $2, 'succeeded', now())",
                    UUID(tenant_a),
                    WINDOW,
                )
    assert (await _row(pool, tenant_b, "solo")) is None
    assert (await _row(pool, tenant_a, "solo"))["outcome"] == "succeeded"
