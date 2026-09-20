"""adj_003 against real Postgres: the nightly cascade lands judge_batch.run in job_runs after
readjudicate.run, a live m1_065 consent row routes the judge to the cloud path and the spent
rows carry the token counts, a re-run is already_done, a forced re-run re-posts the spent votes
without a second Batch call, no consent row means client-side rows with no vote, the CHECK
refuses a half-recorded cloud row, and RLS keeps one tenant's dispatches invisible to another."""

import functools
import os
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import UUID, uuid4

import asyncpg
import httpx
import pytest
from app.db import _tenant_guc_reset, set_local_tenant
from app.jobs import JOBS
from app.jobs.judge_batch import run
from app.jobs.nightly import certs_recompute, promotion_step, spectral_estimate
from app.jobs.readjudicate import run as readjudicate_run
from app.jobs.registry import validate
from app.jobs.runner import run_many
from app.registry.promotion import RECEIPT_TYPE
from m1p.v1 import Verdict
from pydantic import SecretStr
from tests.test_jobs import FakeChoke
from tests.test_judge_batch import (
    AMBIGUOUS,
    JID,
    MIDBAND,
    NO_TEST,
    SPEC,
    FakeBatch,
    FakeCloud,
    all_rows,
    rid,
)
from tests.test_pg_stores import FakeControld, _mk_tenant
from tests.test_readjudicate import env as _env

env = _env  # the ADJ_RM_* / ADJ_E2B_* fixture readjudicate.run needs, re-exported

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
SETTINGS = SimpleNamespace(
    querychoke_base_url="http://choke", querychoke_token=SecretStr("svc"), http_timeout_s=5.0
)


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


async def _consent(pool, tenant: str, **over) -> UUID:
    row = {"subprocessor": "anthropic", "region": "us", "max_tier": "E0", **over}
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        return await conn.fetchval(
            "INSERT INTO m1_cloud_judge_consents (tenant_id, judge_id, subprocessor, region, "
            "max_tier, consented_by) VALUES ($1, $2, $3, $4, $5, 'test') RETURNING id",
            UUID(tenant),
            JID,
            row["subprocessor"],
            row["region"],
            row["max_tier"],
        )


async def _dispatches(pool, tenant: str) -> dict[UUID, dict]:
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        rows = await conn.fetch("SELECT * FROM judge_dispatches ORDER BY task_id")
    return {r["task_id"]: dict(r) for r in rows}


def _http(cloud: FakeCloud, controld: FakeControld) -> httpx.AsyncClient:
    async def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/internal/v1/receipts/append":
            return controld.handler(req)
        return await cloud.handler(req)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _targets(http: httpx.AsyncClient, batch: FakeBatch) -> dict:
    return {
        **validate(JOBS),
        "spectral.estimate": functools.partial(spectral_estimate, http=FakeChoke([]).client()),
        "certs.recompute": functools.partial(certs_recompute, http=http),
        "readjudicate.run": functools.partial(readjudicate_run, http=http),
        "promotion.step": functools.partial(promotion_step, http=http),
        "judge_batch.run": functools.partial(run, http=http, batch=batch),
    }


def _ctx(pool, tenant: str) -> SimpleNamespace:
    return SimpleNamespace(
        pool=pool, settings=SETTINGS, tenant_id=tenant, window_start=WINDOW, day=WINDOW.date()
    )


async def test_cascade_dispatches_to_the_cloud_under_consent_and_books_the_spend(pool, env):
    tenant = await _mk_tenant(pool)
    await _consent(pool, tenant)
    cloud, batch = FakeCloud(all_rows()), FakeBatch()
    http = _http(cloud, FakeControld({RECEIPT_TYPE, "noise_certificate"}))

    results = await run_many(
        pool, SETTINGS, list(JOBS), _targets(http, batch), tenant_id=tenant, now=NOW
    )
    assert results["readjudicate.run"] == "succeeded"
    assert results["judge_batch.run"] == "succeeded"
    assert len(batch.calls) == 1 and cloud.dispatched == []
    # MIDBAND is bootstrap-refused: a candidate since the select rule widened
    assert {r["custom_id"] for r in batch.calls[0]} == {rid(AMBIGUOUS), rid(NO_TEST), rid(MIDBAND)}
    recs = await _dispatches(pool, tenant)
    assert set(recs) == {AMBIGUOUS, NO_TEST, MIDBAND}
    rec = recs[AMBIGUOUS]
    assert (rec["locus"], rec["vote"], rec["model"], rec["batch_id"]) == (
        "cloud",
        "violated",
        SPEC.model,
        "msgbatch_1",
    )
    assert rec["request_id"] == UUID(rid(AMBIGUOUS)) and rec["window_start"] == WINDOW
    assert (rec["input_tokens"], rec["output_tokens"]) == (1200, 3)
    assert (rec["cache_creation_input_tokens"], rec["cache_read_input_tokens"]) == (0, 1100)
    votes = {UUID(bytes=e.task_id): e.judge_vote for e in cloud.events()}
    assert {t: v.vote for t, v in votes.items()} == {
        AMBIGUOUS: Verdict.VIOLATED,
        NO_TEST: Verdict.VIOLATED,
        MIDBAND: Verdict.VIOLATED,
    }
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        jobs = await conn.fetch(
            "SELECT job, outcome, attempts, finished_at FROM job_runs WHERE tenant_id = $1 "
            "AND job IN ('judge_batch.run', 'readjudicate.run') ORDER BY finished_at",
            tenant,
        )
    assert [(j["job"], j["outcome"], j["attempts"]) for j in jobs] == [
        ("readjudicate.run", "succeeded", 1),
        ("judge_batch.run", "succeeded", 1),
    ]

    again = await run_many(
        pool, SETTINGS, list(JOBS), _targets(http, batch), tenant_id=tenant, now=NOW
    )
    assert again["judge_batch.run"] == "already_done" and len(batch.calls) == 1

    # A forced re-run of the same window: the spent rows are re-posted, the model is not.
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        await conn.execute("DELETE FROM job_runs WHERE job = 'judge_batch.run'")
    posted_before = len(cloud.ingested)
    await run(_ctx(pool, tenant), http=http, batch=batch)
    assert len(batch.calls) == 1 and len(cloud.ingested) == posted_before + 1
    ids = [bytes(e.event_id) for e in cloud.events()]
    assert len(ids) == 6 and len(set(ids)) == 3, "the re-post carries the same three event_ids"
    assert await _dispatches(pool, tenant) == recs


async def test_no_consent_row_means_client_side_rows_with_no_vote(pool):
    tenant = await _mk_tenant(pool)
    cloud, batch = FakeCloud(all_rows()), FakeBatch()
    await run(_ctx(pool, tenant), http=cloud.client(), batch=batch)
    assert batch.calls == [] and cloud.ingested == []
    assert {d["request"]["requestId"] for d in cloud.dispatched} == {
        rid(AMBIGUOUS),
        rid(NO_TEST),
        rid(MIDBAND),
    }
    recs = await _dispatches(pool, tenant)
    assert {t: (r["locus"], r["vote"], r["input_tokens"]) for t, r in recs.items()} == {
        AMBIGUOUS: ("client_side", None, None),
        NO_TEST: ("client_side", None, None),
        MIDBAND: ("client_side", None, None),
    }
    # The next night reposts under the same request_id (the edge's dedupe key).
    await run(_ctx(pool, tenant), http=cloud.client(), batch=batch)
    assert (
        len(cloud.dispatched) == 6
        and len({d["request"]["requestId"] for d in cloud.dispatched}) == 3
    )


async def test_check_refuses_a_cloud_row_without_its_spend(pool):
    tenant = await _mk_tenant(pool)
    base = dict(
        tenant_id=UUID(tenant),
        task_id=uuid4(),
        judge_id=JID,
        request_id=uuid4(),
        window_start=WINDOW,
        locus="cloud",
        vote="violated",
        model=SPEC.model,
        input_tokens=10,
        output_tokens=1,
    )

    async def insert(**kw):
        row = {**base, **kw}
        cols = ", ".join(row)
        params = ", ".join(f"${i + 1}" for i in range(len(row)))
        async with pool.acquire() as conn, conn.transaction():
            await set_local_tenant(conn, tenant)
            await conn.execute(
                f"INSERT INTO judge_dispatches ({cols}) VALUES ({params})", *row.values()
            )

    await insert()
    for bad in (
        {"task_id": uuid4(), "vote": None},
        {"task_id": uuid4(), "input_tokens": None},
        {"task_id": uuid4(), "locus": "client_side"},  # a client-side row never carries a vote
        {"task_id": uuid4(), "locus": "edge"},
        {"task_id": uuid4(), "judge_id": "rm:qwen@1"},
    ):
        with pytest.raises(asyncpg.CheckViolationError):
            await insert(**bad)
    with pytest.raises(asyncpg.UniqueViolationError):
        await insert()


async def test_rls_hides_another_tenants_dispatches(pool):
    a, b = await _mk_tenant(pool), await _mk_tenant(pool)
    cloud = FakeCloud(all_rows())
    await run(_ctx(pool, a), http=cloud.client(), batch=FakeBatch())
    assert set(await _dispatches(pool, a)) == {AMBIGUOUS, NO_TEST, MIDBAND}
    assert await _dispatches(pool, b) == {}
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, b)
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await conn.execute(
                "INSERT INTO judge_dispatches (tenant_id, task_id, judge_id, request_id, "
                "window_start, locus) VALUES ($1, $2, $3, $4, $5, 'client_side')",
                UUID(a),
                uuid4(),
                JID,
                uuid4(),
                WINDOW,
            )
