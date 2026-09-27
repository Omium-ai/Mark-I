"""adj_003 against real Postgres: the nightly cascade lands judge_batch.run in job_runs after
readjudicate.run, a live m1_065 consent row admits the cloud judge and the spent rows carry the
token counts, a re-run is already_done, a forced re-run re-posts the spent votes without a second
router call, m1_092 revoked every live @1 cloud consent, no consent row means edge rows with no
vote, the CHECK refuses a half-recorded cloud row, and RLS keeps one tenant's dispatches
invisible to another."""

import functools
import os
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID, uuid4

import asyncpg
import httpx
import pytest
from app.db import set_local_tenant
from app.jobs import JOBS
from app.jobs.judge_batch import run
from app.jobs.nightly import certs_recompute, promotion_step, spectral_estimate
from app.jobs.readjudicate import run as readjudicate_run
from app.jobs.registry import validate
from app.jobs.runner import run_many
from app.registry.promotion import RECEIPT_TYPE
from m1p.v1 import JudgeTrigger, Verdict
from tests.roles import service_pool
from tests.test_jobs import FakeChoke
from tests.test_judge_batch import (
    AMBIGUOUS,
    CANDIDATES,
    CLOUD_TASKS,
    EDGE,
    JID,
    JUDGED,
    SPEC,
    FakeCloud,
    all_rows,
    rid,
    settings,
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
MIGRATION = Path(__file__).resolve().parents[3] / "migrations/m1_092_router_judge_consents.sql"
WINDOW = datetime(2026, 9, 15, tzinfo=UTC)
SETTINGS = settings(http_timeout_s=5.0)


@pytest.fixture
async def pool():
    if not DSN:
        pytest.fail("M1_TEST_PG_DSN unset under M1_REQUIRE_STORES=1", pytrace=False)
    try:
        p = await service_pool(min_size=1, max_size=3)
    except Exception as exc:
        if REQUIRE_STORES:
            pytest.fail(f"{DSN!r} unreachable under M1_REQUIRE_STORES=1: {exc!r}", pytrace=False)
        pytest.skip(f"Postgres unreachable: {exc!r}")
    try:
        yield p
    finally:
        await p.close()


async def _consent(pool, tenant: str, **over) -> UUID:
    row = {"subprocessor": "nebius", "region": "global", "max_tier": "E1", "judge_id": JID, **over}
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        return await conn.fetchval(
            "INSERT INTO m1_cloud_judge_consents (tenant_id, judge_id, subprocessor, region, "
            "max_tier, consented_by) VALUES ($1, $2, $3, $4, $5, 'test') RETURNING id",
            UUID(tenant),
            row["judge_id"],
            row["subprocessor"],
            row["region"],
            row["max_tier"],
        )


async def _device(pool, tenant: str, *consents: tuple[bool, bool, timedelta]) -> list[dict]:
    """A device of `tenant` with m1_082 rows (e1, cloud_judge, recorded_at skew) in write order,
    and all_rows() re-stamped as recorded by it (m1_devices.id is global, the fixture's is not)."""
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        device = await conn.fetchval(
            "INSERT INTO m1_devices (tenant_id, platform, hostname_hmac) "
            "VALUES ($1, 'linux', $2) RETURNING id",
            UUID(tenant),
            random.randbytes(32),
        )
        for e1, cloud_judge, skew in consents:
            await conn.execute(
                "INSERT INTO m1_device_consents (tenant_id, device_id, e1, cloud_judge, training, "
                "recorded_at) VALUES ($1, $2, $3, $4, false, now() + $5::interval)",
                UUID(tenant),
                device,
                e1,
                cloud_judge,
                skew,
            )
    return [{**r, "device_id": str(device)} for r in all_rows()]


async def _dispatches(pool, tenant: str, jid: str = JID) -> dict[UUID, dict]:
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        rows = await conn.fetch(
            "SELECT * FROM judge_dispatches WHERE judge_id = $1 ORDER BY task_id", jid
        )
    return {r["task_id"]: dict(r) for r in rows}


def _http(cloud: FakeCloud, controld: FakeControld) -> httpx.AsyncClient:
    async def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/internal/v1/receipts/append":
            return controld.handler(req)
        return await cloud.handler(req)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _targets(http: httpx.AsyncClient) -> dict:
    return {
        **validate(JOBS),
        "spectral.estimate": functools.partial(spectral_estimate, http=FakeChoke([]).client()),
        "certs.recompute": functools.partial(certs_recompute, http=http),
        "readjudicate.run": functools.partial(readjudicate_run, http=http),
        "promotion.step": functools.partial(promotion_step, http=http),
        "judge_batch.run": functools.partial(run, http=http),
    }


def _ctx(pool, tenant: str) -> SimpleNamespace:
    return SimpleNamespace(
        pool=pool, settings=SETTINGS, tenant_id=tenant, window_start=WINDOW, day=WINDOW.date()
    )


async def test_cascade_dispatches_to_the_cloud_under_consent_and_books_the_spend(admin, pool, env):
    tenant = await _mk_tenant(admin)
    await _consent(admin, tenant)
    cloud = FakeCloud(await _device(admin, tenant, (True, True, timedelta(0))))
    http = _http(cloud, FakeControld({RECEIPT_TYPE, "noise_certificate"}))

    results = await run_many(pool, SETTINGS, list(JOBS), _targets(http), tenant_id=tenant, now=NOW)
    assert results["readjudicate.run"] == "succeeded"
    assert results["judge_batch.run"] == "succeeded"
    assert len(cloud.completions) == 4 and cloud.edge_ids() == {EDGE}
    recs = await _dispatches(pool, tenant)
    assert set(recs) == CLOUD_TASKS, "the cloud judge runs on every task, not only ambiguous ones"
    rec = recs[AMBIGUOUS]
    assert (rec["locus"], rec["vote"], rec["model"], rec["batch_id"]) == (
        "cloud",
        "violated",
        SPEC.model,
        None,
    )
    assert rec["request_id"] == UUID(rid(AMBIGUOUS)) and rec["window_start"] == WINDOW
    assert (rec["input_tokens"], rec["output_tokens"]) == (1200, 3)
    assert (rec["cache_creation_input_tokens"], rec["cache_read_input_tokens"]) == (0, 1100)
    votes = {UUID(bytes=e.task_id): e.judge_vote for e in cloud.events()}
    assert {t: v.vote for t, v in votes.items()} == {t: Verdict.VIOLATED for t in CLOUD_TASKS}
    assert {v.trigger for v in votes.values()} == {JudgeTrigger.ALWAYS}
    assert {r["evidence_tier"] for r in recs.values()} == {"E0"}, "no E1 reader: the E0 fallback"
    # The runner's order, never finished_at's: now() is wall clock, and WSL2 steps it backwards.
    assert list(results).index("readjudicate.run") < list(results).index("judge_batch.run")
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        jobs = await conn.fetch(
            "SELECT job, outcome, attempts FROM job_runs WHERE tenant_id = $1 "
            "AND job IN ('judge_batch.run', 'readjudicate.run') ORDER BY job",
            tenant,
        )
    assert [tuple(j) for j in jobs] == [
        ("judge_batch.run", "succeeded", 1),
        ("readjudicate.run", "succeeded", 1),
    ]

    again = await run_many(pool, SETTINGS, list(JOBS), _targets(http), tenant_id=tenant, now=NOW)
    assert again["judge_batch.run"] == "already_done" and len(cloud.completions) == 4

    # A forced re-run of the same window: the spent rows are re-posted, the model is not.
    async with admin.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        await conn.execute("DELETE FROM job_runs WHERE job = 'judge_batch.run'")
    posted_before = len(cloud.ingested)
    await run(_ctx(pool, tenant), http=http)
    assert len(cloud.completions) == 4 and len(cloud.ingested) == posted_before + 1
    ids = [bytes(e.event_id) for e in cloud.events()]
    assert len(ids) == 8 and len(set(ids)) == 4, "the re-post carries the same four event_ids"
    assert await _dispatches(pool, tenant) == recs


async def test_m1_092_revokes_live_anthropic_consent_and_the_check_admits_mem(admin, pool):
    migrate = os.environ.get("M1_MIGRATE_PG_DSN", "")
    if not migrate:
        pytest.fail("M1_MIGRATE_PG_DSN unset: m1_092 needs the migrator to re-run", pytrace=False)
    tenant = await _mk_tenant(admin)
    old = await _consent(admin, tenant, judge_id=EDGE, subprocessor="anthropic", region="us")
    await _consent(admin, tenant, judge_id="mem:extract@1", max_tier="E0")
    conn = await asyncpg.connect(migrate)
    try:
        await conn.execute(MIGRATION.read_text())  # idempotent + re-runnable, house style
    finally:
        await conn.close()
    async with admin.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        rows = await conn.fetch(
            "SELECT id, judge_id, revoked_at IS NOT NULL AS revoked, revoked_reason "
            "FROM m1_cloud_judge_consents ORDER BY judge_id"
        )
        with pytest.raises(asyncpg.CheckViolationError):
            await conn.execute(
                "INSERT INTO m1_cloud_judge_consents (tenant_id, judge_id, subprocessor, region, "
                "max_tier, consented_by) VALUES ($1, 'memory:extract@1', 'nebius', 'global', "
                "'E0', 'test')",
                UUID(tenant),
            )
    assert [(r["judge_id"], r["revoked"], r["revoked_reason"]) for r in rows] == [
        (EDGE, True, "subprocessor_changed:anthropic->nebius"),
        ("mem:extract@1", False, None),
    ]
    assert rows[0]["id"] == old, "revoked by UPDATE, never deleted"


async def test_no_consent_row_means_edge_rows_with_no_vote(admin, pool):
    tenant = await _mk_tenant(admin)
    cloud = FakeCloud(all_rows())
    await run(_ctx(pool, tenant), http=cloud.client())
    assert cloud.completions == [] and cloud.ingested == []
    edge_ids = {rid(t, EDGE) for t in (*CANDIDATES, JUDGED)}
    assert {d["request"]["requestId"] for d in cloud.dispatched} == edge_ids
    assert await _dispatches(pool, tenant) == {}
    recs = await _dispatches(pool, tenant, EDGE)
    assert {t: (r["locus"], r["vote"], r["input_tokens"]) for t, r in recs.items()} == {
        t: ("client_side", None, None) for t in (*CANDIDATES, JUDGED)
    }
    # The next night reposts under the same request_id (the edge's dedupe key).
    await run(_ctx(pool, tenant), http=cloud.client())
    assert (
        len(cloud.dispatched) == 8
        and {d["request"]["requestId"] for d in cloud.dispatched} == edge_ids
    )


async def test_check_refuses_a_cloud_row_without_its_spend(admin, pool):
    tenant = await _mk_tenant(admin)
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


async def test_rls_hides_another_tenants_dispatches(admin, pool):
    a, b = await _mk_tenant(admin), await _mk_tenant(admin)
    cloud = FakeCloud(all_rows())
    await run(_ctx(pool, a), http=cloud.client())
    assert set(await _dispatches(pool, a, EDGE)) == {*CANDIDATES, JUDGED}
    assert await _dispatches(pool, b, EDGE) == {}
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


async def test_the_daily_ledger_never_over_grants_and_rls_keeps_it_per_tenant(admin, pool):
    """m1_101 under concurrency: two reservations racing on one tenant-day split the cap, a third
    gets nothing, and another tenant's day is its own row, invisible to the first."""
    import asyncio

    from app.llm import reserve_today

    a, b = await _mk_tenant(admin), await _mk_tenant(admin)
    async with pool.acquire() as c1, pool.acquire() as c2:
        got = await asyncio.gather(
            reserve_today(c1, a, JID, 40, 60), reserve_today(c2, a, JID, 40, 60)
        )
    assert sorted(got) == [20, 40]
    async with pool.acquire() as c:
        assert await reserve_today(c, a, JID, 5, 60) == 0
        assert await reserve_today(c, b, JID, 5, 60) == 5
        async with c.transaction():
            await set_local_tenant(c, b)
            rows = await c.fetch("SELECT tenant_id, units FROM m1_llm_spend_days")
    assert [(str(r["tenant_id"]), r["units"]) for r in rows] == [(b, 5)]


async def test_the_devices_last_written_consent_gates_the_cloud_judge(admin, pool):
    """H4: the tenant row is on, the member's device turned cloud_judge off with a clock stepped
    backwards: row_seq, not recorded_at, decides, and nothing of the member's leaves."""
    tenant = await _mk_tenant(admin)
    await _consent(admin, tenant)
    early = timedelta(hours=-1)
    rows = await _device(admin, tenant, (True, True, timedelta(0)), (True, False, early))
    cloud = FakeCloud(rows)
    await run(_ctx(pool, tenant), http=cloud.client())
    assert cloud.completions == [] and await _dispatches(pool, tenant) == {}
    assert cloud.edge_ids() == {EDGE}

    regrant = await _device(admin, tenant, (False, False, timedelta(0)), (True, True, 2 * early))
    cloud = FakeCloud(regrant)
    await run(_ctx(pool, tenant), http=cloud.client())
    assert len(cloud.completions) == 4 and set(await _dispatches(pool, tenant)) == CLOUD_TASKS


async def test_a_device_with_no_consent_row_sends_nothing(admin, pool):
    tenant = await _mk_tenant(admin)
    await _consent(admin, tenant)
    cloud = FakeCloud(await _device(admin, tenant))
    await run(_ctx(pool, tenant), http=cloud.client())
    assert cloud.completions == [] and await _dispatches(pool, tenant) == {}
