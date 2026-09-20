"""The nightly cascade end to end over real Postgres: gold.refresh freezes a formed set,
spectral.estimate lands its run (votes through a mock choke), certs.recompute reads both,
all three land in job_runs, and a re-run is a ledger no-op."""

import functools
import json
import os
import random
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import UUID

import asyncpg
import httpx
import numpy as np
import pytest
from app.certs.state_machine import GOLD_BOOTSTRAP_MIN
from app.db import _tenant_guc_reset, set_local_tenant
from app.gold.select import add_members, create_gold_set
from app.jobs import JOBS
from app.jobs.nightly import certs_recompute, gold_refresh, spectral_estimate
from app.jobs.registry import validate
from app.jobs.runner import run_many
from pydantic import SecretStr
from tests.test_jobs import PAPER2, FakeChoke, vote_rows
from tests.test_pg_stores import FakeControld, _mk_judge_verifier, _mk_tenant

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
SETTINGS = SimpleNamespace(
    querychoke_base_url="http://choke", querychoke_token=SecretStr("svc"), http_timeout_s=5.0
)


MINE = ("gold.refresh", "spectral.estimate", "certs.recompute")


def _mine(results: dict[str, str]) -> dict[str, str]:
    """This cascade's three outcomes; sibling jobs registered after certs.recompute ride along."""
    return {k: results[k] for k in MINE}


def _controld(rows: list[dict]) -> httpx.AsyncClient:
    """One mock controld: the choke read wire for `rows` and the receipt append wire."""
    choke, receipts = FakeChoke(rows).client(), FakeControld()

    async def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/internal/v1/receipts/append":
            return receipts.handler(req)
        return await choke.send(
            httpx.Request(req.method, req.url, headers=req.headers, content=req.content)
        )

    return httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://choke")


def _targets(rows: list[dict]) -> dict:
    """The registry's targets with spectral.estimate reading `rows` from a mock choke."""
    client = _controld(rows)
    return {
        **validate(JOBS),
        "spectral.estimate": functools.partial(spectral_estimate, http=client),
        "certs.recompute": functools.partial(certs_recompute, http=client),
    }


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


async def _tenant_state(pool: asyncpg.Pool, tenant: str) -> tuple[list, int, list]:
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        sets = await conn.fetch(
            "SELECT id, frozen_at FROM gold_sets WHERE tenant_id = $1", UUID(tenant)
        )
        certs = await conn.fetch(
            "SELECT status::text AS status, identifiable, diagnostics FROM noise_certificates"
        )
        runs = await conn.fetch(
            "SELECT job, outcome, attempts, requested FROM job_runs ORDER BY job"
        )
    return sets, certs, runs


async def test_cascade_freezes_a_formed_set_and_ledgers_both_jobs(pool):
    tenant = await _mk_tenant(pool)
    await _mk_judge_verifier(pool)
    gold_set = await create_gold_set(pool, tenant, "claudecode")
    labels = [
        (random.randbytes(32), random.choice(["satisfied", "violated"]), "t3")
        for _ in range(GOLD_BOOTSTRAP_MIN)
    ]
    await add_members(pool, tenant, gold_set, labels)
    targets = _targets([])

    first = _mine(await run_many(pool, SETTINGS, list(JOBS), targets, tenant_id=tenant, now=NOW))
    assert first == {
        "gold.refresh": "succeeded",
        "spectral.estimate": "succeeded",
        "certs.recompute": "succeeded",
    }
    sets, certs, runs = await _tenant_state(pool, tenant)
    # The open set keeps accumulating; the night mints one frozen snapshot beside it.
    assert sorted(s["frozen_at"] is not None for s in sets) == [False, True]
    # 50 labels formed + the estimator ran (an honest empty window) ⇒ bootstrapping, one
    # row per live verifier, carrying the run's failed gates; never identifiable.
    assert certs and {(c["status"], c["identifiable"]) for c in certs} == {("bootstrapping", False)}
    assert json.loads(certs[0]["diagnostics"])["failed"] == ["G1", "G3"]
    assert [(r["job"], r["outcome"], r["attempts"]) for r in runs if r["job"] in MINE] == [
        ("certs.recompute", "succeeded", 1),
        ("gold.refresh", "succeeded", 1),
        ("spectral.estimate", "succeeded", 1),
    ]

    frozen_at = [s["frozen_at"] for s in sets if s["frozen_at"] is not None]
    second = _mine(await run_many(pool, SETTINGS, list(JOBS), targets, tenant_id=tenant, now=NOW))
    assert second == {
        "gold.refresh": "already_done",
        "spectral.estimate": "already_done",
        "certs.recompute": "already_done",
    }
    sets, _, runs = await _tenant_state(pool, tenant)
    assert [s["frozen_at"] for s in sets if s["frozen_at"] is not None] == frozen_at
    assert {(r["attempts"], r["requested"]) for r in runs if r["job"] in MINE} == {(1, 2)}


async def test_snapshots_grow_with_the_open_set(pool):
    """gold.refresh mints a new frozen snapshot only when the open set grew; the latest
    snapshot (what certs cite) carries every label, so the D15 200 gate is reachable."""
    tenant = await _mk_tenant(pool)
    gold_set = await create_gold_set(pool, tenant, "claudecode")
    labels = [(random.randbytes(32), "satisfied", "human") for _ in range(GOLD_BOOTSTRAP_MIN)]
    await add_members(pool, tenant, gold_set, labels)
    await gold_refresh(SimpleNamespace(pool=pool, tenant_id=tenant))
    await gold_refresh(
        SimpleNamespace(pool=pool, tenant_id=tenant)
    )  # unchanged: no second snapshot
    await add_members(
        pool, tenant, gold_set, [(random.randbytes(32), "violated", "human") for _ in range(10)]
    )
    await gold_refresh(SimpleNamespace(pool=pool, tenant_id=tenant))
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        rows = await conn.fetch(
            "SELECT s.frozen_at, count(m.*) AS n FROM gold_sets s "
            "LEFT JOIN gold_set_members m ON m.gold_set_id = s.id "
            "WHERE s.tenant_id = $1 GROUP BY s.id, s.frozen_at ORDER BY s.frozen_at NULLS FIRST",
            UUID(tenant),
        )
    assert [(r["frozen_at"] is not None, r["n"]) for r in rows] == [
        (False, 60),
        (True, 50),
        (True, 60),
    ]


async def test_unformed_set_stays_open(pool):
    tenant = await _mk_tenant(pool)
    gold_set = await create_gold_set(pool, tenant, "claudecode")
    await add_members(pool, tenant, gold_set, [(random.randbytes(32), "violated", "t3")])
    results = await run_many(pool, SETTINGS, list(JOBS), _targets([]), tenant_id=tenant, now=NOW)
    assert _mine(results) == {
        "gold.refresh": "succeeded",
        "spectral.estimate": "succeeded",
        "certs.recompute": "succeeded",
    }
    sets, certs, _ = await _tenant_state(pool, tenant)
    assert sets[0]["frozen_at"] is None
    assert certs == []


async def test_failed_refresh_skips_recompute(pool):
    tenant = await _mk_tenant(pool)

    async def broken(ctx) -> None:
        raise RuntimeError("gold source down")

    targets = {**_targets([]), "gold.refresh": broken}
    results = await run_many(pool, SETTINGS, list(JOBS), targets, tenant_id=tenant, now=NOW)
    assert _mine(results) == {
        "gold.refresh": "failed",
        "spectral.estimate": "succeeded",
        "certs.recompute": "skipped_prereq_failed",
    }


async def test_spectral_run_lands_and_its_verdict_rides_the_cert_row(pool, simulate):
    """Planted Paper II votes through the mock choke: the spectral_runs row carries the
    passed gate + per-verifier laws, certs.recompute copies identifiable/diagnostics (and
    the verifier's own law) onto the bootstrapping cert row it issues, and the same window
    re-run upserts rather than duplicates."""
    tenant = await _mk_tenant(pool)
    judge = await _mk_judge_verifier(pool)
    async with pool.acquire() as conn:
        judge_key = await conn.fetchval(
            "SELECT verifier_key FROM m1_verifiers WHERE id = $1", judge
        )
    gold_set = await create_gold_set(pool, tenant, "claudecode")
    await add_members(
        pool,
        tenant,
        gold_set,
        [(random.randbytes(32), "satisfied", "t3") for _ in range(GOLD_BOOTSTRAP_MIN)],
    )
    votes, _ = simulate(np.random.default_rng(1), [0.4, 0.6], PAPER2, 5000)
    rows = vote_rows(votes, (judge_key, "rrm", "anchor"))

    results = await run_many(pool, SETTINGS, list(JOBS), _targets(rows), tenant_id=tenant, now=NOW)
    assert results["spectral.estimate"] == "succeeded" and results["certs.recompute"] == "succeeded"
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        run = await conn.fetchrow("SELECT * FROM spectral_runs")
        certs = await conn.fetch(
            "SELECT status::text AS status, identifiable, diagnostics, receipt_id "
            "FROM noise_certificates WHERE verifier_id = $1",
            judge,
        )
    assert run["passed"] and run["n_tasks"] == 5000
    laws = json.loads(run["confusion"])
    assert set(laws) == {judge_key, "rrm", "anchor"}
    assert abs(np.array(laws["anchor"]) - PAPER2[2]).max() < 0.03
    # Natarajan is unmeasurable (no gold-vs-verdict pairs yet) so certified is NOT claimed —
    # but the identifiability half of the claim is on the row, with this verifier's law.
    (cert,) = certs
    diag = json.loads(cert["diagnostics"])
    assert (cert["status"], cert["identifiable"]) == ("bootstrapping", True)
    assert cert["receipt_id"] is not None, "the cert row carries controld's receipt"
    assert diag["failed"] == [] and diag["confusion"] == laws[judge_key]

    again = await run_many(pool, SETTINGS, list(JOBS), _targets(rows), tenant_id=tenant, now=NOW)
    assert again["spectral.estimate"] == "already_done"
    targets = {
        **_targets(rows),
        "spectral.estimate": functools.partial(spectral_estimate, http=FakeChoke([]).client()),
    }
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        await conn.execute("DELETE FROM job_runs WHERE job = 'spectral.estimate'")
    await run_many(pool, SETTINGS, list(JOBS), targets, tenant_id=tenant, now=NOW)
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        reruns = await conn.fetch("SELECT passed FROM spectral_runs")
    assert [r["passed"] for r in reruns] == [False], "same window re-run upserts, never duplicates"
