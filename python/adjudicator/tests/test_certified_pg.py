"""m1_074 against real Postgres: the t3: consent key the register now admits, the run
row (FK to the consent it ran under, E1-only CHECK, signed divergence, the tenant's
running mean), the RLS negative, and the runner end to end over a fake E2B."""

import json
import os
from datetime import UTC, datetime
from uuid import UUID, uuid4

import asyncpg
import pytest
from app.certified.runner import (
    CONSENT_ID,
    CONSISTENCY_ID,
    CertifiedRunner,
    RunRow,
    definition,
    execution_hash,
    pg_run_recorder,
    pg_t3_consent_reader,
)
from app.db import _tenant_guc_reset, set_local_tenant
from app.judges.cloud_path import Consent
from app.registry.catalog import entry_from_row
from mark1_receipts import canonical_json
from tests.test_certified import ANCHOR, T3_ID, TEMPLATE, FakeE2B, Harness
from tests.test_pg_stores import _mk_tenant

DSN = os.environ.get("M1_TEST_PG_DSN", "")
REQUIRE_STORES = os.environ.get("M1_REQUIRE_STORES", "0") == "1"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not DSN and not REQUIRE_STORES,
        reason="M1_TEST_PG_DSN not set (estate skipif idiom; M1_REQUIRE_STORES=0)",
    ),
]


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


async def _consent(pool, tenant: UUID, key=CONSENT_ID, max_tier="E1") -> UUID:
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, str(tenant))
        return await conn.fetchval(
            """
            INSERT INTO m1_cloud_judge_consents
              (tenant_id, judge_id, subprocessor, region, max_tier, consented_by)
            VALUES ($1, $2, 'e2b', 'us', $3, 'test') RETURNING id
            """,
            tenant,
            key,
            max_tier,
        )


def _row(tenant: UUID, consent: UUID, div: int, **kw) -> RunRow:
    base = dict(
        tenant_id=tenant,
        consent_id=consent,
        task_id=uuid4(),
        attempt_id=uuid4(),
        anchor_id=ANCHOR,
        sandbox_id="sb-pg",
        evidence_tier="E1",
        execution_hash=execution_hash(ANCHOR, TEMPLATE),
        exit_code=1,
        verdict="violated",
        edge_verdict="satisfied",
        provisional="satisfied",
        divergence=div,
        started_at=datetime.now(UTC),
    )
    base.update(kw)
    return RunRow(**base)


async def test_register_admits_t3_keys_beside_judge_keys_and_nothing_else(pool):
    tenant = UUID(await _mk_tenant(pool))
    read = pg_t3_consent_reader(pool)
    assert await read(tenant, CONSENT_ID) is None
    cid = await _consent(pool, tenant)
    await _consent(pool, tenant, key="judge:grounded-rubric@1", max_tier="E0")
    got = await read(tenant, CONSENT_ID)
    assert got == (cid, Consent("e2b", "us", "E1"))
    with pytest.raises(asyncpg.CheckViolationError):
        await _consent(pool, tenant, key="sandbox:e2b@1")
    with pytest.raises(asyncpg.CheckViolationError):
        await _consent(pool, UUID(await _mk_tenant(pool)), max_tier="E2")


async def test_run_rows_carry_signed_divergence_and_the_tenant_running_mean(pool):
    a, b = UUID(await _mk_tenant(pool)), UUID(await _mk_tenant(pool))
    ca, cb = await _consent(pool, a), await _consent(pool, b)
    record = pg_run_recorder(pool)
    _, m1 = await record(_row(a, ca, 1))
    _, m2 = await record(_row(a, ca, 1))
    _, m3 = await record(_row(a, ca, -1, verdict="satisfied", edge_verdict="violated"))
    assert (m1, m2, m3) == (1.0, 1.0, pytest.approx(1 / 3))
    _, mb = await record(_row(b, cb, 0, verdict="satisfied"))
    assert mb == 0.0  # b's mean is b's alone
    with pytest.raises(asyncpg.CheckViolationError):
        await record(_row(b, cb, 0, evidence_tier="E0"))
    with pytest.raises(asyncpg.CheckViolationError):
        await record(_row(b, cb, 2))
    with pytest.raises(asyncpg.ForeignKeyViolationError):
        await record(_row(b, uuid4(), 0))


async def test_rls_isolation_on_certified_runs(pool):
    async with pool.acquire() as conn:
        bypass = await conn.fetchval(
            "SELECT rolbypassrls OR rolsuper FROM pg_roles WHERE rolname = current_user"
        )
    if bypass:
        msg = "test role bypasses RLS — isolation not observable from here"
        if REQUIRE_STORES:
            pytest.fail(msg, pytrace=False)
        pytest.skip(msg)
    a, b = UUID(await _mk_tenant(pool)), UUID(await _mk_tenant(pool))
    ca = await _consent(pool, a)
    run_id, _ = await pg_run_recorder(pool)(_row(a, ca, 1))
    async with pool.acquire() as conn:
        assert await conn.fetchval("SELECT count(*) FROM m1_certified_runs") == 0  # no GUC
        async with conn.transaction():
            await set_local_tenant(conn, str(b))
            assert run_id not in {
                r["id"] for r in await conn.fetch("SELECT id FROM m1_certified_runs")
            }
        # A write for tenant A under tenant B's GUC is refused by WITH CHECK, not laundered.
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            async with conn.transaction():
                await set_local_tenant(conn, str(b))
                await conn.execute(
                    """
                    INSERT INTO m1_certified_runs
                      (tenant_id, consent_id, task_id, attempt_id, anchor_id, provider,
                       evidence_tier, execution_hash, verdict, edge_verdict, provisional,
                       divergence, tenant_divergence, started_at)
                    VALUES ($1, $2, $3, $4, $5, 'e2b', 'E1', $6, 'error', 'error', 'error',
                            0, 0, now())
                    """,
                    a,
                    ca,
                    uuid4(),
                    uuid4(),
                    ANCHOR,
                    b"\x00" * 32,
                )


async def test_runner_end_to_end_lands_a_row_the_registry_recognises(pool):
    tenant = UUID(await _mk_tenant(pool))
    cid = await _consent(pool, tenant)
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            INSERT INTO m1_verifiers (verifier_key, kind, version, display_name, definition,
                                      effective_execution_hash)
            VALUES ($1, 'anchor', 1, 't3 pytest', $2::jsonb, $3),
                   ($4, 'consistency', 1, 't3 consistency', '{"kind": "consistency"}'::jsonb, NULL)
            RETURNING id, verifier_key, version, kind, definition, effective_execution_hash,
                      retired_at
            """,
            f"{T3_ID.split('@')[0]}-{tenant.hex[:8]}",
            canonical_json(definition(ANCHOR, TEMPLATE)),
            execution_hash(ANCHOR, TEMPLATE),
            f"consistency:t3-rerun-{tenant.hex[:8]}",
        )
    registry = {}
    for r in rows:
        d = dict(r)
        d["definition"] = json.loads(d["definition"])
        e = entry_from_row(d)
        registry[T3_ID if e.db_kind == "anchor" else CONSISTENCY_ID] = e
    h = Harness(FakeE2B(stdout=b"FAILED tests/test_x.py::t\n", exit_code=1), registry=registry)
    runner = CertifiedRunner(
        h.client,
        pg_t3_consent_reader(pool),
        h.runner._archive_for,
        pg_run_recorder(pool),
        registry,
        TEMPLATE,
        "us",
    )
    run = await runner.run(tenant, uuid4(), uuid4(), ANCHOR, "E1", "satisfied", "satisfied")
    assert run.verdict == "violated" and run.refusals == [] and run.divergence == 1
    assert all(v.tier == "T3" for v in run.votes) and not any(v.integrity.tamper for v in run.votes)
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, str(tenant))
        row = await conn.fetchrow("SELECT * FROM m1_certified_runs WHERE id = $1", run.run_id)
    assert row["consent_id"] == cid and row["sandbox_id"] == "sb-1"
    assert (row["verdict"], row["edge_verdict"], row["divergence"]) == ("violated", "satisfied", 1)
    assert bytes(row["execution_hash"]) == registry[T3_ID].effective_execution_hash
    assert row["receipt_id"] is None  # no certified_run receipt class exists yet
