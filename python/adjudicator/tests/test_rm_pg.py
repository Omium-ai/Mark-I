"""The RM member against real Postgres: its m1_020 catalog row resolves to kind=rm, it registers
in probation through promotion.register (m1_069: no other birth state), shadow_ids lists it as
non-serving so split_shadow keeps it out of fusion, and m1_065 cannot yet hold an rm: consent."""

import json
import os
from uuid import UUID

import asyncpg
import pytest
from app.db import _tenant_guc_reset, set_local_tenant
from app.judges.cloud_path import pg_consent_reader
from app.registry.catalog import list_verifiers
from app.registry.handlers import normalize_votes
from app.registry.promotion import register, shadow_ids, split_shadow
from app.rm.scorer import CALIBRATION_VERSION, RmSettings, definition, to_raw_vote
from m1p.v1 import RmScore
from tests.test_pg_stores import _mk_tenant

DSN = os.environ.get("M1_TEST_PG_DSN", "")
REQUIRE_STORES = os.environ.get("M1_REQUIRE_STORES", "0") == "1"
SETTINGS = RmSettings(base_url="http://rm.test/v1", api_key="k")

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


async def _mk_rm_verifier(pool: asyncpg.Pool, key: str) -> UUID:
    async with pool.acquire() as conn:
        return await conn.fetchval(
            "INSERT INTO m1_verifiers (verifier_key, kind, version, display_name, definition) "
            "VALUES ($1, 'reward_model', 1, 'test rm', $2::jsonb) RETURNING id",
            key,
            json.dumps(definition(SETTINGS)),
        )


async def test_rm_registers_in_probation_and_stays_out_of_fusion(pool):
    tenant = await _mk_tenant(pool)
    key = f"rm:qwen3-4b-{tenant[:8]}"
    rm_id = f"{key}@1"
    verifier = await _mk_rm_verifier(pool, key)
    async with pool.acquire() as conn:
        await register(conn, tenant_id=tenant, verifier_id=verifier)
        async with conn.transaction():
            await set_local_tenant(conn, tenant)
            state = await conn.fetchval(
                "SELECT state FROM m1_verifier_promotions WHERE verifier_id = $1", verifier
            )
        assert state == "probation"
        non_serving = await shadow_ids(conn, tenant)
    assert rm_id in non_serving

    (entry,) = [e for e in await list_verifiers(pool) if e.verifier_key == key]
    assert (entry.kind, entry.db_kind, entry.effective_execution_hash) == (
        "rm",
        "reward_model",
        None,
    )
    raw = to_raw_vote(RmScore(rm_id, 0.95, CALIBRATION_VERSION), UUID(int=1), UUID(int=2), b"")
    votes, refusals = await normalize_votes([raw], {rm_id: entry})
    assert refusals == [] and votes[0].tier == "T2"
    fused, shadow = split_shadow(votes, non_serving)
    assert fused == [] and [v.verifier_id for v in shadow] == [rm_id]


async def test_m1_073_holds_an_rm_consent_and_still_refuses_other_prefixes(pool):
    tenant = await _mk_tenant(pool)
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        await conn.execute(
            "INSERT INTO m1_cloud_judge_consents (tenant_id, judge_id, subprocessor, region, "
            "max_tier, consented_by) VALUES ($1, $2, 'omium', 'us', 'E1', 'test')",
            UUID(tenant),
            SETTINGS.rm_id,
        )
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        with pytest.raises(asyncpg.CheckViolationError):
            await conn.execute(
                "INSERT INTO m1_cloud_judge_consents (tenant_id, judge_id, subprocessor, region, "
                "max_tier, consented_by) VALUES ($1, 'anchor:ruff@1', 'omium', 'us', 'E1', 'test')",
                UUID(tenant),
            )
    consent = await pg_consent_reader(pool)(UUID(tenant), SETTINGS.rm_id)
    assert consent is not None and consent.max_tier == "E1" and consent.region == "us"
