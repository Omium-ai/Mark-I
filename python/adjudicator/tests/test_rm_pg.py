"""The RM members against real Postgres (m1_069 + m1_098): the seeded rm:mark1-rm-{a,b}@1 rows,
their one pending -> sealed publish and nothing after, the widened execution-hash CHECK, a learned
row with no head held out of fusion (fail closed), the register caller, promotion on >= 200 gold
overlaps with no certified cert, the 48 h canary hold, and the rm: cloud consent Baseten names."""

import json
import os
from uuid import UUID, uuid4

import asyncpg
import pytest
from app.db import set_local_tenant
from app.judges.cloud_path import pg_consent_reader
from app.registry.catalog import list_verifiers
from app.registry.handlers import normalize_votes
from app.registry.promotion import (
    GOLD,
    RECEIPT_TYPE,
    Measurement,
    register,
    register_catalog,
    run_promotion,
    shadow_ids,
    split_shadow,
    transition,
)
from app.rm.cloud import MODEL_ID, RmCloudSettings, admit
from app.rm.scorer import CALIBRATION_VERSION, to_raw_vote
from blake3 import blake3
from m1p.v1 import RmScore
from tests.roles import service_pool
from tests.test_jobs import RM_XH
from tests.test_pg_stores import FakeControld, _mk_tenant
from tests.test_promotion import pairs
from tests.test_rm import SEALED

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
        p = await service_pool(min_size=1, max_size=3)
    except Exception as exc:
        if REQUIRE_STORES:
            pytest.fail(f"{DSN!r} unreachable under M1_REQUIRE_STORES=1: {exc!r}", pytrace=False)
        pytest.skip(f"Postgres unreachable: {exc!r}")
    try:
        yield p
    finally:
        await p.close()


PENDING = {"kind": "rm", "group": "rm-t", "artifact": {"status": "pending"}}


async def _mk_rm_verifier(
    pool: asyncpg.Pool, key: str, definition: dict | None = None, *, tenant: str | None = None
) -> UUID:
    """A tenant fine-tune row (registers only in `tenant`) or a global one: the catalog is
    shared and immutable, so a test row must never register in every later test's tenant."""
    scope = {"tenant_id": tenant} if tenant else {"scope": "global"}
    async with pool.acquire() as conn:
        return await conn.fetchval(
            "INSERT INTO m1_verifiers (verifier_key, kind, version, display_name, definition) "
            "VALUES ($1, 'reward_model', 1, 'test rm', $2::jsonb) RETURNING id",
            key,
            json.dumps({**(definition or PENDING), **scope}),
        )


async def _mk_sealed_rm(pool: asyncpg.Pool, key: str, *, tenant: str, group: str = "rm-t") -> UUID:
    """A per-test RM row sealed the way rm-publish seals (m1_103): born pending, then its one
    pending -> sealed update, artifact.execution_hash = effective_execution_hash = RM_XH."""
    vid = await _mk_rm_verifier(
        pool, key, {"kind": "rm", "group": group, "artifact": {"status": "pending"}}, tenant=tenant
    )
    artifact = {
        "status": "sealed",
        "manifest_uri": f"s3://test/rm/{key}@1/manifest.json",
        "model_sha256": None,
        "gguf_sha256": "ab" * 32,
        "template_sha256": "cd" * 32,
        "calibration": {
            "version": CALIBRATION_VERSION,
            "scale": 1.0,
            "shift": 0.0,
            "reject_below": 0.4,
            "accept_above": 0.6,
        },
        "eval_card": {"sha256": "ef" * 32, "passed": True, "gates": []},
        "execution_hash": RM_XH.hex(),
    }
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE m1_verifiers SET definition = jsonb_set(definition, '{artifact}', $2::jsonb), "
            "effective_execution_hash = $3 WHERE id = $1",
            vid,
            json.dumps(artifact),
            RM_XH,
        )
    return vid


async def test_the_seeded_catalog_rows(pool):
    by_key = {e.verifier_key: e for e in await list_verifiers(pool)}
    a, b = by_key["rm:mark1-rm-a"], by_key["rm:mark1-rm-b"]
    for e, group in ((a, "rm-a"), (b, "rm-b")):
        assert (e.db_kind, e.kind, e.version) == ("reward_model", "rm", 1)
        assert e.definition["group"] == group and e.definition["scope"] == "global"
        assert e.definition["artifact"]["status"] == "pending"
        assert e.effective_execution_hash is None
    assert a.definition["base_family"] != b.definition["base_family"]


async def test_publish_seals_a_pending_rm_once_and_nothing_else_moves(admin):
    key = f"rm:seal-{uuid4().hex[:8]}"
    vid = await _mk_rm_verifier(admin, key)
    artifact = {
        **SEALED["artifact"],
        "status": "sealed",
        "gguf_sha256": "ab" * 32,
        "template_sha256": "cd" * 32,
        "eval_card": {"passed": True},
    }
    xh = blake3(b"GGUF sealed" + b"\x00llama.cpp b11193\x00" + b"cd" * 32).digest()  # rm-exec/v1
    artifact["execution_hash"] = xh.hex()
    seal = (
        "UPDATE m1_verifiers SET definition = jsonb_set(definition, '{artifact}', $2::jsonb), "
        "effective_execution_hash = $3 WHERE id = $1"
    )
    async with admin.acquire() as conn:
        with pytest.raises(asyncpg.InsufficientPrivilegeError, match="immutable"):
            await conn.execute(seal, vid, json.dumps(artifact), b"\x00" * 32)  # hash ≠ artifact
        legacy = {**artifact, "execution_sha256": xh.hex()}
        del legacy["execution_hash"]
        with pytest.raises(asyncpg.InsufficientPrivilegeError, match="immutable"):
            await conn.execute(seal, vid, json.dumps(legacy), xh)  # m1_098's key is superseded
        await conn.execute(seal, vid, json.dumps(artifact), xh)
        row = await conn.fetchrow(
            "SELECT definition, effective_execution_hash FROM m1_verifiers WHERE id = $1", vid
        )
        assert json.loads(row["definition"])["artifact"]["status"] == "sealed"
        assert row["effective_execution_hash"] == xh
        with pytest.raises(asyncpg.InsufficientPrivilegeError, match="immutable"):
            await conn.execute(seal, vid, json.dumps({**artifact, "gguf_sha256": "ee" * 32}), xh)
        with pytest.raises(asyncpg.InsufficientPrivilegeError, match="immutable"):
            await conn.execute(
                "UPDATE m1_verifiers SET definition = definition || $2::jsonb WHERE id = $1",
                vid,
                json.dumps({"group": "x"}),
            )
        with pytest.raises(asyncpg.CheckViolationError, match="anchor_hash"):
            await conn.execute(
                "INSERT INTO m1_verifiers (verifier_key, kind, version, display_name, definition, "
                "effective_execution_hash) VALUES ($1, 'judge', 1, 'j', '{}'::jsonb, $2)",
                f"judge:hash-{uuid4().hex[:8]}",
                xh,
            )
        await conn.execute(
            "INSERT INTO m1_verifiers (verifier_key, kind, version, display_name, definition, "
            "effective_execution_hash) VALUES ($1, 'reward_model', 1, 'r', $3::jsonb, $2)",
            f"rm:hashed-{uuid4().hex[:8]}",
            xh,
            json.dumps({"kind": "rm", "scope": "global"}),
        )


async def test_rm_without_a_head_is_held_out_until_registered_and_promoted(admin, pool):
    tenant = await _mk_tenant(admin)
    key = f"rm:head-{tenant[:8]}"
    rm_id = f"{key}@1"
    verifier = await _mk_rm_verifier(admin, key, tenant=tenant)
    async with pool.acquire() as conn:
        assert rm_id in await shadow_ids(conn, tenant), "no head: fail closed"
        (entry,) = [e for e in await list_verifiers(pool) if e.verifier_key == key]
        born = await register_catalog(conn, tenant_id=tenant, entries=[entry])
        assert len(born) == 1
        assert await register_catalog(conn, tenant_id=tenant, entries=[entry]) == []
        async with conn.transaction():
            await set_local_tenant(conn, tenant)
            state = await conn.fetchval(
                "SELECT state FROM m1_verifier_promotions WHERE verifier_id = $1", verifier
            )
        assert state == "probation"
        non_serving = await shadow_ids(conn, tenant)
    assert rm_id in non_serving
    raw = to_raw_vote(RmScore(rm_id, 0.95, CALIBRATION_VERSION), UUID(int=1), UUID(int=2), b"")
    votes, refusals = await normalize_votes([raw], {rm_id: entry})
    assert refusals == [] and votes[0].tier == "T2"
    fused, shadow = split_shadow(votes, non_serving)
    assert fused == [] and [v.verifier_id for v in shadow] == [rm_id]


async def test_register_caller_skips_global_scope_without_the_global_tenant(admin, pool):
    tenant = await _mk_tenant(admin)
    global_rm = [e for e in await list_verifiers(pool) if e.verifier_key == "rm:mark1-rm-a"]
    async with pool.acquire() as conn:
        assert await register_catalog(conn, tenant_id=tenant, entries=global_rm) == []


async def test_gold_overlaps_promote_with_no_certified_cert_and_canary_holds_48h(admin, pool):
    tenant = await _mk_tenant(admin)
    verifier = await _mk_rm_verifier(
        admin, f"rm:gold-{tenant[:8]}", {**SEALED, "artifact": {}}, tenant=tenant
    )
    controld = FakeControld(RECEIPT_TYPE)
    append = controld.append()
    async with pool.acquire() as conn:
        pid = await register(conn, tenant_id=tenant, verifier_id=verifier)
        await transition(
            conn,
            append,
            tenant_id=tenant,
            promotion_id=pid,
            from_state="probation",
            to_state="shadow",
            reason="eval_card_complete",
        )
        few = Measurement(pairs(150, 0.8, 0.1, cert=GOLD), votes=600)
        rep = await run_promotion(conn, append, tenant_id=tenant, measured={pid: few})
        assert rep.promoted == 0
        gold = Measurement(pairs(260, 0.8, 0.1, cert=GOLD), votes=600)
        rep = await run_promotion(conn, append, tenant_id=tenant, measured={pid: gold})
        async with conn.transaction():
            await set_local_tenant(conn, tenant)
            head = await conn.fetchrow("SELECT * FROM m1_verifier_promotions WHERE id = $1", pid)
            evidence = await conn.fetchval(
                "SELECT evidence FROM m1_verifier_promotion_transitions "
                "WHERE promotion_id = $1 AND to_state = 'lcb_promoted'",
                pid,
            )
        assert rep.promoted == 1 and head["state"] == "lcb_promoted"
        assert head["cert_id"] is None and head["gold_n"] == 260 and head["shadow_n"] == 600
        assert json.loads(evidence)["gold_n"] == 260
        rep = await run_promotion(conn, append, tenant_id=tenant, measured={})
        with pytest.raises(asyncpg.CheckViolationError, match="canary_hold"):
            await transition(
                conn,
                append,
                tenant_id=tenant,
                promotion_id=pid,
                from_state="canary",
                to_state="active",
                reason="too_soon",
            )


async def test_rm_consent_names_baseten_and_admits_only_e1(admin, pool):
    tenant = await _mk_tenant(admin)
    async with admin.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        await conn.execute(
            "INSERT INTO m1_cloud_judge_consents (tenant_id, judge_id, subprocessor, region, "
            "max_tier, consented_by) VALUES ($1, $2, 'baseten', 'us', 'E1', 'test')",
            UUID(tenant),
            MODEL_ID,
        )
    async with admin.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        with pytest.raises(asyncpg.CheckViolationError):
            await conn.execute(
                "INSERT INTO m1_cloud_judge_consents (tenant_id, judge_id, subprocessor, region, "
                "max_tier, consented_by) VALUES ($1, 'anchor:ruff@1', 'baseten', 'us', 'E1', 't')",
                UUID(tenant),
            )
    consent = await pg_consent_reader(pool)(UUID(tenant), MODEL_ID)
    assert consent is not None and admit(RmCloudSettings(), consent) is None
