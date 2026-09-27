"""Retrieval against real Postgres (m1_040): the admitted allowlist under RLS, the halfvec stamp,
and the planted-neighbor recovery over ix_artifacts_error_signature (FR-REMEMBER-004/008)."""

import os
from decimal import Decimal
from uuid import uuid4

import pytest
from app.db import set_local_tenant
from app.memory import admit, extract, retrieve
from test_memory_pg import _mk_cert, _mk_device, _mk_tenant, fake_append
from test_memory_retrieve import FAR, NEAR, PLANTED
from tests.roles import service_pool

DSN = os.environ.get("M1_TEST_PG_DSN", "")
REQUIRE_STORES = os.environ.get("M1_REQUIRE_STORES", "0") == "1"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not DSN and not REQUIRE_STORES, reason="M1_TEST_PG_DSN not set"),
]


@pytest.fixture
async def conn():
    if not DSN:
        pytest.fail("M1_TEST_PG_DSN is unset and M1_REQUIRE_STORES=1", pytrace=False)
    try:
        p = await service_pool(min_size=1, max_size=1)
    except Exception as exc:
        if REQUIRE_STORES:
            pytest.fail(f"M1_REQUIRE_STORES=1 and {DSN!r} is unreachable: {exc!r}", pytrace=False)
        pytest.skip(f"Postgres unreachable: {exc!r}")
    try:
        async with p.acquire() as c:
            yield c
    finally:
        await p.close()


async def _plant(conn, tenant, cert, device, kind, trigger, *, admitted=True, lcb="0.25"):
    guidance = f"guidance-{uuid4().hex[:6]}"
    a = extract.Artifact(
        id=extract.artifact_id(tenant, kind, trigger, guidance),
        tenant_id=tenant,
        kind=kind,
        body={
            "trigger": trigger,
            "guidance": guidance,
            "evidence": ["d1"],
            "provenance": {"device_id": device, "task_id": "t", "session_id": "s", "verdict": "x"},
            "support_n": 1,
        },
        cert_id=cert,
    )
    assert await extract.insert_artifacts(conn, tenant, [a]) == 1
    if admitted:
        await admit.admit_artifact(
            conn,
            fake_append(),
            tenant_id=tenant,
            artifact_id=a.id,
            kind=kind,
            lcb=Decimal(lcb),
            n_obs=10,
            cert_id=cert,
            idempotency_key=f"t:{a.id}",
        )
    return str(a.id)


async def test_admitted_serves_only_the_injectable_allowlist_in_tenant(admin_conn, conn):
    tenant, other = await _mk_tenant(admin_conn), await _mk_tenant(admin_conn)
    cert, device = await _mk_cert(admin_conn, tenant), await _mk_device(admin_conn, tenant)
    o_cert, o_device = await _mk_cert(admin_conn, other), await _mk_device(admin_conn, other)
    low = await _plant(conn, tenant, cert, device, "pitfall", PLANTED, lcb="0.10")
    high = await _plant(conn, tenant, cert, device, "fix_pattern", "when tests flake", lcb="0.90")
    await _plant(conn, tenant, cert, device, "preference", "prefer haiku for lint")
    await _plant(conn, tenant, cert, device, "invariant", "config is yaml", admitted=False)
    await _plant(conn, other, o_cert, o_device, "pitfall", PLANTED)

    rows = await retrieve.admitted(conn, tenant)
    assert [r["artifact_id"] for r in rows] == [high, low]
    assert rows[0]["utility_lcb"] == 0.9 and "error_sig_digest" not in rows[0]
    assert rows[1]["error_sig_digest"] == retrieve.signature_digest(
        retrieve.normalize_signature(PLANTED)
    )
    assert [r["artifact_id"] for r in await retrieve.admitted(conn, other)] != [high, low]


async def test_embed_missing_stamps_pitfalls_once(admin_conn, conn):
    tenant = await _mk_tenant(admin_conn)
    cert, device = await _mk_cert(admin_conn, tenant), await _mk_device(admin_conn, tenant)
    pid = await _plant(conn, tenant, cert, device, "pitfall", PLANTED)
    await _plant(conn, tenant, cert, device, "pitfall", "   ")
    await _plant(conn, tenant, cert, device, "fix_pattern", "not a pitfall")
    assert await retrieve.embed_missing(conn, tenant) == 1
    assert await retrieve.embed_missing(conn, tenant) == 0
    async with conn.transaction():
        await set_local_tenant(conn, tenant)
        stamped = await conn.fetch(
            "SELECT id, vector_dims(error_signature) AS d FROM memory_artifacts "
            "WHERE error_signature IS NOT NULL"
        )
    assert [(str(r["id"]), r["d"]) for r in stamped] == [(pid, retrieve.DIM)]


async def test_planted_neighbor_recovered_within_d29_over_the_hnsw_column(admin_conn, conn):
    tenant, other = await _mk_tenant(admin_conn), await _mk_tenant(admin_conn)
    cert, device = await _mk_cert(admin_conn, tenant), await _mk_device(admin_conn, tenant)
    o_cert, o_device = await _mk_cert(admin_conn, other), await _mk_device(admin_conn, other)
    planted = await _plant(conn, tenant, cert, device, "pitfall", PLANTED)
    far = await _plant(conn, tenant, cert, device, "pitfall", FAR)
    await _plant(conn, tenant, cert, device, "pitfall", NEAR, admitted=False)
    await _plant(conn, other, o_cert, o_device, "pitfall", NEAR)
    for t in (tenant, other):
        await retrieve.embed_missing(conn, t)
    decoy = await _plant(conn, tenant, cert, device, "fix_pattern", PLANTED)
    async with conn.transaction():
        await set_local_tenant(conn, tenant)
        await conn.execute(
            "UPDATE memory_artifacts SET error_signature = $2::text::halfvec WHERE id = $1",
            decoy,
            retrieve.vector_literal(retrieve.embed(retrieve.normalize_signature(PLANTED))),
        )

    near = await retrieve.fuzzy_match(conn, tenant, retrieve.normalize_signature(NEAR))
    assert [a["artifact_id"] for a in near] == [planted]
    assert 0.0 < near[0]["distance"] <= retrieve.FUZZ_DISTANCE, near[0]["distance"]

    exact = await retrieve.fuzzy_match(
        conn, tenant, retrieve.normalize_signature(PLANTED.replace("3 attempts", "9 attempts"))
    )
    assert [a["artifact_id"] for a in exact] == [planted] and exact[0]["distance"] < 1e-3

    assert [
        a["artifact_id"]
        for a in await retrieve.fuzzy_match(conn, tenant, retrieve.normalize_signature(FAR))
    ] == [far]
    assert (
        await retrieve.fuzzy_match(
            conn, tenant, retrieve.normalize_signature("segfault in libfoo.so at 0x0001")
        )
        == []
    )
    assert await retrieve.fuzzy_match(conn, tenant, "") == []

    async with conn.transaction():
        await set_local_tenant(conn, tenant)
        await conn.execute("SET LOCAL enable_seqscan = off")
        plan = await conn.fetch(
            "EXPLAIN SELECT id FROM memory_artifacts WHERE error_signature IS NOT NULL "
            "ORDER BY error_signature <=> $1::text::halfvec LIMIT 3",
            retrieve.vector_literal(retrieve.embed(retrieve.normalize_signature(NEAR))),
        )
    assert any("ix_artifacts_error_signature" in r[0] for r in plan), plan
