"""pg_receipt_reader against real Postgres (m1_077): the bound receipt reads back under the
tenant GUC, RLS hides it from another tenant, and the row is what admit() keys on."""

import hashlib
import os
from uuid import UUID, uuid4

import asyncpg
import pytest
from app.certified.archive import Excerpt, RedactionReceipt, admit, pg_receipt_reader
from app.db import set_local_tenant
from tests.roles import service_pool
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
        p = await service_pool(min_size=1, max_size=3)
    except Exception as exc:
        if REQUIRE_STORES:
            pytest.fail(f"{DSN!r} unreachable under M1_REQUIRE_STORES=1: {exc!r}", pytrace=False)
        pytest.skip(f"Postgres unreachable: {exc!r}")
    try:
        yield p
    finally:
        await p.close()


async def _mk_receipt(pool: asyncpg.Pool, tenant: str, x: Excerpt, part: bytes) -> None:
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        device = await conn.fetchval(
            "INSERT INTO m1_devices (tenant_id, platform, hostname_hmac) "
            "VALUES ($1, 'linux', $2) RETURNING id",
            UUID(tenant),
            bytes(32),
        )
        key_id = f"ed25519:{x.receipt_id[:8].hex()}"
        await conn.execute(
            "INSERT INTO m1_device_keys (tenant_id, device_id, key_id, public_key) "
            "VALUES ($1, $2, $3, $4)",
            UUID(tenant),
            device,
            key_id,
            bytes(32),
        )
        await conn.execute(
            "INSERT INTO m1_redaction_receipts (tenant_id, receipt_id, device_id, device_key_id, "
            "device_signature, subject_id, payload, pre_hash, post_hash, excerpt_event_id) "
            "VALUES ($1, $2, $3, $4, $5, $6, '{}', $7, $8, $9)",
            UUID(tenant),
            x.receipt_id,
            device,
            key_id,
            bytes(64),
            x.evidence_event_id,
            hashlib.sha256(b"raw").digest(),
            hashlib.sha256(part).digest(),
            x.event_id,
        )


async def test_bound_receipt_reads_back_under_its_tenant_only(admin, pool):
    tenant, other = await _mk_tenant(admin), await _mk_tenant(admin)
    part = b"+sanitized\n"
    x = Excerpt(uuid4(), uuid4(), "attach.x.e1", hashlib.sha256(tenant.encode()).digest())
    await _mk_receipt(admin, tenant, x, part)

    got = await pg_receipt_reader(pool, UUID(tenant))(x.receipt_id)
    assert got == RedactionReceipt(x.evidence_event_id, hashlib.sha256(part).digest(), x.event_id)
    assert admit(x, got, part) is None
    assert admit(x, got, part + b"!") == "refused_post_hash_mismatch"
    assert await pg_receipt_reader(pool, UUID(other))(x.receipt_id) is None
    assert await pg_receipt_reader(pool, UUID(tenant))(bytes(32)) is None
