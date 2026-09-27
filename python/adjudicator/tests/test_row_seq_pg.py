"""m1_105 against real Postgres: every latest-row read the adjudicator makes takes the row written
last (row_seq), never the newest timestamp, so a wall clock stepped backwards between two writes
cannot resurrect a withdrawn consent, an older certificate, a superseded label or an older set."""

import random
from datetime import timedelta
from uuid import UUID

from app.certs.store import current_cert
from app.db import set_local_tenant
from app.gold.select import add_members, create_gold_set, freeze_gold_set
from app.jobs.nightly import _gold_labels, _latest_set
from app.rm.cloud import cloud_devices
from tests import test_rm_pg
from tests.test_pg_stores import _mk_judge_verifier, _mk_tenant
from tests.test_rm_pg import pytestmark  # noqa: F401 — the DSN gate

pool = test_rm_pg.pool
EARLY = timedelta(hours=-1)


async def test_the_last_written_consent_wins_whatever_its_clock_says(admin, pool):
    tenant = await _mk_tenant(admin)
    async with admin.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        device = await conn.fetchval(
            "INSERT INTO m1_devices (tenant_id, platform, hostname_hmac) "
            "VALUES ($1, 'linux', $2) RETURNING id",
            UUID(tenant),
            random.randbytes(32),
        )

    async def record(on: bool, skew: timedelta) -> set[UUID]:
        async with admin.acquire() as conn, conn.transaction():
            await set_local_tenant(conn, tenant)
            await conn.execute(
                "INSERT INTO m1_device_consents (tenant_id, device_id, e1, cloud_judge, training, "
                "cloud_rm, recorded_at) "
                "VALUES ($1, $2, $3, false, false, $3, now() + $4::interval)",
                UUID(tenant),
                device,
                on,
                skew,
            )
        return await cloud_devices(pool, UUID(tenant))

    assert await record(True, timedelta(0)) == {device}
    assert await record(False, EARLY) == set(), "an early-stamped withdrawal"
    assert await record(True, 2 * EARLY) == {device}, "an early-stamped re-grant"


async def test_the_certificate_written_last_is_current_whatever_its_issued_at(admin, pool):
    tenant = await _mk_tenant(admin)
    verifier = await _mk_judge_verifier(admin)
    ids = []
    for skew in (timedelta(0), EARLY):
        async with pool.acquire() as conn, conn.transaction():
            await set_local_tenant(conn, tenant)
            ids.append(
                await conn.fetchval(
                    "INSERT INTO noise_certificates (tenant_id, verifier_id, status, issued_at, "
                    "expires_at) VALUES ($1, $2, 'bootstrapping', now() + $3::interval, "
                    "now() + interval '30 days') RETURNING id",
                    UUID(tenant),
                    verifier,
                    skew,
                )
            )
    assert (await current_cert(pool, tenant)).id == ids[1]


async def test_a_relabel_and_a_freeze_are_newer_than_what_they_supersede(admin, pool):
    """A relabel in the open set outranks the frozen snapshot's copy even when the snapshot's
    labeled_at reads later; the set frozen last is the latest frozen set."""
    tenant = await _mk_tenant(admin)
    digest = random.randbytes(32)
    open_set = await create_gold_set(pool, tenant, "claudecode")
    await add_members(pool, tenant, open_set, [(digest, "satisfied", "human")])
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        snapshot = await conn.fetchval(
            "INSERT INTO gold_sets (tenant_id, agent, frozen_at) "
            "VALUES ($1, 'claudecode', now() - $2::interval) RETURNING id",
            UUID(tenant),
            EARLY,
        )
        await conn.execute(
            "INSERT INTO gold_set_members (gold_set_id, tenant_id, task_digest, true_label, "
            "label_source, labeled_at) "
            "VALUES ($1, $2, $3, 'satisfied', 'human', now() - $4::interval)",
            snapshot,
            UUID(tenant),
            digest,
            EARLY,
        )
    await add_members(pool, tenant, open_set, [(digest, "violated", "human")])
    async with pool.acquire() as conn:
        assert (await _gold_labels(conn, tenant))[digest] == "violated"
    second = await create_gold_set(pool, tenant, "claudecode")
    await freeze_gold_set(pool, tenant, second)
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        latest = await _latest_set(conn, tenant, frozen=True)
    assert latest["id"] == second != snapshot
    assert latest["frozen_at"] < (await _frozen_at(pool, tenant, snapshot))


async def _frozen_at(db, tenant: str, set_id: UUID):
    async with db.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        return await conn.fetchval("SELECT frozen_at FROM gold_sets WHERE id = $1", set_id)
