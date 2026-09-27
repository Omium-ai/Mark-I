"""m1_105 against real Postgres: every latest-row read intel makes takes the row written last
(row_seq), never the newest timestamp, so a wall clock stepped backwards between two writes can
neither resurrect a withdrawn consent nor hand a re-enrolled device back to its old owner."""

import random
from datetime import timedelta
from uuid import UUID, uuid4

import test_corpus_pg_gate as gate
from app.corpus.contributions import live_rows
from app.corpus.export import training_consented
from app.db import set_local_tenant
from app.digest.weekly import _DEVICE_OWNERS
from app.memory.extract import device_owners
from app.memory.retrieve import LATEST_TEAM_CONSENT
from test_corpus_pg_gate import _mk_tenant, pytestmark  # noqa: F401 — the DSN gate
from test_memory_team_pg import _mk_device

pool = gate.pool


async def _record(db, tenant: str, device: str, on: bool, skew: timedelta) -> None:
    async with db.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        await conn.execute(
            "INSERT INTO m1_device_consents (tenant_id, device_id, e1, cloud_judge, training, "
            "team, contribute_outcomes, recorded_at) "
            "VALUES ($1, $2, $3, $3, $3, $3, $3, now() + $4)",
            UUID(tenant),
            UUID(device),
            on,
            skew,
        )


async def _consent_reads(db, tenant: str) -> tuple[bool, int, bool]:
    async with db.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        training = await training_consented(conn, tenant)
        rows, _ = await live_rows(conn)
        team = await conn.fetchval(
            f"SELECT {LATEST_TEAM_CONSENT.format(subject='$2')} IS TRUE",
            UUID(tenant),
            "omium:alice",
        )
    return training, len(rows), team


async def test_the_last_written_consent_wins_whatever_its_clock_says(admin, pool):
    tenant = await _mk_tenant(admin)
    async with admin.acquire() as conn:
        device = await _mk_device(conn, tenant, "omium:alice")
    async with admin.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        await conn.execute(
            "INSERT INTO m1_outcome_contributions (tenant_id, event_id, batch_id, device_id, "
            "session_id, task_id, object_key) VALUES ($1, $2, $3, $4, $5, $6, 'k')",
            UUID(tenant),
            uuid4(),
            uuid4(),
            UUID(device),
            uuid4(),
            uuid4(),
        )
    await _record(admin, tenant, device, True, timedelta(0))
    assert await _consent_reads(pool, tenant) == (True, 1, True)
    await _record(admin, tenant, device, False, timedelta(hours=-1))
    assert await _consent_reads(pool, tenant) == (False, 0, False), "an early-stamped withdrawal"
    await _record(admin, tenant, device, True, timedelta(hours=-2))
    assert await _consent_reads(pool, tenant) == (True, 1, True), "an early-stamped re-grant"


async def test_a_re_enrolled_device_belongs_to_its_last_enrollment_whatever_its_clock_says(
    admin, pool
):
    tenant = await _mk_tenant(admin)
    async with admin.acquire() as conn:
        device = await _mk_device(conn, tenant, "omium:alice")
        async with conn.transaction():
            await set_local_tenant(conn, tenant)
            await conn.execute(
                "UPDATE m1_device_enrollments SET status = 'revoked' WHERE device_id = $1",
                UUID(device),
            )
            await conn.execute(
                "INSERT INTO m1_device_enrollments (tenant_id, device_id, device_code_hash, "
                "device_pubkey, oidc_subject, status, token_hash, started_at, token_expires_at) "
                "VALUES ($1, $2, $3, $4, 'omium:carol', 'approved', $5, now() - interval '1 hour', "
                "now())",
                UUID(tenant),
                UUID(device),
                random.randbytes(32),
                random.randbytes(32),
                random.randbytes(32),
            )
    async with pool.acquire() as conn:
        owners, _ = await device_owners(conn, tenant)
        async with conn.transaction():
            await set_local_tenant(conn, tenant)
            digest = {
                r["device_id"]: r["oidc_subject"]
                for r in await conn.fetch(_DEVICE_OWNERS, UUID(tenant))
            }
    assert owners[device] == digest[device] == "omium:carol"
