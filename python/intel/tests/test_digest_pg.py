"""digest.weekly against real Postgres (m1_091) and the strict querychoke mock: only opted-in people
still in the tenant, only those with work that week, the refusal without a postal address, and a
send ledger that retries failures without ever mailing anyone twice."""

import random
from datetime import UTC, date, datetime
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from app.db import set_local_tenant
from app.digest import weekly as digest
from choke_mock import MockChoke
from test_jobs_pg import (
    pool,  # noqa: F401 — the DSN-gated pool fixture
    pytestmark,  # noqa: F401 — the DSN gate
)

WEEK = date(2026, 9, 14)


async def _world(pool):  # noqa: F811
    tag = uuid4().hex[:8]
    alice, bob, carol, dave, eve = (
        f"omium:{n}-{tag}" for n in ("alice", "bob", "carol", "dave", "eve")
    )
    tenant = uuid4()
    devices = {}
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, str(tenant))
        await conn.execute(
            "INSERT INTO m1_tenants (id, name, kind, owner_subject) "
            "VALUES ($1, $2, 'personal', $3)",
            tenant,
            f"digest-{tag}",
            alice,
        )
        for s, left in ((bob, False), (carol, True), (dave, False), (eve, False)):
            await conn.execute(
                "INSERT INTO m1_team_members (tenant_id, subject, role, left_at) "
                "VALUES ($1, $2, 'member', $3)",
                tenant,
                s,
                datetime.now(UTC) if left else None,
            )
        for s in (alice, bob, carol):
            d = await conn.fetchval(
                "INSERT INTO m1_devices (tenant_id, platform, hostname_hmac) "
                "VALUES ($1, 'linux', $2) RETURNING id",
                tenant,
                random.randbytes(32),
            )
            await conn.execute(
                "INSERT INTO m1_device_enrollments (tenant_id, device_id, device_code_hash, "
                "device_pubkey, "
                "oidc_subject, status, token_hash, token_expires_at) "
                "VALUES ($1, $2, $3, $4, $5, 'approved', $6, now() + interval '1 hour')",
                tenant,
                d,
                random.randbytes(32),
                random.randbytes(32),
                s,
                random.randbytes(32),
            )
            devices[s] = str(d)
        for s, on in ((alice, True), (bob, True), (carol, True), (dave, True), (eve, False)):
            await conn.execute(
                "INSERT INTO m1_notification_prefs (tenant_id, subject, email, weekly_digest) "
                "VALUES ($1, $2, $3, $4)",
                tenant,
                s,
                s.split(":")[1] + "@it.example",
                on,
            )
    return str(tenant), (alice, bob, carol, dave), devices


async def _ledger(pool, tenant):  # noqa: F811
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        rows = await conn.fetch(
            "SELECT subject, outcome, delivery_id FROM m1_notification_sends "
            "WHERE tenant_id = $1 AND period_start = $2",
            UUID(tenant),
            WEEK,
        )
    return {r["subject"]: (r["outcome"], r["delivery_id"]) for r in rows}


async def test_weekly_digest_sends_once_to_active_opted_in_people(admin, pool, monkeypatch):  # noqa: F811
    tenant, (alice, bob, carol, dave), devices = await _world(admin)
    choke = MockChoke()
    choke.templates["team_device_totals"] = [
        {
            "device_id": devices[alice],
            "sessions": 2,
            "tasks_verified": 1,
            "tokens": 100,
            "tokens_saved": 7,
        },
        {
            "device_id": devices[bob],
            "sessions": 1,
            "tasks_verified": 0,
            "tokens": 40,
            "tokens_saved": 0,
        },
        {
            "device_id": devices[carol],
            "sessions": 5,
            "tasks_verified": 5,
            "tokens": 900,
            "tokens_saved": 9,
        },
        {
            "device_id": str(uuid4()),
            "sessions": 9,
            "tasks_verified": 9,
            "tokens": 9,
            "tokens_saved": 9,
        },
    ]
    ctx = SimpleNamespace(
        pool=pool,
        tenant_id=tenant,
        window_start=datetime(2026, 9, 14, tzinfo=UTC),
        settings=SimpleNamespace(querychoke_base_url="http://choke", http_timeout_s=5),
    )
    monkeypatch.setenv("INTEL_QUERYCHOKE_TOKEN", "svc")
    monkeypatch.delenv("EMAIL_POSTAL_ADDRESS", raising=False)
    monkeypatch.setenv("CUSTOMERIO_APP_API_KEY", "k")
    outbox: list = []
    failing = {bob}

    async def send(_http, m):
        if any(m.to.startswith(s.split(":")[1]) for s in failing):
            raise RuntimeError("customer.io: 503")
        outbox.append(m)
        return f"d-{len(outbox)}"

    # no postal address: refuse, counting the two who would be mailed (carol left, dave was idle)
    async with choke.client() as http:
        with pytest.raises(
            RuntimeError, match=r"EMAIL_POSTAL_ADDRESS unset: 2 weekly digest\(s\) not sent"
        ):
            await digest.weekly(ctx, http=http, send=send)
    assert outbox == [] and await _ledger(pool, tenant) == {}
    template, params, _ = choke.requests[-1]
    assert template == "team_device_totals" and params == {"from": "2026-09-14", "to": "2026-09-20"}

    # bob's send fails: alice is sent and ledgered, bob is failed, the run fails so a re-run happens
    monkeypatch.setenv("EMAIL_POSTAL_ADDRESS", "Omium, 1 Test St")
    async with choke.client() as http:
        with pytest.raises(RuntimeError, match="1 weekly digest"):
            await digest.weekly(ctx, http=http, send=send)
    assert [m.to for m in outbox] == [alice.split(":")[1] + "@it.example"]
    assert "Omium, 1 Test St" in outbox[0].text and outbox[0].headers["List-Unsubscribe-Post"]
    assert await _ledger(pool, tenant) == {alice: ("sent", "d-1"), bob: ("failed", None)}

    # the re-run retries only bob; a third run mails nobody (idle dave is never a recipient)
    failing.clear()
    async with choke.client() as http:
        assert await digest.weekly(ctx, http=http, send=send) is None
    assert [m.to.split("@")[0] for m in outbox] == [alice.split(":")[1], bob.split(":")[1]]
    assert await _ledger(pool, tenant) == {alice: ("sent", "d-1"), bob: ("sent", "d-2")}
    async with choke.client() as http:
        assert await digest.weekly(ctx, http=http, send=send) is None
    assert len(outbox) == 2

    # the unsubscribe link is the person's own token
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        token = await conn.fetchval(
            "SELECT unsub_token FROM m1_notification_prefs WHERE tenant_id = $1 AND subject = $2",
            UUID(tenant),
            bob,
        )
    assert f"/api/v1/unsubscribe/{token}>" in outbox[1].headers["List-Unsubscribe"]


async def test_weekly_digest_is_quiet_for_a_tenant_nobody_opted_into(admin, pool, monkeypatch):  # noqa: F811
    tenant, _, _ = await _world(admin)
    async with admin.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        await conn.execute(
            "UPDATE m1_notification_prefs SET weekly_digest = false WHERE tenant_id = $1",
            UUID(tenant),
        )
    choke = MockChoke()
    monkeypatch.delenv("EMAIL_POSTAL_ADDRESS", raising=False)
    ctx = SimpleNamespace(
        pool=pool,
        tenant_id=tenant,
        window_start=datetime(2026, 9, 14, tzinfo=UTC),
        settings=SimpleNamespace(querychoke_base_url="http://choke", http_timeout_s=5),
    )
    async with choke.client() as http:
        assert await digest.weekly(ctx, http=http) is None
    assert choke.requests == []


async def test_weekly_digest_restates_last_week_when_a_late_verdict_moved_it(
    admin,
    pool,  # noqa: F811
    monkeypatch,
):
    """ADR-0013: the ledger keeps the figure each email carried; the next week's run recomputes
    last week through today and says so on its own line when a late verdict moved it — and only
    then, only once (the ledger still refuses a second send)."""
    tenant, (alice, bob, _carol, _dave), devices = await _world(admin)
    late = {"alice": 7}

    def rows(params):
        first = params["from"]
        saved = {"2026-09-14": (late["alice"], 0), "2026-09-21": (3, 1)}[first]
        return [
            {
                "device_id": devices[alice],
                "sessions": 1,
                "tasks_verified": 1,
                "tokens": 50,
                "tokens_saved": saved[0],
            },
            {
                "device_id": devices[bob],
                "sessions": 1,
                "tasks_verified": 0,
                "tokens": 20,
                "tokens_saved": saved[1],
            },
        ]

    choke = MockChoke()
    choke.templates["team_device_totals"] = rows
    monkeypatch.setenv("INTEL_QUERYCHOKE_TOKEN", "svc")
    monkeypatch.setenv("EMAIL_POSTAL_ADDRESS", "Omium, 1 Test St")
    monkeypatch.setenv("CUSTOMERIO_APP_API_KEY", "k")
    outbox: list = []

    async def send(_http, m):
        outbox.append(m)
        return f"d-{len(outbox)}"

    def ctx(week):
        return SimpleNamespace(
            pool=pool,
            tenant_id=tenant,
            window_start=datetime(week.year, week.month, week.day, tzinfo=UTC),
            settings=SimpleNamespace(querychoke_base_url="http://choke", http_timeout_s=5),
        )

    async with choke.client() as http:
        assert await digest.weekly(ctx(WEEK), http=http, send=send) is None
    assert all("restated" not in m.text for m in outbox) and len(outbox) == 2
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        stored = {
            r["subject"]: r["tokens_saved"]
            for r in await conn.fetch(
                "SELECT subject, tokens_saved FROM m1_notification_sends "
                "WHERE tenant_id = $1 AND period_start = $2",
                UUID(tenant),
                WEEK,
            )
        }
    assert stored == {alice: 7, bob: 0}

    # A verdict dated after that email resolved alice's Sunday block: week one now reads 57.
    late["alice"] = 57
    next_week = date(2026, 9, 21)
    async with choke.client() as http:
        assert await digest.weekly(ctx(next_week), http=http, send=send) is None
    second = {m.to.split("@")[0]: m for m in outbox[2:]}
    assert len(second) == 2
    assert "Last week's tokens saved, restated: 57 (was 7)" in second[alice.split(":")[1]].text
    assert "restated" not in second[bob.split(":")[1]].text
    asked = [p for t, p, _ in choke.requests if t == "team_device_totals"]
    assert {"from": "2026-09-14", "to": "2026-09-20"} in asked[-2:]
    assert {"from": "2026-09-21", "to": "2026-09-27"} in asked[-2:]
    async with choke.client() as http:
        assert await digest.weekly(ctx(next_week), http=http, send=send) is None
    assert len(outbox) == 4
