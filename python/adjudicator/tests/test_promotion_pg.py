"""06 §12.4 state machine against real Postgres (m1_069): every legal edge receipted through
controld (the FakeControld append wire), every illegal edge refused by the trigger with its
SQLSTATE, promotion refused without a live certified cert (C5), demotion on regression, D39
retirement through the nightly wrapper, and a controld 500 landing no transition at all."""

import json
import os
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import UUID, uuid4

import asyncpg
import httpx
import pytest
from app.db import _tenant_guc_reset, set_local_tenant
from app.jobs.nightly import promotion_step
from app.registry import promotion
from app.registry.promotion import RECEIPT_TYPE, Measurement, register, run_promotion, transition
from mark1_receipts import ReceiptAppendError
from pydantic import SecretStr
from tests.test_pg_stores import FakeControld, _mk_judge_verifier, _mk_tenant
from tests.test_promotion import pairs

DSN = os.environ.get("M1_TEST_PG_DSN", "")
REQUIRE_STORES = os.environ.get("M1_REQUIRE_STORES", "0") == "1"
CHECK_VIOLATION = "23514"
INSUFFICIENT_PRIVILEGE = "42501"

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


@pytest.fixture
async def conn(pool):
    async with pool.acquire() as c:
        yield c


@pytest.fixture
def controld() -> FakeControld:
    return FakeControld(RECEIPT_TYPE)


@pytest.fixture
def append(controld):
    return controld.append()


async def _mk_cert(conn, tenant: str, verifier: UUID, *, status="certified", expired=False) -> str:
    async with conn.transaction():
        await set_local_tenant(conn, tenant)
        gold = await conn.fetchval(
            "INSERT INTO gold_sets (tenant_id, agent, frozen_at) VALUES ($1, 'claudecode', now()) "
            "RETURNING id",
            UUID(tenant),
        )
        shift = "- interval '2 days'" if expired else ""
        return str(
            await conn.fetchval(
                "INSERT INTO noise_certificates (tenant_id, verifier_id, gold_set_id, status, "
                "rho_plus, rho_minus, natarajan_lcb, gold_n, identifiable, issued_at, expires_at) "
                f"VALUES ($1, $2, $3, $4::cert_status, 0.05, 0.05, 0.8, 200, true, "
                f"now() {shift}, now() + interval '1 day' {shift}) RETURNING id",
                UUID(tenant),
                verifier,
                gold,
                status,
            )
        )


async def _head(conn, tenant: str, pid: UUID):
    async with conn.transaction():
        await set_local_tenant(conn, tenant)
        return await conn.fetchrow("SELECT * FROM m1_verifier_promotions WHERE id = $1", pid)


async def _ledger(conn, tenant: str, pid: UUID) -> list[tuple[str, str, str]]:
    async with conn.transaction():
        await set_local_tenant(conn, tenant)
        rows = await conn.fetch(
            "SELECT from_state, to_state, reason FROM m1_verifier_promotion_transitions "
            "WHERE promotion_id = $1 ORDER BY at, from_state",
            pid,
        )
    return [(r["from_state"], r["to_state"], r["reason"]) for r in rows]


async def _receipt_ids(conn, tenant: str, pid: UUID) -> list[UUID]:
    async with conn.transaction():
        await set_local_tenant(conn, tenant)
        rows = await conn.fetch(
            "SELECT receipt_id FROM m1_verifier_promotion_transitions "
            "WHERE promotion_id = $1 ORDER BY at",
            pid,
        )
    return [r["receipt_id"] for r in rows]


async def _cited(controld: FakeControld, conn, tenant: str, pid: UUID) -> list[dict]:
    """The acked receipts the ledger rows cite, in ledger order; a refused edge's receipt is an
    orphan at controld that no row names (the insert_cert posture) and is not in this list."""
    by_id = {r["receipt_id"]: r for r in _acked(controld, tenant)}
    return [by_id[rid] for rid in await _receipt_ids(conn, tenant, pid)]


def _acked(controld: FakeControld, tenant: str) -> list[dict]:
    """controld's receipts for this tenant, in append order, with the ack's receipt id."""
    return [
        {
            **b,
            "receipt_id": UUID(
                controld.acks[(tenant, RECEIPT_TYPE, b["idempotency_key"])]["receipt_id"]
            ),
        }
        for b in controld.appended
        if b["tenant_id"] == tenant
    ]


async def _candidate(conn, pool, append, *, to_shadow=True) -> tuple[str, UUID, UUID]:
    tenant = await _mk_tenant(pool)
    verifier = await _mk_judge_verifier(pool)
    pid = await register(conn, tenant_id=tenant, verifier_id=verifier)
    if to_shadow:
        await transition(
            conn,
            append,
            tenant_id=tenant,
            promotion_id=pid,
            from_state="probation",
            to_state="shadow",
            reason="eval_card_complete",
        )
    return tenant, verifier, pid


async def _step(conn, append, tenant, pid, frm, to, reason="test"):
    return await transition(
        conn, append, tenant_id=tenant, promotion_id=pid, from_state=frm, to_state=to, reason=reason
    )


def _sqlstate(excinfo) -> str:
    return excinfo.value.sqlstate


async def test_promotion_pipeline_state_machine(conn, pool, controld, append):
    """No path to active without shadow votes, an LCB pass over the bar under a live cert,
    and a canary row; every edge lands one ledger row and one chained receipt."""
    tenant, verifier, pid = await _candidate(conn, pool, append)
    cert = await _mk_cert(conn, tenant, verifier)

    for frm, to in (("probation", "lcb_promoted"), ("shadow", "active"), ("shadow", "canary")):
        with pytest.raises(asyncpg.CheckViolationError) as e:
            await _step(conn, append, tenant, pid, frm, to)
        assert _sqlstate(e) == CHECK_VIOLATION
    with pytest.raises(asyncpg.CheckViolationError, match="stale transition"):
        await _step(conn, append, tenant, pid, "probation", "shadow")
    with pytest.raises(asyncpg.CheckViolationError, match="insufficient_evidence"):
        await _step(conn, append, tenant, pid, "shadow", "lcb_promoted")

    short = Measurement(pairs(promotion.SHADOW_MIN - 1, 0.9, 0.0, cert=cert))
    rep = await run_promotion(conn, append, tenant_id=tenant, measured={pid: short})
    assert (rep.promoted, (await _head(conn, tenant, pid))["state"]) == (0, "shadow")
    with pytest.raises(asyncpg.CheckViolationError, match="shadow_n=499"):
        await _step(conn, append, tenant, pid, "shadow", "lcb_promoted")

    good = Measurement(pairs(600, 0.8, 0.1, cert=cert), bar=0.0)
    rep = await run_promotion(conn, append, tenant_id=tenant, measured={pid: good})
    head = await _head(conn, tenant, pid)
    assert rep.promoted == 1 and head["state"] == "lcb_promoted"
    assert head["shadow_n"] == 600 and head["lcb"] > head["bar"] == 0
    assert str(head["cert_id"]) == cert

    with pytest.raises(asyncpg.CheckViolationError) as e:
        await _step(conn, append, tenant, pid, "lcb_promoted", "active")
    assert _sqlstate(e) == CHECK_VIOLATION
    await _step(conn, append, tenant, pid, "lcb_promoted", "canary", "canary_plan_attached")
    await _step(conn, append, tenant, pid, "canary", "active", "widen_criteria_met")
    assert (await _head(conn, tenant, pid))["state"] == "active"

    assert await _ledger(conn, tenant, pid) == [
        ("probation", "shadow", "eval_card_complete"),
        ("shadow", "lcb_promoted", "lcb_promotion"),
        ("lcb_promoted", "canary", "canary_plan_attached"),
        ("canary", "active", "widen_criteria_met"),
    ]
    async with conn.transaction():
        await set_local_tenant(conn, tenant)
        evidence = await conn.fetchval(
            "SELECT evidence FROM m1_verifier_promotion_transitions "
            "WHERE promotion_id = $1 AND to_state = 'lcb_promoted'",
            pid,
        )
    assert json.loads(evidence)["shadow_n"] == 600 and json.loads(evidence)["cert_id"] == cert
    cited = await _cited(controld, conn, tenant, pid)
    assert [r["record_type"] for r in cited] == ["verifier_promotion"] * 4
    assert [r["payload"]["to_state"] for r in cited] == [
        "shadow",
        "lcb_promoted",
        "canary",
        "active",
    ]
    assert all(r["idempotency_key"] == f"promotion.step:{r['subject_id']}" for r in cited)


async def test_registration_and_direct_state_writes_refused_by_the_db(conn, pool, append):
    tenant, verifier, pid = await _candidate(conn, pool, append)
    other = await _mk_judge_verifier(pool)
    async with conn.transaction():
        await set_local_tenant(conn, tenant)
        with pytest.raises(asyncpg.CheckViolationError, match="registers in probation"):
            await conn.execute(
                "INSERT INTO m1_verifier_promotions (tenant_id, verifier_id, state) "
                "VALUES ($1, $2, 'active')",
                UUID(tenant),
                other,
            )
    async with conn.transaction():
        await set_local_tenant(conn, tenant)
        with pytest.raises(asyncpg.InsufficientPrivilegeError) as e:
            await conn.execute(
                "UPDATE m1_verifier_promotions SET state = 'active' WHERE id = $1", pid
            )
        assert _sqlstate(e) == INSUFFICIENT_PRIVILEGE
    for stmt in (
        "UPDATE m1_verifier_promotion_transitions SET reason = 'x' WHERE promotion_id = $1",
        "DELETE FROM m1_verifier_promotion_transitions WHERE promotion_id = $1",
    ):
        async with conn.transaction():
            await set_local_tenant(conn, tenant)
            with pytest.raises(asyncpg.InsufficientPrivilegeError, match="append-only"):
                await conn.execute(stmt, pid)
    assert (await _head(conn, tenant, pid))["state"] == "shadow"
    assert len(await _ledger(conn, tenant, pid)) == 1


@pytest.mark.parametrize("status,expired", [("bootstrapping", False), ("certified", True)])
async def test_promotion_refused_without_live_certified_cert(conn, pool, append, status, expired):
    """C5 twice: uncertified pairs are not evidence (n stays 0), and a head whose cert_id is
    not currently certified cannot cross into lcb_promoted even with the numbers in place."""
    tenant, verifier, pid = await _candidate(conn, pool, append)
    dead = await _mk_cert(conn, tenant, verifier, status=status, expired=expired)
    rep = await run_promotion(
        conn, append, tenant_id=tenant, measured={pid: Measurement(pairs(600, 0.9, 0.0, cert=dead))}
    )
    head = await _head(conn, tenant, pid)
    assert (rep.promoted, head["state"], head["shadow_n"], head["cert_id"]) == (
        0,
        "shadow",
        0,
        None,
    )

    async with conn.transaction():
        await set_local_tenant(conn, tenant)
        await conn.execute(
            "UPDATE m1_verifier_promotions SET shadow_n = 600, lcb = 0.5, bar = 0, cert_id = $2, "
            "measured_at = now() WHERE id = $1",
            pid,
            UUID(dead),
        )
    with pytest.raises(asyncpg.CheckViolationError, match="not currently certified") as e:
        await _step(conn, append, tenant, pid, "shadow", "lcb_promoted")
    assert _sqlstate(e) == CHECK_VIOLATION
    async with conn.transaction():
        await set_local_tenant(conn, tenant)
        await conn.execute(
            "UPDATE m1_verifier_promotions SET shadow_n = 499, cert_id = $2 WHERE id = $1",
            pid,
            UUID(await _mk_cert(conn, tenant, await _mk_judge_verifier(pool))),
        )
    with pytest.raises(asyncpg.CheckViolationError, match="insufficient_evidence.*shadow_n=499"):
        await _step(conn, append, tenant, pid, "shadow", "lcb_promoted")
    assert (await _head(conn, tenant, pid))["state"] == "shadow"


async def test_demotion_on_regression_and_stale_evidence_refused(conn, pool, controld, append):
    tenant, verifier, pid = await _candidate(conn, pool, append)
    cert = await _mk_cert(conn, tenant, verifier)
    await run_promotion(
        conn, append, tenant_id=tenant, measured={pid: Measurement(pairs(600, 0.8, 0.1, cert=cert))}
    )
    await _step(conn, append, tenant, pid, "lcb_promoted", "canary")
    await _step(conn, append, tenant, pid, "canary", "active")

    steady = Measurement(pairs(600, 0.8, 0.1, seed=7, cert=cert), bar=0.5)
    rep = await run_promotion(conn, append, tenant_id=tenant, measured={pid: steady})
    assert (rep.regressed, (await _head(conn, tenant, pid))["state"]) == (0, "active")

    worse = Measurement(pairs(600, 0.3, 0.3, cert=cert), bar=0.5)
    rep = await run_promotion(conn, append, tenant_id=tenant, measured={pid: worse})
    head = await _head(conn, tenant, pid)
    assert (rep.regressed, head["state"]) == (1, "shadow")
    assert head["shadow_n"] == 600 and head["lcb"] > 0, "old promotion numbers survive the demotion"
    with pytest.raises(asyncpg.CheckViolationError, match="insufficient_evidence"):
        await _step(conn, append, tenant, pid, "shadow", "lcb_promoted")
    with pytest.raises(asyncpg.CheckViolationError, match="illegal promotion transition"):
        await _step(conn, append, tenant, pid, "shadow", "active")

    rep = await run_promotion(
        conn,
        append,
        tenant_id=tenant,
        measured={pid: Measurement(pairs(600, 0.8, 0.1, seed=3, cert=cert))},
    )
    assert (rep.promoted, (await _head(conn, tenant, pid))["state"]) == (1, "lcb_promoted")
    assert [t[1] for t in await _ledger(conn, tenant, pid)] == [
        "shadow",
        "lcb_promoted",
        "canary",
        "active",
        "shadow",
        "lcb_promoted",
    ]
    async with conn.transaction():
        await set_local_tenant(conn, tenant)
        ev = json.loads(
            await conn.fetchval(
                "SELECT evidence FROM m1_verifier_promotion_transitions "
                "WHERE promotion_id = $1 AND reason = 'regression'",
                pid,
            )
        )
    assert ev["n"] == 600 and ev["ucb"] < ev["bar"] == 0.5
    cited = await _cited(controld, conn, tenant, pid)
    assert [r["payload"]["reason"] for r in cited][-2:] == ["regression", "lcb_promotion"]


async def test_receipt_and_ledger_row_share_one_transaction(conn, pool, controld, append):
    """The receipt comes first and the row commits carrying its id: a controld 500 lands no
    transition (the negative), a DB-refused edge leaves controld's receipt an orphan that no
    ledger row cites (the insert_cert posture), and a legal edge's row names its receipt."""
    tenant, verifier, pid = await _candidate(conn, pool, append)
    controld.fail_with = (500, "M1E-9500", "chain head locked")
    with pytest.raises(ReceiptAppendError, match="M1E-9500"):
        await _step(conn, append, tenant, pid, "shadow", "retired", "withdrawn")
    controld.fail_with = None
    assert await _ledger(conn, tenant, pid) == [("probation", "shadow", "eval_card_complete")]
    assert (await _head(conn, tenant, pid))["state"] == "shadow"
    assert len(_acked(controld, tenant)) == 1

    with pytest.raises(asyncpg.CheckViolationError):
        await _step(conn, append, tenant, pid, "shadow", "active")
    orphan = _acked(controld, tenant)[-1]
    assert orphan["payload"]["to_state"] == "active"
    assert orphan["receipt_id"] not in await _receipt_ids(conn, tenant, pid)

    receipt_id = await _step(conn, append, tenant, pid, "shadow", "retired", "withdrawn")
    async with conn.transaction():
        await set_local_tenant(conn, tenant)
        row = await conn.fetchrow(
            "SELECT id, receipt_id FROM m1_verifier_promotion_transitions "
            "WHERE promotion_id = $1 AND to_state = 'retired'",
            pid,
        )
    last = _acked(controld, tenant)[-1]
    assert row["receipt_id"] == receipt_id == last["receipt_id"]
    assert last["subject_id"] == str(row["id"])
    with pytest.raises(asyncpg.CheckViolationError, match="illegal promotion transition"):
        await _step(conn, append, tenant, pid, "retired", "shadow")


async def test_nightly_step_retires_after_shadow_ttl(conn, pool, controld, append):
    tenant, _verifier, pid = await _candidate(conn, pool, append)
    fresh_tenant, _v2, fresh = await _candidate(conn, pool, append)
    async with conn.transaction():
        await set_local_tenant(conn, tenant)
        await conn.execute(
            "UPDATE m1_verifier_promotions SET state_since = $2 WHERE id = $1",
            pid,
            datetime.now(UTC) - promotion.SHADOW_TTL - timedelta(days=1),
        )
    http = httpx.AsyncClient(transport=httpx.MockTransport(controld.handler), base_url="http://c")
    settings = SimpleNamespace(
        querychoke_base_url="http://controld", querychoke_token=SecretStr("svc"), http_timeout_s=5.0
    )
    ctx = SimpleNamespace(pool=pool, tenant_id=tenant, settings=settings)
    assert await promotion_step(ctx, http=http) is not None
    assert (await _head(conn, tenant, pid))["state"] == "retired"
    assert await _ledger(conn, tenant, pid) == [
        ("probation", "shadow", "eval_card_complete"),
        ("shadow", "retired", "shadow_ttl"),
    ]
    assert _acked(controld, tenant)[-1]["payload"]["reason"] == "shadow_ttl"
    fresh_ctx = SimpleNamespace(pool=pool, tenant_id=fresh_tenant, settings=settings)
    assert await promotion_step(fresh_ctx, http=http) is None
    assert (await _head(conn, fresh_tenant, fresh))["state"] == "shadow"
    stale_tenant, v3, stale = await _candidate(conn, pool, append)
    cert = await _mk_cert(conn, stale_tenant, v3)
    async with conn.transaction():
        await set_local_tenant(conn, stale_tenant)
        await conn.execute(
            "UPDATE m1_verifier_promotions SET state_since = $2 WHERE id = $1",
            stale,
            datetime.now(UTC) - promotion.SHADOW_TTL - timedelta(days=1),
        )
    short = Measurement(pairs(promotion.SHADOW_MIN - 1, 0.9, 0.0, cert=cert))
    rep = await run_promotion(conn, append, tenant_id=stale_tenant, measured={stale: short})
    assert rep.retired == 1 and (await _head(conn, stale_tenant, stale))["state"] == "retired"


async def test_shadow_ids_and_rls(conn, pool, append):
    tenant, verifier, pid = await _candidate(conn, pool, append)
    other = await _mk_tenant(pool)
    async with conn.transaction():
        await set_local_tenant(conn, tenant)
        key = await conn.fetchrow(
            "SELECT verifier_key, version FROM m1_verifiers WHERE id = $1", verifier
        )
    vid = f"{key['verifier_key']}@{key['version']}"
    assert vid in await promotion.shadow_ids(conn, tenant)
    assert await promotion.shadow_ids(conn, other) == set()
    cert = await _mk_cert(conn, tenant, verifier)
    await run_promotion(
        conn, append, tenant_id=tenant, measured={pid: Measurement(pairs(600, 0.8, 0.1, cert=cert))}
    )
    assert (await _head(conn, tenant, pid))["state"] == "lcb_promoted"
    assert vid in await promotion.shadow_ids(conn, tenant), "lcb_promoted still serves nothing"
    await _step(conn, append, tenant, pid, "lcb_promoted", "canary")
    assert vid not in await promotion.shadow_ids(conn, tenant)
    async with conn.transaction():
        await set_local_tenant(conn, other)
        assert (
            await conn.fetchrow("SELECT 1 FROM m1_verifier_promotions WHERE id = $1", pid) is None
        )
        with pytest.raises(asyncpg.ForeignKeyViolationError, match="not in tenant"):
            await conn.execute(
                "INSERT INTO m1_verifier_promotion_transitions (tenant_id, promotion_id, "
                "from_state, to_state, reason, receipt_id) "
                "VALUES ($1, $2, 'shadow', 'active', 'x', $3)",
                UUID(tenant),
                pid,
                uuid4(),
            )


async def test_canary_regression_returns_to_shadow(conn, pool, append):
    tenant, verifier, pid = await _candidate(conn, pool, append)
    cert = await _mk_cert(conn, tenant, verifier)
    await run_promotion(
        conn, append, tenant_id=tenant, measured={pid: Measurement(pairs(600, 0.8, 0.1, cert=cert))}
    )
    await _step(conn, append, tenant, pid, "lcb_promoted", "canary")
    worse = Measurement(pairs(600, 0.3, 0.3, cert=cert), bar=0.5)
    rep = await run_promotion(conn, append, tenant_id=tenant, measured={pid: worse})
    assert (rep.regressed, (await _head(conn, tenant, pid))["state"]) == (1, "shadow")
    assert [t[1] for t in await _ledger(conn, tenant, pid)] == [
        "shadow",
        "lcb_promoted",
        "canary",
        "shadow",
    ]
