"""The memory write surface against real Postgres (m1_040 + m1_081): retire receipted through
controld's append route then flipped in one transaction, pin/share flags under RLS (a foreign id
reads as 404, never 403), the pinned guard on ADMIT-LCB's retire branch, and GET outcomes."""

import os
from decimal import Decimal
from uuid import UUID, uuid4

import httpx
import pytest
from app.db import set_local_tenant
from app.memory import admit, retrieve
from app.memory.routes import get_append, get_pool, router
from app.tvo.reader import QuerychokeReader
from choke_mock import MockChoke
from fastapi import FastAPI
from mark1_receipts import ReceiptAppendError
from test_memory_pg import (
    BEARER,
    DAY,
    _artifact_row,
    _mk_artifact,
    _mk_cert,
    _mk_device,
    _mk_tenant,
    _outcomes,
    fake_append,
)
from tests.roles import service_pool

DSN = os.environ.get("M1_TEST_PG_DSN", "")
REQUIRE_STORES = os.environ.get("M1_REQUIRE_STORES", "0") == "1"
SVC = "controld-service-token"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not DSN and not REQUIRE_STORES, reason="M1_TEST_PG_DSN not set"),
]


@pytest.fixture(autouse=True)
def _service_token(monkeypatch):
    monkeypatch.setenv("INTEL_QUERYCHOKE_TOKEN", SVC)


@pytest.fixture
async def pool():
    if not DSN:
        pytest.fail("M1_TEST_PG_DSN is unset and M1_REQUIRE_STORES=1", pytrace=False)
    try:
        p = await service_pool(min_size=1, max_size=3)
    except Exception as exc:
        if REQUIRE_STORES:
            pytest.fail(f"M1_REQUIRE_STORES=1 and {DSN!r} is unreachable: {exc!r}", pytrace=False)
        pytest.skip(f"Postgres unreachable: {exc!r}")
    try:
        yield p
    finally:
        await p.close()


@pytest.fixture
async def conn(pool):
    async with pool.acquire() as c:
        yield c


def client(pool, choke: MockChoke, bearer: str = SVC) -> httpx.AsyncClient:
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_pool] = lambda: pool
    app.dependency_overrides[get_append] = lambda: fake_append(choke)
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://intel",
        headers={"Authorization": f"Bearer {bearer}"},
    )


async def _admit(conn, choke, tenant, a, cert):
    return await admit.admit_artifact(
        conn,
        fake_append(choke),
        tenant_id=tenant,
        artifact_id=a.id,
        kind=a.kind,
        lcb=Decimal("0.25"),
        n_obs=10,
        cert_id=cert,
        idempotency_key=f"t:{a.id}",
    )


async def _flags(conn, tenant, artifact_id):
    async with conn.transaction():
        await set_local_tenant(conn, tenant)
        return await conn.fetchrow(
            "SELECT state::text AS state, pinned, scope, receipt_id FROM memory_artifacts "
            "WHERE id = $1",
            artifact_id,
        )


async def test_retire_is_receipted_then_flipped_and_idempotent(admin_conn, pool, conn):
    tenant = await _mk_tenant(admin_conn)
    cert, device = await _mk_cert(admin_conn, tenant), await _mk_device(admin_conn, tenant)
    a = await _mk_artifact(conn, tenant, cert, device)
    choke = MockChoke()
    await _admit(conn, choke, tenant, a, cert)
    async with client(pool, choke) as c:
        resp = await c.post(
            f"/v1/memory/artifacts/{a.id}/retire",
            json={"tenant_id": tenant, "reason": "stale advice", "by": "usr_1"},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        row = await _flags(conn, tenant, a.id)
        assert (body["state"], row["state"], UUID(body["receipt_id"])) == (
            "retired",
            "retired",
            row["receipt_id"],
        )
        assert choke.appended[-1]["record_type"] == "memory_admission"
        assert choke.appended[-1]["idempotency_key"] == f"memory.retire:{a.id}"
        assert choke.appended[-1]["payload"] == {
            "act": "retire",
            "reason": "stale advice",
            "by": "usr_1",
            "from_state": "admitted",
        }
        assert UUID(choke.appended[-1]["subject_id"]) == a.id
        n = len(choke.appended)
        again = await c.post(
            f"/v1/memory/artifacts/{a.id}/retire", json={"tenant_id": tenant, "reason": "twice"}
        )
        assert again.status_code == 200 and again.json() == body
        assert len(choke.appended) == n
        # The retired row leaves the served set (retrieve.admitted is the edge's sync source).
        assert await retrieve.admitted(conn, tenant) == []


async def test_unreceipted_retire_never_flips(admin_conn, conn):
    tenant = await _mk_tenant(admin_conn)
    cert, device = await _mk_cert(admin_conn, tenant), await _mk_device(admin_conn, tenant)
    a = await _mk_artifact(conn, tenant, cert, device)
    choke = MockChoke()
    choke.append_fail_with = (500, "M1E-9500", "chain append failed")
    with pytest.raises(ReceiptAppendError):
        await admit.retire_artifact(
            conn, fake_append(choke), tenant_id=tenant, artifact_id=a.id, reason="r", by="u"
        )
    row = await _flags(conn, tenant, a.id)
    assert (row["state"], row["receipt_id"]) == ("extracted", None)


async def test_cross_tenant_ids_read_as_404_and_bad_input_as_400(admin_conn, pool, conn):
    tenant, other = await _mk_tenant(admin_conn), await _mk_tenant(admin_conn)
    cert, device = await _mk_cert(admin_conn, tenant), await _mk_device(admin_conn, tenant)
    a = await _mk_artifact(conn, tenant, cert, device)
    choke = MockChoke()
    async with client(pool, choke) as c:
        for action, body in (
            ("retire", {"tenant_id": other, "reason": "not mine"}),
            ("pin", {"tenant_id": other}),
            ("share", {"tenant_id": other}),
        ):
            resp = await c.post(f"/v1/memory/artifacts/{a.id}/{action}", json=body)
            assert resp.status_code == 404, (action, resp.text)
            assert resp.json()["error"]["code"] == "M1E-2009"
        assert choke.appended == []
        row = await _flags(conn, tenant, a.id)
        assert (row["state"], row["pinned"], row["scope"]) == ("extracted", False, "mine")
        resp = await c.post(f"/v1/memory/artifacts/{uuid4()}/pin", json={"tenant_id": tenant})
        assert resp.status_code == 404
        resp = await c.post(f"/v1/memory/artifacts/{a.id}/bless", json={"tenant_id": tenant})
        assert resp.status_code == 404
        for path, body in (
            ("/v1/memory/artifacts/not-a-uuid/pin", {"tenant_id": tenant}),
            (f"/v1/memory/artifacts/{a.id}/pin", {"tenant_id": "nope"}),
            (f"/v1/memory/artifacts/{a.id}/retire", {"tenant_id": tenant, "reason": ""}),
            (f"/v1/memory/artifacts/{a.id}/retire", {"tenant_id": tenant}),
        ):
            resp = await c.post(path, json=body)
            assert resp.status_code in (400, 422), (path, resp.text)
    async with client(pool, choke, bearer="wrong") as c:
        resp = await c.post(f"/v1/memory/artifacts/{a.id}/pin", json={"tenant_id": tenant})
        assert resp.status_code == 403 and resp.json()["error"]["code"] == "M1E-1001"
        resp = await c.get("/v1/memory/outcomes", params={"tenant_id": tenant})
        assert resp.status_code == 403


async def test_pin_share_flip_and_are_served_to_the_app(admin_conn, pool, conn):
    tenant = await _mk_tenant(admin_conn)
    cert, device = await _mk_cert(admin_conn, tenant), await _mk_device(admin_conn, tenant)
    a = await _mk_artifact(conn, tenant, cert, device)
    choke = MockChoke()
    await _admit(conn, choke, tenant, a, cert)
    async with client(pool, choke) as c:
        for action, key, value in (
            ("pin", "pinned", True),
            ("share", "scope", "team"),
            ("unshare", "scope", "mine"),
            ("unpin", "pinned", False),
        ):
            resp = await c.post(f"/v1/memory/artifacts/{a.id}/{action}", json={"tenant_id": tenant})
            assert resp.status_code == 200 and resp.json() == {"artifact_id": str(a.id), key: value}
            row = await _flags(conn, tenant, a.id)
            assert row[key] == value, action
            served = (await c.get("/v1/memory/artifacts", params={"tenant_id": tenant})).json()
            (art,) = served["artifacts"]
            assert (art["state"], art[key], art["n"]) == ("admitted", value, 10)
    assert choke.appended[1:] == []


async def test_pinned_artifact_survives_the_lcb_retire_branch(admin_conn, conn):
    tenant = await _mk_tenant(admin_conn)
    cert, device = await _mk_cert(admin_conn, tenant), await _mk_device(admin_conn, tenant)
    pinned, loose = (
        await _mk_artifact(conn, tenant, cert, device),
        await _mk_artifact(conn, tenant, cert, device),
    )
    assert await admit.set_flag(
        conn, tenant_id=tenant, artifact_id=pinned.id, column="pinned", value=True
    )
    choke = MockChoke()
    choke.templates[admit.OUTCOME_TEMPLATE] = lambda params: _outcomes(
        device, cert, utility=-5000.0
    )
    async with choke.client() as http:
        report = await admit.run_admit(
            QuerychokeReader(http, "http://choke"),
            conn,
            fake_append(choke),
            tenant_id=tenant,
            day=DAY,
            bearer=BEARER,
        )
    assert (report.retired, report.held) == (1, 1)
    assert (await _artifact_row(conn, tenant, pinned.id))["state"] == "shadow"
    assert (await _artifact_row(conn, tenant, loose.id))["state"] == "retired"


async def test_outcomes_are_per_artifact_lcb_evidence_in_tenant(admin_conn, pool, conn):
    tenant, other = await _mk_tenant(admin_conn), await _mk_tenant(admin_conn)
    cert, device = await _mk_cert(admin_conn, tenant), await _mk_device(admin_conn, tenant)
    o_cert, o_device = await _mk_cert(admin_conn, other), await _mk_device(admin_conn, other)
    a = await _mk_artifact(conn, tenant, cert, device)
    await _mk_artifact(conn, tenant, cert, device)
    o = await _mk_artifact(conn, other, o_cert, o_device)
    choke = MockChoke()
    await _admit(conn, choke, tenant, a, cert)
    await _admit(conn, choke, other, o, o_cert)
    async with client(pool, choke) as c:
        resp = await c.get("/v1/memory/outcomes", params={"tenant_id": tenant})
        assert resp.status_code == 200
        assert resp.json() == {
            "outcomes": [
                {"artifact_id": str(a.id), "verified_outcomes": 10, "uplift_lcb": 0.25, "n": 10}
            ]
        }
        resp = await c.get("/v1/memory/outcomes", params={"tenant_id": "nope"})
        assert resp.status_code == 400
