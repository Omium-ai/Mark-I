"""Doc 15 memory ownership against real Postgres (m1_090): owner stamping and the owner-keyed
merge, the serving predicate on artifacts/match/outcomes, owner-only actions with the share
consent gate, the team-scoped LCB evidence, and non-team tenants left exactly as they were."""

import json
import random
import sys
from datetime import timedelta
from decimal import Decimal
from uuid import UUID, uuid4

import pytest
import test_memory_actions_pg as actions
from app.db import set_local_tenant
from app.memory import admit, extract, retrieve
from app.tvo.reader import QuerychokeReader
from choke_mock import MockChoke
from test_memory_pg import (
    BEARER,
    DAY,
    SESSION_ROW,
    _artifact_row,
    _consent_extract,
    _mk_cert,
    _mk_tenant,
    _outcomes,
    fake_append,
    pytestmark,  # noqa: F401 — the DSN gate
)

pool, conn, service_token, client = (
    actions.pool,
    actions.conn,
    actions._service_token,
    actions.client,
)
OWNER, MEMBER = "omium:owner", "omium:member"
TRIGGER = "ENOENT: no such file"


@pytest.fixture(autouse=True)
def _fresh_subjects(monkeypatch):
    # the one-active-membership index spans every tenant, so each test's teammates are new people
    monkeypatch.setattr(sys.modules[__name__], "OWNER", f"omium:owner-{uuid4()}")
    monkeypatch.setattr(sys.modules[__name__], "MEMBER", f"omium:member-{uuid4()}")


async def _mk_team(conn, *, members=None, shared=True) -> str:
    members = (MEMBER,) if members is None else members
    tenant = uuid4()
    async with conn.transaction():
        await set_local_tenant(conn, str(tenant))
        await conn.execute(
            "INSERT INTO m1_tenants (id, name, kind, owner_subject, shared_memory) "
            "VALUES ($1, $2, 'personal', $3, $4)",
            tenant,
            f"team-{tenant.hex[:8]}",
            OWNER,
            shared,
        )
        for m in members:
            await conn.execute(
                "INSERT INTO m1_team_members (tenant_id, subject, role) VALUES ($1, $2, 'member')",
                tenant,
                m,
            )
    return str(tenant)


async def _mk_device(conn, tenant: str, subject: str | None) -> str:
    async with conn.transaction():
        await set_local_tenant(conn, tenant)
        device = await conn.fetchval(
            "INSERT INTO m1_devices (tenant_id, platform, hostname_hmac) "
            "VALUES ($1, 'linux', $2) RETURNING id",
            UUID(tenant),
            random.randbytes(32),
        )
        if subject is not None:
            await conn.execute(
                "INSERT INTO m1_device_enrollments (tenant_id, device_id, device_code_hash, "
                "device_pubkey, oidc_subject, status, token_hash, token_expires_at) "
                "VALUES ($1, $2, $3, $4, $5, 'approved', $6, now() + interval '1 hour')",
                UUID(tenant),
                device,
                random.randbytes(32),
                random.randbytes(32),
                subject,
                random.randbytes(32),
            )
    return str(device)


async def _consent(conn, tenant: str, device: str, team: bool) -> None:
    async with conn.transaction():
        await set_local_tenant(conn, tenant)
        await conn.execute(
            "INSERT INTO m1_device_consents (tenant_id, device_id, e1, cloud_judge, training, "
            "team, recorded_at) VALUES ($1, $2, true, false, false, $3, clock_timestamp())",
            UUID(tenant),
            UUID(device),
            team,
        )


async def _plant(conn, tenant, cert, device, owner, *, scope="mine", guidance=None) -> str:
    guidance = guidance or f"guidance-{uuid4().hex[:6]}"
    a = extract.Artifact(
        id=extract.artifact_id(tenant, "pitfall", TRIGGER, guidance, owner),
        tenant_id=tenant,
        kind="pitfall",
        body={
            "trigger": TRIGGER,
            "guidance": guidance,
            "evidence": ["d1"],
            "provenance": {"device_id": device, "task_id": "t", "session_id": "s", "verdict": "x"},
            "support_n": 1,
        },
        cert_id=cert,
        owner_subject=owner,
    )
    assert await extract.insert_artifacts(conn, tenant, [a]) == 1
    await admit.admit_artifact(
        conn,
        fake_append(),
        tenant_id=tenant,
        artifact_id=a.id,
        kind="pitfall",
        lcb=Decimal("0.25"),
        n_obs=10,
        cert_id=cert,
        idempotency_key=f"t:{a.id}",
    )
    if scope == "team":
        assert await admit.set_flag(
            conn, tenant_id=tenant, artifact_id=a.id, column="scope", value="team"
        )
    return str(a.id)


async def _served(c, tenant, viewer=None) -> set[str]:
    params = {"tenant_id": tenant} | ({"viewer_subject": viewer} if viewer is not None else {})
    resp = await c.get("/v1/memory/artifacts", params=params)
    assert resp.status_code == 200, resp.text
    return {a["artifact_id"] for a in resp.json()["artifacts"]}


async def test_extract_stamps_the_enrolled_owner_and_never_merges_two_owners(admin_conn, conn):
    tenant = await _mk_team(admin_conn)
    await _consent_extract(admin_conn, tenant)
    cert = await _mk_cert(admin_conn, tenant)
    d_owner, d_member = (
        await _mk_device(admin_conn, tenant, OWNER),
        await _mk_device(admin_conn, tenant, MEMBER),
    )
    choke = MockChoke()
    events = [{**SESSION_ROW["events"][0], "digest": "d1"}]
    choke.templates[extract.SESSION_TEMPLATE] = [
        {
            **SESSION_ROW,
            "session_id": f"s-{t}",
            "task_id": t,
            "device_id": d,
            "noise_cert_id": cert,
            "verdict_stage": "certified",
            "events": events,
        }
        for t, d in (("o", d_owner), ("m", d_member))
    ]
    same = {"kind": "pitfall", "trigger": TRIGGER, "guidance": "check cwd", "evidence": ["d1"]}

    class Batch:
        async def run(self, requests):
            return {
                r["custom_id"]: json.dumps({"valid": True} if ":" in r["custom_id"] else [same])
                for r in requests
            }

    async with choke.client() as http:
        report = await extract.run_extract(
            QuerychokeReader(http, "http://choke"),
            conn,
            Batch(),
            tenant_id=tenant,
            day=DAY,
            bearer=BEARER,
        )
    assert report.inserted == 2
    async with conn.transaction():
        await set_local_tenant(conn, tenant)
        rows = await conn.fetch("SELECT id, owner_subject FROM memory_artifacts")
    assert {r["id"]: r["owner_subject"] for r in rows} == {
        # the tenant owner keeps the pre-teams id; a teammate's carries their subject
        extract.artifact_id(tenant, "pitfall", TRIGGER, "check cwd"): OWNER,
        extract.artifact_id(tenant, "pitfall", TRIGGER, "check cwd", MEMBER): MEMBER,
    }


async def test_serving_predicate_in_a_team_tenant(admin_conn, pool, conn):
    tenant = await _mk_team(admin_conn)
    cert = await _mk_cert(admin_conn, tenant)
    d_owner, d_member = (
        await _mk_device(admin_conn, tenant, OWNER),
        await _mk_device(admin_conn, tenant, MEMBER),
    )
    mine_o = await _plant(conn, tenant, cert, d_owner, OWNER)
    legacy = await _plant(conn, tenant, cert, d_owner, None)
    mine_m = await _plant(conn, tenant, cert, d_member, MEMBER)
    shared_m = await _plant(conn, tenant, cert, d_member, MEMBER, scope="team")
    everything = {mine_o, legacy, mine_m, shared_m}
    async with client(pool, MockChoke()) as c:
        assert await _served(c, tenant) == everything
        # the member has not consented yet: nothing they share reaches the owner
        assert await _served(c, tenant, OWNER) == {mine_o, legacy}
        assert await _served(c, tenant, MEMBER) == {mine_m, shared_m}
        await _consent(admin_conn, tenant, d_member, True)
        assert await _served(c, tenant, OWNER) == {mine_o, legacy, shared_m}
        await _consent(admin_conn, tenant, d_member, False)
        assert await _served(c, tenant, OWNER) == {mine_o, legacy}
        await _consent(admin_conn, tenant, d_member, True)
        async with admin_conn.transaction():
            await set_local_tenant(admin_conn, tenant)
            await admin_conn.execute(
                "UPDATE m1_tenants SET shared_memory = false WHERE id = $1", UUID(tenant)
            )
        assert await _served(c, tenant, OWNER) == {mine_o, legacy}
        assert await _served(c, tenant, "omium:stranger") == set()
        async with admin_conn.transaction():
            await set_local_tenant(admin_conn, tenant)
            await admin_conn.execute(
                "UPDATE m1_tenants SET shared_memory = true WHERE id = $1", UUID(tenant)
            )
        resp = await c.get(
            "/v1/memory/artifacts", params={"tenant_id": tenant, "viewer_subject": OWNER}
        )
        assert {a["artifact_id"]: a["mine"] for a in resp.json()["artifacts"]} == {
            mine_o: True,
            legacy: True,
            shared_m: False,
        }
        # a leaver's last token reads only their own artifacts, never what teammates share
        leaver = f"omium:leaver-{uuid4()}"
        async with admin_conn.transaction():
            await set_local_tenant(admin_conn, tenant)
            await admin_conn.execute(
                "INSERT INTO m1_team_members (tenant_id, subject, role, left_at) "
                "VALUES ($1, $2, 'member', now())",
                UUID(tenant),
                leaver,
            )
        assert await _served(c, tenant, leaver) == set()
        async with conn.transaction():
            await set_local_tenant(conn, tenant)
            await retrieve.embed_missing(conn, tenant)
        resp = await c.post(
            "/v1/memory/match",
            params={"viewer_subject": MEMBER},
            json={"tenant_id": tenant, "error": TRIGGER},
        )
        assert {a["artifact_id"] for a in resp.json()["artifacts"]} == {mine_m, shared_m}
        resp = await c.get(
            "/v1/memory/outcomes", params={"tenant_id": tenant, "viewer_subject": MEMBER}
        )
        assert {o["artifact_id"] for o in resp.json()["outcomes"]} == {mine_m, shared_m}


async def test_team_consent_is_every_device_not_the_last_writer(admin_conn, pool, conn):
    tenant = await _mk_team(admin_conn)
    cert = await _mk_cert(admin_conn, tenant)
    await _mk_device(admin_conn, tenant, OWNER)
    laptop, desktop = (
        await _mk_device(admin_conn, tenant, MEMBER),
        await _mk_device(admin_conn, tenant, MEMBER),
    )
    shared = await _plant(conn, tenant, cert, laptop, MEMBER, scope="team")
    async with client(pool, MockChoke()) as c:
        await _consent(admin_conn, tenant, desktop, False)
        await _consent(admin_conn, tenant, laptop, True)
        assert shared not in await _served(c, tenant, OWNER)
        await _consent(admin_conn, tenant, desktop, True)
        assert shared in await _served(c, tenant, OWNER)
        await _consent(admin_conn, tenant, laptop, False)
        assert shared not in await _served(c, tenant, OWNER)


async def test_non_team_tenant_serves_everything_to_any_viewer(admin_conn, pool, conn):
    tenant = await _mk_team(admin_conn, members=())
    org = await _mk_tenant(admin_conn)
    cert, o_cert = await _mk_cert(admin_conn, tenant), await _mk_cert(admin_conn, org)
    device, o_device = (
        await _mk_device(admin_conn, tenant, OWNER),
        await _mk_device(admin_conn, org, "idp:a"),
    )
    ids = {
        await _plant(conn, tenant, cert, device, OWNER),
        await _plant(conn, tenant, cert, device, None),
    }
    o_ids = {
        await _plant(conn, org, o_cert, o_device, "idp:a"),
        await _plant(conn, org, o_cert, o_device, "idp:b"),
    }
    async with client(pool, MockChoke()) as c:
        assert await _served(c, tenant, "omium:anyone") == ids
        assert await _served(c, org, "idp:a") == o_ids
        for aid in o_ids:
            for action in ("share", "pin", "unshare", "unpin"):
                resp = await c.post(
                    f"/v1/memory/artifacts/{aid}/{action}",
                    params={"viewer_subject": "idp:a"},
                    json={"tenant_id": org},
                )
                assert resp.status_code == 200, (action, resp.text)


async def test_actions_are_owner_only_and_share_needs_consent(admin_conn, pool, conn):
    tenant = await _mk_team(admin_conn)
    cert = await _mk_cert(admin_conn, tenant)
    d_owner, d_member = (
        await _mk_device(admin_conn, tenant, OWNER),
        await _mk_device(admin_conn, tenant, MEMBER),
    )
    of_owner = await _plant(conn, tenant, cert, d_owner, OWNER)
    legacy = await _plant(conn, tenant, cert, d_owner, None)
    of_member = await _plant(conn, tenant, cert, d_member, MEMBER)
    choke = MockChoke()

    async def act(aid, action, viewer):
        body = {"tenant_id": tenant} | ({"reason": "stale"} if action == "retire" else {})
        return await c.post(
            f"/v1/memory/artifacts/{aid}/{action}", params={"viewer_subject": viewer}, json=body
        )

    def refused(resp, reason):
        assert resp.status_code == 403, resp.text
        code = "M1E-1008" if reason == "consent_required" else "M1E-1007"
        assert resp.json() == {"error": {"code": code, "message": reason, "reason": reason}}

    async with client(pool, choke) as c:
        n = len(choke.appended)
        for action in ("pin", "unpin", "share", "unshare", "retire"):
            refused(await act(of_owner, action, MEMBER), "not_owner")
            refused(await act(legacy, action, MEMBER), "not_owner")
        assert len(choke.appended) == n
        refused(await act(of_member, "share", MEMBER), "consent_required")
        await _consent(admin_conn, tenant, d_member, True)
        assert (await act(of_member, "share", MEMBER)).json() == {
            "artifact_id": of_member,
            "scope": "team",
        }
        for action in ("unshare", "pin", "retire"):
            refused(await act(of_member, action, OWNER), "not_owner")
        assert (await act(legacy, "pin", OWNER)).status_code == 200
        refused(await act(of_owner, "share", OWNER), "consent_required")
        assert (await act(of_member, "retire", MEMBER)).status_code == 200
        assert (await act(uuid4(), "pin", MEMBER)).status_code == 404


async def test_admission_counts_only_the_owners_evidence_in_a_team(admin_conn, conn):
    tenant = await _mk_team(admin_conn)
    cert = await _mk_cert(admin_conn, tenant)
    d_owner, d_member = (
        await _mk_device(admin_conn, tenant, OWNER),
        await _mk_device(admin_conn, tenant, MEMBER),
    )
    a = extract.Artifact(
        id=extract.artifact_id(tenant, "pitfall", TRIGGER, "g"),
        tenant_id=tenant,
        kind="pitfall",
        body={
            "trigger": TRIGGER,
            "guidance": "g",
            "evidence": ["d1"],
            "provenance": {"device_id": d_owner},
        },
        cert_id=cert,
        owner_subject=OWNER,
    )
    assert await extract.insert_artifacts(conn, tenant, [a]) == 1
    choke = MockChoke()
    choke.templates[admit.OUTCOME_TEMPLATE] = lambda params: _outcomes(d_member, cert, n=10)
    async with choke.client() as http:
        report = await admit.run_admit(
            QuerychokeReader(http, "http://choke"),
            conn,
            fake_append(choke),
            tenant_id=tenant,
            day=DAY,
            bearer=BEARER,
        )
    assert (report.admitted, report.held) == (0, 1)
    assert (await _artifact_row(conn, tenant, a.id))["n_obs"] == 0
    choke.templates[admit.OUTCOME_TEMPLATE] = lambda params: _outcomes(d_owner, cert, n=10)
    async with choke.client() as http:
        report = await admit.run_admit(
            QuerychokeReader(http, "http://choke"),
            conn,
            fake_append(choke),
            tenant_id=tenant,
            day=DAY + timedelta(days=1),
            bearer=BEARER,
        )
    assert report.admitted == 1
