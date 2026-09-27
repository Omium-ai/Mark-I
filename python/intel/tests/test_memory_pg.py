"""Memory plane against real Postgres (m1_001/020/021/040): the enum, the DB-side ADMIT-LCB
refusal, the admission receipted through controld's append route (a fake speaking its exact
wire), the live-cert gate on extraction, the revoked-device refusal."""

import json
import os
import random
from datetime import date
from decimal import Decimal
from functools import partial
from pathlib import Path
from uuid import UUID, uuid4

import asyncpg
import pytest
from app.db import set_local_tenant
from app.memory import admit, extract
from app.tvo.reader import QuerychokeReader
from choke_mock import MockChoke
from mark1_receipts import ReceiptAppendError, append_server_record
from tests.roles import service_pool

DSN = os.environ.get("M1_TEST_PG_DSN", "")
REQUIRE_STORES = os.environ.get("M1_REQUIRE_STORES", "0") == "1"
DAY = date(2026, 8, 1)
BEARER = "op-token"


def fake_append(choke: MockChoke | None = None) -> admit.ReceiptAppend:
    """What memory/jobs.py builds: the shared client bound to controld's base URL + credential."""
    return partial(append_server_record, (choke or MockChoke()).client(), "http://choke", BEARER)


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


async def _mk_tenant(conn) -> str:
    tag = f"memtest-{random.randbytes(4).hex()}"
    tenant = uuid4()
    async with conn.transaction():
        org = await conn.fetchval(
            "INSERT INTO m1_organizations (name, primary_domain) VALUES ($1, $2) RETURNING id",
            tag,
            f"{tag}.example",
        )
        await set_local_tenant(conn, str(tenant))
        await conn.execute(
            "INSERT INTO m1_tenants (id, org_id, name) VALUES ($1, $2, $3)", tenant, org, tag
        )
    return str(tenant)


async def _consent_extract(conn, tenant: str, **over) -> None:
    """The mem:extract@1 row controld's "Learn from my sessions" switch writes (m1_092)."""
    row = {"subprocessor": "nebius", "region": "global", **over}
    async with conn.transaction():
        await set_local_tenant(conn, tenant)
        await conn.execute(
            "INSERT INTO m1_cloud_judge_consents (tenant_id, judge_id, subprocessor, region, "
            "max_tier, consented_by) VALUES ($1, 'mem:extract@1', $2, $3, 'E0', 'test')",
            UUID(tenant),
            row["subprocessor"],
            row["region"],
        )


async def _mk_cert(conn, tenant: str, *, expired: bool = False, status: str = "certified") -> str:
    async with conn.transaction():
        await set_local_tenant(conn, tenant)
        verifier = await conn.fetchval(
            "INSERT INTO m1_verifiers (verifier_key, kind, version, display_name, definition) "
            "VALUES ($1, 'judge', 1, 'test judge', '{}'::jsonb) RETURNING id",
            f"judge:mem-{uuid4().hex[:8]}",
        )
        gold = await conn.fetchval(
            "INSERT INTO gold_sets (tenant_id, agent, frozen_at) VALUES ($1, 'claudecode', now()) "
            "RETURNING id",
            UUID(tenant),
        )
        issued, expires = (
            ("now() - interval '2 days'", "now() - interval '1 day'")
            if expired
            else (
                "now()",
                "now() + interval '1 day'",
            )
        )
        return str(
            await conn.fetchval(
                "INSERT INTO noise_certificates (tenant_id, verifier_id, gold_set_id, status, "
                "rho_plus, rho_minus, natarajan_lcb, gold_n, identifiable, issued_at, expires_at) "
                f"VALUES ($1, $2, $3, '{status}', 0.05, 0.05, 0.8, 200, true, "
                f"{issued}, {expires}) RETURNING id",
                UUID(tenant),
                verifier,
                gold,
            )
        )


async def _mk_device(conn, tenant: str, *, revoked: bool = False) -> str:
    revocation = "now(), 'sec@omium.ai'" if revoked else "NULL, NULL"
    async with conn.transaction():
        await set_local_tenant(conn, tenant)
        return str(
            await conn.fetchval(
                "INSERT INTO m1_devices (tenant_id, platform, hostname_hmac, revoked_at, "
                f"revoked_by) VALUES ($1, 'linux', $2, {revocation}) RETURNING id",
                UUID(tenant),
                random.randbytes(32),
            )
        )


async def _mk_artifact(conn, tenant: str, cert: str, device: str) -> extract.Artifact:
    guidance = f"guidance-{uuid4().hex[:6]}"
    a = extract.Artifact(
        id=extract.artifact_id(tenant, "pitfall", "ENOENT", guidance),
        tenant_id=tenant,
        kind="pitfall",
        body={
            "trigger": "ENOENT",
            "guidance": guidance,
            "evidence": ["d1"],
            "provenance": {
                "device_id": device,
                "task_id": "t1",
                "session_id": "s1",
                "verdict": "satisfied",
            },
            "support_n": 1,
        },
        cert_id=cert,
    )
    assert await extract.insert_artifacts(conn, tenant, [a]) == 1
    return a


async def _artifact_row(conn, tenant: str, artifact_id):
    async with conn.transaction():
        await set_local_tenant(conn, tenant)
        return await conn.fetchrow(
            "SELECT state, lcb, n_obs, receipt_id FROM memory_artifacts WHERE id = $1", artifact_id
        )


def _appended(choke: MockChoke, tenant: str):
    return [
        (b["record_type"], UUID(b["subject_id"]), b["idempotency_key"], b["payload"])
        for b in choke.appended
        if b["tenant_id"] == tenant
    ]


_TEMPLATE_ROWS = json.loads(
    (
        Path(__file__).resolve().parents[3]
        / "go/controld/internal/querychoke/testdata/intel_template_rows.json"
    ).read_text()
)
OUTCOME_ROWS = _TEMPLATE_ROWS["artifact_outcomes"]
OUTCOME_ROW = OUTCOME_ROWS[0]
SESSION_ROW = _TEMPLATE_ROWS[extract.SESSION_TEMPLATE][0]


def _outcomes(device: str, cert: str, utility: float = 5000.0, n: int = 10, stage="certified"):
    """`artifact_outcomes` wire rows, key set locked to controld's fixture (the Go side asserts
    the template's aliases equal these keys)."""
    rows = [
        {
            **OUTCOME_ROW,
            "task_id": str(UUID(int=i + 1)),
            "utility": utility,
            "task_cost": 1000,
            "verdict_stage": stage,
            "noise_cert_id": cert,
            "device_id": device,
        }
        for i in range(n)
    ]
    assert all(r.keys() == OUTCOME_ROW.keys() for r in rows)
    return rows


async def test_artifact_kinds_equal_db_enum(conn):
    rows = await conn.fetch(
        "SELECT enumlabel FROM pg_enum e JOIN pg_type t ON t.oid = e.enumtypid "
        "WHERE t.typname = 'artifact_kind'"
    )
    assert {r["enumlabel"] for r in rows} == extract.KINDS


async def test_extraction_refuses_uncertified_session_at_the_live_cert(admin_conn, conn):
    tenant = await _mk_tenant(admin_conn)
    await _consent_extract(admin_conn, tenant)
    live, expired = (
        await _mk_cert(admin_conn, tenant),
        await _mk_cert(admin_conn, tenant, expired=True),
    )
    boot = await _mk_cert(admin_conn, tenant, status="bootstrapping")
    device = await _mk_device(admin_conn, tenant)
    choke = MockChoke()

    def row(task, stage, cert):
        """A `memory_certified_sessions` wire row, key set locked to controld's fixture."""
        r = {
            **SESSION_ROW,
            "session_id": f"s-{task}",
            "task_id": task,
            "device_id": device,
            "verdict_stage": stage,
            "noise_cert_id": cert,
            "events": [{**SESSION_ROW["events"][0], "digest": "d1"}],
        }
        assert r.keys() == SESSION_ROW.keys()
        return r

    choke.templates[extract.SESSION_TEMPLATE] = [
        row("ok", "certified", live),
        row("stale", "certified", expired),
        row("boot", "certified", boot),
        row("prov", "provisional", live),
    ]
    seen: list[list[str]] = []

    class Batch:
        async def run(self, requests):
            seen.append([r["custom_id"] for r in requests])
            answers = {
                "ok": [
                    {
                        "kind": "pitfall",
                        "trigger": "ENOENT",
                        "guidance": "check cwd",
                        "evidence": ["d1"],
                    }
                ],
                "stale": [
                    {"kind": "pitfall", "trigger": "x", "guidance": "stale", "evidence": ["d1"]}
                ],
                "prov": [
                    {"kind": "pitfall", "trigger": "x", "guidance": "prov", "evidence": ["d1"]}
                ],
                "ok:0": {"valid": True, "reason": ""},
            }
            return {r["custom_id"]: json.dumps(answers[r["custom_id"]]) for r in requests}

    async with choke.client() as http:
        report = await extract.run_extract(
            QuerychokeReader(http, "http://choke"),
            conn,
            Batch(),
            tenant_id=tenant,
            day=DAY,
            bearer=BEARER,
        )
    assert seen == [["ok"], ["ok:0"]]
    assert (report.sessions_seen, report.sessions_certified, report.inserted) == (4, 1, 1)
    async with conn.transaction():
        await set_local_tenant(conn, tenant)
        assert await conn.fetchval("SELECT count(*) FROM memory_artifacts") == 1
    async with choke.client() as http:
        rerun = await extract.run_extract(
            QuerychokeReader(http, "http://choke"),
            conn,
            Batch(),
            tenant_id=tenant,
            day=DAY,
            bearer=BEARER,
        )
    assert rerun.inserted == 0


async def test_extraction_reads_nothing_without_a_live_mem_extract_consent(admin_conn, conn):
    tenant = await _mk_tenant(admin_conn)
    choke = MockChoke()

    class Batch:
        async def run(self, requests):
            raise AssertionError("an unconsented tenant reached the router")

    async def extract_once() -> extract.ExtractReport:
        async with choke.client() as http:
            return await extract.run_extract(
                QuerychokeReader(http, "http://choke"),
                conn,
                Batch(),
                tenant_id=tenant,
                day=DAY,
                bearer=BEARER,
            )

    assert await extract_once() == extract.ExtractReport(0, 0, 0, 0, 0, 0)
    await _consent_extract(admin_conn, tenant, subprocessor="anthropic", region="us")
    assert await extract_once() == extract.ExtractReport(0, 0, 0, 0, 0, 0)
    async with admin_conn.transaction():
        await set_local_tenant(admin_conn, tenant)
        await admin_conn.execute(
            "UPDATE m1_cloud_judge_consents SET revoked_at = now(), revoked_reason = 'settings' "
            "WHERE tenant_id = $1",
            UUID(tenant),
        )
    await _consent_extract(admin_conn, tenant)
    assert await extract.extraction_consented(conn, tenant)
    assert await conn.fetchval(
        "SELECT has_table_privilege('intel_app', 'm1_cloud_judge_consents', 'SELECT')"
    ), "m1_092's grant: intel reads the consent as intel_app in prod"


async def test_admission_below_lcb_refused_at_the_db(admin_conn, conn):
    tenant = await _mk_tenant(admin_conn)
    cert, device = await _mk_cert(admin_conn, tenant), await _mk_device(admin_conn, tenant)
    a = await _mk_artifact(conn, tenant, cert, device)
    choke = MockChoke()
    with pytest.raises(asyncpg.CheckViolationError) as ei:
        await admit.admit_artifact(
            conn,
            fake_append(choke),
            tenant_id=tenant,
            artifact_id=a.id,
            kind=a.kind,
            lcb=Decimal("0"),
            n_obs=10,
            cert_id=cert,
            idempotency_key=f"t:{a.id}",
        )
    assert ei.value.sqlstate == "23514" and ei.value.constraint_name == "admitted_is_earned"
    row = await _artifact_row(conn, tenant, a.id)
    assert row["state"] == "extracted" and row["receipt_id"] is None
    # The receipt landed first and the flip rolled back: a harmless orphan, never a flipped row.
    assert [x[1] for x in _appended(choke, tenant)] == [a.id]


async def test_admission_above_lcb_admitted_with_receipt(admin_conn, conn):
    tenant = await _mk_tenant(admin_conn)
    cert, device = await _mk_cert(admin_conn, tenant), await _mk_device(admin_conn, tenant)
    first, second = (
        await _mk_artifact(conn, tenant, cert, device),
        await _mk_artifact(conn, tenant, cert, device),
    )
    choke = MockChoke()
    ids = [
        await admit.admit_artifact(
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
        for a in (first, second)
    ]
    row = await _artifact_row(conn, tenant, first.id)
    assert (row["state"], row["lcb"], row["n_obs"], row["receipt_id"]) == (
        "admitted",
        Decimal("0.25"),
        10,
        ids[0],
    )
    assert _appended(choke, tenant) == [
        (
            "memory_admission",
            a.id,
            f"t:{a.id}",
            {"kind": "pitfall", "lcb_micro": 250_000, "n_obs": 10, "cert_id": cert},
        )
        for a in (first, second)
    ]
    assert [UUID(r["receipt_id"]) for r in choke.receipts.values()] == ids
    # An admitted artifact is not admissible again; the repeat under its key mints no new link.
    with pytest.raises(ValueError, match="not admissible"):
        await admit.admit_artifact(
            conn,
            fake_append(choke),
            tenant_id=tenant,
            artifact_id=first.id,
            kind=first.kind,
            lcb=Decimal("0.25"),
            n_obs=10,
            cert_id=cert,
            idempotency_key=f"t:{first.id}",
        )
    assert len(choke.appended) == 2


async def test_admission_under_expired_cert_refused_by_trigger(admin_conn, conn):
    tenant = await _mk_tenant(admin_conn)
    live, expired = (
        await _mk_cert(admin_conn, tenant),
        await _mk_cert(admin_conn, tenant, expired=True),
    )
    a = await _mk_artifact(conn, tenant, live, await _mk_device(admin_conn, tenant))
    with pytest.raises(asyncpg.CheckViolationError, match="not currently certified"):
        await admit.admit_artifact(
            conn,
            fake_append(),
            tenant_id=tenant,
            artifact_id=a.id,
            kind=a.kind,
            lcb=Decimal("0.25"),
            n_obs=10,
            cert_id=expired,
            idempotency_key=f"t:{a.id}",
        )
    assert (await _artifact_row(conn, tenant, a.id))["receipt_id"] is None


async def test_unreceipted_admission_never_flips(admin_conn, conn):
    """controld answers 500 (or refuses the credential): the flip is not attempted, the
    transaction rolls back, and the artifact stays exactly where it was (fail-closed)."""
    tenant = await _mk_tenant(admin_conn)
    cert, device = await _mk_cert(admin_conn, tenant), await _mk_device(admin_conn, tenant)
    a = await _mk_artifact(conn, tenant, cert, device)
    choke = MockChoke()
    for failure, code in (
        ((500, "M1E-9500", "chain append failed"), "M1E-9500"),
        ((403, "M1E-1001", "service credential rejected"), "M1E-1001"),
    ):
        choke.append_fail_with = failure
        with pytest.raises(ReceiptAppendError) as e:
            await admit.admit_artifact(
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
        assert e.value.code == code
        row = await _artifact_row(conn, tenant, a.id)
        assert (row["state"], row["receipt_id"], choke.appended) == ("extracted", None, [])
    choke.append_fail_with = None
    choke.templates[admit.OUTCOME_TEMPLATE] = lambda params: _outcomes(device, cert, n=10)
    async with choke.client() as http:
        report = await admit.run_admit(
            QuerychokeReader(http, "http://choke"),
            conn,
            fake_append(choke),
            tenant_id=tenant,
            day=DAY,
            bearer=BEARER,
        )
    assert report.admitted == 1
    assert (await _artifact_row(conn, tenant, a.id))["state"] == "admitted"


async def test_revoked_device_artifacts_are_not_admitted(admin_conn, conn):
    tenant = await _mk_tenant(admin_conn)
    cert = await _mk_cert(admin_conn, tenant)
    good, revoked = (
        await _mk_device(admin_conn, tenant),
        await _mk_device(admin_conn, tenant, revoked=True),
    )
    tainted, clean = (
        await _mk_artifact(conn, tenant, cert, revoked),
        await _mk_artifact(conn, tenant, cert, good),
    )
    choke = MockChoke()
    choke.templates[admit.OUTCOME_TEMPLATE] = lambda params: _outcomes(good, cert, n=25)
    async with choke.client() as http:
        report = await admit.run_admit(
            QuerychokeReader(http, "http://choke"),
            conn,
            fake_append(choke),
            tenant_id=tenant,
            day=DAY,
            bearer=BEARER,
        )
    assert (report.considered, report.admitted, report.refused_revoked) == (2, 1, 1)
    assert (await _artifact_row(conn, tenant, tainted.id))["state"] == "extracted"
    row = await _artifact_row(conn, tenant, clean.id)
    assert row["state"] == "admitted" and row["lcb"] > 0 and row["n_obs"] == admit.B_QUOTA
    assert [(x[1], x[2]) for x in _appended(choke, tenant)] == [
        (clean.id, f"memory.admit:{DAY.isoformat()}:{clean.id}")
    ]
    assert report.receipt_ids == (row["receipt_id"],)
    assert json.loads(next(iter(choke.receipts.values()))["payload"])["subject_id"] == str(clean.id)


async def test_hold_and_retire_never_receipt(admin_conn, conn):
    tenant = await _mk_tenant(admin_conn)
    cert, device = await _mk_cert(admin_conn, tenant), await _mk_device(admin_conn, tenant)
    a = await _mk_artifact(conn, tenant, cert, device)
    choke = MockChoke()
    choke.templates[admit.OUTCOME_TEMPLATE] = lambda params: (
        _outcomes(device, cert, n=3) + _outcomes(device, cert, n=7, stage="provisional")
    )
    append = fake_append(choke)
    async with choke.client() as http:
        reader = QuerychokeReader(http, "http://choke")
        held = await admit.run_admit(reader, conn, append, tenant_id=tenant, day=DAY, bearer=BEARER)
        assert (held.held, (await _artifact_row(conn, tenant, a.id))["state"]) == (1, "shadow")
        choke.templates[admit.OUTCOME_TEMPLATE] = lambda params: _outcomes(
            device, cert, utility=-5000.0
        )
        retired = await admit.run_admit(
            reader, conn, append, tenant_id=tenant, day=DAY, bearer=BEARER
        )
    assert (retired.retired, (await _artifact_row(conn, tenant, a.id))["state"]) == (1, "retired")
    assert choke.appended == []


async def test_certified_outcomes_reads_controld_fixture_rows(admin_conn, conn):
    """The `artifact_outcomes` wire, both ways: controld's fixture rows (aliases locked on the
    Go side) go through certified_outcomes — the certified row under a live cert becomes the
    ADMIT-LCB sample, the row with no stage-final verdict never does (§5.4) — and the request
    carries exactly the half-open window and artifact the template takes."""
    tenant = await _mk_tenant(admin_conn)
    cert, device = await _mk_cert(admin_conn, tenant), await _mk_device(admin_conn, tenant)
    certified, uncertified = OUTCOME_ROWS
    assert (certified["verdict_stage"], uncertified["verdict_stage"]) == ("certified", "")
    rows = [
        {**certified, "noise_cert_id": cert, "device_id": device},
        {**uncertified, "device_id": device},
    ]
    artifact = uuid4()
    choke = MockChoke()
    choke.templates[admit.OUTCOME_TEMPLATE] = rows
    async with choke.client() as http:
        got = await admit.certified_outcomes(
            QuerychokeReader(http, "http://choke"),
            conn,
            tenant_id=tenant,
            artifact_id=artifact,
            window_start=date(2026, 8, 10),
            window_end=date(2026, 9, 9),
            bearer=BEARER,
        )
    assert got == [
        admit.Outcome(
            task_id=certified["task_id"],
            utility=float(certified["utility"]),
            task_cost=float(certified["task_cost"]),
            stage="certified",
            noise_cert_id=cert,
            device_id=device,
        )
    ]
    assert choke.requests == [
        (
            admit.OUTCOME_TEMPLATE,
            {"from": "2026-08-10", "to": "2026-09-09", "artifact_id": str(artifact)},
            f"Bearer {BEARER}",
        )
    ]
