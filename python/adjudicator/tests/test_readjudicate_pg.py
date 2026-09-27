"""adj_002 against real Postgres: the nightly cascade lands readjudicate.run and promotion.step in
job_runs, the escalations row cites the m1_certified_runs row it ran, the RM's folded RmScore
votes accrue on the m1_069 head against the certified ledger through promotion.step
(FR-LEARN-004, 16 §L6), the CHECKs refuse half-recorded legs, and RLS keeps one tenant's
escalations invisible to another."""

import functools
import json
import os
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import UUID, uuid4

import asyncpg
import httpx
import pytest
from app.certified.runner import CONSENT_ID, CONSISTENCY_ID, definition, execution_hash
from app.db import set_local_tenant
from app.jobs import JOBS
from app.jobs.judge_batch import run as judge_batch_run
from app.jobs.nightly import certs_recompute, promotion_step, spectral_estimate
from app.jobs.readjudicate import NO_ATTEMPT, RM_NOT_ESCALATION_SCOPED, run
from app.jobs.registry import validate
from app.jobs.runner import run_many
from app.registry.promotion import RECEIPT_TYPE, register, transition
from mark1_receipts import canonical_json
from pydantic import SecretStr
from tests.roles import service_pool
from tests.test_certified import ANCHOR, T3_ID, TEMPLATE
from tests.test_jobs import FakeChoke
from tests.test_pg_stores import FakeControld, _mk_judge_verifier, _mk_tenant
from tests.test_promotion_pg import _head, _mk_cert
from tests.test_readjudicate import AMBIGUOUS, NO_TEST, FakeCloud, rm_row, row, rows
from tests.test_readjudicate import env as _env
from tests.test_rm_pg import _mk_sealed_rm

env = _env  # the ADJ_RM_* / ADJ_E2B_* fixture, re-exported for this module's collection

DSN = os.environ.get("M1_TEST_PG_DSN", "")
REQUIRE_STORES = os.environ.get("M1_REQUIRE_STORES", "0") == "1"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not DSN and not REQUIRE_STORES,
        reason="M1_TEST_PG_DSN not set (estate skipif idiom; M1_REQUIRE_STORES=0)",
    ),
]

NOW = datetime(2026, 9, 16, 3, 0, tzinfo=UTC)
SETTINGS = SimpleNamespace(
    querychoke_base_url="http://choke",
    querychoke_token=SecretStr("svc"),
    http_timeout_s=5.0,
    llm_router_url="",
    judge_max_tasks_per_day=60,
    judge_max_tasks_per_run=60,
)


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


async def _verifier(pool, key: str, kind: str, defn: dict, xh: bytes | None = None) -> UUID:
    """A global m1_verifiers row keyed so registry_by_wire_id resolves the wire id. The code pins
    these keys, so a row already there must be exactly this one, never silently reused."""
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO m1_verifiers (verifier_key, kind, version, display_name, definition, "
            "effective_execution_hash) VALUES ($1, $2, 1, $1, $3::jsonb, $4) "
            "ON CONFLICT (verifier_key, version) DO NOTHING",
            key,
            kind,
            canonical_json(defn),
            xh,
        )
        row = await conn.fetchrow(
            "SELECT id, kind, definition, effective_execution_hash FROM m1_verifiers "
            "WHERE verifier_key = $1 AND version = 1",
            key,
        )
    assert (row["kind"], json.loads(row["definition"]), row["effective_execution_hash"]) == (
        kind,
        defn,
        xh,
    ), f"{key}@1 in the shared catalog is not this test's row"
    return row["id"]


async def _verifiers(pool, tenant: str) -> tuple[UUID, str]:
    await _verifier(
        pool, T3_ID, "anchor", definition(ANCHOR, TEMPLATE), execution_hash(ANCHOR, TEMPLATE)
    )
    await _verifier(pool, CONSISTENCY_ID.split("@")[0], "consistency", {"kind": "consistency"})
    await _verifier(pool, "judge:g", "judge", {"kind": "judge", "group": "judge"})
    key = f"rm:readj-{uuid4().hex[:8]}"
    return await _mk_sealed_rm(pool, key, tenant=tenant), f"{key}@1"


async def _consent(pool, tenant: str) -> UUID:
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        return await conn.fetchval(
            "INSERT INTO m1_cloud_judge_consents (tenant_id, judge_id, subprocessor, region, "
            "max_tier, consented_by) VALUES ($1, $2, 'e2b', 'us', 'E1', 'test') RETURNING id",
            UUID(tenant),
            CONSENT_ID,
        )


async def _escalations(pool, tenant: str) -> list[dict]:
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        return [dict(r) for r in await conn.fetch("SELECT * FROM escalations ORDER BY task_id")]


def _http(cloud: FakeCloud, controld: FakeControld) -> httpx.AsyncClient:
    async def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/internal/v1/receipts/append":
            return controld.handler(req)
        return await cloud.handler(req)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def _evidence(task_id, attempt_id, tier):
    return f"{tier}:typed"


async def _archive(task_id, attempt_id, tier):
    return b"TAR-" + tier.encode()


def _targets(http: httpx.AsyncClient) -> dict:
    return {
        **validate(JOBS),
        "spectral.estimate": functools.partial(spectral_estimate, http=FakeChoke([]).client()),
        "certs.recompute": functools.partial(certs_recompute, http=http),
        "readjudicate.run": functools.partial(
            run, http=http, evidence_for=_evidence, archive_for=_archive
        ),
        "promotion.step": functools.partial(promotion_step, http=http),
        "judge_batch.run": functools.partial(judge_batch_run, http=http),
    }


def _certified(r: dict, verdict: str, cert: str) -> dict:
    return {**r, "task_verdict": verdict, "task_noise_cert_id": cert}


async def test_cascade_escalates_persists_and_accrues_the_shadow_pair(admin, pool, env):
    tenant = await _mk_tenant(admin)
    rm_verifier, rm_id = await _verifiers(admin, tenant)
    consent = await _consent(admin, tenant)
    controld = FakeControld({RECEIPT_TYPE, "noise_certificate"})
    async with pool.acquire() as conn:
        cert = await _mk_cert(conn, tenant, await _mk_judge_verifier(admin))
        pid = await register(conn, tenant_id=tenant, verifier_id=rm_verifier)
        await transition(
            conn,
            controld.append(),
            tenant_id=tenant,
            promotion_id=pid,
            from_state="probation",
            to_state="shadow",
            reason="eval_card_complete",
        )
    # lint-accept + a diff judge's accept (two cliques): eta 0.891, just over 1 - A/D; no test
    # anchor, so the escalated verdict is `satisfied` and the Youden pairs have both classes.
    # The RM scored all three tasks (0.9 folds to accept) and the ledger certified them.
    satisfied_task = uuid4()
    cloud = FakeCloud(
        [
            *rows(),
            row(satisfied_task, "ruff@cat-1", "AnchorVote", "satisfied"),
            row(satisfied_task, "judge:g@1", "JudgeVote", "satisfied", seq=2),
            _certified({**rm_row(AMBIGUOUS, 0.9), "verifier_id": rm_id}, "violated", cert),
            _certified({**rm_row(NO_TEST, 0.9), "verifier_id": rm_id}, "violated", cert),
            _certified({**rm_row(satisfied_task, 0.9), "verifier_id": rm_id}, "satisfied", cert),
        ]
    )
    http = _http(cloud, controld)

    results = await run_many(pool, SETTINGS, list(JOBS), _targets(http), tenant_id=tenant, now=NOW)
    assert results["readjudicate.run"] == "succeeded" and results["promotion.step"] == "succeeded"
    assert len(cloud.ingested) == 1  # the three verdicts re-entered the ledger in one batch
    esc = {r["task_id"]: r for r in await _escalations(pool, tenant)}
    assert set(esc) == {AMBIGUOUS, NO_TEST, satisfied_task}
    assert esc[satisfied_task]["verdict"] == "satisfied"
    rec = esc[AMBIGUOUS]
    assert (rec["provisional"], rec["verdict"], rec["stage"]) == (
        "violated",
        "violated",
        "bootstrapping",
    )
    assert rec["noise_cert_id"] == UUID(cert) and len(rec["posterior"]) == 4
    assert (rec["consistency_fused"], rec["consistency_excluded"]) == (1, 0)
    assert (rec["rm_verifier_id"], rec["rm_vote"]) == (None, None)
    assert rec["rm_skipped"] == RM_NOT_ESCALATION_SCOPED
    assert rec["t3_skipped"] is None and rec["agreement_rate"] == 1
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        t3 = await conn.fetchrow(
            "SELECT * FROM m1_certified_runs WHERE id = $1", rec["certified_run_id"]
        )
    assert t3["consent_id"] == consent and t3["task_id"] == AMBIGUOUS
    assert t3["attempt_id"] == NO_ATTEMPT and t3["verdict"] == "violated"
    assert t3["edge_verdict"] == "satisfied" and t3["divergence"] == 1

    # FR-LEARN-004: the RM's 3 votes pair with certified verdicts; the m1_069 head counts them
    async with pool.acquire() as conn:
        head = await _head(conn, tenant, pid)
    assert head["state"] == "shadow" and head["shadow_n"] == 3 and head["cert_id"] == UUID(cert)
    assert head["gold_n"] == 0 and head["bar"] == 0
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        jobs = await conn.fetch(
            "SELECT job, outcome, attempts FROM job_runs WHERE tenant_id = $1 ORDER BY job",
            tenant,
        )
    assert [(j["job"], j["outcome"], j["attempts"]) for j in jobs if "read" in j["job"]] == [
        ("readjudicate.run", "succeeded", 1)
    ]

    again = await run_many(pool, SETTINGS, list(JOBS), _targets(http), tenant_id=tenant, now=NOW)
    assert again["readjudicate.run"] == "already_done" and again["promotion.step"] == "already_done"
    assert len(cloud.e2b.calls) == 5, "one sandbox lifecycle; the re-run touched nothing"

    # A task whose T3 ran is final; one without a run is recomputed into the same row.
    async with admin.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        await conn.execute("DELETE FROM job_runs WHERE job = 'readjudicate.run'")
    ctx = SimpleNamespace(
        pool=pool, settings=SETTINGS, tenant_id=tenant, window_start=NOW, day=NOW.date()
    )
    await run(ctx, http=http, evidence_for=_evidence, archive_for=_archive)
    assert len(cloud.e2b.calls) == 5
    assert len(await _escalations(pool, tenant)) == 3


async def test_checks_refuse_half_recorded_legs(admin, pool):
    tenant = await _mk_tenant(admin)
    base = dict(
        tenant_id=UUID(tenant),
        task_id=uuid4(),
        window_start=NOW,
        eta=0.3,
        provisional="violated",
        verdict="violated",
        stage="uncertified",
        posterior=[0.3, 0.6, 0.05, 0.05],
        provenance="prior",
        vote_count=2,
        t3_skipped="t3_no_test_anchor",
        rm_skipped="rm_no_scorer",
    )

    async def insert(**kw):
        row = {**base, **kw}
        cols = ", ".join(row)
        params = ", ".join(f"${i + 1}" for i in range(len(row)))
        async with pool.acquire() as conn, conn.transaction():
            await set_local_tenant(conn, tenant)
            await conn.execute(f"INSERT INTO escalations ({cols}) VALUES ({params})", *row.values())

    await insert()
    for bad in (
        {"task_id": uuid4(), "rm_vote": "accept"},  # vote without the member and a skip reason
        {"task_id": uuid4(), "rm_skipped": None},  # neither vote nor reason
        {"task_id": uuid4(), "t3_skipped": None},  # no run and no reason
        {"task_id": uuid4(), "posterior": [0.5, 0.5]},
        {"task_id": uuid4(), "stage": "PROVISIONAL"},
        {"task_id": uuid4(), "eta": 1.5},
    ):
        with pytest.raises(asyncpg.CheckViolationError):
            await insert(**bad)
    with pytest.raises(asyncpg.ForeignKeyViolationError):
        await insert(task_id=uuid4(), certified_run_id=uuid4(), t3_skipped=None)
    assert len(await _escalations(pool, tenant)) == 1


async def test_rls_isolation_on_escalations(admin, pool):
    async with pool.acquire() as conn:
        bypass = await conn.fetchval(
            "SELECT rolbypassrls OR rolsuper FROM pg_roles WHERE rolname = current_user"
        )
    if bypass:
        msg = "test role bypasses RLS — isolation not observable from here"
        if REQUIRE_STORES:
            pytest.fail(msg, pytrace=False)
        pytest.skip(msg)
    a, b = await _mk_tenant(admin), await _mk_tenant(admin)
    task = uuid4()
    sql = (
        "INSERT INTO escalations (tenant_id, task_id, window_start, eta, provisional, verdict, "
        "stage, posterior, provenance, vote_count, t3_skipped, rm_skipped) VALUES "
        "($1, $2, $3, 0.3, 'violated', 'violated', 'uncertified', $4, 'prior', 1, 'x', 'y')"
    )
    async with pool.acquire() as conn:
        async with conn.transaction():
            await set_local_tenant(conn, a)
            await conn.execute(sql, UUID(a), task, NOW, [0.3, 0.6, 0.05, 0.05])
        assert await conn.fetchval("SELECT count(*) FROM escalations") == 0  # no GUC
        async with conn.transaction():
            await set_local_tenant(conn, b)
            assert (
                await conn.fetch("SELECT task_id FROM escalations WHERE task_id = $1", task) == []
            )
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            async with conn.transaction():
                await set_local_tenant(conn, b)
                await conn.execute(sql, UUID(a), uuid4(), NOW, [0.3, 0.6, 0.05, 0.05])
    assert [r["task_id"] for r in await _escalations(pool, a)] == [task]
    assert json.dumps(str(task)) not in json.dumps(str(await _escalations(pool, b)))
