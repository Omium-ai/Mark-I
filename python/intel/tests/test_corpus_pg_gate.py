"""FR-LEARN-001 against the real m1_021 store: the corpus_admissions trigger refuses an
uncertified warrant, and load_gate() re-checks freshness so an expired certificate withholds
rows at export time. Store contract + zero-skip inversion as adjudicator/tests/test_pg_stores.py."""

import json
import os
import random
from datetime import UTC, date, datetime, timedelta
from types import SimpleNamespace
from uuid import UUID, uuid4

import asyncpg
import pytest
from app.corpus import export as ex
from app.corpus import jobs
from app.db import _tenant_guc_reset, set_local_tenant
from app.tvo.reader import QuerychokeError
from choke_mock import MockChoke
from mark1_receipts import ReceiptAppendError

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
        pytest.fail(
            "M1_TEST_PG_DSN unset under M1_REQUIRE_STORES=1: a missing store is a failure",
            pytrace=False,
        )
    try:
        p = await asyncpg.create_pool(dsn=DSN, min_size=1, max_size=3, setup=_tenant_guc_reset)
    except Exception as exc:
        if REQUIRE_STORES:
            pytest.fail(f"M1_REQUIRE_STORES=1 and {DSN!r} is unreachable: {exc!r}", pytrace=False)
        pytest.skip(f"Postgres unreachable: {exc!r}")
    try:
        yield p
    finally:
        await p.close()


async def _mk_tenant(pool) -> str:
    tag, tenant = f"corpustest-{random.randbytes(4).hex()}", uuid4()
    async with pool.acquire() as conn, conn.transaction():
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


async def _mk_cert(conn, tenant: str, *, status: str, issued: datetime, expires: datetime) -> UUID:
    verifier = await conn.fetchval(
        "INSERT INTO m1_verifiers (verifier_key, kind, version, display_name, definition)"
        " VALUES ($1, 'judge', 1, 'test judge', $2::jsonb) RETURNING id",
        f"judge:corpus-{uuid4().hex[:8]}",
        json.dumps({"kind": "judge"}),
    )
    gold = await conn.fetchval(
        "INSERT INTO gold_sets (tenant_id, agent, frozen_at) VALUES ($1, 'claudecode', now())"
        " RETURNING id",
        UUID(tenant),
    )
    return await conn.fetchval(
        "INSERT INTO noise_certificates (tenant_id, verifier_id, gold_set_id, status, rho_plus,"
        " rho_minus, natarajan_lcb, gold_n, identifiable, issued_at, expires_at)"
        " VALUES ($1, $2, $3, $4, 0.05, 0.05, 0.7, 200, true, $5, $6) RETURNING id",
        UUID(tenant),
        verifier,
        gold,
        status,
        issued,
        expires,
    )


async def _admit(conn, tenant: str, digest: bytes, cert: UUID) -> None:
    await conn.execute(
        "INSERT INTO corpus_admissions (tenant_id, task_digest, label, cert_id)"
        " VALUES ($1, $2, 'satisfied', $3)",
        UUID(tenant),
        digest,
        cert,
    )


async def test_trigger_refuses_uncertified_warrant(pool):
    tenant = await _mk_tenant(pool)
    now = datetime.now(UTC)
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        cert = await _mk_cert(
            conn, tenant, status="bootstrapping", issued=now, expires=now + timedelta(days=1)
        )
        with pytest.raises(asyncpg.CheckViolationError, match="not currently certified"):
            await _admit(conn, tenant, random.randbytes(32), cert)


async def test_load_gate_admits_fresh_and_withholds_expired(pool, tmp_path):
    tenant = await _mk_tenant(pool)
    now = datetime.now(UTC)
    root = ex.tenant_root(bytes(range(32)), tenant)
    fresh_task, stale_task = (str(uuid4()), str(uuid4())), (str(uuid4()), str(uuid4()))
    fresh_digest, stale_digest = (
        ex.task_digest(root, *fresh_task),
        ex.task_digest(root, *stale_task),
    )
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        fresh = await _mk_cert(
            conn, tenant, status="certified", issued=now, expires=now + timedelta(days=1)
        )
        stale = await _mk_cert(
            conn,
            tenant,
            status="certified",
            issued=now - timedelta(days=2),
            expires=now - timedelta(days=1),
        )
        await _admit(conn, tenant, fresh_digest, fresh)
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        with pytest.raises(asyncpg.CheckViolationError):  # the DB gate, same clock as load_gate
            await _admit(conn, tenant, stale_digest, stale)
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        admitted, certs = await ex.load_gate(conn, tenant)
    assert admitted == {fresh_digest} and certs == {str(fresh): 0.7}
    async with pool.acquire() as conn, conn.transaction():  # a foreign tenant sees nothing
        await set_local_tenant(conn, await _mk_tenant(pool))
        assert await ex.load_gate(conn, tenant) == (set(), {})

    def cand(task: tuple[str, str], cert: UUID) -> dict:
        return {
            "task_id": task[1],
            "session_id": task[0],
            "task_seg_version": "task_seg.v1",
            "agent": "claudecode",
            "model": "m",
            "prompt_digest": random.randbytes(32),
            "verdict": "satisfied",
            "verdict_stage": "certified",
            "p_satisfied": 0.9,
            "p_violated": 0.05,
            "p_refused": 0.03,
            "p_error": 0.02,
            "noise_cert_id": str(cert),
            "input_tokens": 1,
            "output_tokens": 1,
            "cache_read_input_tokens": 0,
            "checkpoint_seq": 3,
            "occurred_at": now,
            "prompt": "p",
            "completion": "c",
        }

    r = ex.export(
        str(tmp_path),
        tenant,
        [cand(fresh_task, fresh), cand(stale_task, stale)],
        admitted,
        certs,
        hmac_root=root,
    )
    assert r.receipt_fields["rows"] == {"parquet": 1, "kto": 1}
    assert r.receipt_fields["excluded"] == {"uncertified": 1}


async def test_export_job_plumbing(pool, tmp_path, monkeypatch):
    """app.corpus.jobs:export — root refusal, choke refusal (M1E-2008, nothing written), a
    controld receipt refusal (objects written, no manifest: an unreferenced export_id), then one
    gated row through the mock template to the receipted pair on disk."""
    monkeypatch.delenv("INTEL_QUERYCHOKE_TOKEN", raising=False)
    tenant = await _mk_tenant(pool)
    now = datetime.now(UTC)
    pepper = bytes(range(32))
    session, task = str(uuid4()), str(uuid4())
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        cert = await _mk_cert(
            conn, tenant, status="certified", issued=now, expires=now + timedelta(days=1)
        )
        await _admit(
            conn, tenant, ex.task_digest(ex.tenant_root(pepper, tenant), session, task), cert
        )
    settings = SimpleNamespace(
        corpus_root_uri=str(tmp_path),
        tenant_hmac_pepper=pepper.hex(),
        querychoke_base_url="http://choke",
        http_timeout_s=5.0,
    )
    ctx = SimpleNamespace(
        pool=pool, settings=settings, tenant_id=tenant, day=date(2026, 9, 15), window_start=now
    )
    choke = MockChoke()
    for missing in ("corpus_root_uri", "tenant_hmac_pepper"):
        partial = SimpleNamespace(**{k: v for k, v in vars(settings).items() if k != missing})
        with pytest.raises(
            RuntimeError, match="INTEL_CORPUS_ROOT_URI and INTEL_TENANT_HMAC_PEPPER"
        ):
            await jobs.export(SimpleNamespace(**{**vars(ctx), "settings": partial}))
    with pytest.raises(RuntimeError, match="INTEL_QUERYCHOKE_TOKEN"):
        await jobs.export(ctx, http=choke.client())
    monkeypatch.setenv("INTEL_QUERYCHOKE_TOKEN", "svc")
    with pytest.raises(QuerychokeError) as e:
        await jobs.export(ctx, http=choke.client())
    assert e.value.code == "M1E-2008" and not (tmp_path / "t").exists()
    choke.templates[jobs.CANDIDATES_TEMPLATE] = [
        {
            "task_id": task,
            "session_id": session,
            "task_seg_version": "task_seg.v1",
            "agent": "claudecode",
            "model": "m",
            "prompt_digest": random.randbytes(32).hex(),
            "verdict": "satisfied",
            "verdict_stage": "certified",
            "p_satisfied": 0.9,
            "p_violated": 0.05,
            "p_refused": 0.03,
            "p_error": 0.02,
            "noise_cert_id": str(cert),
            "input_tokens": 1,
            "output_tokens": 1,
            "cache_read_input_tokens": 0,
            "checkpoint_seq": 3,
            "occurred_at": now.isoformat(),
            "prompt": "p",
            "completion": "c",
        }
    ]
    kto = tmp_path / "t" / tenant / "kto" / "v1"
    choke.append_fail_with = (500, "M1E-9500", "chain append failed")
    with pytest.raises(ReceiptAppendError) as e:
        await jobs.export(ctx, http=choke.client())
    assert e.value.code == "M1E-9500" and choke.appended == []
    (orphan,) = kto.iterdir()
    assert sorted(p.name for p in orphan.iterdir()) == ["rows.jsonl"]  # no manifest: never served

    choke.append_fail_with = None
    receipt_id = await jobs.export(ctx, http=choke.client())
    assert choke.requests[-1][1] == {"from": "2026-09-15", "to": "2026-09-15"}
    (pair,) = (p for p in kto.iterdir() if p != orphan)
    export_id = pair.name.removeprefix("export=")
    assert len((pair / "rows.jsonl").read_text().splitlines()) == 1
    (body,) = choke.appended
    assert (body["tenant_id"], body["record_type"], body["subject_id"]) == (
        tenant,
        ex.RECEIPT_TYPE,
        export_id,
    )
    assert body["idempotency_key"] == f"corpus.export:{export_id}"
    assert [o["key"].rsplit("/", 1)[1] for o in body["payload"]["objects"]] == [
        "part-0.parquet",
        "rows.jsonl",
        "manifest.json",
    ]
    ack = next(iter(choke.receipts.values()))
    assert receipt_id == ack["receipt_id"]
    assert (pair / "receipt.json").read_text() == ack["payload"]
    assert json.loads((pair / "receipt.json").read_text())["export_id"] == export_id
    assert json.loads((pair / "manifest.json").read_text())["dataset_id"] == export_id
