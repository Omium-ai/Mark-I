"""Real-Postgres hand-off (m1_070 bundle_drafts; 05 §4.1; 06 §10.4): the nightly job writes ONE
pending draft per window through the choke mock, a re-run is a no-op, a violated knee gate lands
as `refused` and parks the job, carry-forward reads the last published draft, and the RLS
negative. Same DSN gating as test_jobs_pg.py."""

import hashlib
import os
import random
from datetime import UTC, datetime
from uuid import UUID, uuid4

import asyncpg
import pytest
from app.db import _tenant_guc_reset, set_local_tenant
from app.jobs.runner import JobContext
from app.policy_compiler import jobs
from app.policy_compiler.compile import SECTION_NAMES, compile_sections
from app.policy_compiler.cpvs import Regime
from app.policy_compiler.publish import KneeGateViolation, previous_sections, write_draft
from app.regime import RegimeUnset
from app.tvo.reader import QuerychokeError
from choke_mock import MockChoke
from test_policy_compiler import REGIME, attempts

DSN = os.environ.get("M1_TEST_PG_DSN", "")
REQUIRE_STORES = os.environ.get("M1_REQUIRE_STORES", "0") == "1"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not DSN and not REQUIRE_STORES,
        reason="M1_TEST_PG_DSN not set (estate skipif idiom; M1_REQUIRE_STORES=0)",
    ),
]

WINDOW = datetime(2026, 9, 15, tzinfo=UTC)


class _Settings:
    querychoke_base_url = "http://choke"
    http_timeout_s = 5.0


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


async def _mk_tenant(pool: asyncpg.Pool) -> str:
    tag = f"pctest-{random.randbytes(4).hex()}"
    tenant = uuid4()
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


async def _drafts(pool: asyncpg.Pool, tenant: str) -> list[asyncpg.Record]:
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        return await conn.fetch(
            "SELECT * FROM bundle_drafts WHERE tenant_id = $1 ORDER BY window_start", UUID(tenant)
        )


def _rows() -> list[dict]:
    return [a.model_dump() for a in attempts()]


def _ctx(pool, tenant) -> JobContext:
    return JobContext(pool=pool, settings=_Settings(), tenant_id=tenant, window_start=WINDOW)


async def test_job_writes_one_pending_draft_per_window(pool, monkeypatch):
    monkeypatch.setenv("INTEL_QUERYCHOKE_TOKEN", "intel-svc")
    tenant = await _mk_tenant(pool)
    choke = MockChoke()
    choke.templates[jobs.ATTEMPTS_TEMPLATE] = _rows()
    async with choke.client() as http:
        assert await jobs.compile(_ctx(pool, tenant), http=http, regime=REGIME) is None
        # Idempotent re-run (06 §7.3): same (tenant, channel, window) ⇒ the same row, untouched.
        assert await jobs.compile(_ctx(pool, tenant), http=http, regime=REGIME) is None
    template, params, _ = choke.requests[0]
    assert template == jobs.ATTEMPTS_TEMPLATE
    assert params == {"from": "2026-08-17", "to": "2026-09-16"}  # 30 closed days, half-open
    (draft,) = await _drafts(pool, tenant)
    expected = compile_sections(attempts(), REGIME)
    assert (draft["channel"], draft["state"], draft["knee_gate_ok"]) == ("canary", "pending", True)
    assert draft["window_start"] == WINDOW and draft["published_seq"] is None
    assert all(bytes(draft[f"{n}_cbor"]) == expected.sections[n] for n in SECTION_NAMES)
    assert bytes(draft["draft_hash"]) == expected.draft_hash
    assert draft["max_age"].days == 7 and draft["refusal_reason"] is None


async def test_violated_knee_gate_is_recorded_refused_and_parks_the_job(pool, monkeypatch):
    monkeypatch.setenv("INTEL_QUERYCHOKE_TOKEN", "intel-svc")
    tenant = await _mk_tenant(pool)
    choke = MockChoke()
    choke.templates[jobs.ATTEMPTS_TEMPLATE] = _rows()
    bad = Regime(cost_basis="quota", v_default=10.0, window_limit_tokens=100_000)
    async with choke.client() as http:
        with pytest.raises(KneeGateViolation, match="VIOLATED"):
            await jobs.compile(_ctx(pool, tenant), http=http, regime=bad)
    (draft,) = await _drafts(pool, tenant)
    assert (draft["state"], draft["knee_gate_ok"]) == ("refused", False)
    assert draft["refusal_reason"].startswith("knee sanity gate (06 §10.3)")


async def test_job_refusals_before_any_draft(pool, monkeypatch):
    monkeypatch.setenv("INTEL_QUERYCHOKE_TOKEN", "intel-svc")
    tenant = await _mk_tenant(pool)
    choke = MockChoke()
    async with choke.client() as http:
        # The template is not in controld's closed registry yet: M1E-2008, fail-closed.
        with pytest.raises(QuerychokeError) as exc:
            await jobs.compile(_ctx(pool, tenant), http=http, regime=REGIME)
        assert exc.value.code == "M1E-2008"
        # Mixed bases in one channel window never blend (CON-014).
        mixed = _rows()
        mixed[0]["cost_basis"] = "usd"
        choke.templates[jobs.ATTEMPTS_TEMPLATE] = mixed
        with pytest.raises(RuntimeError, match="never mixed"):
            await jobs.compile(_ctx(pool, tenant), http=http, regime=REGIME)
        # No m1_075 row for the tenant: parks with the named gap, no draft (app/regime).
        choke.templates[jobs.ATTEMPTS_TEMPLATE] = _rows()
        with pytest.raises(RegimeUnset, match="no regime row"):
            await jobs.compile(_ctx(pool, tenant), http=http)
        # Nothing certified: nothing to compile, no row, no error.
        choke.templates[jobs.ATTEMPTS_TEMPLATE] = [
            {**r, "verdict_stage": "provisional"} for r in _rows()
        ]
        assert await jobs.compile(_ctx(pool, tenant), http=http, regime=REGIME) is None
        monkeypatch.delenv("INTEL_QUERYCHOKE_TOKEN")
        with pytest.raises(RuntimeError, match="INTEL_QUERYCHOKE_TOKEN"):
            await jobs.compile(_ctx(pool, tenant), http=http, regime=REGIME)
    assert await _drafts(pool, tenant) == []


async def _publish_as_controld(conn, tenant: str, channel: str, window: datetime) -> int:
    """What policydist/drafts.go does after Module.Publish, minus signing and the log: a catalog
    row at head+1 (m1_042's trigger chains it) and the draft marked published against it."""
    body = b"\xa0"
    seq = await conn.fetchval(
        "INSERT INTO policy_bundles (tenant_id, channel, seq, body_cbor, body_sha256, prev_hash, "
        "max_age, signatures, signing_key_id, tlog_index, tlog_proof, receipt_id) "
        "SELECT $1, $2, head_seq + 1, $3, $4, head_hash, interval '1 day', '{}', 'test', "
        "head_seq, '{}', $5 FROM bundle_channel_heads WHERE tenant_id = $1 AND channel = $2 "
        "RETURNING seq",
        UUID(tenant),
        channel,
        body,
        hashlib.sha256(body).digest(),
        uuid4(),
    )
    await conn.execute(
        "UPDATE bundle_drafts SET state = 'published', published_seq = $4 "
        "WHERE tenant_id = $1 AND channel = $2 AND window_start = $3",
        UUID(tenant),
        channel,
        window,
        seq,
    )
    return seq


async def test_carry_forward_reads_the_last_published_draft_and_rls_hides_it(pool):
    tenant, other = await _mk_tenant(pool), await _mk_tenant(pool)
    first = compile_sections(attempts(), REGIME)
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        assert await previous_sections(conn, tenant, "canary") is None
        assert await write_draft(conn, tenant, "canary", WINDOW, first)
        assert not await write_draft(conn, tenant, "canary", WINDOW, first)  # ON CONFLICT
        # Pending drafts are not "previous": only a publication is carried forward.
        assert await previous_sections(conn, tenant, "canary") is None
        await conn.execute(
            "INSERT INTO bundle_channel_heads (tenant_id, channel) VALUES ($1, 'canary') "
            "ON CONFLICT DO NOTHING",
            UUID(tenant),
        )
        seq = await _publish_as_controld(conn, tenant, "canary", WINDOW)
        assert seq == 1
        assert await previous_sections(conn, tenant, "canary") == first.sections
    # The state-evidence CHECK: a refusal without a reason cannot be stored (own tx: it aborts).
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        with pytest.raises(asyncpg.CheckViolationError):
            await conn.execute(
                "INSERT INTO bundle_drafts (tenant_id, channel, window_start, verify_cbor, "
                "route_cbor, memory_cbor, cortex_cbor, gates_cbor, agent_maps_cbor, draft_hash, "
                "max_age, knee_gate_ok, knee_note, state) VALUES ($1, 'canary', now(), '', '', "
                "'', '', '', '', $2, interval '1 day', false, '', 'refused')",
                UUID(tenant),
                bytes(32),
            )
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, other)
        assert await previous_sections(conn, tenant, "canary") is None
        assert await conn.fetchval("SELECT count(*) FROM bundle_drafts") == 0
    assert len(await _drafts(pool, tenant)) == 1
